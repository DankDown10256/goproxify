// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

const secretsEncPrefix = "GPXSEC1:"

// ErrNoBackupKey : la section secrets n'est jamais écrite ni lue sans GPX_BACKUP_KEY.
var ErrNoBackupKey = errors.New("GPX_BACKUP_KEY non définie")

// maxSecretFileBytes borne la taille d'un fichier copié dans la section secrets.
const maxSecretFileBytes = 8 << 20

// secretTables : tables d'état sensibles, restaurées avant les tables de configuration
// (les utilisateurs d'abord : équipes, MFA et jetons y font référence).
var secretTables = []string{
	"users",
	"tokens",
	"user_api_tokens",
	"user_api_token_scopes",
	"user_mfa",
	"user_backup_codes",
	"user_trusted_devices",
	"gdpr_keys",
	"edge_erasure_queue", // effacements d'IP à rejouer aux passerelles absentes : une obligation, jamais à perdre (IP chiffrées par gdpr_keys)
	"ech_keys",
	"internal_ca",
	"internal_ca_certs",
	"cert_pull_tokens",
	"team_permissions",
	"user_permissions",
	"alert_channels",
}

// SecretBundle regroupe tout ce que le snapshot standard vide ou exclut : lignes brutes
// (secrets en clair) et fichiers d'état de l'Admin (architecture.json, CA interne…).
type SecretBundle struct {
	Tables map[string][]map[string]any `json:"tables"`
	// Files : clé "<étiquette>/<chemin relatif>" → contenu.
	Files map[string][]byte `json:"files,omitempty"`
}

// keyRing : clé active et clés retirées enregistrées depuis l'interface (l'active ne l'emporte jamais
// sur GPX_BACKUP_KEY ; les retirées servent seulement à relire d'anciens snapshots).
type keyRing struct {
	active  string
	retired []string
}

var ring atomic.Value // keyRing

func currentRing() keyRing { r, _ := ring.Load().(keyRing); return r }

// SetKeyRing installe la clé active ("" = aucune) et les clés retirées.
func SetKeyRing(active string, retired []string) {
	r := keyRing{active: strings.TrimSpace(active)}
	for _, k := range retired {
		if k = strings.TrimSpace(k); k != "" {
			r.retired = append(r.retired, k)
		}
	}
	ring.Store(r)
}

// SetFileKey installe (ou retire, avec "") la seule clé active.
func SetFileKey(raw string) { SetKeyRing(raw, nil) }

// KeySource indique d'où vient la clé : "env", "file" ou "none".
func KeySource() string {
	if strings.TrimSpace(os.Getenv("GPX_BACKUP_KEY")) != "" {
		return "env"
	}
	if currentRing().active != "" {
		return "file"
	}
	return "none"
}

// BackupKey dérive la clé de chiffrement (32 octets) depuis GPX_BACKUP_KEY, à défaut depuis la clé
// enregistrée dans l'interface.
func BackupKey() ([]byte, bool) {
	raw := strings.TrimSpace(os.Getenv("GPX_BACKUP_KEY"))
	if raw == "" {
		raw = currentRing().active
	}
	if raw == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], true
}

// AllBackupKeys : toutes les clés connues (environnement, active, retirées), la plus récente d'abord.
func AllBackupKeys() [][]byte {
	var raws []string
	if e := strings.TrimSpace(os.Getenv("GPX_BACKUP_KEY")); e != "" {
		raws = append(raws, e)
	}
	r := currentRing()
	if r.active != "" {
		raws = append(raws, r.active)
	}
	raws = append(raws, r.retired...)
	seen := map[string]bool{}
	var out [][]byte
	for _, raw := range raws {
		sum := sha256.Sum256([]byte(raw))
		if k := string(sum[:]); !seen[k] {
			seen[k] = true
			out = append(out, sum[:])
		}
	}
	return out
}

// DecryptAny déchiffre nonce||texte chiffré avec la première clé connue qui l'authentifie : une
// rotation de clé ne rend donc aucun ancien snapshot illisible.
func DecryptAny(blob []byte) ([]byte, error) {
	keys := AllBackupKeys()
	if len(keys) == 0 {
		return nil, ErrNoBackupKey
	}
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(blob) < gcm.NonceSize() {
			continue
		}
		if plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil); err == nil {
			return plain, nil
		}
	}
	return nil, errors.New("déchiffrement impossible : aucune clé connue ne correspond (clé active ou retirée manquante ?)")
}

// DecryptAnyConsume est DecryptAny pour un tampon jetable : avec une seule clé connue, le déchiffrement
// se fait sur place (le texte chiffré est écrasé), sans second tampon de la taille du snapshot. Avec
// plusieurs clés, un essai raté effacerait le tampon : on retombe sur DecryptAny.
func DecryptAnyConsume(blob []byte) ([]byte, error) {
	keys := AllBackupKeys()
	if len(keys) != 1 {
		return DecryptAny(blob)
	}
	block, err := aes.NewCipher(keys[0])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(blob) < gcm.NonceSize() {
		return nil, errors.New("déchiffrement impossible : données tronquées")
	}
	ns := gcm.NonceSize()
	plain, err := gcm.Open(blob[ns:ns], blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, errors.New("déchiffrement impossible : aucune clé connue ne correspond (clé active ou retirée manquante ?)")
	}
	return plain, nil
}

func secretsGCM() (cipher.AEAD, error) {
	key, ok := BackupKey()
	if !ok {
		return nil, ErrNoBackupKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealSecrets(plain []byte) (string, error) { return sealWith(secretsEncPrefix, plain) }

func sealWith(prefix string, plain []byte) (string, error) {
	gcm, err := secretsGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, nil)), nil
}

func openSecrets(sealed string) ([]byte, error) { return openWith(secretsEncPrefix, sealed) }

func openWith(prefix, sealed string) ([]byte, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return nil, errors.New("section chiffrée : format inconnu")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return nil, err
	}
	plain, err := DecryptAny(raw)
	if err != nil {
		return nil, fmt.Errorf("section chiffrée : %w", err)
	}
	return plain, nil
}

// AttachSecrets construit la section secrets et la joint à b, chiffrée. dirs : étiquette →
// dossier à copier tel quel. Sans GPX_BACKUP_KEY, ne fait rien et renvoie ErrNoBackupKey.
func AttachSecrets(db *sql.DB, b *Backup, dirs map[string]string, extra map[string][]byte) ([]string, error) {
	if _, ok := BackupKey(); !ok {
		return nil, ErrNoBackupKey
	}
	sb := SecretBundle{Tables: exportRawTables(db, append(append([]string{}, secretTables...), backupTables...))}
	pruneNonSecretTables(sb.Tables)
	sb.Files = readDirs(dirs)
	for name, data := range extra {
		sb.Files["config/"+name] = data
	}
	gw, warnings := collectGateways(db)
	for name, data := range gw {
		sb.Files[name] = data
	}
	warnings = append(warnings, SizeNotes("section secrets", sb.Tables, sb.Files)...)
	plain, err := json.Marshal(sb)
	if err != nil {
		return warnings, err
	}
	b.Secrets, err = sealSecrets(plain)
	return warnings, err
}

func readDirs(dirs map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for label, root := range dirs {
		if root == "" {
			continue
		}
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:errcheck
			if err != nil || d.IsDir() || strings.HasSuffix(p, ".tmp") {
				return nil
			}
			if info, err := d.Info(); err != nil || info.Size() > maxSecretFileBytes {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			out[label+"/"+filepath.ToSlash(rel)] = data
			return nil
		})
	}
	return out
}

// SecretsSummary décrit le contenu de la section secrets sans rien écrire.
type SecretsSummary struct {
	Tables      map[string]int `json:"tables"`
	Files       int            `json:"files"`
	Gateways    []string       `json:"gateways,omitempty"`     // passerelles dont l'état est dans la sauvegarde
	ConfigFiles []string       `json:"config_files,omitempty"` // config HA, admin.json (restaurés dans restored-config/)
}

// OpenSecretsSummary déchiffre la section secrets et en résume le contenu.
func OpenSecretsSummary(b *Backup) (*SecretsSummary, error) {
	if b.Secrets == "" {
		return nil, errors.New("cette sauvegarde ne contient pas de section secrets")
	}
	plain, err := openSecrets(b.Secrets)
	if err != nil {
		return nil, err
	}
	return summarizeSecretsPlain(plain)
}

func openBundle(b *Backup) (*SecretBundle, error) {
	if b.Secrets == "" {
		return nil, errors.New("cette sauvegarde ne contient pas de section secrets")
	}
	plain, err := openSecrets(b.Secrets)
	if err != nil {
		return nil, err
	}
	var sb SecretBundle
	if err := json.Unmarshal(plain, &sb); err != nil {
		return nil, err
	}
	return &sb, nil
}

// SecretFiles déchiffre la section secrets et rend ses fichiers : « <étiquette>/<chemin> » → contenu (`state/…`,
// `config/…`, `gateway/<nom>/…`). Rien n'est écrit : c'est ce qui permet de lire une sauvegarde sans Admin.
func SecretFiles(b *Backup) (map[string][]byte, error) {
	sb, err := openBundle(b)
	if err != nil {
		return nil, err
	}
	return sb.Files, nil
}

// restoreSecrets remplace les lignes sensibles (écrasement systématique : ce sont les
// valeurs vidées par l'import standard) et réécrit les fichiers d'état.
func restoreSecrets(db *sql.DB, b *Backup, dirs map[string]string) (rows, files int, gateways []GatewayRestore, err error) {
	sb, err := openBundle(b)
	if err != nil {
		return 0, 0, nil, err
	}
	gwFiles := map[string][]byte{}
	order := append(append([]string{}, secretTables...), backupTables...)
	rows, _ = applyTablesOrdered(db, sb.Tables, order, true, true)
	// Les tables sans secret ne sont plus recopiées dans la section secrets (elles sont entières dans la
	// section standard) : la restauration des secrets les reprend de là, comme avant ce changement.
	rest := map[string][]map[string]any{}
	for _, table := range backupTables {
		if _, inBundle := sb.Tables[table]; !inBundle && len(b.Tables[table]) > 0 {
			rest[table] = b.Tables[table]
		}
	}
	if len(rest) > 0 {
		w, _ := applyTablesOrdered(db, rest, backupTables, true, true)
		rows += w
	}
	for name, data := range sb.Files {
		label, rel, ok := strings.Cut(name, "/")
		if label == gatewayLabel {
			gwFiles[name] = data
			continue
		}
		root := dirs[label]
		if !ok || root == "" {
			continue
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if r, rerr := filepath.Rel(root, dst); rerr != nil || strings.HasPrefix(r, "..") {
			continue // chemin hors du dossier cible
		}
		if os.MkdirAll(filepath.Dir(dst), 0o700) != nil {
			continue
		}
		if atomicWriteFile(dst, data) == nil {
			files++
		}
	}
	if len(gwFiles) > 0 {
		gateways = restoreGateways(db, gwFiles)
	}
	return rows, files, gateways, nil
}
