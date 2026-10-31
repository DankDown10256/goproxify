// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pilote SQLite pour la copie cohérente des bases
)

// backupSkipDirs : dossiers de l'état de la passerelle qu'une sauvegarde ne reprend pas
// (téléchargeables ou purement runtime).
var backupSkipDirs = map[string]bool{"geoip": true, "logs": true, "edge-logs": true, "threat-lists": true, "restore-tmp": true}

// logsKept : le dossier des logs est exclu de la sauvegarde pour sa taille (ADR 0012 : la base se reconstitue côté Admin
// pour ce qui l'intéresse, et les exports légaux se font avant), sauf les gels légaux : le registre et les archives
// des lignes qu'ils gardent. Sans eux, une restauration lèverait les gels en silence et ces lignes seraient perdues.
func logsKept(rel string) bool {
	rel = filepath.ToSlash(rel)
	return rel == "logs/legal-holds.json" || strings.HasPrefix(rel, "logs/held/")
}

// backupTmpPrefix : dossier de travail des copies SQLite, créé dans le volume de données (inscriptible
// même quand le système de fichiers du conteneur est en lecture seule) et jamais exporté.
const backupTmpPrefix = ".gpx-backup-"

func edgeDataDir() string {
	if d := os.Getenv("GPX_EDGE_DATA_DIR"); d != "" {
		return d
	}
	return "/etc/goproxify"
}

// envMB lit une taille en Mo dans l'environnement.
func envMB(name string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(name), 10, 64); err == nil && v > 0 {
		return v << 20
	}
	return def << 20
}

func backupSkipFile(name string) bool {
	return strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".mmdb") ||
		strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") || strings.HasSuffix(name, ".cast.gpx") || name == "asn-db.gpx"
}

// backupBundle : fichiers d'état d'une passerelle, chemin relatif → contenu.
type backupBundle struct {
	Files   map[string][]byte `json:"files"`
	Skipped []string          `json:"skipped,omitempty"`
	Sizes   map[string]int64  `json:"sizes,omitempty"`
}

type backupEntry struct {
	rel  string
	path string // fichier à lire (pour une base SQLite : sa copie cohérente)
	size int64
}

// planBackup liste ce qu'une sauvegarde reprend, sans rien charger en mémoire. Les bases SQLite sont
// copiées par VACUUM INTO (cohérent à chaud) dans un dossier de travail du volume de données. La
// raison de chaque fichier ignoré est renvoyée. cleanup supprime le dossier de travail.
func planBackup(root string) (entries []backupEntry, skipped []string, cleanup func(), err error) {
	maxFile, maxTotal := envMB("GPX_BACKUP_MAX_FILE_MB", 16), envMB("GPX_BACKUP_MAX_TOTAL_MB", 64)
	var tmp string
	cleanup = func() {
		if tmp != "" {
			os.RemoveAll(tmp)
		}
	}
	var total int64
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		slash := filepath.ToSlash(rel)
		if d.IsDir() {
			if slash == "logs" || slash == "logs/held" || strings.HasPrefix(slash, "logs/held/") {
				return nil // on y descend : seuls les gels légaux y sont repris, voir logsKept
			}
			if backupSkipDirs[rel] || strings.HasPrefix(d.Name(), backupTmpPrefix) || strings.HasPrefix(slash, "logs/") {
				return filepath.SkipDir
			}
			return nil
		}
		if backupSkipFile(d.Name()) || (strings.HasPrefix(slash, "logs/") && !logsKept(slash)) {
			return nil
		}
		rel = slash
		info, ierr := d.Info()
		if ierr != nil {
			skipped = append(skipped, rel+" (illisible : "+ierr.Error()+")")
			return nil
		}
		src, size := p, info.Size()
		if strings.HasSuffix(d.Name(), ".db") {
			if tmp == "" {
				if tmp, ierr = os.MkdirTemp(root, backupTmpPrefix); ierr != nil {
					tmp = ""
					skipped = append(skipped, rel+" (dossier de travail impossible : "+ierr.Error()+")")
					return nil
				}
			}
			dst := filepath.Join(tmp, strconv.Itoa(len(entries))+".db")
			if verr := vacuumTo(p, dst); verr != nil {
				skipped = append(skipped, rel+" (copie de la base impossible : "+verr.Error()+")")
				return nil
			}
			st, serr := os.Stat(dst)
			if serr != nil {
				skipped = append(skipped, rel+" (copie illisible : "+serr.Error()+")")
				return nil
			}
			src, size = dst, st.Size()
		}
		switch {
		case size > maxFile:
			skipped = append(skipped, fmt.Sprintf("%s (%d Mo, au-delà de %d Mo par fichier)", rel, size>>20, maxFile>>20))
		case total+size > maxTotal:
			skipped = append(skipped, fmt.Sprintf("%s (%d Mo, au-delà de %d Mo au total)", rel, size>>20, maxTotal>>20))
		default:
			total += size
			entries = append(entries, backupEntry{rel: rel, path: src, size: size})
		}
		return nil
	})
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	return entries, skipped, cleanup, err
}

// vacuumTo écrit dans dst une copie cohérente de la base SQLite src, même ouverte (mode WAL) par la passerelle.
func vacuumTo(src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(src)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`VACUUM INTO ?`, dst)
	return err
}

// vacuumCopy renvoie le contenu d'une copie cohérente d'une base SQLite (utilisé par les tests).
func vacuumCopy(path string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "gpx-vacuum-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	dst := filepath.Join(dir, "copy.db")
	if err := vacuumTo(path, dst); err != nil {
		return nil, err
	}
	return os.ReadFile(dst)
}

// safeRestorePath refuse tout chemin absolu, remontant, ou visant un dossier exclu.
func safeRestorePath(root, rel string) (string, bool) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.Contains(rel, "\\") {
		return "", false
	}
	first := strings.SplitN(filepath.ToSlash(clean), "/", 2)[0]
	if first == "logs" && !logsKept(clean) {
		return "", false
	}
	if (backupSkipDirs[first] && first != "logs") || strings.HasPrefix(first, backupTmpPrefix) || backupSkipFile(filepath.Base(clean)) {
		return "", false
	}
	return filepath.Join(root, clean), true
}

func writeRestoredFile(dst string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".restore-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if strings.HasSuffix(dst, ".db") { // un -wal/-shm périmé corromprait la base restaurée
		os.Remove(dst + "-wal")
		os.Remove(dst + "-shm")
	}
	return os.Rename(tmp.Name(), dst)
}

// handleBackupExport : GET /internal/v1/backup/export — état persisté de la passerelle (appelé par l'Admin).
// La réponse est écrite en flux, un fichier à la fois : la mémoire de la passerelle n'est jamais
// chargée de l'ensemble de l'état.
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	entries, skipped, cleanup, err := planBackup(edgeDataDir())
	defer cleanup()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sizes := make(map[string]int64, len(entries))
	for _, e := range entries {
		sizes[e.rel] = e.size
	}
	w.Header().Set("Content-Type", "application/json")
	bw := bufio.NewWriterSize(w, 256<<10)
	defer bw.Flush()
	bw.WriteString(`{"files":{`)
	first := true
	for _, e := range entries {
		f, ferr := os.Open(e.path)
		if ferr != nil {
			skipped = append(skipped, e.rel+" (illisible : "+ferr.Error()+")")
			delete(sizes, e.rel)
			continue
		}
		if !first {
			bw.WriteByte(',')
		}
		first = false
		key, _ := json.Marshal(e.rel)
		bw.Write(key)
		bw.WriteString(`:"`)
		enc := base64.NewEncoder(base64.StdEncoding, bw)
		_, cerr := io.Copy(enc, f)
		enc.Close()
		f.Close()
		bw.WriteByte('"')
		if cerr != nil {
			return // flux interrompu : l'Admin le détecte (JSON incomplet) et le signale
		}
	}
	bw.WriteString(`}`)
	if len(skipped) > 0 {
		b, _ := json.Marshal(skipped)
		bw.WriteString(`,"skipped":`)
		bw.Write(b)
	}
	b, _ := json.Marshal(sizes)
	bw.WriteString(`,"sizes":`)
	bw.Write(b)
	bw.WriteString(`}`)
}

// handleBackupRestore : POST /internal/v1/backup/restore — réécrit les fichiers d'état. Un
// redémarrage de la passerelle est nécessaire pour qu'elle les relise.
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var b backupBundle
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<20)).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	root := edgeDataDir()
	written, rejected := 0, []string{}
	for rel, data := range b.Files {
		dst, ok := safeRestorePath(root, rel)
		if !ok {
			rejected = append(rejected, rel)
			continue
		}
		if err := writeRestoredFile(dst, data); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s (%v)", rel, err))
			continue
		}
		written++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"written": written, "rejected": rejected, "restart_required": true}) //nolint:errcheck
}
