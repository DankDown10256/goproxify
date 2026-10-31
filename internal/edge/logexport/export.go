// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logexport

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// Formats de sortie.
const (
	FormatNDJSON = "ndjson"
	FormatCSV    = "csv"
)

// Request décrit un export.
type Request struct {
	Node     string
	Operator string
	Reason   string
	Kind     logstore.Kind
	From, To time.Time
	Domain   string
	// Origin exporte les lignes qu'une ancienne version a répliquées de ce pair, au lieu des lignes propres de la base.
	Origin string
	IP     string
	Format string
	// Password chiffre la sortie. Vide : sortie en clair, que l'appelant doit avoir demandée explicitement.
	Password string
}

// Result nomme les deux fichiers produits.
type Result struct {
	DataPath     string
	ManifestPath string
	Manifest     Manifest
}

type exportRow struct {
	ID              string `json:"id"`
	Ts              string `json:"ts"`
	Level           string `json:"level"`
	Component       string `json:"component,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Method          string `json:"method,omitempty"`
	Path            string `json:"path,omitempty"`
	Status          int    `json:"status,omitempty"`
	Bytes           int64  `json:"bytes,omitempty"`
	LatencyMs       int64  `json:"latency_ms,omitempty"`
	IP              string `json:"ip,omitempty"`
	IPPseudonymized bool   `json:"ip_pseudonymized,omitempty"`
	IPTruncated     bool   `json:"ip_truncated,omitempty"`
	// IPStored : l'IP telle que la base la garde (tronquée) quand IP porte l'IP réelle d'une ligne pseudonymisée ; absent sinon.
	IPStored     string   `json:"ip_stored,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	Referrer     string   `json:"referrer,omitempty"`
	RequestID    string   `json:"request_id,omitempty"`
	WAFMatches   []string `json:"waf_matches,omitempty"`
	ThreatSignal string   `json:"threat_signal,omitempty"`
	TLSJA3       string   `json:"tls_ja3,omitempty"`
	TLSJA4       string   `json:"tls_ja4,omitempty"`
	Message      string   `json:"message,omitempty"`
}

var csvHeader = []string{"id", "ts", "level", "component", "domain", "method", "path", "status", "bytes", "latency_ms", "ip",
	"ip_pseudonymized", "ip_truncated", "user_agent", "referrer", "request_id", "waf_matches", "threat_signal", "tls_ja3", "tls_ja4", "message"}

func toExportRow(node string, kind logstore.Kind, r logstore.Row) exportRow {
	x := exportRow{
		ID: node + ":" + string(kind) + ":" + strconv.FormatInt(rowNumber(r), 10), Ts: r.Ts.UTC().Format("2006-01-02T15:04:05.000000Z"), Level: r.Level,
		Component: r.Component, Domain: r.Domain, Method: r.Method, Path: r.Path, Status: r.Status, Bytes: r.Bytes, LatencyMs: r.LatencyMs,
		IP: r.IP, IPPseudonymized: r.Pseudonymized, IPTruncated: r.IPTruncated, UserAgent: r.UserAgent, Referrer: r.Referrer,
		RequestID: r.RequestID, WAFMatches: r.WAFMatches, ThreatSignal: r.ThreatSignal, TLSJA3: r.TLSJA3, TLSJA4: r.TLSJA4, Message: r.Message,
	}
	if r.RealIP != "" {
		x.IPStored = x.IP
		x.IP, x.IPTruncated = r.RealIP, false
	}
	return x
}

// csvCell neutralise une cellule qu'un tableur lirait comme une formule : les champs de texte viennent des clients.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (x exportRow) csv() []string {
	return []string{x.ID, x.Ts, x.Level, x.Component, csvCell(x.Domain), x.Method, csvCell(x.Path), strconv.Itoa(x.Status),
		strconv.FormatInt(x.Bytes, 10), strconv.FormatInt(x.LatencyMs, 10), x.IP, strconv.FormatBool(x.IPPseudonymized),
		strconv.FormatBool(x.IPTruncated), csvCell(x.UserAgent), csvCell(x.Referrer), x.RequestID, strings.Join(x.WAFMatches, ";"),
		x.ThreatSignal, x.TLSJA3, x.TLSJA4, csvCell(x.Message)}
}

// countHash compte et empreinte ce qui passe.
type countHash struct {
	h hash.Hash
	n int64
}

func (c *countHash) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

func (c *countHash) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

// DataName rend le nom du fichier de données d'un export.
func DataName(base string, req Request) string {
	name := base + "." + req.Format
	if req.Password != "" {
		name += ".gpxe"
	}
	return name
}

// ManifestName rend le nom du fichier de manifeste.
func ManifestName(base string) string { return base + ".manifest.json" }

// Run écrit l'export de la plage demandée sous base (« export-2026 » donne export-2026.ndjson.gpxe et
// export-2026.manifest.json) et rend ce qui a été écrit. Les fichiers n'existent qu'à la fin d'une réussite.
func Run(store *logstore.Store, priv ed25519.PrivateKey, req Request, base string, now func() time.Time) (*Result, error) {
	return RunSources([]Source{{Name: req.Node, Store: store}}, priv, req, base, now)
}

// Source est un store à exporter et le nom sous lequel ses lignes figurent dans l'export (la passerelle).
type Source struct {
	Name  string
	Store *logstore.Store
}

// RunSources écrit un export qui couvre plusieurs stores (l'Admin range un store par passerelle, ADR 0018) : les lignes de
// chaque source se suivent, identifiées par son nom ; le manifeste les nomme.
func RunSources(sources []Source, priv ed25519.PrivateKey, req Request, base string, now func() time.Time) (*Result, error) {
	if len(sources) == 0 {
		return nil, errors.New("aucune source à exporter")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errors.New("un motif est obligatoire")
	}
	if req.From.IsZero() || req.To.IsZero() || req.To.Before(req.From) {
		return nil, errors.New("plage de dates invalide")
	}
	if req.Format != FormatNDJSON && req.Format != FormatCSV {
		return nil, fmt.Errorf("format inconnu %q (ndjson ou csv)", req.Format)
	}
	if req.Kind != logstore.KindAccess && req.Kind != logstore.KindSystem {
		return nil, fmt.Errorf("type de logs inconnu %q (access ou system)", req.Kind)
	}
	dataPath, manifestPath := DataName(base, req), ManifestName(base)
	for _, p := range []string{dataPath, manifestPath} {
		if _, err := os.Stat(p); err == nil {
			return nil, fmt.Errorf("%s existe déjà : un export n'écrase rien", p)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(dataPath), ".export-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	file := &countHash{h: sha256.New()}
	plain := &countHash{h: sha256.New()}
	var sink io.Writer = io.MultiWriter(tmp, file)
	var enc io.WriteCloser
	if req.Password != "" {
		if enc, err = NewEncryptWriter(sink, req.Password); err != nil {
			return nil, err
		}
		sink = enc
	}
	out := bufio.NewWriterSize(io.MultiWriter(sink, plain), 64<<10)
	var cw *csv.Writer
	if req.Format == FormatCSV {
		cw = csv.NewWriter(out)
		if err := cw.Write(csvHeader); err != nil {
			return nil, err
		}
	}

	m := Manifest{Version: 1, Node: req.Node, Operator: req.Operator, Reason: req.Reason, Kind: string(req.Kind),
		From: req.From.UTC().Format(time.RFC3339), To: req.To.UTC().Format(time.RFC3339), Format: req.Format, Encrypted: req.Password != ""}
	if len(sources) > 1 {
		for _, src := range sources {
			m.Nodes = append(m.Nodes, src.Name)
		}
	}
	m.Filters.Domain = req.Domain
	m.Origin = req.Origin
	if req.IP != "" {
		sum := sha256.Sum256([]byte(ipcrypt.CanonicalIP(req.IP)))
		m.Filters.IPSHA256 = hex.EncodeToString(sum[:])
	}
	enc1 := json.NewEncoder(out)
	enc1.SetEscapeHTML(false)
	emit := func(src string, r logstore.Row) error {
		x := toExportRow(src, req.Kind, r)
		if m.Rows == 0 {
			m.FirstTS = x.Ts
		}
		m.LastTS = x.Ts
		m.Rows++
		if cw != nil {
			return cw.Write(x.csv())
		}
		return enc1.Encode(x)
	}
	filter := logstore.ScanFilter{From: req.From, To: req.To, Domain: req.Domain, IP: req.IP, Origin: req.Origin}
	for _, src := range sources {
		src := src
		if err = src.Store.Scan(req.Kind, filter, func(r logstore.Row) error { return emit(src.Name, r) }); err != nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			return nil, err
		}
	}
	if err := out.Flush(); err != nil {
		return nil, err
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return nil, err
		}
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	m.PlainSHA256, m.PlainBytes = plain.sum(), plain.n
	m.FileSHA256, m.FileBytes, m.File = file.sum(), file.n, filepath.Base(dataPath)
	m.CreatedAt = now().UTC().Format(time.RFC3339)
	signed, err := SignManifest(priv, m)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, dataPath); err != nil {
		return nil, err
	}
	done = true
	if err := os.WriteFile(manifestPath, signed, 0o600); err != nil {
		os.Remove(dataPath)
		return nil, err
	}
	_ = os.Chmod(dataPath, 0o600)
	parsed, err := ParseManifest(signed, nil)
	if err != nil {
		return nil, err
	}
	return &Result{DataPath: dataPath, ManifestPath: manifestPath, Manifest: parsed}, nil
}

// VerifyReport est le résultat d'une vérification.
type VerifyReport struct {
	Manifest Manifest
	// FileChecked : le fichier de données remis a l'empreinte du manifeste.
	FileChecked bool
	// PlainChecked : le contenu déchiffré a l'empreinte du manifeste.
	PlainChecked bool
}

// Verify contrôle un export : la signature du manifeste (avec la clé attendue si pinned est donnée), puis, si dataPath
// est fourni, l'empreinte du fichier remis ; avec le mot de passe, le contenu déchiffré (écrit dans plainOut si
// non nil).
func Verify(manifestPath, dataPath, password string, pinned ed25519.PublicKey, plainOut io.Writer) (*VerifyReport, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(raw, pinned)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Manifest: m}
	if dataPath == "" {
		return rep, nil
	}
	f, err := os.Open(dataPath)
	if err != nil {
		return rep, err
	}
	defer f.Close()
	fh := &countHash{h: sha256.New()}
	if _, err := io.Copy(fh, f); err != nil {
		return rep, err
	}
	if fh.sum() != m.FileSHA256 || fh.n != m.FileBytes {
		return rep, errors.New("le fichier de données ne correspond pas au manifeste : il a été modifié ou tronqué")
	}
	rep.FileChecked = true
	if m.Encrypted && password == "" {
		return rep, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return rep, err
	}
	var r io.Reader = f
	if m.Encrypted {
		if r, err = NewDecryptReader(f, password); err != nil {
			return rep, err
		}
	}
	ph := &countHash{h: sha256.New()}
	var dst io.Writer = ph
	if plainOut != nil {
		dst = io.MultiWriter(ph, plainOut)
	}
	if _, err := io.Copy(dst, r); err != nil {
		return rep, err
	}
	if ph.sum() != m.PlainSHA256 || ph.n != m.PlainBytes {
		return rep, errors.New("le contenu déchiffré ne correspond pas au manifeste")
	}
	rep.PlainChecked = true
	return rep, nil
}

// rowNumber rend le numéro d'une ligne tel qu'il figure dans l'export : pour une ligne que l'Admin a reçue d'une passerelle,
// celui qu'elle a chez la passerelle (ADR 0018), sinon celui de la base.
func rowNumber(r logstore.Row) int64 {
	if r.SourceID > 0 {
		return r.SourceID
	}
	return r.ID
}
