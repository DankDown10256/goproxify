// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/launcher"
	"github.com/vincamok/goproxify/internal/sqltime"
)

const (
	// joinTicketTTL : un ticket d'installation vit peu, il est recréé à chaque affichage (ADR 0019, section 4).
	joinTicketTTL  = 15 * time.Minute
	joinTicketKind = "launcher-join"
	// agentStatusTimeout borne l'interrogation des passerelles pour l'état des Agents.
	agentStatusTimeout = 2 * time.Second
)

var (
	errNoArchitecture = errors.New("architecture.json indisponible")
	// ErrHostUnknown : l'hôte n'est pas déclaré dans architecture.json.
	ErrHostUnknown = errors.New("hôte inconnu dans l'architecture")
	// ErrHostJoined : tous les nœuds de l'hôte sont déjà en ligne, il n'y a rien à installer.
	ErrHostJoined = errors.New("hôte déjà intégré")
)

// HostsHandler expose les hôtes déclarés dans architecture.json et leur installation par ticket (ADR 0019, étape 4) :
// GET /api/v1/hosts, POST /api/v1/hosts/{name}/join-ticket, et GET /api/v1/join/{token} (public, le ticket fait foi).
type HostsHandler struct {
	DB    *sql.DB
	Arch  *archstore.Store
	Nodes *NodesHandler
	Log   *slog.Logger
	// PublicURL donne la base publique de l'Admin, comme pour les tickets d'intégration.
	PublicURL func(r *http.Request) string
	// Root donne le secret racine (GPX_PAIRING_SECRET) dont dérivent les clés remises aux hôtes ; vide = non configuré.
	Root func() string
	// CertFile donne le certificat TLS servi par l'Admin ; vide = l'Admin ne sert pas lui-même en TLS.
	CertFile func() string
	// Registry, Tag et TZ règlent les images et le fuseau des hôtes installés (GPX_DEPLOY_REGISTRY, GPX_DEPLOY_TAG, TZ).
	Registry, Tag, TZ string
	// Now sert aux tests ; time.Now par défaut.
	Now func() time.Time
}

func (h *HostsHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// HostNode est l'état d'un nœud (passerelle ou Agent) d'un hôte : online, ou declared s'il n'est jamais venu.
type HostNode struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

// HostTicketInfo est le ticket d'installation en cours de validité d'un hôte (le jeton n'est jamais relisible).
type HostTicketInfo struct {
	ExpiresAt string `json:"expires_at"`
}

// HostRow est un hôte de l'architecture.
type HostRow struct {
	Name   string          `json:"name"`
	Addr   string          `json:"addr"`
	Roles  []string        `json:"roles"`
	Group  string          `json:"group,omitempty"`
	Status string          `json:"status"` // pending | partial | joined
	Nodes  []HostNode      `json:"nodes"`
	Ticket *HostTicketInfo `json:"ticket,omitempty"`
}

// JoinTicket est ce que l'Admin remet pour installer un hôte : l'adresse où récupérer sa description et l'empreinte
// du certificat de l'Admin à vérifier avant d'y présenter le jeton.
type JoinTicket struct {
	Host        string   `json:"host"`
	NodeNames   []string `json:"node_names"`
	Token       string   `json:"token"`
	ExpiresAt   string   `json:"expires_at"`
	SpecURL     string   `json:"spec_url"`
	Fingerprint string   `json:"fingerprint"`
	// TriggerURL est ce que le QR code encode : la page de confirmation du launcher de l'hôte, qui attend sur son port
	// 8080. Elle porte l'Admin, le jeton et l'empreinte. Vide si l'Admin n'a pas d'adresse publique en https.
	TriggerURL string `json:"trigger_url,omitempty"`
	QRCode     string `json:"qr_code,omitempty"` // PNG de TriggerURL, en data URL
	// ListenCommand lance le launcher de l'hôte en attente du QR ; JoinCommand l'installe tout de suite, sans QR.
	ListenCommand string `json:"listen_command"`
	JoinCommand   string `json:"join_command"`
	Warning       string `json:"warning,omitempty"`
}

func (h *HostsHandler) topology() (*launcher.Topology, error) {
	// Les tickets d'intégration partagent leur table : elle est créée à la première utilisation.
	(&BootstrapHandler{DB: h.DB}).ensureTable()
	if h.Arch == nil {
		return nil, errNoArchitecture
	}
	arch, err := h.Arch.Get()
	if err != nil {
		return nil, err
	}
	return launcher.TopologyFromArchitecture(arch), nil
}

// liveStatuses : l'état de chaque nœud connu, par nom. Une passerelle vient de la table des battements, un Agent de sa
// passerelle.
func (h *HostsHandler) liveStatuses(r *http.Request) map[string]string {
	out := map[string]string{}
	if rows, err := h.DB.QueryContext(r.Context(), `SELECT node_name, status FROM nodes WHERE role='edge'`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, status string
			if rows.Scan(&name, &status) == nil {
				out[name] = status
			}
		}
	}
	if h.Nodes != nil {
		// Une passerelle pas encore installée ne répond pas, et le client interne attend deux minutes : on ne l'attend pas.
		// Un état incomplet (ses Agents « déclarés ») vaut mieux qu'une page qui pend.
		ctx, cancel := context.WithTimeout(r.Context(), agentStatusTimeout)
		defer cancel()
		for _, a := range h.Nodes.fetchAgentNodesFromEdges(ctx) {
			out[a.NodeName] = a.Status
		}
	}
	return out
}

// activeTicket : le ticket d'installation en cours de validité d'un hôte.
func (h *HostsHandler) activeTicket(r *http.Request, host string) *HostTicketInfo {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT payload, expires_at FROM bootstrap_tickets WHERE host_name=? AND expires_at > ? ORDER BY expires_at DESC`,
		host, sqltime.Format(h.now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		var exp time.Time
		var p struct {
			Kind string `json:"kind"`
		}
		if rows.Scan(&payload, &exp) == nil && json.Unmarshal([]byte(payload), &p) == nil && p.Kind == joinTicketKind {
			return &HostTicketInfo{ExpiresAt: exp.UTC().Format(time.RFC3339)}
		}
	}
	return nil
}

// List rend les hôtes déclarés, leur état et leur ticket en cours.
func (h *HostsHandler) List(r *http.Request) ([]HostRow, error) {
	topo, err := h.topology()
	if err != nil {
		return nil, err
	}
	live := h.liveStatuses(r)
	out := make([]HostRow, 0, len(topo.Hosts))
	for _, host := range topo.Hosts {
		row := HostRow{Name: host.Name, Addr: host.Addr, Roles: host.Roles, Group: host.Group, Nodes: []HostNode{}}
		online := 0
		for _, role := range []string{launcher.RoleEdge, launcher.RoleAgent} {
			if !host.Has(role) {
				continue
			}
			name := topo.EdgeName(host)
			if role == launcher.RoleAgent {
				name = topo.AgentName(host)
			}
			status := live[name]
			if status == "" {
				status = "declared"
			}
			if status == "online" {
				online++
			}
			row.Nodes = append(row.Nodes, HostNode{Name: name, Role: role, Status: status})
		}
		row.Status = hostStatus(online, len(row.Nodes))
		if row.Status != "joined" {
			row.Ticket = h.activeTicket(r, host.Name)
		}
		out = append(out, row)
	}
	return out, nil
}

func hostStatus(online, total int) string {
	switch {
	case total > 0 && online == total:
		return "joined"
	case online > 0:
		return "partial"
	}
	return "pending"
}

// adminFingerprint : empreinte SHA-256 (hexadécimal minuscule) du certificat que l'Admin sert lui-même, vide s'il n'en
// sert pas (reverse proxy : la chaîne de confiance du système suffit).
func (h *HostsHandler) adminFingerprint() string {
	if h.CertFile == nil {
		return ""
	}
	path := strings.TrimSpace(h.CertFile())
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// CreateTicket crée un ticket d'installation pour l'hôte : 15 minutes, à usage unique, listant les nœuds de l'hôte, qui
// sont acceptés automatiquement tant qu'il vaut. Il remplace le précédent de l'hôte.
func (h *HostsHandler) CreateTicket(r *http.Request, name string) (*JoinTicket, error) {
	topo, err := h.topology()
	if err != nil {
		return nil, err
	}
	host, ok := topo.Host(name)
	if !ok {
		return nil, ErrHostUnknown
	}
	names := topo.NodeNames(host)
	live := h.liveStatuses(r)
	online := 0
	for _, n := range names {
		if live[n] == "online" {
			online++
		}
	}
	if online == len(names) {
		return nil, ErrHostJoined
	}

	tok, err := randomBootstrapToken()
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]any{
		"kind": joinTicketKind, "host": host.Name, "node_names": names, "auto_accept": true,
	})
	exp := h.now().UTC().Add(joinTicketTTL)
	// Un seul ticket par hôte : le précédent cesse de valoir dès que le suivant est affiché.
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM bootstrap_tickets WHERE host_name=? AND payload LIKE ?`,
		host.Name, `%"kind":"`+joinTicketKind+`"%`); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO bootstrap_tickets(token, host_name, edge_endpoint, payload, expires_at) VALUES(?,?,?,?,?)`,
		tok, host.Name, "", string(payload), sqltime.Format(exp)); err != nil {
		return nil, err
	}

	base := ""
	if h.PublicURL != nil {
		base = strings.TrimRight(strings.TrimSpace(h.PublicURL(r)), "/")
	}
	t := &JoinTicket{
		Host: host.Name, NodeNames: names, Token: tok, ExpiresAt: exp.Format(time.RFC3339),
		SpecURL: base + "/api/v1/join/" + url.PathEscape(tok), Fingerprint: h.adminFingerprint(),
	}
	image := launcher.Env{Registry: h.Registry, Tag: h.Tag}.Image("launcher")
	const sock = "-v /var/run/docker.sock:/var/run/docker.sock "
	t.ListenCommand = fmt.Sprintf("docker run --rm -p %d:%d %s%s", launcher.DefaultListenPort, launcher.DefaultListenPort, sock, image)
	t.JoinCommand = "docker run --rm " + sock + image + " join " + t.SpecURL
	if t.Fingerprint != "" {
		t.JoinCommand += " --fingerprint " + t.Fingerprint
	}

	// Le launcher n'accepte qu'un Admin en https : un lien vers un Admin en clair serait refusé, autant ne pas le produire.
	if !strings.HasPrefix(base, "https://") {
		t.Warning = "l'Admin n'a pas d'adresse publique en https (GPX_ADMIN_PUBLIC_URL) : ni QR code ni lien de déclenchement, et la description ne doit pas transiter en clair"
		return t, nil
	}
	q := url.Values{"admin": {base}, "token": {tok}, "host": {host.Name}, "roles": {strings.Join(host.Roles, ",")}}
	if t.Fingerprint != "" {
		q.Set("fp", t.Fingerprint)
	}
	t.TriggerURL = fmt.Sprintf("http://%s/join?%s", net.JoinHostPort(host.Addr, fmt.Sprint(launcher.DefaultListenPort)), q.Encode())
	if png, err := qrcode.Encode(t.TriggerURL, qrcode.Medium, 256); err == nil {
		t.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	return t, nil
}

// ServeList : GET /api/v1/hosts.
func (h *HostsHandler) ServeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	rows, err := h.List(r)
	if err != nil {
		h.Log.Error("hosts: lecture de l'architecture", "err", err)
		http.Error(w, "architecture illisible", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rows)
}

// ServeCreateTicket : POST /api/v1/hosts/{name}/join-ticket.
func (h *HostsHandler) ServeCreateTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	t, err := h.CreateTicket(r, r.PathValue("name"))
	switch {
	case errors.Is(err, ErrHostUnknown):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, ErrHostJoined):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		h.Log.Error("hosts: création du ticket", "host", r.PathValue("name"), "err", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
	default:
		jsonOK(w, t)
	}
}

// ServeSpec : GET /api/v1/join/{token}. Public : le ticket, secret et à durée courte, fait foi. Rend la description de
// l'hôte (voir internal/deploy), clés dérivées comprises ; elle ne doit être servie qu'en TLS. Lire la description ne
// consomme pas le ticket : il l'est quand les nœuds de l'hôte arrivent (ConsumeBootstrapTicket).
func (h *HostsHandler) ServeSpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	(&BootstrapHandler{DB: h.DB}).ensureTable()
	var payload string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT payload FROM bootstrap_tickets WHERE token=? AND expires_at > ?`,
		r.PathValue("token"), sqltime.Format(h.now())).Scan(&payload)
	var p struct {
		Kind string `json:"kind"`
		Host string `json:"host"`
	}
	if err != nil || json.Unmarshal([]byte(payload), &p) != nil || p.Kind != joinTicketKind {
		http.Error(w, "ticket inconnu ou expiré", http.StatusNotFound)
		return
	}

	root := ""
	if h.Root != nil {
		root = h.Root()
	}
	if root == "" {
		h.Log.Error("hosts: secret racine absent, description impossible", "host", p.Host)
		http.Error(w, "secret racine non configuré sur l'Admin", http.StatusInternalServerError)
		return
	}
	topo, err := h.topology()
	if err != nil {
		http.Error(w, "architecture illisible", http.StatusInternalServerError)
		return
	}
	spec, err := topo.HostSpec(p.Host, launcher.Env{
		Secrets: &launcher.Secrets{Root: root}, Registry: h.Registry, Tag: h.Tag, TZ: h.TZ,
	})
	if err != nil {
		h.Log.Warn("hosts: description impossible", "host", p.Host, "err", err)
		http.Error(w, "hôte inconnu dans l'architecture", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, spec)
}
