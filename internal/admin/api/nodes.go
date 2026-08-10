// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/auth"
)

// NodesHandler gère la liste des nœuds et le déclenchement des mises à jour.
// Les nœuds de type "core" sont lus depuis la table nodes (heartbeat Core→Admin).
// Les nœuds de type "agent" sont agrégés depuis les Cores via GET /internal/v1/nodes.
type NodesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type nodeRow struct {
	ID                string    `json:"id"`
	NodeName          string    `json:"node_name"`
	DisplayName       string    `json:"display_name"`
	Role              string    `json:"role"`
	Version           string    `json:"version"`
	Endpoint          string    `json:"endpoint"`
	CPUPCT            *float64  `json:"cpu_pct,omitempty"`
	MemPCT            *float64  `json:"mem_pct,omitempty"`
	Status            string    `json:"status"`
	Region            string    `json:"region,omitempty"`
	Environment       string    `json:"environment,omitempty"`
	Tags              []string  `json:"tags"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	ContainerRuntimes []string  `json:"container_runtimes,omitempty"`
	TargetCore        string    `json:"target_core,omitempty"`
}

func (h *NodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodGet && id == "meta" && action == "regions":
		h.metaValues(w, r, "region")
	case r.Method == http.MethodGet && id == "meta" && action == "environments":
		h.metaValues(w, r, "environment")
	case r.Method == http.MethodGet && id != "" && action == "":
		h.get(w, r, id)
	case r.Method == http.MethodPatch && id != "" && action == "":
		h.patch(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "accept":
		h.acceptPending(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "reject":
		h.rejectPending(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "update":
		h.triggerUpdate(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "rollback":
		h.triggerRollback(w, r, id)
	case r.Method == http.MethodPost && id != "" && action == "rescan":
		h.triggerRescan(w, r, id)
	case r.Method == http.MethodDelete && id != "" && action == "":
		h.deleteNode(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func scanNode(rows interface {
	Scan(...any) error
}, n *nodeRow) error {
	var cpuPct, memPct sql.NullFloat64
	var runtimes, tags string
	if err := rows.Scan(&n.ID, &n.NodeName, &n.DisplayName, &n.Role, &n.Version, &n.Endpoint,
		&cpuPct, &memPct, &n.Status, &n.Region, &n.Environment, &tags,
		&n.LastSeenAt, &runtimes); err != nil {
		return err
	}
	if cpuPct.Valid {
		n.CPUPCT = &cpuPct.Float64
	}
	if memPct.Valid {
		n.MemPCT = &memPct.Float64
	}
	n.Tags = []string{}
	if tags != "" && tags != "[]" {
		json.Unmarshal([]byte(tags), &n.Tags) //nolint:errcheck
	}
	if runtimes != "" && runtimes != "[]" {
		json.Unmarshal([]byte(runtimes), &n.ContainerRuntimes) //nolint:errcheck
	}
	if n.DisplayName == "" {
		n.DisplayName = n.NodeName
	}
	return nil
}

const nodeSelectCols = `id, node_name,
	COALESCE(NULLIF(display_name,''), node_name),
	role, version, endpoint,
	cpu_pct, mem_pct, status,
	COALESCE(region,''), COALESCE(environment,''), COALESCE(tags,'[]'),
	last_seen_at, COALESCE(container_runtimes,'')`

func (h *NodesHandler) list(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	result := make([]nodeRow, 0)

	// Nœuds Core depuis la DB Admin (heartbeat Core→Admin)
	liveNames := map[string]bool{} // pour dédupliquer avec declared_nodes
	if role == "" || role == "core" {
		q := `SELECT ` + nodeSelectCols + ` FROM nodes WHERE role='core' ORDER BY node_name`
		rows, err := h.DB.QueryContext(r.Context(), q)
		if err != nil && !isCtxErr(err) {
			h.Log.Error("nodes: list cores", "err", err)
		}
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var n nodeRow
				if err := scanNode(rows, &n); err != nil {
					continue
				}
				liveNames[n.NodeName] = true
				result = append(result, n)
			}
		}
	}

	// Nœuds Agent : agrégés depuis chaque Core via GET /internal/v1/nodes
	if role == "" || role == "agent" {
		agentNodes := h.fetchAgentNodesFromCores(r.Context())
		for _, n := range agentNodes {
			liveNames[n.NodeName] = true
		}
		result = append(result, agentNodes...)
	}

	// Nœuds en attente d'acceptation (pairing_secret validé, admin pas encore cliqué).
	pendingRows, _ := h.DB.QueryContext(r.Context(),
		`SELECT id, node_name, role, version, remote_addr, created_at
		 FROM pending_nodes WHERE status='pending' ORDER BY created_at`)
	if pendingRows != nil {
		defer pendingRows.Close()
		for pendingRows.Next() {
			var id, name, prole, version, remoteAddr string
			var createdAt time.Time
			if pendingRows.Scan(&id, &name, &prole, &version, &remoteAddr, &createdAt) != nil {
				continue
			}
			if role != "" && role != prole {
				continue
			}
			result = append(result, nodeRow{
				ID:          id,
				NodeName:    name,
				DisplayName: name,
				Role:        prole,
				Version:     version,
				Status:      "pending",
				Endpoint:    remoteAddr,
				Tags:        []string{},
				LastSeenAt:  createdAt,
			})
		}
	}

	// Nœuds déclarés via l'assistant Infrastructure (pas encore connectés).
	// On les inclut uniquement s'ils n'ont pas encore de heartbeat live.
	declRows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, role, name, region, environment, config FROM declared_nodes ORDER BY created_at`)
	if err == nil {
		defer declRows.Close()
		for declRows.Next() {
			var id, drole, name, region, env, cfg string
			if declRows.Scan(&id, &drole, &name, &region, &env, &cfg) != nil {
				continue
			}
			if role != "" && role != drole {
				continue
			}
			if liveNames[name] {
				continue // déjà représenté par un nœud live
			}
			// Extraire target_core du config JSON (pour la topologie)
			var targetCore string
			if cfg != "" {
				var cfgMap map[string]any
				if json.Unmarshal([]byte(cfg), &cfgMap) == nil {
					if tc, ok := cfgMap["target_core"].(string); ok {
						targetCore = tc
					}
				}
			}
			now := time.Now()
			result = append(result, nodeRow{
				ID:          id,
				NodeName:    name,
				DisplayName: name,
				Role:        drole,
				Status:      "declared",
				Region:      region,
				Environment: env,
				TargetCore:  targetCore,
				Tags:        []string{},
				LastSeenAt:  now,
			})
		}
	}

	jsonOK(w, result)
}

// fetchAgentNodesFromCores interroge tous les Cores connus et agrège leurs nœuds Agent.
func (h *NodesHandler) fetchAgentNodesFromCores(ctx context.Context) []nodeRow {
	// Récupère les endpoints + tokens + node_name des Cores actifs directement depuis tokens
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_endpoint, token, COALESCE(node_name,'') FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type coreToken struct{ nodeName, endpoint, token string }
	var cores []coreToken
	seenEndpoints := map[string]bool{}
	for rows.Next() {
		var c coreToken
		if rows.Scan(&c.endpoint, &c.token, &c.nodeName) == nil && c.endpoint != "" {
			if seenEndpoints[c.endpoint] {
				continue // évite d'appeler deux fois le même Core (tokens en doublon)
			}
			seenEndpoints[c.endpoint] = true
			c.token = auth.PlainNodeToken(c.token)
			cores = append(cores, c)
		}
	}

	var mu sync.Mutex
	var result []nodeRow
	var wg sync.WaitGroup

	for _, c := range cores {
		wg.Add(1)
		go func(ep, tok, coreName string) {
			defer wg.Done()
			nodes := fetchNodesFromCore(ctx, ep, tok, coreName)
			mu.Lock()
			result = append(result, nodes...)
			mu.Unlock()
		}(c.endpoint, c.token, c.nodeName)
	}
	wg.Wait()
	return result
}

func fetchNodesFromCore(ctx context.Context, coreEndpoint, token, coreName string) []nodeRow {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		coreEndpoint+"/internal/v1/nodes", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("nodes: Core injoignable pour liste agents", "core", coreName, "endpoint", coreEndpoint, "err", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("nodes: Core a refusé la liste agents", "core", coreName, "endpoint", coreEndpoint, "status", resp.StatusCode)
		return nil
	}

	var raw []struct {
		NodeName          string    `json:"node_name"`
		Role              string    `json:"role"`
		Version           string    `json:"version"`
		Endpoint          string    `json:"endpoint"`
		CPUPCT            float64   `json:"cpu_pct"`
		MemPCT            float64   `json:"mem_pct"`
		Status            string    `json:"status"`
		ContainerRuntimes []string  `json:"container_runtimes"`
		LastSeenAt        time.Time `json:"last_seen_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil
	}
	result := make([]nodeRow, 0, len(raw))
	for _, n := range raw {
		cpu := n.CPUPCT
		mem := n.MemPCT
		result = append(result, nodeRow{
			ID:                n.NodeName,
			NodeName:          n.NodeName,
			Role:              "agent",
			Version:           n.Version,
			Endpoint:          n.Endpoint,
			CPUPCT:            &cpu,
			MemPCT:            &mem,
			Status:            n.Status,
			LastSeenAt:        n.LastSeenAt,
			ContainerRuntimes: n.ContainerRuntimes,
			TargetCore:        coreName,
		})
	}
	return result
}

func (h *NodesHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var n nodeRow
	err := scanNode(h.DB.QueryRowContext(r.Context(),
		`SELECT `+nodeSelectCols+` FROM nodes WHERE id=? OR node_name=?`, id, id,
	), &n)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, n)
}

// patch met à jour les métadonnées modifiables d'un nœud (display_name, region, environment, tags).
func (h *NodesHandler) deleteNode(w http.ResponseWriter, r *http.Request, id string) {
	// Récupère le node_name avant suppression pour révoquer le token associé.
	var nodeName string
	_ = h.DB.QueryRowContext(r.Context(), `SELECT node_name FROM nodes WHERE id=?`, id).Scan(&nodeName)

	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM nodes WHERE id=?`, id)
	if err != nil {
		h.Log.Error("nodes: delete", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}

	// Révoque le token associé à ce node_name (si trouvé).
	if nodeName != "" {
		h.DB.ExecContext(r.Context(), //nolint:errcheck
			`UPDATE tokens SET revoked=1 WHERE node_name=? AND role='core' AND revoked=0`, nodeName)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *NodesHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		DisplayName *string  `json:"display_name"`
		Region      *string  `json:"region"`
		Environment *string  `json:"environment"`
		Tags        []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	// Construction dynamique du SET pour ne mettre à jour que les champs fournis.
	sets := []string{}
	args := []any{}
	if req.DisplayName != nil {
		sets = append(sets, "display_name=?")
		args = append(args, *req.DisplayName)
	}
	if req.Region != nil {
		sets = append(sets, "region=?")
		args = append(args, *req.Region)
	}
	if req.Environment != nil {
		sets = append(sets, "environment=?")
		args = append(args, *req.Environment)
	}
	if req.Tags != nil {
		b, _ := json.Marshal(req.Tags)
		sets = append(sets, "tags=?")
		args = append(args, string(b))
	}
	if len(sets) == 0 {
		http.Error(w, "aucun champ à mettre à jour", http.StatusBadRequest)
		return
	}

	q := "UPDATE nodes SET " + strings.Join(sets, ", ") + " WHERE id=? OR node_name=?"
	args = append(args, id, id)
	res, err := h.DB.ExecContext(r.Context(), q, args...)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("nodes: patch", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.node_not_found")
		return
	}
	h.get(w, r, id)
}

// metaValues retourne les valeurs distinctes non vides d'une colonne (pour l'autocomplétion).
func (h *NodesHandler) metaValues(w http.ResponseWriter, r *http.Request, col string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT DISTINCT `+col+` FROM nodes WHERE `+col+` != '' ORDER BY `+col,
	)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	values := make([]string, 0)
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && v != "" {
			values = append(values, v)
		}
	}
	jsonOK(w, values)
}

type updateTriggerRequest struct {
	Container string `json:"container"` // nom du conteneur à mettre à jour (vide = tous)
	Prune     bool   `json:"prune"`
}

// triggerUpdate envoie une commande de mise à jour à l'Agent via le relay Core.
// Si la cible est un Core, on demande à un Agent rattaché (même hôte / docker.sock)
// de mettre à jour le conteneur du Core.
func (h *NodesHandler) triggerUpdate(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req updateTriggerRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	payload := map[string]any{
		"action":    "update",
		"container": req.Container,
		"prune":     req.Prune,
	}
	target, err := h.resolveCommandTarget(r.Context(), nodeID, req.Container)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("nodes: trigger update", "node", nodeID, "err", err)
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload["container"] = target.container
	if err := h.relayToAgent(r.Context(), target.agentName, payload); err != nil {
		if !isCtxErr(err) {
			h.Log.Error("nodes: trigger update", "node", nodeID, "agent", target.agentName, "err", err)
		}
		writeErr(w, r, http.StatusBadGateway, "api.err.agent_unreachable")
		return
	}
	h.Log.Info("nodes: update déclenché", "node", nodeID, "via_agent", target.agentName, "container", target.container)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "triggered", "node": nodeID, "via_agent": target.agentName})
}

// triggerRollback envoie une commande de rollback à l'Agent via le relay Core.
func (h *NodesHandler) triggerRollback(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req struct {
		Container string `json:"container"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	target, err := h.resolveCommandTarget(r.Context(), nodeID, req.Container)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("nodes: trigger rollback", "node", nodeID, "err", err)
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload := map[string]any{"action": "rollback", "container": target.container}
	if err := h.relayToAgent(r.Context(), target.agentName, payload); err != nil {
		if !isCtxErr(err) {
			h.Log.Error("nodes: trigger rollback", "node", nodeID, "err", err)
		}
		writeErr(w, r, http.StatusBadGateway, "api.err.agent_unreachable")
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rollback_triggered", "node": nodeID, "via_agent": target.agentName})
}

type commandTarget struct {
	agentName string
	container string
}

// resolveCommandTarget détermine l'Agent à contacter et le conteneur cible.
// Pour un Agent : l'Agent lui-même (container vide = self).
// Pour un Core : un Agent rattaché à ce Core, avec container = nom du Core.
func (h *NodesHandler) resolveCommandTarget(ctx context.Context, nodeID, container string) (commandTarget, error) {
	if h.isCoreNode(ctx, nodeID) {
		agentName := h.findAgentOnCore(ctx, nodeID)
		if agentName == "" {
			return commandTarget{}, fmt.Errorf("aucun Agent rattaché à ce Core pour exécuter la mise à jour — déployez un Agent sur le même hôte (docker.sock)")
		}
		c := container
		if c == "" {
			c = nodeID // nom du conteneur Core (= node_name)
		}
		return commandTarget{agentName: agentName, container: c}, nil
	}
	return commandTarget{agentName: nodeID, container: container}, nil
}

func (h *NodesHandler) isCoreNode(ctx context.Context, nodeID string) bool {
	var role string
	err := h.DB.QueryRowContext(ctx,
		`SELECT role FROM nodes WHERE id=? OR node_name=?`, nodeID, nodeID,
	).Scan(&role)
	if err == nil && role == "core" {
		return true
	}
	err = h.DB.QueryRowContext(ctx,
		`SELECT role FROM tokens WHERE (id=? OR node_name=?) AND role='core' AND revoked=0 LIMIT 1`,
		nodeID, nodeID,
	).Scan(&role)
	return err == nil && role == "core"
}

func (h *NodesHandler) findAgentOnCore(ctx context.Context, coreName string) string {
	agents := h.fetchAgentNodesFromCores(ctx)
	var fallback string
	for _, a := range agents {
		if a.TargetCore != coreName {
			continue
		}
		if a.Status == "online" {
			return a.NodeName
		}
		if fallback == "" {
			fallback = a.NodeName
		}
	}
	return fallback
}

// relayToAgent envoie une commande JSON à un Agent via le relay Core.
// Tous les appels Admin→Agent passent par ce relay (cross-machine Docker bridge NAT).
func (h *NodesHandler) relayToAgent(ctx context.Context, nodeID string, payload any) error {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_endpoint, token FROM tokens WHERE role='core' AND revoked=0 AND node_endpoint != ''`)
	if err != nil {
		return fmt.Errorf("DB: %w", err)
	}
	defer rows.Close()

	type coreEntry struct{ endpoint, token string }
	var cores []coreEntry
	for rows.Next() {
		var c coreEntry
		if rows.Scan(&c.endpoint, &c.token) == nil && c.endpoint != "" {
			c.token = auth.PlainNodeToken(c.token)
			cores = append(cores, c)
		}
	}
	if len(cores) == 0 {
		return fmt.Errorf("aucun Core disponible")
	}

	body, _ := json.Marshal(payload)
	for _, c := range cores {
		url := c.endpoint + "/internal/v1/agent/" + nodeID + "/command"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			h.Log.Warn("nodes: relay — Core injoignable", "core", c.endpoint, "err", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
	}
	return fmt.Errorf("agent injoignable")
}

// triggerRescan demande à l'Agent de relancer un scan complet de ses conteneurs.
func (h *NodesHandler) triggerRescan(w http.ResponseWriter, r *http.Request, nodeID string) {
	if err := h.relayToAgent(r.Context(), nodeID, map[string]string{"action": "rescan"}); err != nil {
		h.Log.Warn("nodes: rescan échoué", "node", nodeID, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.Log.Info("nodes: rescan déclenché", "node", nodeID)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rescan_started", "node": nodeID})
}

func (h *NodesHandler) nodeEndpoint(ctx context.Context, nodeID string) (string, error) {
	// Cherche d'abord dans la DB Admin (Cores)
	var endpoint string
	err := h.DB.QueryRowContext(ctx,
		`SELECT endpoint FROM nodes WHERE id=? OR node_name=?`, nodeID, nodeID,
	).Scan(&endpoint)
	if err == nil && endpoint != "" {
		return endpoint, nil
	}
	// Fallback : agents vivent en mémoire dans les Cores, pas dans la DB Admin
	for _, n := range h.fetchAgentNodesFromCores(ctx) {
		if n.NodeName == nodeID || n.ID == nodeID {
			if n.Endpoint != "" {
				return n.Endpoint, nil
			}
		}
	}
	return "", fmt.Errorf("nœud introuvable : %s", nodeID)
}

func (h *NodesHandler) pushToAgent(ctx context.Context, endpoint string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/internal/v1/command", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := os.Getenv("GPX_PAIRING_SECRET"); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("agent: non autorisé")
	}
	return nil
}

// acceptPending accepte un nœud en attente : génère un auth_token, le stocke dans tokens
// et le met à disposition du nœud via handlePairStatus.
// L'identifiant peut être l'UUID pending OU le node_name (idempotence UI / race).
func (h *NodesHandler) acceptPending(w http.ResponseWriter, r *http.Request, id string) {
	var pendingID, nodeName, role, status string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, node_name, role, status FROM pending_nodes WHERE id=?`, id,
	).Scan(&pendingID, &nodeName, &role, &status)
	if err == sql.ErrNoRows {
		// Fallback : lookup par node_name (UI stale ou acceptation déjà faite avec mauvais id)
		err = h.DB.QueryRowContext(r.Context(),
			`SELECT id, node_name, role, status FROM pending_nodes WHERE node_name=? ORDER BY created_at DESC LIMIT 1`, id,
		).Scan(&pendingID, &nodeName, &role, &status)
	}
	if err == sql.ErrNoRows {
		// Déjà accepté et éventuellement nettoyé, ou jamais créé : vérifier tokens existants.
		var tokRole string
		terr := h.DB.QueryRowContext(r.Context(),
			`SELECT role FROM tokens WHERE node_name=? AND revoked=0 LIMIT 1`, id,
		).Scan(&tokRole)
		if terr == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":        id,
				"node_name": id,
				"role":      tokRole,
				"status":    "accepted",
			})
			return
		}
		http.Error(w, "nœud pending introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	id = pendingID
	// Idempotence : si déjà traité, on évite un faux négatif côté UI.
	if status == "accepted" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":        id,
			"node_name": nodeName,
			"role":      role,
			"status":    "accepted",
		})
		return
	}
	if status == "rejected" {
		http.Error(w, "nœud pending déjà rejeté", http.StatusConflict)
		return
	}

	tok := auth.GenerateToken(role, nodeName)
	tokenID := uuid.New().String()

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	stored, hash := auth.PrepareNodeTokenForStore(tok)
	if _, err = tx.ExecContext(r.Context(),
		`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name) VALUES (?, ?, ?, ?, 'admin', ?)`,
		tokenID, stored, hash, role, nodeName,
	); err != nil {
		h.Log.Error("nodes: accept pending — insertion token", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if _, err = tx.ExecContext(r.Context(),
		`UPDATE pending_nodes SET status='accepted', token=? WHERE id=?`, tok, id,
	); err != nil {
		h.Log.Error("nodes: accept pending — mise à jour status", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	h.Log.Info("nodes: nœud accepté", "node", nodeName, "role", role, "id", id)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":        id,
		"node_name": nodeName,
		"role":      role,
		"status":    "accepted",
	})
}

// rejectPending refuse un nœud en attente.
func (h *NodesHandler) rejectPending(w http.ResponseWriter, r *http.Request, id string) {
	var pendingID, status string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, status FROM pending_nodes WHERE id=?`, id,
	).Scan(&pendingID, &status)
	if err == sql.ErrNoRows {
		err = h.DB.QueryRowContext(r.Context(),
			`SELECT id, status FROM pending_nodes WHERE node_name=? ORDER BY created_at DESC LIMIT 1`, id,
		).Scan(&pendingID, &status)
	}
	if err == sql.ErrNoRows {
		// Déjà absent : idempotent
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	id = pendingID
	// Idempotence : un nœud déjà rejeté ne doit pas générer d'erreur.
	if status == "rejected" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if status == "accepted" {
		http.Error(w, "nœud pending déjà accepté", http.StatusConflict)
		return
	}
	if _, err = h.DB.ExecContext(r.Context(),
		`UPDATE pending_nodes SET status='rejected' WHERE id=?`, id,
	); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	h.Log.Info("nodes: nœud refusé", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- Heartbeat handler (appelé par l'Agent) --------------------------------

// HeartbeatHandler reçoit les heartbeats des Agents et des Cores.
type HeartbeatHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type heartbeatPayload struct {
	NodeName          string   `json:"node_name"`
	Role              string   `json:"role"`
	Version           string   `json:"version"`
	Endpoint          string   `json:"endpoint"`
	CPUPCT            float64  `json:"cpu_pct"`
	MemPCT            float64  `json:"mem_pct"`
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
}

func (h *HeartbeatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	var hb heartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if hb.NodeName == "" {
		http.Error(w, "node_name requis", http.StatusBadRequest)
		return
	}

	// Remplace les IPs Docker bridge (172.16.0.0/12) par l'IP source réelle.
	if hb.Endpoint != "" {
		if u, pErr := url.Parse(hb.Endpoint); pErr == nil {
			if host := u.Hostname(); host != "" {
				if ip := net.ParseIP(host); ip != nil {
					_, docker172, _ := net.ParseCIDR("172.16.0.0/12")
					if docker172 != nil && docker172.Contains(ip) {
						if srcIP, _, sErr := net.SplitHostPort(r.RemoteAddr); sErr == nil {
							u.Host = net.JoinHostPort(srcIP, u.Port())
							hb.Endpoint = u.String()
						}
					}
				}
			}
		}
	}

	runtimesJSON := "[]"
	if len(hb.ContainerRuntimes) > 0 {
		if b, err := json.Marshal(hb.ContainerRuntimes); err == nil {
			runtimesJSON = string(b)
		}
	}

	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO nodes (id, node_name, display_name, role, version, endpoint, cpu_pct, mem_pct, status, last_seen_at, container_runtimes)
		 VALUES (lower(hex(randomblob(8))), ?, ?, ?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, ?)
		 ON CONFLICT(node_name) DO UPDATE SET
		   role=excluded.role, version=excluded.version, endpoint=excluded.endpoint,
		   cpu_pct=excluded.cpu_pct, mem_pct=excluded.mem_pct,
		   status='online', last_seen_at=CURRENT_TIMESTAMP,
		   container_runtimes=excluded.container_runtimes`,
		// display_name, region, environment, tags ne sont PAS écrasés sur UPDATE
		// (l'utilisateur peut les modifier dans l'UI sans que le heartbeat les réinitialise)
		hb.NodeName, hb.NodeName, hb.Role, hb.Version, hb.Endpoint, hb.CPUPCT, hb.MemPCT, runtimesJSON,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("heartbeat: upsert node", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- NodeEvents handler ---------------------------------------------------

// NodeEventsHandler expose l'historique des événements de santé.
type NodeEventsHandler struct {
	DB             *sql.DB
	Log            *slog.Logger
	AlertingEngine interface {
		Emit(alerting.Event)
	}
}

type nodeEvent struct {
	ID          int64     `json:"id"`
	NodeName    string    `json:"node_name"`
	ContainerID string    `json:"container_id,omitempty"`
	EventType   string    `json:"event_type"`
	Detail      string    `json:"detail,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *NodeEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.record(w, r)
		return
	}
	if r.Method == http.MethodGet {
		h.list(w, r)
		return
	}
	writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
}

func (h *NodeEventsHandler) list(w http.ResponseWriter, r *http.Request) {
	nodeFilter := r.URL.Query().Get("node")
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200
	}

	result := h.fetchEventsFromDB(r.Context(), nodeFilter)
	fromCores := h.fetchEventsFromCores(r.Context(), nodeFilter)
	result = append(result, fromCores...)

	// Déduplique (node+type+container+detail+created_at minute)
	seen := map[string]bool{}
	deduped := make([]nodeEvent, 0, len(result))
	for _, e := range result {
		key := fmt.Sprintf("%s|%s|%s|%s|%d", e.NodeName, e.EventType, e.ContainerID, e.Detail, e.CreatedAt.Unix())
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, e)
	}
	sortNodeEvents(deduped)
	if len(deduped) > limit {
		deduped = deduped[:limit]
	}
	jsonOK(w, deduped)
}

func (h *NodeEventsHandler) fetchEventsFromDB(ctx context.Context, nodeFilter string) []nodeEvent {
	q := `SELECT id, node_name, COALESCE(container_id,''), event_type, COALESCE(detail,''), created_at
	      FROM node_events`
	args := []any{}
	if nodeFilter != "" {
		q += ` WHERE node_name=?`
		args = append(args, nodeFilter)
	}
	q += ` ORDER BY created_at DESC LIMIT 200`
	rows, err := h.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []nodeEvent
	for rows.Next() {
		var e nodeEvent
		if rows.Scan(&e.ID, &e.NodeName, &e.ContainerID, &e.EventType, &e.Detail, &e.CreatedAt) != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (h *NodeEventsHandler) fetchEventsFromCores(ctx context.Context, nodeFilter string) []nodeEvent {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_endpoint, token FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return []nodeEvent{}
	}
	defer rows.Close()

	type ct struct{ endpoint, token string }
	var cores []ct
	for rows.Next() {
		var c ct
		if rows.Scan(&c.endpoint, &c.token) == nil {
			c.token = auth.PlainNodeToken(c.token)
			cores = append(cores, c)
		}
	}

	var mu sync.Mutex
	var result []nodeEvent
	var wg sync.WaitGroup
	for _, c := range cores {
		wg.Add(1)
		go func(ep, tok string) {
			defer wg.Done()
			u := ep + "/internal/v1/node-events"
			if nodeFilter != "" {
				u += "?node=" + url.QueryEscape(nodeFilter)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				h.Log.Warn("node_events: Core injoignable", "core", ep, "err", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				h.Log.Warn("node_events: Core HTTP", "core", ep, "status", resp.StatusCode)
				return
			}
			var evs []nodeEvent
			if json.NewDecoder(resp.Body).Decode(&evs) != nil {
				return
			}
			if nodeFilter != "" {
				filtered := evs[:0]
				for _, e := range evs {
					if e.NodeName == nodeFilter {
						filtered = append(filtered, e)
					}
				}
				evs = filtered
			}
			mu.Lock()
			result = append(result, evs...)
			mu.Unlock()
		}(c.endpoint, c.token)
	}
	wg.Wait()
	return result
}

func sortNodeEvents(evs []nodeEvent) {
	n := len(evs)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && evs[j].CreatedAt.After(evs[j-1].CreatedAt); j-- {
			evs[j], evs[j-1] = evs[j-1], evs[j]
		}
	}
}

func (h *NodeEventsHandler) record(w http.ResponseWriter, r *http.Request) {
	var e struct {
		NodeName    string `json:"node_name"`
		ContainerID string `json:"container_id"`
		EventType   string `json:"event_type"`
		Detail      string `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO node_events (node_name, container_id, event_type, detail) VALUES (?, ?, ?, ?)`,
		e.NodeName, e.ContainerID, e.EventType, e.Detail,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("node_events: insert", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	// Émet une alerte pour les événements de scaling et d'escalade de santé.
	if h.AlertingEngine != nil {
		ev := alerting.Event{
			NodeName:  e.NodeName,
			Component: "agent",
			Detail:    map[string]any{"event_type": e.EventType, "detail": e.Detail, "container": e.ContainerID},
		}
		switch {
		case strings.HasPrefix(e.EventType, "scale_"):
			ev.Trigger = alerting.TriggerScaleEvent
			ev.Severity = alerting.SevInfo
		case e.EventType == "health_escalation":
			ev.Trigger = alerting.TriggerHealthEscalation
			ev.Severity = alerting.SevWarning
		}
		if ev.Trigger != "" {
			h.AlertingEngine.Emit(ev)
		}
	}

	w.WriteHeader(http.StatusCreated)
}
