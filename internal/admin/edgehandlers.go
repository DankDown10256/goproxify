// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// --- Routes pour les passerelles -----------------------------------------------

// handlePair traite la première connexion d'un nœud (Passerelle ou Agent) via le pairing_secret.
// Flux : secret validé → nœud mis en état PENDING → Admin accepte → auth_token émis.
// Un nœud déjà accepté (token actif en DB) reçoit son token directement (reconnexion).
// Endpoint public : POST /internal/v1/pair
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	configuredSecret := os.Getenv("GPX_PAIRING_SECRET")

	var req struct {
		Secret   string `json:"secret"`
		NodeName string `json:"node_name"`
		Role     string `json:"role"`
		Version  string `json:"version"`
		TokenID  string `json:"token_id"` // UUID stable depuis edge.json (depuis v0.3.84+)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corps JSON invalide", http.StatusBadRequest)
		return
	}
	if configuredSecret == "" {
		http.Error(w, "pairing non configuré", http.StatusServiceUnavailable)
		return
	}
	if !auth.SecureEqual(configuredSecret, req.Secret) {
		http.Error(w, "secret invalide", http.StatusForbidden)
		return
	}

	role := req.Role
	if role != "edge" && role != "agent" {
		role = "edge"
	}
	nodeName := req.NodeName
	if nodeName == "" {
		if role == "agent" {
			nodeName = "agent-1"
		} else {
			nodeName = "edge-1"
		}
	}

	// Reconnexion par token_id stable (edges avec edge.json v0.3.84+).
	// Si le node_name a changé (renommage), on met à jour la DB et on retourne le token existant.
	if req.TokenID != "" {
		var existingToken, existingName string
		_ = s.db.QueryRowContext(r.Context(),
			`SELECT token, node_name FROM tokens WHERE id=? AND revoked=0 LIMIT 1`,
			req.TokenID,
		).Scan(&existingToken, &existingName)
		if existingToken != "" {
			if existingName != nodeName {
				_, _ = s.db.ExecContext(r.Context(),
					`UPDATE tokens SET node_name=? WHERE id=?`, nodeName, req.TokenID)
				s.log.Info("pair: node renommé via token_id", "old", existingName, "new", nodeName, "id", req.TokenID)
			}
			if plain, err := auth.OpenNodeToken(existingToken); err == nil {
				existingToken = plain
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": existingToken})
			return
		}
	}

	// Reconnexion par node_name (edges sans token_id ou anciens edges).
	var existing string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT token FROM tokens WHERE role=? AND node_name=? AND revoked=0 LIMIT 1`,
		role, nodeName,
	).Scan(&existing)
	if existing != "" {
		if plain, err := auth.OpenNodeToken(existing); err == nil {
			existing = plain
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": existing})
		return
	}

	// Auto-acceptation des passerelles : le pairing secret valide suffit — pas de validation manuelle.
	// La passerelle est déployée par le même opérateur que l'Admin (même docker-compose / infra maîtrisée).
	// Sans cela, une DB Admin fraîche (volume recréé, restart) force l'opérateur à ré-accepter
	// manuellement à chaque fois, même si la passerelle n'a pas changé.
	// Agents déclarés via wizard architecture (auto_accept) : même traitement.
	if configuredSecret != "" && (role == "edge" || role == "agent" || api.NodeAutoAccept(s.db, nodeName)) {
		tok := auth.GenerateToken(role, nodeName)
		// Utilise le token_id fourni par la passerelle si disponible, sinon génère un UUID.
		tokenID := req.TokenID
		if tokenID == "" {
			tokenID = uuid.New().String()
		}
		stored, hash := auth.PrepareNodeTokenForStore(tok)
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name) VALUES (?, ?, ?, ?, 'admin', ?)`,
			tokenID, stored, hash, role, nodeName,
		); err != nil {
			s.log.Error("pair: auto-accept", "err", err, "role", role, "node", nodeName)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Nettoyer un éventuel pending résiduel.
		_, _ = s.db.ExecContext(r.Context(),
			`UPDATE pending_nodes SET status='accepted', token=? WHERE node_name=? AND role=? AND status='pending'`,
			tok, nodeName, role,
		)
		s.log.Info("pair: nœud auto-accepté", "role", role, "node", nodeName, "token_id", tokenID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": tok})
		return
	}

	// Nœud déjà accepté mais en attente de récupération du token.
	var pendingStatus, pendingToken, pendingID string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT id, status, token FROM pending_nodes WHERE node_name=? AND role=?`,
		nodeName, role,
	).Scan(&pendingID, &pendingStatus, &pendingToken)

	if pendingStatus == "accepted" && pendingToken != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": pendingToken})
		return
	}
	if pendingStatus == "rejected" {
		http.Error(w, "connexion refusée par l'administrateur", http.StatusForbidden)
		return
	}

	// Première demande : créer l'entrée pending (idempotent via UNIQUE index).
	if pendingID == "" {
		pendingID = uuid.New().String()
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT OR IGNORE INTO pending_nodes (id, node_name, role, version, remote_addr)
			 VALUES (?, ?, ?, ?, ?)`,
			pendingID, nodeName, role, req.Version, r.RemoteAddr,
		); err != nil {
			s.log.Error("pair: insertion pending_node", "err", err)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Re-lire l'ID au cas où un autre goroutine a inséré en parallèle.
		_ = s.db.QueryRowContext(r.Context(),
			`SELECT id FROM pending_nodes WHERE node_name=? AND role=?`, nodeName, role,
		).Scan(&pendingID)
		s.log.Info("pair: nœud en attente d'acceptation", "role", role, "node", nodeName, "pending_id", pendingID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "pending_id": pendingID})
}

// handlePairStatus permet à un nœud de vérifier si son entrée pending a été acceptée.
// Endpoint public : GET /internal/v1/pair/status?pending_id=...
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	pendingID := r.URL.Query().Get("pending_id")
	if pendingID == "" {
		http.Error(w, "pending_id requis", http.StatusBadRequest)
		return
	}

	var status, token string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT status, token FROM pending_nodes WHERE id=?`, pendingID,
	).Scan(&status, &token)
	if err != nil {
		// Entrée introuvable : expirée ou jamais créée.
		http.Error(w, "demande introuvable", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch status {
	case "accepted":
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": token})
	case "rejected":
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
	default:
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}
}

func (s *Server) handleEdgeRoutes(w http.ResponseWriter, r *http.Request) {
	// Identifie le token pour appliquer le filtre RBAC + délégations.
	bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenID, rbacRole := rbac.TokenRBACRole(r.Context(), s.db, bearerToken)

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT config FROM proxies WHERE enabled=1`)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var allRoutes []router.Route
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		var route router.Route
		if err := json.Unmarshal([]byte(cfg), &route); err == nil {
			allRoutes = append(allRoutes, route)
		}
	}

	var nodeName string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(node_name,'') FROM tokens WHERE id=?`, tokenID).Scan(&nodeName)
	acc := rbac.LoadEdgeAccess(r.Context(), s.db, tokenID, nodeName)
	if acc.Role != "" {
		rbacRole = acc.Role
	}

	var filtered []router.Route
	if s.wsManager != nil {
		filtered = s.wsManager.FilterRoutesForEdge(r.Context(), tokenID, nodeName, rbacRole, acc.Scopes, allRoutes)
	} else {
		filtered = rbac.FilterRoutesByScopes(rbacRole, acc.Scopes, allRoutes)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered) //nolint:errcheck
}

// handleEdgeRegister met à jour l'endpoint d'une passerelle dans la table tokens
// et enregistre/met à jour le client WS Admin→Passerelle dans le Manager.
func (s *Server) handleEdgeRegister(mgr *edgews.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Endpoint     string `json:"endpoint"`
			RaftEndpoint string `json:"raft_endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Endpoint == "" {
			http.Error(w, "endpoint requis", http.StatusBadRequest)
			return
		}

		// Identifie le token depuis l'en-tête Authorization.
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Si l'endpoint fourni contient une IP Docker interne (172.x.x.x),
		// la remplacer par l'IP source de la requête afin qu'Admin puisse
		// joindre la passerelle cross-machine (Docker bridge → host NAT).
		if u, err := url.Parse(req.Endpoint); err == nil {
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				_, docker172, _ := net.ParseCIDR("172.16.0.0/12")
				if docker172.Contains(ip) {
					if srcIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
						u.Host = net.JoinHostPort(srcIP, u.Port())
						req.Endpoint = u.String()
					}
				}
			}
		}

		res, err := s.db.ExecContext(r.Context(),
			`UPDATE tokens SET node_endpoint=?, raft_endpoint=? WHERE token=? AND role='edge' AND revoked=0`,
			req.Endpoint, req.RaftEndpoint, token,
		)
		if err != nil {
			s.log.Error("edge register: update endpoint", "err", err)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			http.Error(w, "token introuvable ou révoqué", http.StatusNotFound)
			return
		}

		// Récupérer l'ID et le nom de la passerelle pour l'enregistrement dans le Manager.
		var edgeID, nodeName, rbacRole string
		_ = s.db.QueryRowContext(r.Context(),
			`SELECT id, COALESCE(node_name,''), COALESCE(rbac_role,'admin')
			 FROM tokens WHERE token=? AND role='edge' AND revoked=0`,
			token,
		).Scan(&edgeID, &nodeName, &rbacRole)

		s.log.Info("edge enregistré", "endpoint", req.Endpoint, "node", nodeName)

		// Enregistrer/mettre à jour le client WS Admin→Passerelle.
		// La connexion WS + le full_sync sont déclenchés automatiquement dans Register.
		settings := s.runtimeSettings()
		mgr.SetSettings(settings)
		if edgeID != "" {
			mgr.Register(edgeID, nodeName, req.Endpoint, rbacRole)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleNodeMetrics(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT endpoint, COALESCE(cpu_pct,0), COALESCE(mem_pct,0) FROM nodes WHERE status='online'`)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type nodeMetric struct {
		Endpoint string  `json:"endpoint"`
		CPUPCT   float64 `json:"cpu_pct"`
		MemPCT   float64 `json:"mem_pct"`
	}
	result := make([]nodeMetric, 0)
	for rows.Next() {
		var m nodeMetric
		if err := rows.Scan(&m.Endpoint, &m.CPUPCT, &m.MemPCT); err != nil {
			continue
		}
		result = append(result, m)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

