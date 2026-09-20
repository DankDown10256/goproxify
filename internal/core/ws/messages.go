// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import "encoding/json"

// Message est l'enveloppe JSON de tous les messages WebSocket du plan de contrôle.
// seq : compteur croissant côté émetteur — un trou déclenche un full_sync.
type Message struct {
	Seq     int64           `json:"seq"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Types de messages Admin → Core
const (
	TypeAdminToken        = "admin_token" // jeton HTTP que Core doit reconnaître pour les appels Admin→Core
	TypePushRoutes        = "push_routes"
	TypeDeleteRoute       = "delete_route"
	TypePushCert          = "push_cert"
	TypePushSnippets      = "push_snippets"
	TypePushAuthProviders = "push_auth_providers"
	TypePushIPProfiles    = "push_ip_profiles"
	TypePushBans          = "push_bans"
	TypePushSettings      = "push_settings"
	TypePushClusterPeers  = "push_cluster_peers"
	TypePushGatewayPeers  = "push_gateway_peers"
	TypePushDelegations   = "push_delegations"
	TypePushThreatConfig  = "push_threat_config"
	TypePushF2BConfig       = "push_f2b_config"
	TypePushCrowdSecConfig  = "push_crowdsec_config"
	TypePushServerConfig  = "push_server_config"
	TypePushErrorPages        = "push_error_pages"
	TypePushPortal            = "push_portal"
	TypePushPortalTemplates   = "push_portal_templates"
	TypeFullSync          = "full_sync"
	TypeApproveAgent      = "approve_agent"
	TypeRevokeAgent       = "revoke_agent"
	TypePushAutoRules     = "push_auto_rules"     // pousse les règles automatiques vers Core
	TypePushTunnelConfig  = "push_tunnel_config"  // pousse la config peers tunnel L4 mTLS vers Core
)

// Types de messages Agent → Core
const (
	TypeAgentRegister   = "register"
	TypeAgentHeartbeat  = "heartbeat"
	TypeAgentContainers = "containers"
	TypeAgentMetrics    = "metrics"
	TypeAgentEvent      = "event"
	TypeAgentLog        = "log"
)

// Types de messages Core → Agent
const (
	TypeApprove    = "approve"
	TypeRotateHMAC = "rotate_hmac"
	TypeCommand    = "command"
	TypeRescan     = "rescan"
	TypePing       = "ping"
	TypePong       = "pong"
	TypeShellOpen  = "shell_open"  // Core → Agent : ouvrir docker exec
	TypeShellReady = "shell_ready" // Agent → Core : exec attaché
	TypeShellData  = "shell_data"  // bidirectionnel : chunks base64
	TypeShellClose = "shell_close" // bidirectionnel
	TypeShellError = "shell_error" // Agent → Core
)

// Types de messages Core → Admin
const (
	TypeAgentPending  = "agent_pending"
	TypeNodeUpdate    = "node_update"
	TypeCoreHeartbeat = "core_heartbeat"
	TypeAccessLog              = "access_log" // batches d'access logs (Prism / Logs)
	TypePortalInviteCompleted = "portal_invite_completed"
	TypePortalSendEmailOTP    = "portal_send_email_otp"
	TypePortalAudit           = "portal_audit"
	TypeThreatBan             = "threat_ban"    // IP bannie par le moteur de détection automatique
	TypeF2BBan                = "f2b_ban"         // IP bannie par le moteur Fail2Ban Core
	TypeCrowdSecDecisions     = "crowdsec_decisions" // décisions CrowdSec Core→Admin (agrégation)
	TypeWAFReloaded           = "waf_reloaded"  // Confirmation Core → Admin : règles WAF appliquées
	TypeBackendDown           = "backend_down"  // Backend déclaré indisponible par health-check
	TypeRuleFired             = "rule_fired"    // Règle automatique déclenchée Core → Admin
)

// RuleFiredPayload est envoyé par Core → Admin quand une règle automatique se déclenche.
type RuleFiredPayload struct {
	NodeName    string         `json:"node_name,omitempty"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	ActionType  string         `json:"action_type,omitempty"` // ban_ip | disable_proxy | notify | enable_strict_f2b
	CondResult  bool           `json:"cond_result"`
	ActionTaken bool           `json:"action_taken"`
	Detail      map[string]any `json:"detail,omitempty"`
	Error       string         `json:"error,omitempty"`
	FiredAt     string         `json:"fired_at"` // RFC3339
}

// BackendDownPayload est envoyé par Core → Admin quand un backend passe unhealthy.
type BackendDownPayload struct {
	URL      string `json:"url"`
	NodeName string `json:"node_name,omitempty"`
}

// CrowdSecDecision est une décision CrowdSec relayée Core→Admin.
type CrowdSecDecision struct {
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Scope    string `json:"scope"`
}

// CrowdSecDecisionsPayload est envoyé par Core → Admin après chaque sync CrowdSec.
type CrowdSecDecisionsPayload struct {
	NodeName string             `json:"node_name,omitempty"`
	Added    []CrowdSecDecision `json:"added,omitempty"`
	Deleted  []CrowdSecDecision `json:"deleted,omitempty"`
}

// F2BBanPayload est envoyé par Core → Admin quand le moteur Fail2Ban Core banne une IP.
type F2BBanPayload struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339, vide = permanent
	NodeName  string `json:"node_name,omitempty"`
}

// ThreatBanPayload est envoyé par Core → Admin quand le moteur détecte et banne une IP.
type ThreatBanPayload struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339
	NodeName  string `json:"node_name,omitempty"`
}

// LogEntryPayload est le format normalisé des logs relayés Core → Admin.
// Compatible avec POST /internal/v1/logs (Admin) et AccessLogger.ship.
type LogEntryPayload struct {
	Ts        string `json:"ts"`
	Level     string `json:"level"`
	Component string `json:"component"`
	NodeName  string `json:"node_name,omitempty"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	IP        string `json:"ip"`
	// RealIP est présent uniquement en mode pseudonymisation — chiffré côté Admin, jamais stocké en clair.
	RealIP    string `json:"real_ip,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Bytes     int64  `json:"bytes"`
	Message   string `json:"message"`
	Referrer  string `json:"referrer,omitempty"`
}

// CoreHeartbeatPayload est envoyé par Core → Admin toutes les 30 s.
type CoreHeartbeatPayload struct {
	NodeName string  `json:"node_name"`
	Role     string  `json:"role"`
	Version  string  `json:"version"`
	CPUPct   float64 `json:"cpu_pct"`
	MemPct   float64 `json:"mem_pct"`
}

// AdminTokenPayload transporte le token HTTP qu'Admin utilise pour appeler l'API interne du Core.
// Core l'enregistre dans son tokenStore (RoleAdmin) dès réception.
type AdminTokenPayload struct {
	Token string `json:"token"`
}

// ApproveAgentPayload est envoyé par Admin → Core pour approuver un Agent en attente.
type ApproveAgentPayload struct {
	AgentID string `json:"agent_id"`
}

// RevokeAgentPayload est envoyé par Admin → Core pour révoquer un Agent :
// fermeture de la connexion WS + invalidation du HMAC persisté.
type RevokeAgentPayload struct {
	AgentID string `json:"agent_id"` // id ou name de l'Agent
}

// ApprovePayload est envoyé par Core → Agent après approbation.
type ApprovePayload struct {
	AgentID   string `json:"agent_id"`
	AgentHMAC string `json:"agent_hmac"`
}

// RotateHMACPayload est envoyé par Core → Agent pour rotation horaire du secret HMAC.
type RotateHMACPayload struct {
	AgentHMAC string `json:"agent_hmac"`
}

// AgentPendingPayload est envoyé par Core → Admin pour signaler un nouvel Agent en attente.
type AgentPendingPayload struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Version   string `json:"version"`
}

// AgentMetricsPayload contient les métriques d'un Agent (streamées toutes les 10 s).
type AgentMetricsPayload struct {
	AgentName  string            `json:"agent_name"`
	CPUPct     float64           `json:"cpu_pct"`
	MemPct     float64           `json:"mem_pct"`
	Containers []ContainerMetric `json:"containers,omitempty"`
}

// ContainerMetric contient les métriques d'un conteneur individuel pour le LB adaptatif.
type ContainerMetric struct {
	ContainerID string  `json:"container_id"`
	Name        string  `json:"name"`
	IP          string  `json:"ip,omitempty"` // IP réseau Docker — clé Score() du balancer
	CPUPct      float64 `json:"cpu_pct"`
	MemPct      float64 `json:"mem_pct"`
	DiskIOPCT   float64 `json:"disk_io_pct,omitempty"` // 0–100
	LatencyP95  float64 `json:"latency_p95_ms,omitempty"`
	ErrorRate   float64 `json:"error_rate,omitempty"` // erreurs par seconde
}

// Encode sérialise le message en JSON.
func (m Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// ShellOpenPayload demande à l'Agent d'ouvrir un docker exec interactif.
type ShellOpenPayload struct {
	SessionID string   `json:"session_id"`
	Container string   `json:"container"`
	Cmd       []string `json:"cmd,omitempty"`
}

// ShellReadyPayload confirme que le docker exec est prêt.
type ShellReadyPayload struct {
	SessionID string `json:"session_id"`
}

// ShellDataPayload transporte un chunk stdin/stdout (base64).
type ShellDataPayload struct {
	SessionID string `json:"session_id"`
	Data      string `json:"data"` // base64
}

// ShellClosePayload termine une session shell.
type ShellClosePayload struct {
	SessionID string `json:"session_id"`
}

// ShellErrorPayload signale une erreur Agent sur une session.
type ShellErrorPayload struct {
	SessionID string `json:"session_id"`
	Error     string `json:"error"`
}

// TunnelPeer est un pair tunnel L4 mTLS (nom + adresse host:port).
type TunnelPeer struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// TunnelConfigPayload est envoyé par Admin → Core pour mettre à jour la liste des peers tunnel.
type TunnelConfigPayload struct {
	Peers []TunnelPeer `json:"peers"`
}

// NewMessage construit un Message à partir d'un type et d'un payload quelconque.
func NewMessage(seq int64, msgType string, payload any) (Message, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Seq: seq, Type: msgType, Payload: b}, nil
}
