// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"encoding/json"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

// Message est l'enveloppe JSON de tous les messages WebSocket du plan de contrôle.
// seq : compteur croissant côté émetteur — un trou déclenche un full_sync.
type Message struct {
	Seq     int64           `json:"seq"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Types de messages Admin → passerelle
const (
	TypeAdminToken          = "admin_token" // jeton HTTP que la passerelle doit reconnaître pour les appels Admin→Passerelle
	TypePushRoutes          = "push_routes"
	TypeDeleteRoute         = "delete_route"
	TypePushCert            = "push_cert"
	TypeACMEChallenge       = "acme_challenge" // pose/retire une réponse http-01 / tls-alpn-01
	TypePushECHKeys         = "push_ech_keys"  // clés ECH (Encrypted Client Hello) à accepter ; liste vide = ECH désactivé
	TypePushSnippets        = "push_snippets"
	TypePushPlugins         = "push_plugins" // paquets de plugins WASM (liste complète : les absents sont retirés)
	TypePushAuthProviders   = "push_auth_providers"
	TypePushIPProfiles      = "push_ip_profiles"
	TypePushBans            = "push_bans"
	TypeUnbanIPs            = "unban_ips"  // lève les bans d'IPs débannies depuis l'Admin, toutes sources confondues (payload : []UnbanEntry)
	TypeEraseIPs            = "erase_ips"  // efface d'une passerelle les traces d'IPs (droit à l'effacement RGPD) : lignes d'accès de sa base de logs et historique des bans (payload : []EraseEntry)
	TypeLogLive             = "log_live"   // Admin → passerelle : une vue Live est ouverte, envoyer les nouvelles lignes pendant TTLSec secondes (payload : LogLivePayload)
	TypeLogAck              = "log_ack"    // Admin → passerelle : positions que l'Admin a rangées dans son volume de logs, par flux ; la passerelle peut purger ce qui est acquitté (payload : LogAckPayload)
	TypeLogResume           = "log_resume" // Admin → passerelle : reprendre l'envoi des logs après la position que l'Admin a déjà enregistrée (payload : LogResumePayload)
	TypePushSettings        = "push_settings"
	TypePushGatewayPeers    = "push_gateway_peers"
	TypePushDelegations     = "push_delegations"
	TypePushThreatConfig    = "push_threat_config"
	TypePushF2BConfig       = "push_f2b_config"
	TypePushLogRetention    = "push_log_retention" // durées de conservation des logs de la passerelle (payload : LogRetentionPayload)
	TypePushSIEMConfig      = "push_siem_config"   // configuration de l'exporteur SIEM de la passerelle (payload : siem.Config)
	TypePushCrowdSecConfig  = "push_crowdsec_config"
	TypePushWAFConfig       = "push_waf_config"
	TypePushServerConfig    = "push_server_config"
	TypePushErrorPages      = "push_error_pages"
	TypePushPortal          = "push_portal"
	TypePushPortalTemplates = "push_portal_templates"
	TypeKillPortalSession   = "kill_portal_session" // termine une connexion pontée du portail (payload : {"id"})
	TypeFullSync            = "full_sync"
	TypeApproveAgent        = "approve_agent"
	TypeRevokeAgent         = "revoke_agent"
	TypePushAutoRules       = "push_auto_rules"    // pousse les règles automatiques vers passerelle
	TypePushTunnelConfig    = "push_tunnel_config" // pousse la config peers tunnel L4 mTLS vers passerelle
	TypePushGroupCard       = "push_group_card"    // fiche du groupe HA de la passerelle (payload : GroupCard)
	TypePushDisabledRoutes  = "push_disabled_routes" // hôtes dont la route issue d'un conteneur est désactivée (payload : DisabledRoutes)
)

// TypeRevokeStaleAdminTokens révoque les autres jetons qu'un Admin a poussés à la passerelle (payload : AdminTokenPayload,
// le jeton à garder).
const TypeRevokeStaleAdminTokens = "revoke_stale_admin_tokens"

// Types de messages Agent → passerelle
const (
	TypeAgentRegister   = "register"
	TypeAgentHeartbeat  = "heartbeat"
	TypeAgentContainers = "containers"
	TypeAgentMetrics    = "metrics"
	TypeAgentEvent      = "event"
	TypeAgentLog        = "log"
	TypeAgentState      = "agent_state" // fichiers d'état locaux de l'Agent, conservés par sa passerelle
)

// Types de messages passerelle → Agent
const (
	TypeApprove      = "approve"
	TypeRotateHMAC   = "rotate_hmac"
	TypeRestoreState = "restore_state" // Passerelle → Agent revenu sans état local : lui rend ses fichiers
	TypeCommand      = "command"
	TypeRescan       = "rescan"
	TypePing         = "ping"
	TypePong         = "pong"
	TypeShellOpen    = "shell_open"  // Passerelle → Agent : ouvrir docker exec
	TypeShellReady   = "shell_ready" // Agent → passerelle : exec attaché
	TypeShellData    = "shell_data"  // bidirectionnel : chunks base64
	TypeShellClose   = "shell_close" // bidirectionnel
	TypeShellError   = "shell_error" // Agent → passerelle
)

// Types de messages passerelle → Admin
const (
	TypeAgentPending          = "agent_pending"
	TypeNodeUpdate            = "node_update"
	TypeEdgeHeartbeat         = "edge_heartbeat"
	TypeEdgeTraffic           = "edge_traffic"        // débit récent de la passerelle, toutes les 5 s, pour la carte de topologie (payload : EdgeTrafficPayload)
	TypeLogLiveRows           = "log_live_rows"       // lignes récentes envoyées à une vue Live, sans numéro ni reprise (payload : LogLiveRowsPayload)
	TypeLogStream             = "log_stream"          // lot de logs numérotés lus dans la base de logs de la passerelle (payload : LogStreamPayload)
	TypeAggStream             = "agg_stream"          // cumuls par minute calculés par la passerelle avec ses lignes (payload : MinuteStreamPayload)
	TypeLogInfo               = "log_info"            // rétention réellement appliquée par la passerelle, toutes les 30 s (payload : LogInfoPayload)
	TypeSIEMStatus            = "siem_status"         // état de chaque destination de l'exporteur SIEM, toutes les 30 s (payload : SIEMStatusPayload)
	TypeSurfaceSuggestions    = "surface_suggestions" // ajouts suggérés à la politique de surface de chaque proxy, toutes les 5 min (payload : SurfaceSuggestionsPayload)
	TypeIPStream              = "ip_stream"           // compteurs d'erreurs client par IP et par minute, pour le Fail2Ban global de l'Admin (payload : IPStreamPayload)
	TypePortalInviteCompleted = "portal_invite_completed"
	TypePortalSendEmailOTP    = "portal_send_email_otp"
	TypePortalAudit           = "portal_audit"
	TypePortalLive            = "portal_live"           // instantané des connexions pontées en cours
	TypePortalAccessRequest   = "portal_access_request" // demande d'accès temporaire d'un utilisateur du portail
	TypeThreatBan             = "threat_ban"            // IP bannie par le moteur de détection automatique
	TypeF2BBan                = "f2b_ban"               // IP bannie par le moteur Fail2Ban passerelle
	TypeCrowdSecDecisions     = "crowdsec_decisions"    // décisions CrowdSec passerelle→Admin (agrégation)
	TypeWAFReloaded           = "waf_reloaded"          // Confirmation passerelle → Admin : règles WAF appliquées
	TypeBackendDown           = "backend_down"          // Backend déclaré indisponible par health-check
	TypeRuleFired             = "rule_fired"            // Règle automatique déclenchée passerelle → Admin
	TypeASNOffer              = "asn_db_offer"          // Admin → passerelle : version de la base IP → ASN que l'Admin possède (payload : ASNOfferPayload)
	TypeASNWant               = "asn_db_want"           // passerelle → Admin : réclame la base ASN (payload : ASNWantPayload)
	TypePushASN               = "push_asn_db"           // Admin → passerelle : un morceau de la base ASN compacte (payload : ASNChunkPayload)
)

// ASNOfferPayload annonce la base ASN de l'Admin ; la passerelle la réclame si elle n'a pas la même version.
type ASNOfferPayload struct {
	Version string `json:"version"`
}

// ASNWantPayload est la demande d'une passerelle qui n'a pas la base ASN annoncée.
type ASNWantPayload struct {
	NodeName string `json:"node_name"`
	Have     string `json:"have,omitempty"` // version qu'elle a déjà
}

// ASNChunkPayload est un morceau de la base ASN compacte (internal/asncompact), à assembler dans l'ordre de Seq.
type ASNChunkPayload struct {
	Version string `json:"version"`
	Seq     int    `json:"seq"`
	Total   int    `json:"total"`
	Data    []byte `json:"data"`
}

// RuleFiredPayload est envoyé par passerelle → Admin quand une règle automatique se déclenche.
type RuleFiredPayload struct {
	NodeName    string         `json:"node_name,omitempty"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	ActionType  string         `json:"action_type,omitempty"` // ban_ip | disable_proxy | notify | enable_strict_f2b
	CondResult  bool           `json:"cond_result"`
	ActionTaken bool           `json:"action_taken"`
	Silenced    bool           `json:"silenced,omitempty"` // déclenchement ignoré : mise en sourdine
	Detail      map[string]any `json:"detail,omitempty"`
	Error       string         `json:"error,omitempty"`
	FiredAt     string         `json:"fired_at"` // RFC3339
}

// BackendDownPayload est envoyé par passerelle → Admin quand un backend passe unhealthy.
type BackendDownPayload struct {
	URL      string `json:"url"`
	NodeName string `json:"node_name,omitempty"`
}

// CrowdSecDecision est une décision CrowdSec relayée passerelle→Admin.
type CrowdSecDecision struct {
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Scope    string `json:"scope"`
}

// CrowdSecDecisionsPayload est envoyé par passerelle → Admin après chaque sync CrowdSec.
type CrowdSecDecisionsPayload struct {
	NodeName string             `json:"node_name,omitempty"`
	Added    []CrowdSecDecision `json:"added,omitempty"`
	Deleted  []CrowdSecDecision `json:"deleted,omitempty"`
}

// F2BBanPayload est envoyé par passerelle → Admin quand le moteur Fail2Ban passerelle banne une IP.
type F2BBanPayload struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339, vide = permanent
	NodeName  string `json:"node_name,omitempty"`
	// UserAgent : le dernier User-Agent vu pour l'IP au moment du ban.
	UserAgent string `json:"user_agent,omitempty"`
}

// UnbanEntry est un déban décidé dans l'Admin. At vide : déban à l'instant (la passerelle prend sa
// propre heure, insensible au décalage d'horloge) ; At renseigné : rejeu à la reconnexion, seuls les
// bans posés avant At sont levés.
type UnbanEntry struct {
	IP string     `json:"ip"`
	At *time.Time `json:"at,omitempty"`
}

// EraseEntry est une IP à effacer de la passerelle. L'ordre est rejoué à chaque connexion pendant la
// durée de conservation des fichiers : effacer une IP absente est sans effet.
type EraseEntry struct {
	IP string `json:"ip"`
}

// PluginBanSourcePrefix préfixe la source du ban d'un plugin de détection : "plugin:coraza".
const PluginBanSourcePrefix = "plugin:"

// ThreatBanPayload est envoyé par passerelle → Admin quand le moteur détecte et banne une IP.
type ThreatBanPayload struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339
	NodeName  string `json:"node_name,omitempty"`
	// Source : "plugin:<nom>" pour le ban d'un plugin de détection ; vide pour Ephor.
	Source string `json:"source,omitempty"`
	// Signals : les signaux qui expliquent le ban, avec leurs points et la valeur observée (ADR 0011).
	Signals []router.BanSignal `json:"signals,omitempty"`
	// UserAgent : le dernier User-Agent vu pour l'IP au moment du ban.
	UserAgent string `json:"user_agent,omitempty"`
}

// LogEntryPayload est le format normalisé des logs relayés passerelle → Admin.
// Compatible avec POST /internal/v1/logs (Admin) et AccessLogger.ship.
type LogEntryPayload struct {
	Ts        string `json:"ts"`
	Level     string `json:"level"`
	Component string `json:"component"`
	NodeName  string `json:"node_name,omitempty"`
	// NodeID est écrasé côté Admin par l'ID stable de la connexion WS
	// (edgeID/token) quel que soit ce que la passerelle envoie ici — voir
	// stampLogBatchNode dans internal/admin/edgews/manager.go. Un
	// renommage du nœud (node_name) ne casse donc plus le filtrage
	// historique des logs par nœud.
	NodeID string `json:"node_id,omitempty"`
	Domain string `json:"domain"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	IP     string `json:"ip"`
	// RealIP est présent uniquement en mode pseudonymisation — chiffré côté Admin, jamais stocké en clair.
	RealIP string `json:"real_ip,omitempty"`
	// IPTruncated : IP tronquée par la passerelle (voir logger.ShipEntry), pas une IP client.
	IPTruncated bool   `json:"ip_truncated,omitempty"`
	LatencyMs   int64  `json:"latency_ms"`
	Bytes       int64  `json:"bytes"`
	Message     string `json:"message"`
	Referrer    string `json:"referrer,omitempty"`
	// UserAgent n'est envoyé que par le flux de lignes (ADR 0018) : le store de l'Admin en a besoin pour ses classements.
	UserAgent string `json:"user_agent,omitempty"`
	// RequestID/WAFMatches/ThreatSignal : contexte de sécurité de la requête d'origine
	// (voir logger.ShipEntry côté passerelle) — vides pour la majorité des requêtes
	// propres, renseignés quand le WAF ou Ephor se sont déclenchés.
	RequestID    string   `json:"request_id,omitempty"`
	WAFMatches   []string `json:"waf_matches,omitempty"`
	ThreatSignal string   `json:"threat_signal,omitempty"`
	TLSJA3       string   `json:"tls_ja3,omitempty"`
	TLSJA4       string   `json:"tls_ja4,omitempty"`
	// Seq est l'identifiant de la ligne dans la base de logs de la passerelle : le curseur du flux
	// (LogStreamPayload). Absent d'un lot envoyé sans base de logs locale.
	Seq int64 `json:"seq,omitempty"`
}

// Flux de logs : la passerelle garde ses lignes et l'Admin retient, par flux, la dernière position qu'il a
// enregistrée. Un flux est "access" (requêtes HTTP) ou "system" (logs de la passerelle).
const (
	LogStreamAccess = "access"
	LogStreamSystem = "system"
)

// LogResumePayload : positions de l'Admin par flux. 0 ou absent : depuis le début de la base de la passerelle.
type LogResumePayload struct {
	// Stored : les positions sont celles de lignes rangées dans le volume de logs de l'Admin (ADR 0018), donc acquittées : la
	// passerelle peut en purger la base. Faux (Admin sans volume de logs) : les positions ne protègent rien et ne purgent rien.
	Stored bool `json:"stored,omitempty"`
	Cursors map[string]int64 `json:"cursors"`
}

// LogAckPayload : positions rangées par l'Admin, par flux (access, system, minute, iperr). Elles ne reculent pas : une remise en
// arrière passe par log_resume, quand le volume de logs de l'Admin a été remplacé.
type LogAckPayload struct {
	Cursors map[string]int64 `json:"cursors"`
}

// LogLivePayload : durée pendant laquelle la passerelle envoie ses nouvelles lignes ; l'Admin la renouvelle tant
// qu'une vue Live est ouverte.
type LogLivePayload struct {
	TTLSec int `json:"ttl_sec"`
}

// LogLiveRowsPayload : lignes récentes pour une vue Live. Dropped : la passerelle en a sauté faute de débit.
type LogLiveRowsPayload struct {
	Entries []LogEntryPayload `json:"entries"`
	Dropped bool              `json:"dropped,omitempty"`
}

// LogStreamPayload est un lot de lignes contiguës d'un flux. After est la position qui précède la première
// ligne : l'Admin n'accepte le lot que si elle n'est pas au-delà de la sienne, sinon il manque des lignes et il
// redemande l'envoi depuis sa position.
type LogStreamPayload struct {
	Stream  string            `json:"stream"`
	After   int64             `json:"after"`
	Entries []LogEntryPayload `json:"entries"`
	// Through : dernière position examinée par la passerelle quand elle a écarté des lignes (accès non signalés) :
	// l'Admin y avance son curseur même sans ligne reçue.
	Through int64 `json:"through,omitempty"`
	// Reset : la position After de l'Admin dépasse tout ce que la base de la passerelle a jamais attribué, parce qu'elle
	// a été remplacée (état restauré sans le dossier des logs, disque neuf). L'Admin ramène son curseur à 0 : tout ce que
	// contient la nouvelle base lui sera envoyé, sans qu'aucune de ses lignes ne soit sautée.
	Reset bool `json:"reset,omitempty"`
}

// LogStreamMinute est le flux des cumuls par minute. Contrairement aux flux de lignes, une ligne de cumul revient
// avec sa valeur à jour chaque fois qu'elle change : l'Admin la remplace, ce qui rend un renvoi sans effet.
const LogStreamMinute = "minute"

// MinuteRowPayload est le cumul d'une minute pour un domaine et un code de statut. Il ne contient ni IP ni chemin.
type MinuteRowPayload struct {
	Minute       string `json:"minute"` // AAAA-MM-JJTHH:MM, UTC
	NodeName     string `json:"node_name"`
	Domain       string `json:"domain"`
	Status       int    `json:"status"`
	Requests     int64  `json:"requests"`
	Bytes        int64  `json:"bytes"`
	LatencyMsSum int64  `json:"latency_ms_sum"`
	Bots         int64  `json:"bots"`
	// Seq est le numéro de la dernière mise à jour de la ligne : le curseur du flux.
	Seq int64 `json:"seq"`
}

// MinuteStreamPayload est un lot de cumuls dans l'ordre de leurs mises à jour. After est la position qui précède
// le premier : même règle que LogStreamPayload.
type MinuteStreamPayload struct {
	After int64              `json:"after"`
	Rows  []MinuteRowPayload `json:"rows"`
}

// LogStreamIPErrors est le flux des compteurs d'erreurs client par IP : même contrat que LogStreamMinute (la valeur
// à jour d'une ligne remplace la précédente).
const LogStreamIPErrors = "iperr"

// IPErrorRowPayload est le nombre d'erreurs client (4xx hors 404) d'une IP lisible pendant une minute. Une IP
// tronquée par l'anonymisation ou la pseudonymisation n'est jamais envoyée.
type IPErrorRowPayload struct {
	Minute string `json:"minute"` // AAAA-MM-JJTHH:MM, UTC
	IP     string `json:"ip"`
	Errors int64  `json:"errors"`
	Seq    int64  `json:"seq"`
}

// IPStreamPayload est un lot de compteurs dans l'ordre de leurs mises à jour ; After a le sens de LogStreamPayload.
type IPStreamPayload struct {
	After int64               `json:"after"`
	Rows  []IPErrorRowPayload `json:"rows"`
}

// EdgeTrafficPayload : les requêtes que la passerelle a traitées pendant les WindowSec dernières secondes. L'Admin ne
// reçoit plus les accès ordinaires un à un : ce débit vient de la passerelle, qui seule les connaît.
type EdgeTrafficPayload struct {
	NodeName  string `json:"node_name"`
	WindowSec int    `json:"window_sec"`
	Requests  int64  `json:"requests"`
	Blocked   int64  `json:"blocked"` // refusées : 403 et 429
	Errors    int64  `json:"errors"`  // erreurs de backend : 5xx
}

// LogRetentionPayload : les durées de conservation, en jours, que l'Admin impose à une passerelle.
type LogRetentionPayload struct {
	AccessDays int `json:"access_days"`
	SystemDays int `json:"system_days"`
}

// LogInfoPayload : la rétention des logs qu'une passerelle applique, config ou ordre de l'Admin confondus.
type LogInfoPayload struct {
	NodeName   string `json:"node_name"`
	AccessDays int    `json:"access_days"`
	SystemDays int    `json:"system_days"`
	// AccessLast et SystemLast : le dernier identifiant que la base de logs de la passerelle a attribué, par type. L'Admin les
	// compare à la position de sa copie pour savoir si elle est à jour (ADR 0018).
	AccessLast int64 `json:"access_last,omitempty"`
	SystemLast int64 `json:"system_last,omitempty"`
	// BufferActive : la base de la passerelle se comporte en tampon (l'Admin acquitte ses lignes). UnackedDays : âge, en jours
	// entiers, de la plus ancienne ligne que l'Admin n'a pas acquittée ; BufferMaxDays : âge au-delà duquel elle est supprimée.
	BufferActive  bool `json:"buffer_active,omitempty"`
	UnackedDays   int  `json:"unacked_days,omitempty"`
	BufferMaxDays int  `json:"buffer_max_days,omitempty"`
}

// SIEMStatusPayload : l'état de l'exporteur SIEM d'une passerelle. Liste vide : aucune destination active.
type SIEMStatusPayload struct {
	NodeName     string                   `json:"node_name"`
	Destinations []siem.DestinationStatus `json:"destinations"`
}

// SurfaceSuggestionPayload est un ajout que le profil de surface d'un proxy suggère à sa politique.
type SurfaceSuggestionPayload struct {
	Key        string `json:"key"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Confidence string `json:"confidence"` // high | low
}

// SurfaceProxyPayload : les ajouts suggérés pour un proxy.
type SurfaceProxyPayload struct {
	Route       string                     `json:"route"`
	Host        string                     `json:"host"`
	Suggestions []SurfaceSuggestionPayload `json:"suggestions"`
}

// SurfaceSuggestionsPayload : l'état des suggestions d'une passerelle. C'est un état, pas un journal : un envoi perdu pendant une
// coupure est remplacé par le suivant, et un proxy absent n'a plus de suggestion.
type SurfaceSuggestionsPayload struct {
	NodeName string                `json:"node_name"`
	Proxies  []SurfaceProxyPayload `json:"proxies"`
}

// EdgeHeartbeatPayload est envoyé par passerelle → Admin toutes les 30 s.
type EdgeHeartbeatPayload struct {
	NodeName string  `json:"node_name"`
	Role     string  `json:"role"`
	Version  string  `json:"version"`
	CPUPct   float64 `json:"cpu_pct"`
	MemPct   float64 `json:"mem_pct"`
}

// AdminTokenPayload transporte le token HTTP qu'Admin utilise pour appeler l'API interne de la passerelle.
// Passerelle l'enregistre dans son tokenStore (RoleAdmin) dès réception.
type AdminTokenPayload struct {
	Token string `json:"token"`
}

// ApproveAgentPayload est envoyé par Admin → passerelle pour approuver un Agent en attente.
type ApproveAgentPayload struct {
	AgentID string `json:"agent_id"`
}

// RevokeAgentPayload est envoyé par Admin → passerelle pour révoquer un Agent :
// fermeture de la connexion WS + invalidation du HMAC persisté.
type RevokeAgentPayload struct {
	AgentID string `json:"agent_id"` // id ou name de l'Agent
}

// ApprovePayload est envoyé par passerelle → Agent après approbation.
type ApprovePayload struct {
	AgentID   string `json:"agent_id"`
	AgentHMAC string `json:"agent_hmac"`
}

// AgentStatePayload : fichiers d'état d'un Agent (nom → contenu).
type AgentStatePayload struct {
	Files map[string][]byte `json:"files"`
}

// RotateHMACPayload est envoyé par passerelle → Agent pour rotation horaire du secret HMAC.
type RotateHMACPayload struct {
	AgentHMAC string `json:"agent_hmac"`
}

// AgentPendingPayload est envoyé par passerelle → Admin pour signaler un nouvel Agent en attente.
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

// TunnelConfigPayload est envoyé par Admin → passerelle pour mettre à jour la liste des peers tunnel.
type TunnelConfigPayload struct {
	Peers []TunnelPeer `json:"peers"`
}

// DisabledRoutes liste les hôtes dont la route issue d'un conteneur (Docker, Portainer, Podman, Kubernetes, annuaires)
// est désactivée : la passerelle ne la sert plus, mais la garde listée pour qu'on puisse la réactiver. La liste est
// complète, triée, et remplace la précédente.
type DisabledRoutes struct {
	Hosts []string `json:"hosts"`
}

// GroupCard est la fiche d'un groupe HA (ADR 0014, section 3) : la composition et les domaines du groupe, tels que
// l'Admin les déclare. Chaque membre en garde une copie locale chiffrée et la sert à l'Admin qui doit se reconstituer.
// Version augmente à chaque modification ; la plus haute l'emporte.
type GroupCard struct {
	Group   string       `json:"group"`
	Version int64        `json:"version"`
	Members []CardMember `json:"members"`
	Domains []CardDomain `json:"domains,omitempty"`
}

// CardMember est un membre du groupe : l'identifiant du nœud dans l'architecture, son nom et l'adresse de sa passerelle.
type CardMember struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint,omitempty"`
}

// CardDomain est un domaine géré par le groupe. Les identifiants DNS y figurent tels que l'Admin les garde dans
// architecture.json : ils permettent le renouvellement DNS d'un domaine et le retour de la déclaration dans un Admin
// reconstitué.
type CardDomain struct {
	ID                string `json:"id"`
	Domain            string `json:"domain"`
	EdgeID            string `json:"edge_id"`
	DNSProvider       string `json:"dns_provider"`
	DNSCredentials    string `json:"dns_credentials,omitempty"`
	CertMethod        string `json:"cert_method"`
	DelegatedToEdgeID string `json:"delegated_to_edge_id,omitempty"`
	DelegatedEndpoint string `json:"delegated_endpoint,omitempty"`
	DelegationMode    string `json:"delegation_mode,omitempty"`
	// EdgeName et DelegatedToName : les noms des passerelles que EdgeID et DelegatedToEdgeID désignent (des jetons, qui ne
	// survivent pas à la perte de l'Admin). Un Admin reconstitué retrouve les jetons actuels par ces noms.
	EdgeName        string `json:"edge_name,omitempty"`
	DelegatedToName string `json:"delegated_to_name,omitempty"`
}

// NewMessage construit un Message à partir d'un type et d'un payload quelconque.
func NewMessage(seq int64, msgType string, payload any) (Message, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Seq: seq, Type: msgType, Payload: b}, nil
}
