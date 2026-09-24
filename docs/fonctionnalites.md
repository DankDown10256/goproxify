# GoProxify Features

## 1. Overview

GoProxify is a **distributed, secure reverse proxy** compiled as a **single Go binary** with zero runtime dependency. The instance personality is determined at startup by the CLI subcommand or the `GOPROXIFY_MODE` environment variable.

The product comes in **three complementary personalities**:

| Component | Role | Persistence | Exposed ports |
|---|---|---|---|
| **Core** | Data Plane — high-performance routing engine + WS hub (+ optional Access) | RAM + encrypted cache | `:80`, `:443` TCP+UDP, `:8000` internal + WS; Access `:2222` / `:8444` if enabled |
| **Admin** | Control Plane — UI, API, MCP, alerting, Access | SQLite | `:9443` |
| **Agent** | Discovery & Telemetry — Docker sidecar | Volatile | `:9191` Prometheus, `:51820` WireGuard (no inbound port for control plane) |

---

## 2. Core — Data Plane

### Supported protocols

| Protocol | Details |
|---|---|
| HTTP/1.1 | Full reverse proxy with header management |
| HTTP/2 | Stream multiplexing, ALPN negotiation |
| HTTP/3 QUIC | UDP transport, `Alt-Svc` negotiation |
| WebSocket | HTTP → WS upgrade handled natively |
| gRPC | Transparent proxy over HTTP/2 |
| TCP L4 | Pure stream: local port → remote host:port, native SSL passthrough, L4 load balancing |
| UDP L4 | Pure tunnel, bytes in/out metrics |

### TLS

- **TLS termination**: certificates pushed into RAM only via `GetCertificate` — never written to disk
- **SNI Passthrough**: passive detection by reading the first 5 bytes of the Client Hello (no decryption)
- **ALPN negotiation**: `h2` and `http/1.1`
- **mTLS client**: client certificate validation (Milestone 5)
- **Inter-Core delegation**: an entry Core can forward a domain to another Core — **Passthrough** (raw TLS tunnel) or **Terminate** (TLS at entry + HTTP(S) proxy + `X-Forwarded-For`) modes. See [docs/delegation.md](delegation.md).

### Autonomous operation without Admin

The Core can operate **autonomously** if the Admin is temporarily unreachable:

- Automatic backup of the routing table and certificates in an **encrypted local cache** (`/etc/goproxify/core-cache.gpx`)
- Triggered on each push received from Admin + configurable interval
- On startup without reachable Admin: automatic load from cache
- **Automatic reconnect** as soon as Admin becomes available again → cache update
- Explicit log indicating startup mode (live / local cache)

### Performance

- `sync.Map` for routing table: atomic updates **with no connection interruption**
- Network buffer `sync.Pool`: stable P99 under load, reduced GC pressure
- Configurable Gzip compression
- Disk proxy cache (planned)

### Security

| Feature | Details |
|---|---|
| IP/CIDR filtering | Built-in profiles: Cloudflare, Tor, Bogons, custom ranges |
| Geo-IP | Allow or block by country (MaxMind GeoLite2; auto-download at startup) |
| Rate limiting | Token bucket per IP or authenticated user — `key_by` field: `ip` (default), `jwt_sub`, `jwt_email`, `jwt_claim:<name>` |
| HTTP security headers | HSTS, X-Frame-Options, Content-Security-Policy, etc. |
| CORS | Configurable origins, methods and headers |
| Server fingerprint masking | Removal of revealing headers (`Server`, `X-Powered-By`) |
| WAF | Native Go engine, 13 OWASP CRS-4 rule sets, request **and** response inspection, detect/block mode, custom rules hot-reload — see [docs/security.md](security.md#waf) |
| Sentinel | Per-IP behavioral detection: sliding window, immediate ban on signal, global anti-DDoS RPS — see [docs/security.md](security.md#sentinel) |
| Native Go Fail2Ban | Automatic banning after N failures, no external dependency |
| CrowdSec | LAPI stream bouncer → bans pushed to Core (403), Docker compatible |
| Automatic rules engine | Event-driven conditions (critical CVE, ban spike, silent engine, error rate, repeat offender IP, node offline, cert expiring) → actions (disable proxy, ban IP, alert, strict mode, webhook call, trigger backup); cooldown, dry-run, history — see [docs/security.md](security.md#automatic-rules-engine) |
| SSO | GitHub OAuth2, LDAP/Active Directory, SAML 2.0, OIDC (Google, Microsoft/Entra, Auth0, Okta, Keycloak, Zitadel, Casdoor, Dex, Authentik, Authelia) |
| JWT validation | JWKS (planned) |

### Request transformation pipeline

Each route can declare a `RequestTransform` block (Admin UI → proxy → **Transform** tab):

| Field | Description |
|---|---|
| `rewrite_from` / `rewrite_to` | URL prefix rewrite (e.g. `/api/v1` → `/v1`) |
| `add_request_headers` | Headers to inject into the upstream request |
| `remove_request_headers` | Headers to strip from the upstream request |
| `add_response_headers` | Headers to inject into the client response |
| `remove_response_headers` | Headers to strip from the client response |

The middleware applies first in the chain, before WAF and upstream routing. Hot-reload without Core restart.

### L4 mTLS Core↔Core tunnel

The `internal/core/tunnel` package provides a persistent encrypted TCP channel between two Cores (inter-datacenter L4 traffic, relay for backends unreachable from the entry Core).

**Architecture:**
```
Core A (client)          Core B (server)
   │                          │
   ├─ mTLS TLS 1.3 ──────────▶│:9443
   │   CONNECT-like:           │
   │   "host:port\n"  ──────▶  │ dial TCP target
   │   ◀── "OK\n"              │ bidirectional pipe
   │   [L4 stream]   ◁────────▶│
```

- **Manager** (client side): peer pool `PeerConfig{Name, Addr, CACert, CertPEM, KeyPEM}`, automatic reconnect, failover to other registered peers
- **Serve** (server side): mTLS listener `RequireAndVerifyClientCert`, TLS 1.3 min, CONNECT-like protocol on one ASCII line
- Usage: `Manager.Dial(peerName, targetAddr)` returns a ready-to-use `net.Conn` for proxying or L4 access

### Resilience

- **Load balancing**: Round Robin, Weighted, **Adaptive** (CPU×0.5 + mem×0.3 + disk IO×0.2 via Agent WS metrics)
- **Configurable active health checks**: `HealthCheckConfig` per route — `path`, `interval`, `timeout`, `healthy_threshold`, `unhealthy_threshold`; `StartChecksFromRoutes` replaces the global fixed-interval call
- **Failover**: short quarantine + try next backend on dial/proxy failure
- **Circuit Breaker**: thread-safe (mutex), `RecordSuccess`/`RecordFailure` called from handler after each attempt; automatic isolation of failing backends
- **Retry policy** with configurable exponential backoff
- **Sticky sessions** via cookie
- **Configurable server timeouts**: `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` HTTP/QUIC — configurable from Admin (Security > Server settings) and propagated to Cores via WebSocket

### Observability

- **Async JSON access log**: client IP, domain, method, HTTP code, duration, upstream, HTTP version
- **Structured JSON system log** for all components, with rotation
- **Prometheus metrics** exposed on `/metrics` — full instrumentation of all services: `gpx_core_*`, `gpx_backend_*`, `gpx_backend_up`, `gpx_peer_sync_duration_seconds`, `gpx_waf_profiles_active`, `gpx_portal_sessions_active`, `gpx_pipeline_*`, `gpx_tls_*`, `gpx_auth_*`, `gpx_ratelimit_*`, `gpx_traffic_*`, `gpx_routing_*`, `gpx_f2b_*`, `gpx_crowdsec_*`, `gpx_rulesengine_*`, `gpx_vulnscan_*`, `gpx_admin_http_*` — see `docs/services.md`
- **OpenTelemetry tracing** (planned)
- **JSON audit log**: full traceability of all operations

### GoProxify Access (SSH / shell portal)

Operator portal served by the **Core** (not Admin):

- **Dual façade**: web terminal (xterm.js) + standard `ssh` client with UUID token (`ssh -p 2222 <uuid>@<core>`)
- **Targets**: VM / bare-metal (`sshd`) or Docker containers (`docker exec` via Agent)
- **Vault**: SSH login + password or private key, encrypted on the Core (never exposed to Admin)
- Optional **2FA** (TOTP / OTP email); TTL / one-shot sessions / revocation; metadata audit
- Config & catalogue pushed from Admin (see §3)

---

## 3. Admin — Control Plane

### First start

- Automatic detection of missing SQLite database on first launch
- **Guided initialization screen**: enter administrator email and password
- Generation of ECDSA P-256 key for JWT token signing

### REST API

Endpoints on `:9443` — two families:

- `/api/v1/` — session JWT authentication (human administrators) **or** PAT `gpx_pat_*`
- `/internal/v1/` — pairing token authentication (Cores and Agents, backward compat)

| Resource | Operations |
|---|---|
| Proxies (HTTP, TCP, UDP) | Full CRUD + immediate push to Core(s) |
| Users | Create, edit, delete, password reset |
| Teams | Access organization by scope |
| Pairing tokens | Generate, list, revoke (`gpx_core_*`, `gpx_join_*`) |
| User API tokens (PAT) | Self-service `/api/v1/me/tokens` — resource scopes, optional expiry |
| Snippets | Reusable profiles: IP, TLS, CORS, rate-limit, auth providers, DNS providers |
| Nodes | Registration, cluster state, accept/reject pending |
| Agents | List, approve / revoke (pending → approved workflow) |
| Declared / bootstrap | Wizard declared nodes; QR tickets `/i/{token}` + `curl|bash` |
| Domains | Apex / wildcards, entry Core, ACME DNS, **delegation** Passthrough or Terminate to another Core |
| Security | Bans, CrowdSec threats, CVE, Fail2Ban, overview |
| Access | Destination catalogue, SMTP user invite, HTML templates, portal options per Core, audit |

### MCP server

Endpoint `https://<admin>:9443/mcp` — MCP protocol `2025-03-26`, JSON-RPC 2.0 + SSE.

- **Auth:** PAT only (`Authorization: Bearer gpx_pat_…`) — UI session JWT is rejected
- **Scopes:** each tool requires a scope (`proxies:read|write|delete`, `nodes:read|write`, `audit:read` for security, `portal:read|write` for Access, …) ∩ current account rights
- **Read:** proxies, nodes, agents, declared-nodes, alerts, metrics, backups, users, snippets, domains, certs, logs, teams, audit, bans / threats / CVE, alert channels/rules, auth providers, IP profiles, Access (config, catalogue, users, templates, audit)
- **Write:** `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `approve_agent`, `revoke_agent`, `create_declared_node`, `create_bootstrap_ticket`, `accept_node` / `reject_node`, `create_security_ban`, `delete_security_ban`, `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `create_auth_provider`, `delete_auth_provider`, `create_ip_profile`, `delete_ip_profile`, `create_snippet`, `delete_snippet`, `create_domain`, `renew_domain`, `obtain_cert`, Access tools (`update_portal_*`, `invite_portal_user`, `push_portal`, templates…)
- Documentation: [docs/mcp.md](mcp.md)
- **Access control (`/mcp-access`, admin only):**
  - **Source IP allowlist:** admins restrict `/mcp` to a list of IP/CIDR entries (`GET`/`PUT /api/v1/mcp-access/allowed-ips`); enforced server-side before PAT auth even runs. Empty list (default) = no restriction.
  - **Active users:** table of every user holding an active PAT on the instance, with their scopes — "who can use the MCP" at a glance.
  - **Scope catalogue (reference):** each scope's covered MCP tools. Scope selection at issuance stays self-service on `/api-tokens` (a PAT is personal to its holder).

### Automation menu

`Automatisation` groups three sub-pages, all admin-only:

| Page | Route | Content |
|------|-------|---------|
| Automatic rules | `security-rules` | Rules engine CRUD, dry-run, execution history (see [docs/security.md](security.md#automatic-rules-engine)) |
| Alert channels | `alert-channels` | Notification channels (email, webhook, ntfy, gotify) |
| Rule store | `rules-store` | 15 preconfigured rule templates (`GET /api/v1/rules-engine/templates`), one-click install via `POST /api/v1/rules-engine/templates/{id}/install` |

### Architecture wizard

The **Infrastructure → + Add** entry opens an **architecture canvas** (hosts + palette): Core / Agent / Admin placement, Access / Portainer / K8s options, multi-Core and HA groups. For each host, copy-paste install packs + bootstrap ticket (QR / `/i/{token}` link / `curl|bash`) anchored to the Core. Nodes declared from the canvas can be **auto-accepted** on connection.

### Multi-Core delegation

A domain can be **delegated**: the entry Core (DNS / public IP) forwards traffic to a target Core.

| Mode | Behavior | Client IP on target Core |
|---|---|---|
| **Passthrough** | Raw TLS tunnel (SNI) | Entry Core's IP |
| **Terminate** | TLS terminated at entry + HTTP(S) proxy + `X-Forwarded-For` | Public IP (if seen by entry) |

Detailed documentation: [delegation.md](delegation.md).

### WebSocket control plane

Admin maintains a **persistent WS connection** to each registered Core (Admin→Core). This connection replaces HTTP push calls to `/internal/v1/*`:

- **Automatic reconnect**: exponential backoff 1s → 60s + jitter
- **Full-sync on reconnect**: complete state automatically resent
- **Message queue**: messages emitted during a disconnect are queued and delivered on reconnect
- **Immediate propagation**: any config change is sent in real time to the affected Core

### Agent approval

Agents connecting for the first time via `JOIN_TOKEN` appear in `pending` status. The operator approves via UI or API (`POST /api/v1/agents/:id/approve`). The Core immediately sends the first `agent_hmac` via WS.

### TLS / ACME DNS-01 management

- **Wildcard Let's Encrypt certificates** via DNS-01 challenge
- Supported DNS providers: **OVH, Cloudflare, Gandi, Route53, Hetzner**
- Automatic renewal 30 days before expiry
- Push decoded certificates to Core in RAM only (never on disk on Core side)

### Certificate Hub (v0.8)

Feature suite around the TLS certificate lifecycle.

**ACME monitoring — single entry point** (`/acme-monitor`, sidebar Access → Monitoring ACME)
- Unifies what used to be three separate menus ("Certificates", "Certificate deployment", "ACME Monitoring") into one page — the other two are removed
- Dashboard: status per cert (`ok` / `warning ≤30d` / `critical ≤7d` / `expired`), global KPIs, inline renewal button
- Per-row actions: **Deploy** (opens the Deploy Hub drawer below) and **Edit** (opens the source domain's modal — DNS provider, manual PEM, entry Core, delegation — disabled when the cert has no linked domain, e.g. manual import); `domain_id` field in `GET /api/v1/certs/acme-monitor` links the emitted cert back to its `domains` row
- Automatic alerts: `cert_expiring_soon` (warning ≤30d, critical ≤7d) emitted to the existing alert engine
- **Multi-DNS providers**: manage multiple named providers (e.g. `cloudflare-prod`, `ovh-zone2`) via the "DNS Providers" section of the ACME Monitoring page; each provider has a type (`cloudflare`, `ovh`, `gandi`, `hetzner`, `route53`) and JSON credentials; full CRUD via `/api/v1/acme/providers`

**External certificate import**
- `POST /api/v1/certs/import`: PEM + private key upload — domain auto-extracted from SAN/CN, upserted in DB, real-time push to Cores
- Modal interface in the `acme-monitor` page

**Deploy Hub** (reachable via the "Deploy" button on each cert row in ACME Monitoring — no longer a standalone menu)
- **Deploy targets**: webhook (POST HMAC-SHA256 signed) or `ssh_exec` (script executed on target machine with `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN`)
- Automatic trigger on each ACME renewal + manual trigger
- Audit history per target (`cert_deploy_history`)
- `cert_deploy_failed` alert on failure

**Pull tokens**
- Secure tokens (HMAC-SHA256, TTL, max_uses) for pull download via `curl`
- 7 output formats: `pem`, `key`, `fullchain`, `der`, `der_key`, `pkcs12` (password), `json`
- Public endpoint `GET /api/v1/cert-bundle?token=…&format=…`

### Granular alerting

Alertmanager-inspired model: each rule independently defines its scope, triggers and channels. The same event can notify multiple teams on different channels.

**Rule scope**:
- Target node(s)
- Domain pattern (glob: `infra.*.com`, `*.prod.*`)
- Team(s)
- Component (`core` / `agent` / `admin`)
- Minimum severity (`info` / `warning` / `critical`)

**Configurable triggers**:
- Core/Agent node offline
- Certificate expiring in < N days
- CVE detected on a backend
  - The HTTP scanner rejects private targets (RFC1918/ULA), localhost and cloud metadata by default (anti-SSRF). To scan Docker/LAN backends: `GPX_VULNSCAN_ALLOW_PRIVATE=true` on Admin, or via the toggle in the UI (Security > CVE Scanner, Core view only — the manual scan trigger, the private-network toggle and the scanner status card all live on the Core side; the Admin view shows only the aggregated CVE list across all Cores, with a Core column identifying which Core reported each CVE).
- New Fail2Ban ban (threshold: N bans/hour)
- Critical CrowdSec decision
- Sensitive configuration change
- Scheduled backup failure
- HTTP error rate > threshold on a proxy
- P95 latency > threshold on a proxy
- N failed admin login attempts

**Quality of service**: anti-spam rate limiting per trigger, grouping of similar alerts (configurable cooldown).

### Scheduled backups

- **Core**: routing table snapshot (JSON), per-proxy versioning, navigable history, per-proxy rollback
- **Admin**: JSON dump (users, token metadata without secrets, snippets, alert channels/rules, declared nodes, plus configuration tables: settings incl. MCP IP allowlist, automatic rules, teams/scopes, workspaces, domains, cert deploy targets, auth providers, IP profiles, tunnel configs, error/portal pages, fail2ban/CrowdSec config); secrets redacted (a redacted secret never overwrites an existing value on restore); optional AES-GCM encryption via `GPX_BACKUP_KEY`
- **Configurable cron** scheduling, configurable retention (number of snapshots)
- Restore with diff preview before applying
- CLI: `goproxify backup create/list/restore`

### Third-party config import

Automatic source format detection. Two modes: paste content or import one or more files. Preview before validation, partial import possible.

Supported formats: nginx, HAProxy, Traefik YAML, Traefik TOML, Traefik Labels, Caddy, Zoraxy, BunkerWeb, CSV, GoProxify native JSON.

### Coordinated cluster update

- Version inconsistency detection between nodes (via heartbeat)
- Alert if Cores or Agents run different versions
- Triggered from UI (per node or entire cluster) or via CLI
- Configurable rolling update (one node at a time, validation between each)
- Cluster rollback orchestrated from Admin

### Web interface

- Dashboard: cluster state, real-time metrics
- Unified proxy list view (HTTP/HTTPS + TCP + UDP) — Docker labels greyed out read-only
- Adaptive create/edit form by proxy type
- Interactive Docker Compose label generator (HTTP, TCP, UDP)
- TLS certificate, snippet, token, user, team management
- Integrations: Prism (traffic analysis), Security dashboard, Backups, Import
- **Logs**: aggregated view (access + system + audit), filters, pagination, live mode via WebSocket
- **Prism**: KPIs, time series, GeoIP map, HTTP codes, top IPs/paths/referrers, CSV/JSON/HTML/PDF exports

---

## 4. Agent — Discovery & Telemetry

### Docker discovery

- Listens to Docker events via Unix socket (`/var/run/docker.sock`, mounted read-only)
- Detects `goproxify.*` labels on containers at startup and in real time (start/stop/die)
- **Hot-connects** the Core to the application's private Docker bridge network (apps expose no port on the host)
- Transmits network configuration to Admin (validated token)
- Discovered proxies marked `source: "label"` → read-only in UI

### Supported Docker labels

> Full reference: [docs/labels.md](labels.md)

Key examples:

```yaml
goproxify.enable: "true"
goproxify.host: "app.example.com"
goproxify.port: "3000"
goproxify.tls: "true"
goproxify.waf: "block"
goproxify.sentinel.whitelist: "10.0.0.0/8"
goproxify.canary: "true"
goproxify.canary.weight: "10"
```

### Kubernetes discovery

Symmetrically to Docker mode, the Agent can discover annotated Kubernetes resources:

- Watches `Ingress` and `Service` resources carrying `goproxify.*` annotations
- Same annotation semantics as Docker labels (`goproxify.enable`, `goproxify.host`, `goproxify.port`, etc.)
- Proxies created read-only in UI (source `k8s`)
- Requires a `ServiceAccount` with `get/watch/list` access on `ingresses` and `services`
- Compatible with multi-namespace Kubernetes deployments; target namespace configurable in `agent.json`

```json
{
  "kubernetes": {
    "enabled": true,
    "kubeconfig": "/etc/goproxify/kubeconfig",
    "namespaces": ["production", "staging"]
  }
}
```

### Horizontal auto-scaling

- Configurable triggers: container CPU (Agent telemetry) and/or request rate / P95 latency (Core metrics)
- Coordinated decision by Admin (min/max instance rules)
- Instance creation/deletion via `docker compose up --scale` or `docker run`
- Hot-add to Core routing table without interruption
- Compatible with resource-weighted adaptive load balancing
- Configurable cooldown between decisions (anti-flapping)

### Health escalation

Progressive recovery logic for `unhealthy` containers:

1. **Simple restart** (`docker restart`)
2. **Recreate** if still unhealthy after configurable delay (`docker rm` + `docker run`)
3. **Rollback** to previous image
4. **Quarantine**: removal from LB pool + operator alert

Delays and thresholds configurable per container via `goproxify.healthcheck.*` labels.

### Image lifecycle management

- Detection of available updates (local vs registry digest comparison)
- Per-container strategies: `auto`, `scheduled` (cron), `manual`
- Pull + recreate without interruption if multiple replicas
- Automatic rollback if container does not return `healthy` within configured delay
- Optional prune after successful update

### Log forwarding

- Collection of labelled container logs (`docker logs --follow`) opt-in (`goproxify.logs: "true"`)
- Real-time streaming to Admin
- Correlation with Core/Agent/Admin logs in Logs view
- Configurable rotation and retention per container

### System telemetry

- Reads `/proc/stat` and `/proc/meminfo`
- Prometheus export on `:9191/metrics`
- Data used by Core adaptive load balancing (host + containers via WS)

### Persistent WS connectivity

Agent maintains a **persistent WS connection** to the Core (Agent→Core). This connection:

- **Replaces the HTTP 30s heartbeat**: heartbeat sent via WS if connected, HTTP as fallback
- **Transmits discovered containers** in real time via `containers` message
- **Streams per-container metrics** (CPU, mem, latency) via `metrics` message every 10s
- **Sends lifecycle events** (start, stop, scale, die) via `event` message
- **Automatic reconnect**: exponential backoff 1s → 60s + jitter
- The Agent exposes **no inbound port** for the control plane

**Authentication:**
1. First start: `JOIN_TOKEN` (TTL 24h) → `pending` state
2. After Admin approval: rotating `agent_hmac` (automatic rotation every hour)

### Adaptive LB

Docker metrics (**CPU**, **memory**, **disk IO**) of `goproxify.enable` containers are streamed to the Core every **10s** via WS (`metrics`). Score per IP:

`cpu×0.5 + mem×0.3 + disk_io×0.2` — lowest score backend receives the request.

- **Local pool**: multiple containers with the same `goproxify.host` → one `docker-host:…` multi-backend route.
- **Failover**: proxy failure → ~15s quarantine → try another pool backend (no 502 as long as one healthy remains).
- **Cross-Core**: if the same host is discovered on Core A and Core B, peer sync + `gateway/tunnel` tunnel to the remote IP via the owner Core (see [architecture.md](architecture.md#adaptive-load-balancing)).

P95 latency / error_rate: fields planned in payload, not used in v1 score.

### Canary and Shadow Mirror

**Manual** configuration on the proxy (UI / API): `CanaryConfig` (weight %, header, cookie) and `ShadowConfig` (fire-and-forget mirror).

Docker labels `goproxify.canary` / `goproxify.shadow`: automatic detection via Agent discovery — the Core activates `CanaryConfig` / `ShadowConfig` on the `docker-host:` route without manual config. The canary/shadow container stays outside the LB pool (same `goproxify.host` as normal backends).

### Network connectivity

- Optional **WireGuard** tunnels for inter-node communication (port `:51820` UDP)

---

## 5. Alert channels

All channels can be combined in the same rule.

| Channel | Description |
|---|---|
| **Email** | Configurable SMTP, direct notification to operators |
| **Webhook** | Generic webhook — compatible with Slack, Discord, Teams, n8n, etc. |
| **ntfy.sh** | Mobile push, self-hosted or public instance |
| **Gotify** | Mobile push, self-hosted |
| **Jira** | Automatic issue creation in a Jira project |
| **Linear** | Automatic issue creation in Linear |
| **GitHub Issues** | Issue opened in a GitHub repository |
| **GitLab Issues** | Issue opened in a GitLab project |
| **Zammad** | Ticket creation in the Zammad open-source ticketing system |
| **GLPI** | Ticket creation via the GLPI REST API |

Each channel has a "Test" button in the admin interface.

---

## 6. Config import

| Format | Notes |
|---|---|
| **nginx** | `server {}` blocks |
| **HAProxy** | `frontend` / `backend` sections |
| **Traefik YAML** | Routes, middlewares, TLS configuration |
| **Traefik TOML** | TOML equivalent |
| **Traefik Labels** | Interactive conversion guide to GoProxify config |
| **Caddy** | Caddyfile |
| **Zoraxy** | Native Zoraxy JSON |
| **BunkerWeb** | BunkerWeb configuration |
| **CSV** | Columns: domain, backend, options |
| **JSON** | GoProxify native format or generic JSON |

---

## 7. CLI

```
goproxify <command> [options]
```

| Command | Role |
|---|---|
| `admin` | Start Admin (Control Plane + Web UI) |
| `core` | Start Core (Data Plane — Reverse Proxy) |
| `agent` | Start Agent (Discovery & Telemetry) |
| `token create/list/revoke` | Core/Agent pairing tokens (Admin API) |
| `backup create/list/restore` | Admin snapshots + routing export (Admin API) |
| `import` | Import nginx/Traefik/Caddy/HAProxy (parse local, apply remote) |
| `proxy list/get/enable/disable/delete` | Proxy route management |
| `cert list/obtain/delete` | TLS certificates |
| `user list/get/create/update/passwd/delete` | Admin user accounts |
| `audit list/export` | Action audit log |
| `logs list/export` | Access and system logs |
| `alert channels/rules/test` | Alert channels and rules |
| `snippet list/get/create/update/delete` | Reusable middleware snippets |
| `domain list/get/create/renew/delete` | Managed ACME domains |
| `agent-mgmt list/get/approve/revoke/delete` | Registered Docker agents (management) |
| `settings smtp/mfa` | Admin config: SMTP, MFA (SMS, WebAuthn) |
| `auth-provider list/get/create/update/enable/disable/delete` | External auth providers (OIDC, SAML…) |
| `teams list/get/create/update/delete + members` | RBAC teams |
| `workspaces list/get/create/update/delete + members + resources` | Workspaces (multi-tenant) |
| `ip-profile list/get/create/update/delete` | IP profiles (CIDR allowlist/blocklist, GeoIP) |
| `containers list` | Discovered Docker containers (read-only) |
| `me get/update/passwd + me tokens` | Current profile + personal API tokens (PAT) |
| `security threat/bans/waf` | Security: Sentinel, IP bans, WAF per proxy |
| `status` | Cluster state (nodes, versions, health) |
| `access` | GoProxify Access (config, catalogue, users, templates, audit) |
| `nodes` | List / accept / reject nodes (Infrastructure) |
| `declared` | Architecture wizard declared nodes |
| `bootstrap` | QR / curl\|bash host integration tickets |
| `core cache show/refresh/export/clear` | Core local cache management |
| `update check/apply/rollback` | Docker image updates (via Agent) |
| `version` | Display binary version |
| `help` | Display help |

Common options: `-config <path>`, `-admin-url <url>`, `-token <token>` (or `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`).

---

## 8. High Availability

### Core — independent groups

- Cores organize into **groups** (by datacenter, region, customer…)
- Each group elects its **coordinator via the Raft algorithm** (majority required)
- Any config change is validated by the group majority before applying
- If the network partitions a group, only the majority half can elect a coordinator
- On loss of Admin access, each Core falls back to its **encrypted local cache**

### Admin — rqlite

- **3 Admin instances** continuously synchronized via rqlite (distributed SQLite over Raft)
- Writes go through the **leader node**, reads on any node
- If one instance goes down, the other two continue without interruption
- Automatic leader failover in seconds

### Inter-node connectivity

- WireGuard tunnels managed by the Agent for secure communication between groups
- Adaptive load balancing based on metrics reported by Agents

---

## 9. Deployment

| Mode | Details |
|---|---|
| **Docker Compose** | `docker compose up -d` — recommended, `docker-compose.yml` and `docker-compose-dev.yml` files provided |
| **Bare-metal** | Interactive `setup.sh` script — module selection (Admin / Core / Agent) |
| **systemd** | Hardened service (systemd units with sandboxing) |
| **setcap** | `setcap cap_net_bind_service` to listen on ports < 1024 without root |

Configuration: JSON files in `config/` (`admin.json`, `core.json`, `agent.json`) + `GPX_*` prefixed environment variables (production priority).

---

## 10. Tech stack

| Domain | Choice |
|---|---|
| Language | Go — single binary, zero runtime dependency |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 QUIC (UDP), WebSocket, gRPC, TCP/UDP L4 |
| **Control plane** | **Persistent WebSocket (nhooyr.io/websocket) — Admin→Core(WS), Agent→Core(WS)** |
| TLS | `crypto/tls` + `GetCertificate` (RAM only), passive SNI passthrough, ACME DNS-01 wildcard |
| Routing table | `sync.Map` — atomic updates without interruption |
| Persistence | Embedded SQLite `modernc.org/sqlite` (CGO-free) — Admin only |
| Admin HA | rqlite (distributed SQLite, 3 nodes, Raft) |
| Core HA | Raft algorithm per group, encrypted local cache |
| Configuration | Viper — JSON + `GPX_*` env var override |
| Discovery | Docker Engine API via Unix socket (`/var/run/docker.sock`) |
| Metrics | Prometheus (`/metrics`), OpenTelemetry |
| Auth | JWT ECDSA P-256, bcrypt passwords, HMAC-SHA256 WS control plane, JOIN_TOKEN lifecycle, PAT `gpx_pat_*` (API + MCP) |
| App security | Native Go Fail2Ban, CrowdSec LAPI bouncer, native Go WAF (OWASP CRS-4, 13 rules) |
| LLM integrations | MCP server JSON-RPC 2.0 + SSE (`/mcp`, PAT auth) |
| Deployment | Single binary · Docker Compose · systemd (hardening) · `setcap cap_net_bind_service` |
