# GoProxify

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-preview%20%2F%200.x-orange.svg)](DISCLAIMER.md)
[![Go](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](go.mod)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fvincamok%2Fgoproxify-black)](https://github.com/Vincamok/goproxify/pkgs/container/goproxify%2Fadmin)
[![Release](https://img.shields.io/github/v/release/Vincamok/goproxify?display_name=tag&sort=semver)](https://github.com/Vincamok/goproxify/releases)

**GoProxify is a distributed reverse proxy compiled as a single Go binary** — built to manage multiple servers from a central interface, without heavy agents or configuration scattered across every machine.

You have several VPS, Docker containers on different hosts, and you want to route traffic, manage TLS certificates and keep control of everything from one place? That's exactly what GoProxify is for.

### What makes it different

- **One binary, three roles** — the same executable starts as Edge (proxy), Admin (management UI) or Agent (service discovery)
- **The Edge is autonomous** — it starts and routes traffic even when the Admin is unreachable; routes and certificates are held locally, in RAM
- **HTTP/1.1, HTTP/2, HTTP/3 QUIC, TCP/UDP L4** — one tool covers all protocols
- **Built-in OWASP CRS-4 WAF** — 13 rule sets (SQLi, XSS, Log4Shell…) with no external plugin
- **SSH and Docker access from the UI** — web terminal, UUID `ssh` to VMs and `docker exec` to containers, directly from your browser
- **Automatic service discovery** — the Agent reads `goproxify.*` labels on Docker/Podman containers and Kubernetes services, or tags from Consul, Nomad, etcd and Amazon ECS, and pushes routes in real time; a discovered container can be converted into a regular, editable proxy with one click, or its route switched off and on without touching the container
- **WASM plugins** — sandboxed plugins on requests, bodies and TCP/UDP streams; Coraza (SecLang) and ready-made examples installable in one click
- **Alerting to 10 channels** — Email, Webhook, ntfy.sh, Jira, Linear, GitHub Issues, and more

---

> **Preview (0.x).** Use at your own risk. Details: [DISCLAIMER.md](DISCLAIMER.md) · license [Apache-2.0](LICENSE).

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Support: [Discussions](https://github.com/Vincamok/goproxify/discussions) · Roadmap: [suivi/roadmap-public.md](suivi/roadmap-public.md).

---

## Architecture

```
                        ┌──────────────────────────────────┐
                        │  ADMIN  (Control Plane)          │
                        │  Web UI · REST API · MCP · :9443 │
                        │  SQLite · ACME · Alerting        │
                        │  Proxies: Edge YAML files        │
                        │  rebuildable from Edges          │
                        └──────────┬───────────────────────┘
                                   │ persistent WS Admin→Edge
                                   │ (push routes/certs/config)
                                   ▼
┌──────────────┐    ┌──────────────────────────────────────┐
│   INTERNET   │───►│  EDGE  (Data Plane · central WS hub) │
│  :80 / :443  │    │  HTTP/1·2·3 QUIC · TCP/UDP L4        │
│  HTTP/1·2·3  │    │  TLS in RAM · AES-256 local cache    │
└──────────────┘    │  Zero reload · autonomous w/o Admin  │
                    │  :80 :443 :443/UDP :8000+WS (internal)│
                    └────────────▲─────────────────────────┘
                                 │ persistent WS Agent→Edge
                                 │ (heartbeat/metrics/events)
                    ┌────────────┴─────────────────────────┐
                    │  AGENT  (Docker Discovery)           │
                    │  Uses docker.sock (host access)      │
                    │  Detects goproxify.* labels          │
                    │  Prometheus :9191/metrics            │
                    │  No inbound control-plane port       │
                    └──────────────────────────────────────┘
```

| Component | Role | Persistence | Exposed ports |
|-----------|------|-------------|---------------|
| **Edge** | Data Plane — routing, TLS, L4 · WS control-plane hub | RAM + encrypted local cache · **YAML proxies** (`proxies/*.yaml`) | `:80`, `:443` (TCP+UDP), `:8000` (internal + WS) |
| **Admin** | Control Plane — UI, API, alerting | SQLite (config, users, tokens) | `:9443` |
| **Agent** | Docker discovery & metrics | Volatile | `:9191` (Prometheus) — **no inbound WS port** |

### Example layouts

Many layouts are possible; two reference examples (also shown on the landing page). Read them top to bottom: Internet → gateways (Edges) → Agents (HTTP(S) proxies via labels) or hosts (TCP/UDP proxies). The Admin is the management link to the Edges.

**Home lab — 1 Admin · 1 Edge · 1 Agent**

```
              INTERNET
                 │ HTTPS · TCP · UDP
                 ▼
  ADMIN ◄──► GATEWAY (Edge)
                 │
        ┌────────┴─────────┐
        ▼                  ▼
  Docker host          Other host (NAS, VM…)
  AGENT + containers   TCP/UDP direct, no Agent
  (HTTP(S) via labels)
```

**Enterprise, redundant — 1 Admin · 2 Edges · 4 hosts with Agents**

```
                    INTERNET
                       │ HTTPS · TCP · UDP
        DNS round-robin or virtual IP
           ┌───────────┴───────────┐
           ▼                       ▼
   GATEWAY 1 (Edge) ◄─ ADMIN ─► GATEWAY 2 (Edge)
           └───────────┬───────────┘
                Internal network
     ┌──────────┬──────┴───┬──────────┐
     ▼          ▼          ▼          ▼
   HOST 1     HOST 2     HOST 3     HOST 4
   AGENT      AGENT      AGENT      AGENT
```

Step-by-step install for both: [docs/deployment.md](docs/deployment.md).

---

## Quick start

> Preview only — read [DISCLAIMER.md](DISCLAIMER.md) before any deployment.

### Launcher (recommended)

One command, no file to write: the launcher pulls its image, generates the secrets, the admin account, a TLS certificate and a backup key, deploys Admin + Edge + Agent on this machine, then removes itself.

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview --admin --edge --agent
```

Without options, add `-p 8080:8080` to open its design page (`http://<host>:8080/design`, access code printed in its output): declare your machines and roles and watch the diagram of the infrastructure update (drawing or Mermaid text). Other machines install from a QR code shown by the Admin; `launcher update` updates a host keeping its volumes; `launcher --restore` rebuilds a lost Admin from a backup. See [docs/cli.md](docs/cli.md) and [ADR 0019](docs/adr/0019-launcher-bootstrap-multi-hotes.md).

### Docker Compose (files you can read and edit)

```bash
# 1. Run the quickstart script — it generates docker-compose.yml and .env
curl -fsSL https://github.com/vincamok/goproxify/raw/main/scripts/quickstart.sh -o quickstart.sh
bash quickstart.sh
```

The script generates hex-32 secrets, writes `.env` (chmod 600), checks Docker / ports,
then starts Admin + Edge + Agent. Variants (run alone): `bash quickstart.sh --print-secrets`
· `bash quickstart.sh --env-only`.

Images are published on **GHCR** (`ghcr.io/vincamok/goproxify`). Default quickstart:
floating tag **`preview`**. To pin a SemVer: `GOPROXIFY_ADMIN_TAG`,
`GOPROXIFY_EDGE_TAG`, `GOPROXIFY_AGENT_TAG` (see `versions.json` / `.env.example`).

The admin interface is available at **http://localhost:9443**.

The Edge and Agent pair automatically with the Admin via `GPX_PAIRING_SECRET` — no manual token copy needed.

### Portainer

1. **Stacks → Add stack → Web editor**
2. Paste the compose from [docs/deployment.md](docs/deployment.md#33-créer-le-fichier-docker-composeyml) (or run `bash scripts/quickstart.sh --env-only` locally and copy the generated `docker-compose.yml`)
3. Environment variables: `GPX_JWT_SECRET`, `GPX_PAIRING_SECRET`, `GPX_FIRST_ADMIN_EMAIL`, `GPX_FIRST_ADMIN_PASSWORD` (generate secrets with `openssl rand -hex 32`)
4. **Deploy the stack**

### Binary

```bash
# Build
git clone https://github.com/vincamok/goproxify && cd goproxify
go build -o goproxify ./cmd/goproxify

# Start Admin
GPX_SECURITY_JWT_SECRET=<secret> ./goproxify admin

# Start an Edge (token generated from Admin UI)
GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://localhost:9443 \
GPX_EDGE_TOKEN=gpx_... \
./goproxify edge

# Start Agent (optional)
GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://localhost:8000 \
./goproxify agent
```

---

## Pairing Edge / Agent

### Edge → Admin

Two methods to connect an Edge to an Admin:

| Method | Use case | Variable |
|--------|----------|----------|
| **Shared secret** | All-in-one stack (same machine / same compose) | `GPX_PAIRING_SECRET` |
| **Explicit token** | Remote Edge, multi-site | `GPX_EDGE_TOKEN` |

The shared secret is the recommended method for standard deployments. The explicit token is generated from Admin UI → Settings → Tokens.

### Agent → Edge (WS)

The Agent↔Edge control plane uses a persistent WebSocket tunnel. The Agent connects to the Edge — not the other way around.

| Step | Description | Variable |
|------|-------------|----------|
| 1. **JOIN_TOKEN** | First start — Agent connects and enters `pending` state | `GPX_CONTROL_PLANE_JOIN_TOKEN` |
| 2. **Approval** | Operator approves the Agent in Admin UI | — |
| 3. **agent_hmac** | Edge sends an HMAC secret via WS → Agent is `approved` | auto-negotiated |
| 4. **Rotation** | Edge regenerates `agent_hmac` every hour | automatic |

To generate a `JOIN_TOKEN`: Admin UI → Tokens → Create → role `agent`, TTL `24h`.

---

## CLI

```
goproxify <command> [options]

Service commands:
  admin    Start Administration (Control Plane + Web UI)
  edge     Start Edge (Data Plane — Reverse Proxy)
  agent    Start Agent (service discovery)
  landing  Start landing page (optional)

Operational commands (talk to Admin via HTTP):
  token      Edge/Agent pairing tokens
  backup     Backup and restore
  import     Import from nginx / Traefik / Caddy / HAProxy
  alert      Test alert channels
  status     Cluster status
  access     GoProxify Access (config, catalogue, users, templates, audit)
  nodes      Infrastructure nodes (list / accept / reject)
  declared   Architecture wizard declared nodes
  bootstrap  QR tickets / curl|bash host integration
  launcher   Install Admin / Edge / Agent on this host from one command (ghcr.io/vincamok/goproxify/launcher image)
  update     Update Docker images (via Agent)

  version  Binary version
  help     Help
```

Common auth for operational commands: `-admin-url` / `-token` or env vars `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`.

Full reference → **[docs/cli.md](docs/cli.md)**

---

## Features

### Edge (Data Plane)

- **HTTP/1.1, HTTP/2, HTTP/3 QUIC** routing (UDP)
- **TCP and UDP (L4)** streaming
- TLS termination + SSL Passthrough via passive SNI detection
- Routes and certificates stored **in RAM** (`sync.Map`, `GetCertificate`) — no private key on disk
- **AES-256-GCM encrypted local cache** — starts and routes without Admin available
- Hot configuration reload, zero connection interruption
- Load balancing (Round Robin, Weighted, adaptive CPU/mem/IO + failover + inter-Edge gateway), Circuit Breaker, Retry, per-route slow-start
- Rate limiting, per-route **backpressure** (bounded queue, 503 + Retry-After), IP/CIDR filtering, Geo-IP, **OWASP CRS-4 WAF** (13 rule sets: SQLi, XSS, LFI, RCE, PHP, SSRF, Scanner, Java/Log4Shell, RFI, NodeJS, HTTP Smuggling, Sensitive Files, Response Leaks), HTTP security headers
- **Automation flows** — rules, schedules and playbooks built in one flow editor: a trigger (conditions on CVEs, bans, error rate, offline nodes, expiring certificates or any sampled metric; alert events; cron; manual runs with parameters) → steps (disable proxy, ban IP, notify, strict Fail2Ban mode, webhooks, PagerDuty, backup, wait, if/else, human approval, call a playbook); simulation, versions, parameterised templates, and simple flows run by the gateways even when the Admin is down
- Basic, Forward Auth, JWT authentication per route
- Live topology map (health, req/s, risk score per node), async JSON access log, Prometheus metrics, OpenTelemetry tracing (W3C `traceparent` propagated caller → Edge → backend, sampling)
- **GoProxify Access** — operator portal on the Edge: web terminal + UUID `ssh` to VMs/`sshd` and Docker containers (`docker exec` via Agent); SSH login vault + secrets; 2FA; TTL sessions

### Admin (Control Plane)

- **Web UI + REST API** — CRUD proxies, snippets, tokens, users; three skins (Flat, Industry DS, Console), light or dark, each with its own accent colours
- **GoProxify Access** — destination catalogue (global / per-Edge view), invite users by email (SMTP), tags, Access HTML templates, portal options per Edge
- **User API tokens (PAT)** — `gpx_pat_*` self-service with scopes (`proxies:read`, `certs:write`, …) for scripts and MCP clients; a read scope never allows a write; distinct from Edge/Agent pairing tokens
- **MCP server** — JSON-RPC 2.0 + SSE; **PAT-only** authentication (no session JWT); every tool and resource requires the scope of its REST equivalent, plus the admin role where the REST route is admin-only — a tool without a declared scope is refused
- **Terraform provider** — [`integrations/terraform-provider-goproxify`](integrations/terraform-provider-goproxify): proxies, bans (optionally scoped to a gateway or HA group), ban whitelist and IP profiles as code, with import and drift detection (not yet published on the Terraform Registry)
- **Infrastructure view & architecture editor** — live flow schema (Internet → Edges → Agents) with a node detail panel and a "to handle" bar; in-place editing (drag-and-drop palette, host cards, changes flagged with their impact, review before save), multi-Edge/HA, QR tickets / `curl|bash` to integrate a host
- **Bans page** — the same page in the Admin (all Edges) and in each Edge menu: KPIs, 48 h timeline, origin by country, filters, bulk actions and a mobile card layout; every ban records the Edge that reported it
- **Ephor and the WAF learn** — one risk note per IP, shared by both engines: every request feeds a behavioural store (rate, error spread, missing assets, regular cadence, User-Agent vs TLS fingerprint, whole-ASN failures), compared with the **normal rate learned per route and hour**; every new signal starts in `detect` (explained in the ban it would have caused, counted as a shadow note) and moves to `block` after a log replay; a long clean history raises the ban threshold; works without the Admin — see [docs/security.md](docs/security.md#note-commune-et-signaux-de-comportement-adr-0011)
- **Surface learning (observe only)** — switch a proxy to `learn` and the gateway builds a profile of what its legitimate traffic really uses: methods, path templates (`/api/users/{int}`), content types, body sizes, parameters, clients. Nothing is blocked, scanners and suspicious IPs teach it nothing, no value or IP is stored, and a convergence check tells you when the profile can be trusted. From that profile it proposes justified settings (body size limit, rate limit, countries, client networks, CORS origins) without applying anything — see [ADR 0016](docs/adr/0016-apprentissage-de-la-surface-d-un-proxy.md); it can also generate that profile as an OpenAPI specification for the existing `openapi` control, in detect mode, and lists the requests that fall outside it. It can then refuse those violations one type at a time (unknown path, unknown method, invalid parameter…), with guard rails against blocking too early and one gesture back to detect. Learning stays on afterwards: paths that keep coming back from clean clients are suggested for addition, and the policy never widens by itself.
- **WAF exclusions that stay narrow** — a rule that misfires on legitimate traffic (a CMS editor posting HTML, an admin console sending SQL) is excluded **per path** (`waf.exclusions`: `/wp-admin/` only) and stays active on the rest of the proxy; platform auto-recognition only reports what it found and suggests the path, it never changes the protection on its own. Details: [docs/security.md](docs/security.md).
- **HA groups** — Ephor, the WAF switch, HTTP timeouts and the access portal are configured once per HA group; the portal store (accounts, 2FA, vaults, optional shared web sessions) and Ephor reference lists are replicated between Edges, and bans keep flowing between peers when the Admin is down
- **Guided first start** — initial configuration wizard
- ACME DNS-01 wildcard management (OVH, Cloudflare, Gandi, Route 53, Hetzner and 28 more providers through [libdns](https://github.com/libdns): DigitalOcean, Scaleway, Namecheap, GoDaddy, Azure DNS, Google Cloud DNS, Porkbun, deSEC…), plus HTTP-01 and TLS-ALPN-01 validation served by the Edge (no DNS provider needed)
- OCSP stapling fetched autonomously by each Edge
- Certificate push to Edge (RAM only, never persisted on Edge side)
- **Certificate Hub** — ACME monitoring (dashboard + expiry alerts), external PEM cert import, deploy targets (HMAC webhook / ssh_exec), multi-format pull tokens (PEM/DER/PKCS#12/JSON)
- **Internal CA** — generate a self-signed internal root CA and issue server/client certificates for internal services, outside ACME
- **Encrypted Client Hello (ECH)** — hide the site name (SNI) in the TLS handshake; keys generated by the Admin, kept by the Edges, rotation, `goproxify ech`
- **Granular alerting** — rules per node/domain/team, 10 channels: Email, Webhook, ntfy.sh, Gotify, Jira, Linear, GitHub Issues, GitLab Issues, Zammad, GLPI
- Structured audit log for all components
- **GDPR-ready access logs** — client IPs kept in full, anonymised or pseudonymised (AES-GCM, revealable with an audited legal reason by the superadmin or a delegated DPO, account or team), retention that defaults to 90 days, Art. 15/20 export and Art. 17 erasure by IP or user (also on the gateways), no third-party geolocation unless you opt in — see [docs/rgpd.md](docs/rgpd.md) and the [compliance kit](docs/rgpd-conformite.md) (register of processing, impact assessment, privacy notice)
- **SIEM export from every gateway** — each gateway ships its own logs to your SIEM (syslog RFC 5424 over TCP/TLS, HTTP NDJSON or OpenTelemetry OTLP) with its own cursor and at-least-once delivery, even while the Admin is off; filter by type, level or WAF/Ephor-flagged lines, with a lag alert before unexported lines are purged — see [docs/fonctionnalites.md](docs/fonctionnalites.md)
- **Signed log export and legal hold** — from the gateway itself, Admin off: every line of a date range with the real IP decrypted, password-encrypted, with a manifest signed by the gateway and a hash-chained local audit trail; a legal hold freezes log files against the retention purge — see [docs/cli.md](docs/cli.md#goproxify-edge)
- Scheduled backups and restore
- Import: nginx, HAProxy, Traefik, Caddy, CSV, JSON
- **WASM plugins** (wazero) — signed packages, plugin repositories, per-route attachment; Coraza (SecLang, its denials logged and able to ban the IP) and four example plugins (`path-guard`, `rate-guard`, `body-redact`, `tcp-allow`) shipped with the Admin

### Agent (Service Discovery)

- Uses `/var/run/docker.sock`: access **equivalent to root on the host** (a read-only mount does not limit it), so run the Agent only on hosts that need it
- Detects `goproxify.*` labels on containers in real time
- Also discovers Portainer, Kubernetes `Ingress`/`Service` annotations, and **Consul, Nomad, etcd and Amazon ECS** instances (polled; an unreachable directory never removes a route)
- Sends routes, metrics and events to the Edge via **persistent WS tunnel** (Agent→Edge)
- HTTP heartbeat fallback if WS connection is unavailable
- Canary (`goproxify.canary`) and Shadow Mirror (`goproxify.shadow`) labels supported
- Prometheus export on `:9191/metrics`
- **No inbound port** required for the control plane

---

## Ports

| Port | Protocol | Component | Exposure |
|------|----------|-----------|----------|
| `80` | TCP | Edge | Public |
| `443` | TCP | Edge | Public |
| `443` | UDP | Edge | Public (HTTP/3 QUIC) |
| `8000` | TCP | Edge | **Internal only** |
| `2222` | TCP | Edge (Access) | UUID SSH portal (if Access enabled; configurable) |
| `8444` | TCP | Edge (Access) | Internal Access UI (if Access enabled; configurable) |
| `9443` | TCP | Admin | Operator |
| `9191` | TCP | Agent | Internal (Prometheus) |

> Port `8000` (Edge internal API) must **not** be exposed publicly.  
> Restrict access: `ufw allow from <admin-ip> to any port 8000`

---

## Environment variables

`GPX_*` variables are read when a component first starts, to generate its `admin.json` / `edge.json` / `agent.json`; once the file exists, **the JSON wins** (only `engine.metrics_disabled`, `engine.access_log_disabled` and `identity.node_name` can still come from the environment when absent from the JSON).  
See `.env.example` for the full list.

| Variable | Component | Description |
|----------|-----------|-------------|
| `GPX_SECURITY_JWT_SECRET` | Admin | JWT signing key (required) |
| `GPX_PAIRING_SECRET` | Admin / Edge / Agent | Shared secret for automatic pairing (HMAC WebSocket) |
| `GPX_EDGE_TOKEN` | Edge | Explicit token (alternative to shared secret) |
| `GPX_TRUSTED_PROXIES` | Edge / Admin | CSV of IPs/CIDRs of trusted front proxies (e.g. Cloudflare ranges) whose `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` are honored. Loopback and private ranges are always trusted; `*` trusts everything (legacy, spoofable). |
| `GPX_IDENTITY_EDGE_NODE_NAME` | Admin | Edge hostname/IP reachable by Admin (`http://<value>:8000`) |
| `GPX_CONTROL_PLANE_EDGE_ENDPOINT` | Agent | Edge URL as seen by Agent (`http://<edge>:8000`) |
| `GPX_ENGINE_LOG_LEVEL` | All | Log level (`debug`/`info`/`warn`/`error`) |
| `GPX_VULNSCAN_ALLOW_PRIVATE` | Admin | `true`/`1`/`yes`: allow CVE scanner on private backends (RFC1918/ULA). Default: denied (anti-SSRF). Localhost and cloud metadata remain blocked. |
| `GPX_BACKUP_KEY` | Admin | (optional) Encryption key for Admin snapshots (AES-GCM). Takes precedence over a key set in the UI (*Backups › Encryption key*: generate, rotate, reveal by the superadmin). Without any key: JSON redacted of secrets, unencrypted. With a key: snapshots also embed an encrypted `secrets` section for a full restore (keep a copy of the key off the server). |
| `GPX_NODE_TOKEN_KEY` | Admin | (optional) Encrypts node tokens at rest. Otherwise derived from JWT secret. |

---

## Tech stack

| Domain | Choice |
|--------|--------|
| Language | Go 1.25 — single static binary, zero runtime dependency |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 QUIC (quic-go), TCP/UDP L4 |
| **Control plane** | **Persistent WebSocket `nhooyr.io/websocket` — Admin→Edge(WS), Agent→Edge(WS)** |
| TLS | SSL termination + SNI Passthrough, ACME DNS-01 wildcard (33 DNS providers), HTTP-01, TLS-ALPN-01 |
| Admin persistence | CGO-free SQLite (`modernc.org/sqlite`) — config, users, tokens — Raft HA option |
| Edge persistence | Proxies: **YAML** files (`proxies/*.yaml`, `proxies-revisions/*.yaml`) · AES-256-GCM local cache (certs) |
| Configuration | `GPX_*` environment variables + optional JSON |
| Discovery | Docker Engine API via Unix socket, Portainer, Kubernetes, Consul, Nomad, etcd v3, Amazon ECS |
| Plugins | WebAssembly via `wazero` (no CGO) |
| Metrics | Prometheus on the Edge internal API (`:8000/metrics`, bearer token; public `/metrics` only with `GPX_METRICS_PUBLIC=1`), OpenTelemetry (OTLP) |
| Security | OWASP CRS-4 WAF (13 rule sets, request + response inspection), behavioral Ephor, native Fail2Ban, CrowdSec, **automation flows** (rules, schedules, playbooks with approval), step-by-step **IP / CIDR trace** over long periods, rate limiting, Geo-IP, ECDSA P-256 JWT, HMAC-SHA256 WS, CVE scanner with KEV/EPSS enrichment and configurable remediation SLA |
| Deployment | Single binary · Docker Compose · systemd |

---

## Documentation

| Document | Description |
|----------|-------------|
| [CLI](docs/cli.md) | Full reference for all commands and options |
| [Detailed architecture](docs/architecture.md) | Data flows, technical decisions |
| [Inter-Edge delegation](docs/delegation.md) | Passthrough vs Terminate modes, client IP, prerequisites |
| [Features](docs/fonctionnalites.md) | Product capability catalogue |
| [API specifications](docs/api_specs.md) | Full REST contract |
| [MCP](docs/mcp.md) | MCP server — tools, PAT auth, Claude/Cursor clients |
| [Config schema](docs/config_schema.json) | JSON schema for proxies |
| [FAQ](docs/faq.md) | First start, password reset, Docker labels, delegation |
| [Changelog](suivi/changelog.md) | Change history by version |
| [Versioning](suivi/versioning.md) | Version bump rules (SemVer) |
| [Public roadmap](suivi/roadmap-public.md) | High-level milestones |
| [Contributing](CONTRIBUTING.md) | PR, tests, DCO |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Contributor Covenant |
| [Security](docs/security.md) | WAF, Ephor, bans, timeouts, vulnscan — full security engine reference |
| [Vulnerability reporting](SECURITY.md) | Responsible disclosure |
| [License](LICENSE) | Apache License 2.0 |
| [NOTICE](NOTICE) | Copyright and third-party notices |
| [Disclaimer](DISCLAIMER.md) | Preview, no warranty or liability |

> French version: [README.fr.md](README.fr.md)
