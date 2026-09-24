# GoProxify

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-preview%20%2F%200.x-orange.svg)](DISCLAIMER.md)
[![Go](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](go.mod)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fvincamok%2Fgoproxify-black)](https://github.com/Vincamok/goproxify/pkgs/container/goproxify%2Fadmin)
[![Release](https://img.shields.io/github/v/release/Vincamok/goproxify?display_name=tag&sort=semver)](https://github.com/Vincamok/goproxify/releases)

**GoProxify is a distributed reverse proxy compiled as a single Go binary** — built to manage multiple servers from a central interface, without heavy agents or configuration scattered across every machine.

You have several VPS, Docker containers on different hosts, and you want to route traffic, manage TLS certificates and keep control of everything from one place? That's exactly what GoProxify is for.

### What makes it different

- **One binary, three roles** — the same executable starts as Core (proxy), Admin (management UI) or Agent (Docker discovery)
- **The Core is autonomous** — it starts and routes traffic even when the Admin is unreachable; routes and certificates are held locally, in RAM
- **HTTP/1.1, HTTP/2, HTTP/3 QUIC, TCP/UDP L4** — one tool covers all protocols
- **Built-in OWASP CRS-4 WAF** — 13 rule sets (SQLi, XSS, Log4Shell…) with no external plugin
- **SSH and Docker access from the UI** — web terminal, UUID `ssh` to VMs and `docker exec` to containers, directly from your browser
- **Automatic Docker discovery** — the Agent reads `goproxify.*` labels on your containers and pushes routes in real time
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
                        │  Proxies: Core YAML files        │
                        │  rebuildable from Cores          │
                        └──────────┬───────────────────────┘
                                   │ persistent WS Admin→Core
                                   │ (push routes/certs/config)
                                   ▼
┌──────────────┐    ┌──────────────────────────────────────┐
│   INTERNET   │───►│  CORE  (Data Plane · central WS hub) │
│  :80 / :443  │    │  HTTP/1·2·3 QUIC · TCP/UDP L4        │
│  HTTP/1·2·3  │    │  TLS in RAM · AES-256 local cache    │
└──────────────┘    │  Zero reload · autonomous w/o Admin  │
                    │  :80 :443 :443/UDP :8000+WS (internal)│
                    └────────────▲─────────────────────────┘
                                 │ persistent WS Agent→Core
                                 │ (heartbeat/metrics/events)
                    ┌────────────┴─────────────────────────┐
                    │  AGENT  (Docker Discovery)           │
                    │  Reads docker.sock (read-only)       │
                    │  Detects goproxify.* labels          │
                    │  Prometheus :9191/metrics            │
                    │  No inbound control-plane port       │
                    └──────────────────────────────────────┘
```

| Component | Role | Persistence | Exposed ports |
|-----------|------|-------------|---------------|
| **Core** | Data Plane — routing, TLS, L4 · WS control-plane hub | RAM + encrypted local cache · **YAML proxies** (`proxies/*.yaml`) | `:80`, `:443` (TCP+UDP), `:8000` (internal + WS) |
| **Admin** | Control Plane — UI, API, alerting | SQLite (config, users, tokens) | `:9443` |
| **Agent** | Docker discovery & metrics | Volatile | `:9191` (Prometheus) — **no inbound WS port** |

---

## Quick start

> Preview only — read [DISCLAIMER.md](DISCLAIMER.md) before any deployment.

### Docker Compose (recommended)

```bash
# 1. Download the all-in-one compose file
curl -LO https://github.com/vincamok/goproxify/raw/main/docker-compose.quickstart.yml
curl -LO https://github.com/vincamok/goproxify/raw/main/.env.example

# 2. Generate required secrets
cp .env.example .env
# Edit .env — minimum required:
#   GPX_JWT_SECRET=$(openssl rand -hex 32)
#   GPX_PAIRING_SECRET=$(openssl rand -hex 32)
#   GPX_FIRST_ADMIN_EMAIL=admin@example.com
#   GPX_FIRST_ADMIN_PASSWORD=change-me

# 3. Start — Admin + Core + Agent (pulls GHCR images)
docker compose -f docker-compose.quickstart.yml up -d
```

Images are published on **GHCR** (`ghcr.io/vincamok/goproxify`). Default quickstart:
floating tag **`preview`**. To pin a SemVer: `GOPROXIFY_ADMIN_TAG`,
`GOPROXIFY_CORE_TAG`, `GOPROXIFY_AGENT_TAG` (see `versions.json` / `.env.example`).

The admin interface is available at **http://localhost:9443**.

The Core and Agent pair automatically with the Admin via `GPX_PAIRING_SECRET` — no manual token copy needed.

### Portainer

1. **Stacks → Add stack → Repository**
2. URL: `https://github.com/vincamok/goproxify`
3. Compose path: `docker-compose.quickstart.yml`
4. Environment variables: `GPX_JWT_SECRET`, `GPX_PAIRING_SECRET`, `GPX_FIRST_ADMIN_EMAIL`, `GPX_FIRST_ADMIN_PASSWORD` (generate secrets with `openssl rand -hex 32`)
5. **Deploy the stack**

### Binary

```bash
# Build
git clone https://github.com/vincamok/goproxify && cd goproxify
go build -o goproxify ./cmd/goproxify

# Start Admin
GPX_SECURITY_JWT_SECRET=<secret> ./goproxify admin

# Start a Core (token generated from Admin UI)
GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://localhost:9443 \
GPX_CORE_TOKEN=gpx_... \
./goproxify core

# Start Agent (optional)
GPX_CONTROL_PLANE_CORE_ENDPOINT=http://localhost:8000 \
./goproxify agent
```

---

## Pairing Core / Agent

### Core → Admin

Two methods to connect a Core to an Admin:

| Method | Use case | Variable |
|--------|----------|----------|
| **Shared secret** | All-in-one stack (same machine / same compose) | `GPX_PAIRING_SECRET` |
| **Explicit token** | Remote Core, multi-site | `GPX_CORE_TOKEN` |

The shared secret is the recommended method for standard deployments. The explicit token is generated from Admin UI → Settings → Tokens.

### Agent → Core (WS)

The Agent↔Core control plane uses a persistent WebSocket tunnel. The Agent connects to the Core — not the other way around.

| Step | Description | Variable |
|------|-------------|----------|
| 1. **JOIN_TOKEN** | First start — Agent connects and enters `pending` state | `GPX_CONTROL_PLANE_JOIN_TOKEN` |
| 2. **Approval** | Operator approves the Agent in Admin UI | — |
| 3. **agent_hmac** | Core sends an HMAC secret via WS → Agent is `approved` | auto-negotiated |
| 4. **Rotation** | Core regenerates `agent_hmac` every hour | automatic |

To generate a `JOIN_TOKEN`: Admin UI → Tokens → Create → role `agent`, TTL `24h`.

---

## CLI

```
goproxify <command> [options]

Service commands:
  admin    Start Administration (Control Plane + Web UI)
  core     Start Core (Data Plane — Reverse Proxy)
  agent    Start Agent (Docker Discovery)
  landing  Start landing page (optional)

Operational commands (talk to Admin via HTTP):
  token      Core/Agent pairing tokens
  backup     Backup and restore
  import     Import from nginx / Traefik / Caddy / HAProxy
  alert      Test alert channels
  status     Cluster status
  access     GoProxify Access (config, catalogue, users, templates, audit)
  nodes      Infrastructure nodes (list / accept / reject)
  declared   Architecture wizard declared nodes
  bootstrap  QR tickets / curl|bash host integration
  update     Update Docker images (via Agent)

  version  Binary version
  help     Help
```

Common auth for operational commands: `-admin-url` / `-token` or env vars `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`.

Full reference → **[docs/cli.md](docs/cli.md)**

---

## Features

### Core (Data Plane)

- **HTTP/1.1, HTTP/2, HTTP/3 QUIC** routing (UDP)
- **TCP and UDP (L4)** streaming
- TLS termination + SSL Passthrough via passive SNI detection
- Routes and certificates stored **in RAM** (`sync.Map`, `GetCertificate`) — no private key on disk
- **AES-256-GCM encrypted local cache** — starts and routes without Admin available
- Hot configuration reload, zero connection interruption
- Load balancing (Round Robin, Weighted, adaptive CPU/mem/IO + failover + inter-Core gateway), Circuit Breaker, Retry
- Rate limiting, IP/CIDR filtering, Geo-IP, **OWASP CRS-4 WAF** (13 rule sets: SQLi, XSS, LFI, RCE, PHP, SSRF, Scanner, Java/Log4Shell, RFI, NodeJS, HTTP Smuggling, Sensitive Files, Response Leaks), HTTP security headers
- **Automatic rules engine** — conditions (critical CVE, ban spike, silent engine, error rate, repeat offender IP, node offline, cert expiring) → actions (disable proxy, ban IP, alert, strict Fail2Ban mode, webhook call, trigger backup)
- Basic, Forward Auth, JWT authentication per route
- Async JSON access log, Prometheus metrics, OpenTelemetry tracing
- **GoProxify Access** — operator portal on the Core: web terminal + UUID `ssh` to VMs/`sshd` and Docker containers (`docker exec` via Agent); SSH login vault + secrets; 2FA; TTL sessions

### Admin (Control Plane)

- **Web UI + REST API** — CRUD proxies, snippets, tokens, users
- **GoProxify Access** — destination catalogue (global / per-Core view), invite users by email (SMTP), tags, Access HTML templates, portal options per Core
- **User API tokens (PAT)** — `gpx_pat_*` self-service with scopes (`proxies:read`, …) for scripts and MCP clients; distinct from Core/Agent pairing tokens
- **MCP server** — JSON-RPC 2.0 + SSE; **PAT-only** authentication (no session JWT)
- **Architecture wizard** — host canvas + palette, multi-Core/HA, QR tickets / `curl|bash` to integrate a host
- **Guided first start** — initial configuration wizard
- ACME DNS-01 wildcard management (OVH, Cloudflare, Gandi, Route53, Hetzner)
- Certificate push to Core (RAM only, never persisted on Core side)
- **Certificate Hub** — ACME monitoring (dashboard + expiry alerts), external PEM cert import, deploy targets (HMAC webhook / ssh_exec), multi-format pull tokens (PEM/DER/PKCS#12/JSON)
- **Granular alerting** — rules per node/domain/team, 10 channels: Email, Webhook, ntfy.sh, Gotify, Jira, Linear, GitHub Issues, GitLab Issues, Zammad, GLPI
- Structured audit log for all components
- Scheduled backups and restore
- Import: nginx, HAProxy, Traefik, Caddy, CSV, JSON

### Agent (Docker Discovery)

- Reads `/var/run/docker.sock` **read-only**
- Detects `goproxify.*` labels on containers in real time
- Sends routes, metrics and events to the Core via **persistent WS tunnel** (Agent→Core)
- HTTP heartbeat fallback if WS connection is unavailable
- Canary (`goproxify.canary`) and Shadow Mirror (`goproxify.shadow`) labels supported
- Prometheus export on `:9191/metrics`
- **No inbound port** required for the control plane

---

## Ports

| Port | Protocol | Component | Exposure |
|------|----------|-----------|----------|
| `80` | TCP | Core | Public |
| `443` | TCP | Core | Public |
| `443` | UDP | Core | Public (HTTP/3 QUIC) |
| `8000` | TCP | Core | **Internal only** |
| `2222` | TCP | Core (Access) | UUID SSH portal (if Access enabled; configurable) |
| `8444` | TCP | Core (Access) | Internal Access UI (if Access enabled; configurable) |
| `9443` | TCP | Admin | Operator |
| `9191` | TCP | Agent | Internal (Prometheus) |

> Port `8000` (Core internal API) must **not** be exposed publicly.  
> Restrict access: `ufw allow from <admin-ip> to any port 8000`

---

## Environment variables

`GPX_*` variables take priority over JSON config files.  
See `.env.example` for the full list.

| Variable | Component | Description |
|----------|-----------|-------------|
| `GPX_SECURITY_JWT_SECRET` | Admin | JWT signing key (required) |
| `GPX_SECURITY_CLUSTER_SYNC_KEY` | Admin | Cluster sync key |
| `GPX_PAIRING_SECRET` | Admin / Core / Agent | Shared secret for automatic pairing (HMAC WebSocket) |
| `GPX_CORE_TOKEN` | Core | Explicit token (alternative to shared secret) |
| `GPX_TRUSTED_PROXIES` | Core / Admin | CSV of IPs/CIDRs of trusted front proxies (e.g. Cloudflare ranges) whose `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` are honored. Loopback and private ranges are always trusted; `*` trusts everything (legacy, spoofable). |
| `GPX_IDENTITY_CORE_NODE_NAME` | Admin | Core hostname/IP reachable by Admin (`http://<value>:8000`) |
| `GPX_CONTROL_PLANE_CORE_ENDPOINT` | Agent | Core URL as seen by Agent (`http://<core>:8000`) |
| `GPX_ENGINE_LOG_LEVEL` | All | Log level (`debug`/`info`/`warn`/`error`) |
| `GPX_VULNSCAN_ALLOW_PRIVATE` | Admin | `true`/`1`/`yes`: allow CVE scanner on private backends (RFC1918/ULA). Default: denied (anti-SSRF). Localhost and cloud metadata remain blocked. |
| `GPX_BACKUP_KEY` | Admin | (optional) Encrypts Admin snapshots (AES-GCM). Without key: JSON redacted of secrets, unencrypted. |
| `GPX_NODE_TOKEN_KEY` | Admin | (optional) Encrypts node tokens at rest. Otherwise derived from JWT secret. |

---

## Tech stack

| Domain | Choice |
|--------|--------|
| Language | Go 1.25 — single static binary, zero runtime dependency |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 QUIC (quic-go), TCP/UDP L4 |
| **Control plane** | **Persistent WebSocket `nhooyr.io/websocket` — Admin→Core(WS), Agent→Core(WS)** |
| TLS | SSL termination + SNI Passthrough, ACME DNS-01 wildcard |
| Admin persistence | CGO-free SQLite (`modernc.org/sqlite`) — config, users, tokens — Raft HA option |
| Core persistence | Proxies: **YAML** files (`proxies/*.yaml`, `proxies-revisions/*.yaml`) · AES-256-GCM local cache (certs) |
| Configuration | `GPX_*` environment variables + optional JSON |
| Discovery | Docker Engine API via Unix socket (read-only) |
| Metrics | Prometheus `/metrics`, OpenTelemetry (OTLP) |
| Security | OWASP CRS-4 WAF (13 rule sets, request + response inspection), behavioral Sentinel, native Fail2Ban, CrowdSec, **automatic rules engine**, rate limiting, Geo-IP, ECDSA P-256 JWT, HMAC-SHA256 WS |
| Deployment | Single binary · Docker Compose · systemd |

---

## Documentation

| Document | Description |
|----------|-------------|
| [CLI](docs/cli.md) | Full reference for all commands and options |
| [Detailed architecture](docs/architecture.md) | Data flows, technical decisions |
| [Inter-Core delegation](docs/delegation.md) | Passthrough vs Terminate modes, client IP, prerequisites |
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
| [Security](docs/security.md) | WAF, Sentinel, bans, timeouts, vulnscan — full security engine reference |
| [Vulnerability reporting](SECURITY.md) | Responsible disclosure |
| [License](LICENSE) | Apache License 2.0 |
| [NOTICE](NOTICE) | Copyright and third-party notices |
| [Disclaimer](DISCLAIMER.md) | Preview, no warranty or liability |

> French version: [README.fr.md](README.fr.md)
