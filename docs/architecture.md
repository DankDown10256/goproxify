# GoProxify Architecture

## Overview

GoProxify deploys as a **single Go binary**. The instance personality is determined at startup by `GOPROXIFY_MODE` (or the CLI subcommand).

```
  ┌──────────────────────────────────────────────────────────┐
  │  ADMIN  (Control Plane)                                  │
  │  Web UI · REST API · :9443                               │
  │  SQLite · ACME · Alerting                                │
  └────────────────────────┬─────────────────────────────────┘
                           │  persistent WS (Admin initiates)
                           │  HMAC-SHA256
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  CORE  (Data Plane — central WS hub)                     │
  │  HTTP/1·2·3 QUIC · TCP/UDP L4                            │
  │  TLS in RAM · AES-256 local cache                        │
  │  :80 :443 :443/UDP  :8000 (internal WS hub)              │
  └────────────────────────▲─────────────────────────────────┘
                           │  persistent WS (Agent initiates)
                           │  JOIN_TOKEN → rotating HMAC
  ┌──────────────────────────────────────────────────────────┐
  │  AGENT  (Docker Discovery)                               │
  │  Reads docker.sock · goproxify.* labels                  │
  │  Streams CPU/mem/disk IO metrics via WS (adaptive LB)    │
  │  Prometheus :9191/metrics                                │
  └──────────────────────────────────────────────────────────┘
```

The Core is the **single connection hub** — only it needs an accessible port. Admin and Agent initiate the WS connection from their side; the Core makes no outbound calls to them.

---

## Components

### Core (Data Plane)

**Responsibility:** High-performance network engine. Persists nothing to disk.

**Key points:**
- `sync.Map` routing table — atomic updates with no connection drops
- TLS certificates pushed into RAM via `GetCertificate` (no reload)
- `sync.Pool` for network buffers — stable P99 under load
- Passive SNI detection (decodes 5 bytes of the Client Hello, not the payload)

**Ports:** `:80` (HTTP), `:443` (HTTPS + HTTP/3 UDP)

### Admin (Control Plane)

**Responsibility:** Central orchestrator. Admin persistence (config, users, tokens) in SQLite; proxies as **YAML files** on the Core (`proxies/*.yaml`).

**Key points:**
- Detects absence of SQLite on first launch → mandatory initialization screen
- Two config sources: Manual (UI/API) and Declarative (Docker labels via Agent)
- Proxies from labels appear **read-only** (greyed out) in the UI
- Acquires wildcard certificates via ACME DNS-01 and pushes them decoded to the Core
- Generates cryptographic pairing tokens (`gpx_core_*`, `gpx_join_*`)
- Maintains an **outbound WS connection** to each Core — no inbound port required on the Admin side

**Port:** `:9443`

**Architecture wizard:** the UI composes a topology (hosts + services), derives install packages and emits bootstrap tickets (`/i/{token}`) anchored to the Core. Admin stays the interface; Core is the integration target.

### Agent (Discovery & Telemetry)

**Responsibility:** Local Docker translator. Ultra-lightweight, no persistent state.

**Key points:**
- Watches `/var/run/docker.sock` — apps expose **no port** on the host
- Hot-connects the Core container to the application's private bridge network
- Reads `/proc/stat` and `/proc/meminfo` (heartbeat) and per-container Docker stats (CPU / memory / disk IO) for adaptive LB
- Streams metrics via WS (`metrics`, every 10s) to the Core
- Canary / Shadow labels: manual proxy configuration (auto-detection via labels planned)
- Prometheus export on `:9191/metrics`
- **No inbound port required** — the Agent initiates the WS connection to the Core

**Portainer multi-host:**

The Agent can watch a remote Portainer API to discover containers across multiple hosts without deploying an Agent on each. Advanced options in `agent.json` → `portainer` section:

| Field | Type | Description |
|-------|------|-------------|
| `skip_endpoints` | `[]string` | Portainer endpoint names to skip during discovery |
| `endpoint_cores` | `map[string]{ core_endpoint, auth_token }` | Route an endpoint's routes to an alternate GoProxify Core |

Example:
```json
{
  "portainer": {
    "url": "https://portainer:9443",
    "api_key": "ptr_xxx",
    "skip_endpoints": ["local"],
    "endpoint_cores": {
      "edge-dc2": {
        "core_endpoint": "http://core-dc2:8000",
        "auth_token": "gpx_agent_..."
      }
    }
  }
}
```

Routes discovered on `edge-dc2` are relayed to `core-dc2` (Core→Core relay via internal endpoint `:8000`) rather than to the Agent's default Core.

---

## Adaptive load balancing

`lb: adaptive` mode (UI: "Adaptive") picks the **least loaded** backend on each request, based on Agent metrics — not fixed weights.

### Score

For each container IP (and fallback to the Agent host IP):

```
score = cpu×0.5 + mem×0.3 + disk_io×0.2   # 0–100, lowest wins
```

- **Agent**: `GET /containers/{id}/stats?stream=false` for `goproxify.enable=true` containers, then WS `metrics` message.
- **Core**: `AgentMetricsStore` fed by WS (no more Admin HTTP polling for LB).

### Local pool (same Core)

Multiple containers with the **same** `goproxify.host`, discovered by one or more Agents attached to **this** Core, are merged into a `docker-host:<hostname>` multi-backend route (`LBAdaptive` by default).

```
Agent(s) ──containers──▶ Core
                              └── route docker-host:app.example.com
                                    backends: [IP_A:port, IP_B:port]
                                    lb: adaptive
```

The Core reaches Docker IPs via the bridge network (ports **not** published on the host).

### Immediate failover

If dial / proxy to a backend fails:

1. short quarantine (~15s) of that backend;
2. try the **next** backend in the pool (adaptive preference, then others);
3. 502 only if **all** backends in the pool have failed.

Without ≥ 2 backends, no failover is possible.

### Cross-Core (Agent A / Core A + Agent B / Core B)

Goal: the **same site** reachable via a container behind each stack, without a production VXLAN mesh.

```
                    ┌─ dial local ──────────────▶ container A (Docker IP)
 Client ──▶ Core A ─┤
                    └─ OwnerCoreEndpoint=B ──tunnel──▶ Core B ──▶ container B
```

1. **Admin** pushes `push_gateway_peers`: list `{name, endpoint, token}` for each Core.
2. Each Core **syncs** (~15s) `GET /internal/v1/agent/containers` and `GET /internal/v1/lb/scores` from its peers.
3. If the same host exists locally **and** at a peer → remote backends annotated `owner_core_endpoint`.
4. Remote dial: `POST /internal/v1/gateway/tunnel` `{target:"IP:port"}` (Bearer of the owner Core) → TCP pipe. Only IPs **locally owned** by the owner are allowed.

Prerequisites: internal `:8000` endpoints reachable between Cores; Core tokens registered in Admin.

This mechanism is **distinct** from [domain delegation](delegation.md) (DNS entry → one target Core for an entire domain).

---

## Network flow: label-based deployment

```
1. App starts with labels    →  2. Agent detects (Unix socket)
   (ports not published)
                                           ↓
5. HTTPS request routed      ←  4. Core receives config + cert (RAM)
   (private Docker network)           ↑
                                  3. Admin validates, ACME DNS-01, push
```

Docker Compose label example:
```yaml
labels:
  goproxify.enable: "true"
  goproxify.host: "myapp.example.com"
  goproxify.port: "8080"
  goproxify.tls: "true"
  goproxify.snippets: "headers-secure"   # Admin snippet IDs
  goproxify.waf: "block"
```

---

## Ports and networks

| Port | Protocol | Component | Exposure | Usage |
|---|---|---|---|---|
| 80 | TCP | Core | Public | HTTP (redirect or plaintext) |
| 443 | TCP | Core | Public | HTTPS (TLS termination) |
| 443 | UDP | Core | Public | HTTP/3 QUIC |
| 8000 | TCP | Core | Internal only | WS hub + internal API — receives WS connections from Admin and Agent |
| 9443 | TCP | Admin | Operator | REST API + Web UI |
| 9191 | TCP | Agent | Internal only | Prometheus metrics |
| 51820 | UDP | Agent | Internal only | WireGuard (optional) |

> **Golden rule:** only port 8000 of the Core needs to be reachable from Admin and Agent networks. Admin and Agent require no inbound port for the control plane.

---

## Inter-Core delegation

Multiple Cores can share domains. The **entry Core** receives public traffic; the **target Core** hosts the application proxies.

Two modes (Domains page in Admin):

| Mode | Flow | Client certificate | Client IP on target Core |
|---|---|---|---|
| **Passthrough** | TCP TLS tunnel (SNI) | Target Core | Entry Core's IP |
| **Terminate** | TLS at entry → HTTPS proxy to target | Entry Core | Client IP via `X-Forwarded-For` |

Full guide: [delegation.md](delegation.md).

---

## `/etc/goproxify/` directory layout

Admin and Core each have a Docker volume mounted at `/etc/goproxify/` (separate containers). Proxy JSON files are **not** on the Admin.

```
# Admin volume (goproxify_admin_data)
/etc/goproxify/
├── database/
│   └── goproxify.db
├── storage/                      # error pages, Admin assets
└── logs/
    └── admin.log

# Core volume (goproxify_core_data) — only place to look for proxy files
/etc/goproxify/
├── proxies/                      # prod (1 flat JSON / proxy) — created at Core boot
│   └── app.example.com.json
├── proxies-revisions/            # pending → dry-run → promote
│   └── <proxy-id>--<rev>.json
├── core-cache.gpx
├── core-tokens.db
├── geoip/
├── certs/
└── logs/
    ├── core_system.log
    └── core_access.log
```

---

## Log formats

### System log (`admin.log`, `agent.log`, `core_system.log`)

```json
{
  "time": "2026-07-15T23:54:12.456Z",
  "level": "INFO",
  "component": "administration",
  "msg": "New wildcard Let's Encrypt certificate generated",
  "domain": "*.example.com",
  "provider": "ovh"
}
```

### HTTP access log (`core_access.log`)

```json
{
  "time": "2026-07-15T23:55:01.123Z",
  "component": "core-router",
  "client_ip": "193.56.21.10",
  "host": "app.example.com",
  "method": "GET",
  "path": "/api/v1/status",
  "status": 200,
  "duration_ms": 14.2,
  "bytes_sent": 1024,
  "user_agent": "Mozilla/5.0...",
  "upstream_backend": "http://172.18.0.5:8880",
  "http_version": "HTTP/3"
}
```

---

## WebSocket control plane

### Message protocol

All WS messages use a JSON envelope:
```json
{ "seq": 42, "type": "push_routes", "payload": { ... } }
```

The `seq` field is an incrementing counter per sender. A gap in the sequence triggers an automatic `full_sync`.

### Admin → Core flow

1. Admin opens `GET ws://core:8000/ws/admin` with header `X-Goproxify-Signature: hmac-sha256 <timestamp>.<sig>`
2. Core validates the HMAC-SHA256 and accepts the connection
3. Core immediately replies with a `full_sync` to align state
4. Admin sends messages as configuration changes occur: `push_routes`, `push_cert`, `delete_route`…
5. If the connection is lost: Admin reconnects with exponential backoff 1s → 60s + jitter

### Agent → Core flow

1. First start: Agent presents its `JOIN_TOKEN` (generated by Admin UI, TTL 24h) in the WS upgrade header
2. Core creates the Agent entry in `pending` state and notifies Admin via the Admin WS connection
3. Operator approves in the UI → Core sends an `approve` message with the first `agent_hmac`
4. Agent stores the `agent_hmac` and uses it for all future reconnections
5. Core emits a `rotate_hmac` message every hour; the Agent adopts the new secret without interruption
6. Agent streams continuously: `heartbeat` (30s), `containers` (on change), `metrics` (10s), `event`, `log`
7. Core → Agent: `command` (restart, update), `rescan`

### Resilience

- Application-level ping/pong every 30s; 3 unanswered pings → reconnect
- Admin disconnect → Core preserves cache; zero traffic interruption
- Agent disconnect → backends marked `unhealthy` after 90s of absence

---

## Token security

```
Admin  ─HMAC-SHA256──►  Core (ws/admin)
                              │
                              │  message: approve
                              ▼
        Agent (JOIN_TOKEN) ──►  Core (ws/agent)  ──► rotating agent_hmac (1h)
```

| Token | Format | Usage | Lifetime |
|-------|--------|-------|----------|
| `gpx_join_*` | Random opaque | Agent first connection → Core | 24h (single use) |
| `agent_hmac` | HMAC-SHA256 secret | Agent reconnections → Core | Rotated every 1h |
| `admin_hmac_secret` | Symmetric key | Admin → Core handshake | Static, configurable |
| JWT ECDSA P-256 | Signed JWT | Admin UI sessions | 8h |
| `gpx_api_*` | Revocable opaque | External API access | Permanent or configured TTL |
