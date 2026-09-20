# FAQ — GoProxify

Knowledge base for common incidents and frequently asked questions.

---

## Getting started & initialization

**Q: The admin interface shows an initialization screen on first launch — is that normal?**
Yes. GoProxify detects the absence of a SQLite database and forces initial admin account setup. Enter an email and a strong password, then confirm.

**Q: I lost the admin password. How do I reset it?**
Use the CLI directly on the server (direct SQLite access, bypasses the API):
```bash
goproxify admin -reset-password -email "admin@example.com" -password "newPassword123!"
```

---

## Proxies & routing

**Q: Why are some proxies greyed out and read-only in the UI?**
These proxies were automatically discovered via **Docker labels** by an Agent. They are read-only to prevent desync between the declarative configuration (Compose) and the Admin. To modify them, update the labels in your Docker Compose file.

**Q: How do I configure a proxy via Docker Compose?**
Add labels to your service. Use the "Label Generator" tab in the UI for guidance. Minimal example:
```yaml
services:
  myapp:
    image: myapp:latest
    labels:
      goproxify.enable: "true"
      goproxify.host: "myapp.example.com"
      goproxify.port: "8080"
      goproxify.tls: "true"
      # Optional — security (Admin snippets / auth, or inline)
      # goproxify.snippets: "headers-secure,rate-api"
      # goproxify.auth_provider: "authentik-prod"
      # goproxify.waf: "block"
    # No ports: - "8080:8080" — Core connects via internal network
    networks:
      - my_app_network

networks:
  my_app_network:
```

**Q: My application is not accessible after deployment. What should I check?**
1. Is the Agent started and connected to the Core (`GET /api/v1/agents`)? Expected status: `online`.
2. If the Agent is in `pending` status: have you approved it in the UI?
3. Has the Core container been connected to the app's Docker network (check `docker network inspect`)?
4. Has the TLS certificate been issued (`GET /api/v1/certs`)?
5. Do the Agent logs (`/etc/goproxify/logs/agent.log`) show any errors?

---

## TLS & certificates

**Q: Does GoProxify support wildcard certificates?**
Yes, via ACME DNS-01 (Let's Encrypt). A `*.example.com` certificate covers all subdomains without individual configuration. Configure your DNS provider in the snippets (`dns_providers`).

**Q: Are certificates reloaded without interruption?**
Yes. The Admin pushes decoded certificates directly into the Core's RAM via Go's native TLS `GetCertificate` function. No reload is required.

**Q: Which DNS providers are supported for ACME DNS-01?**
OVH, Cloudflare, Gandi, Route53 (AWS), Hetzner DNS.

---

## Performance & stability

**Q: Can the Core be updated without interrupting HTTP/3 QUIC or WebSocket connections?**
Yes. The routing table is stored in a `sync.Map` — updates are atomic and do not drop existing connections.

**Q: What is the "flat P99" mentioned in the documentation?**
Thanks to a buffer pool (`sync.Pool`), the Core recycles network allocations instead of submitting them to the Go garbage collector. This avoids latency spikes (GC pauses) under heavy load, keeping the 99th percentile latency stable.

---

## Security & tokens

**Q: The CVE scanner marks all backends as "Unreachable — forbidden IP address (SSRF)". What should I do?**
This is expected behavior. The scanner (Admin process) probes the `backends[].url` URLs of proxies directly, not the public domain. By default, private IPs (RFC1918/ULA: `192.168.x`, `10.x`, `172.16–31.x`), localhost, and cloud metadata endpoints are blocked (anti-SSRF).

To scan Docker / LAN backends reachable from the Admin, enable the opt-in on the Admin and restart it:

```bash
GPX_VULNSCAN_ALLOW_PRIVATE=true
```

(Helm: `admin.config.vulnscanAllowPrivate: true`.) Localhost and metadata remain blocked. Also verify that the Admin can reach those IPs on the network; otherwise the SSRF refusal will be replaced by a network error.

Do not put the proxy's public URL in `backends[].url` to bypass the block: this would break routing and the scan would not see the real backend's headers.

**Q: What should I do if a pairing token is compromised?**
Revoke it immediately via the UI (`DELETE /api/v1/tokens/:id`) or the CLI, then generate a new one for the affected node. The Core or Agent will disconnect and must be restarted with the new token.

**Q: Do tokens have a limited lifetime?**
By default, tokens generated via `goproxify token` are permanent. You can specify a TTL (`-ttl 24h`) for ephemeral tokens in CI/CD deployments.

**Q: What is the `JOIN_TOKEN` and what is it for?**
The `JOIN_TOKEN` (variable `GPX_CONTROL_PLANE_JOIN_TOKEN`) is an ephemeral token (TTL 24h) used by the Agent to initiate its first WebSocket connection to the Core. It identifies the Agent and triggers the approval workflow:

1. Agent connects with the `JOIN_TOKEN` → `pending` state
2. Operator approves in the UI or via `POST /api/v1/agents/:id/approve`
3. Core sends an `agent_hmac` (HMAC-SHA256 secret) via WS → `approved` state
4. Subsequent WS connections use the `agent_hmac` (rotated every hour)

**Q: Why does the Agent no longer need an inbound port for the control plane?**
The new WS architecture inverts the connection model: the Agent initiates the connection to the Core (persistent WS tunnel Agent→Core). The Core is the only connection hub. The Agent therefore no longer listens on an inbound port to receive commands — they are pushed via the WS tunnel established by the Agent.

Port `:8001` (former Agent internal API) is kept temporarily for backward compatibility but will be removed after the full migration.

**Q: How do I re-pair an Agent after rotation or expiry of the `agent_hmac`?**
If the `agent_hmac` is lost (Agent restart without persistence), generate a new `JOIN_TOKEN` in the UI (Admin → Tokens → Create → role `agent`), and configure it in `GPX_CONTROL_PLANE_JOIN_TOKEN` before restarting the Agent. The Admin will receive an `agent_pending` notification again and approval will be required.

**Q: How does automatic `agent_hmac` rotation work?**
Every hour, the Core generates a new HMAC-SHA256 secret and sends it to the Agent via the `rotate_hmac` WS message. The Agent immediately adopts the new secret for future connections. If the connection is lost during rotation, the Agent reconnects with the old HMAC (still valid until the next established connection) — the Core updates it upon reconnection.

---

## Domains & multi-Core delegation

**Q: What is the difference between Passthrough and Terminate?**
- **Passthrough**: the entry Core forwards the TLS stream without decrypting it. The target Core sees the entry Core's IP in its logs.
- **Terminate**: the entry Core terminates TLS, then proxies HTTP(S) to the target Core with `X-Forwarded-For` / `X-Real-IP`. The target Core can log the client's public IP.

Details, prerequisites and diagrams: [delegation.md](delegation.md).

**Q: In delegation mode, the target Core only logs the entry Core's IP — is that normal?**
Yes in **Passthrough** mode (TCP tunnel). Switch to **Terminate** if you need the client IP on the target Core (and the entry Core already sees public IPs).

**Q: Terminate returns 502 / "no certificate" on the target Core?**
The entry Core must reconnect in HTTPS with the **SNI = domain** (not the endpoint IP). This is expected behavior since the SNI vhost fix; redeploy the entry Core and re-push the delegations. Also verify that the entry Core has the domain's certificate (token scopes).

**Q: Entry Core vs domain rights?**
The entry Core defines **who receives traffic** (routing / delegation / ACME). **Rights** (who receives routes and certificates) are managed via the Core token's **domain scopes** — the two are independent.

---

## Agent & Docker

**Q: Does the application need to expose its ports on the host?**
No — that's precisely the point of the Agent model. The Agent hot-connects the Core container to the application's private bridge network. No port is published on the physical host (`-p` or `ports:` in Compose).

**Q: Does the Agent work with Podman?**
Podman exposes a Docker-compatible API on a Unix socket. Point `AGENT_DOCKER_SOCKET` to the Podman socket (e.g. `/run/user/1000/podman/podman.sock`). Support is experimental.
