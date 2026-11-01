# GoProxify Features

## 1. Overview

GoProxify is a **distributed, secure reverse proxy** compiled as a **single Go binary** with zero runtime dependency. The instance personality is determined at startup by the CLI subcommand or the `GOPROXIFY_MODE` environment variable.

The product comes in **three complementary personalities**:

| Component | Role | Persistence | Exposed ports |
|---|---|---|---|
| **Edge** | Data Plane — high-performance routing engine + WS hub (+ optional Access) | RAM + encrypted cache | `:80`, `:443` TCP+UDP, `:8000` internal + WS; Access `:2222` / `:8444` if enabled |
| **Admin** | Control Plane — UI, API, MCP, alerting, Access | SQLite | `:9443` |
| **Agent** | Discovery & Telemetry — Docker sidecar | Volatile | `:9191` Prometheus, `:51820` WireGuard (no inbound port for control plane) |

---

## 2. Edge — Data Plane

### Supported protocols

| Protocol | Details |
|---|---|
| HTTP/1.1 | Full reverse proxy with header management |
| HTTP/2 | Stream multiplexing, ALPN negotiation |
| HTTP/3 QUIC | UDP transport, `Alt-Svc` negotiation |
| WebSocket | HTTP → WS upgrade handled natively; when the route defines `cors.allowed_origins`, an upgrade whose `Origin` is not listed (or is `null`) gets `403` (anti cross-site WebSocket hijacking); requests without `Origin` pass |
| gRPC | Transparent proxy over HTTP/2 |
| TCP L4 | Pure stream: local port → remote host:port, native SSL passthrough, L4 load balancing |
| TCP L4 idle timeout | `idle_timeout_sec` on a `tcp` route closes connections silent in both directions for that long (0 = never, the default; max 86400); one timer for both directions, re-armed on every byte |
| TCP/UDP L4 backends | Connections and UDP sessions are spread over all backends (round-robin, or weighted with `lb: weighted`); a failing backend is set aside for 10 s and the connection retried on the next one; `health_check` adds active TCP connect probes; UDP uses ICMP "port unreachable" where the platform reports it |
| UDP L4 | Tunnel with one session per client (stable source toward the backend, any number of replies, idle expiry, session cap), bytes in/out metrics |

### TLS

- **TLS termination**: certificates pushed into RAM only via `GetCertificate` — never written to disk
- **SNI Passthrough**: passive detection by reading the first 5 bytes of the Client Hello (no decryption)
- **ALPN negotiation**: `h2` and `http/1.1`
- **mTLS client**: client certificate validation (Milestone 5)
- **Inter-Edge delegation**: an entry Edge can forward a domain to another Edge — **Passthrough** (raw TLS tunnel) or **Terminate** (TLS at entry + HTTP(S) proxy + `X-Forwarded-For`) modes. See [docs/delegation.md](delegation.md).

### Path locations — case sensitivity

`locations` (`path_type` `prefix` | `exact` | `regex`) are matched on the decoded, normalised path (`//`, `/./`, `..`, `;a=b`, `%2f`, `%00`, `%5c` are rejected upstream). Matching is **case-insensitive by default for any prefix/exact location carrying `auth`, `ip_filter` or `rate_limit`**, and case-sensitive otherwise. Per-location option `case_insensitive` (`true`/`false`) overrides the default. `regex` locations are never folded (use `(?i)` explicitly). `strip_prefix` follows the same rule. Why: a case-insensitive backend (IIS, ASP.NET) serves `/API/ADMIN` as `/api/admin`, so a case-sensitive protected location would be bypassed. Forcing `case_insensitive: false` on a protected location re-opens that bypass against such backends.

### Autonomous operation without Admin

The Edge can operate **autonomously** if the Admin is temporarily unreachable:

- Automatic backup of the routing table and certificates in an **encrypted local cache** (`/etc/goproxify/edge-cache.gpx`)
- Triggered on each push received from Admin + configurable interval
- On startup without reachable Admin: automatic load from cache
- **Automatic reconnect** as soon as Admin becomes available again → cache update
- Explicit log indicating startup mode (live / local cache)

### Performance

- `sync.Map` for routing table: atomic updates **with no connection interruption**
- Network buffer `sync.Pool`: stable P99 under load, reduced GC pressure
- Response compression negotiated per proxy (`compression`): **zstd**, **Brotli** and **gzip**, chosen from `Accept-Encoding`; configurable algorithms, minimum size, level and MIME types; skips already-encoded, SSE and WebSocket responses
- **TLS fingerprinting JA3 / JA4 wired to Ephor** (Edge `0.36.0`): the gateway reads each client's raw TLS ClientHello (GREASE ignored) and computes its **JA3** (MD5) and **JA4** fingerprints, whatever the HTTP client claims in its User-Agent. Ephor `custom_lists.tls_fingerprints` lists signatures to ban (signal `tls_fp`, critical score, normal ban flow: duration, escalation, HA propagation, `detect` mode logs without banning, whitelisted IPs exempt). Every access-log line carries `tls_ja3` / `tls_ja4` so a scanner's signature can be found then listed; the Ephor drawer has an "Empreintes TLS bloquées" field. TLS only — plain HTTP and HTTP/3 have no fingerprint. Local computation, works without the Admin
- **TLS fingerprints in the Admin logs** (Admin `0.115.0`, Edge `0.44.0`): the gateway ships `tls_ja3` / `tls_ja4` with each access-log line to the Admin, which stores them (indexed). Logs page: a JA4 column, JA3 and JA4 in the entry drawer, click-to-filter, `tls_ja3` / `tls_ja4` filters in the API (`GET /logs`, `/logs/facets`), CLI (`logs list -tls-ja4`) and MCP (`list_logs`). Entries from before the upgrade, plain HTTP and HTTP/3 carry no fingerprint. Prism has a "TLS fingerprints" tab (Admin `0.117.0`): top JA4 with requests, errors, requests flagged by the WAF or Ephor and distinct IPs — one signature shared by many IPs, or often flagged, points to a scanner or botnet; click opens the logs filtered on it (also `GET /prism/tls-fingerprints`, `goproxify prism tls`, MCP `get_prism_tls_fingerprints`).
- **Bot challenge settings in the proxy dialog** (Admin `0.115.0`): in Protection › Bot protection, mode "JS challenge" shows provider (proof of work, Turnstile, hCaptcha), difficulty (1–24 bits), proof lifetime, site/secret keys and exempt paths (one per line).
- **Browser challenge against bots and AI scrapers** (Edge `0.35.0`, proxy `bot` option in `challenge` mode): the previous page only set a cookie that any scraper could copy from the HTML. It is now a real **proof-of-work** (default `challenge_provider: "pow"`): the page makes the browser find a nonce so that SHA-256 of a signed, stateless challenge has `challenge_difficulty` leading zero bits (default 16 ≈ 1 s, max 24; each bit doubles the work); solving it costs the client CPU, scraping at scale becomes expensive. Optional **Cloudflare Turnstile** (`turnstile`) or **hCaptcha** (`hcaptcha`) with `challenge_site_key` and `challenge_provider_secret` (token verified server-side, refused if the provider cannot be reached). The proof is an `HttpOnly` cookie bound to the client's IP and User-Agent (a copied cookie is useless elsewhere), valid `challenge_ttl` (default 24h), and removed before the request reaches the backend. `challenge_exempt_paths` lists prefixes never challenged (APIs, webhooks); non-GET requests without proof get a plain `403`. Set `challenge_secret` to share the signing key across HA members (otherwise each gateway has its own and re-challenges after a restart). No Admin needed at runtime
- **PROXY protocol v1/v2** (Edge `0.34.0`): inbound on `:80` / `:443` (Edge config `network.proxy_protocol: { enabled, trusted_cidrs }`) so the real client IP survives a Layer-4 load balancer — only sources listed in `trusted_cidrs` are believed (no spoofing), `enabled` without `trusted_cidrs` is refused at startup, and a trusted source sending no header (LB health probe) is served with its own address. Outbound per proxy (`proxy_protocol: "v1" | "v2"`) towards HTTP backends and TLS passthrough routes; on an HTTP route each request uses its own backend connection (a PROXY header describes a single client, so no keep-alive reuse). Local config only — works without the Admin
  - **Health probes carry the PROXY header too** (Edge `0.45.0`): when a route sets `proxy_protocol`, its active health checks (HTTP and the TCP fallback) write a header with no client address (`LOCAL` in v2, `UNKNOWN` in v1), so backends that require PROXY no longer see them as invalid connections or flap down.
- Disk proxy cache (`cache`, Edge `0.33.0`): TTL per status code, `Vary`, bypass rules, **stale-while-revalidate**, **stale-if-error**, **request coalescing** and **purge by tag or URL** (`Cache-Tag` / `Surrogate-Key` response headers; API, CLI `proxy cache-purge`, MCP `purge_proxy_cache`)

### Security

| Feature | Details |
|---|---|
| IP/CIDR filtering | Gateway-wide profiles (all proxies, before routing; `allow` beats `deny`; per-proxy filtering stays in the `ip_filter` snippet): built-in feed profiles (Cloudflare, Tor, FireHOL…), templates for more feeds (Bogons, blocklist.de, CINS Army) and manually entered IP/CIDR lists (validated, deduplicated, exclusive with a feed); feeds aggregated (dedup + merged prefixes), private ranges excluded from deny lists, conditional downloads (ETag/304), exponential retry backoff with visible failure state, and a shrink guard against emptied/truncated feeds and an `ip_profile_refresh_failed` alert after N consecutive failures |
| Geo-IP | Allow or block by country (MaxMind GeoLite2; auto-download at startup) |
| Rate limiting | Token bucket per IP or authenticated user — `key_by` field: `ip` (default), `jwt_sub`, `jwt_email`, `jwt_claim:<name>` |
| Backpressure | Per-route cap on concurrent requests (`backpressure`: `max_inflight`, `queue`, `queue_timeout_ms`); extra requests wait in a bounded queue, then get `503` + `Retry-After`. WebSocket upgrades are exempt. Metrics `gpx_backpressure_*` — see [docs/security.md](security.md#backpressure-par-route) |
| Entry hardening | The TLS ClientHello is read outside the accept loop (3 s timeout, at most 2,048 pending reads and 32 per source, an IPv6 counting as its /64), so a silent connection no longer delays the others; closed connections are counted (`gpx_tls_rejected_total`). A request for a host with no route gets a neutral `404` with no body and no product name, or a dropped connection with `network.unknown_host_action: "close"`. Every refusal is counted by reason (`gpx_tls_rejected_total`: no SNI, name without certificate, not TLS, cut connection…, plus `gpx_edge_unknown_host_total`), logged at most once per reason every 5 s, and ranked in a fixed-size in-memory table (names asked with the number of distinct IPs asking, IPs, JA4) served by the gateway at `GET /internal/v1/rejections` (Edge `0.135.0`) and shown by the Admin in Prism › Direct traffic, `GET /api/v1/security/rejections`, `goproxify security rejections` and the MCP tool `get_entry_rejections` (Admin `0.228.0`). Per-host metrics are labelled with the route that serves the request (`*.example.fr` for a wildcard), never with the name the client wrote — see [docs/security.md](security.md#porte-dentrée--connexions-tls-et-hôte-inconnu) ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), Edge `0.132.0`) |
| Thresholds | Explicit rules "**N events in T, action**" on the responses a gateway served: a structured filter (status codes or classes, path prefixes, methods, route names, WAF hit/blocked), a count and a window, then a ban (Ephor's duration and escalation) or points added to the common note. Two are provided — `auth-fail` (10 × 401/403 in 5 min on a login entry point, WAF refusals excluded; the weighted 4xx score deliberately ignores 401/403) and `waf-repeat` (5 requests in 10 min that trigger a WAF rule) — plus your own, up to 50. Per-IP counters (IPv6 by /64), bounded, ten buckets per key, **kept across a restart** in Ephor's encrypted local copy. Born in `detect` (counted only; default `off`). Ephor settings drawer › Thresholds; metric `gpx_threat_threshold_total{result}` — see [docs/security.md](security.md#seuils) ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), Edge `0.138.0`, Admin `0.231.0`) |
| Unknown-host signal | An access by the gateway's IP address, or to a name it does not serve (request with no route, TLS handshake refused for no name / an IP / no certificate / not TLS), adds **moderate** points (1 by default) to the IP's common note: several in a row lead to a ban, never the first one (a third-party page can send your visitors to your IP). Needs the cumulative score. Exempt: private networks, Cloudflare, the Ephor and ban allowlists, and declared probes. An IP hitting at a regular pace (six or more accesses almost evenly spaced) is a likely probe: no longer scored, listed in Prism › Direct traffic › Likely probes for you to exempt. Born in `detect` (default `off`). Ephor settings drawer › Unknown host; metric `gpx_threat_unknown_host_total{result}` — see [docs/security.md](security.md#hôte-inconnu-signal-unknown_host) ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), Edge `0.137.0`, Admin `0.230.0`) |
| Decoy paths | Paths your application never uses (`/.git/`, `/.ssh/`, `/backup.sql`, `/dump.sql`… default set plus your own): whoever asks for one is almost surely a scanner, and the hit weighs 8 points in the IP's common note. A path the proxy's legitimate traffic uses (learned surface profile, declared location) is never a trap; an unknown host has no application behind it, so there it is. Born in `detect` (counted only; default `off`). Ephor settings drawer › Decoys; metric `gpx_threat_decoy_total{result}` — see [docs/security.md](security.md#leurres) ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), Edge `0.136.0`, Admin `0.229.0`) |
| Seasonal traffic reference | *(Edge `0.140.0`, Admin `0.233.0`)* Each gateway learns the traffic of every route per slot (day of the week × hour, UTC; fine slot with a coarse fallback): rate, distinct IPs (approximate count, no per-IP table), error share, share of the most requested path. A volume gap alone is a warning; with a gap in nature (new IPs, errors, one path) it is a probable attack. Two windows (10 s and 1 min), an absolute floor for quiet sites, a cold slot never alerts, learning is frozen during an alert, reference kept encrypted across restarts, no Admin needed. `off` by default; `detect` logs, counts, alerts (`traffic_deviation`) and shows it in **Security › Ephor › Detections › Traffic references**; `block` also hardens a route under probable attack (Edge `0.142.0`): proof-of-work challenge and an adaptive rate cap (a multiple of the slot's learned mean) for IPs with no history of their own, regulars untouched — see [docs/security.md](security.md#référence-saisonnière-du-trafic) |
| Challenge before the ban | Between "let through" and "ban": an IP whose common note has crossed `challenge.threshold` (below the ban threshold) gets the proof-of-work browser challenge instead of a refusal — humans barely notice, a bot sending thousands of requests pays dearly, and a shared IP (corporate NAT, CGNAT) is not banned wrongly. Needs the cumulative score; born in `detect` (the challenge that would have been served is counted, never served; default `off`). Only navigations (GET/HEAD asking for HTML) get the page; API clients, images, POSTs, WebSocket upgrades, ACME validations and exempt paths keep the ban path. Own cookie and URL, so a route's own challenge is untouched (and not repeated). Solving it does not clear the note. Ephor settings drawer › Challenge before the ban; metric `gpx_threat_challenge_total{result}` — see [docs/security.md](security.md#défi-avant-le-ban) ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), Edge `0.134.0`) |
| HTTP security headers | HSTS, X-Frame-Options, Content-Security-Policy, etc. |
| CORS | Configurable origins, methods and headers |
| Server fingerprint masking | Removal of revealing headers (`Server`, `X-Powered-By`) |
| WAF | Own setting in the Security step of the proxy modal (mode, advanced settings; rule exclusions are **per path** (`waf.exclusions`) so the rest of the proxy stays protected; the gateway never guesses the platform of a proxy). Native Go engine, 13 OWASP CRS-4 rule sets, request **and** response inspection, detect/block mode, custom rules hot-reload — see [docs/security.md](security.md#waf) |
| Ephor | Per-IP behavioral detection: sliding window, immediate ban on signal, global anti-DDoS RPS, optional bounded **tarpit** (holds the response to blocked IPs), optional **per-IP cumulative score with decay** (a ban only when signals add up faster than they fade), optional **weighted 4xx errors** (per status code and per path prefix) fed into that score, optional **graduated bans** (repeat offenders are banned longer, an unban resets the count) — see [docs/security.md](security.md#ephor). Runs without the Admin: the Edge keeps an encrypted copy of its Ephor config and stores Ephor bans locally, so both survive an Edge restart while the Admin is unreachable. The Ephor page has three tabs (overview, detections, lists and exceptions) and a side settings drawer, with a **dry-run simulation** on recent access logs before saving **One risk note per IP** (ADR 0011, Admin `0.194.0` / Edge `0.108.0`): a single behavioural store per gateway, fed by Ephor with every request (no per-route switch), by the WAF with its rule score, and by CrowdSec with its decisions; the ban is posed on *Ephor's cumulative score + the behaviour signals set to `block`*, merged across an HA group by maximum. Every signal is born in `detect` (computed, explained, counted as a shadow note), five new ones (`ua_tls_mismatch`, `no_assets`, `regular_interval`, `scan_breadth`, `asn_aggregate`) and `rate_deviation`, which compares an IP's rate to the **normal learned per route and hour of day** (median and median absolute deviation, cold start, capped drift, no IP stored); a long clean history raises the ban threshold; thresholds are proposed from the per-minute aggregates. **Every automatic ban says why**: the signals behind it, each with its points and the value observed (path, User-Agent, TLS fingerprint, request rate…), summing to the decision, shown on the Bans page, the Ephor page, the IP trace, the API, the CLI and MCP (`signals`). Its **scores and 4xx / rate windows survive a gateway restart**: an encrypted local copy (`threat-state.gpx`, saved every 5 minutes and on shutdown) is reloaded at startup without the Admin, and entries that aged out meanwhile are dropped. |
| Surface learning | Per-proxy `surface.type` (`api` closed surface, `site` open content, empty = api): a **site** gets no path policy and no path suggestions, converges on age and volume only, and still gets size, network, country, CORS, rate and WAF-rule proposals; the report hints which type the traffic looks like. Per-proxy `surface.mode` (`off` default, `learn`; `detect` and `enforce` come with the positive policy, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md)). In `learn` the gateway watches the proxy's **legitimate** traffic and builds a profile of what it really uses: methods, **path templates** (`/api/users/{int}`), request/response content types, body sizes, query parameter names and types, header names, clients (distinct count, countries, ASNs). **Nothing is blocked.** Only requests that look legitimate teach it (2xx/3xx/401 from an IP with no Ephor signal, WAF match or risk note); a scanner cannot register its paths. No parameter value, header value or IP is stored. A convergence check says when the profile can be trusted (7 days, 1,000 requests, 48 h without a new template). Encrypted local copy, merged between HA group members without the Admin. Report in the proxy dialog (Advanced tab), `GET /api/v1/security/surface`, `goproxify security surface`, MCP `get_proxy_surface` / `reset_proxy_surface`. **Proposals (step 2)**: from the profile the gateway proposes `max_body_size`, `rate_limit` (from Ephor's per-IP references), `geo_ip`, `ip_filter` (client /24 and /48 networks, never exact addresses) and `cors` (cross-origin `Origin` values), each with what it saw, what it would have refused on the learned traffic, its limits and the `goproxify proxy option` command that applies it. Nothing is applied; a setting the proxy already has is never replaced; every setting not proposed says why. **WAF rule exclusions**: a WAF rule that keeps firing on ordinary clients (the backend served the requests, or the WAF refused them: 3 clean clients, 2 days, 3 hits per client at least) is proposed as a **path-scoped exclusion** (`waf.exclusions`, only under the prefix where it fires) in the full `waf` config; a rule with no clear path gets advice to raise `anomaly_threshold` to 10 (then detect mode) instead of a proxy-wide exclusion; never for custom rules, already excluded rules or a WAF set by a snippet. `GET /api/v1/security/surface/proposals`, `goproxify security surface proposals`, MCP `get_proxy_surface_proposals`. **Positive policy (step 3)**: the profile is turned into an **OpenAPI 3.1 specification** for the existing `openapi` control, set to `detect` with `unknown_paths: block` (nothing is refused, anything outside the policy is counted): learned paths (`/api/users/{users_id}`), methods, typed query parameters and request content types, never bodies. Overlapping templates are merged, paths seen by too few clients or days are left out and listed. The generated spec is checked against the real control in tests. In `learn` the control's verdict (even in `detect`) feeds the report: violations by reason, method and normalised path, flagged *to add?* when they mostly succeed from several clean clients; Ephor gets a `surface_violation` signal (detect) only for violations the backend refused. `GET /api/v1/security/surface/openapi`, `goproxify security surface openapi -out`, MCP `get_proxy_surface_openapi`, "Generate the policy" button. **Enforcement (step 4)**: `POST /api/v1/security/surface/enforce` makes the `openapi` control refuse chosen violation types (`block_reasons`) while the others stay counted. Guard rails: an active openapi policy and a profile (never bypassed), a converged profile, no *to add?* path for those types, no profile overflow; `force` bypasses the last three and is audited; refusal = `409` with `blockers`, nothing changed. `dry_run` previews the impact (requests seen per type, those that succeeded from clean IPs, already refused). One gesture back to detect: `POST …/surface/relax`. Refusals are counted in the report (`blocked_totals`). UI panel in the report, `goproxify security surface enforce|relax`, MCP `enforce_proxy_surface` / `relax_proxy_surface`. **Add suggestions (step 5)**: learning stays on once the policy is set; a path or method outside the policy that keeps coming back from several clean clients over several days is suggested for addition, with its evidence. *High* confidence: the backend served those requests (3 clean clients, 2 days); *low*: the control refuses them and only clean clients keep coming (5 clients, 3 days: a distributed scanner looks like this). Well-known scanner paths (`.env`, `wp-login`…) are never suggested. Accepting (`POST …/surface/accept`) only **adds** to the OpenAPI spec (a same-shape path receives the method, a differing parameter type is widened to text), clears the accepted violations from every gateway's profile, and is audited; the policy never widens by itself. `GET …/surface/suggestions`, `goproxify security surface suggestions|accept`, MCP `get_proxy_surface_suggestions` / `accept_proxy_surface_suggestions`, suggestions panel in the report |
| Cross-gateway thresholds | The Admin adds up the client errors (4xx except 404) counted by **each** gateway and bans an IP whose errors are spread over several of them (source `fleet`). 403s served to an already banned IP don't count. With IP anonymisation or pseudonymisation, the Admin ignores truncated IPs and each Edge keeps banning on the real IP — see [docs/security.md](security.md#seuils-multi-passerelles) |
| Self-hosted vector basemap | Optional: drop an OpenStreetMap PMTiles file on the Admin server (`<storage>/basemap/basemap.pmtiles` or `GPX_BASEMAP_PATH`, cut with `pmtiles extract`) and the Prism / Security / Proxy-view maps zoom down to street level with no external tile service. Served with HTTP `Range` requests so the browser only reads visible tiles; drawn under the country outlines in the area it covers, follows the light/dark theme, 2 levels of overzoom. Without the file the maps keep the embedded country outlines. Setup: `docs/deployment.md`. |
| Terraform provider | `integrations/terraform-provider-goproxify`: manage proxies (`goproxify_proxy`), manual bans with optional gateway/group scope (`goproxify_ban`), the ban whitelist (`goproxify_ban_whitelist_entry`) and IP profiles (`goproxify_ip_profile`) as code, with import and drift detection (defaults added by the Admin are not drift). Built on the Admin REST API with a personal access token. Not yet published on the Terraform Registry. |
| ASN bans | Ban a whole operator (hosting provider, ISP) by banning every range it announces: search by number (`AS16276`), IP address (the ASN announcing it) or name; preview before banning (ranges created / skipped / rejected, last 24 h of traffic including successful requests that would be cut, warnings); one operation and one push to the gateways, with gateway/group scope, expiry and reason; lift all of an ASN's bans at once (Bans page "+ ASN" and "Bans par ASN" strip, API, CLI `security bans asn`, MCP `lookup_asn` / `preview_asn_ban` / `ban_asn` / `unban_asn`). Data: the public ip2asn dataset (iptoasn.com, public domain, no account), downloaded by the Admin on first use. Gateways need no ASN data: they get plain range bans and stay autonomous. A snapshot: run it again to add newly announced ranges. |
| Saved filters | Page Bans: the list filters (search, source, expiry, gateway, sort) can be saved under a name, recalled from a drop-down and deleted. Kept in the browser (`localStorage`), separately for the Admin and each gateway menu — they do not follow the account or another browser. UI only. |
| Gateway- or group-scoped bans | A ban (manual or imported) can apply on one gateway only or on the members of an HA group (`target_scope`: gateway name or `group:<name>`; UI « Applies to », CLI `-scope`, MCP `scope`). Each gateway receives only the global bans, the ones aimed at it and its group's; unknown scope refused; scope shown in the bans list and filterable (`?scope=`). |
| Ban whitelist | Page Bans › **Liste blanche**: addresses and CIDR ranges that no ban reaches (manual, thresholds, CrowdSec, Ephor, rules, peer bans) and that Ephor does not evaluate, with a comment per entry. Existing bans are kept and simply stop applying (they show as "Exempt"); a ban fully inside the whitelist is refused. Stored as a managed `allow` IP profile that Edges keep on disk, so it works without the Admin — see [docs/security.md](security.md#liste-blanche-des-bans). API `/security/bans/whitelist`, CLI `security bans whitelist`, MCP `list_ban_whitelist` / `add_ban_whitelist` / `remove_ban_whitelist` |
| List import | Page Bans › **Importer**: create bans (or whitelist entries) from a pasted list or file in one go — plain text (one address or CIDR per line, `#` and `;` comments, as public lists like FireHOL, blocklist.de or Spamhaus DROP), CSV (the bans export re-imports as is) or JSON. Every entry is validated like a single ban; duplicates, already-covered targets and private ranges are skipped. **Analyse first** (dry run) shows what would be created, rejected and skipped, line by line; the real import is one transaction and one push to the Edges — see [docs/security.md](security.md#import-de-liste). API `POST /security/bans/import`, CLI `security bans import`, MCP `import_security_bans` |
| Manual bans on an IP or a CIDR range | A manual ban targets an address **or a CIDR range** (UI, API, CLI `security bans add`, MCP `create_security_ban` / `ban_ip`): the value is validated and normalised (`203.0.113.7/24` becomes `203.0.113.0/24`), ranges wider than /16 (IPv4) or /32 (IPv6) are refused, and so is a range containing the caller's own address. An **impact preview** (form button, `GET /security/bans/preview`, CLI `security bans preview`, MCP `preview_security_ban`) measures recent traffic — including successful requests the ban would cut — and the bans and IP profiles overlapping the target before anything is created — see [docs/security.md](security.md#bans-par-plage-cidr) |
| Unban & allowlists | Unbanning from the Admin lifts every ban of the IP on every Edge, including bans the Edge posted itself (Ephor, plugins, rules, HA peer); kept across an Edge restart and replayed to an Edge that was offline. An IP in the Ephor allowlist is no longer blocked by the bans Ephor and its plugins already posted — see [docs/security.md](security.md#déban) |
| CrowdSec | LAPI stream bouncer → bans pushed to Edge (403), Docker compatible |
| CVE scanner & application inventory | The CVE scanner reads the application inventory of each gateway: for proxies created by labels the Agent announces the container image, the gateway keeps it on the backend (local encrypted copy, survives an Admin outage), and the scanner queries NVD by CPE and version **without probing the backend** (works on private Docker networks). `latest` or unknown images fall back to the header probe; products without a reliable CPE are listed as "not covered". CVEs are tied to a proxy, product, version and source, and flagged "to verify" (backported fixes). API `GET /security/inventory`, CLI `security cve inventory`, MCP `get_app_inventory`. For every proxy (not only labelled ones) the gateway also reads what the backend responses announce (`Server`, `X-Powered-By`, `X-Generator`, `<meta name="generator">`) **before** `hide_server` strips them, with no extra request; entries are kept in an encrypted local copy, shared between HA members, and merged with the image (version wins over none, image wins on disagreement). A coverage report (`GET /security/inventory`, `security cve inventory -gaps`, Vulnerabilities page) lists what the CVE search cannot process and why (unknown version, no reliable CPE, not in the product table), and admin-supplied CPE overrides (`/security/cpe-overrides`, `security cve cpe`) fill the gaps without ever overriding the table. The inventory feeds vulnerabilities only, never the WAF ([ADR 0017](adr/0017-inventaire-des-applications-et-cve.md)) |
| Security menu | One "Security" entry with a shared Overview (score, active bans by source, recent threats, timeline) and a "Security engines" window with a switch per engine and per capability (Ephor, cross-gateway thresholds, CrowdSec, WAF — a per-Edge master switch that turns the WAF off or on for all its proxies without touching their settings, kept encrypted on the Edge —, rules, CVE scanner), plus tabs (Overview, Vulnerabilities, Bans, Ephor, Proxy scores — a per-proxy grade from 9 checks: TLS, HSTS, X-Frame-Options, hidden Server header, rate limiting, WAF, bot protection, IP filtering, authentication), the same on the Admin and on each Edge. Vulnerabilities: a **Fleet** view (one card per Edge on the Admin, per backend on an Edge, with a risk score and severity bar) or a filterable **List**, plus a detail drawer with actions (fixed, ignore, reopen). Each CVE carries **KEV** (actively exploited, CISA catalog), **EPSS** (0-1 exploitation probability, FIRST.org) and a **remediation SLA** (days after detection, per CVSS severity, editable in the Security engines window — Admin `0.52.3`); the risk score and the KEV filter chip account for KEV. Mobile-friendly (bottom sheet, stacked rows) |
| IP / CIDR trace | **With the ASN database installed**: the trace header shows the IP's operator (ASN, name, country), with one-click scopes *this IP* / *whole ASN* (no CIDR to type; `scope=asn`, CLI `-scope`, MCP `scope`). **Security › IP trace** (also "Full trace" in a ban's IP history): follow one IP or CIDR step by step over a long period (24 h to everything kept, or custom dates). Access requests are grouped into **episodes** (a gap of 10 min starts a new one) with domains, paths, status classes, WAF categories and Ephor signals; CrowdSec/Ephor detections, bans and unbans (including bans set on a CIDR that contains the target) and system events are interleaved chronologically, newest first by default (oldest first on request). A ban step shows **why**: its signals and the **User-Agent** the gateway last saw for that IP when it banned it (Ephor/WAF, detection plugins, automatic rules; Admin `0.207.0`, Edge `0.121.0`). Header: first/last seen, totals, daily activity, top IPs (CIDR) / domains / paths / WAF / countries, current bans and IP profiles that contain the target. Requests go back as far as the access-log retention (365 days by default); pseudonymised or truncated IPs (GDPR) are not found. `GET /api/v1/security/ip-trace`, `goproxify security trace`, MCP `trace_ip` (Admin `0.82.0`). A magnifier button ("Analyze IP") next to public IPs on the Bans page, CrowdSec threats, Ephor detections, Prism and the log detail drawer opens the trace for the IP or its range (/24, /16 — /64, /48 in IPv6), offered in a small dialog (Admin `0.83.0`). The trace, the ban and ASN previews and the single-IP history read the gateways' own log databases, so their figures are exact and a banner-style warning names any gateway that did not answer (Admin `0.172.0`, Edge `0.82.0`) |
| Access portal themes | The admin picks the look of the user-facing Access portal per gateway (**Access portal › Settings › Portal theme**; API `theme`, CLI `access config set -theme`, MCP `update_portal_config`): Automatic (follows the OS), Light, Dark, Ocean, Forest, Amethyst or High contrast. Pushed to the gateway, kept in its local copy, applied before first paint; the xterm terminal follows the theme colours. Portal users have no picker (Admin `0.85.0`, Edge `0.22.1`) |
| Access portal entries (views) | One gateway, several dedicated portals, each reachable at its own address: `domain.com/contractors`, `contractors.domain.com`, or any dedicated domain. Same directory and destinations, but each entry has its own theme, title/tagline, authentication provider, 2FA requirement, **allowed users and groups** and **destinations**. Groups are created per gateway (**Users Access › Groups**) and hold members by login (email or directory identifier). The user dialog shows and edits the user's groups, tags and — computed live — the entries and destinations they can reach. Configured in **Access portal › Settings › Dedicated entries** (API `views` + `/portal/groups`, CLI `access config set -views` / `access groups`, MCP `update_portal_config` / `*_portal_group`). A session is bound to the entry it was opened on. The pushed portal configuration is kept in an encrypted local copy, so the portal restarts without the Admin (Admin `0.87.0`, Edge `0.24.0`) |
| Access destination groups | Bundle catalog machines (SSH / Docker) into named groups per gateway (**Access Catalog › Groups**). A portal entry offers every destination of its groups on top of its own list. Groups are expanded when the Admin pushes the config, so the gateway keeps working from its encrypted local copy without the Admin. Deleting a destination removes it from its groups. REST API, CLI (`access destination-groups`) and MCP tools. User groups are managed from **Settings › Access › Users Access**. |
| Bans page | One page for the Admin (all Edges) and for each Edge menu (that Edge's bans plus global bans): KPIs, 48 h timeline, origin by country, breakdown by source / Edge (domain on an Edge) / reason, then an Active / History / CrowdSec list filterable by search, source, duration (expiring within 1 h, temporary, permanent, repeat offenders) and Edge. Row actions as icons (Prism, IP history, extend 24 h, make permanent, lift), bulk actions on a selection, CSV export, mobile card layout. Each ban records the Edge that reported it (`edge_name`, empty = global); `goproxify security bans list -edge …` and the MCP tool `list_security_bans` take the same `edge` filter |
| Automation flows | Rules, schedules and playbooks are one object, the flow: a trigger (condition tree on CVEs, bans, silent engines, error rate, repeat offenders, offline nodes, expiring certificates or any sampled metric; an alert event; a cron schedule; a manual run with parameters) → steps (disable proxy, ban IP, notify, strict mode, webhooks, PagerDuty, backup, wait, if/else, approval, call a playbook, stop); minimum delay, simulation, versions, run journal (Admin `0.139.0`) — see [docs/security.md](security.md#flux-dautomatisation) |
| SSO | GitHub OAuth2, LDAP/Active Directory, SAML 2.0, OIDC (Google, Microsoft/Entra, Auth0, Okta, Keycloak, Zitadel, Casdoor, Dex, Authentik, Authelia) — OIDC et SAML éprouvés de bout en bout contre Keycloak 26, les autres fournisseurs ne l'ont été que par leurs tests unitaires |
| JWT validation | JWKS : RSA (RS256/384/512), EC (ES256/384/512) and Ed25519 (EdDSA); `none` and HS* refused; `header_name: Authorization` accepts `Bearer <token>` |

### Request transformation pipeline

Each route can declare a `RequestTransform` block (Admin UI → proxy → **Transform** tab):

| Field | Description |
|---|---|
| `rewrite_from` / `rewrite_to` | URL prefix rewrite (e.g. `/api/v1` → `/v1`) |
| `add_request_headers` | Headers to inject into the upstream request |
| `remove_request_headers` | Headers to strip from the upstream request |
| `add_response_headers` | Headers to inject into the client response |
| `remove_response_headers` | Headers to strip from the client response |

The middleware applies first in the chain, before WAF and upstream routing. Hot-reload without Edge restart.

### L4 mTLS Edge↔Edge tunnel

The `internal/edge/tunnel` package provides a persistent encrypted TCP channel between two Edges (inter-datacenter L4 traffic, relay for backends unreachable from the entry Edge).

**Architecture:**
```
Edge A (client)          Edge B (server)
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
- **Configurable active health checks**: `HealthCheckConfig` per route — `path`, `interval`, `timeout`, `healthy_threshold`, `unhealthy_threshold`; probes follow the live route table (manual proxies, revisions, agent routes) and are restarted or stopped on change, including after a gateway restart without the Admin. Probes are **per route**: each route probes its backends with its own `health_check` and has its own verdict, even when a backend is shared with another route; a config edit applies live and the probes stop when the route is removed or disabled. Passive quarantine after a proxy error stays shared per backend URL
- **Failover**: short quarantine + try next backend on dial/proxy failure
- **Circuit Breaker**: per backend (a failing backend does not open the circuit of the others); counts transport failures (not 5xx responses). Open circuit = the backend is skipped (failover to the others); if every backend is open, immediate `503` with `Retry-After`. After `timeout`: half-open with a single probe request, success closes the circuit, failure reopens it
- **Retry policy** with configurable exponential backoff
- **Sticky sessions** via cookie
- **Slow-start** (`slow_start_sec`): a backend that is newly added or recovers from an outage ramps up from ~5 % to 100 % of its share over the configured window; sticky sessions keep their backend. Metric `gpx_backend_slowstart_shifted_total`
- **Configurable server timeouts**: `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` HTTP/QUIC — configurable from Admin (Security > Server settings) and propagated to Edges via WebSocket

### Observability

- **Live topology** (Infrastructure → Topology): Admin → Edges → Agents map refreshed every 5 s in place, each node showing health, request rate (req/s over the last 60 s, with a 2-minute sparkline) and a **risk score 0-100** (highest of: offline, rejection rate 403/429, 5xx rate, CPU/RAM pressure; the dominant cause is shown). API `GET /api/v1/nodes/live`, CLI `goproxify nodes live`, MCP `get_topology_live` — see [docs/api_specs.md](api_specs.md#get-apiv1nodeslive)

- **Async JSON access log**: client IP, domain, method, HTTP code, duration, upstream, HTTP version
- **Structured JSON system log** for all components, with rotation
- **Prometheus metrics** exposed on `/internal/v1/metrics` (gateway token; public `/metrics` only with `GPX_METRICS_PUBLIC=1`) — full instrumentation of all services: `gpx_edge_*`, `gpx_backend_*`, `gpx_backend_up`, `gpx_peer_sync_duration_seconds`, `gpx_waf_profiles_active`, `gpx_portal_sessions_active`, `gpx_pipeline_*`, `gpx_tls_*`, `gpx_auth_*`, `gpx_ratelimit_*`, `gpx_traffic_*`, `gpx_routing_*`, `gpx_f2b_*`, `gpx_crowdsec_*`, `gpx_automation_*`, `gpx_vulnscan_*`, `gpx_admin_http_*` — see `docs/services.md`
- **OpenTelemetry tracing** (OTLP/HTTP, W3C Trace Context): one server span per request continuing an incoming `traceparent`, a client span per backend call (`traceparent` forwarded to the backend, so the trace spans caller → Edge → backend), Ephor / ban decisions as span events (`ephor.signal`, `ban.blocked`, no IP recorded) and route attributes (`gpx.route.id`, `gpx.route.host`). `X-Trace-Id` is returned to the client. Enable with `engine.tracing_endpoint` (`host:port` for plain HTTP, or a full `https://…` URL) or from Admin (`tracing_endpoint`, pushed to Edges; applied live); `engine.tracing_sample_ratio` (default `1`) samples new traces while honoring the caller's decision. Without an endpoint the Edge stays transparent: an incoming `traceparent` is still forwarded, nothing is exported. `/metrics` is not traced
- **JSON audit log**: full traceability of all operations

### GoProxify Access (SSH / shell portal)

Operator portal served by the **Edge** (not Admin):

- **Dual façade**: web terminal (xterm.js) + standard `ssh` client with UUID token (`ssh -p 2222 <uuid>@<edge>`)
- **Targets**: VM / bare-metal (`sshd`) or Docker containers (`docker exec` via Agent)
- **Vault**: SSH login + password or private key, encrypted on the Edge (never exposed to Admin)
- Optional **2FA** (TOTP / OTP email); TTL / one-shot sessions / revocation; metadata audit
- Config & catalogue pushed from Admin (see §3)
- **Labels of an existing proxy**: *Proxies › ⋯ › Docker / Kubernetes labels* shows, read-only, the labels that reproduce the proxy as Docker Compose, Portainer (with or without `stack.env`), `docker run` or a Kubernetes Service, with a copy button per target. Secrets become `${GPX_…}` variables (never written in clear), and settings that no label can carry are listed. API `GET /proxies/{id}/labels`, CLI `proxy labels`, MCP `get_proxy_labels`
- **Discovered containers → proxy**: *Traffic › Discovered containers* tiles have a **Convert to proxy** button that creates a regular, editable proxy from the label route (host, aliases, backends, TLS, security, timeouts… everything the labels carry) and opens it in the editor. A proxy always takes priority over the label route of the same host or alias, whatever the order in which the container and the Admin pushes arrive; the label route stays in the table and takes the host back when the proxy is **disabled or deleted**. Tiles show the proxy that replaces them (*identical* or *different backends*), and proxies whose domains and backends match a discovered container get a badge. API `POST /proxies/from-discovered`, CLI `containers convert`, MCP `convert_discovered_container` (Admin `0.153.0` / Edge `0.68.0`). **Container details** (the *i* button on a tile): effective configuration, backends health, security score and checks, latest requests, and the labels that reproduce the route (Compose, Portainer, `docker run`, Kubernetes) either as they are or **with a security template** — tiles flag missing TLS / WAF / rate limit, and the template adds the missing labels (an Admin snippet of the right type if one exists, otherwise WAF in block mode and 100 req/s, to adjust). A converted proxy keeps an `origin` and is flagged **source container gone** when its gateway no longer announces the container (a silent gateway never makes a proxy an orphan). API `GET /discovered-containers/detail` and `/orphans`, CLI `containers show` / `orphans`, MCP `get_discovered_container` / `list_orphan_proxies` (Admin `0.155.0` / Edge `0.70.0`). **Inactive containers**: a Docker or Portainer container that is stopped, paused or restarting stays on its tile, greyed out with an *Inactive · exited* badge, instead of disappearing as if it had been deleted; it never gets a route (it travels in a separate `inactive` field of the Agent state, which older gateways ignore), cannot be converted, does not make a converted proxy an orphan, and is hidden when a running container already serves the same host. A deleted container still disappears (Agent `0.16.0` / Edge `0.99.0` / Admin `0.186.0`). **Kubernetes and the directories do the same** (Agent `0.17.0`): a Service whose `Endpoints` has no ready address, a Consul instance with a `warning` or `critical` check and an ECS task that is pending or `UNHEALTHY` show as inactive instead of vanishing
- **Enable / disable a container route** (Admin `0.220.0`, Edge `0.131.0`): the label route of a discovered container (Docker, Portainer, Podman, Kubernetes, directories) gets a switch on its *Traffic › Discovered containers* tile, per host, without touching the container. A disabled route is out of the routing table (no traffic, no health probe, no certificate), stays listed greyed out with a *Disabled* badge, and the Agent re-announcing it or a container start does not bring it back; enabling it puts it back at once from the Agent's last state. A pool of several containers behind one host is switched as a whole; a configured proxy is never affected. The Admin keeps the list of disabled hosts and pushes it whole (also at every gateway connection); each gateway keeps it in its encrypted local journal and replicates it inside its HA group, so a member that missed the change catches up from a peer and a restart during an Admin outage keeps it. API `PUT /discovered-containers/enabled`, CLI `containers enable|disable`, MCP `set_container_route_enabled`
- **Editable implicit proxies**: the portal's public hosts (and TLS-terminating domain delegations) appear in the proxy list with an *implicit* badge; WAF, rate limits, headers, IP filter, cache… can be set on them while host, backend and inbound TLS stay generated. The customisation is a local file on the Edge (survives an Admin outage and a restart); *Reset* removes it

---

## 3. Admin — Control Plane

### First start

- Automatic detection of missing SQLite database on first launch
- **Guided initialization screen**: enter administrator email and password
- Generation of ECDSA P-256 key for JWT token signing

### REST API

Endpoints on `:9443` — two families:

- `/api/v1/` — session JWT authentication (human administrators) **or** PAT `gpx_pat_*`
- `/internal/v1/` — pairing token authentication (Edges and Agents, backward compat)

| Resource | Operations |
|---|---|
| Proxies (HTTP, TCP, UDP) | Full CRUD + immediate push to Edge(s) |
| Proxy duplication | "Duplicate" action in the proxy ⋯ menu: opens the creation modal pre-filled with the source config (domain and aliases cleared), created on save (Admin `0.72.0`) |
| Proxy dry run | YAML editor: "Test (dry run)" button validates the config without saving or pushing (structure, host/alias/port conflicts, optional backend probes) with an expandable detailed report — `POST /api/v1/proxies/dry-run` (Admin `0.72.0`) |
| Users | Create, edit, delete, password reset; roles `admin`, `user`, `dpo` (data protection officer: user rights + revealing pseudonymised IPs). Superadmin and accounts holding the reveal right can only be changed, reset or deleted by the superadmin (Admin `0.78.0`) |
| Teams | Access organization by scope; the superadmin can grant a team the right to reveal pseudonymised IPs (`gdpr:reveal`), its membership then being superadmin-only (Admin `0.78.0`) |
| Pairing (Infrastructure › Pairing) | Generate, list, revoke pairing tokens (`gpx_edge_*`, `gpx_join_*`) and see each Edge's details (status, endpoint, version, last contact, token); read-only view in Edge settings › Infrastructure › Pairing (Admin `0.79.0`) |
| User API tokens (PAT) | Self-service `/api/v1/me/tokens` — resource scopes, optional expiry; writes need the matching `:write` scope (`alerts:write`, `domains:write`, `certs:write`, `logs:write`, `security:write`…, admin roles only) |
| Snippets | Reusable profiles: IP, TLS, CORS, rate-limit, auth providers, DNS providers. IP filter, GeoIP, bot and WAF snippets are edited through a form built from the server's module manifests and validated server-side (Admin `0.129.0`) |
| WASM plugins | Sandboxed WebAssembly plugins (wazero) run on the gateway on a route's request and response: allow / deny / modify headers. No file, network or clock access, memory and time capped, fresh instance per call; failing plugin denies by default. Stored encrypted on the gateway and active with the Admin down; installed via `/api/v1/plugins` or `goproxify plugin` (admin only). See `docs/plugins.md` (Admin `0.131.0` / Edge `0.54.0`) |
| Plugin hooks, capabilities, repositories | Log hook (`log`: asynchronous, after the response, bounded drop-on-full queue; never delays a request), body hooks (`request_body`, `response_body`, buffered, size-capped, replaceable), declared capabilities (bounded `kv` state, `http` limited to an allow-list with internal addresses refused at connection), TCP/UDP `connect` hook (the gateway now opens listeners for `tcp`/`udp` routes), route-form **Plugins** tab, Docker labels (`goproxify.plugins`, `goproxify.plugin.<name>.<key>`), plugin repositories with catalog / install / update through the same checks as a manual install (Admin `0.134.0` / Edge `0.55.0` / Agent `0.9.3`) |
| Secret-bearing flow actions | `webhook_signed` (HMAC-SHA256 signed webhook) and `pagerduty` (Events API v2) actions; flow, version, simulation, export and MCP outputs mask action secrets (kept per step id on update), and updates / imports that omit or echo the mask keep the stored value; the automation export also masks alert-channel secrets (Admin `0.135.0`) |
| Metric conditions | `metric_threshold` condition on the series the Admin samples every 10 s (per-proxy rps / 5xx rate / p95, per-gateway and global traffic, TLS expiry and handshake, connections, pipeline, Admin counters): aggregation avg / min / max / last / increase / rate over up to 1 h, operator, threshold, minimum samples; the detail carries `proxy_id` so a « Disable proxy » step works directly (Admin `0.139.0`); per-proxy 5xx rate and p95, gateway traffic and TLS metrics are also computed by each gateway on its own traffic, so a simple flow watching one runs on the gateways and keeps working while the Admin is unreachable (Admin `0.142.0`, Edge `0.60.0`) |
| Flows on gateways | A simple condition flow (condition the gateway can evaluate, one action it can run) is pushed to every gateway at each change and runs there on local data, kept in its encrypted local copy, even while the Admin is down; the Admin no longer evaluates it (no double action) and logs what gateways report, routing their notifications to the alert channels (Admin `0.139.0`, gateway `0.58.13`) |
| Plugin signing and page | Ed25519 signatures over the normalized manifest + module digest; with at least one trusted key (`/api/v1/plugin-keys`, `goproxify plugin keys`) every installed or replaced plugin must be signed. Admin page Settings → Plugins WebAssembly to install, replace, delete plugins and manage trusted keys; plugins are included in Admin backups (Admin `0.132.0`) |
| SSO providers page | Settings → Authentication (SSO): create, edit, enable/disable and delete OIDC / GitHub / LDAP / SAML / Basic / forward-auth providers; types and fields come from `GET /api/v1/auth-provider-types`, secrets are masked and kept when left untouched (Admin `0.129.0`) |
| Nodes | Registration, cluster state, accept/reject pending |
| Agents | List, approve / revoke (pending → approved workflow) |
| Declared / bootstrap | Wizard declared nodes; QR tickets `/i/{token}` + `curl|bash` |
| Hosts | Declared hosts of `architecture.json` with their state (`pending`, `partial`, `joined`); a 15-minute install ticket created on demand per host (one valid ticket per host, nodes auto-accepted while it is valid, consumed when the nodes arrive) that gives the launcher the host's structured description and the Admin certificate fingerprint to check ([ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md)) |
| Domains | Apex / wildcards, entry Edge, ACME DNS, **delegation** Passthrough or Terminate to another Edge |
| Security | Bans, CrowdSec threats, CVE, overview |
| Access | Destination catalogue, SMTP user invite, HTML templates, portal options per Edge, audit |

**Write roles (UI session and PAT alike):** certificates (incl. deploy targets and pull tokens), domains, alert channels / rules / acknowledgements, IP profiles and declared nodes are readable by every account but writable by `admin`/`superadmin` only (bootstrap tickets: admins only, Admin `0.135.18`); snippets are writable by admins and by `user` accounts holding at least one `write` grant. The web UI hides those actions from accounts that cannot perform them (Admin `0.70.2`).

### MCP server

Endpoint `https://<admin>:9443/mcp` — MCP protocol `2025-03-26`, JSON-RPC 2.0 + SSE.

- **Auth:** PAT only (`Authorization: Bearer gpx_pat_…`) — UI session JWT is rejected
- **Scopes:** each tool requires the same scope as its REST equivalent (`proxies:read|write|delete`, `nodes:read|write`, `alerts:read|write`, `domains:read|write`, `certs:read|write` incl. internal CA, `audit:read` / `security:write` for security and automation — rules engine, scheduled tasks, playbooks, silences, auth providers, IP profiles —, `portal:read|write` for Access, …) ∩ current account rights. Tools whose REST route is admin-only (security, automation, internal CA, auth providers, agents, architecture, backups, Access…) also require the `admin`/`superadmin` role. Resources (`resources/read`) follow the rules of the tool they expose. Fail-closed: a tool without a declared scope is refused (Admin `0.70.0`)
- **Read:** proxies, nodes, agents, declared-nodes, alerts, metrics, backups, users, snippets, domains, certs, logs, teams, audit, bans / threats / CVE, alert channels/rules, auth providers, IP profiles, Access (config, catalogue, users, templates, audit)
- **Write:** `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `approve_agent`, `revoke_agent`, `create_declared_node`, `create_bootstrap_ticket`, `create_host_join_ticket`, `accept_node` / `reject_node`, `create_security_ban`, `delete_security_ban`, `ban_ip`, `unban_ip`, `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `create_auth_provider`, `delete_auth_provider`, `create_ip_profile`, `delete_ip_profile`, `create_snippet`, `delete_snippet`, `create_domain`, `renew_domain`, `obtain_cert`, Access tools (`update_portal_*`, `invite_portal_user`, `push_portal`, templates…)
- **Tool list sized to the client (Admin `0.148.0`):** `tools/list` only announces the tools the caller may call (PAT scopes ∩ account rights), and `/mcp?toolsets=proxies,observability` limits it to groups (`proxies`, `nodes`, `alerts`, `observability`, `domains`, `certs`, `security`, `automation`, `snippets`, `portal`, `admin`) — the full list (~17k tokens) does not fit an 8k local model
- **Ephor dry-run:** `simulate_ephor_config` (scope `logs:read`, admin role) replays recent access logs against a candidate Ephor config and diffs it with the current one (blocked requests, bans, likely false positives) without applying anything Since Admin `0.173.0` the replay runs on each gateway, on its own traffic and with its own engine (user-agent rules included); the Admin adds the reports and names any gateway that did not answer.
- Documentation: [docs/mcp.md](mcp.md)
- **Access control (`/mcp-access`, admin only):**
  - **Source IP allowlist:** admins restrict `/mcp` to a list of IP/CIDR entries (`GET`/`PUT /api/v1/mcp-access/allowed-ips`); enforced server-side before PAT auth even runs. Empty list (default) = no restriction.
  - **Backend destination allowlist:** `create_proxy` / `update_proxy` may only point to allowed destinations (`GET`/`PUT /api/v1/mcp-access/allowed-backends`; private networks and `*.internal`/`*.local`/`*.svc` by default), so a prompt-injected agent cannot redirect traffic to an external server.
  - **Active users:** table of every user holding an active PAT on the instance, with their scopes — "who can use the MCP" at a glance.
  - **Scope catalogue (reference):** each scope's covered MCP tools. Scope selection at issuance stays self-service on `/api-tokens` (a PAT is personal to its holder).

### Automation menu

`Automatisation` has four admin-only entries; the rest are tabs:

| Entry | Route | Content |
|-------|-------|---------|
| Overview | `automation` | Rules / schedules / playbooks counts, 24 h activity, latest runs, failure banner, **runs awaiting approval** with one-click Approve/Reject, shortcuts, GitOps **export/import as YAML** (`GET/POST /api/v1/automation/export`\|`import` — flows, channels and mutings, flows and channels updated by name on import) |
| Automations | `security-rules` | Every automation is a **flow** (Admin `0.139.0`, ADR 0009): one trigger — condition (and / or / not tree), alert event, cron schedule or manual —, a safeguard (minimum delay, per-value delay such as `{{detail.ip}}`, concurrency, placement) and steps — action, wait, if/else, **approval**, call a playbook, stop — with variables (`{{detail.x}}`, `{{steps.<id>.x}}`). Tabs: **Rules** (`security-rules`, flows started by a condition or an event), **Flow editor** (`automation-flow`: add steps with +, if/else branches, condition groups, variable picker, simulation of an unsaved draft with the path animated, 20 versions with rollback, each listing what changed since the previous one — steps added, removed, changed or moved, trigger, safeguard, parameters (Admin `0.141.0`); triggers, conditions, actions and metrics come from `GET /api/v1/automation/catalog`), **Schedules** (`automation-schedules`, cron flows with next run and last result), **Playbooks** (`automation-playbooks`, manual flows with parameters, run from the list or called by another flow), **Templates** (`rules-store`, 18 parameterised templates: install with a form and live preview; a flow installed from a template is re-edited through its parameters — flagged when the template changed since installation, with the changes saving will bring (Admin `0.141.0`) —, or **detached** to be edited in the editor) |
| Alerts | `alert-channels` | Tabs: **Channels** (email, webhook, ntfy, gotify, Slack, Microsoft Teams, Telegram, SMS via Twilio, plus the Jira/Linear/GitHub/GitLab/Zammad/GLPI ticketing channels), **Alert routing** (`alerts` — per-rule noise-reduction **grouping window**, `group_window_sec`, merges matching events into one notification; per-rule **escalation** steps, `escalation`, renotify unacknowledged events on their own channels, checked against acknowledgement at each step's due time; the **`automation_notify`** trigger routes the « Notify » action of flows), **Muting** (`automation-silences`, time windows that suspend flow triggers and alert notifications alike, for everything or chosen flows and alert rules; gateways receive the windows with the flows they run and apply them on their own, even across an Admin outage — Admin `0.140.0`, gateway `0.59.0`) |
| Journal | `automation-history` | Every flow run (`GET /api/v1/automation/runs`) whatever its source — Admin, gateway, manual, called by a flow —, filterable (completed, failed, in progress, stopped, muted, gateways); each run opens its step log, can be approved/rejected, cancelled or **replayed** |

### Infrastructure page and architecture edit mode

The **Infrastructure** page reads top to bottom:

- one **indicator strip**: traffic (with a session curve), nodes online, HA quorum, WebSocket connections (admin / agents), peer sync;
- a **To handle** bar, only when something needs attention: pending nodes (Accept / Reject), offline nodes (for how long, last heartbeat), hosts to redeploy (declared vs. deployed differences), excluded agents to confirm;
- the **architecture schema**, in three layouts:
  - **Flow**, read left to right: Internet → Edges (HA groups framed, leader and quorum) → Agents, the Admin above the Edges. Links are drawn from the real node positions: user traffic, agent WebSocket (dashed red when the agent is offline), Admin management. Each node is a card (role icon, status, host, throughput or containers, session availability strip);
  - **By host**: each host is a frame holding its roles;
  - **List**: inventory grouped by host (Matches deployed / To redeploy / Not connected, access to the host Configuration), one row per node with status, session availability, load, version and capabilities; filters All / Edges / Agents / Offline / Differences with counts, and a search by name, host or capability.
  Responsive: single column on mobile;
- a **detail panel** next to the schema for the selected node (no modal): status, host and exposure, req/s and **p95 latency** (Edge, from the Admin's last sample of the gateways; WebSocket sessions excluded, shown as « — » under 5 requests per interval) or containers and CPU (Agent), session availability, capabilities, 5xx rate, the **cause of the risk** that turns the status bar brown (refused 403/429, 5xx or CPU/memory over 60 s, with its score), version, configuration state, HA peers or target Edge, operating actions (traffic, settings, configuration, update, rollback, rescan, delete…) and the node's latest events. By default it shows a node that is down, if any;
- the **infrastructure log** (scaling and health events), with **See all**: the 200 most recent node events, filtered by category (scaling, health, connections, other) and by node.

The schema model (host → role → capability) comes from **`architecture.json`** (`GET /api/v1/architecture`); live state (`GET /api/v1/nodes/live`, `GET /api/v1/metrics/summary`, `GET /api/v1/metrics/proxies`, refreshed every 5 s) is only an overlay.

**Infrastructure → Edit architecture** switches the page to **edit mode**:

- an edit bar shows the number of unsaved changes, with *History*, *Cancel* (asks before discarding) and *Review and save*;
- a palette (**Host, Edge, Agent, Admin**) whose items are dragged onto a host card, or clicked to add to the selected host; roles are moved between hosts by drag and drop. On a **touch screen**, tapping a palette item arms it and tapping a host places it; a role is moved with *Runs on* in the inspector. A **By host / By role** switch shows host cards or the Edges / Agents tiers;
- each change is flagged on the canvas — **New**, **Modified** (added / removed capabilities highlighted), **Removed** (with **Restore**) — and listed below the canvas with its impact: install, redeploy, restart, applied on save (Access on a connected Edge), declaration only;
- unsaved changes are kept as a **draft** in the browser (Portainer keys excluded) and restored when you come back, even after a reload; if the architecture changed in the meantime, you choose to resume the draft anyway or discard it. The Infrastructure page reminds you of a pending draft in its *To handle* bar;
- the **inspector** has *General* (name, host), *Capabilities* (Access, HA group, domains & TLS / ACME — known domains offered as chips to include or exclude, plus manual add —, Docker, Podman, Portainer, K8s) and *Network* (reachable address, delegations, target Edge) tabs, and shows the **Before** value of every changed setting. An agent's **target Edge** can be a single Edge or, when at least one HA group of 2+ Edges exists, the group itself — the agent is then linked to every member (`target_edge: "ha:<group id>"` in the declared config), so any Edge of the group can serve it, whether the pair runs active/active or active/passive;
- **Review and save** lists the changes, their impact, the exact **diff of `architecture.json`** (entries added, removed, keys changed) and warnings. For each connected node removed from the canvas, an option also **stops it** (the agent is revoked then excluded, the Edge deleted); without it, only its declaration is removed and the node shows up again while connected. Saving writes `architecture.json`; the confirmation offers the *Configuration* (Compose, install ticket) of hosts with new nodes and the command to stop revoked agents' containers. Nothing is created or approved on save.

A **host** is a machine that carries one or more elements: several gateways, several agents and the Admin. An agent carries one or more platforms (Docker or Podman, Portainer, K8s), or one agent per platform can be placed on the same host.

Each host has a **Configuration** panel (from the detail panel, the List view, the host inspector or the review confirmation). Its header identifies the host (zone, region, roles) with its compliance state — clicking it opens the differences. A side navigation groups the sections:

- **Deploy** — *Docker Compose*, *.env variables*, *Command line* (`docker run`): a code viewer with line numbers, syntax colouring, **secrets masked** by default (pairing secret, JWT, passwords, API keys; *Show secrets* reveals them), and *Copy* / *Download* of the complete file; *Install ticket*: explained in three steps, then generated on demand — install command (`curl|bash`), `/i/{token}` page, expiry and QR code. The ticket (24 h, one-shot) and the pre-approval of the host's agents are only created when you click **Generate a ticket**; nodes declared this way are **auto-accepted** on connection.
- **Check** — *Differences*: a verdict (everything matches / N differences to fix / nothing connected yet) then, per node, declared vs. deployed settings with their state; *Network flows*: table of the ports to open for this host; *Declaration*: the `architecture.json` entries of the host.
- **History** — *Versions*: timeline of the 50 kept versions of `architecture.json` (date, age, size); selecting one shows what changed since then (added / changed / removed) and its content, with *Restore this version*.

**History** in the Infrastructure top bar and in edit mode opens the same timeline on its own.

The canvas state lives in **`architecture.json`** (Admin `state/` folder), the reference file of the architecture: declared nodes, Edges, RBAC scopes. The Admin reconnects the Edges it describes at startup (address taken from `endpoint`, or from the node's `reachable_host`), aligns its database on the file, and keeps the previous **50 versions** of the file (`goproxify architecture versions|restore`, `GET /api/v1/architecture/versions`). Edges of an HA group announce their Raft peers in their heartbeat, so the Admin discovers the other members without extra configuration. **HA groups** (`config.cluster` + `config.cluster_group` in the canvas) share their security settings: Ephor, the WAF switch and HTTP timeouts are edited once and applied to every member (also replayed to a member that was offline), and the Ephor reference lists (UA, paths, IPs) are synchronised between peer Edges. The **access portal** follows the group too: its options, destinations and invited users are those of the group (a member without the portal keeps a standby replica, ready to take over, and forwards the portal hosts to the member that runs it; in the Infrastructure edit mode every Edge belongs to a group, even alone, and the group's settings — Access, domains, ACME, DNS provider — are set once and shared by all its members), and accounts, 2FA, vaults, personal targets, favourites and, optionally (`sticky` or `shared` HA sessions), web sessions are replicated between the members, encrypted with a group key. Bans decided locally are also passed between peer Edges when the Admin is unavailable.

### Multi-Edge delegation

A domain can be **delegated**: the entry Edge (DNS / public IP) forwards traffic to a target Edge.

| Mode | Behavior | Client IP on target Edge |
|---|---|---|
| **Passthrough** | Raw TLS tunnel (SNI) | Entry Edge's IP |
| **Terminate** | TLS terminated at entry + HTTP(S) proxy + `X-Forwarded-For` | Public IP (if seen by entry) |

Detailed documentation: [delegation.md](delegation.md).

### WebSocket control plane

Admin maintains a **persistent WS connection** to each registered Edge (Admin→Edge). This connection replaces HTTP push calls to `/internal/v1/*`:

- **Automatic reconnect**: exponential backoff 1s → 60s + jitter
- **Full-sync on reconnect**: complete state automatically resent
- **Message queue**: messages emitted during a disconnect are queued and delivered on reconnect
- **Immediate propagation**: any config change is sent in real time to the affected Edge

### Agent approval

Agents connecting for the first time via `JOIN_TOKEN` appear in `pending` status. The operator approves via UI or API (`POST /api/v1/agents/:id/approve`). The Edge immediately sends the first `agent_hmac` via WS.

### TLS / ACME management (DNS-01, HTTP-01, TLS-ALPN-01)

- **Domain entry Edge = HA group**: a domain's entry Edge can be a whole HA group (`ha:<group>`) so every member gets the domain scope, certificate and delegations
- **Wildcard Let's Encrypt certificates** via DNS-01 challenge
- **Validation per domain** (`cert_method`): **DNS-01** (wildcard, needs a DNS provider), **HTTP-01** (`acme-http`, port 80) or **TLS-ALPN-01** (`acme-tls-alpn`, port 443) — no DNS provider required, no wildcard. The Admin opens the ACME order and pushes the challenge answer to the Edges covering the domain (`acme_challenge` WS message); the Edge serves `/.well-known/acme-challenge/<token>` or presents the challenge certificate on ALPN `acme-tls/1` (RAM only, 15 min max, removed after validation). Used by automatic renewal too. Issuance still goes through the Admin and needs at least one connected Edge
- Supported DNS providers: **OVH, Cloudflare, Gandi, Route 53, Hetzner** (Route 53 over signed HTTP calls, no AWS SDK) plus **28 providers through [libdns](https://github.com/libdns)** (Azure DNS, Bunny, ClouDNS, deSEC, DigitalOcean, DNSimple, DuckDNS, Dynu, EasyDNS, Gcore, GoDaddy, Google Cloud DNS, Hurricane Electric, Infomaniak, INWX, IONOS, Linode, Loopia, LuaDNS, Namecheap, Name.com, netcup, Netlify, Njalla, Porkbun, PowerDNS, Scaleway, Vercel) behind one adapter, with an optional `zone` parameter (deduced from the registrable domain when empty). TXT challenge records are created relative to the zone and removed after validation by record ID. Each provider is a module of the common registry (ADR 0007): its manifest lists the parameters, the secret ones, the required ones and the environment variable behind each (`OVH_APPLICATION_KEY`, `CF_API_TOKEN`, `HETZNER_API_KEY`, `GANDI_API_KEY`…) — `GET /api/v1/acme/provider-types`. Secrets of named providers are masked in the API and kept when a provider is edited without retyping them; named providers are managed from the CLI too (`goproxify acme types`, `goproxify acme providers add|update|delete`, `goproxify cert obtain <domain> -dns-provider <id>`) and readable over MCP (`list_dns_providers`, `list_dns_provider_types`)
- Automatic renewal 30 days before expiry
- Push decoded certificates to Edge in RAM only (never on disk on Edge side)
- **OCSP stapling** (Edge `0.20.0`): the Edge fetches the CA's OCSP response itself (certificate AIA URL) and staples it in the TLS handshake — refreshed hourly and at half the response validity, never stale, works without the Admin. Skipped for certificates without an OCSP URL (Let's Encrypt, internal CA). Metrics `gpx_tls_ocsp_staple_seconds`, `gpx_tls_ocsp_revoked`
- **Disk cache is user-safe by default** (Edge `0.21.2`): a route with `cache.enabled` never stores nor serves a response to a request carrying `Authorization` or any cookie, and never stores a response with `Cache-Control: private` or `no-store`, a `Set-Cookie`, or `Vary: *`; other `Vary` headers are honored (one variant per value). Opt-in per route: `cache.ignore_cookies` (cookies not part of the key) or `cache.vary_cookies` (named cookies join the key). `bypass_headers` / `bypass_cookies` unchanged. Static resources without cookies stay cached
- **Encrypted Client Hello (ECH)** (Admin `0.75.0` / Edge `0.21.0`): hides the site name (SNI) in the TLS handshake — an on-path observer only sees a configurable public name. The Admin generates X25519/HPKE keys, shows the `ech="…"` value to publish in each domain's HTTPS DNS record, and pushes the key set to the Edges, which keep it in their encrypted local cache (works without the Admin, across restarts), and replicate it between the members of an HA group without the Admin (encrypted by the group key, newest set wins; Edge `0.40.0`). Key rotation keeps the previous key accepting until DNS caches expire. Page Certificates → Settings, `goproxify ech`, MCP `get_ech_status`. TCP only (HTTP/1.1, h2), not for SNI-passthrough hosts

### Certificate Hub (v0.8)

Feature suite around the TLS certificate lifecycle.

**ACME monitoring — single entry point** (`/acme-monitor`, sidebar Access → Monitoring ACME)
- Unifies what used to be three separate menus ("Certificates", "Certificate deployment", "ACME Monitoring") into one page — the other two are removed
- Dashboard: status per cert (`ok` / `warning ≤30d` / `critical ≤7d` / `expired`), global KPIs, inline renewal button
- Per-row actions: **Deploy** (opens the Deploy Hub drawer below) and **Edit** (opens the source domain's modal — DNS provider, manual PEM, entry Edge, delegation — disabled when the cert has no linked domain, e.g. manual import); `domain_id` field in `GET /api/v1/certs/acme-monitor` links the emitted cert back to its `domains` row
- Automatic alerts: `cert_expiring_soon` (warning ≤30d, critical ≤7d) emitted to the existing alert engine
- **Multi-DNS providers**: manage multiple named providers (e.g. `cloudflare-prod`, `ovh-zone2`) via the "DNS Providers" section of the ACME Monitoring page; each provider has a type (`cloudflare`, `ovh`, `gandi`, `hetzner`, `route53`) and JSON credentials; full CRUD via `/api/v1/acme/providers`

**External certificate import**
- `POST /api/v1/certs/import`: PEM + private key upload — domain auto-extracted from SAN/CN, upserted in DB, real-time push to Edges
- Modal interface in the `acme-monitor` page

**Deploy Hub** (reachable via the "Deploy" button on each cert row in ACME Monitoring — no longer a standalone menu)
- **Deploy targets** (modules of the common registry, ADR 0007; `GET /api/v1/cert-deploy-types`): webhook (POST HMAC-SHA256 signed) or `ssh_exec` (script executed on the target machine with `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN / GPX_EXPIRES_AT`, host key pinned on first use, or an explicit fingerprint / `ignore`). Secrets (HMAC secret, SSH private key) are masked in the API; a new target type appears in the Admin form without a JavaScript change
- Automatic trigger on each ACME renewal + manual trigger
- Audit history per target (`cert_deploy_history`)
- `cert_deploy_failed` alert on failure

**Pull tokens**
- Secure tokens (HMAC-SHA256, TTL, max_uses) for pull download via `curl`
- 7 output formats: `pem`, `key`, `fullchain`, `der`, `der_key`, `pkcs12` (password), `json`
- Public endpoint `GET /api/v1/cert-bundle?token=…&format=…`

### Internal CA (internal certificate authority)

Self-signed root CA generation and issuance of internal server/client certificates, outside ACME — for internal services with no public exposure.

- **Root CA generation**: ECDSA P-256 self-signed root, configurable validity (default 10 years); private key persisted on disk under `certs/internal-ca/<ca_id>/`, never in the DB (only the cert PEM and metadata are stored)
- **Certificate issuance**: server (`ExtKeyUsageServerAuth`) or client (`ExtKeyUsageClientAuth`) leaf certificates signed by a chosen internal CA, with DNS/IP SANs, configurable validity (default 397 days)
- **Revocation**: certificates can be marked revoked (`internal_ca_certs.revoked`)
- `GET/POST /api/v1/internal-ca`, `GET/POST /api/v1/internal-ca/{id}/certs`, `DELETE /api/v1/internal-ca/{id}/certs/{certID}`
- CLI: `goproxify internal-ca create-ca|list-ca|issue|list-certs|revoke`
- MCP tools: `create_internal_ca`, `list_internal_cas`, `issue_internal_cert`, `list_internal_certs`, `revoke_internal_cert`
- Admin UI: "Internal CA" section embedded in the "Domains & certificates" page (`/acme-monitor`) — create a CA, list CAs, side panel to issue/revoke certificates per CA

### Domains & certificates page

Single list of public certificates (ACME, imported) and local ones (issued by an internal CA), with expiry counters, an All / Public / Local filter and search. Row actions on the right: renew (reissue for local, replace for imported), deploy (download root CA for local), details, edit, copy, download, delete (revoke for local). The Add button opens a wizard: Public, Local (issued by an internal CA, with a reminder to install the root CA) or Import. ACME settings (email, directory URL), DNS providers and internal CAs live in a Settings side drawer. `GET /api/v1/certs/{domain}/pem` returns the public certificate only.

### Granular alerting

Alertmanager-inspired model: each rule independently defines its scope, triggers and channels. The same event can notify multiple teams on different channels.

**Rule scope**:
- Target node(s)
- Domain pattern (glob: `infra.*.com`, `*.prod.*`)
- Team(s)
- Component (`edge` / `agent` / `admin`)
- Minimum severity (`info` / `warning` / `critical`)

**Configurable triggers**:
- Edge/Agent node offline
- Certificate expiring in < N days
- CVE detected on a backend
  - The HTTP scanner rejects private targets (RFC1918/ULA), localhost and cloud metadata by default (anti-SSRF). To scan Docker/LAN backends: `GPX_VULNSCAN_ALLOW_PRIVATE=true` on Admin, or via the toggle in the UI (Security > CVE Scanner, Edge view only — the manual scan trigger, the private-network toggle and the scanner status card all live on the Edge side; the Admin view shows only the aggregated CVE list across all Edges, with an Edge column identifying which Edge reported each CVE).
- New thresholds ban (threshold: N bans/hour)
- Critical CrowdSec decision
- Sensitive configuration change
- Scheduled backup failure
- HTTP error rate > threshold on a proxy
- P95 latency > threshold on a proxy
- N failed admin login attempts
- A new addition is suggested to a proxy's surface policy (`surface_suggestion`, Admin `0.203.0`): one alert per proxy and batch of new high-confidence suggestions (the backend serves those requests, from several clean clients over several days), with the first five paths; low-confidence suggestions stay silent
- A route's traffic leaves its seasonal reference (`traffic_deviation`, Admin `0.234.0`): one alert per route and alert start, again if it worsens from a warning (volume gap alone) to a probable attack (volume gap plus a gap in nature); the gateway repeats its active alerts every minute so an Admin outage misses none
- SIEM export lagging behind (`siem_export_lag`, Admin `0.178.0`): a destination more than N minutes behind (60 by default), critical when its lag threatens lines about to be purged before delivery
- Logs a gateway keeps for the Admin about to be deleted (`log_buffer_risk`, Admin `0.215.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)): the oldest line the Admin has not stored in its log volume reaches 80% of the gateway buffer limit (30 days by default), critical at 90%; one reminder every 6 hours per gateway

**Quality of service**: anti-spam rate limiting per trigger, grouping of similar alerts (configurable cooldown).

### Scheduled backups

- **Proxies**: per-proxy versioning, navigable history, per-proxy rollback
- **Admin**: JSON dump (users, token metadata without secrets, snippets, alert channels/rules, declared nodes, plus configuration tables: settings incl. MCP IP allowlist, automatic rules, teams/scopes, workspaces, domains, cert deploy targets, auth providers, IP profiles, tunnel configs, error/portal pages, cross-gateway thresholds (`fleet`)/CrowdSec config); secrets redacted (a redacted secret never overwrites an existing value on restore); optional AES-GCM encryption via `GPX_BACKUP_KEY`, which also adds an encrypted `secrets` section (password hashes, MFA, tokens, GDPR/ECH keys, internal CA, state files) restorable by the superadmin; the encryption key can be generated, rotated (old keys kept so past snapshots stay readable) and revealed by the superadmin from the UI; snapshots are checksummed and re-read on creation, and copied to off-site destinations (folder, WebDAV, S3-compatible); the encrypted `secrets` section also carries the effective HA config, each gateway's persisted state and its Agents' local files, and an optional encrypted `history` section holds logs, audit and past bans (and the line-stream positions that go with the logs) with per-destination retention and `backup_failed` alerts; since Admin `0.180.0` the pending IP-erasure queue and the SIEM header tokens travel in the encrypted `secrets` section, and a gateway restored without its log files restarts its log stream from the beginning of its fresh database (Edge state backup also keeps legal holds); see [docs/sauvegardes.md](sauvegardes.md)
- **Configurable cron** scheduling, configurable retention (number of snapshots)
- **Selective restore** of a snapshot: choose which entities to restore (proxies, users, tokens, PATs, snippets, alert channels/rules, configuration) and the conflict mode (overwrite/skip), with per-entity counts shown beforehand; a safety snapshot is taken before any overwrite
- CLI: `goproxify backup create/list/restore`

### Third-party config import

Automatic source format detection. Two modes: paste content or import one or more files. Preview before validation, partial import possible.

Supported formats: nginx, HAProxy, Traefik YAML, Traefik TOML, Caddy, GoProxify native JSON and generic JSON (`host` + `backends`). Each format is a module of the common registry (ADR 0007): `GET /api/v1/import/config-formats` and `goproxify import formats` list them, and the Admin selector shows any new one without a JavaScript change.

### Coordinated cluster update

- Version inconsistency detection between nodes (via heartbeat)
- Alert if Edges or Agents run different versions
- Triggered from UI (per node or entire cluster) or via CLI
- Configurable rolling update (one node at a time, validation between each)
- Cluster rollback orchestrated from Admin

### Web interface

- Dashboard in three tabs sharing one dataset — Health (status verdict, to-do list, services), Cockpit (KPIs, 1 h traffic chart, edges, busiest hosts, certificate expiry), Map (traffic origin by country, blocks per layer, p95 per edge); the chosen tab is remembered
- Unified proxy list view (HTTP/HTTPS + TCP + UDP) — label-discovered containers are read-only tiles that can be converted into a regular proxy
- Adaptive create/edit form by proxy type
- **Proxy edit modal as a request path** (Admin `0.150.0`): seven steps following a request — Entry, Security, Routing, Transformation, Backends, Resilience, Observability — each showing what it enables; a step lists its settings (green dot, plain summary, direct switch) and opens one at a time in a full-width pane with previous/next; setting search (Ctrl/Cmd+K) and a Path / YAML switch in the header. Path-based routing, `proxy_redirect`, cookies, `sub_filter` and request variables each have their own entry. Fields and save logic are unchanged
- Interactive Docker Compose label generator (HTTP, TCP, UDP)
- TLS certificate, snippet, token, user, team management
- **Skins** (Admin `0.149.0`): the style picker in the sidebar footer offers three skins — Flat (default), Industry DS and **Console** — each with light and dark themes and its own four accent colours. Console follows the look of the public landing page: hairline borders instead of shadows, system fonts only, a single accent used sparingly, near-black primary buttons. An accent may declare a lighter dark-theme variant (`accents[].dark` in `app.config.js`). A skin that needs an external font declares it (`skins[].fonts`); it is fetched only while that skin is active, so Flat and Console make no external request. Contrast of Console text, state colours and accents is checked at 4.5:1 by the UI tests
- Integrations: Prism (traffic analysis), Security dashboard, Backups, Import
- **Feature search** (Admin `0.73.0`): search button in the top bar (also Ctrl/Cmd+K or `/`) opens a command palette over every Admin and Edge page by title, section and FR/EN keywords (accent-insensitive, keyboard navigation, role-aware); also finds individual proxies (host, alias, backend), certificates, domains, gateways, snippets and users by name and opens the page listing them with its search field pre-filled; picking a gateway page from the Admin space asks which gateway to open. Keywords live in `searchKeywords` of `app.config.js`
- **Logs**: aggregated view (access + system + audit), filters, pagination, live mode via WebSocket; access logs add quick period and status-class chips, a requests/errors histogram (click a bar to zoom) and a request detail drawer (IP reputation, analyze in Prism, correlate, filter, copy as cURL, ban IP); system logs and the audit journal get the same period/level chips, histogram and detail drawer, and audit exports now honour the page filters Since Admin `0.175.0` the Admin no longer receives ordinary access lines, only the security events (WAF, Ephor): ordinary lines stay in each gateway's own database for 365 days, searchable from the page, the Live mode asks the gateways for their lines while it is open, and the topology map reads each gateway's own throughput. The `ship_access` setting that could bring back a full copy was removed in Admin `0.178.1`. Since Admin `0.176.0` the Admin reads no access line at all: Prism, SLO, anomalies, alerts, automation, MCP, ban and ASN previews, IP history and trace and the Ephor simulation read the per-minute totals and the gateways' own databases.
- **Access logs — unified view redesign** (Admin `0.55.0`): same code for the Admin page (all Edges) and the per-Edge menu (locked scope) — colored gateway chips replace the node dropdown in the Admin scope, hidden in the Edge scope where the scope banner already names it; columns reorganized into a merged "Host & path" cell, then **IP, Country** (new — flag + ISO code, resolved best-effort from the geo-IP cache already used by the dashboard/Prism/Bans, `country` field on `GET /api/v1/logs` entries), and log level shown as a colored left border on the row instead of a dedicated column (full message stays in the detail drawer)
- **Local gateway log database** (Edge `0.74.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): each gateway keeps its raw access and system lines in its own SQLite files (one per week for access, one per month for system) instead of `edge_access.log`, written in batches without ever slowing a request. Access lines are kept 365 days (`engine.log_retention_days`), system lines 90 days (`engine.system_log_retention_days`), by deleting whole period files; folder set by `engine.log_store_dir`. In pseudonymisation mode the real IP is encrypted on the gateway with its own key (`log-ip-key.gpx`) and an IP erasure order deletes it from the database. Remote search comes in a later delivery.
- **Logs without gaps after an Admin outage** (Edge `0.75.0`, Admin `0.165.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): gateways now send their access and system lines from their local log database, numbered, and the Admin records how far it got for each gateway and stream (`edge_log_cursors`, in the same transaction as the lines). When the Admin reconnects it announces its positions (`log_resume`) and each gateway sends what is missing, once — also when the gateway restarted during the outage, and a brand-new Admin database receives the gateway's whole history. A batch the Admin cannot write is refused whole and resent. Container logs from Agents are covered too (Agent `0.12.0`, Edge `0.76.0`): the Agent only advances its Docker read position once its gateway has stored the batch, and the gateway keeps them in its log database before acknowledging.
- **Signed export and legal hold on the Admin log volume** (Admin `0.216.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)): `goproxify admin logs export|verify|hold|nodes|key|audit` runs the signed, encrypted export and the legal hold on the full history the Admin keeps for every gateway (read-only, server stopped or running). One signed manifest names the gateways covered, rows keep their number on the gateway, real IPs are decrypted with the Admin key, and a hold freezes the whole volume (or the targeted IP or domain lines in every store).
- **Admin log volume settings in the Logs page** (Admin `0.219.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)): the Logs settings dialog sets how long the Admin keeps access lines (365 days by default) and system logs (90 days), with a confirmation before lowering a value, and where the Admin reads access lines from (automatic, always the gateway, always the Admin copy). Same fields as `GET/PUT /api/v1/logs/settings`.
- **Admin log volume** (Edge `0.126.0`, Admin `0.213.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)): gateways now send every access and system line to the Admin, which stores them per gateway in a dedicated log volume (`GPX_ADMIN_LOG_DIR`, one SQLite file per week for access, per month for system). The stream position is written with the lines in the same transaction, so a restored volume has no gap or duplicate, and mounting it on an Admin with a fresh database recovers the history. IP pseudonymisation is applied by the Admin with its own key. The Logs pages still read the gateways; they move to the volume in the next delivery.
- **Logs read from the Admin log volume** (Edge `0.127.0`, Admin `0.214.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)): search, histograms, facets, Prism rankings, unique IPs and exports now read the copy the Admin keeps of each gateway, with the same code the gateway runs on its own base (identical answers, same row numbers), so a stopped gateway stays readable. `logs.read_source` (`auto`, `gateway`, `admin`) picks the source; `auto` uses the copy once it has caught up with what the gateway announces. The Live view follows the incoming stream, so every gateway scrolls together in the Admin Logs menu. Erasing an IP also empties the log volume.
- **Per-minute totals computed on the gateway** (Edge `0.77.0`, Admin `0.166.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): each gateway keeps per-minute totals (requests, bytes, latency, robots, by domain and status code) in the same transaction as its log lines, so they cannot drift from them, and sends them to the Admin, which replaces the minute's value in `logs_minute`. The Admin no longer recomputes totals from raw lines for a gateway that sends its own; dashboards read the same table as before. The Admin still receives the raw access lines (searching them remotely comes in a later delivery).
- **Cross-gateway thresholds fed by gateway counters** (Edge `0.78.0`, Admin `0.167.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): each gateway counts the client errors (4xx except 404) of each readable IP per minute and sends them to the Admin, whose cross-gateway thresholds add up the counters of all gateways instead of rescanning raw log lines every 30 seconds (3 errors on each of two gateways still trip a threshold of 5). Never sent for an anonymised or pseudonymised IP; kept 48 hours on the gateway and 24 hours on the Admin; erased with the IP. The counting window loses up to one minute (the partial minutes at its start and at an unban are skipped): fewer bans, never more.
- **Searching the gateways' logs from the Admin** (Edge `0.79.0`, Admin `0.168.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): `source=edge` on the log routes makes the Admin query every gateway's own log database in parallel and merge the pages by date — list, facets, histogram, export and revealing a pseudonymised IP (done on the gateway that owns the line, with its key). A gateway that is down is reported and keeps its place for the next page; a search that hits the gateway's 8-second budget returns a partial page instead of failing. Searching an IP also finds pseudonymised lines. For now the Admin still answers from its own copy by default; the two give identical results, which will allow the switch.
- **Logs page reads the gateways** (Admin `0.169.0`, Edge `0.80.0`): the Logs page, its histogram (for row-level filters), export and IP reveal now use each gateway's own log database, merged by the Admin together with the Admin's own audit and process logs. A yellow banner tells when a gateway is unreachable (its lines are missing) or a search hit its time limit. The CLI (`logs list|export -source edge`, `-node`, `-cursor`, `reveal-ip -entry-ref`) and the MCP `list_logs` tool (`source`, `node`, `cursor`) do the same; a new `request_id` filter finds every line of one request. Live view still reads the Admin's copy for now.
- **Second facteur par email / SMS / push à la connexion** (Admin `0.136.0`) : le code est envoyé au choix de la méthode (`POST /auth/mfa/send`), vers le destinataire enregistré à l'activation, avec les mêmes limites d'envoi que l'écran du compte.
- **Appareils de confiance MFA** (Admin `0.147.1`) : « Faire confiance à cet appareil » dispense du second facteur pendant 7 jours (cookie HttpOnly `_gpx_device`) ; **Mon profil** liste ces appareils (nom, ajout, expiration) avec Révoquer et Révoquer tous. Ils sont tous révoqués quand l'utilisateur change son mot de passe, quand un admin le réinitialise et quand sa MFA est désactivée (dernière méthode vérifiée supprimée).
- **Plugins WASM : exemples compilés et mesure en charge** : `examples/plugins/` couvre la requête, l'état (`kv`), le corps, le réseau (`http`) et TCP/UDP (`connect`), avec le vrai compilateur dans la suite de tests ; débit et latences mesurés dans [plugins.md](plugins.md). Un exemple embarque le moteur Coraza (directives SecLang, livré avec l'Admin ; environ 7 ms par appel pour quatre règles, jeu réduit seulement). Ses refus sont signalés au journal d'accès et peuvent bannir l'IP (source `plugin:coraza`, visible dans « Bans actifs par source » et « Raisons fréquentes »), sur demande par route.
- **Log retention set from the Admin, applied by the gateway** (Admin `0.183.0`, Edge `0.96.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): the Logs settings modal now separates what the **Admin** keeps (security events and its own logs) from the retention of the **gateways**, where access lines live — a common value (365 days for access lines, 90 for system logs by default) plus an optional value per gateway. Each gateway applies it on its own at its next hourly purge, keeps an encrypted local copy read back at boot before `edge.json` (Admin off, restart: unchanged) and reports the value it really applies every 30 s. The period shortcuts of the Logs page (1 month, 6 months, 1 year…) follow the gateway's retention (the longest one in the global view, the gateway's own in its menu) instead of the Admin's.
- **SIEM export from each gateway** (Edge `0.87.0`, Admin `0.178.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): each gateway reads its own log database with a persistent cursor per destination and sends its lines to your SIEM — syslog RFC 5424 over TCP or TLS (octet-counted, structured data `gpx@32473`) HTTP NDJSON (Splunk HEC, Elastic, Loki…; 2xx = acknowledged) or OpenTelemetry OTLP/HTTP in JSON (Admin `0.179.0`, Edge `0.89.0`; semantic attributes such as `http.response.status_code`, `client.address`, `url.path`). A destination can be restricted to some gateways by name; each gateway only receives its own. Delivery is at-least-once: a failed batch is resent as it was after a 1 s → 1 min back-off and the cursor only moves once the SIEM acknowledged, so an outage of the SIEM, of the Admin or a gateway restart loses nothing as long as the database keeps the lines (every line carries a stable `gateway:type:id` to deduplicate). Filters per destination: access and/or system lines, minimum level, only access lines flagged by the WAF or Ephor; a new destination starts from now or N hours back. The configuration is set from Logs › settings › SIEM export (also `GET/PUT /logs/siem`, `goproxify logs siem`), pushed to every gateway and kept in an encrypted local copy: the exporter starts at boot and keeps going with the Admin off. Header tokens are masked once saved. Each gateway reports its state every 30 s (delivered, lag, last error); the `siem_export_lag` alert fires when a destination falls behind its threshold (60 min by default) and turns critical when the lag passes 80 % of the retention — lines about to be purged before delivery. MCP: `get_siem_status`.
- **Signed export and legal hold, on the gateway** (Edge `0.88.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)): `goproxify edge logs export` writes every line of a date range (filter by IP — pseudonymised lines included — and domain) from the gateway's own database, with the **real IP decrypted by the local key**, as NDJSON or CSV, encrypted by a password (AES-256-GCM, scrypt) and accompanied by a manifest signed with a dedicated Ed25519 key of the gateway: SHA-256 of the file and of its content, row count, range, operator, mandatory reason and the gateway's clock (its evidential value depends on NTP). `goproxify edge logs verify` checks it anywhere, with the public key noted at hand-over. It runs with the Admin off, on a read-only view of the database (no purge, no write), and every export or hold is written to a local hash-chained audit trail, without any IP. `goproxify edge logs hold` freezes a date range: no log file overlapping it is purged until the hold is released, and an unreadable hold registry suspends all purging. With `-ip` and/or `-domain` (Edge `0.89.0`) only the targeted lines are kept — copied into a per-hold archive before the retention removes their file, readable by the export only, deleted by `hold release` or an erasure order — so other people's lines still expire. In an HA group each member exports its own database with its own manifest.
- **Logs replicated between HA group members — removed** (Edge `0.109.0`, removed in Edge `0.129.0` and Admin `0.217.0`: the Admin now keeps every gateway's history, see [ADR 0018](adr/0018-logs-geres-par-l-admin.md); original description: [ADR 0012](adr/0012-logs-proprietaire-edge.md)): every member keeps, besides its own lines, the raw access and system lines of its peers, pulled every 5 s over the group-key-encrypted peer channel (2 000 lines per batch, one cursor per peer and type) — a member that was down, has a fresh disk or has just joined catches up alone, Admin off. Copies are stored apart from the member's own lines and never leave the gateway as its own: they are not shipped to the Admin, not exported to the SIEM, not in the per-minute rollups or the signed export, so each request is still counted once, by the gateway that served it, and a copy is never relayed. The gateway's search keeps its meaning (its own lines); `scope=group` (or `origin=<member>`) on `search`, `histogram`, `facets`, `top` and `unique-ips` reads the whole group, every line carrying its `origin`. A pseudonymised line's real IP travels inside the group-encrypted document and is re-encrypted with each member's own key (one key per member), so the peer can reveal and find it. A peer whose database was replaced is re-read without duplicates. GDPR erasure received from the Admin is first passed on to the peers, so a copy cannot bring the IP back. Each member stores the volume of the whole group. Since Admin `0.196.0` the Admin reads one member per HA group (`scope=group`) and falls back to a peer when it is down, so a missing member no longer makes search and Prism results "incomplete"; it keeps reading member by member while a member runs an older Edge or is unknown to it.
- **Logs — GDPR** (Admin `0.71.0`): the Logs settings (gear icon, admins only) set how client IPs are kept — in full, **anonymised** (truncated, irreversible) or **pseudonymised** (truncated on gateways, real IP encrypted with AES-GCM on the Admin); both modes are exclusive, a gateway-local `ip_anonymize` in `edge.json` always wins, and gateways keep the setting across a restart without the Admin. A holder of the reveal right (superadmin, `dpo` role, or an account or team the superadmin delegated it to — Admin `0.78.0`) can **reveal** the real IP of a pseudonymised entry from its detail panel, with a mandatory legal reason recorded in the audit log (`POST /logs/reveal-ip`, `goproxify logs reveal-ip`). **Erasure** by IP or user (Art. 17, `DELETE /logs/by-ip|by-user`, `goproxify logs delete`) also removes pseudonymised entries and does not write the erased IP back in clear; erasure by IP also removes its bans, ban history and GeoIP cache entry (Admin `0.162.1`), and the nightly purge applies `retention_ban_days` (730 days) to the ban history and expired bans and `retention_access_days` to the GeoIP cache. A truncated IP (`x.x.x.0`, /48 prefix) is labelled in the entry detail and in Prism's top IPs, and the UI never offers to ban or scan it — it covers a whole network of clients (`ip_truncated` in `GET /logs`, Admin `0.71.2`). **Access and portability** (Art. 15 and 20): `POST /logs/subject-export`, `goproxify logs subject-export` — logs, bans, GeoIP, audit and account profile as a JSON file (Admin `0.163.0`). Erasure by IP also reaches the gateways (their access log files and ban history, replayed to gateways that were offline). Defaults are short: logs 90 days, ban history 365, portal session recordings 90 (`-1` for unlimited); the third-party geolocation fallback (`ip-api.com`) is off unless `geoip.allow_external_lookup` is set. Register of processing, impact assessment and privacy notice: [docs/rgpd-conformite.md](rgpd-conformite.md). See [docs/rgpd.md](rgpd.md)
- **Observability overview**: one page for the Admin (all Edges, Edge selector) and each Edge menu (Edge locked): top anomalies, KPIs, traffic chart, HTTP codes, Edge table, proxies to watch, top countries, certificates to renew, availability SLO with error budget and burn rate (`/prism/slo`, MCP `get_prism_slo`, alert trigger `slo_burn` evaluated every 5 min per Edge and fleet-wide)
- **Prism**: command-center layout, KPIs with sparklines, Leaflet map with bundled country outlines (no external tiles; zones, cities or regions of every country, requests / error rate / banned IPs, live pulses at the source city), server-side anomaly detection (`/prism/anomalies`, MCP `get_prism_anomalies`, CLI `goproxify prism anomalies`), country and city drill-down, time series, HTTP codes, tabs Paths / IPs / Sources (components, bots, referrers) / Countries, period comparison, IP scan, CSV/JSON/HTML/PDF exports; private/loopback source IPs (no real country) stay in the same country ranking (Prism, dashboard, Bans) but always after real countries, with a "Local network" separator (Admin `0.52.7`) ; rankings (paths, IPs, components, referrers, TLS fingerprints), unique IPs, the country and city views and the live map are computed from each gateway's own log database and merged by the Admin: rankings are exact (threshold algorithm, no sum of partial tops), the unique-IP count is the union of the gateways' sets (exact up to 2,000 addresses, about 1 % estimate beyond, shown as "≈"), and a banner names any unreachable gateway whose traffic is missing (Admin `0.171.0`, Edge `0.81.0`)
- **Alerts and SLO page** (Admin and per Edge): SLO card with server-side target, SLO by Edge, coverage warning + one-click rule creation for the `slo_burn` trigger, recent fired alerts with histogram and detail drawer (`GET /alert-events`, MCP `list_alert_events`, CLI `goproxify alert events`), a **Silenced** badge on events an active silence window blocked from notifying, and an **Acknowledge** button (`POST /alert-events/{id}/ack`) that stops a rule's remaining escalation steps; alert cooldown is now per Edge/domain
- **Metrics page** (Admin): fleet Prometheus view (throughput, 5xx rate, bytes, control connections), Edge table, filterable proxy table with trend, TLS certificates, security pipeline counters
- **Live attacks map** on the Security overview: errors and banned IPs of the last 24 h plus a live feed of `error` / `banned` events, per Edge or for the whole fleet
- **Proxy view** (Admin/Edge `0.69.1`, Observability menu next to Prism, replaces the "Explorer" log explorer): a searchable list of every configured proxy (status dot, requests/s, p95) next to a live control panel for the selected proxy — the same "traffic by country" map as Prism (Requests/Error rate/Banned IPs modes, Zones/Cities/Regions styles) with a "Top countries" ranking (local-network entries grouped last, like Prism) and an embedded live connections feed with repeated-event grouping (`×N`, same as Prism's live feed), KPI tiles (requests/s, p95, error rate), server-side anomalies, and icon-only quick actions: purge cache, put into maintenance/reactivate, bans, full Prism view; same page for the Admin (all proxies) and each Edge menu (locked scope, `GET /proxies?edge=…`). The map, top countries and feed are built purely from the live stream (`/prism/live-ips`) while the page is open — no historical `/prism/geo` aggregate, by design: this is a real-time control panel, not an analysis tool (use the full Prism view for that). Purge cache and maintenance are real server actions: `POST /api/v1/proxies/{id}/cache/purge` (relayed to every Edge hosting the proxy; the disk cache is stored per-route so it purges cleanly one proxy at a time) and the existing `PATCH /api/v1/proxies/{id}` (`enabled`)

---

## 4. Agent — Discovery & Telemetry

### Docker discovery

- Listens to Docker events via Unix socket (`/var/run/docker.sock`; this access is equivalent to root on the host, a read-only mount does not limit it)
- Detects `goproxify.*` labels on containers at startup and in real time (start/stop/die)
- **Hot-connects** the Edge to the application's private Docker bridge network (apps expose no port on the host)
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
goproxify.ephor.whitelist: "10.0.0.0/8"
goproxify.canary: "true"
goproxify.canary.weight: "10"
```

### Kubernetes discovery

Symmetrically to Docker mode, the Agent can discover annotated Kubernetes resources:

- Watches `Ingress` and `Service` resources carrying the **label** `goproxify.enabled: "true"` (a Kubernetes label selector cannot match annotations, so this is a label, unlike Docker's `goproxify.enable`)
- Configuration comes from `goproxify.*` **annotations** with the same semantics as the Docker labels (see [docs/labels.md](labels.md)): `host` (CSV = aliases; on an Ingress the rule host wins), `port`, `backend`, `tls`, `waf`, `rate_limit`, `limit_conn`, `backpressure`, `slow_start`, `jwt`, `mtls`, `headers.add/remove`, `cache`, etc. The label prefix is configurable (`kubernetes.label_prefix`)
- Values deduced from the resource (host, backend, TLS from `spec.tls`) take precedence over the annotations
- Proxies created read-only in UI (source `k8s`)
- Requires a `ServiceAccount` with `get/watch/list` access on `ingresses` and `services`, and on `endpoints` to show a Service without a ready pod as **inactive** (without that right, no Service is ever shown inactive)
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

### Discovery sources (modules)

Docker/Podman, Portainer and Kubernetes are **modules** of a common registry (`internal/agent/sources`, ADR 0007): each declares a manifest (configuration fields, secrets, required fields) and a factory. The Agent builds, starts and hands the pairing token to every source without knowing which one it is, announces their runtimes to the Admin, and protects their secrets when the Admin pushes a configuration patch (Kubernetes token, private-registry password, Portainer API key). Consul, Nomad, etcd and Amazon ECS are such sources (see "Service directory discovery" below); a source added to the code is configured under `sources.<type>` in `agent.json`, validated by its manifest, and listed by `GET /api/v1/discovery-sources` / `goproxify agent-mgmt sources` / MCP `list_discovery_sources`. Sources only need their own gateway — they keep running without the Admin, across an Agent restart. All three follow the Agent's current gateway on an HA failover and re-publish their full state to it (Docker rescan, immediate Portainer scan, Kubernetes watch restart); Portainer `endpoint_edges` stay explicit operator choices.

### Service directory discovery (Consul, Nomad, etcd, Amazon ECS)

The Agent can read the instances of a service directory and publish them as routes on its gateway, with the same options as Docker labels (WAF, rate limit, JWT, mTLS, canary… — [docs/labels.md](labels.md)). One engine (`internal/agent/catalog`) polls the directory (default every 30 s), converts each instance like a Docker container, sends only what changed, and removes an instance when it leaves the directory. Several instances with the same `goproxify.host` form the pool of one route. Configuration is under `sources.<type>` in `agent.json` (`enabled: true` to start it); secrets are masked in the heartbeat and kept by a configuration patch.

| Source | Where the labels live | Instances | Notes |
|---|---|---|---|
| `consul` | service **tags** `goproxify.host=app.example.com` and service **meta**; `goproxify.enable=true` must be a tag | every instance; one with a `warning` or `critical` check is shown **inactive** and gets no route | ACL token, datacenter, namespace, CA |
| `nomad` | service **tags** (Nomad services have no meta) | native Nomad services, all namespaces by default | ACL token, region, CA |
| `etcd` | one key per instance under `key_prefix` (default `/goproxify/services/`): `{"host":"app.example.com","backend":"http://10.0.0.5:8080","labels":{"tls":"true"}}` | every valid key; a key with a lease disappears with it | v3 JSON gateway, user/password, several endpoints with failover |
| `ecs` | container `dockerLabels` of the task definition, completed by task **tags** | tasks desired RUNNING, `awsvpc` network mode (Fargate or EC2); a task that is not yet RUNNING or is UNHEALTHY is shown **inactive** and gets no route | credentials from the configuration, `AWS_*` variables or the task role; no AWS SDK (Signature V4 over HTTPS) |

Common rules: the instance address and port come from the directory (the `goproxify.scheme` label switches to `https`, `goproxify.port` overrides the port); an instance without `goproxify.enable=true` or `goproxify.host` is ignored; `label_prefix` changes the prefix. **Autonomy (ADR 0006):** if the directory is unreachable the Agent removes nothing — the gateway keeps serving the routes it already has, across its own restart. A gateway refusal (invalid security labels) is logged and not retried until the instance changes. At start-up the Agent also removes the gateway's instances of that source that the directory no longer publishes (an instance gone while the Agent was stopped).

```json
{
  "sources": {
    "consul": { "enabled": true, "address": "http://consul.example.com:8500", "token": "…", "poll_interval_s": 15 },
    "ecs":    { "enabled": true, "region": "eu-west-1", "cluster": "prod" }
  }
}
```

### Horizontal auto-scaling

- Trigger: average CPU of the service's containers (the Agent reads it from Docker stats); no request-rate or latency trigger
- Decided **by the Agent alone**, so it keeps working when the Admin is unreachable (ADR 0006); `goproxify.scale.service` / `scale.min` / `scale.max` labels select the group and its bounds, the thresholds and cooldown come from the `autoscale` section of `agent.json`
- Scale-up clones the service's container through the Docker API; scale-down stops the last instances (not `docker compose up --scale`)
- New instances are announced to the Edge like any other container, so they join the routing table through discovery
- Compatible with resource-weighted adaptive load balancing
- Configurable cooldown between decisions (anti-flapping, 120 s by default)

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
- Correlation with Edge/Agent/Admin logs in Logs view
- Configurable rotation and retention per container

### System telemetry

- Reads `/proc/stat` and `/proc/meminfo`
- Prometheus export on `:9191/metrics`
- Data used by Edge adaptive load balancing (host + containers via WS)

### Persistent WS connectivity

Agent maintains a **persistent WS connection** to the Edge (Agent→Edge). This connection:

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

Docker metrics (**CPU**, **memory**, **disk IO**) of `goproxify.enable` containers are streamed to the Edge every **10s** via WS (`metrics`). Score per IP:

`cpu×0.5 + mem×0.3 + disk_io×0.2` — lowest score backend receives the request.

- **Local pool**: multiple containers with the same `goproxify.host` → one `docker-host:…` multi-backend route.
- **Failover**: proxy failure → ~15s quarantine → try another pool backend (no 502 as long as one healthy remains).
- **Cross-Edge**: if the same host is discovered on Edge A and Edge B, peer sync + `gateway/tunnel` tunnel to the remote IP via the owner Edge (see [architecture.md](architecture.md#adaptive-load-balancing)).

P95 latency / error_rate: fields planned in payload, not used in v1 score.

### Canary and Shadow Mirror

**Manual** configuration on the proxy (UI / API): `CanaryConfig` (weight %, header, cookie) and `ShadowConfig` (fire-and-forget mirror). With `compare: true` (Edge `0.42.0`) the mirror response is compared to the primary one: status always, `compare_headers` (list of header names) and `compare_body` (size + SHA-256 of the first 8 MB, nothing stored) on request; differences are counted in `gpx_routing_shadow_diff_total{host,kind}` (`status`, `header`, `body`, `error` when the mirror is unreachable) next to `gpx_routing_shadow_compared_total`, and one sample per 10 s is logged.

Docker labels `goproxify.canary` / `goproxify.shadow`: automatic detection via Agent discovery — the Edge activates `CanaryConfig` / `ShadowConfig` on the `docker-host:` route without manual config. The canary/shadow container stays outside the LB pool (same `goproxify.host` as normal backends).

### Advanced routing and API protection (per proxy, JSON config)

All options run on the Edge alone — no Admin needed, even after an Edge restart.

| Option | Effect |
|---|---|
| `split` | `variants: [{name, backend, weight}]`, `sticky_cookie` (stable A/B assignment), `override` (header/cookie naming a variant, for tests) |
| `conditions[].type = "jwt_claim"` | Route on a claim of a JWT **validated by the route** (`jwt`); array claims such as `groups` match on any element; never true without JWT validation |
| `signed_url` | `secret`, `param_sig` (`sig`), `param_expires` (`expires`), `paths`; `sig = base64url(HMAC-SHA256(secret, path + "\n" + expires))` — 403 if missing, wrong or expired; params stripped before the backend |
| `rate_limit.quota` / `quota_period` | Fixed-window quota per key (`minute`, `hour`, `day`); `key_by` also accepts `header:<name>` (API key) and `cookie:<name>`. Per-Edge counters. A client-chosen header key is spoofable: combine with authentication |
| `bandwidth.bytes_per_sec` | Per-response throughput cap (nginx `limit_rate`) |
| `maintenance` | 503 + `Retry-After`, optional HTML; `bypass_cidrs`, `bypass_header` (`"Name: value"`) |
| `redact_json` | `fields` (key at any depth, or `a.b` path), `mask`; fails closed (502) on invalid, oversized (16 MB) or non-gzip-encoded bodies |
| `html_inject` | `content` (≤ 16 KiB), `position` (`body_end` before the last `</body>`, `head_end` before the first `</head>`), `csp_nonce` (`{{nonce}}` replaced per response and added to the backend's `script-src`); only `text/html`, uncompressed or gzip, ≤ 8 MiB; left untouched when no anchor is found. The backend is asked for gzip only (also with `redact_json` and `sub_filters`) |
| `graphql` | `max_depth`, `max_aliases`, `block_introspection` (POST, batches, GET) |
| `hedge` | `delay_ms`, `max_extra`: a GET/HEAD without body not answered after the delay is also sent to the next backend; first response wins |
| `static` | `root`, `index`, `spa_fallback`, `cache_max_age`: the route serves a gateway folder instead of proxying (no backend needed); GET/HEAD only, no directory listing, dotfiles hidden; with `spa_fallback`, unknown page paths (no extension, or `Accept: text/html`) return the index, missing assets stay 404; ETag revalidation and Range; the index is always revalidated |
| `request_schema` | (for full OpenAPI validation of paths, parameters and bodies see `openapi`) `rules[]` (`methods`, `path_prefix`, `schema`), `mode` (`block` default / `detect`), `max_body`: validates JSON request bodies against a JSON Schema (draft 2020-12 and earlier); first matching rule wins (default methods POST/PUT/PATCH); invalid → 422 with up to 5 `{path, message}` details, body over `max_body` (1 MB) → 413 in block mode; `detect` always forwards and only counts (`gpx_routing_request_schema_total{host,result}`); non-JSON bodies are not validated; schemas must be self-contained (external `$ref` refused); invalid schemas are rejected by the dry-run |
| `grpc_web` | Translates gRPC-Web (binary and `-text`) to gRPC for an HTTP/2 backend, trailers returned in the final frame |
| `openapi` | `block_reasons` (in `detect` mode, violation types that are refused anyway: `unknown_path` 404, `unknown_method` 405, `invalid_param` 400, `invalid_body` 422, `unsupported_media` 415, `too_large` 413; no effect in `block` mode; set one type at a time by the surface learning, ADR 0016), `spec` (OpenAPI 3.0 / 3.1 document, YAML or JSON — a string or the JSON object; local `#/…` references only), `mode` (`block` default / `detect`), `unknown_paths` (`allow` default / `block`), `strip_prefix`, `max_body`, `skip` (`path`, `query`, `header`, `cookie`, `body`): validates the path template and method, path / query / header / cookie parameters (typed from their schema: integers, booleans, arrays, formats such as uuid) and JSON request bodies (`$ref`, `nullable`, `oneOf`…). Block mode answers 400 (parameter), 422 (body), 413 (body over `max_body`), 415 (content type not declared), and with `unknown_paths: block` 404 / 405 (`Allow` header) for a path or method absent from the spec; `detect` always forwards and only counts (`gpx_routing_openapi_total{host,result}`: `valid`, `invalid`, `unknown_path`, `unknown_method`). The most specific template wins (`/pets/mine` before `/pets/{id}`). Bodies that are not JSON (multipart, form) are forwarded unchecked; responses are not validated; invalid specs are rejected by the dry-run |
| `grpc_transcode` | `proto` (map file name → `.proto` source, `google/api/*` and `google/protobuf/*` imports provided) **or** `descriptor_set` (base64 `FileDescriptorSet`, `protoc --include_imports --descriptor_set_out`), `services`, `auto_mapping`, `emit_defaults`, `proto_field_names`, `max_request_body` (4 MB), `max_response_body` (16 MB): exposes a gRPC backend as REST/JSON (unary and streaming methods). Routes come from each method's `google.api.http` annotation (`get`/`post`/`put`/`patch`/`delete`/`custom`, `body` as `*` or a field, `response_body`, `additional_bindings`, path variables such as `{id}`, `{user.id}`, `{name=projects/*}`, `{path=**}`, `:verb`); with `auto_mapping` an unannotated method is also served at `POST /pkg.Service/Method`. Path variables, then the JSON body, then query parameters fill the request message (scalars, enums by name, repeated fields, `Timestamp` / `Duration` / wrappers); unknown query parameters are ignored. gRPC status maps to HTTP (NOT_FOUND → 404, INVALID_ARGUMENT → 400, UNAUTHENTICATED → 401, UNAVAILABLE → 503…) with `{"code","message","details"}` (`details` decoded from `grpc-status-details-bin`); `Grpc-Metadata-<Name>` request headers become metadata `<Name>`. Native gRPC calls (`application/grpc*`) go through untouched; an unmatched REST path gets 404. The backend is reached over HTTP/2 (h2c for `http://`) with the usual load balancing, health checks and failover; the transcoder sits right before the proxy, so cache, `openapi`, `request_schema` and authentication see the REST request. Streaming (Edge `0.48.0`): a server-streaming method answers as NDJSON, one `{"result": …}` line per message delivered as it arrives (a gRPC error after the first message ends the stream with an `{"error": {code, message, details}}` line; before any message it keeps its HTTP status), a client-streaming method takes a request body made of JSON values (NDJSON, concatenated values or one JSON array — each becomes a message, path variables apply to each; `body: "*"` required), a bidirectional method does both — all request messages are sent before the response is read (no interleaved exchange). Metric `gpx_routing_grpc_transcode_total{host,result}` |
| `rate_limit.shared` | HA group members add up each other's quota counts (~2 s lag, clocks must be in sync) and subtract the throughput their peers already admit for the same key from their own `rps` refill (~0.5 s lag, 10 % floor, `burst` stays per gateway); local values if peers are unreachable |
| `sso.provider = "oauth2_proxy"` / `authelia` / `authentik` / `forward` | Forward-auth: any 2xx allows; `forward_auth_signin_url` redirects a 401 (`?rd=`); `forward_auth_timeout_ms`; `headers_to_forward` accepts a trailing `*`; client-supplied identity headers are stripped |

Set from the proxy dialog (Advanced tab › Advanced routing, plus key, quota and HA sharing under Protection › Rate limiting; Admin `0.115.0`), the CLI (`goproxify proxy option`) or MCP (`update_proxy` `options`). Saving the dialog now keeps these options (earlier versions dropped them). Not available yet: interleaved bidirectional exchanges in `grpc_transcode`, HA-shared instantaneous rate (`rps`) and bandwidth cap.

### Network connectivity

- Optional **WireGuard** tunnels for inter-node communication (port `:51820` UDP)

---

## 5. Alert channels

All channels can be combined in the same rule. Each channel type is a **module** of the common registry (`internal/modules`, ADR 0007): its manifest lists the configuration fields, which ones are secret and which are required, and drives validation, secret masking, the Admin form (`GET /api/v1/alert-channel-types`), the MCP tool `list_alert_channel_types` and `goproxify alert channels types`. A secret left empty when editing a channel is kept.

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
| `edge` | Start Edge (Data Plane — Reverse Proxy) |
| `agent` | Start Agent (Discovery & Telemetry) |
| `token create/list/revoke` | Edge/Agent pairing tokens (Admin API) |
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
| `auth-provider types/list/get/create/update/enable/disable/delete` | External auth providers (OIDC, SAML…) |
| `teams list/get/create/update/delete + members + permissions` | RBAC teams, permissions granted to members (`gdpr:reveal`) |
| `workspaces list/get/create/update/delete + members + resources` | Workspaces (multi-tenant) |
| `ip-profile list/get/create/update/delete` | IP profiles (CIDR allowlist/blocklist, GeoIP) |
| `containers list` | Discovered Docker containers (read-only) |
| `me get/update/passwd + me tokens` | Current profile + personal API tokens (PAT) |
| `security threat/bans/waf` | Security: Ephor (including `threat simulate`, a dry-run on recent logs), IP bans, WAF per proxy |
| `status` | Cluster state (nodes, versions, health) |
| `access` | GoProxify Access (config, catalogue, users, templates, audit) |
| `nodes` | List / live health-throughput-risk (`nodes live`) / accept / reject nodes (Infrastructure) |
| `declared` | Architecture wizard declared nodes |
| `bootstrap` | QR / curl\|bash host integration tickets |
| `hosts` | Declared hosts and 15-minute install tickets (`list`, `join-ticket`) |
| `edge cache show/refresh/export/clear` | Edge locale cache management |
| `edge logs export/verify/hold/key/audit` | Signed, password-encrypted export of a gateway's logs and legal hold, local, Admin off |
| `update check/apply/rollback` | Docker image updates (via Agent) |
| `version` | Display binary version |
| `help` | Display help |

Common options: `-config <path>`, `-admin-url <url>`, `-token <token>` (or `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`).

---

## 8. High Availability

### Edge — independent groups

- Edges organize into **groups** (by datacenter, region, customer…)
- A group has **no leader and no quorum**: members are equal and any of them can take over from another, whatever the group size (2, 3 or more). Unique actions (e.g. the notification of an automation rule) go to the **first member seen alive** in the group card, which every member computes alone from its exchanges with its peers; if that member does not answer, the next one acts
- In a network partition each side keeps serving; a rare duplicate of a unique action is accepted
- On loss of Admin access, each Edge falls back to its **encrypted local cache**

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
| **Docker Compose** | `bash scripts/quickstart.sh` generates `docker-compose.yml` + `.env`, then `docker compose up -d` — recommended |
| **Launcher** | `docker run --rm … ghcr.io/vincamok/goproxify/launcher:preview --admin --edge --agent [--host …]` installs the local host (Admin, Edge, Agent) with generated secrets and a TLS certificate for the Admin, declares the other hosts in `architecture.json`, rolls back everything it created if a step fails, then removes itself. A declared host runs the same launcher with no arguments: it waits 15 minutes on port 8080, a phone scans the QR code of the host's 15-minute ticket (a confirmation page shows the Admin and its certificate fingerprint; the install starts on the click, and the launcher checks the pinned fingerprint before sending the ticket), or `launcher join <url>` installs at once. With no arguments the launcher also serves a design page (`/design`, protected by a random access code printed in its output) to declare hosts, dry-run and install the local host from a browser; the Admin's host sheet shows the QR code in a **Launcher (QR code)** section; `launcher update` re-pulls the images of the host's containers and recreates the ones that changed, keeping volumes, variables and secrets, with a return to the old image if the new container does not get healthy; the launcher generates the backup key (shown once), backups carry the root secret and the Admin certificate, a diagram of the planned infrastructure (Mermaid text and SVG, no library) next to the design form, and `launcher --restore <file>` (or the restore section of the design page) rebuilds a lost Admin from a backup (same root secret, certificate and `architecture.json`, so surviving gateways and Agents recognise it) before the data is restored from the Admin ([ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md), in progress) |
| **Bare-metal** | Interactive `setup.sh` script — module selection (Admin / Edge / Agent) |
| **systemd** | Hardened service (systemd units with sandboxing) |
| **setcap** | `setcap cap_net_bind_service` to listen on ports < 1024 without root |

Configuration: JSON files in `config/` (`admin.json`, `edge.json`, `agent.json`) + `GPX_*` prefixed environment variables (production priority).

---

## 10. Tech stack

| Domain | Choice |
|---|---|
| Language | Go — single binary, zero runtime dependency |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 QUIC (UDP), WebSocket, gRPC, TCP/UDP L4 |
| **Control plane** | **Persistent WebSocket (nhooyr.io/websocket) — Admin→Edge(WS), Agent→Edge(WS)** |
| TLS | `crypto/tls` + `GetCertificate` (RAM only), passive SNI passthrough, ACME DNS-01 wildcard |
| Routing table | `sync.Map` — atomic updates without interruption |
| Persistence | Embedded SQLite `modernc.org/sqlite` (CGO-free) — Admin only |
| Admin HA | rqlite (distributed SQLite, 3 nodes, Raft) |
| Edge HA | Leaderless groups (first member seen alive runs unique actions), encrypted local cache |
| Configuration | Viper — JSON + `GPX_*` env var override |
| Discovery | Docker Engine API via Unix socket (`/var/run/docker.sock`) |
| Metrics | Prometheus (`/metrics`), OpenTelemetry |
| Auth | JWT ECDSA P-256, bcrypt passwords, HMAC-SHA256 WS control plane, JOIN_TOKEN lifecycle, PAT `gpx_pat_*` (API + MCP) |
| App security | Ephor thresholds, CrowdSec LAPI bouncer, native Go WAF (OWASP CRS-4, 13 rules) |
| LLM integrations | MCP server JSON-RPC 2.0 + SSE (`/mcp`, PAT auth) |
| Deployment | Single binary · Docker Compose · systemd (hardening) · `setcap cap_net_bind_service` |
