# GoProxify — RGPD / GDPR Compliance Guide

> This document applies to operators running GoProxify. GoProxify is a **self-hosted** tool: the operator is the data controller for all personal data processed through it.

---

## 1. Data collected and where it lives

| Data | Component | Storage | Default retention |
|---|---|---|---|
| Client IP address | Core (access log) | Log file on Core + forwarded to Admin SQLite | 365 days |
| HTTP method, path, host, status, latency | Core (access log) | Log file on Core + Admin SQLite | 365 days |
| User-Agent header | Core (access log) | Log file on Core + Admin SQLite | 365 days |
| Referrer header | Core (access log) | Log file on Core + Admin SQLite | 365 days |
| WAF rule matches (categories only, no payload) | Core (access log) | Admin SQLite | 365 days |
| Banned IP + ban reason + expiry | Core / Admin | Admin SQLite | 730 days |
| Admin user email + bcrypt password hash | Admin | Admin SQLite | Until deleted |
| Admin user session JWT | Admin | In-memory + cookie (browser session) | Until logout or expiry |
| Audit log (who did what, when) | Admin | Admin SQLite | 90 days |
| GeoIP lookups | Core | In-memory only, MaxMind DB on Core disk | Never stored per-request |
| SSH portal session metadata (target, duration) | Core / Admin | Admin SQLite | Until deleted |
| SSH portal credentials (login/key) | Core | AES-GCM encrypted on Core disk, never sent to Admin | Until deleted |

**What GoProxify does NOT collect:**
- Request bodies (WAF inspects them in memory; they are never logged)
- Response bodies (same: in-memory inspection only)
- Cookie values
- Authorization headers or tokens
- Any data sent to Anthropic, Cloudflare, or any third party

---

## 2. Minimisation options

### IP anonymisation in access logs (recommended for GDPR)

Enable in `core.json`:

```json
{
  "engine": {
    "ip_anonymize": true
  }
}
```

Or push from Admin UI → **Logs → Settings → IP anonymisation**.

Effect:
- IPv4: last octet zeroed → `192.168.1.123` becomes `192.168.1.0`
- IPv6: last 80 bits zeroed → prefix `/48` is kept
- Fail2Ban and Sentinel still receive the real IP before anonymisation — protection is not degraded

### Log retention

Configure in Admin UI → **Logs → Settings → Retention** or via API:

```http
PUT /api/v1/logs/settings
{
  "retention_access_days": 90,
  "retention_system_days": 30
}
```

| Setting | Default | GDPR recommendation |
|---|---|---|
| `retention_access_days` | 365 | ≤ 90 days (or 13 months max, CNIL) |
| `retention_system_days` | 90 | 90 days |
| Ban history | 730 days | Legitimate interest — adjust to policy |

Older entries are purged automatically every night.

### IP pseudonymisation (recommandé pour RGPD strict)

Mode plus fort que l'anonymisation : l'IP est **chiffrée** (AES-GCM 256 bits) en base SQLite côté Admin. Le fichier de log du Core reçoit toujours une IP tronquée. L'IP réelle ne peut être obtenue que par un utilisateur possédant le scope `gdpr:reveal` (voir §3 bis).

Activer via Admin UI → **Logs → Settings → Pseudonymisation IP** ou via API :

```http
PUT /api/v1/logs/settings
{ "ip_pseudonymize": true }
```

Ou dans `core.json` (non supporté — ce réglage est Admin-side).

| Comportement | Anonymisation | Pseudonymisation |
|---|---|---|
| IP dans fichier Core | tronquée (x.x.x.0) | tronquée (x.x.x.0) |
| IP dans SQLite Admin | tronquée | chiffrée AES-GCM |
| Taps Fail2Ban/Sentinel | IP réelle ✓ | IP réelle ✓ |
| Révélation possible ? | ❌ irréversible | ✓ avec scope `gdpr:reveal` |

La clé AES-GCM est générée automatiquement au premier démarrage et stockée dans la table `gdpr_keys` de la base Admin. Elle ne quitte jamais le serveur Admin.

---

### Right to erasure (Article 17) — delete by IP

```http
DELETE /api/v1/logs/by-ip/{ip}
```

Removes all access log entries matching the given IP. An audit entry is created with the reason.

CLI equivalent:

```bash
goproxify logs delete --by-ip 203.0.113.42 --reason "GDPR Art.17 request"
```

### Right to erasure — delete by user

```http
DELETE /api/v1/logs/by-user/{user_id}
```

Removes all log entries attributed to an authenticated user (JWT subject).

---

## 3 bis. Droit de révélation IP (scope `gdpr:reveal`)

Quand la pseudonymisation est active, les utilisateurs possédant le scope `gdpr:reveal` peuvent obtenir l'IP réelle d'une entrée spécifique, avec traçabilité complète.

### Qui peut avoir ce droit ?

| Rôle | `gdpr:reveal` par défaut | Délégable via équipe |
|---|---|---|
| Super-admin | ✓ | — |
| Admin | ❌ | ✓ (super-admin délègue) |
| Utilisateur (DPO, juriste, RSSI) | ❌ | ✓ (super-admin délègue) |

### Via API

```http
POST /api/v1/logs/reveal-ip
Content-Type: application/json
{
  "entry_id": 4821,
  "reason": "Réquisition judiciaire n°2026/1234"
}
```

Réponse :
```json
{
  "entry_id": 4821,
  "ip": "203.0.113.42",
  "requested_by": "dpo@example.com",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

### Via CLI

```bash
goproxify logs reveal-ip \
  --entry-id 4821 \
  --reason "Réquisition judiciaire n°2026/1234"
```

### Audit

Chaque révélation crée automatiquement une entrée dans le journal d'audit (`action = gdpr_reveal_ip`) avec l'acteur, l'ID de l'entrée et le motif. Un log système de niveau `warn` est également créé.

---

## 3. GeoIP (MaxMind GeoLite2)

The Core downloads **GeoLite2-Country** at startup (if `geoip.auto_download: true`). This database is:
- Stored locally on the Core volume (`/etc/goproxify/geoip/`)
- Never sent anywhere
- Used only for allow/block decisions and Prism dashboard enrichment (country of request)
- The IP itself is never sent to MaxMind at runtime

MaxMind's terms require attribution and accept that the database is used offline. No personal data is transmitted to MaxMind during normal operation.

To disable auto-download, set `geoip.auto_download: false` in `core.json` and supply your own database.

---

## 4. Third-party integrations (operator-configured)

These integrations are **opt-in** and configured by the operator. GoProxify sends data to them only when explicitly configured.

| Integration | Data sent | When |
|---|---|---|
| CrowdSec LAPI | Client IP (ban check) | On each request if bouncer enabled |
| Alert channels (email, Slack, ntfy…) | Event metadata (no client IP by default) | On alert trigger |
| ACME (Let's Encrypt) | Domain name only | On certificate issuance/renewal |
| DNS providers (OVH, Cloudflare…) | Domain/token for DNS-01 challenge | On certificate issuance/renewal |
| External auth providers (OIDC, SAML, LDAP) | Redirect URI, no credentials stored in GoProxify | On SSO flow |

---

## 5. Data processor checklist for operators

Before going to production, ensure:

- [ ] IP anonymisation enabled (`ip_anonymize: true`) if no legitimate need to store full IPs
- [ ] Log retention set to the shortest period that meets your legal obligations
- [ ] Admin user list reviewed — remove test accounts
- [ ] SSH portal vault entries reviewed — remove unused targets
- [ ] Alert channel configurations reviewed — confirm no personal data is included in alert payloads
- [ ] If using CrowdSec, check CrowdSec's own GDPR documentation
- [ ] Backup encryption enabled (`GPX_BACKUP_KEY`) if backups may contain personal data
- [ ] Privacy notice for end users updated to mention reverse proxy logging

---

## 6. Security measures protecting personal data

| Measure | Details |
|---|---|
| TLS in transit | All Admin↔Core↔browser communication is TLS — certificates in RAM only on Core |
| SSH vault encryption | AES-GCM, key never leaves Core |
| Admin authentication | JWT ECDSA P-256, bcrypt passwords, optional MFA (TOTP / WebAuthn) |
| Audit log | All admin operations are recorded with actor, timestamp, action |
| Role-based access | Teams + scopes limit who can read logs or security data |
| Backup encryption | AES-GCM via `GPX_BACKUP_KEY` |
