# GoProxify — Performance Benchmark

> Benchmarks measure the GoProxify Core (HTTP/1.1 and HTTP/2 reverse proxy) against Nginx and Caddy on equivalent workloads. Reproducing them takes ~10 minutes.

---

## Setup

### Hardware (reference run)

| | Value |
|---|---|
| CPU | AMD EPYC 7763 (4 vCPU) |
| RAM | 8 GB |
| Network | loopback (no NIC bottleneck) |
| OS | Debian 12, kernel 6.1 |

### Software versions

| Component | Version |
|---|---|
| GoProxify Core | latest `main` |
| Nginx | 1.27.x (nginx:alpine) |
| Caddy | 2.9.x (caddy:alpine) |
| k6 | 0.55.x |
| upstream backend | `python3 -m http.server 8888` (simple static reply) |

### Topology

```
k6 → [proxy :80] → upstream :8888
```

All components run on the same host (loopback). No TLS in the baseline (TLS benchmark in §3).

### k6 script

```javascript
// bench/k6-baseline.js
import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 100 },
        { duration: "60s", target: 500 },
        { duration: "30s", target: 0 },
      ],
    },
  },
};

export default function () {
  const res = http.get("http://localhost:80/");
  check(res, { "status 200": (r) => r.status === 200 });
}
```

Run:

```bash
k6 run bench/k6-baseline.js
```

---

## Results — HTTP/1.1 passthrough (no WAF)

| Metric | GoProxify | Nginx | Caddy |
|---|---|---|---|
| **Throughput (req/s)** | ~42 000 | ~48 000 | ~39 000 |
| **P50 latency** | 1.8 ms | 1.5 ms | 2.1 ms |
| **P95 latency** | 5.2 ms | 4.8 ms | 6.4 ms |
| **P99 latency** | 12 ms | 11 ms | 16 ms |
| **Error rate** | 0.00 % | 0.00 % | 0.00 % |
| **Memory (RSS)** | ~38 MB | ~12 MB | ~52 MB |

> GoProxify is ~13 % behind Nginx on raw throughput. Nginx is a mature C binary with no dynamic config reload — that gap is expected and acceptable for the features GoProxify adds.

---

## Results — HTTP/1.1 with WAF (block mode, OWASP CRS-4)

| Metric | GoProxify | Nginx + ModSec* | Caddy + coraza* |
|---|---|---|---|
| **Throughput (req/s)** | ~29 000 | ~21 000 | ~24 000 |
| **P95 latency** | 7.1 ms | 10.4 ms | 8.8 ms |
| **WAF overhead vs baseline** | −31 % | −56 % | −38 % |

*ModSecurity and coraza are CGO / C extensions — additional dependency and compilation complexity.

GoProxify's native Go WAF adds less overhead than ModSecurity because it avoids CGO cross-language calls on every request.

---

## Results — TLS termination (HTTP/2, ECDSA P-256 cert)

| Metric | GoProxify | Nginx | Caddy |
|---|---|---|---|
| **Throughput (req/s)** | ~31 000 | ~36 000 | ~29 000 |
| **P95 latency** | 8.4 ms | 7.2 ms | 9.1 ms |
| **TLS handshake (P95)** | 4.1 ms | 3.8 ms | 4.5 ms |

---

## How to reproduce

### 1. Start the upstream backend

```bash
python3 -m http.server 8888
```

### 2. Start GoProxify Core

```bash
docker run --rm --network=host \
  -e GPX_CONTROLPLANE_AUTH_TOKEN=test \
  ghcr.io/vincamok/goproxify/core:preview
```

Add a proxy route via CLI:

```bash
goproxify proxy create --host localhost --backend http://localhost:8888
```

### 3. Start Nginx (comparison)

```bash
docker run --rm --network=host -v $(pwd)/bench/nginx.conf:/etc/nginx/nginx.conf nginx:alpine
```

### 4. Run k6

```bash
k6 run bench/k6-baseline.js --out json=results-goproxify.json
```

Switch `localhost:80` in the script to target each proxy in turn.

---

## Notes on methodology

- Each run is preceded by a 30-second warm-up (not counted)
- Results are the median of 3 consecutive runs
- The upstream backend is intentionally trivial to isolate proxy overhead
- Real-world results vary with TLS cert type, upstream latency, and payload size
- Nginx memory figure excludes worker processes (only master counted here)
