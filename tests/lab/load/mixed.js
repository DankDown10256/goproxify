// Trafic réaliste : petites/grosses réponses, backend lent, backend instable, uploads, SSE.
import http from "k6/http";
import { check } from "k6";
import { BASE, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  stages: [
    { duration: "30s", target: 100 },
    { duration: "2m", target: 300 },
    { duration: "30s", target: 0 },
  ],
  thresholds: {
    "http_req_failed{kind:ok}": ["rate<0.01"],
    "http_req_duration{kind:ok}": ["p(95)<400"],
  },
};

const payload = "y".repeat(256 * 1024);

export default function () {
  const r = Math.random();
  let res;
  if (r < 0.5) res = http.get(`${BASE}/`, { tags: { kind: "ok" } });
  else if (r < 0.65) res = http.get(`${BASE}/bytes?n=1048576`, { tags: { kind: "ok" } });
  else if (r < 0.75) res = http.get(`${BASE}/slow?ms=300`, { tags: { kind: "ok" } });
  else if (r < 0.85) res = http.get(`${BASE}/flaky?p=30`, { tags: { kind: "flaky" } });
  else if (r < 0.95) res = http.post(`${BASE}/upload`, payload, { tags: { kind: "ok" } });
  else res = http.get(`${BASE}/sse?n=5&ms=100`, { tags: { kind: "ok" } });
  check(res, { "reponse recue": (x) => x.status > 0 });
}

export const handleSummary = summary("mixed");
