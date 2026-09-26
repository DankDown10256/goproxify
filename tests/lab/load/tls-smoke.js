// Smoke HTTPS : 2 VUs, 15 s sur lab-tls.lab.test en HTTPS (cert auto-signé accepté).
// Vérifie que la passerelle répond correctement en TLS sans erreur.
import http from "k6/http";
import { check } from "k6";
import { summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  vus: 2,
  duration: "15s",
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<500"] },
  tlsConfig: { insecureSkipVerify: true },
};

const HOST = __ENV.HOST || "lab-tls.lab.test";
const BASE = `https://${HOST}`;

export default function () {
  const res = http.get(`${BASE}/`);
  check(res, { "status 200": (r) => r.status === 200 });
}

export const handleSummary = summary("tls-smoke");
