// Charge modérée plafonnée (50 VUs, ~1 min) : p95/p99 réalistes sans risque de saturer un Core partagé.
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  stages: [
    { duration: "10s", target: 50 },
    { duration: "40s", target: 50 },
    { duration: "10s", target: 0 },
  ],
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<100", "p(99)<300"] },
};

export default function () {
  const r = Math.random();
  if (r < 0.8) get("/");
  else if (r < 0.9) get("/echo");
  else get("/bytes?n=65536");
}

export const handleSummary = summary("moderate");
