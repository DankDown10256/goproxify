import http from "k6/http";
import { check } from "k6";

export const HOST = __ENV.HOST || "lab-fast.lab.test";
export const BASE = `http://${HOST}`;

export function get(path, tags) {
  const res = http.get(`${BASE}${path}`, { tags });
  check(res, { "status 2xx": (r) => r.status >= 200 && r.status < 300 });
  return res;
}

export function summary(name) {
  return (data) => ({
    [`/results/${name}.json`]: JSON.stringify(data, null, 2),
    stdout: textSummary(data),
  });
}

function textSummary(d) {
  const m = d.metrics;
  const p = (k, q) => (m[k] && m[k].values[q] !== undefined ? m[k].values[q].toFixed(1) : "-");
  return [
    "",
    `requêtes   : ${m.http_reqs.values.count} (${m.http_reqs.values.rate.toFixed(0)}/s)`,
    `échecs     : ${(m.http_req_failed.values.rate * 100).toFixed(2)} %`,
    `latence ms : p50=${p("http_req_duration", "med")} p95=${p("http_req_duration", "p(95)")} p99=${p("http_req_duration", "p(99)")} max=${p("http_req_duration", "max")}`,
    "",
  ].join("\n");
}
