// Montée en charge progressive (équivalent docs/benchmark.md), sans latence backend.
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  stages: [
    { duration: "30s", target: 100 },
    { duration: "60s", target: 500 },
    { duration: "30s", target: 0 },
  ],
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<100", "p(99)<300"] },
};

export default function () {
  get("/");
}

export const handleSummary = summary("baseline");
