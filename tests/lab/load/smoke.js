import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  vus: 2,
  duration: "15s",
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<200"] },
};

export default function () {
  get("/");
  get("/echo");
}

export const handleSummary = summary("smoke");
