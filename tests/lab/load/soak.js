// Endurance : charge modérée constante (DURATION, défaut 30m). Surveiller RSS / goroutines / FD du Core
// pendant le run (lab.sh soak lance aussi la collecte docker stats).
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: {
    soak: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 300),
      timeUnit: "1s",
      duration: __ENV.DURATION || "30m",
      preAllocatedVUs: 200,
      maxVUs: 1000,
    },
  },
  thresholds: { http_req_failed: ["rate<0.005"], http_req_duration: ["p(99)<500"] },
};

export default function () {
  const r = Math.random();
  if (r < 0.7) get("/");
  else if (r < 0.85) get("/echo");
  else if (r < 0.95) get("/bytes?n=65536");
  else get("/slow?ms=200");
}

export const handleSummary = summary("soak");
