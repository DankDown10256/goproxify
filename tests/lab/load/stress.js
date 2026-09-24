// Recherche du point de rupture : débit imposé (open model) croissant jusqu'à saturation.
// Le run s'arrête dès que >10 % d'erreurs (abortOnFail) : le dernier palier sain = capacité.
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: {
    breakpoint: {
      executor: "ramping-arrival-rate",
      startRate: 200,
      timeUnit: "1s",
      preAllocatedVUs: 500,
      maxVUs: 5000,
      stages: [
        { duration: "1m", target: 2000 },
        { duration: "1m", target: 5000 },
        { duration: "1m", target: 10000 },
        { duration: "1m", target: 20000 },
      ],
    },
  },
  thresholds: {
    http_req_failed: [{ threshold: "rate<0.10", abortOnFail: true, delayAbortEval: "20s" }],
  },
};

export default function () {
  get("/");
}

export const handleSummary = summary("stress");
