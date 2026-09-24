// Charge modérée à DÉBIT IMPOSÉ (modèle ouvert) : RATE req/s (défaut 300) pendant DURATION (défaut 1m).
// Le débit est fixé sous le plafond du système : la latence mesurée est celle du service, pas d'une file d'attente.
// dropped_iterations > 0 signifie que le système n'a pas tenu le débit demandé.
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: {
    moderate: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 300),
      timeUnit: "1s",
      duration: __ENV.DURATION || "1m",
      preAllocatedVUs: 100,
      maxVUs: 400,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<100", "p(99)<300"],
    dropped_iterations: ["count==0"],
  },
};

export default function () {
  const r = Math.random();
  if (r < 0.8) get("/");
  else if (r < 0.9) get("/echo");
  else get("/bytes?n=65536");
}

export const handleSummary = summary("moderate");
