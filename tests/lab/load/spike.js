// Pic brutal : 20 -> 1000 VUs en 10 s, palier, retour. Vérifie l'absence d'effondrement et la reprise.
import { get, summary } from "./common.js";

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  stages: [
    { duration: "20s", target: 20 },
    { duration: "10s", target: 1000 },
    { duration: "60s", target: 1000 },
    { duration: "10s", target: 20 },
    { duration: "40s", target: 20 },
  ],
  thresholds: { http_req_failed: ["rate<0.02"] },
};

export default function () {
  get("/slow?ms=20");
}

export const handleSummary = summary("spike");
