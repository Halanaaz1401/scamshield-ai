// ScamShield AI — Frontend API Client Foundation

import { API_BASE_URL } from "./constants";
import type {
  AnalysisRequest,
  AnalysisResponse,
  HealthResponse,
} from "@/types/analysis";

/**
 * Check backend health status (GET /health).
 */
export async function checkHealth(): Promise<HealthResponse> {
  const url = `${API_BASE_URL}/health`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    throw new Error(`Health check failed with HTTP status ${res.status}`);
  }

  return res.json();
}

/**
 * Submit untrusted message for threat analysis (POST /analyze).
 * Foundation stub wired to API endpoint.
 */
export async function analyzeContent(
  payload: AnalysisRequest
): Promise<AnalysisResponse> {
  const url = `${API_BASE_URL}/analyze`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData?.error?.message || `Analysis request failed with status ${res.status}`
    );
  }

  return res.json();
}
