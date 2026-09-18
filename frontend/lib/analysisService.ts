/**
 * ScamShield AI — Threat Analysis Service
 *
 * Real end-to-end integration connecting UI to the ScamShield analysis API:
 * Next.js Frontend -> API Gateway / Route -> Lambda -> Validation -> Detection -> Bedrock -> Risk Fusion -> DynamoDB.
 */

import { analyzeContent } from "./api";
import type { AnalysisResponse } from "@/types/analysis";

/**
 * Main analysis function invoked by UI components.
 * Submits untrusted communication payload to the production analysis API.
 */
export async function analyzeMessage(
  content: string,
  sourceType: string = "message"
): Promise<AnalysisResponse> {
  const validSources = ["sms", "email", "message", "url", "other"] as const;
  type ValidSource = typeof validSources[number];
  const isKnownSource = (s: string): s is ValidSource =>
    (validSources as readonly string[]).includes(s);
  const normalizedSource: ValidSource = isKnownSource(sourceType)
    ? sourceType
    : "message";

  return await analyzeContent({
    message: content,
    sourceType: normalizedSource,
  });
}
