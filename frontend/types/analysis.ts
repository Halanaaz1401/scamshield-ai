// ScamShield AI — Shared Analysis & Threat Contract Types

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "SAFE" | "SUSPICIOUS" | "MALICIOUS";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AnalysisRequest {
  message: string;
  content?: string;
  sourceType?: "sms" | "email" | "message" | "url" | "other";
}

export interface Indicator {
  id: string;
  findingId?: string;
  type?: string;
  source?: string;
  confidence?: "HIGH" | "MEDIUM" | "LOW";
  name: string;
  description: string;
  severity: Severity;
  evidence?: string;
  whyItMatters?: string;
  attackerObjective?: string;
  attackStage?: string;
}

export interface AttackStep {
  step: number;
  stage: string;
  description: string;
  findingId?: string;
  source?: string;
  evidence?: string;
}

export interface ThreatIntelligenceSummary {
  status: string;
  isKnownMalicious: boolean;
  threatTypes: string[];
  provider: string;
  details?: string;
}

export interface AIIntentResponse {
  scamCategory: string;
  attackerIntent: string;
  manipulationTactics: string[];
  requestedAction: string;
  urgencyLevel: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  explanation: string;
  potentialConsequence: string;
  recommendedAction: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  evidencePhrases: string[];
  aiAvailable: boolean;
  modelId?: string;
  errorMessage?: string;
}

export interface AnalysisResponse {
  analysisId: string;
  riskScore: number;
  riskLevel: RiskLevel;
  category?: string;
  indicators: Indicator[];
  reasoning: string;
  attackerIntent?: string;
  attackPath?: AttackStep[];
  recommendedAction: string;
  recommendedActions?: string[];
  confidence?: "HIGH" | "MEDIUM" | "LOW";
  falsePositiveChecks?: string[];
  verdict?: "KNOWN_MALICIOUS" | "HIGH_RISK" | "SUSPICIOUS" | "UNKNOWN_UNVERIFIED" | "LOW_RISK" | "BENIGN";
  demandedAction?: string;
  pressureLevel?: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  manipulationTactic?: string;
  manipulationTactics?: string[];
  potentialImpact?: string[];
  doActions?: string[];
  doNotActions?: string[];
  threatIntelligence?: ThreatIntelligenceSummary;
  aiIntent?: AIIntentResponse;
  timestamp: string;
}

export interface ValidationErrorDetail {
  field: string;
  reason: string;
}

export interface ValidationErrorResponse {
  error: {
    code: string;
    message: string;
    details: ValidationErrorDetail[];
  };
}

export interface HealthResponse {
  status: "ok";
}
