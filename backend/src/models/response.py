"""Response data models and nested threat structures for ScamShield AI."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RiskLevel(str, Enum):
    """Categorical threat risk rating."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    """Indicator severity ranking."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScamCategory(str, Enum):
    """Authoritative taxonomy of threat categories."""

    BANKING_SCAM = "BANKING_SCAM"
    PAYMENT_SCAM = "PAYMENT_SCAM"
    PHISHING = "PHISHING"
    JOB_SCAM = "JOB_SCAM"
    INVESTMENT_SCAM = "INVESTMENT_SCAM"
    LOTTERY_REWARD_SCAM = "LOTTERY_REWARD_SCAM"
    GOVERNMENT_IMPERSONATION = "GOVERNMENT_IMPERSONATION"
    ACCOUNT_KYC_SCAM = "ACCOUNT_KYC_SCAM"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    ELECTRICITY_SCAM = "ELECTRICITY_SCAM"
    COURIER_SCAM = "COURIER_SCAM"
    SIM_DEACTIVATION_SCAM = "SIM_DEACTIVATION_SCAM"
    CUSTOMER_SUPPORT_SCAM = "CUSTOMER_SUPPORT_SCAM"
    OTHER_SUSPICIOUS = "OTHER_SUSPICIOUS"
    BENIGN = "BENIGN"


class Indicator(BaseModel):
    """Specific technical or psychological red flag identified in the message."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Unique slug or rule identifier for the indicator.")
    finding_id: Optional[str] = Field(
        default=None,
        alias="findingId",
        description="Canonical unique forensic finding identifier (e.g. URGENCY_001, SHORTENER_001).",
    )
    type: Optional[str] = Field(
        default=None,
        description="Categorical finding type (e.g. artificial_deadline, destination_obfuscation, otp_solicitation).",
    )
    source: Optional[str] = Field(
        default="deterministic_heuristic",
        description="Originating detection layer: deterministic_heuristic, threat_intelligence, semantic_analysis.",
    )
    confidence: Optional[str] = Field(
        default="HIGH",
        description="Finding-level confidence rating: HIGH, MEDIUM, LOW.",
    )
    name: str = Field(..., description="Human-readable title of the indicator.")
    description: str = Field(..., description="Contextual explanation of why this is suspicious.")
    severity: Severity = Field(..., description="Severity classification of the indicator.")
    evidence: Optional[str] = Field(
        default=None,
        description="Snippet or extracted cue demonstrating the indicator.",
    )
    why_it_matters: Optional[str] = Field(
        default=None,
        alias="whyItMatters",
        description="Contextual security rationale for why this signal represents an exploitation risk.",
    )
    attacker_objective: Optional[str] = Field(
        default=None,
        alias="attackerObjective",
        description="Tactical goal the attacker is attempting to achieve at this step.",
    )
    attack_stage: Optional[str] = Field(
        default=None,
        alias="attackStage",
        description="Kill chain stage (e.g. Inbound Lure, Urgency Coercion, Credential Theft).",
    )

    @model_validator(mode="after")
    def sync_finding_id(self) -> "Indicator":
        if not self.finding_id:
            self.finding_id = self.id
        return self


# Alias Indicator as RedFlag for dual nomenclature
RedFlag = Indicator


class AttackStep(BaseModel):
    """Single stage in the social engineering attack path / scam DNA."""

    model_config = ConfigDict(populate_by_name=True)

    step: int = Field(..., description="Sequential step index in attack chain.")
    stage: str = Field(..., description="Name of the attack stage.")
    description: str = Field(..., description="Operational detail of the attacker's tactic.")
    finding_id: Optional[str] = Field(
        default=None,
        alias="findingId",
        description="Referenced finding ID that supports and grounds this attack stage.",
    )
    source: Optional[str] = Field(
        default=None,
        description="Originating evidence source supporting this stage.",
    )
    evidence: Optional[str] = Field(
        default=None,
        description="Extracted textual or technical proof for this stage.",
    )


class AIIntentResponse(BaseModel):
    """Structured AI intent reasoning payload for plain-language explanation."""

    model_config = ConfigDict(populate_by_name=True)

    scam_category: str = Field(..., alias="scamCategory")
    attacker_intent: str = Field(..., alias="attackerIntent")
    manipulation_tactics: List[str] = Field(default_factory=list, alias="manipulationTactics")
    requested_action: str = Field(..., alias="requestedAction")
    urgency_level: str = Field(..., alias="urgencyLevel")
    explanation: str = Field(..., alias="explanation")
    potential_consequence: str = Field(..., alias="potentialConsequence")
    recommended_action: str = Field(..., alias="recommendedAction")
    confidence: str = Field(default="MEDIUM", alias="confidence")
    evidence_phrases: List[str] = Field(default_factory=list, alias="evidencePhrases")
    ai_available: bool = Field(default=True, alias="aiAvailable")
    model_id: Optional[str] = Field(default=None, alias="modelId")
    error_message: Optional[str] = Field(default=None, alias="errorMessage")


class AnalysisResponse(BaseModel):
    """Complete, structured threat assessment response contract."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    analysis_id: str = Field(
        default_factory=lambda: str(uuid4()),
        alias="analysisId",
        description="Unique evaluation identifier.",
    )
    risk_score: float = Field(
        ...,
        alias="riskScore",
        ge=0.0,
        le=100.0,
        description="Calibrated threat score between 0.0 (safest) and 100.0 (maximum threat).",
    )
    risk_level: RiskLevel = Field(
        ...,
        alias="riskLevel",
        description="Categorical threat risk band (LOW, MEDIUM, HIGH, CRITICAL).",
    )
    scam_category: str = Field(
        default=ScamCategory.OTHER_SUSPICIOUS.value,
        alias="category",
        description="Primary scam category classification.",
    )
    summary: str = Field(
        ...,
        alias="reasoning",
        description="Human-readable summary explanation of why the message was flagged or cleared.",
    )
    red_flags: List[Indicator] = Field(
        default_factory=list,
        alias="indicators",
        description="List of detected red flags and security indicators.",
    )
    attacker_intent: Optional[str] = Field(
        default=None,
        alias="attackerIntent",
        description="Analyzed attacker motivation or intended consequence.",
    )
    attack_path: List[AttackStep] = Field(
        default_factory=list,
        alias="attackPath",
        description="Step-by-step scam DNA / kill chain reconstructing the attacker's methodology.",
    )
    recommended_action: str = Field(
        ...,
        alias="recommendedAction",
        description="Primary protective directive for the user.",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        alias="recommendedActions",
        description="Prioritized list of recommended safety responses.",
    )
    confidence: str = Field(
        default="HIGH",
        description="Confidence classification: HIGH, MEDIUM, or LOW.",
    )
    false_positive_checks: Optional[List[str]] = Field(
        default=None,
        alias="falsePositiveChecks",
        description="Checklist of verified negative indicators for benign/low-risk messages.",
    )
    verdict: Optional[str] = Field(
        default=None,
        description="Calibrated threat verdict: KNOWN_MALICIOUS, HIGH_RISK, SUSPICIOUS, UNKNOWN_UNVERIFIED, LOW_RISK, BENIGN.",
    )
    demanded_action: str = Field(
        default="No Direct Action Demanded",
        alias="demandedAction",
        description="Explicit or inferred demanded action.",
    )
    pressure_level: str = Field(
        default="NONE",
        alias="pressureLevel",
        description="Calibrated psychological pressure rating (HIGH, MEDIUM, LOW, NONE).",
    )
    manipulation_tactic: str = Field(
        default="None",
        alias="manipulationTactic",
        description="Primary detected manipulation tactic.",
    )
    manipulation_tactics: List[str] = Field(
        default_factory=list,
        alias="manipulationTactics",
        description="All detected manipulation tactics.",
    )
    potential_impact: List[str] = Field(
        default_factory=list,
        alias="potentialImpact",
        description="Evidence-grounded potential consequences if the user complies.",
    )
    do_actions: List[str] = Field(
        default_factory=list,
        alias="doActions",
        description="Authoritative actions the user should take.",
    )
    do_not_actions: List[str] = Field(
        default_factory=list,
        alias="doNotActions",
        description="Authoritative actions the user must avoid.",
    )
    threat_intelligence: Optional[dict] = Field(
        default=None,
        alias="threatIntelligence",
        description="Summary metadata from external threat intelligence feeds (e.g. Google Web Risk).",
    )
    ai_intent: Optional[AIIntentResponse] = Field(
        default=None,
        alias="aiIntent",
        description="Structured AI intent reasoning, psychological manipulation, and plain-language explanation.",
    )
    status: str = Field(
        default="received",
        description="Pipeline processing status indicator.",
    )
    length: Optional[int] = Field(
        default=None,
        description="Character count of evaluated message.",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp of analysis completion.",
    )

    # Convenience properties for dual nomenclature
    @property
    def category(self) -> str:
        return self.scam_category

    @property
    def reasoning(self) -> str:
        return self.summary

    @property
    def indicators(self) -> List[Indicator]:
        return self.red_flags

    @property
    def scam_dna(self) -> List[AttackStep]:
        return self.attack_path

    @model_validator(mode="before")
    @classmethod
    def reconcile_aliases(cls, data: Any) -> Any:
        """Reconcile dual nomenclature between PRD, architecture, and frontend types."""
        if isinstance(data, dict):
            data = dict(data)
            # Map legacy SAFE / SUSPICIOUS / MALICIOUS to LOW / MEDIUM / HIGH / CRITICAL
            level = data.get("riskLevel") or data.get("risk_level")
            if level == "SAFE":
                data["riskLevel"] = "LOW"
            elif level == "SUSPICIOUS":
                data["riskLevel"] = "MEDIUM"
            elif level == "MALICIOUS":
                data["riskLevel"] = "HIGH"

            # Reconcile summary / reasoning / explanation
            summary = data.get("summary") or data.get("reasoning") or data.get("explanation")
            if summary:
                data["summary"] = summary
                data["reasoning"] = summary

            # Reconcile category / scamCategory / scam_category
            cat = data.get("scamCategory") or data.get("scam_category") or data.get("category")
            if cat:
                data["category"] = cat

            # Reconcile red_flags / indicators
            flags = data.get("red_flags") or data.get("redFlags") or data.get("indicators")
            if flags is not None:
                data["indicators"] = flags

            # Reconcile attack_path / scam_dna / attackPath
            path = data.get("attack_path") or data.get("attackPath") or data.get("scam_dna")
            if path is not None:
                data["attackPath"] = path

            # Reconcile recommendedAction vs recommendedActions
            rec_action = data.get("recommendedAction") or data.get("recommended_action")
            rec_actions = data.get("recommendedActions") or data.get("recommended_actions")
            if not rec_action and rec_actions and len(rec_actions) > 0:
                data["recommendedAction"] = rec_actions[0]
            elif rec_action and not rec_actions:
                data["recommendedActions"] = [rec_action]

        return data

    @field_validator("risk_score", mode="after")
    @classmethod
    def round_score(cls, value: float) -> float:
        """Round risk score to 1 decimal place."""
        return round(value, 1)