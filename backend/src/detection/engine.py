"""Core deterministic threat detection engine for ScamShield AI."""

from dataclasses import dataclass, field
from typing import List, Optional, Set

from backend.src.detection.categories import resolve_primary_category
from backend.src.detection.indicators import extract_threat_indicators
from backend.src.models.response import Indicator, ScamCategory, Severity

# Indicator severity weight values for preliminary deterministic aggregation
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 5.0,
}


@dataclass(frozen=True)
class DeterministicAnalysis:
    """Structured result produced exclusively by the deterministic detection engine.

    Note: The deterministic_score represents the weighted rule score for Phase 3 aggregation.
    Final user-facing threat scoring and risk fusion will be determined in Phase 5.
    """

    indicators: List[Indicator]
    primary_category: ScamCategory
    deterministic_score: float
    is_benign: bool
    signal_count: int
    matched_rule_ids: List[str]
    explanation: str


def compute_deterministic_score(indicators: List[Indicator]) -> float:
    """Compute an aggregated deterministic threat score (0.0 - 100.0) based on signal weights."""
    if not indicators:
        return 0.0

    raw_score = sum(SEVERITY_WEIGHTS.get(ind.severity, 10.0) for ind in indicators)

    # Multi-signal reinforcement bonus: attackers combining multiple vectors (e.g. urgency + link + threat)
    if len(indicators) >= 3:
        raw_score += 10.0

    # Ensure score stays bounded between 0.0 and 100.0
    return min(100.0, max(0.0, round(raw_score, 1)))


def build_deterministic_summary(category: ScamCategory, indicators: List[Indicator]) -> str:
    """Build a concise, evidence-based explanation of deterministic findings."""
    if not indicators:
        return "No known deterministic scam or phishing indicators were identified in the message."

    indicator_names = [ind.name for ind in indicators[:3]]
    names_str = ", ".join(indicator_names)

    return (
        f"Deterministic engine flagged {len(indicators)} security signal(s) "
        f"consistent with {category.value}: {names_str}."
    )


def detect_threat_signals(
    message: str,
    source_type: Optional[str] = None,
) -> DeterministicAnalysis:
    """Inspect untrusted message content and produce structured deterministic threat signals.

    This function is 100% deterministic, stateless, and safe:
    - Treats all input as untrusted data
    - Never evaluates instructions or prompt injection payloads
    - Produces stable, reproducible results for the same input
    """
    # Guard against null/empty input
    clean_text = (message or "").strip()
    if not clean_text:
        return DeterministicAnalysis(
            indicators=[],
            primary_category=ScamCategory.BENIGN,
            deterministic_score=0.0,
            is_benign=True,
            signal_count=0,
            matched_rule_ids=[],
            explanation="Empty input contains no threat signals.",
        )

    # 1. Extract indicators using deterministic regex and heuristic rules
    indicators = extract_threat_indicators(clean_text)

    # 2. Collect unique matched rule IDs
    matched_rule_ids = [ind.id for ind in indicators]
    if any(ind.id.startswith("IND_URL_") or ind.id == "IND_SUSPICIOUS_URL" for ind in indicators):
        if "IND_SUSPICIOUS_URL" not in matched_rule_ids:
            matched_rule_ids.append("IND_SUSPICIOUS_URL")
    signal_id_set: Set[str] = set(matched_rule_ids)

    # 3. Resolve authoritative primary category
    primary_category = resolve_primary_category(signal_id_set, clean_text.lower())

    # 4. Compute preliminary deterministic score
    det_score = compute_deterministic_score(indicators)

    # 5. Build summary
    explanation = build_deterministic_summary(primary_category, indicators)

    return DeterministicAnalysis(
        indicators=indicators,
        primary_category=primary_category,
        deterministic_score=det_score,
        is_benign=len(indicators) == 0 or all(ind.id == "IND_URGENT_LANGUAGE" for ind in indicators),
        signal_count=len(indicators),
        matched_rule_ids=matched_rule_ids,
        explanation=explanation,
    )