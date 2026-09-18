package org.scamshield.android.model

/**
 * Privacy-safe internal result model holding the outcome of a threat analysis.
 *
 * CRITICAL PRIVACY REQUIREMENT:
 * - Does NOT store original notification text.
 * - Does NOT store raw AI prompt or raw backend payload.
 * - Only retains structured cybersecurity classifications needed for protection.
 */
data class AnalysisResult(
    val analysisId: String,
    val riskScore: Double,
    val riskLevel: String, // LOW, MEDIUM, HIGH, CRITICAL
    val scamCategory: String,
    val summary: String,
    val indicators: List<IndicatorItem> = emptyList(),
    val attackerIntent: String? = null,
    val attackPath: List<AttackStepItem> = emptyList(),
    val recommendedActions: List<String> = emptyList(),
    val aiAvailable: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

data class IndicatorItem(
    val id: String,
    val name: String,
    val description: String,
    val severity: String,
    val evidence: String? = null
)

data class AttackStepItem(
    val step: Int,
    val stage: String,
    val description: String
)
