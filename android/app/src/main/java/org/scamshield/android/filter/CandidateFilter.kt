package org.scamshield.android.filter

import java.util.Locale

/**
 * Fast, deterministic local candidate filter.
 *
 * Purpose:
 * Decides whether an incoming notification warrants cybersecurity analysis by the
 * authoritative ScamShield backend, or should be discarded locally to save bandwidth
 * and preserve user privacy.
 *
 * Design:
 * - Extremely lightweight pattern matching.
 * - Prioritizes discarding obvious benign transactional notifications (e.g. debit alerts,
 *   routine received payments, and genuine bank OTP disclaimers).
 * - Flags suspicious social engineering signals: coercion, links, credential demands,
 *   disconnection threats, lottery lures, and KYC intimidation.
 */
object CandidateFilter {

    // Common Indian scam cue keywords and phrases (English & Hinglish)
    private val URGENCY_SIGNALS = listOf(
        "immediately", "tonight", "today", "within 24 hours", "urgent",
        "hurry", "expire", "expiring", "turant", "aaj raat", "jaldi"
    )

    private val ACCOUNT_SUSPENSION_SIGNALS = listOf(
        "blocked today", "account will be blocked", "account is suspended",
        "account suspended", "temporarily blocked", "block ho jayega",
        "kyc expire", "complete kyc", "update kyc", "update aadhaar",
        "pan blocked", "sim deactivation", "service disconnected"
    )

    private val UTILITY_DISCONNECT_SIGNALS = listOf(
        "electricity connection", "power connection", "bijli connection",
        "will be disconnected", "cut ho jayega", "lpg subsidy", "gas subsidy"
    )

    private val REWARD_LOTTERY_JOB_SIGNALS = listOf(
        "won ₹", "won rs", "won usd", "won $", "claim your prize",
        "lottery", "processing fee", "bhejo", "jeet gaye", "lucky draw",
        "work from home", "earn ₹", "earn rs", "part time job"
    )

    private val THREAT_POLICE_CUSTOMS_SIGNALS = listOf(
        "cyber cell", "police notice", "illegal activity", "parcel is held",
        "customs charge", "arrest warrant", "customs clearance", "narcotics"
    )

    private val CREDENTIAL_THEFT_SIGNALS = listOf(
        "verify your pin", "share otp", "send otp", "tell otp", "provide otp",
        "enter pin", "share password", "verify pin", "upi pin"
    )

    private val SUSPICIOUS_CALL_SIGNALS = listOf(
        "call immediately", "call on this number", "contact manager",
        "contact customer care on", "call now"
    )

    /**
     * Determines whether the notification text qualifies as a candidate for backend analysis.
     *
     * @param text The normalized notification text.
     * @param urls The list of URLs detected in the notification.
     * @return true if candidate for backend threat analysis, false if safely discarded locally.
     */
    fun isCandidate(text: String?, urls: List<String>): Boolean {
        if (text.isNullOrBlank()) return false
        val lower = text.lowercase(Locale.ROOT)

        // 1. If any URL is present in the notification, it is always a candidate for link/threat analysis
        if (urls.isNotEmpty()) {
            return true
        }

        // 2. Check for benign transactional patterns that should NOT trigger analysis
        if (isBenignTransactional(lower)) {
            return false
        }

        // 3. Social engineering & coercion cues:

        // Credential / PIN / OTP harvesting
        if (CREDENTIAL_THEFT_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Account suspension / KYC pressure
        if (ACCOUNT_SUSPENSION_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Utility disconnection extortion (e.g. Bijli/Electricity scam)
        if (UTILITY_DISCONNECT_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Lottery, prize, or work-from-home fee lures
        if (REWARD_LOTTERY_JOB_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Police / Customs / Cyber crime intimidation
        if (THREAT_POLICE_CUSTOMS_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Suspicious call-back coercions
        if (SUSPICIOUS_CALL_SIGNALS.any { lower.contains(it) }) {
            return true
        }

        // Payment demand coupled with urgency (e.g. "Pay ₹10 immediately" or "payment karo")
        val hasPaymentLure = lower.contains("pay ₹") || lower.contains("pay rs") ||
                lower.contains("payment of ₹") || lower.contains("payment karo") ||
                lower.contains("processing fee")
        val hasUrgency = URGENCY_SIGNALS.any { lower.contains(it) }

        if (hasPaymentLure && hasUrgency) {
            return true
        }

        return false
    }

    /**
     * Identifies legitimate informational alerts, such as genuine bank transaction SMS
     * or standard bank OTP delivery messages that advise the user NOT to share their OTP.
     */
    private fun isBenignTransactional(lower: String): Boolean {
        // Legitimate OTP delivery: Bank sends OTP and explicitly instructs "do not share"
        val hasOtpMention = lower.contains("otp") || lower.contains("one time password")
        val hasDoNotShareWarning = lower.contains("do not share") || lower.contains("never share") ||
                lower.contains("not to share") || lower.contains("kisi ke sath share na kare")
        val isAskingToShare = lower.contains("share otp") || lower.contains("send otp") ||
                lower.contains("enter otp") || lower.contains("verify otp")

        if (hasOtpMention && hasDoNotShareWarning && !isAskingToShare) {
            return true
        }

        // Routine bank debit/credit confirmation
        val isBankDebitOrCredit = (lower.contains("debited") || lower.contains("credited") ||
                lower.contains("received successfully") || lower.contains("sent successfully")) &&
                (lower.contains("account") || lower.contains("a/c") || lower.contains("vpa") || lower.contains("bank"))

        val hasSuspensionThreat = lower.contains("block") || lower.contains("suspend") ||
                lower.contains("kyc") || lower.contains("expire") || lower.contains("penalty")

        if (isBankDebitOrCredit && !hasSuspensionThreat) {
            return true
        }

        return false
    }
}
