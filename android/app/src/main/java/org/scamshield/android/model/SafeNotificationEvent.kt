package org.scamshield.android.model

/**
 * Safe minimal metadata representation for proof of notification receipt.
 *
 * STRICT PRIVACY GUARANTEE:
 * - NO raw message text, title, or body is retained.
 * - NO sender identity, phone number, or contact information is stored.
 * - NO passwords, OTPs, PINs, or financial data are inspected or persisted.
 * - This event exists strictly in volatile device memory for local status visibility.
 * - Zero network transmission or cloud persistence.
 */
data class SafeNotificationEvent(
    val source: NotificationSource,
    val packageName: String,
    val timestampMillis: Long,
    val hasContent: Boolean
)
