package org.scamshield.android.model

/**
 * Enumeration of explicitly authorized notification sources for ScamShield.
 * Any notification from an unlisted package is strictly ignored.
 */
enum class NotificationSource(val displayName: String) {
    WHATSAPP("WhatsApp"),
    SMS("Messages/SMS")
}
