package org.scamshield.android.service

import org.scamshield.android.model.NotificationSource

/**
 * Filter responsible for identifying authorized notification sources.
 *
 * Scopes inspection strictly to WhatsApp and SMS/Messages notifications.
 * All other applications (social media, games, email, etc.) are strictly ignored.
 */
object SourceFilter {

    /** Package names associated with official WhatsApp client variants */
    val WHATSAPP_PACKAGES: Set<String> = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b" // WhatsApp Business
    )

    /** Standard SMS/MMS packages across major Android OEM distributions */
    val DEFAULT_SMS_PACKAGES: Set<String> = setOf(
        "com.google.android.apps.messaging", // Google Messages
        "com.samsung.android.messaging",    // Samsung Messages
        "com.android.mms",                  // AOSP / Standard OEM Messages
        "com.oneplus.mms",                  // OnePlus OxygenOS Messages
        "com.xiaomi.mms",                   // Xiaomi / MIUI Messages
        "com.oppo.mms"                      // Oppo / Realme ColorOS Messages
    )

    /**
     * Resolve the NotificationSource for a given package name.
     *
     * @param packageName The package name from the StatusBarNotification
     * @param dynamicDefaultSmsPackage The system default SMS package if resolved via Telephony
     * @return NotificationSource if recognized and authorized; null if ignored
     */
    fun resolveSource(
        packageName: String?,
        dynamicDefaultSmsPackage: String? = null
    ): NotificationSource? {
        if (packageName.isNullOrBlank()) return null

        val cleanPackage = packageName.trim()

        if (cleanPackage in WHATSAPP_PACKAGES) {
            return NotificationSource.WHATSAPP
        }

        if (cleanPackage in DEFAULT_SMS_PACKAGES ||
            (!dynamicDefaultSmsPackage.isNullOrBlank() && cleanPackage == dynamicDefaultSmsPackage.trim())
        ) {
            return NotificationSource.SMS
        }

        // Unknown / unauthorized sources are strictly ignored
        return null
    }

    /**
     * Check if a package is authorized for notification inspection.
     */
    fun isAllowed(packageName: String?, dynamicDefaultSmsPackage: String? = null): Boolean {
        return resolveSource(packageName, dynamicDefaultSmsPackage) != null
    }
}
