package org.scamshield.android.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import org.scamshield.android.service.ScamNotificationListenerService

/**
 * Utility helper for managing Android NotificationListenerService permission checks
 * and navigation to the official system notification access settings.
 */
object PermissionHelper {

    /**
     * Determine whether notification access is explicitly granted to ScamShield.
     *
     * Validates via NotificationManagerCompat and cross-checks the system
     * enabled_notification_listeners registry for maximum reliability across OEM ROMs.
     */
    fun isNotificationAccessGranted(context: Context): Boolean {
        val packageName = context.packageName

        // Primary check: NotificationManagerCompat
        val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
        if (enabledPackages.contains(packageName)) {
            return true
        }

        // Secondary fallback check: Settings.Secure query
        val flat = Settings.Secure.getString(
            context.contentResolver,
            "enabled_notification_listeners"
        )
        if (!flat.isNullOrBlank()) {
            val component = ComponentName(context, ScamNotificationListenerService::class.java)
            val flattenedComponent = component.flattenToString()
            val flattenedShortComponent = component.flattenToShortString()
            if (flat.contains(flattenedComponent) || flat.contains(flattenedShortComponent) || flat.contains(packageName)) {
                return true
            }
        }

        return false
    }

    /**
     * Create an Intent directing the user to Android's official Notification Access settings.
     */
    fun createNotificationSettingsIntent(): Intent {
        return Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
}
