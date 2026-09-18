package org.scamshield.android.extractor

import android.app.Notification
import android.os.Bundle
import android.service.notification.StatusBarNotification

/**
 * Safely extracts and normalizes textual content from authorized notifications.
 *
 * Privacy & Safety Guarantees:
 * - Uses only the standard notification extras legitimately exposed by Android.
 * - Never scrapes proprietary app storage or databases.
 * - Never throws runtime exceptions on null or unexpected bundle object types.
 */
object NotificationExtractor {

    /**
     * Extracts normalized textual content from a notification.
     * Returns null if no actionable text is present.
     */
    fun extractText(sbn: StatusBarNotification?): String? {
        if (sbn == null) return null
        val notification = sbn.notification ?: return null

        // Ignore ongoing / non-clearable foreground services
        if ((notification.flags and Notification.FLAG_ONGOING_EVENT) != 0) {
            return null
        }

        // Ignore summary headers of notification groups that contain no actual message body
        if ((notification.flags and Notification.FLAG_GROUP_SUMMARY) != 0) {
            val text = extractFromExtras(notification.extras)
            return if (text.isNullOrBlank()) null else text
        }

        return extractFromExtras(notification.extras)
    }

    /**
     * Extracts text from the notification bundle extras safely.
     */
    fun extractFromExtras(extras: Bundle?): String? {
        if (extras == null) return null

        val parts = mutableListOf<String>()

        try {
            // 1. Title (e.g. sender name or sender bank short-code)
            val title = safeCharSequenceToString(extras.getCharSequence(Notification.EXTRA_TITLE))
            if (!title.isNullOrBlank()) {
                parts.add(title)
            }

            // 2. Big text (expanded notification body) or regular text
            val bigText = safeCharSequenceToString(extras.getCharSequence(Notification.EXTRA_BIG_TEXT))
            if (!bigText.isNullOrBlank()) {
                parts.add(bigText)
            } else {
                val text = safeCharSequenceToString(extras.getCharSequence(Notification.EXTRA_TEXT))
                if (!text.isNullOrBlank()) {
                    parts.add(text)
                }
            }

            // 3. Multi-line notifications (e.g., InboxStyle or multiple messaging lines)
            val textLines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
            if (textLines != null && textLines.isNotEmpty()) {
                val combinedLines = textLines
                    .mapNotNull { safeCharSequenceToString(it) }
                    .filter { it.isNotBlank() }
                    .joinToString("\n")
                if (combinedLines.isNotBlank() && !parts.contains(combinedLines)) {
                    parts.add(combinedLines)
                }
            }

            // 4. SubText if distinct
            val subText = safeCharSequenceToString(extras.getCharSequence(Notification.EXTRA_SUB_TEXT))
            if (!subText.isNullOrBlank() && !parts.contains(subText)) {
                parts.add(subText)
            }
        } catch (_: Exception) {
            // Never crash on malformed bundle contents or custom parcelables
            return null
        }

        if (parts.isEmpty()) return null

        val rawCombined = parts.joinToString("\n")
        return normalizeWhitespace(rawCombined)
    }

    /**
     * Converts a CharSequence safely to String, handling null or unusual Spanned types.
     */
    private fun safeCharSequenceToString(cs: CharSequence?): String? {
        if (cs == null) return null
        return try {
            cs.toString().trim()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Normalizes whitespace: collapses multiple tabs/spaces while preserving single line breaks.
     */
    fun normalizeWhitespace(input: String): String {
        return input
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .lines()
            .map { it.trim().replace(Regex("[ \\t]+"), " ") }
            .filter { it.isNotEmpty() }
            .joinToString("\n")
            .trim()
    }
}
