package org.scamshield.android.extractor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NotificationExtractorTest {

    @Test
    fun normalizeWhitespace_collapsesSpacesAndTrims() {
        val raw = "   Your   account   will   be   blocked   today.  \n\n\n  Click   here: https://example.com   "
        val normalized = NotificationExtractor.normalizeWhitespace(raw)
        assertEquals("Your account will be blocked today.\nClick here: https://example.com", normalized)
    }

    @Test
    fun normalizeWhitespace_handlesWindowsAndUnixNewlines() {
        val raw = "Line 1\r\nLine 2\rLine 3\nLine 4"
        val normalized = NotificationExtractor.normalizeWhitespace(raw)
        assertEquals("Line 1\nLine 2\nLine 3\nLine 4", normalized)
    }

    @Test
    fun extractFromExtras_handlesNullExtrasSafely() {
        val result = NotificationExtractor.extractFromExtras(null)
        assertNull(result)
    }

    @Test
    fun extractText_handlesNullStatusBarNotificationSafely() {
        val result = NotificationExtractor.extractText(null)
        assertNull(result)
    }
}
