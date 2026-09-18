package org.scamshield.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.scamshield.android.model.NotificationSource

/**
 * Unit tests for SourceFilter logic.
 *
 * Verifies that:
 * 1. WhatsApp & WhatsApp Business are correctly identified.
 * 2. Major OEM SMS applications and dynamic default SMS applications are identified.
 * 3. Unapproved applications (social, browser, email, etc.) are strictly ignored.
 * 4. Null or empty package names are safely handled.
 */
class SourceFilterTest {

    @Test
    fun testWhatsAppPackageIdentified() {
        val source = SourceFilter.resolveSource("com.whatsapp")
        assertEquals(NotificationSource.WHATSAPP, source)
        assertTrue(SourceFilter.isAllowed("com.whatsapp"))
    }

    @Test
    fun testWhatsAppBusinessPackageIdentified() {
        val source = SourceFilter.resolveSource("com.whatsapp.w4b")
        assertEquals(NotificationSource.WHATSAPP, source)
        assertTrue(SourceFilter.isAllowed("com.whatsapp.w4b"))
    }

    @Test
    fun testGoogleMessagesIdentified() {
        val source = SourceFilter.resolveSource("com.google.android.apps.messaging")
        assertEquals(NotificationSource.SMS, source)
        assertTrue(SourceFilter.isAllowed("com.google.android.apps.messaging"))
    }

    @Test
    fun testSamsungMessagesIdentified() {
        val source = SourceFilter.resolveSource("com.samsung.android.messaging")
        assertEquals(NotificationSource.SMS, source)
        assertTrue(SourceFilter.isAllowed("com.samsung.android.messaging"))
    }

    @Test
    fun testAospMmsIdentified() {
        val source = SourceFilter.resolveSource("com.android.mms")
        assertEquals(NotificationSource.SMS, source)
        assertTrue(SourceFilter.isAllowed("com.android.mms"))
    }

    @Test
    fun testDynamicDefaultSmsPackageIdentified() {
        val customCarrierSms = "com.carrier.custom.sms"
        val source = SourceFilter.resolveSource(customCarrierSms, dynamicDefaultSmsPackage = customCarrierSms)
        assertEquals(NotificationSource.SMS, source)
        assertTrue(SourceFilter.isAllowed(customCarrierSms, dynamicDefaultSmsPackage = customCarrierSms))
    }

    @Test
    fun testUnknownApplicationsStrictlyIgnored() {
        val unknownPackages = listOf(
            "com.instagram.android",
            "com.facebook.katana",
            "org.telegram.messenger",
            "com.spotify.music",
            "com.android.chrome",
            "com.google.android.gm",
            "com.netflix.mediaclient"
        )

        for (pkg in unknownPackages) {
            assertNull("Package $pkg should be ignored", SourceFilter.resolveSource(pkg))
            assertFalse("Package $pkg should not be allowed", SourceFilter.isAllowed(pkg))
        }
    }

    @Test
    fun testNullAndBlankPackagesSafelyIgnored() {
        assertNull(SourceFilter.resolveSource(null))
        assertNull(SourceFilter.resolveSource(""))
        assertNull(SourceFilter.resolveSource("   "))
        assertFalse(SourceFilter.isAllowed(null))
        assertFalse(SourceFilter.isAllowed(""))
        assertFalse(SourceFilter.isAllowed("   "))
    }
}
