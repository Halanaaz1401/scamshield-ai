package org.scamshield.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.scamshield.android.model.NotificationSource
import org.scamshield.android.model.SafeNotificationEvent

/**
 * Unit tests verifying that SafeNotificationEvent and NotificationStateRepository
 * enforce privacy by design:
 * 1. Event holds only safe metadata (source, package, timestamp, hasContent flag).
 * 2. Event contains NO field capable of storing raw message body, OTPs, or passwords.
 * 3. StateRepository records receipts and counts accurately.
 */
class SafeNotificationEventTest {

    @Before
    fun setup() {
        NotificationStateRepository.reset()
        NotificationStateRepository.setConnected(false)
    }

    @Test
    fun testEventContainsOnlySafeMetadata() {
        val event = SafeNotificationEvent(
            source = NotificationSource.WHATSAPP,
            packageName = "com.whatsapp",
            timestampMillis = 1700000000000L,
            hasContent = true
        )

        assertEquals(NotificationSource.WHATSAPP, event.source)
        assertEquals("com.whatsapp", event.packageName)
        assertEquals(1700000000000L, event.timestampMillis)
        assertTrue(event.hasContent)

        // Privacy verification via reflection: Confirm no private message text fields exist
        val declaredFieldNames = SafeNotificationEvent::class.java.declaredFields.map { it.name }
        assertTrue(declaredFieldNames.contains("source"))
        assertTrue(declaredFieldNames.contains("packageName"))
        assertTrue(declaredFieldNames.contains("timestampMillis"))
        assertTrue(declaredFieldNames.contains("hasContent"))

        val forbiddenFields = listOf("text", "message", "body", "content", "otp", "password", "pin", "sender", "phone")
        for (forbidden in forbiddenFields) {
            assertTrue(
                "SafeNotificationEvent must not contain sensitive field: $forbidden",
                declaredFieldNames.none { it.equals(forbidden, ignoreCase = true) }
            )
        }
    }

    @Test
    fun testRepositoryStateTransitions() {
        assertEquals(0, NotificationStateRepository.receivedCount.value)
        assertNull(NotificationStateRepository.lastEvent.value)

        // Record WhatsApp event
        val event1 = SafeNotificationEvent(
            source = NotificationSource.WHATSAPP,
            packageName = "com.whatsapp",
            timestampMillis = System.currentTimeMillis(),
            hasContent = true
        )
        NotificationStateRepository.recordSafeReceipt(event1)

        assertEquals(1, NotificationStateRepository.receivedCount.value)
        assertNotNull(NotificationStateRepository.lastEvent.value)
        assertEquals(NotificationSource.WHATSAPP, NotificationStateRepository.lastEvent.value?.source)

        // Record SMS event
        val event2 = SafeNotificationEvent(
            source = NotificationSource.SMS,
            packageName = "com.google.android.apps.messaging",
            timestampMillis = System.currentTimeMillis(),
            hasContent = true
        )
        NotificationStateRepository.recordSafeReceipt(event2)

        assertEquals(2, NotificationStateRepository.receivedCount.value)
        assertEquals(NotificationSource.SMS, NotificationStateRepository.lastEvent.value?.source)

        // Test reset
        NotificationStateRepository.reset()
        assertEquals(0, NotificationStateRepository.receivedCount.value)
        assertNull(NotificationStateRepository.lastEvent.value)
    }

    @Test
    fun testConnectionStateToggle() {
        assertEquals(false, NotificationStateRepository.isServiceConnected.value)

        NotificationStateRepository.setConnected(true)
        assertEquals(true, NotificationStateRepository.isServiceConnected.value)

        NotificationStateRepository.setConnected(false)
        assertEquals(false, NotificationStateRepository.isServiceConnected.value)
    }
}
