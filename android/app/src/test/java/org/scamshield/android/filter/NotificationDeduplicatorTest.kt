package org.scamshield.android.filter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationDeduplicatorTest {

    @Test
    fun isDuplicateAndRecord_firstSeenReturnsFalse() {
        val deduplicator = NotificationDeduplicator()
        val isDup = deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello world")
        assertFalse(isDup)
    }

    @Test
    fun isDuplicateAndRecord_secondSeenReturnsTrue() {
        val deduplicator = NotificationDeduplicator()
        deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello world")
        val isDup = deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello world")
        assertTrue(isDup)
    }

    @Test
    fun isDuplicateAndRecord_differentTextReturnsFalse() {
        val deduplicator = NotificationDeduplicator()
        deduplicator.isDuplicateAndRecord("com.whatsapp", "Message 1")
        val isDup = deduplicator.isDuplicateAndRecord("com.whatsapp", "Message 2")
        assertFalse(isDup)
    }

    @Test
    fun isDuplicateAndRecord_differentPackageSameTextReturnsFalse() {
        val deduplicator = NotificationDeduplicator()
        deduplicator.isDuplicateAndRecord("com.whatsapp", "Identical message text")
        val isDup = deduplicator.isDuplicateAndRecord("com.google.android.apps.messaging", "Identical message text")
        assertFalse(isDup)
    }

    @Test
    fun clear_resetsDeduplicationMemory() {
        val deduplicator = NotificationDeduplicator()
        deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello")
        assertTrue(deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello"))

        deduplicator.clear()
        assertFalse(deduplicator.isDuplicateAndRecord("com.whatsapp", "Hello"))
    }
}
