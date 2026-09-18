package org.scamshield.android.filter

import java.security.MessageDigest
import java.util.LinkedHashMap

/**
 * In-memory notification deduplicator.
 *
 * Prevents redundant network analysis when the same notification is re-posted, updated,
 * or received repeatedly within a short sliding window.
 *
 * Privacy & Resource Guarantees:
 * - Strictly in-memory; no database, no file persistence, no SharedPreferences.
 * - Stores only SHA-256 cryptographic hashes; never stores raw message text.
 * - Bounded LRU cache (max 100 entries) with a 5-minute sliding window expiry.
 */
class NotificationDeduplicator(
    private val ttlMillis: Long = 5 * 60 * 1000L, // 5 minutes
    private val maxCapacity: Int = 100
) {

    private val lock = Any()

    // Fixed-size LRU map mapping Hash -> Timestamp
    private val cache = object : LinkedHashMap<String, Long>(maxCapacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > maxCapacity
        }
    }

    /**
     * Checks if a notification from [packageName] with [text] is a duplicate.
     * If not duplicate, records its hash in memory and returns false.
     * If duplicate, returns true.
     */
    fun isDuplicateAndRecord(packageName: String, text: String): Boolean {
        val hash = computeHash("$packageName:$text")
        val now = System.currentTimeMillis()

        synchronized(lock) {
            val lastSeen = cache[hash]
            if (lastSeen != null && (now - lastSeen) < ttlMillis) {
                return true // Duplicate notification within TTL window
            }
            cache[hash] = now
            return false
        }
    }

    /**
     * Clears all cached hashes (useful during test teardown).
     */
    fun clear() {
        synchronized(lock) {
            cache.clear()
        }
    }

    /**
     * Computes a privacy-safe hex-encoded SHA-256 hash.
     */
    private fun computeHash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
