package org.scamshield.android.extractor

import java.util.regex.Pattern

/**
 * Focused URL extractor for detecting HTTP/HTTPS links inside notification text.
 *
 * Designed to clean trailing punctuation and deduplicate links in transient memory.
 */
object UrlExtractor {

    // Regex matching standard HTTP / HTTPS schemes up to whitespace or enclosing brackets
    private val URL_PATTERN = Pattern.compile(
        "https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
        Pattern.CASE_INSENSITIVE
    )

    // Trailing punctuation characters commonly attached in natural text sentences
    private val TRAILING_PUNCTUATION = charArrayOf(
        '.', ',', '!', '?', ';', ':', ')', ']', '}', '>', '"', '\'', '`'
    )

    /**
     * Extracts and deduplicates valid URLs from the text.
     * Preserves order of first appearance.
     */
    fun extractUrls(text: String?): List<String> {
        if (text.isNullOrBlank()) return emptyList()

        val results = LinkedHashSet<String>()
        val matcher = URL_PATTERN.matcher(text)

        while (matcher.find()) {
            val rawMatch = matcher.group()
            val cleaned = cleanTrailingPunctuation(rawMatch)
            if (isValidHttpUrl(cleaned)) {
                results.add(cleaned)
            }
        }

        return results.toList()
    }

    /**
     * Cleans trailing punctuation that does not belong to the URL query or path.
     */
    fun cleanTrailingPunctuation(url: String): String {
        var end = url.length
        while (end > 0 && TRAILING_PUNCTUATION.contains(url[end - 1])) {
            // Handle balanced parentheses: if closing ')' is preceded by opening '(', keep it
            if (url[end - 1] == ')' && url.substring(0, end - 1).contains('(')) {
                break
            }
            end--
        }
        return url.substring(0, end)
    }

    /**
     * Quick structural sanity check for extracted URL.
     */
    private fun isValidHttpUrl(url: String): Boolean {
        val lower = url.lowercase()
        return (lower.startsWith("http://") || lower.startsWith("https://")) &&
                url.length > 8 &&
                !url.contains(" ")
    }
}
