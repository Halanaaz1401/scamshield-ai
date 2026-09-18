package org.scamshield.android.extractor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlExtractorTest {

    @Test
    fun extractUrls_detectsHttpAndHttps() {
        val text = "Please visit http://insecure-portal.com and https://secure-portal.org/login"
        val urls = UrlExtractor.extractUrls(text)
        assertEquals(2, urls.size)
        assertEquals("http://insecure-portal.com", urls[0])
        assertEquals("https://secure-portal.org/login", urls[1])
    }

    @Test
    fun extractUrls_handlesTrailingPunctuation() {
        val text = "Click here: https://example.com/update. Urgent action required!"
        val urls = UrlExtractor.extractUrls(text)
        assertEquals(1, urls.size)
        assertEquals("https://example.com/update", urls[0])
    }

    @Test
    fun extractUrls_handlesParenthesesAndBrackets() {
        val text = "Check document (https://docs.example.com/file) and [https://link.com/path]."
        val urls = UrlExtractor.extractUrls(text)
        assertEquals(2, urls.size)
        assertEquals("https://docs.example.com/file", urls[0])
        assertEquals("https://link.com/path", urls[1])
    }

    @Test
    fun extractUrls_deduplicatesRepeatedUrls() {
        val text = "Link 1: https://bit.ly/claim123, duplicate: https://bit.ly/claim123."
        val urls = UrlExtractor.extractUrls(text)
        assertEquals(1, urls.size)
        assertEquals("https://bit.ly/claim123", urls[0])
    }

    @Test
    fun extractUrls_returnsEmptyForTextWithoutUrls() {
        val text = "Your account was debited Rs 500 at Store. No link here."
        val urls = UrlExtractor.extractUrls(text)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun extractUrls_handlesNullAndBlank() {
        assertTrue(UrlExtractor.extractUrls(null).isEmpty())
        assertTrue(UrlExtractor.extractUrls("   ").isEmpty())
    }

    @Test
    fun extractUrls_handlesShortenedUrlsInHinglish() {
        val text = "Aapka bijli connection cut ho jayega. Pay now: https://t.ly/bijli-pay."
        val urls = UrlExtractor.extractUrls(text)
        assertEquals(1, urls.size)
        assertEquals("https://t.ly/bijli-pay", urls[0])
    }
}
