package org.scamshield.android.filter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.scamshield.android.extractor.UrlExtractor

class CandidateFilterTest {

    // ==========================================
    // Indian Scam Notification Examples from Spec
    // ==========================================

    @Test
    fun isCandidate_flagsSbiKycScam() {
        val msg = "Your SBI account will be blocked today. Complete KYC immediately: https://example.com"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsElectricityDisconnectScam() {
        val msg = "Your electricity connection will be disconnected tonight. Pay ₹10 immediately using this link https://bijli-bill.xyz"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsLotteryRewardScam() {
        val msg = "Congratulations! You have won ₹25,00,000. Pay processing fee to claim your prize."
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsUpiSuspendedScam() {
        val msg = "Your UPI account is suspended. Verify your PIN immediately."
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsPoliceCyberCellNotice() {
        val msg = "Police cyber cell notice. Your bank account is involved in illegal activity. Call immediately."
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsLpgSubsidyScam() {
        val msg = "Your LPG subsidy is pending. Update Aadhaar/KYC using this link http://lpg-update.in"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsParcelCustomsScam() {
        val msg = "Your parcel is held. Pay ₹25 customs charge immediately."
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    // ==========================================
    // Hinglish Examples from Spec
    // ==========================================

    @Test
    fun isCandidate_flagsHinglishKycExpire() {
        val msg = "Sir aapka KYC expire ho gaya hai, abhi verify nahi kiya toh account block ho jayega"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsHinglishBijliConnectionCut() {
        val msg = "Bijli connection aaj raat cut ho jayega, ₹10 payment karo"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_flagsHinglishLotteryJeetGaye() {
        val msg = "Congratulations madam aap lottery jeet gaye ho, processing fee bhejo"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    // ==========================================
    // Benign Examples from Spec (MUST BE LOCAL DISCARD)
    // ==========================================

    @Test
    fun isCandidate_discardsBenignBankDebit() {
        val msg = "Your SBI account has been debited ₹500 at XYZ store."
        val urls = UrlExtractor.extractUrls(msg)
        assertFalse(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_discardsLegitimateOtpNotification() {
        // Spec requirement: OTP alert must NOT be classified as a scam simply because it contains an OTP
        val msg = "Your OTP for SBI net banking is 482913. Do not share it with anyone."
        val urls = UrlExtractor.extractUrls(msg)
        assertFalse(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_discardsBenignPaymentReceived() {
        val msg = "Payment of ₹500 received successfully."
        val urls = UrlExtractor.extractUrls(msg)
        assertFalse(CandidateFilter.isCandidate(msg, urls))
    }

    // ==========================================
    // Edge Cases & Resiliency
    // ==========================================

    @Test
    fun isCandidate_handlesEmptyAndBlank() {
        assertFalse(CandidateFilter.isCandidate("", emptyList()))
        assertFalse(CandidateFilter.isCandidate("   ", emptyList()))
        assertFalse(CandidateFilter.isCandidate(null, emptyList()))
    }

    @Test
    fun isCandidate_handlesUnicodeAndEmojis() {
        val msg = "⚡ URGENT: Aapka account block ho jayega ⚠️ Call immediately 🚨"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }

    @Test
    fun isCandidate_handlesVeryLongNotification() {
        val longPadding = "Notification header with general update info. ".repeat(20)
        val msg = "$longPadding Urgent: Complete KYC immediately or account will be blocked today: https://update-bank.in"
        val urls = UrlExtractor.extractUrls(msg)
        assertTrue(CandidateFilter.isCandidate(msg, urls))
    }
}
