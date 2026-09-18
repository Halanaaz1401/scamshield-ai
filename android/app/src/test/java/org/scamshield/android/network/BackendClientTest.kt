package org.scamshield.android.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.scamshield.android.model.AnalysisResult

class BackendClientTest {

    private val client = BackendClient()

    @Test
    fun parseResponse_correctlyMapsBackendResponsePayload() {
        val sampleBackendJson = """
        {
            "analysisId": "test-uuid-12345",
            "riskScore": 88.5,
            "riskLevel": "HIGH",
            "category": "BANKING_SCAM",
            "reasoning": "Suspicious KYC suspension threat with unverified domain.",
            "indicators": [
                {
                    "id": "ind-urgency",
                    "name": "Artificial Urgency",
                    "description": "Demands immediate action today",
                    "severity": "HIGH",
                    "evidence": "blocked today"
                }
            ],
            "attackerIntent": "Harvest credentials via phishing link.",
            "attackPath": [
                {
                    "step": 1,
                    "stage": "Lure & Pressure",
                    "description": "Frighten user with account block threat."
                }
            ],
            "recommendedActions": [
                "Do not click the link.",
                "Do not provide your OTP or password.",
                "Verify directly with your bank."
            ],
            "confidence": "HIGH"
        }
        """.trimIndent()

        val result = client.parseResponse(sampleBackendJson)

        assertEquals("test-uuid-12345", result.analysisId)
        assertEquals(88.5, result.riskScore, 0.01)
        assertEquals("HIGH", result.riskLevel)
        assertEquals("BANKING_SCAM", result.scamCategory)
        assertEquals("Suspicious KYC suspension threat with unverified domain.", result.summary)
        assertEquals("Harvest credentials via phishing link.", result.attackerIntent)
        assertEquals(1, result.indicators.size)
        assertEquals("Artificial Urgency", result.indicators[0].name)
        assertEquals(1, result.attackPath.size)
        assertEquals("Lure & Pressure", result.attackPath[0].stage)
        assertEquals(3, result.recommendedActions.size)
        assertEquals("Do not click the link.", result.recommendedActions[0])
    }

    @Test
    fun analysisResult_preservesPrivacyInvariant_noMessageTextStored() {
        // Reflection test: ensure AnalysisResult model has no raw text property
        val fields = AnalysisResult::class.java.declaredFields.map { it.name }
        assertFalse(fields.contains("message"))
        assertFalse(fields.contains("text"))
        assertFalse(fields.contains("rawContent"))
        assertFalse(fields.contains("content"))
        assertFalse(fields.contains("url"))
        assertFalse(fields.contains("urls"))
    }

    @Test
    fun parseResponse_handlesMissingOptionalFieldsGracefully() {
        val minimalJson = """
        {
            "riskScore": 12.0,
            "riskLevel": "LOW",
            "category": "BENIGN",
            "reasoning": "Routine notification.",
            "recommendedAction": "No action needed."
        }
        """.trimIndent()

        val result = client.parseResponse(minimalJson)

        assertEquals(12.0, result.riskScore, 0.01)
        assertEquals("LOW", result.riskLevel)
        assertEquals("BENIGN", result.scamCategory)
        assertEquals(1, result.recommendedActions.size)
        assertEquals("No action needed.", result.recommendedActions[0])
        assertTrue(result.indicators.isEmpty())
        assertTrue(result.attackPath.isEmpty())
    }
}
