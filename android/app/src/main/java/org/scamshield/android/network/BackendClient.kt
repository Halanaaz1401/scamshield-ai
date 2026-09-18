package org.scamshield.android.network

import org.json.JSONArray
import org.json.JSONObject
import org.scamshield.android.BuildConfig
import org.scamshield.android.model.AnalysisResult
import org.scamshield.android.model.AttackStepItem
import org.scamshield.android.model.IndicatorItem
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Lightweight, secure client for the ScamShield threat analysis backend.
 *
 * Privacy & Security Guarantees:
 * - Never logs the raw notification message or extracted URLs.
 * - Enforces HTTPS in production; permits cleartext development endpoints via network_security_config.
 * - Contains zero AWS credentials, secrets, or Bedrock API keys.
 * - Handles connection timeouts and server errors gracefully without throwing runtime exceptions.
 */
class BackendClient(
    private val baseUrl: String = BuildConfig.DEFAULT_BACKEND_URL,
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 10000
) {

    /**
     * Submits a candidate notification message to the ScamShield backend for threat analysis.
     *
     * @param message The extracted text from the candidate notification.
     * @param sourceType The communication vector (e.g. "whatsapp", "sms", or "message").
     * @return Result containing [AnalysisResult] on success, or an Exception on failure.
     */
    fun analyze(message: String, sourceType: String): Result<AnalysisResult> {
        return try {
            val endpoint = if (baseUrl.endsWith("/")) "${baseUrl}analyze" else "$baseUrl/analyze"
            val url = URL(endpoint)
            val connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = connectTimeoutMs
                readTimeout = readTimeoutMs
                doInput = true
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=UTF-8")
                setRequestProperty("Accept", "application/json")
            }

            // Minimal payload expected by backend /analyze
            val requestJson = JSONObject().apply {
                put("message", message)
                put("sourceType", sourceType)
            }

            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(requestJson.toString())
                writer.flush()
            }

            val responseCode = connection.responseCode
            if (responseCode in 200..299) {
                val responseText = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                val parsed = parseResponse(responseText)
                Result.success(parsed)
            } else {
                val errorStream = connection.errorStream
                val errorMsg = if (errorStream != null) {
                    errorStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                } else {
                    "HTTP $responseCode"
                }
                Result.failure(Exception("Backend responded with HTTP $responseCode: $errorMsg"))
            }
        } catch (e: Exception) {
            // Fail safely: return Result.failure without leaking sensitive text in exceptions
            Result.failure(Exception("Backend analysis connection failed: ${e.javaClass.simpleName}: ${e.message}"))
        }
    }

    /**
     * Parses the backend JSON response into a privacy-safe [AnalysisResult] model.
     */
    fun parseResponse(jsonString: String): AnalysisResult {
        val root = JSONObject(jsonString)

        val analysisId = root.optString("analysisId", "generated-${System.currentTimeMillis()}")
        val riskScore = root.optDouble("riskScore", 0.0)
        val riskLevel = root.optString("riskLevel", "LOW")
        val category = root.optString("category", root.optString("scamCategory", "OTHER_SUSPICIOUS"))
        val summary = root.optString("reasoning", root.optString("summary", "Analysis completed."))
        val attackerIntent = root.optString("attackerIntent").takeIf { it.isNotBlank() }

        // Parse indicators
        val indicators = mutableListOf<IndicatorItem>()
        val indArray = root.optJSONArray("indicators") ?: JSONArray()
        for (i in 0 until indArray.length()) {
            val indObj = indArray.optJSONObject(i) ?: continue
            indicators.add(
                IndicatorItem(
                    id = indObj.optString("id", "ind-$i"),
                    name = indObj.optString("name", "Indicator"),
                    description = indObj.optString("description", ""),
                    severity = indObj.optString("severity", "MEDIUM"),
                    evidence = indObj.optString("evidence").takeIf { it.isNotBlank() }
                )
            )
        }

        // Parse attack path
        val attackPath = mutableListOf<AttackStepItem>()
        val pathArray = root.optJSONArray("attackPath") ?: JSONArray()
        for (i in 0 until pathArray.length()) {
            val stepObj = pathArray.optJSONObject(i) ?: continue
            attackPath.add(
                AttackStepItem(
                    step = stepObj.optInt("step", i + 1),
                    stage = stepObj.optString("stage", "Exploitation"),
                    description = stepObj.optString("description", "")
                )
            )
        }

        // Parse recommended actions
        val recommendedActions = mutableListOf<String>()
        val recArray = root.optJSONArray("recommendedActions")
        if (recArray != null) {
            for (i in 0 until recArray.length()) {
                val action = recArray.optString(i)
                if (!action.isNullOrBlank()) {
                    recommendedActions.add(action)
                }
            }
        }
        if (recommendedActions.isEmpty()) {
            val primaryAction = root.optString("recommendedAction")
            if (primaryAction.isNotBlank()) {
                recommendedActions.add(primaryAction)
            }
        }

        val aiAvailable = root.optBoolean("aiAvailable", false)

        return AnalysisResult(
            analysisId = analysisId,
            riskScore = riskScore,
            riskLevel = riskLevel,
            scamCategory = category,
            summary = summary,
            indicators = indicators,
            attackerIntent = attackerIntent,
            attackPath = attackPath,
            recommendedActions = recommendedActions,
            aiAvailable = aiAvailable,
            timestamp = System.currentTimeMillis()
        )
    }
}
