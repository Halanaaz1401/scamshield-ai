package org.scamshield.android.service

import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.scamshield.android.extractor.NotificationExtractor
import org.scamshield.android.extractor.UrlExtractor
import org.scamshield.android.filter.CandidateFilter
import org.scamshield.android.filter.NotificationDeduplicator
import org.scamshield.android.model.SafeNotificationEvent
import org.scamshield.android.network.BackendClient

/**
 * Android NotificationListenerService implementation for ScamShield.
 *
 * PROACTIVE PROTECTION PIPELINE:
 * 1. Source Filtering: Discards all notifications except WhatsApp and supported SMS apps.
 * 2. Safe Content Extraction: Extracts title/body/subText in transient memory.
 * 3. Deduplication: In-memory sliding window prevents repetitive processing of identical alerts.
 * 4. Local Candidate Filter: Fast, deterministic evaluation keeps benign alerts local.
 * 5. URL Extraction: Extracts URLs in transient memory.
 * 6. Authoritative Backend Analysis: Sends candidate text to existing ScamShield backend.
 * 7. Structured Result Ingestion: Stores [AnalysisResult] in-memory for Part 3.
 *
 * PRIVACY & SECURITY GUARANTEES:
 * - NEVER logs raw notification text or URLs.
 * - NEVER stores notification content in SharedPreferences, SQLite, or Room.
 * - Benign notifications never trigger network requests.
 * - No AWS or Bedrock credentials in Android.
 */
class ScamNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "ScamShieldListener"
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val deduplicator = NotificationDeduplicator()
    internal var backendClient = BackendClient()

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "Notification listener connected by system.")
        NotificationStateRepository.setConnected(true)
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.i(TAG, "Notification listener disconnected by system.")
        NotificationStateRepository.setConnected(false)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // 1. Source filtering: check if notification originates from WhatsApp or SMS
        val defaultSmsPackage = try {
            Telephony.Sms.getDefaultSmsPackage(applicationContext)
        } catch (_: Exception) {
            null
        }

        val source = SourceFilter.resolveSource(packageName, defaultSmsPackage) ?: return

        // 2. Extract textual content safely from extras
        val text = NotificationExtractor.extractText(sbn) ?: return

        // 3. In-memory deduplication: prevent redundant processing of the same notification
        if (deduplicator.isDuplicateAndRecord(packageName, text)) {
            Log.d(TAG, "Duplicate notification from ${source.displayName} ignored.")
            return
        }

        // Record proof of receipt event (privacy-safe: strictly NO text body stored)
        val safeEvent = SafeNotificationEvent(
            source = source,
            packageName = packageName,
            timestampMillis = sbn.postTime,
            hasContent = true
        )
        NotificationStateRepository.recordSafeReceipt(safeEvent)

        // 4. URL extraction in transient memory
        val urls = UrlExtractor.extractUrls(text)

        // 5. Local candidate filtering: determine whether analysis is warranted
        val isCandidate = CandidateFilter.isCandidate(text, urls)
        if (!isCandidate) {
            // High confidence benign alert: discarded locally without network activity
            Log.d(TAG, "Notification from ${source.displayName} evaluated as benign locally; skipped backend.")
            return
        }

        // 6. Candidate detected: dispatch minimal payload to authoritative ScamShield backend
        Log.d(TAG, "Notification from ${source.displayName} qualified as candidate. Submitting to backend.")
        serviceScope.launch {
            val result = backendClient.analyze(
                message = text,
                sourceType = source.name.lowercase()
            )

            result.onSuccess { analysis ->
                NotificationStateRepository.recordAnalysisResult(analysis)
                Log.i(TAG, "Analysis complete for ${source.displayName}: ${analysis.riskLevel} (${analysis.scamCategory}, score=${analysis.riskScore})")
            }.onFailure { error ->
                Log.w(TAG, "Backend analysis request failed safely: ${error.message}")
            }
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        super.onNotificationRemoved(sbn)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        deduplicator.clear()
        NotificationStateRepository.setConnected(false)
        Log.i(TAG, "Notification listener destroyed.")
    }
}
