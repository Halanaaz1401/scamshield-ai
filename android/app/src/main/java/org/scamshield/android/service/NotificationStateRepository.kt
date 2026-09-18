package org.scamshield.android.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.scamshield.android.model.AnalysisResult
import org.scamshield.android.model.SafeNotificationEvent

/**
 * Thread-safe in-memory repository for local notification protection state.
 *
 * Exposes live observable state to the UI without any persistent disk storage,
 * database records, or telemetry tracking.
 */
object NotificationStateRepository {

    private val _isServiceConnected = MutableStateFlow(false)
    val isServiceConnected: StateFlow<Boolean> = _isServiceConnected.asStateFlow()

    private val _lastEvent = MutableStateFlow<SafeNotificationEvent?>(null)
    val lastEvent: StateFlow<SafeNotificationEvent?> = _lastEvent.asStateFlow()

    private val _latestAnalysisResult = MutableStateFlow<AnalysisResult?>(null)
    val latestAnalysisResult: StateFlow<AnalysisResult?> = _latestAnalysisResult.asStateFlow()

    private val _receivedCount = MutableStateFlow(0)
    val receivedCount: StateFlow<Int> = _receivedCount.asStateFlow()

    private val _analyzedCount = MutableStateFlow(0)
    val analyzedCount: StateFlow<Int> = _analyzedCount.asStateFlow()

    fun setConnected(connected: Boolean) {
        _isServiceConnected.value = connected
    }

    fun recordSafeReceipt(event: SafeNotificationEvent) {
        _lastEvent.value = event
        _receivedCount.value += 1
    }

    fun recordAnalysisResult(result: AnalysisResult) {
        _latestAnalysisResult.value = result
        _analyzedCount.value += 1
    }

    fun reset() {
        _lastEvent.value = null
        _latestAnalysisResult.value = null
        _receivedCount.value = 0
        _analyzedCount.value = 0
    }
}
