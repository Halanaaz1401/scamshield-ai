package org.scamshield.android

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.scamshield.android.databinding.ActivityMainBinding
import org.scamshield.android.model.AnalysisResult
import org.scamshield.android.model.SafeNotificationEvent
import org.scamshield.android.service.NotificationStateRepository
import org.scamshield.android.util.PermissionHelper
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Minimal Privacy & Protection Status Activity for ScamShield.
 *
 * Provides:
 * 1. Clear privacy explanation: ScamShield checks selected notifications without needing account access.
 * 2. Explicit user-initiated notification access permission flow.
 * 3. Clear Protection ON / OFF state representation.
 * 4. Safe local debugging status proving notification receipt and backend analysis
 *    without logging or displaying private message text.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val timeFormat = SimpleDateFormat("hh:mm:ss a", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupListeners()
        observeNotificationState()
    }

    override fun onResume() {
        super.onResume()
        // Refresh protection status whenever returning from system settings
        updateProtectionUiState()
    }

    private fun setupListeners() {
        binding.btnProtectionAction.setOnClickListener {
            try {
                val intent = PermissionHelper.createNotificationSettingsIntent()
                startActivity(intent)
            } catch (e: Exception) {
                Toast.makeText(
                    this,
                    "Unable to open notification settings directly. Please enable ScamShield under Settings > Apps > Special app access > Notification access.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun updateProtectionUiState() {
        val isGranted = PermissionHelper.isNotificationAccessGranted(this)

        if (isGranted) {
            // Protection ON state
            binding.tvProtectionState.text = getString(R.string.status_protection_on)
            binding.tvProtectionState.setTextColor(ContextCompat.getColor(this, R.color.emerald_accent))
            binding.viewStatusDot.setBackgroundColor(ContextCompat.getColor(this, R.color.emerald_accent))
            binding.tvProtectionDesc.text = getString(R.string.status_protection_on_desc)
            binding.btnProtectionAction.text = getString(R.string.btn_manage_protection)
            binding.btnProtectionAction.setBackgroundColor(ContextCompat.getColor(this, R.color.surface_card_inner))
            binding.btnProtectionAction.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
        } else {
            // Protection OFF state
            binding.tvProtectionState.text = getString(R.string.status_protection_off)
            binding.tvProtectionState.setTextColor(ContextCompat.getColor(this, R.color.red_accent))
            binding.viewStatusDot.setBackgroundColor(ContextCompat.getColor(this, R.color.red_accent))
            binding.tvProtectionDesc.text = getString(R.string.status_protection_off_desc)
            binding.btnProtectionAction.text = getString(R.string.btn_enable_protection)
            binding.btnProtectionAction.setBackgroundColor(ContextCompat.getColor(this, R.color.indigo_primary))
            binding.btnProtectionAction.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
        }
    }

    private fun observeNotificationState() {
        lifecycleScope.launch {
            combine(
                NotificationStateRepository.receivedCount,
                NotificationStateRepository.analyzedCount
            ) { received, analyzed ->
                Pair(received, analyzed)
            }.collectLatest { (received, analyzed) ->
                binding.tvEventCounter.text = getString(R.string.debug_counter_format, received, analyzed)
            }
        }

        lifecycleScope.launch {
            NotificationStateRepository.lastEvent.collectLatest { event ->
                updateSafeDebugView(event)
            }
        }

        lifecycleScope.launch {
            NotificationStateRepository.latestAnalysisResult.collectLatest { result ->
                updateAnalysisSummaryView(result)
            }
        }
    }

    /**
     * Updates safe local developer status.
     *
     * STRICT PRIVACY ENFORCEMENT:
     * Only displays source name and timestamp. Never displays message body or sender info.
     */
    private fun updateSafeDebugView(event: SafeNotificationEvent?) {
        if (event == null) {
            binding.tvDebugStatus.text = getString(R.string.debug_status_listening)
            binding.tvDebugStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        } else {
            val formattedTime = timeFormat.format(Date(event.timestampMillis))
            val safeStatus = "${event.source.displayName} notification received [$formattedTime]"
            binding.tvDebugStatus.text = safeStatus
            binding.tvDebugStatus.setTextColor(ContextCompat.getColor(this, R.color.emerald_accent))
        }
    }

    /**
     * Updates latest analysis outcome display safely without exposing raw message text.
     */
    private fun updateAnalysisSummaryView(result: AnalysisResult?) {
        if (result == null) {
            binding.tvAnalysisSummary.visibility = View.GONE
        } else {
            binding.tvAnalysisSummary.visibility = View.VISIBLE
            binding.tvAnalysisSummary.text = getString(
                R.string.debug_analyzed_format,
                result.riskLevel,
                result.scamCategory,
                result.riskScore
            )
            val colorRes = when (result.riskLevel.uppercase(Locale.ROOT)) {
                "CRITICAL", "HIGH" -> R.color.red_accent
                "MEDIUM" -> R.color.amber_accent
                else -> R.color.emerald_accent
            }
            binding.tvAnalysisSummary.setTextColor(ContextCompat.getColor(this, colorRes))
        }
    }
}
