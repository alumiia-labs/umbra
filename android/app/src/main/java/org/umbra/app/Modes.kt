package org.umbra.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.SystemClock
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.work.WorkManager as Work
import java.security.SecureRandom

/**
 * The three modes of Part 8 §8.3, and the content preview of `NTF-083`.
 * Instant mode registers the push token of the platform. Private mode
 * holds no token, and the device wakes on a fixed clock that no arrival
 * moves. Off drains when the user opens the app. The mode is a setting of
 * this device.
 */
enum class NotifyMode(val label: String, private val words: String?) {
    // NTF-009: the trade of the default mode, in one honest line.
    Instant("Instant", null),
    Private("Private", "A message arrives on a fixed clock of about 30 minutes. Google learns nothing about arrivals."),
    Off("Off", "A message arrives when you open UMBRA."),
    ;

    /** The trade of the mode in one line. */
    val trade: String
        get() = words ?: UiText.get(R.string.umbra_ui_ntf_009)
}

object Modes {
    private const val PREFERENCES = "modes"
    private const val MODE = "mode"
    private const val PREVIEW = "preview"
    private const val PHASE = "phase"
    private var isWatching = false

    /** The fixed clock of Private mode (§8.3). */
    private const val PRIVATE_PERIOD_MS = 30 * 60 * 1_000L

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /** The mode of this device. A build ships Instant (`NTF-083`). */
    fun mode(context: Context): NotifyMode =
        preferences(context).getString(MODE, null)?.let { held ->
            NotifyMode.entries.firstOrNull { it.name == held }
        } ?: NotifyMode.Instant

    /** Whether an alert shows the sender and the text. Off by default. */
    fun preview(context: Context): Boolean = preferences(context).getBoolean(PREVIEW, false)

    fun setPreview(context: Context, isOn: Boolean) {
        preferences(context).edit().putBoolean(PREVIEW, isOn).apply()
    }

    fun setMode(context: Context, mode: NotifyMode) {
        preferences(context).edit().putString(MODE, mode.name).apply()
        apply(context)
    }

    /**
     * The high-risk configuration of `NTF-082`: Private notifications, and
     * no content preview.
     */
    fun highRisk(context: Context) {
        setPreview(context, false)
        setMode(context, NotifyMode.Private)
    }

    /** Puts the carriers of the mode in place: the token, the poll, the clock. */
    fun apply(context: Context) {
        val app = context.applicationContext
        when (mode(app)) {
            NotifyMode.Instant -> {
                cancelClock(app)
                Push.opened(app)
                Poll.schedule(app)
                Core.refreshWake(app)
            }
            NotifyMode.Private -> {
                // NTF-039: no token, thus no push of high priority.
                Core.clearPushToken()
                // NTF-137: no push, thus no wake table.
                WakeStore.delete(app)
                Work.getInstance(app).cancelUniqueWork(Poll.NAME)
                drawPhase(app)
                scheduleClock(app)
            }
            NotifyMode.Off -> {
                Core.clearPushToken()
                WakeStore.delete(app)
                Work.getInstance(app).cancelUniqueWork(Poll.NAME)
                cancelClock(app)
            }
        }
    }

    /**
     * NTF-052: the phase of the clock, drawn from the CSPRNG. One phase
     * across two networks would link them, thus a network change draws it
     * again.
     */
    fun drawPhase(context: Context) {
        val phase = (SecureRandom().nextDouble() * PRIVATE_PERIOD_MS).toLong()
        preferences(context).edit().putLong(PHASE, phase).apply()
    }

    private fun clockIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
        context,
        0,
        Intent(context, PrivateClock::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    /** The next tick of the fixed clock: the phase inside the next period. */
    fun scheduleClock(context: Context) {
        val phase = preferences(context).getLong(PHASE, 0)
        val now = System.currentTimeMillis()
        val period = PRIVATE_PERIOD_MS
        var next = now - now % period + phase
        if (next <= now) next += period
        val alarms = context.getSystemService(AlarmManager::class.java)
        // An inexact alarm needs no permission, and its batching is no
        // function of an arrival.
        alarms.setAndAllowWhileIdle(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + (next - now),
            clockIntent(context),
        )
    }

    private fun cancelClock(context: Context) {
        context.getSystemService(AlarmManager::class.java).cancel(clockIntent(context))
    }

    /** A network change draws a new phase for Private mode (`NTF-052`). */
    fun watchNetwork(context: Context) {
        if (isWatching) return
        isWatching = true
        val app = context.applicationContext
        app.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (mode(app) == NotifyMode.Private) {
                        drawPhase(app)
                        scheduleClock(app)
                    }
                }
            },
        )
    }
}

/** A tick of the fixed clock of Private mode: a drain, and the next tick. */
class PrivateClock : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Modes.mode(context) != NotifyMode.Private) return
        if (Core.isOpen()) Core.wake(context)
        Modes.scheduleClock(context)
    }
}

/** The mode of this device, each with its trade in one line (`NTF-009`). */
@Composable
fun NotificationsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var mode by remember { mutableStateOf(Modes.mode(context)) }
    var preview by remember { mutableStateOf(Modes.preview(context)) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Notifications", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            for (choice in NotifyMode.entries) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) {
                            mode = choice
                            Modes.setMode(context, choice)
                        }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = mode == choice)
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(choice.label)
                        Text(
                            choice.trade,
                            style = MaterialTheme.typography.bodySmall,
                            color = Palette.TextSecondary,
                            modifier = Modifier.subline(),
                        )
                    }
                }
                HorizontalDivider(color = Palette.Divider)
            }
            ToggleRow("Show sender and text", preview) {
                preview = it
                Modes.setPreview(context, it)
            }
            HorizontalDivider(color = Palette.Divider)
            Spacer(Modifier.height(16.dp))
            SecondaryButton("Use the high-risk configuration") {
                Modes.highRisk(context)
                mode = Modes.mode(context)
                preview = Modes.preview(context)
            }
            Spacer(Modifier.height(12.dp))
            Note("Private mode, and no sender or text in an alert.")
        }
    }
}
