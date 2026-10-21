package com.alumiialabs.umbra

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.work.WorkManager as Work
import java.security.SecureRandom

/**
 * The four modes of Part 8 §8.3, and the content preview of `NTF-083`.
 * Instant mode registers the push token of the platform. Direct mode holds
 * no token and takes each record over its own connection. Private mode
 * holds no token, and the device wakes on a fixed clock that no arrival
 * moves. Off drains when the user opens the app. The mode is a setting of
 * this device, and the user sets it as a [Delivery] and a delay
 * (`NTF-147`).
 */
enum class NotifyMode(private val labelId: Int) {
    // NTF-148: the screen names Instant mode after the party that sees each push.
    Instant(R.string.modes_google),
    Direct(R.string.modes_direct),
    Private(R.string.modes_direct_delayed),
    Off(R.string.modes_none),
    ;

    /** The name of the mode, as the settings list shows it. */
    val label: String
        get() = UiText.get(labelId)

    /** Instant and Direct hold the persistent socket while the client is open. */
    val holdsConnection: Boolean
        get() = this == Instant || this == Direct
}

/** The delivery of `NTF-147`, in the order of the screen. */
enum class Delivery(private val labelId: Int, private val words: Int) {
    // NTF-009: the trade of each delivery, in one honest line.
    Direct(R.string.modes_direct, R.string.umbra_ui_ntf_009_direct),
    Google(R.string.modes_google, R.string.umbra_ui_ntf_009),
    None(R.string.modes_none, R.string.umbra_ui_ntf_009_off),
    ;

    val label: String
        get() = UiText.get(labelId)

    val trade: String
        get() = UiText.get(words)
}

object Modes {
    private const val PREFERENCES = "modes"
    private const val MODE = "mode"
    private const val DELIVERY = "delivery"
    private const val DELAYED = "delayed"
    private const val PREVIEW = "preview"
    private const val SHOW_SENDER = "show-sender"
    private const val SHOW_TEXT = "show-text"
    private const val KEEP_NOTICE = "keep-notice"
    private const val PHASE = "phase"

    /** Whether the callback of the network is in place. */
    private var isWatching = false

    /** The fixed clock of Private mode (§8.3). */
    private const val PRIVATE_PERIOD_MS = 30 * 60 * 1_000L

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /**
     * The mode of this device, from the delivery and the delay. A build ships
     * Direct (`NTF-083`). A build with no FCM holds no Instant mode, thus
     * Direct takes its place (`NTF-140`).
     */
    fun mode(context: Context): NotifyMode = when (delivery(context)) {
        Delivery.Direct -> if (isDelayed(context)) NotifyMode.Private else NotifyMode.Direct
        Delivery.Google -> if (Push.isAvailable(context)) NotifyMode.Instant else NotifyMode.Direct
        Delivery.None -> NotifyMode.Off
    }

    fun delivery(context: Context): Delivery {
        val preferences = preferences(context)
        preferences.getString(DELIVERY, null)?.let { name ->
            Delivery.entries.firstOrNull { it.name == name }?.let { return it }
        }

        // The mode of an earlier build gives the delivery and the delay.
        return when (preferences.getString(MODE, null)) {
            NotifyMode.Instant.name -> Delivery.Google
            NotifyMode.Off.name -> Delivery.None
            else -> Delivery.Direct
        }
    }

    /** Whether the fixed clock of Private mode holds the delivery. Google takes no delay (`NTF-147`). */
    fun isDelayed(context: Context): Boolean {
        val preferences = preferences(context)
        return preferences.getBoolean(DELAYED, preferences.getString(MODE, null) == NotifyMode.Private.name)
    }

    /** The deliveries that this build offers (`NTF-140`). */
    fun offered(context: Context): List<Delivery> =
        Delivery.entries.filter { it != Delivery.Google || Push.isAvailable(context) }

    /**
     * Whether an alert shows the sender, and whether it shows the text, on
     * this device (`NTF-149`). Each is off by default. The one switch of an
     * earlier build gives the two.
     */
    fun showsSender(context: Context): Boolean =
        preferences(context).let { it.getBoolean(SHOW_SENDER, it.getBoolean(PREVIEW, false)) }

    fun showsText(context: Context): Boolean =
        preferences(context).let { it.getBoolean(SHOW_TEXT, it.getBoolean(PREVIEW, false)) }

    fun setShowsSender(context: Context, isOn: Boolean) {
        preferences(context).edit().putBoolean(SHOW_SENDER, isOn).apply()
    }

    fun setShowsText(context: Context, isOn: Boolean) {
        preferences(context).edit().putBoolean(SHOW_TEXT, isOn).apply()
    }

    /** Whether the notice of the service comes back after a swipe. */
    fun keepsNotice(context: Context): Boolean = preferences(context).getBoolean(KEEP_NOTICE, true)

    fun setKeepNotice(context: Context, isOn: Boolean) {
        preferences(context).edit().putBoolean(KEEP_NOTICE, isOn).apply()
        if (isOn) Notifier.showCarrier(context)
    }

    fun setDelivery(context: Context, delivery: Delivery) {
        preferences(context).edit().putString(DELIVERY, delivery.name).apply()
        apply(context)
    }

    fun setDelayed(context: Context, isOn: Boolean) {
        preferences(context).edit().putBoolean(DELAYED, isOn).apply()
        apply(context)
    }

    /** Puts the carriers of the mode in place: the token, the poll, the clock. */
    fun apply(context: Context) {
        val app = context.applicationContext
        // The carrier and the run with no view follow the mode.
        Core.modeIs(app, mode(app))

        when (mode(app)) {
            NotifyMode.Instant -> {
                cancelClock(app)
                Core.setWatch(false)
                WakeStore.deleteWatch(app)
                Push.opened(app)
                Poll.schedule(app)
                Core.refreshWake(app)
            }
            NotifyMode.Direct -> {
                // NTF-139: no token, thus no party of the push path. The
                // watch of a locked client takes the blobs (`NTF-142`).
                Core.clearPushToken()
                Push.closed(app)
                Core.setWatch(true)
                cancelClock(app)
                Poll.schedule(app)
                Core.refreshWake(app)
            }
            NotifyMode.Private -> {
                // NTF-039: no token, thus no push of high priority.
                Core.clearPushToken()
                Core.setWatch(false)
                Push.closed(app)
                // NTF-137: no push, thus no wake table.
                WakeStore.delete(app)
                Work.getInstance(app).cancelUniqueWork(Poll.NAME)
                drawPhase(app)
                scheduleClock(app)
            }
            NotifyMode.Off -> {
                Core.clearPushToken()
                Core.setWatch(false)
                Push.closed(app)
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

    /** NTF-053: a new ingress relay pair draws a new phase for Private mode. */
    fun ingressChanged(context: Context) {
        val app = context.applicationContext
        if (mode(app) != NotifyMode.Private) return

        drawPhase(app)
        scheduleClock(app)
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
    var delivery by remember { mutableStateOf(Modes.delivery(context)) }
    var isDelayed by remember { mutableStateOf(Modes.isDelayed(context)) }
    var showsSender by remember { mutableStateOf(Modes.showsSender(context)) }
    var showsText by remember { mutableStateOf(Modes.showsText(context)) }
    var keepsNotice by remember { mutableStateOf(Modes.keepsNotice(context)) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_notifications), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            for (choice in Modes.offered(context)) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) {
                            delivery = choice
                            Modes.setDelivery(context, choice)
                        }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = delivery == choice)
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

                // The battery line stays here after the card of the chat list went.
                if (choice == Delivery.Direct && delivery == choice && !isDelayed && Battery.state != BatteryState.Unrestricted) {
                    Text(
                        batteryLine(),
                        style = MaterialTheme.typography.bodySmall,
                        color = Palette.TextSecondary,
                        modifier = Modifier.padding(start = PressInset + 34.dp),
                    )
                    InlineButton(
                        stringResource(R.string.battery_allow),
                        modifier = Modifier.padding(start = PressInset + 34.dp, bottom = 12.dp),
                    ) { Battery.open(context) }
                }
                HorizontalDivider(color = Palette.Divider)
            }

            // NTF-147: the delay is its own switch, and None takes none.
            if (delivery == Delivery.Direct) {
                ToggleRow(stringResource(R.string.modes_delayed), isDelayed) {
                    isDelayed = it
                    Modes.setDelayed(context, it)
                }
                Text(
                    stringResource(R.string.umbra_ui_ntf_009_private),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                    modifier = Modifier.padding(start = PressInset, end = PressInset, bottom = 12.dp),
                )
                HorizontalDivider(color = Palette.Divider)
            }

            // NTF-082: the controls of the high-risk configuration sit on
            // this one screen.
            ToggleRow(stringResource(R.string.modes_show_sender), showsSender) {
                showsSender = it
                Modes.setShowsSender(context, it)
            }
            HorizontalDivider(color = Palette.Divider)
            ToggleRow(stringResource(R.string.modes_show_text), showsText) {
                showsText = it
                Modes.setShowsText(context, it)
            }
            HorizontalDivider(color = Palette.Divider)
            ToggleRow(stringResource(R.string.modes_keep_notice), keepsNotice) {
                keepsNotice = it
                Modes.setKeepNotice(context, it)
            }
            HorizontalDivider(color = Palette.Divider)
        }
    }
}
