package org.umbra.app

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.Hop

/** The three states of the link that the top bar and the view show. */
enum class LinkState { Connected, Connecting, Down }

private val Amber = Color(0xFFB07A1E)

/**
 * The live state of the connection in the top bar: a dot, and the count of
 * the relays that the circuits of this device use. It leads to the view of
 * the connection. A dot that waits for a circuit pulses.
 */
@Composable
fun ConnectionStatus(onOpen: () -> Unit) {
    val state = Core.linkState
    val words = when (state) {
        LinkState.Connected -> relayCount(Core.connection?.relaysInUse?.toInt() ?: 0)
        LinkState.Connecting -> "Connecting"
        LinkState.Down -> "Offline"
    }
    Row(
        Modifier
            .clip(RoundedCornerShape(16.dp))
            .press(role = Role.Button, label = "Connection") { onOpen() }
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusDot(state)
        Spacer(Modifier.width(7.dp))
        Text(words, style = MaterialTheme.typography.labelMedium, color = Palette.TextSecondary)
    }
}

@Composable
private fun StatusDot(state: LinkState) {
    val tint = when (state) {
        LinkState.Connected -> Palette.Action
        LinkState.Connecting -> Amber
        LinkState.Down -> Palette.Error
    }
    val pulse = rememberInfiniteTransition(label = "connecting")
    val faded by pulse.animateFloat(
        initialValue = 1f,
        targetValue = 0.25f,
        animationSpec = infiniteRepeatable(tween(durationMillis = 800), RepeatMode.Reverse),
        label = "dot",
    )
    Box(
        Modifier
            .size(8.dp)
            .alpha(if (state == LinkState.Connecting) faded else 1f)
            .background(tint, CircleShape),
    )
}

private fun relayCount(count: Int) = if (count == 1) "1 relay" else "$count relays"

private fun place(hop: Hop) = "${hop.host} · ${hop.country}"

/** Mockup 120. */
@Composable
fun ConnectionScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val connection = Core.connection
    val state = Core.linkState
    Column(Modifier.fillMaxSize()) {
        BackBar("Connection", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            HeroIcon("wifi")
            Spacer(Modifier.height(20.dp))
            val circuits = connection?.circuits.orEmpty()
            Headline(
                when (state) {
                    LinkState.Connected -> "Connected"
                    LinkState.Connecting -> "Connecting"
                    LinkState.Down -> "No connection"
                },
                when {
                    state == LinkState.Down -> Core.linkFault
                    connection == null -> null
                    else -> "${connection.relaysInUse} of ${connection.relaysKnown} relays in " +
                        if (circuits.size == 1) "1 circuit" else "${circuits.size} circuits"
                },
            )
            Spacer(Modifier.height(10.dp))
            connection?.ingress?.let {
                FactRow("globe", "Ingress relay", place(it))
                HorizontalDivider(color = Palette.Divider)
            }
            connection?.standby?.let {
                FactRow("globe", "Standby relay", place(it))
                HorizontalDivider(color = Palette.Divider)
            }
            circuits.forEachIndexed { index, hops ->
                FactRow("route", "Circuit ${index + 1}", hops.joinToString(" → ") { it.country })
                HorizontalDivider(color = Palette.Divider)
            }
            val epoch = connection?.directoryEpoch?.toLong() ?: 0L
            FactRow(
                "file-lines",
                "Relay directory",
                when {
                    epoch == 0L -> "Not signed"
                    BuildNetwork.isClockCorrected -> "Signed · the device clock differs"
                    else -> "Signed · current"
                },
            )
            HorizontalDivider(color = Palette.Divider)
            Spacer(Modifier.height(16.dp))
            SecondaryButton("Reconnect") { Core.connect(context) }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** A row with a line icon, a title and a smaller line. It leads nowhere. */
@Composable
private fun FactRow(icon: String, title: String, detail: String) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = PressInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon(icon, size = 20.dp, tint = Palette.Text)
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(title)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
    }
}
