package org.umbra.app

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/** The choices of mockup 108. `IMP-119` caps the idle time at 30 minutes. */
private val AutoLockChoices = listOf(
    0L to ("Immediately" to "When you leave the app"),
    5 * 60L to ("5 minutes" to null),
    15 * 60L to ("15 minutes" to null),
    30 * 60L to ("30 minutes" to null),
)

private fun autoLockLabel(seconds: Long): String = when (seconds) {
    0L -> "When you leave the app"
    else -> "After ${seconds / 60} minutes of inactivity"
}

/** Mockup 106: the settings of the lock. The lock itself is one button of it. */
@Composable
fun AppLockScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar("App lock", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            EntryRow(RowEntry("key", "Change passphrase") { push(Screen.ChangePassphrase) })
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("clock", "Auto-lock", autoLockLabel(Core.autoLockSeconds)) {
                    push(Screen.AutoLock)
                },
            )
            HorizontalDivider(color = Palette.Divider)
            Spacer(Modifier.height(14.dp))
            SecondaryButton("Lock now") { Core.lock() }
            Spacer(Modifier.height(14.dp))
            // A fact that a user cannot know, and that decides the choice above.
            Note("While UMBRA is locked, no message arrives.")
        }
    }
}

/** Mockup 108. */
@Composable
fun AutoLockScreen(onBack: () -> Unit) {
    var chosen by remember { mutableStateOf(Core.autoLockSeconds) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Auto-lock", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            for ((seconds, words) in AutoLockChoices) {
                val (title, detail) = words
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) { chosen = seconds }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = chosen == seconds)
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(title)
                        detail?.let {
                            Text(
                                it,
                                style = MaterialTheme.typography.bodySmall,
                                color = Palette.TextSecondary,
                                modifier = Modifier.subline(),
                            )
                        }
                    }
                }
                HorizontalDivider(color = Palette.Divider)
            }
            Spacer(Modifier.height(14.dp))
            PrimaryButton("Save") {
                Core.setAutoLock(chosen)
                onBack()
            }
        }
    }
}

private val MIB = 1_024uL * 1_024uL

/** The choices of the automatic download limit (`IMP-167`). */
private val AutoDownloadChoices = listOf(
    0uL to "Off",
    1uL * MIB to "Up to 1 MB",
    5uL * MIB to "Up to 5 MB",
    25uL * MIB to "Up to 25 MB",
    100uL * MIB to "Up to 100 MB",
    ULong.MAX_VALUE to "Any size",
)

/** The words of the limit in the row of the settings. */
fun autoDownloadLabel(bytes: ULong, wifiOnly: Boolean): String {
    val limit = AutoDownloadChoices.firstOrNull { it.first == bytes }?.second ?: "Up to ${bytes / MIB} MB"
    return if (wifiOnly && bytes != 0uL) "$limit · Wi-Fi only" else limit
}

/**
 * The automatic download limit of this device (`IMP-167`). A photo, a
 * video, or a file above it shows its preview and its size, and it comes at
 * a tap.
 */
@Composable
fun AutoDownloadScreen(onBack: () -> Unit) {
    var chosen by remember { mutableStateOf(Core.autoDownloadLimit) }
    var wifiOnly by remember { mutableStateOf(Core.autoDownloadWifiOnly) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Automatic download", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            for ((bytes, title) in AutoDownloadChoices) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) { chosen = bytes }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = chosen == bytes)
                    Spacer(Modifier.width(14.dp))
                    Text(title)
                }
                HorizontalDivider(color = Palette.Divider)
            }
            // IMP-168: on mobile data each file waits for a tap, and the
            // files below the limit come when Wi-Fi comes.
            Row(
                Modifier
                    .fillMaxWidth()
                    .pressShadeInColumn()
                    .press(role = Role.Switch) { wifiOnly = !wifiOnly }
                    .padding(horizontal = PressInset, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Only on Wi-Fi", modifier = Modifier.weight(1f))
                SwitchMark(isOn = wifiOnly, enabled = chosen != 0uL)
            }
            HorizontalDivider(color = Palette.Divider)
            Spacer(Modifier.height(14.dp))
            PrimaryButton("Save") {
                Core.setAutoDownload(chosen, wifiOnly)
                onBack()
            }
            Spacer(Modifier.height(14.dp))
            // A fact that a user cannot know, and that decides the choice above.
            Note("A download at a tap shows the relays of the file when you opened the chat.")
        }
    }
}

/**
 * The mark of a switch in the weight of [RadioMark]: a ring track and a
 * dot. The row around it takes the tap.
 */
@Composable
fun SwitchMark(isOn: Boolean, enabled: Boolean = true) {
    val offset by animateDpAsState(if (isOn) 16.dp else 0.dp, label = "switch")
    val tint = if (isOn) Palette.Action else Palette.Outline
    Box(
        Modifier
            .alpha(if (enabled) 1f else 0.4f)
            .size(width = 36.dp, height = 20.dp)
            .background(if (isOn) Palette.Container else Color.Transparent, CircleShape)
            .border(2.dp, tint, CircleShape)
            .padding(4.dp),
    ) {
        Box(Modifier.offset(x = offset).size(12.dp).background(tint, CircleShape))
    }
}

/** The mark of one choice of a list, as the mockups draw it. */
@Composable
fun RadioMark(isChosen: Boolean) {
    Box(
        Modifier
            .size(20.dp)
            .border(2.dp, if (isChosen) Palette.Action else Palette.Outline, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        if (isChosen) Box(Modifier.size(10.dp).background(Palette.Action, CircleShape))
    }
}

/** Mockup 107. Each field gives a `CharArray`, as the unlock field does. */
@Composable
fun ChangePassphraseScreen(onBack: () -> Unit) {
    val current = rememberPlatformField()
    val new = rememberPlatformField()
    val confirm = rememberPlatformField()
    var fault by remember { mutableStateOf<String?>(null) }
    var isWorking by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Change passphrase", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            FramedPlatformField(current, "Current passphrase", isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            FramedPlatformField(new, "New passphrase", isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            FramedPlatformField(confirm, "Confirm new passphrase", isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            PrimaryButton(if (isWorking) "Changing…" else "Change passphrase", enabled = !isWorking) {
                val old = current.take()
                val first = new.take()
                val second = confirm.take()
                fault = when {
                    old == null || first == null || second == null -> "Fill in the three fields."
                    !first.contentEquals(second) -> "The two new passphrases differ."
                    else -> null
                }
                if (fault == null && old != null && first != null) {
                    isWorking = true
                    Core.changePassphrase(old, first) { failure ->
                        isWorking = false
                        fault = failure
                        if (failure == null) onBack()
                    }
                } else {
                    old?.fill('\u0000')
                    first?.fill('\u0000')
                }
                second?.fill('\u0000')
            }
            fault?.let {
                Spacer(Modifier.height(12.dp))
                Note(it, isError = true)
            }
            Spacer(Modifier.height(12.dp))
            Note("Nobody can reset a passphrase that you forget.")
        }
    }
}
