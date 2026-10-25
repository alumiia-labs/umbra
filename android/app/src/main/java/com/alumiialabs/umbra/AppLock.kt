package com.alumiialabs.umbra

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/** The idle times before the lock. `IMP-119` caps the idle time at 30 minutes. */
private val AutoLockChoices = listOf<Pair<Long, Pair<Int, Int?>>>(
    0L to (R.string.lock_immediately to R.string.lock_when_you_leave),
    5 * 60L to (R.string.lock_5_minutes to null),
    15 * 60L to (R.string.lock_15_minutes to null),
    30 * 60L to (R.string.lock_30_minutes to null),
)

/** The words of the idle time in the row of the settings. */
fun autoLockLabel(seconds: Long): String = when (seconds) {
    0L -> UiText.get(R.string.lock_when_you_leave)
    else -> {
        val minutes = seconds / 60
        UiText.plural(R.plurals.lock_after_minutes, minutes.toInt(), minutes)
    }
}

/**
 * The idle time before the lock. The note states whether a message waits
 * while the app is locked, which decides the choice.
 */
@Composable
fun AutoLockSheet(onDismiss: () -> Unit) {
    val context = LocalContext.current

    ChoiceSheet(
        stringResource(R.string.lock_auto_lock),
        AutoLockChoices.map { (seconds, words) ->
            val (title, detail) = words
            SheetChoice(stringResource(title), Core.autoLockSeconds == seconds, detail?.let { stringResource(it) }) {
                Core.setAutoLock(seconds)
            }
        },
        note = stringResource(
            if (alertsWhileLocked(Modes.mode(context))) {
                R.string.lock_message_waits_while_locked
            } else {
                R.string.lock_no_message_while_locked
            },
        ),
        onDismiss = onDismiss,
    )
}

/**
 * Whether a locked client shows that a message waits. Periodic mode holds no
 * connection, and it watches at each tick (Part 8 `NTF-153`). Private mode
 * and Off receive nothing while locked (§8.3).
 */
private fun alertsWhileLocked(mode: NotifyMode): Boolean =
    mode.holdsConnection || mode == NotifyMode.Periodic

private val MIB = 1_024uL * 1_024uL

/** The choices of the automatic download limit (`IMP-167`). */
private val AutoDownloadChoices = listOf(
    0uL,
    1uL * MIB,
    5uL * MIB,
    25uL * MIB,
    100uL * MIB,
    ULong.MAX_VALUE,
)

/** The words of one limit. */
fun downloadLimitLabel(bytes: ULong): String = when (bytes) {
    0uL -> UiText.get(R.string.common_off)
    ULong.MAX_VALUE -> UiText.get(R.string.lock_download_any_size)
    else -> UiText.get(R.string.lock_download_up_to, (bytes / MIB).toLong())
}

/**
 * The automatic download limit of this device (`IMP-167`). A photo, a
 * video, or a file above it shows its preview and its size, and it comes at
 * a tap.
 */
@Composable
fun AutoDownloadSheet(onDismiss: () -> Unit) {
    ChoiceSheet(
        stringResource(R.string.lock_automatic_download),
        AutoDownloadChoices.map { bytes ->
            SheetChoice(downloadLimitLabel(bytes), Core.autoDownloadLimit == bytes) {
                Core.setAutoDownload(bytes, Core.autoDownloadWifiOnly)
            }
        },
        note = stringResource(R.string.lock_download_note),
        onDismiss = onDismiss,
    )
}

/** The mark of one choice of a list. */
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

/** The change of the passphrase. Each field gives a `CharArray`, as the unlock field does. */
@Composable
fun ChangePassphraseScreen(onBack: () -> Unit) {
    val current = rememberPlatformField()
    val new = rememberPlatformField()
    val confirm = rememberPlatformField()
    var fault by remember { mutableStateOf<String?>(null) }
    var isWorking by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_change_passphrase), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            FramedPlatformField(current, stringResource(R.string.lock_current_passphrase), isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            FramedPlatformField(new, stringResource(R.string.common_new_passphrase), isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            FramedPlatformField(confirm, stringResource(R.string.lock_confirm_new_passphrase), isPassphrase = true)

            Spacer(Modifier.height(14.dp))
            PrimaryButton(
                stringResource(if (isWorking) R.string.lock_changing else R.string.common_change_passphrase),
                enabled = !isWorking,
            ) {
                val old = current.take()
                val first = new.take()
                val second = confirm.take()

                fault = when {
                    old == null || first == null || second == null -> UiText.get(R.string.lock_fill_three_fields)
                    !first.contentEquals(second) -> UiText.get(R.string.lock_passphrases_differ)
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
            Note(stringResource(R.string.lock_no_reset))
        }
    }
}
