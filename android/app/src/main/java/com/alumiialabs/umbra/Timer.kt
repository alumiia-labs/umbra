package com.alumiialabs.umbra

import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.ConversationTimer

/** The periods of a conversation timer (`WIR-201`), with their words. */
private val TimerChoices = listOf(
    0u to R.string.common_off,
    30u to R.string.timer_30_seconds,
    300u to R.string.timer_5_minutes,
    3_600u to R.string.timer_1_hour,
    28_800u to R.string.timer_8_hours,
    86_400u to R.string.timer_1_day,
    604_800u to R.string.timer_1_week,
    2_419_200u to R.string.timer_4_weeks,
    7_776_000u to R.string.timer_90_days,
)

/**
 * The words of one period. A period other than "Off" also goes inside a
 * sentence, thus its words need no change of case.
 */
fun timerLabel(seconds: UInt): String =
    TimerChoices.firstOrNull { it.first == seconds }?.second?.let { UiText.get(it) }
        ?: UiText.plural(R.plurals.timer_seconds, seconds.toInt(), seconds.toLong())

/** Who set a timer, for the row of the change (`DEV-206`). */
fun timerAuthor(chat: Chat, isOutgoing: Boolean): String = when {
    isOutgoing -> UiText.get(R.string.common_you)
    chat.isGroup -> UiText.get(R.string.timer_an_admin)
    else -> chat.title
}

/** The words of the row that marks a timer change (`DEV-207`). */
fun timerChangeText(seconds: UInt, who: String): String =
    if (seconds == 0u) {
        UiText.get(R.string.timer_turned_off, who)
    } else {
        UiText.get(R.string.timer_set_to, who, timerLabel(seconds))
    }

/** The preview of a timer change in the list of chats. */
fun timerPreview(seconds: UInt): String =
    if (seconds == 0u) {
        UiText.get(R.string.timer_preview_off)
    } else {
        UiText.get(R.string.timer_preview, timerLabel(seconds))
    }

/** The row of a timer change in a conversation, centred as a notice. */
@Composable
fun TimerLine(line: Line, chat: Chat) {
    val seconds = line.info.timer ?: return
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier
                .background(Palette.Incoming, CircleShape)
                .padding(horizontal = 12.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon("clock", size = 10.dp, tint = Palette.TextSecondary)
            Spacer(Modifier.width(6.dp))
            Text(
                timerChangeText(seconds, timerAuthor(chat, line.info.outgoing)),
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * The timer of one conversation (Part 7 §7.5.8). The view shows who set the
 * current value and when (`DEV-206`), and that a party can keep a copy
 * (`DEV-218`).
 */
@Composable
fun DisappearingScreen(chat: Chat, onBack: () -> Unit) {
    var current by remember { mutableStateOf<ConversationTimer?>(null) }
    var chosen by remember { mutableStateOf(0u) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.timer(chat.conversation) {
            if (current == null) chosen = it.seconds
            current = it
        }
    }
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_disappearing_messages), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            current?.let { now ->
                if (now.setAtMs != 0uL) {
                    val at = DateUtils.formatDateTime(
                        context,
                        now.setAtMs.toLong(),
                        DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_TIME,
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        when {
                            now.byUser -> stringResource(R.string.timer_set_by_you, at)
                            chat.isGroup -> stringResource(R.string.timer_set_by_admin, at)
                            else -> stringResource(R.string.timer_set_by, chat.title, at)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = Palette.TextSecondary,
                        modifier = Modifier.subline(),
                    )
                }
                Spacer(Modifier.height(8.dp))
                for ((seconds, title) in TimerChoices) {
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
                        Text(stringResource(title))
                    }
                    HorizontalDivider(color = Palette.Divider)
                }
                Spacer(Modifier.height(14.dp))
                PrimaryButton(stringResource(R.string.common_save), enabled = chosen != now.seconds) {
                    Core.setTimer(chat.conversation, chosen)
                    onBack()
                }
                Spacer(Modifier.height(14.dp))
                // DEV-218: a fact that the interface must state.
                Note(UiText.get(R.string.umbra_ui_dev_218))
            }
        }
    }
}

/** The time that remains to a timed message, in its largest unit. */
fun leftLabel(seconds: Long): String = UiText.get(R.string.timer_left, spanLabel(seconds))

/** A short time span, the largest unit first. */
fun spanLabel(seconds: Long): String = when {
    seconds < 60 -> UiText.get(R.string.timer_span_seconds, seconds.coerceAtLeast(0))
    seconds < 3_600 -> UiText.get(R.string.timer_span_minutes, seconds / 60)
    seconds < 86_400 -> UiText.get(R.string.timer_span_hours, seconds / 3_600)
    else -> UiText.get(R.string.timer_span_days, seconds / 86_400)
}
