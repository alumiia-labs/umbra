package com.alumiialabs.umbra

import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.LifecycleResumeEffect

/** The notification settings of Part 7 §7.5.9, as the core numbers them. */
const val ALERT_ALL: UByte = 0u
const val ALERT_MENTIONS: UByte = 1u
const val ALERT_NONE: UByte = 2u

/** The words of one setting. */
fun alertLabel(value: UByte): String = when (value) {
    ALERT_MENTIONS -> UiText.get(R.string.alerts_mentions_only)
    ALERT_NONE -> UiText.get(R.string.common_off)
    else -> UiText.get(R.string.alerts_all_messages)
}

/**
 * The notification rows of one conversation: the alerts, the priority mark
 * (`DEV-358`), and the sender and the text of an alert (`DEV-344`). Each
 * row except the mark opens a sheet. A pairwise conversation has no
 * mention, thus it offers two alert choices.
 */
@Composable
fun AlertRows(chat: Chat) {
    val context = LocalContext.current
    var alert by remember { mutableStateOf<UByte?>(null) }
    var preview by remember { mutableStateOf<Int?>(null) }
    var priority by remember { mutableStateOf<Boolean?>(null) }
    var editing by remember { mutableStateOf<AlertSheet?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.alertSetting(chat.conversation) { alert = it }
        Core.previewSetting(chat.conversation) { preview = it }
        Core.isPriority(chat.conversation) { priority = it }
    }
    val held = alert ?: return
    val shown = preview ?: return
    val marked = priority ?: return

    // The user can change the channel in the settings of the system and
    // come back, thus each return to the view reads it again.
    var interrupts by remember { mutableStateOf(Notifier.priorityInterrupts(context)) }
    LifecycleResumeEffect(Unit) {
        interrupts = Notifier.priorityInterrupts(context)
        onPauseOrDispose {}
    }

    EntryRow(
        RowEntry("bell", stringResource(R.string.alerts_notify_for), alertLabel(held)) { editing = AlertSheet.Alerts },
        leads = false,
    )
    HorizontalDivider(color = Palette.Divider)
    ToggleRow(
        stringResource(R.string.alerts_priority),
        marked,
        detail = stringResource(
            when {
                !marked -> R.string.alerts_priority_about
                interrupts -> R.string.alerts_priority_interrupts
                else -> R.string.alerts_priority_blocked
            },
        ),
        icon = "bell",
    ) { on ->
        priority = on
        Core.setPriority(context, chat.conversation, on)
        // NTF-155: only the user can let the channel through Do Not
        // Disturb, thus the switch opens its settings.
        if (on && !interrupts) openPriorityChannel(context)
    }
    HorizontalDivider(color = Palette.Divider)
    if (marked && !interrupts) {
        EntryRow(
            RowEntry("triangle-exclamation", stringResource(R.string.alerts_priority_allow)) { openPriorityChannel(context) },
        )
        HorizontalDivider(color = Palette.Divider)
    }
    EntryRow(
        RowEntry("user-group", stringResource(R.string.alerts_sender), previewLabel(shown and 3)) { editing = AlertSheet.Sender },
        leads = false,
    )
    HorizontalDivider(color = Palette.Divider)
    EntryRow(
        RowEntry("comment", stringResource(R.string.alerts_text), previewLabel(shown shr 2 and 3)) { editing = AlertSheet.Text },
        leads = false,
    )

    val close = { editing = null }
    when (val open = editing) {
        AlertSheet.Alerts -> {
            val choices = if (chat.isGroup) listOf(ALERT_ALL, ALERT_MENTIONS, ALERT_NONE) else listOf(ALERT_ALL, ALERT_NONE)
            ChoiceSheet(
                stringResource(R.string.alerts_notify_for),
                choices.map { value ->
                    SheetChoice(alertLabel(value), held == value) {
                        alert = value
                        Core.setAlert(context, chat.conversation, value)
                    }
                },
                onDismiss = close,
            )
        }
        AlertSheet.Sender, AlertSheet.Text -> {
            val shift = if (open == AlertSheet.Sender) 0 else 2
            ChoiceSheet(
                stringResource(if (open == AlertSheet.Sender) R.string.alerts_sender else R.string.alerts_text),
                listOf(PREVIEW_DEFAULT, PREVIEW_SHOW, PREVIEW_HIDE).map { field ->
                    SheetChoice(previewLabel(field), shown shr shift and 3 == field) {
                        val next = shown and (3 shl shift).inv() or (field shl shift)
                        preview = next
                        Core.setPreviewSetting(chat.conversation, next)
                    }
                },
                onDismiss = close,
            )
        }
        null -> Unit
    }
}

private fun openPriorityChannel(context: android.content.Context) {
    runCatching { context.startActivity(Notifier.priorityChannelSettings(context)) }
}

/** The sheets of the notification rows. */
private enum class AlertSheet { Alerts, Sender, Text }

/** The sender and the text of an alert take these values (`DEV-345`). */
const val PREVIEW_DEFAULT = 0
const val PREVIEW_SHOW = 1
const val PREVIEW_HIDE = 2

@Composable
private fun previewLabel(field: Int): String = when (field) {
    PREVIEW_SHOW -> stringResource(R.string.alerts_show)
    PREVIEW_HIDE -> stringResource(R.string.alerts_hide)
    else -> stringResource(R.string.alerts_default)
}
