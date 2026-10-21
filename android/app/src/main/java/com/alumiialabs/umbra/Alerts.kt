package com.alumiialabs.umbra

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
import androidx.compose.ui.unit.dp

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
 * The notification setting of one conversation. A pairwise conversation
 * has no mention, thus it offers two choices.
 */
@Composable
fun AlertsScreen(chat: Chat, onBack: () -> Unit) {
    val context = LocalContext.current
    var chosen by remember { mutableStateOf<UByte?>(null) }
    LaunchedEffect(chat.conversation) { Core.alertSetting(chat.conversation) { chosen = it } }
    var preview by remember { mutableStateOf<Int?>(null) }
    var editing by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(chat.conversation) { Core.previewSetting(chat.conversation) { preview = it } }
    val choices = if (chat.isGroup) listOf(ALERT_ALL, ALERT_MENTIONS, ALERT_NONE) else listOf(ALERT_ALL, ALERT_NONE)

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_notifications), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            chosen?.let { held ->
                for (value in choices) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .pressShadeInColumn()
                            .press(role = Role.RadioButton) {
                                chosen = value
                                Core.setAlert(context, chat.conversation, value)
                            }
                            .padding(horizontal = PressInset, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioMark(isChosen = held == value)
                        Spacer(Modifier.width(14.dp))
                        Text(alertLabel(value))
                    }
                    HorizontalDivider(color = Palette.Divider)
                }
            }

            // DEV-344: the sender and the text of this conversation.
            preview?.let { held ->
                Spacer(Modifier.height(12.dp))
                EntryRow(RowEntry("eye", stringResource(R.string.alerts_sender), previewLabel(held and 3)) { editing = 0 })
                HorizontalDivider(color = Palette.Divider)
                EntryRow(RowEntry("comment", stringResource(R.string.alerts_text), previewLabel(held shr 2 and 3)) { editing = 2 })
                HorizontalDivider(color = Palette.Divider)

                editing?.let { shift ->
                    ActionSheet(
                        stringResource(if (shift == 0) R.string.alerts_sender else R.string.alerts_text),
                        listOf(PREVIEW_DEFAULT, PREVIEW_SHOW, PREVIEW_HIDE).map { field ->
                            RowEntry(if (held shr shift and 3 == field) "check" else "eye", previewLabel(field)) {
                                val next = held and (3 shl shift).inv() or (field shl shift)
                                preview = next
                                Core.setPreviewSetting(chat.conversation, next)
                            }
                        },
                        onDismiss = { editing = null },
                    )
                }
            }
        }
    }
}

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
