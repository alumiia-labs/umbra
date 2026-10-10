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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/** The notification settings of Part 7 §7.5.9, as the core numbers them. */
const val ALERT_ALL: UByte = 0u
const val ALERT_MENTIONS: UByte = 1u
const val ALERT_NONE: UByte = 2u

/** The words of one setting. */
fun alertLabel(value: UByte): String = when (value) {
    ALERT_MENTIONS -> "Mentions only"
    ALERT_NONE -> "Off"
    else -> "All messages"
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
    val choices = if (chat.isGroup) listOf(ALERT_ALL, ALERT_MENTIONS, ALERT_NONE) else listOf(ALERT_ALL, ALERT_NONE)
    Column(Modifier.fillMaxSize()) {
        BackBar("Notifications", onBack = onBack)
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
        }
    }
}
