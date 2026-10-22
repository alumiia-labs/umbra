package com.alumiialabs.umbra

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/**
 * The block of a contact or of a member of a group (Part 13 §13.12). The
 * note states what a block does not do (`ABU-040` to `ABU-042`).
 */
@Composable
fun BlockSheet(name: String, isBlocked: Boolean, onSet: (Boolean) -> Unit, onDismiss: () -> Unit) {
    ActionSheet(
        stringResource(if (isBlocked) R.string.block_unblock_q else R.string.block_block_q, name),
        listOf(
            RowEntry("ban", stringResource(if (isBlocked) R.string.common_unblock else R.string.common_block)) {
                onSet(!isBlocked)
            },
        ),
        note = if (isBlocked) {
            stringResource(R.string.block_unblock_note)
        } else {
            UiText.get(R.string.umbra_ui_abu_040) + " " + UiText.get(R.string.umbra_ui_abu_041)
        },
        onDismiss = onDismiss,
    )
}

/** The line of a conversation that a block touches. */
@Composable
fun BlockedLine(chat: Chat) {
    var line by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        if (chat.isGroup) {
            // ABU-038: the view shows the gap that the blocks made.
            Core.discardedCount(chat.conversation) { count ->
                line = when {
                    count == 0uL -> null
                    else -> UiText.plural(R.plurals.block_hidden, count.toInt(), count.toLong())
                }
            }
        } else {
            Core.isBlocked(chat.conversation) { blocked ->
                line = if (blocked) UiText.get(R.string.block_contact_dropped) else null
            }
        }
    }

    val text = line ?: return
    Box(Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 8.dp)) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = Palette.TextSecondary,
            modifier = Modifier.align(Alignment.Center),
        )
    }
}
