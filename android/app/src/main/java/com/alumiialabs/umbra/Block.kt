package com.alumiialabs.umbra

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.unit.dp

/**
 * The block of a contact or of a member of a group (Part 13 §13.12). The
 * words state what a block does not do (`ABU-040` to `ABU-042`).
 */
@Composable
fun BlockScreen(
    name: String,
    isBlocked: Boolean?,
    onBack: () -> Unit,
    onSet: (Boolean) -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        BackBar(
            stringResource(if (isBlocked == true) R.string.common_unblock else R.string.common_block),
            onBack = onBack,
        )
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("ban")
            Spacer(Modifier.height(24.dp))
            Headline(stringResource(if (isBlocked == true) R.string.block_unblock_q else R.string.block_block_q, name))
            Spacer(Modifier.height(16.dp))
            isBlocked ?: return@Column
            if (isBlocked) {
                Note(stringResource(R.string.block_unblock_note))
                Spacer(Modifier.height(16.dp))
                PrimaryButton(stringResource(R.string.common_unblock)) { onSet(false) }
            } else {
                Note(
                    UiText.get(R.string.umbra_ui_abu_040) + " " + UiText.get(R.string.umbra_ui_abu_041),
                )
                Spacer(Modifier.height(16.dp))
                DangerButton(stringResource(R.string.common_block)) { onSet(true) }
            }
            QuietButton(stringResource(R.string.common_cancel), onClick = onBack)
        }
    }
}

@Composable
fun BlockContactScreen(chat: Chat, onBack: () -> Unit) {
    val context = LocalContext.current
    var isBlocked by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(chat.conversation) { Core.isBlocked(chat.conversation) { isBlocked = it } }
    BlockScreen(chat.title, isBlocked, onBack) { blocked ->
        Core.setBlocked(context, chat.conversation, blocked)
        onBack()
    }
}

@Composable
fun BlockMemberScreen(chat: Chat, index: UShort, name: String, onBack: () -> Unit) {
    var isBlocked by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(chat.conversation, index) {
        Core.blockedMembers(chat.conversation) { isBlocked = index in it }
    }
    BlockScreen(name, isBlocked, onBack) { blocked ->
        Core.setMemberBlocked(chat.conversation, index, blocked)
        onBack()
    }
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
