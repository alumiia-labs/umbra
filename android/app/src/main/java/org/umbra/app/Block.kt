package org.umbra.app

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
        BackBar(if (isBlocked == true) "Unblock" else "Block", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("ban")
            Spacer(Modifier.height(24.dp))
            Headline(if (isBlocked == true) "Unblock $name?" else "Block $name?")
            Spacer(Modifier.height(16.dp))
            isBlocked ?: return@Column
            if (isBlocked) {
                Note("Messages from now on show again. Messages sent while blocked stay gone.")
                Spacer(Modifier.height(16.dp))
                PrimaryButton("Unblock") { onSet(false) }
            } else {
                Note(
                    "They can still send. Their messages reach this device and are dropped " +
                        "unread. They are not told.",
                )
                Spacer(Modifier.height(16.dp))
                DangerButton("Block") { onSet(true) }
            }
            QuietButton("Cancel", onClick = onBack)
        }
    }
}

@Composable
fun BlockContactScreen(chat: Chat, onBack: () -> Unit) {
    var isBlocked by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(chat.conversation) { Core.isBlocked(chat.conversation) { isBlocked = it } }
    BlockScreen(chat.title, isBlocked, onBack) { blocked ->
        Core.setBlocked(chat.conversation, blocked)
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
                    count == 1uL -> "1 message from a blocked member is hidden."
                    else -> "$count messages from blocked members are hidden."
                }
            }
        } else {
            Core.isBlocked(chat.conversation) { blocked ->
                line = if (blocked) "Blocked. Messages from this contact are dropped." else null
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
