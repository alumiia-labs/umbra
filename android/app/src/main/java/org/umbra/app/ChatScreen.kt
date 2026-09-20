package org.umbra.app

import android.text.format.DateUtils
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

@Composable
fun ChatScreen(chat: Chat, onBack: () -> Unit) {
    var isRenaming by remember { mutableStateOf(false) }
    if (isRenaming) {
        BackHandler { isRenaming = false }
        RenameContactScreen(chat) { isRenaming = false }
        return
    }
    var lines by remember { mutableStateOf(emptyList<Line>()) }
    val listState = rememberLazyListState()
    val conversation = chat.conversation
    LaunchedEffect(conversation, Core.revision) {
        Core.load(conversation) { lines = it }
        // The user looks at the conversation, thus each message is seen.
        Core.markRead(conversation)
    }
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    val composer = rememberPlatformField()
    Column(Modifier.fillMaxSize()) {
        BackBar(chat.title, onBack = onBack) {
            OverflowMenu(listOf("Edit contact" to { isRenaming = true }))
        }
        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
        ) {
            item {
                // One line, and no more: the top of a conversation is for
                // its messages.
                Box(Modifier.fillMaxWidth().padding(top = 8.dp), contentAlignment = Alignment.Center) {
                    Row(
                        Modifier
                            .background(Palette.Incoming, CircleShape)
                            .padding(horizontal = 12.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FaIcon("lock", size = 10.dp, tint = Palette.TextSecondary)
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "End-to-end encrypted",
                            style = MaterialTheme.typography.labelSmall,
                            color = Palette.TextSecondary,
                        )
                    }
                }
            }
            itemsIndexed(lines) { index, line ->
                val before = lines.getOrNull(index - 1)
                if (before == null || !isSameDay(before.info.storedAtMs, line.info.storedAtMs)) {
                    DayLabel(line.info.storedAtMs.toLong())
                }
                Bubble(line)
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp)
                    .background(Palette.Incoming, RoundedCornerShape(24.dp))
                    .padding(horizontal = 18.dp, vertical = 12.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                // With no network the record waits in the store.
                PlatformInput(
                    composer,
                    hint = "Message",
                    isPassphrase = false,
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 5,
                )
            }
            Spacer(Modifier.width(8.dp))
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(Palette.Action)
                    .clickable(role = Role.Button, onClickLabel = "Send") {
                        composer.take()?.let { Core.send(conversation, it) }
                    },
                contentAlignment = Alignment.Center,
            ) { FaIcon("paper-plane", label = "Send", size = 18.dp, tint = Color.White) }
        }
    }
}

private fun isSameDay(a: ULong, b: ULong): Boolean {
    val day = DateUtils.DAY_IN_MILLIS
    val zone = java.util.TimeZone.getDefault()
    val dayOf = { at: Long -> (at + zone.getOffset(at)) / day }
    return dayOf(a.toLong()) == dayOf(b.toLong())
}

@Composable
private fun DayLabel(atMs: Long) {
    val context = LocalContext.current
    val label = if (DateUtils.isToday(atMs)) {
        "Today"
    } else {
        DateUtils.formatDateTime(context, atMs, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_WEEKDAY)
    }
    Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = Palette.TextSecondary)
    }
}

@Composable
private fun Bubble(line: Line) {
    val isOutgoing = line.info.outgoing
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .background(
                    if (isOutgoing) Palette.Container else Palette.Incoming,
                    RoundedCornerShape(16.dp),
                )
                .padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.End,
        ) {
            PlatformText(line.text, Palette.Text)
            Spacer(Modifier.height(2.dp))
            val clock = DateUtils.formatDateTime(
                LocalContext.current,
                line.info.storedAtMs.toLong(),
                DateUtils.FORMAT_SHOW_TIME,
            )
            Text(
                if (isOutgoing) "$clock · ${deliveryLabel(line.info.delivery)}" else clock,
                style = MaterialTheme.typography.labelSmall,
                color = if (line.info.delivery.toInt() == FAILED) Palette.Error else Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
    }
}

private const val FAILED = 4

/**
 * The closed list of Part 15 §15.9.1. "Accepted" means that a relay took the
 * record. It does not mean that the contact has it.
 */
private fun deliveryLabel(state: UByte): String = when (state.toInt()) {
    0 -> "Waiting"
    1 -> "Accepted"
    2 -> "Delivered"
    3 -> "Read"
    else -> "Not sent"
}
