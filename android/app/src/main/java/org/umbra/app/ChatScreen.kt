package org.umbra.app

import android.text.format.DateUtils
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.border
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.animateColorAsState

@Composable
fun ChatScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var lines by remember { mutableStateOf(emptyList<Line>()) }
    val listState = rememberLazyListState()
    val conversation = chat.conversation
    // The count of the messages that the user did not see, at the moment the
    // view opened. The read marker moves at once, and the line stays where
    // it was for this visit.
    val unseenAtOpen = remember(conversation) { chat.unread }
    var newFrom by remember(conversation) { mutableStateOf<ULong?>(null) }
    var isPlaced by remember(conversation) { mutableStateOf(false) }
    LaunchedEffect(conversation, Core.revision) {
        Core.load(conversation) { loaded ->
            if (!isPlaced) {
                isPlaced = true
                // The line sits above the oldest of the received messages
                // that the user did not see.
                newFrom = loaded.filter { !it.info.outgoing }
                    .takeLast(unseenAtOpen)
                    .firstOrNull()
                    ?.info?.storedAtMs
            }
            lines = loaded
        }
        // The user looks at the conversation, thus each message is seen.
        Core.markRead(conversation)
    }
    LaunchedEffect(lines.size) {
        if (lines.isEmpty()) return@LaunchedEffect
        val firstNew = lines.indexOfFirst { it.info.storedAtMs == newFrom && !it.info.outgoing }
        // A visit that starts with new messages starts at the line. The
        // item before each message is the chip of the view.
        val isFirstPlacement = listState.firstVisibleItemIndex == 0 && firstNew >= 0
        listState.scrollToItem(if (isFirstPlacement) firstNew else lines.lastIndex + 1)
    }
    val readUpTo = lines.indexOfLast { it.info.outgoing && it.info.delivery.toInt() == READ }
    val composer = rememberPlatformField()
    // The message under the finger, and the message that the composer answers.
    var chosen by remember(conversation) { mutableStateOf<Line?>(null) }
    var answered by remember(conversation) { mutableStateOf<Line?>(null) }
    // The message that a jump from an answer shows for a moment.
    var flashed by remember(conversation) { mutableStateOf<List<Byte>?>(null) }
    val scope = rememberCoroutineScope()
    val jumpTo = { target: List<Byte> ->
        val at = lines.indexOfFirst { it.key == target }
        if (at >= 0) {
            scope.launch {
                // The first item of the list is the chip of the view.
                listState.animateScrollToItem(at + 1)
                flashed = target
                delay(900)
                flashed = null
            }
        }
    }
    chosen?.let { line ->
        ActionSheet(
            "Message",
            listOf(RowEntry("reply", "Reply") { answered = line }),
            onDismiss = { chosen = null },
        )
    }
    Column(Modifier.fillMaxSize()) {
        // The name leads to the details of the contact, and that view holds
        // each action of a conversation. The bar needs no menu beside it.
        BackBar(
            chat.title,
            onBack = onBack,
            isVerified = chat.isVerified,
            onTitle = { push(Screen.ContactDetails(chat.conversation)) },
        )
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
                if (!line.info.outgoing && line.info.storedAtMs == newFrom) NewLabel()
                Bubble(
                    line,
                    chat,
                    isFlashed = flashed == line.key,
                    onQuote = line.quote?.let { quote -> { jumpTo(quote.key) } },
                    onLongPress = { chosen = line },
                )
                // The contact saw each message up to this one. The mark
                // sits under it and under no other, as a read marker does.
                if (index == readUpTo) ReadMark(chat)
            }
        }
        answered?.let { line ->
            ReplyStrip(if (line.info.outgoing) "You" else chat.title, line.text) { answered = null }
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
                        composer.take()?.let {
                            Core.send(conversation, it, answered?.handle)
                            answered = null
                        }
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

/** The line above the first message that the user did not see yet. */
@Composable
private fun NewLabel() {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        HorizontalDivider(Modifier.weight(1f), color = Palette.Action.copy(alpha = 0.35f))
        Text(
            "New",
            style = MaterialTheme.typography.labelMedium,
            color = Palette.Action,
            modifier = Modifier.padding(horizontal = 12.dp),
        )
        HorizontalDivider(Modifier.weight(1f), color = Palette.Action.copy(alpha = 0.35f))
    }
}

@Composable
private fun Bubble(
    line: Line,
    chat: Chat,
    isFlashed: Boolean,
    onQuote: (() -> Unit)?,
    onLongPress: () -> Unit,
) {
    val isOutgoing = line.info.outgoing
    // A jump to a message shows it for a moment, and the mark fades.
    val flash by animateColorAsState(
        if (isFlashed) Palette.Action.copy(alpha = 0.22f) else Color.Transparent,
        tween(durationMillis = if (isFlashed) 120 else 700),
        label = "jump flash",
    )
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start,
    ) {
        // The text is a view of the platform, thus the press area lies above
        // the content, as in a row of the chat list. A press on an answer
        // leads to the message that it answers.
        PressOver(
            Modifier
                .widthIn(max = 300.dp)
                .clip(RoundedCornerShape(16.dp))
                .drawWithContent {
                    drawContent()
                    drawRect(flash)
                },
            onClick = onQuote,
            longLabel = "Message actions",
            onLongClick = onLongPress,
        ) { BubbleContent(line, chat) }
    }
}

@Composable
private fun BubbleContent(line: Line, chat: Chat) {
    val isOutgoing = line.info.outgoing
    Column(
        modifier = Modifier
            .background(if (isOutgoing) Palette.Container else Palette.Incoming)
            // The quote spans the bubble, thus the bubble is as wide as its
            // widest part.
            .width(IntrinsicSize.Max)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.End,
    ) {
        if (line.isReply) {
            val quote = line.quote
            QuoteBlock(
                author = quote?.let { if (it.isOutgoing) "You" else chat.title },
                text = quote?.text,
                modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
            )
        }
        // The text starts at the left edge, and the time sits at the right.
        PlatformText(line.text, Palette.Text, modifier = Modifier.align(Alignment.Start))
        Spacer(Modifier.height(2.dp))
        val clock = DateUtils.formatDateTime(
            LocalContext.current,
            line.info.storedAtMs.toLong(),
            DateUtils.FORMAT_SHOW_TIME,
        )
        // A read message carries no word: the mark under the newest
        // one says it for each of them.
        val state = line.info.delivery.toInt()
        Text(
            if (isOutgoing && state != READ) "$clock · ${deliveryLabel(line.info.delivery)}" else clock,
            style = MaterialTheme.typography.labelSmall,
            color = if (state == FAILED) Palette.Error else Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
    }
}

/**
 * The message that a message answers, as each messenger shows it: a bar in
 * the accent colour, the name of the author, and the start of the text. An
 * answer to a message that this device does not hold has no author
 * (`WIR-173`).
 */
@Composable
private fun QuoteBlock(author: String?, text: CharArray?, modifier: Modifier = Modifier) {
    Row(
        modifier
            .height(IntrinsicSize.Min)
            .clip(RoundedCornerShape(10.dp))
            .background(Palette.Pressed),
    ) {
        Box(Modifier.width(4.dp).fillMaxHeight().background(Palette.Action))
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            if (author != null) {
                Text(
                    author,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Action,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (text == null) {
                Text(
                    "Message not on this device",
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                )
            } else {
                PlatformText(text, Palette.TextSecondary, sizeSp = 13f, maxLines = 2)
            }
        }
    }
}

/** What the composer answers, above the field, with a way to take it back. */
@Composable
private fun ReplyStrip(author: String, text: CharArray, onCancel: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // The arrow says what the block is, before a user reads the name.
        FaIcon("reply", size = 18.dp, tint = Palette.Action)
        Spacer(Modifier.width(12.dp))
        QuoteBlock(author, text, Modifier.weight(1f))
        IconAction("xmark", "Cancel the reply", onCancel)
    }
}

private const val FAILED = 4
private const val READ = 3

/** The small picture of the contact under the newest message that it saw. */
@Composable
private fun ReadMark(chat: Chat) {
    Row(
        Modifier.fillMaxWidth().padding(end = 4.dp, bottom = 2.dp).semantics { contentDescription = "Read" },
        horizontalArrangement = Arrangement.End,
    ) { Avatar(chat, size = 16) }
}

/**
 * The closed list of Part 15 §15.9.1. "Accepted" means that a relay took the
 * record. It does not mean that the contact has it.
 */
private fun deliveryLabel(state: UByte): String = when (state.toInt()) {
    0 -> "Waiting"
    1 -> "Accepted"
    2 -> "Delivered"
    FAILED -> "Not sent"
    // A read message shows the mark of the contact and no word.
    else -> ""
}
