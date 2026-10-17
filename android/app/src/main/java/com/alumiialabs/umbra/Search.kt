package com.alumiialabs.umbra

import android.graphics.Typeface
import android.text.SpannableStringBuilder
import android.text.TextUtils
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.util.TypedValue
import android.widget.TextView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.delay
import java.nio.CharBuffer

/** The characters of a result line before its match. */
private const val SNIPPET_LEAD = 24

/** The wait after a change of a message before the index builds again. */
private const val REBUILD_WAIT_MS = 400L

private const val DAY_MS = 86_400_000L

/** One value of a limit of the search, with the resource of its word and its icon. */
private class Choice(val label: Int, val icon: String, val value: Int)

private val ORDERS = listOf(
    Choice(R.string.search_best_match, "magnifying-glass", 0),
    Choice(R.string.search_newest, "clock", 1),
    Choice(R.string.search_oldest, "hourglass-half", 2),
)

private val SIDES = listOf(
    Choice(R.string.search_from_anyone, "user-group", 0),
    Choice(R.string.search_from_you, "paper-plane", 1),
    Choice(R.string.search_from_others, "comment", 2),
)

private val KINDS = listOf(
    Choice(R.string.search_all_messages, "comment", 0),
    Choice(R.string.search_files, "file", 1),
)

private val AGES = listOf(
    Choice(R.string.search_any_time, "clock", 0),
    Choice(R.string.search_last_7_days, "clock", 7),
    Choice(R.string.search_last_30_days, "clock", 30),
    Choice(R.string.search_last_year, "clock", 365),
)

/**
 * The search of the messages of one conversation, or of each one (Part 14
 * §14.6.7). The index sits in the memory of the core, and it leaves with
 * this view and at a lock.
 */
@Composable
fun SearchScreen(scope: Conversation?, onBack: () -> Unit, push: (Screen) -> Unit) {
    val field = rememberPlatformField()
    var found by remember { mutableStateOf<List<Core.Found>?>(null) }
    var typed by remember { mutableIntStateOf(0) }
    var isFirstBuild by remember { mutableStateOf(true) }
    var order by remember { mutableIntStateOf(0) }
    var side by remember { mutableIntStateOf(0) }
    var kind by remember { mutableIntStateOf(0) }
    var age by remember { mutableIntStateOf(0) }
    // The names of the members of each group that a result is from.
    var members by remember { mutableStateOf(emptyMap<Conversation, Map<UShort, String>>()) }

    val listState = rememberLazyListState()
    // A new query or a new limit gives a new list, which starts at its top.
    LaunchedEffect(found) { listState.scrollToItem(0) }

    val run = {
        val query = field.copy()
        if (query.all(Char::isWhitespace)) {
            found = null
        } else {
            val since = if (age == 0) 0L else System.currentTimeMillis() - age * DAY_MS
            Core.search(query, scope, Core.SearchLimits(order, side, kind == 1, since)) { found = it }
        }
        query.fill('\u0000')
    }

    // The user leaves the search, thus the index and the query go. A tap on
    // a result keeps both: Back from the conversation shows the results.
    val leave = {
        Core.searchClose()
        onBack()
    }
    BackHandler(onBack = leave)

    LaunchedEffect(Unit) {
        Core.searchQueryOf(scope)?.let { field.set(it) }
        field.onChange = { typed++ }
        field.focus()
    }

    // A message that came, changed, or went is in the next build.
    LaunchedEffect(Core.revision) {
        if (!isFirstBuild) delay(REBUILD_WAIT_MS)
        isFirstBuild = false
        Core.searchBuild { run() }
    }

    // A query in the time of a build reads the part that is ready.
    LaunchedEffect(typed, order, side, kind, age) { run() }

    LaunchedEffect(found) {
        val groups = found.orEmpty().map { it.conversation }.distinct().filter { conversation ->
            conversation !in members && Core.chats.any { it.conversation == conversation && it.isGroup }
        }

        for (group in groups) {
            Core.groupMembers(group) { loaded ->
                members = members + (
                    group to loaded.associate { member ->
                        val title = member.contact?.let { contact ->
                            Core.chats.firstOrNull { it.conversation.id.contentEquals(contact) }?.title
                        }
                        member.index to (title ?: UiText.get(R.string.common_member_number, member.index.toInt()))
                    }
                )
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 4.dp, end = 16.dp, top = 8.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconAction("arrow-left", stringResource(R.string.common_back), leave)
            Spacer(Modifier.width(4.dp))
            PlatformInput(field, stringResource(R.string.common_search), isPassphrase = false, modifier = Modifier.weight(1f))
        }

        Row(
            Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LimitChip(stringResource(R.string.search_sort), ORDERS, order) { order = it }
            LimitChip(stringResource(R.string.search_from), SIDES, side) { side = it }
            LimitChip(stringResource(R.string.search_show), KINDS, kind) { kind = it }
            LimitChip(stringResource(R.string.search_date), AGES, age) { age = it }
        }

        val results = found
        when {
            results == null -> Unit
            results.isEmpty() -> EmptyState(stringResource(R.string.search_no_results))
            else -> LazyColumn(state = listState) {
                items(results, key = { it.key }) { result ->
                    PressOver(
                        Modifier.fillMaxWidth().pressShadeInList(),
                        onClick = { push(Screen.Chat(result.conversation, result.key)) },
                    ) { ResultRow(result, showsChat = scope == null, members[result.conversation]) }
                }
            }
        }
    }
}

/** One limit of the search: its current value, and a sheet with each value. */
@Composable
private fun LimitChip(title: String, choices: List<Choice>, current: Int, onPick: (Int) -> Unit) {
    var isOpen by remember { mutableStateOf(false) }
    val chosen = choices.firstOrNull { it.value == current } ?: choices.first()
    // A limit that is not the default shows in the color of a selection.
    val isSet = chosen !== choices.first()

    Box(
        Modifier
            .clip(CircleShape)
            .background(if (isSet) Palette.Container else Palette.Incoming)
            .press(role = Role.Button, label = title) { isOpen = true }
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(
            stringResource(chosen.label),
            style = MaterialTheme.typography.labelLarge,
            fontWeight = if (isSet) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 1,
        )
    }

    if (isOpen) {
        val selected = stringResource(R.string.search_selected)
        val labels = choices.map { stringResource(it.label) }
        ActionSheet(
            title,
            choices.mapIndexed { index, choice ->
                RowEntry(choice.icon, labels[index], if (choice === chosen) selected else null) {
                    onPick(choice.value)
                }
            },
            onDismiss = { isOpen = false },
        )
    }
}

/** The name of the sender of a result. */
private fun senderOf(result: Core.Found, chat: Chat?, names: Map<UShort, String>?): String = when {
    result.isOutgoing -> UiText.get(R.string.common_you)
    chat?.isGroup == true -> result.sender
        ?.let { names?.get(it) ?: UiText.get(R.string.common_member_number, it.toInt()) }
        ?: chat.title
    else -> chat?.title.orEmpty()
}

@Composable
private fun ResultRow(result: Core.Found, showsChat: Boolean, names: Map<UShort, String>?) {
    val chat = Core.chats.firstOrNull { it.conversation == result.conversation }
    val sender = senderOf(result, chat, names)

    Row(
        Modifier.fillMaxWidth().padding(horizontal = PressInset, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (showsChat && chat != null) {
            Avatar(chat)
            Spacer(Modifier.width(14.dp))
        }
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // A search of one conversation names the sender here. A
                // search of each one names the conversation.
                Text(
                    if (showsChat) chat?.title.orEmpty() else sender,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    timeLabel(LocalContext.current, result.atMs),
                    style = MaterialTheme.typography.labelSmall,
                    color = Palette.TextSecondary,
                )
            }

            // The contact of a conversation of two is its title, thus the
            // line repeats no name for it.
            val showsSender = showsChat && (result.isOutgoing || chat?.isGroup == true)
            Snippet(result, if (showsSender) stringResource(R.string.search_sender_prefix, sender) else "", Modifier.subline())
        }
    }
}

/**
 * The text of a result near its match, with the match in the action color.
 * The text sits in a buffer of the view, and in no `String` (`IMP-037`).
 */
@Composable
private fun Snippet(result: Core.Found, prefix: String, modifier: Modifier = Modifier) {
    val color = Palette.TextSecondary.toArgb()
    val markColor = Palette.Action.toArgb()

    AndroidView(
        modifier = modifier,
        factory = { context ->
            TextView(context).apply {
                styleAsApp(this)
                ellipsize = TextUtils.TruncateAt.END
                maxLines = 2
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            }
        },
        update = { view ->
            view.setTextColor(color)

            val text = result.text
            // A long text starts a little before its match. A pair of
            // surrogates stays whole.
            var from = if (result.start > SNIPPET_LEAD + 4) result.start - SNIPPET_LEAD else 0
            if (from in 1 until text.size && text[from].isLowSurrogate()) from++

            val lead = prefix.length + if (from > 0) 1 else 0
            val shown = CharArray(lead + text.size - from)
            prefix.toCharArray(shown, 0, 0, prefix.length)
            if (from > 0) shown[prefix.length] = '…'
            for (at in from until text.size) {
                val char = text[at]
                shown[lead + at - from] = if (char == '\n' || char == '\r') ' ' else char
            }

            val line = SpannableStringBuilder(CharBuffer.wrap(shown))
            val start = result.start - from + lead
            val end = result.end - from + lead
            if (start in 0 until end && end <= shown.size) {
                line.setSpan(ForegroundColorSpan(markColor), start, end, 0)
                line.setSpan(StyleSpan(Typeface.BOLD), start, end, 0)
            }

            view.text = line
            shown.fill('\u0000')
        },
    )
}
