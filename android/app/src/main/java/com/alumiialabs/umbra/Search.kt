package com.alumiialabs.umbra

import android.graphics.Typeface
import android.text.SpannableStringBuilder
import android.text.TextUtils
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.util.TypedValue
import android.widget.TextView
import androidx.activity.compose.BackHandler
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
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
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
    if (scope != null) ScreenshotBlock(scope)
    val run = {
        val query = field.copy()
        if (query.all(Char::isWhitespace)) {
            found = null
        } else {
            Core.search(query, scope) { found = it }
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
    LaunchedEffect(typed) { run() }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 4.dp, end = 16.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconAction("arrow-left", "Back", leave)
            Spacer(Modifier.width(4.dp))
            PlatformInput(field, "Search", isPassphrase = false, modifier = Modifier.weight(1f))
        }
        val results = found
        when {
            results == null -> Unit
            results.isEmpty() -> EmptyState("No results.")
            else -> LazyColumn {
                items(results, key = { it.key }) { result ->
                    PressOver(
                        Modifier.fillMaxWidth().pressShadeInList(),
                        onClick = { push(Screen.Chat(result.conversation, result.key)) },
                    ) { ResultRow(result, showsChat = scope == null) }
                }
            }
        }
    }
}

@Composable
private fun ResultRow(result: Core.Found, showsChat: Boolean) {
    val chat = Core.chats.firstOrNull { it.conversation == result.conversation }
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
                Box(Modifier.weight(1f)) {
                    if (showsChat) {
                        Text(
                            chat?.title.orEmpty(),
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                Text(
                    timeLabel(LocalContext.current, result.atMs),
                    style = MaterialTheme.typography.labelSmall,
                    color = Palette.TextSecondary,
                )
            }
            Snippet(result, Modifier.subline())
        }
    }
}

/**
 * The text of a result near its match, with the match in the action color.
 * The text sits in a buffer of the view, and in no `String` (`IMP-037`).
 */
@Composable
private fun Snippet(result: Core.Found, modifier: Modifier = Modifier) {
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
            val lead = if (from > 0) 1 else 0
            val shown = CharArray(lead + text.size - from)
            if (lead == 1) shown[0] = '…'
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
