package org.umbra.app

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiPoll

/** `POLL_OPTION_MAX` of Part 6 §6.6.6. */
private const val OPTION_MAX = 12

/** `POLL_GROUP_MAX` of Part 11 §11.10. */
const val POLL_GROUP_MAX = 100

/** The periods of a poll, with their words. */
private val PollPeriods = listOf(
    0u to "No end",
    3_600u to "1 hour",
    86_400u to "1 day",
    604_800u to "1 week",
)

/** The poll composer: a question, 2 to 12 options, and the rules of the vote. */
@Composable
fun NewPollScreen(chat: Chat, onBack: () -> Unit) {
    var question by remember { mutableStateOf("") }
    val options = remember { mutableStateListOf("", "") }
    var multiple by remember { mutableStateOf(false) }
    var period by remember { mutableStateOf(0u) }
    var hidden by remember { mutableStateOf(false) }
    val filled = options.map { it.trim() }.filter { it.isNotEmpty() }
    val isReady = question.isNotBlank() && filled.size >= 2
    Column(Modifier.fillMaxSize()) {
        BackBar("New poll", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = question,
                onValueChange = { question = fit(it, QUESTION_BYTES) },
                label = { Text("Question") },
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            options.forEachIndexed { index, option ->
                OutlinedTextField(
                    value = option,
                    onValueChange = { options[index] = fit(it, OPTION_BYTES) },
                    label = { Text("Option ${index + 1}") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                )
            }
            if (options.size < OPTION_MAX) {
                InlineButton("Add option") { options.add("") }
            }
            Spacer(Modifier.height(8.dp))
            ToggleRow("More than one answer", multiple) { multiple = it }
            HorizontalDivider(color = Palette.Divider)
            Text(
                "Ends",
                style = MaterialTheme.typography.labelLarge,
                color = Palette.TextSecondary,
                modifier = Modifier.padding(top = 16.dp, bottom = 4.dp).subline(),
            )
            for ((seconds, title) in PollPeriods) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) {
                            period = seconds
                            if (seconds == 0u) hidden = false
                        }
                        .padding(horizontal = PressInset, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = period == seconds)
                    Spacer(Modifier.width(14.dp))
                    Text(title)
                }
            }
            HorizontalDivider(color = Palette.Divider)
            // A count that stays hidden needs an end.
            if (period != 0u) {
                ToggleRow("Hide results until it ends", hidden) { hidden = it }
                HorizontalDivider(color = Palette.Divider)
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton("Send", enabled = isReady) {
                Core.sendPoll(chat.conversation, question.trim(), filled, multiple, hidden, period)
                onBack()
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

/** `POLL_QUESTION_MAX` and `POLL_OPTION_TEXT_MAX` of §6.6.6, in bytes. */
private const val QUESTION_BYTES = 200
private const val OPTION_BYTES = 100

/** The text cut to `bytes` of UTF-8, at the end of a whole character. */
private fun fit(text: String, bytes: Int): String {
    var kept = text
    while (kept.toByteArray(Charsets.UTF_8).size > bytes) {
        kept = kept.dropLast(if (kept.length >= 2 && kept[kept.length - 1].isLowSurrogate()) 2 else 1)
    }
    return kept
}

/**
 * A poll in its bubble: the question, each option with its share, and the
 * count that this device holds. A group has no order across senders, thus
 * the count is the local view and the bubble says so (`GRP-148`).
 */
@Composable
fun PollContent(line: Line, poll: FfiPoll, modifier: Modifier = Modifier) {
    val canVote = !poll.closed && !line.info.deleted
    val top = poll.counts.maxOrNull()?.takeIf { it > 0u } ?: 1u
    val chosen = poll.mine.map { it.toUByte() }
    Column(modifier.widthIn(min = 240.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FaIcon("chart-bar", size = 14.dp, tint = Palette.TextSecondary)
            Spacer(Modifier.width(8.dp))
            Text(
                if (poll.multiple) "Poll · one or more" else "Poll · one answer",
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(poll.question, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(8.dp))
        poll.options.forEachIndexed { index, option ->
            val choice = index.toUByte()
            val isMine = choice in chosen
            val count = poll.counts.getOrNull(index)
            Column(
                Modifier
                    .fillMaxWidth()
                    .then(
                        if (canVote) {
                            Modifier.press(role = if (poll.multiple) Role.Checkbox else Role.RadioButton) {
                                val next = when {
                                    !poll.multiple -> listOf(choice)
                                    isMine -> chosen.filter { it != choice }
                                    else -> (chosen + choice).sorted()
                                }
                                // A vote takes one option at least (WIR-186).
                                if (next.isNotEmpty() && next != chosen) Core.vote(line.handle, next)
                            }
                        } else {
                            Modifier
                        },
                    )
                    .padding(vertical = 6.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ChoiceMark(isMine, poll.multiple)
                    Spacer(Modifier.width(10.dp))
                    Text(option, modifier = Modifier.weight(1f))
                    if (count != null) {
                        Spacer(Modifier.width(8.dp))
                        Text(
                            count.toString(),
                            style = MaterialTheme.typography.labelLarge,
                            color = Palette.TextSecondary,
                        )
                    }
                }
                if (count != null) {
                    Spacer(Modifier.height(4.dp))
                    Box(
                        Modifier
                            .padding(start = 28.dp)
                            .fillMaxWidth()
                            .height(4.dp)
                            .background(Palette.Divider, RoundedCornerShape(2.dp)),
                    ) {
                        Box(
                            Modifier
                                .fillMaxWidth(count.toFloat() / top.toFloat())
                                .fillMaxHeight()
                                .background(Palette.Action, RoundedCornerShape(2.dp)),
                        )
                    }
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            pollFooter(poll),
            style = MaterialTheme.typography.labelSmall,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
    }
}

/** The mark of one option: a circle for one answer, a square for more. */
@Composable
private fun ChoiceMark(isChosen: Boolean, isSquare: Boolean) {
    val shape = if (isSquare) RoundedCornerShape(4.dp) else CircleShape
    Box(
        Modifier
            .size(18.dp)
            .border(2.dp, if (isChosen) Palette.Action else Palette.Outline, shape),
        contentAlignment = Alignment.Center,
    ) {
        if (isChosen) Box(Modifier.size(10.dp).background(Palette.Action, shape))
    }
}

/** The state of a poll under its options: the local count, and the end. */
private fun pollFooter(poll: FfiPoll): String {
    val votes = if (poll.voters == 1u) "1 vote" else "${poll.voters} votes"
    val end = when {
        poll.closed -> "Ended"
        poll.closesAt == 0uL -> null
        else -> "Ends in " + leftLabel(poll.closesAt.toLong() - System.currentTimeMillis() / 1_000)
            .removeSuffix(" left")
    }
    val hidden = if (poll.hidden && !poll.closed) "Results at the end" else null
    // GRP-148: the count is what this device holds.
    return listOfNotNull("$votes on this device", hidden, end).joinToString(" · ")
}
