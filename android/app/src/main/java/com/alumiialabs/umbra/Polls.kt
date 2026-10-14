package com.alumiialabs.umbra

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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiPoll

/** `POLL_OPTION_MAX` of Part 6 §6.6.6. */
private const val OPTION_MAX = 12

/** `POLL_GROUP_MAX` of Part 11 §11.10. */
const val POLL_GROUP_MAX = 100

/** The periods of a poll, with their words. */
private val PollPeriods = listOf(
    0u to R.string.common_no_end,
    3_600u to R.string.poll_one_hour,
    86_400u to R.string.poll_one_day,
    604_800u to R.string.poll_one_week,
)

/** `POLL_OPEN_MIN` and `POLL_OPEN_MAX` of Part 6 §6.6.6, in seconds. */
private const val OPEN_MIN = 300L
private const val OPEN_MAX = 2_592_000L

/** The units of a custom period, with their seconds. */
private val PeriodUnits = listOf(R.string.poll_unit_minutes to 60L, R.string.poll_unit_hours to 3_600L, R.string.poll_unit_days to 86_400L)

/** The poll composer: a question, 2 to 12 options, and the rules of the vote. */
@Composable
fun NewPollScreen(chat: Chat, onBack: () -> Unit) {
    var question by remember { mutableStateOf("") }
    val options = remember { mutableStateListOf("", "") }
    var multiple by remember { mutableStateOf(false) }
    var period by remember { mutableStateOf(0u) }
    var hidden by remember { mutableStateOf(false) }
    // A period that the user sets: a count and a unit.
    var isCustom by remember { mutableStateOf(false) }
    var count by remember { mutableStateOf("") }
    var unit by remember { mutableStateOf(1) }
    val custom = (count.toLongOrNull() ?: 0L) * PeriodUnits[unit].second
    // WIR-557: a period inside the two bounds.
    val isInBounds = custom in OPEN_MIN..OPEN_MAX
    val openSeconds = if (isCustom) custom.coerceIn(0L, OPEN_MAX).toUInt() else period
    val filled = options.map { it.trim() }.filter { it.isNotEmpty() }
    val isReady = question.isNotBlank() && filled.size >= 2 && (!isCustom || isInBounds)
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.poll_new_poll), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = question,
                onValueChange = { question = fit(it, QUESTION_BYTES) },
                label = { Text(stringResource(R.string.poll_question)) },
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            options.forEachIndexed { index, option ->
                Row(Modifier.padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = option,
                        onValueChange = { options[index] = fit(it, OPTION_BYTES) },
                        label = { Text(stringResource(R.string.poll_option_number, index + 1)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                        modifier = Modifier.weight(1f),
                    )
                    // WIR-180: a poll holds two options at the least.
                    if (options.size > 2) {
                        IconAction("xmark", stringResource(R.string.poll_remove_option_number, index + 1)) { options.removeAt(index) }
                    }
                }
            }
            if (options.size < OPTION_MAX) {
                InlineButton(stringResource(R.string.poll_add_option)) { options.add("") }
            }
            Spacer(Modifier.height(8.dp))
            ToggleRow(stringResource(R.string.poll_more_than_one_answer), multiple) { multiple = it }
            HorizontalDivider(color = Palette.Divider)
            Text(
                stringResource(R.string.poll_ends),
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
                            isCustom = false
                            period = seconds
                            if (seconds == 0u) hidden = false
                        }
                        .padding(horizontal = PressInset, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = !isCustom && period == seconds)
                    Spacer(Modifier.width(14.dp))
                    Text(stringResource(title))
                }
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .pressShadeInColumn()
                    .press(role = Role.RadioButton) { isCustom = true }
                    .padding(horizontal = PressInset, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioMark(isChosen = isCustom)
                Spacer(Modifier.width(14.dp))
                Text(stringResource(R.string.poll_custom))
            }
            if (isCustom) {
                Row(Modifier.padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = count,
                        onValueChange = { typed -> count = typed.filter(Char::isDigit).take(5) },
                        label = { Text(stringResource(R.string.poll_number)) },
                        singleLine = true,
                        isError = count.isNotEmpty() && !isInBounds,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.width(120.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    PeriodUnits.forEachIndexed { index, (title, _) ->
                        val shape = RoundedCornerShape(12.dp)
                        Box(
                            Modifier
                                .padding(end = 6.dp)
                                .clip(shape)
                                .background(if (unit == index) Palette.Container else Palette.Surface)
                                .border(1.dp, if (unit == index) Palette.Action else Palette.Outline, shape)
                                .press(role = Role.RadioButton) { unit = index }
                                .padding(horizontal = 10.dp, vertical = 10.dp),
                        ) { Text(stringResource(title), style = MaterialTheme.typography.labelLarge) }
                    }
                }
                Text(
                    stringResource(R.string.poll_period_bounds),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (count.isNotEmpty() && !isInBounds) Palette.Error else Palette.TextSecondary,
                    modifier = Modifier.padding(bottom = 8.dp).subline(),
                )
            }
            HorizontalDivider(color = Palette.Divider)
            // A count that stays hidden needs an end.
            if (isCustom || period != 0u) {
                ToggleRow(stringResource(R.string.poll_hide_results_until_end), hidden) { hidden = it }
                HorizontalDivider(color = Palette.Divider)
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.common_send), enabled = isReady) {
                Core.sendPoll(chat.conversation, question.trim(), filled, multiple, hidden, openSeconds)
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
                stringResource(if (poll.multiple) R.string.poll_kind_multiple else R.string.poll_kind_single),
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
    val voters = poll.voters.toInt()
    // GRP-148: the count is what this device holds.
    val votes = UiText.plural(R.plurals.poll_votes_on_device, voters, voters)
    val end = when {
        poll.closed -> UiText.get(R.string.poll_ended)
        poll.closesAt == 0uL -> null
        else -> UiText.get(
            R.string.poll_ends_in,
            spanLabel(poll.closesAt.toLong() - System.currentTimeMillis() / 1_000),
        )
    }
    val hidden = if (poll.hidden && !poll.closed) UiText.get(R.string.poll_results_at_end) else null
    return listOfNotNull(votes, hidden, end).joinToString(" · ")
}
