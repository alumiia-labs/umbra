package com.alumiialabs.umbra

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiModNote
import uniffi.umbra_ffi.FfiRosterNote

/** The moderator actions of Part 11 §11.9.6, as the core numbers them. */
const val MOD_HIDE: UByte = 1u
const val MOD_REMOVE: UByte = 2u
const val MOD_UNHIDE: UByte = 3u

/** The acting role of a placeholder (`GRP-082`). */
fun roleWord(role: UByte): String = when (role.toInt()) {
    4 -> UiText.get(R.string.mod_an_admin)
    5 -> UiText.get(R.string.mod_an_owner)
    else -> UiText.get(R.string.mod_a_moderator)
}

/**
 * The words of one moderation epoch: each act and its count (`GRP-089`).
 * At a removal the line states that an older backup brings the messages
 * back (`GRP-090`).
 */
fun modNoteText(note: FfiModNote): String {
    val who = roleWord(note.actorRole)
    return buildList {
        if (note.removed > 0u) {
            add(counted(R.plurals.mod_removed, who, note.removed) + " " + UiText.get(R.string.umbra_ui_grp_090))
        }
        if (note.hidden > 0u) add(counted(R.plurals.mod_hid, who, note.hidden))
        if (note.shown > 0u) add(counted(R.plurals.mod_put_back, who, note.shown))
    }.joinToString(" ")
}

/** One act of a moderator on `count` messages, in words. */
private fun counted(id: Int, who: String, count: UShort): String =
    UiText.plural(id, count.toInt(), who, count.toInt())

/** One line of a conversation that no member wrote: a change of the group. */
class ChatNote(val atMs: ULong, val text: String, val icon: String)

/** The role of a roster note, in words. */
private fun roleName(role: UByte): String = when (role.toInt()) {
    1 -> UiText.get(R.string.mod_role_observer)
    3 -> UiText.get(R.string.mod_role_moderator)
    4 -> UiText.get(R.string.mod_role_admin)
    5 -> UiText.get(R.string.mod_role_owner)
    else -> UiText.get(R.string.mod_role_member)
}

/**
 * The words of one change of the roster. A removal for silence says so
 * (`GRP-050`). A fork names the member that a signature names, and a fork
 * of plain epochs names nobody (`GRP-072` to `GRP-074`).
 */
fun rosterNoteText(note: FfiRosterNote, names: Map<UShort, String>): String {
    val who = names[note.index] ?: UiText.get(R.string.common_member_number, note.index.toInt())
    val isYou = who == YOU

    return when (note.kind.toInt()) {
        1 -> UiText.get(R.string.mod_joined, who)
        2 -> if (isYou) UiText.get(R.string.mod_you_left) else UiText.get(R.string.mod_no_longer, who)
        3 -> UiText.get(R.string.umbra_ui_grp_050, who)
        4 -> if (isYou) {
            UiText.get(R.string.mod_you_are_now, roleName(note.role))
        } else {
            UiText.get(R.string.mod_is_now, who, roleName(note.role))
        }
        5 -> if (note.index == NOBODY) {
            UiText.get(R.string.mod_members_disagree)
        } else {
            UiText.get(R.string.mod_two_changes, who)
        }
        6 -> UiText.get(R.string.umbra_ui_net_103)
        7 -> UiText.get(R.string.umbra_ui_wir_341)
        else -> ""
    }
}

private val NOBODY: UShort = 0xFFFFu

/** The name of this member among the names of a group. */
val YOU: String get() = UiText.get(R.string.common_you)

/** The notes of a group, in the order of time. */
fun chatNotes(mods: List<FfiModNote>, roster: List<FfiRosterNote>, names: Map<UShort, String>): List<ChatNote> {
    val modNotes = mods.map { ChatNote(it.atMs, modNoteText(it), "ban") }
    val rosterNotes = roster.map {
        // A fork and the later kinds are warnings.
        val icon = if (it.kind.toInt() >= 5) "triangle-exclamation" else "user-group"
        ChatNote(it.atMs, rosterNoteText(it, names), icon)
    }

    return (modNotes + rosterNotes)
        .filter { it.text.isNotEmpty() }
        .sortedBy { it.atMs }
}

/** One change of the group in the conversation, centered as a notice. */
@Composable
fun NoteLine(note: ChatNote) {
    val text = note.text
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier
                .background(Palette.Incoming, RoundedCornerShape(12.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon(note.icon, size = 10.dp, tint = Palette.TextSecondary)
            Spacer(Modifier.width(6.dp))
            Text(
                text,
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}
