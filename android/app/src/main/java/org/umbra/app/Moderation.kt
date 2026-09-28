package org.umbra.app

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

/** The moderator actions of Part 11 §11.9.6, as the core numbers them. */
const val MOD_HIDE: UByte = 1u
const val MOD_REMOVE: UByte = 2u
const val MOD_UNHIDE: UByte = 3u

/** The acting role of a placeholder (`GRP-082`). */
fun roleWord(role: UByte): String = when (role.toInt()) {
    4 -> "An admin"
    5 -> "An owner"
    else -> "A moderator"
}

private fun messages(count: UShort) = if (count.toInt() == 1) "1 message" else "$count messages"

/**
 * The words of one moderation epoch: each act and its count (`GRP-089`).
 * At a removal the line states that an older backup brings the messages
 * back (`GRP-090`).
 */
fun modNoteText(note: FfiModNote): String {
    val who = roleWord(note.actorRole)
    return buildList {
        if (note.removed > 0u) {
            add("$who removed ${messages(note.removed)}. A restore from a backup that predates today brings them back.")
        }
        if (note.hidden > 0u) add("$who hid ${messages(note.hidden)}.")
        if (note.shown > 0u) add("$who put back ${messages(note.shown)}.")
    }.joinToString(" ")
}

/** One moderation epoch in the conversation, centred as a notice. */
@Composable
fun ModLine(note: FfiModNote) {
    val text = modNoteText(note)
    if (text.isEmpty()) return
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier
                .background(Palette.Incoming, RoundedCornerShape(12.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon("ban", size = 10.dp, tint = Palette.TextSecondary)
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
