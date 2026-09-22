package org.umbra.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiGroupOffer

/** The longest name of a group, as `GROUP_NAME_MAX` of the core gives it. */
private const val GROUP_NAME_MAX = 64

/**
 * Mockup 048: the name of a new private group. The group takes two relays
 * of its own at the creation, thus it needs a connection.
 */
@Composable
fun NewGroupScreen(onBack: () -> Unit, onMade: (Conversation) -> Unit) {
    var name by remember { mutableStateOf("") }
    var isMaking by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        BackBar("New private group", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("user-group")
            Spacer(Modifier.height(24.dp))
            Headline("Bring your people together.")
            Spacer(Modifier.height(20.dp))
            // A name is a label of the user and no message text.
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(GROUP_NAME_MAX) },
                label = { Text("Group name") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryButton(
                "Create group",
                enabled = Core.online && name.isNotBlank() && !isMaking,
            ) {
                isMaking = true
                Core.createGroup(name.trim()) { conversation -> onMade(conversation) }
            }
            if (!Core.online) {
                Spacer(Modifier.height(10.dp))
                Note("Connecting. A group takes two relays at its creation.")
            }
        }
    }
}

/**
 * Mockup 052: what this device holds of a group. The rows of the mockup
 * that Part 11 does not carry yet are not here.
 */
@Composable
fun GroupDetailsScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar("Group details", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Avatar(chat, size = 56)
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(chat.title, style = MaterialTheme.typography.titleLarge)
                    Text(
                        groupSubtitle(chat),
                        style = MaterialTheme.typography.bodyMedium,
                        color = Palette.TextSecondary,
                        modifier = Modifier.subline(),
                    )
                }
            }
            Spacer(Modifier.height(20.dp))
            FactRow("user-group", "Members", chat.members.toString())
            FactRow("file-lines", "Group identifier", chat.conversation.label)
            Spacer(Modifier.height(8.dp))
            // Mockup 052: an admin brings a contact in.
            EntryRow(
                RowEntry("user-plus", "Invite a contact") {
                    push(Screen.InviteToGroup(chat.conversation))
                },
            )
            val waiting = Core.groupJoiners.filter { it.groupId.toList() == chat.groupId.toList() }
            for (joiner in waiting) {
                JoinerRow(joiner)
            }
            if (!chat.isReady) {
                Spacer(Modifier.height(12.dp))
                // A technical fact that the user cannot see anywhere else.
                Note("One of the two relays of this group has not answered. Messages wait.")
            }
        }
    }
}

/** One contact that asked to come in (§11.9.1 step 3). */
@Composable
private fun JoinerRow(joiner: FfiGroupOffer) {
    val name = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(joiner.from) }?.title ?: "A contact"
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(if (joiner.isAdded) "$name comes in" else "$name asks to come in")
            Text(
                if (joiner.isAdded) {
                    "The roster goes to them through the relays."
                } else {
                    "The group gives them its roster and its keys."
                },
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
        if (!joiner.isAdded) {
            Spacer(Modifier.width(12.dp))
            InlineButton("Let in") { Core.admitJoiner(joiner) }
        }
    }
}

/**
 * Mockup 049 in its first form: the contacts of this device, one of which
 * takes an offer of the group.
 */
@Composable
fun InviteToGroupScreen(chat: Chat, onBack: () -> Unit) {
    var invited by remember { mutableStateOf(setOf<List<Byte>>()) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Invite a contact", onBack = onBack)
        val contacts = Core.chats.filter { !it.isGroup }
        if (contacts.isEmpty()) {
            EmptyState("No contacts yet.")
            return
        }
        LazyColumn {
            items(contacts, key = { it.conversation.label }) { contact ->
                val isInvited = contact.conversation.id.toList() in invited
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInList()
                        .press {
                            if (!isInvited) {
                                Core.offerGroup(chat.conversation, contact.conversation)
                                invited = invited + setOf(contact.conversation.id.toList())
                            }
                        }
                        .padding(horizontal = PressInset, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(contact)
                    Spacer(Modifier.width(14.dp))
                    Text(contact.title, modifier = Modifier.weight(1f))
                    if (isInvited) {
                        Text(
                            "Invited",
                            style = MaterialTheme.typography.labelMedium,
                            color = Palette.TextSecondary,
                        )
                    }
                }
            }
        }
    }
}

/** The offers of a group that wait for the user (mockup 050). */
@Composable
fun GroupOfferPrompt() {
    val offer = Core.groupOffers.firstOrNull() ?: return
    val from = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(offer.from) }?.title ?: "A contact"
    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text("$from invited you to ${offer.name}")
        Text(
            "The group learns that you joined, as each member does.",
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        InlineButton("Join") { Core.acceptGroupOffer(offer) }
    }
}

/** The line under the name of a group, as mockup 051 gives it. */
fun groupSubtitle(chat: Chat): String {
    val members = if (chat.members == 1) "1 member" else "${chat.members} members"
    return "Private group · $members"
}
