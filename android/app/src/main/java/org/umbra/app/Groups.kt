package org.umbra.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
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
fun GroupDetailsScreen(chat: Chat, onBack: () -> Unit) {
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
            if (!chat.isReady) {
                Spacer(Modifier.height(12.dp))
                // A technical fact that the user cannot see anywhere else.
                Note("One of the two relays of this group has not answered. Messages wait.")
            }
        }
    }
}

/** The line under the name of a group, as mockup 051 gives it. */
fun groupSubtitle(chat: Chat): String {
    val members = if (chat.members == 1) "1 member" else "${chat.members} members"
    return "Private group · $members"
}
