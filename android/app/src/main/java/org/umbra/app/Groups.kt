package org.umbra.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiGroupMember
import uniffi.umbra_ffi.FfiGroupOffer
import uniffi.umbra_ffi.FfiRole

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
    var members by remember { mutableStateOf(listOf<FfiGroupMember>()) }
    LaunchedEffect(chat.conversation.label, chat.members) {
        Core.groupMembers(chat.conversation) { members = it }
    }
    // GRP-310: an admin alone brings a contact in.
    val isAdmin = members.any { it.isSelf && it.role >= FfiRole.ADMIN }
    var timer by remember { mutableStateOf<UInt?>(null) }
    var alert by remember { mutableStateOf<UByte?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.timer(chat.conversation) { timer = it.seconds }
        Core.alertSetting(chat.conversation) { alert = it }
    }
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
            // Mockup 052: the members, an invitation, and the way out.
            EntryRow(
                RowEntry("user-group", "Members and roles") {
                    push(Screen.GroupMembers(chat.conversation))
                },
            )
            EntryRow(
                RowEntry("photo-film", "Media and files") {
                    push(Screen.Media(chat.conversation))
                },
            )
            alert?.let {
                EntryRow(
                    RowEntry("bell", "Notifications", alertLabel(it)) {
                        push(Screen.Alerts(chat.conversation))
                    },
                )
            }
            // DEV-248: an admin alone sets the timer of a group.
            timer?.let {
                if (chat.isMember && isAdmin) {
                    EntryRow(
                        RowEntry("clock", "Disappearing messages", timerLabel(it)) {
                            push(Screen.Disappearing(chat.conversation))
                        },
                    )
                } else {
                    FactRow("clock", "Disappearing messages", timerLabel(it))
                }
            }
            if (chat.isMember) {
                if (isAdmin) {
                    EntryRow(
                        RowEntry("user-plus", "Invite a contact") {
                            push(Screen.InviteToGroup(chat.conversation))
                        },
                    )
                }
                EntryRow(
                    RowEntry("xmark", "Leave group") {
                        push(Screen.LeaveGroup(chat.conversation))
                    },
                )
            }
            val waiting = Core.groupJoiners.filter { it.groupId.toList() == chat.groupId.toList() }
            for (joiner in waiting) {
                JoinerRow(joiner)
            }
            if (chat.isLapsed) {
                Spacer(Modifier.height(12.dp))
                Note("Your membership lapsed while this device was away. Ask a member for a new invitation.")
            } else if (chat.isClosed) {
                Spacer(Modifier.height(12.dp))
                Note("The relays of this group hold it no more. It takes no new message.")
            } else if (chat.ownerNeeded) {
                Spacer(Modifier.height(12.dp))
                // GRP-184: the group keeps two owners, thus a silent owner
                // leaves only after another member becomes one.
                Note("An owner has been silent for 30 days. Make another member an owner.")
            } else if (chat.isReturning) {
                Spacer(Modifier.height(12.dp))
                Note("A removed device took your place in this group. Your request to an admin waits.")
            } else if (chat.needsInvitation) {
                Spacer(Modifier.height(12.dp))
                Note("A removed device took your place in this group. Ask an admin for a new invitation.")
            } else if (!chat.isMember) {
                Spacer(Modifier.height(12.dp))
                Note("You are no longer a member of this group.")
            } else if (!chat.isReady) {
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
        // A roster that did not reach the relays takes the same press
        // again, and the group adds nobody a second time.
        val isStuck = joiner.isAdded && !joiner.isMoving
        Column(Modifier.weight(1f)) {
            Text(if (joiner.isAdded) "$name comes in" else "$name asks to come in")
            Text(
                when {
                    isStuck -> "The roster did not reach the relays."
                    joiner.isAdded -> "The roster goes to them through the relays."
                    else -> "The group gives them its roster and its keys."
                },
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
        if (!joiner.isAdded || isStuck) {
            Spacer(Modifier.width(12.dp))
            InlineButton(if (isStuck) "Try again" else "Let in") { Core.admitJoiner(joiner) }
        }
    }
}

/** The label of a role, as mockup 053 writes it. */
private fun roleLabel(role: FfiRole): String = when (role) {
    FfiRole.OWNER -> "Owner"
    FfiRole.ADMIN -> "Admin"
    FfiRole.MODERATOR -> "Moderator"
    FfiRole.MEMBER -> "Member"
    FfiRole.OBSERVER -> "Observer"
}

/**
 * The name of a member. The roster names no contact, thus a member that
 * another admin brought in shows its index alone.
 */
private fun memberName(member: FfiGroupMember): String {
    if (member.isSelf) return "You"
    val contact = member.contact ?: return "Member ${member.index}"
    return Core.chats.firstOrNull { it.conversation.id.contentEquals(contact) }?.title
        ?: "Member ${member.index}"
}

/**
 * Mockup 053: each member of the group with its role. An admin opens the
 * removal of a member below it.
 */
@Composable
fun GroupMembersScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var members by remember { mutableStateOf(listOf<FfiGroupMember>()) }
    LaunchedEffect(chat.conversation.label, chat.members) {
        Core.groupMembers(chat.conversation) { members = it }
    }
    val own = members.firstOrNull { it.isSelf }
    val mayRemove = own != null && own.role >= FfiRole.ADMIN && !chat.isClosed
    Column(Modifier.fillMaxSize()) {
        BackBar("Members · ${members.size}", onBack = onBack)
        LazyColumn {
            items(members, key = { it.index.toInt() }) { member ->
                val editable = mayRemove && !member.isSelf && member.role <= own!!.role
                // Each other member opens its block (Part 13 §13.12), and an
                // admin opens its role and its removal beside it (`ABU-039`).
                MemberRow(member, !member.isSelf) {
                    push(
                        if (editable) {
                            Screen.MemberRole(
                                chat.conversation,
                                member.index,
                                memberName(member),
                                member.role,
                                own!!.role,
                            )
                        } else {
                            Screen.BlockMember(chat.conversation, member.index, memberName(member))
                        },
                    )
                }
            }
            if (chat.isMember && mayRemove) {
                item {
                    Spacer(Modifier.height(12.dp))
                    Column(Modifier.padding(horizontal = 20.dp)) {
                        SecondaryButton("Add members") {
                            push(Screen.InviteToGroup(chat.conversation))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MemberRow(member: FfiGroupMember, removable: Boolean, onRemove: () -> Unit) {
    val row = Modifier.fillMaxWidth()
    val pressable = if (removable) {
        row.pressShadeInList().press(onClick = onRemove).padding(horizontal = PressInset)
    } else {
        row.padding(horizontal = 20.dp)
    }
    Row(
        pressable.padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        LetterAvatar(memberName(member), member.index.toInt(), size = 44)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(memberName(member), style = MaterialTheme.typography.titleMedium)
            Text(
                roleLabel(member.role),
                style = MaterialTheme.typography.bodyMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
        if (removable) {
            FaIcon("chevron-right", size = 14.dp, tint = Palette.TextSecondary)
        }
    }
}

/** The roles an admin gives, with the words of mockup 054. */
private val RoleChoices = listOf(
    FfiRole.MEMBER to "Can send messages",
    FfiRole.MODERATOR to "Can moderate content",
    FfiRole.ADMIN to "Can manage members and settings",
)

/** An owner also names owners, which the group keeps at two or more. */
private val OwnerChoice = FfiRole.OWNER to "Can manage admins and owners"

/**
 * Mockup 054: the role of one member, and the way to its removal. A
 * removal reaches a member below `moderator` (`GRP-382`).
 */
@Composable
fun MemberRoleScreen(
    chat: Chat,
    index: UShort,
    name: String,
    role: FfiRole,
    ownRole: FfiRole,
    onBack: () -> Unit,
    push: (Screen) -> Unit,
) {
    var chosen by remember { mutableStateOf(role) }
    val choices = if (ownRole == FfiRole.OWNER) RoleChoices + OwnerChoice else RoleChoices
    var isSaving by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Member role", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                LetterAvatar(name, index.toInt(), size = 80)
            }
            Spacer(Modifier.height(16.dp))
            Text(name, style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            for ((choice, detail) in choices) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = androidx.compose.ui.semantics.Role.RadioButton) {
                            chosen = choice
                        }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = chosen == choice)
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(roleLabel(choice))
                        Text(
                            detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = Palette.TextSecondary,
                            modifier = Modifier.subline(),
                        )
                    }
                }
                HorizontalDivider(color = Palette.Divider)
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton("Save role", enabled = chosen != role && !isSaving) {
                isSaving = true
                Core.setGroupRole(chat.conversation, index, chosen) { onBack() }
            }
            if (role <= FfiRole.MEMBER) {
                Spacer(Modifier.height(10.dp))
                SecondaryButton("Remove from group") {
                    push(Screen.RemoveMember(chat.conversation, index, name))
                }
            }
            QuietButton("Block") { push(Screen.BlockMember(chat.conversation, index, name)) }
        }
    }
}

/**
 * Mockup 055: the removal of one member. The group starts a new epoch in
 * the same action, thus the member reads no later record (`GRP-264`).
 */
@Composable
fun RemoveMemberScreen(
    chat: Chat,
    index: UShort,
    name: String,
    onBack: () -> Unit,
    onDone: () -> Unit,
) {
    var isRemoving by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Group membership", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(
                "Remove $name?",
                "They read no message of this group after this. The messages " +
                    "and the files they already hold stay with them.",
            )
            Spacer(Modifier.height(20.dp))
            DangerButton("Remove member", enabled = !isRemoving) {
                isRemoving = true
                Core.removeFromGroup(chat.conversation, index) { onDone() }
            }
            QuietButton("Cancel", onBack)
        }
    }
}

/**
 * Mockup 060: the way out of a group. An owner leaves only after it gave
 * the role to another member (`GRP-051`).
 */
@Composable
fun LeaveGroupScreen(chat: Chat, onBack: () -> Unit, onLeft: () -> Unit) {
    var members by remember { mutableStateOf(listOf<FfiGroupMember>()) }
    LaunchedEffect(chat.conversation.label) {
        Core.groupMembers(chat.conversation) { members = it }
    }
    var isLeaving by remember { mutableStateOf(false) }
    val own = members.firstOrNull { it.isSelf }
    val owners = members.count { it.role == FfiRole.OWNER }
    val lastOwner = own?.role == FfiRole.OWNER && owners <= 1
    Column(Modifier.fillMaxSize()) {
        BackBar("Leave group", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(
                "Leave ${chat.title}?",
                "You read no new message of this group after this. The " +
                    "members keep the messages you already sent.",
            )
            Spacer(Modifier.height(20.dp))
            if (lastOwner) {
                // GRP-051: a group keeps an owner, thus this one stays.
                Note("This group has one owner. Give the role to another member first.")
                Spacer(Modifier.height(16.dp))
            }
            DangerButton("Leave group", enabled = !isLeaving && !lastOwner) {
                isLeaving = true
                Core.leaveGroup(chat.conversation) { onLeft() }
            }
            QuietButton("Stay in group", onBack)
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
