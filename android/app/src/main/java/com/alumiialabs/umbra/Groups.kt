package com.alumiialabs.umbra

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.FfiGroupMember
import uniffi.umbra_ffi.FfiGroupOffer
import uniffi.umbra_ffi.FfiRole

/** The longest name of a group, as `GROUP_NAME_MAX` of the core gives it. */
private const val GROUP_NAME_MAX = 64

/**
 * The name of a new private group. The group takes two relays
 * of its own at the creation, thus it needs a connection.
 */
@Composable
fun NewGroupScreen(onBack: () -> Unit, onMade: (Conversation) -> Unit) {
    var name by remember { mutableStateOf("") }
    var isMaking by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.group_new_private_group), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("user-group")
            Spacer(Modifier.height(24.dp))
            Headline(stringResource(R.string.group_bring_people_together))
            Spacer(Modifier.height(20.dp))
            // A name is a label of the user and no message text.
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(GROUP_NAME_MAX) },
                label = { Text(stringResource(R.string.group_name_label)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryButton(
                stringResource(R.string.group_create),
                enabled = Core.online && name.isNotBlank() && !isMaking,
            ) {
                isMaking = true
                Core.createGroup(name.trim()) { conversation -> onMade(conversation) }
            }
            if (!Core.online) {
                Spacer(Modifier.height(10.dp))
                Note(stringResource(R.string.group_connecting_note))
            }
        }
    }
}

/** What this device holds of a group. */
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
    var noForward by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.forwardRules(chat.conversation) { noForward = it.own }
        Core.timer(chat.conversation) { timer = it.seconds }
        Core.alertSetting(chat.conversation) { alert = it }
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.group_details), onBack = onBack)
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
            FactRow("user-group", stringResource(R.string.group_members), chat.members.toString())
            FactRow("file-lines", stringResource(R.string.group_identifier), chat.conversation.label)
            Spacer(Modifier.height(8.dp))

            // The members, an invitation, and the way out.
            EntryRow(
                RowEntry("user-group", stringResource(R.string.group_members_and_roles)) {
                    push(Screen.GroupMembers(chat.conversation))
                },
            )
            EntryRow(
                RowEntry("photo-film", stringResource(R.string.common_media_and_files)) {
                    push(Screen.Media(chat.conversation))
                },
            )

            alert?.let {
                EntryRow(
                    RowEntry("bell", stringResource(R.string.common_notifications), alertLabel(it)) {
                        push(Screen.Alerts(chat.conversation))
                    },
                )
            }

            // DEV-248: an admin alone sets the timer of a group.
            timer?.let {
                if (chat.isMember && isAdmin) {
                    EntryRow(
                        RowEntry("clock", stringResource(R.string.common_disappearing_messages), timerLabel(it)) {
                            push(Screen.Disappearing(chat.conversation))
                        },
                    )
                } else {
                    FactRow("clock", stringResource(R.string.common_disappearing_messages), timerLabel(it))
                }
            }

            // DEV-325: an admin alone sets the forward policy of a group.
            noForward?.let {
                if (chat.isMember && isAdmin) {
                    ToggleRow(stringResource(R.string.group_no_forwarding), it) { on ->
                        noForward = on
                        Core.setForwardProhibited(chat.conversation, on)
                    }
                    // DEV-326: the policy is a request and no enforcement.
                    if (it) Note(UiText.get(R.string.umbra_ui_dev_326))
                } else if (it) {
                    FactRow("share-nodes", stringResource(R.string.group_forwarding), stringResource(R.string.common_off))
                }
            }

            if (chat.isMember) {
                if (isAdmin) {
                    EntryRow(
                        RowEntry("user-plus", stringResource(R.string.group_invite_contact)) {
                            push(Screen.InviteToGroup(chat.conversation))
                        },
                    )
                }
                EntryRow(
                    RowEntry("xmark", stringResource(R.string.common_leave_group)) {
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
                Note(stringResource(R.string.group_lapsed_note))
            } else if (chat.isClosed) {
                Spacer(Modifier.height(12.dp))
                Note(stringResource(R.string.group_closed_note))
            } else if (chat.ownerNeeded) {
                Spacer(Modifier.height(12.dp))
                // GRP-184: the group keeps two owners, thus a silent owner
                // leaves only after another member becomes one.
                Note(stringResource(R.string.group_owner_silent_note))
            } else if (chat.isReturning) {
                Spacer(Modifier.height(12.dp))
                Note(stringResource(R.string.group_returning_note))
            } else if (chat.needsInvitation) {
                Spacer(Modifier.height(12.dp))
                Note(UiText.get(R.string.umbra_ui_grp_374))
            } else if (!chat.isMember) {
                Spacer(Modifier.height(12.dp))
                Note(stringResource(R.string.group_not_member_note))
            } else if (!chat.isReady) {
                Spacer(Modifier.height(12.dp))
                // A technical fact that the user cannot see anywhere else.
                Note(stringResource(R.string.group_relay_silent_note))
            }
        }
    }
}

/** One contact that asked to come in (§11.9.1 step 3). */
@Composable
private fun JoinerRow(joiner: FfiGroupOffer) {
    val name = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(joiner.from) }
        ?.title
        ?: stringResource(R.string.common_a_contact)

    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // A roster that did not reach the relays takes the same press
        // again, and the group adds nobody a second time.
        val isStuck = joiner.isAdded && !joiner.isMoving
        Column(Modifier.weight(1f)) {
            Text(
                if (joiner.isAdded) {
                    stringResource(R.string.group_joiner_comes_in, name)
                } else {
                    stringResource(R.string.group_joiner_asks, name)
                },
            )
            Text(
                when {
                    isStuck -> stringResource(R.string.group_joiner_stuck)
                    joiner.isAdded -> stringResource(R.string.group_joiner_added)
                    else -> stringResource(R.string.group_joiner_waiting)
                },
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
        if (!joiner.isAdded || isStuck) {
            Spacer(Modifier.width(12.dp))
            InlineButton(
                if (isStuck) stringResource(R.string.common_try_again) else stringResource(R.string.group_let_in),
            ) { Core.admitJoiner(joiner) }
        }
    }
}

/** The label of a role. */
private fun roleLabel(role: FfiRole): String = when (role) {
    FfiRole.OWNER -> UiText.get(R.string.group_role_owner)
    FfiRole.ADMIN -> UiText.get(R.string.group_role_admin)
    FfiRole.MODERATOR -> UiText.get(R.string.group_role_moderator)
    FfiRole.MEMBER -> UiText.get(R.string.group_role_member)
    FfiRole.OBSERVER -> UiText.get(R.string.group_role_observer)
}

/**
 * The name of a member. The roster names no contact, thus a member that
 * another admin brought in shows its index alone.
 */
private fun memberName(member: FfiGroupMember): String {
    if (member.isSelf) return UiText.get(R.string.common_you)

    val contact = member.contact ?: return UiText.get(R.string.common_member_number, member.index.toInt())

    return Core.chats.firstOrNull { it.conversation.id.contentEquals(contact) }?.title
        ?: UiText.get(R.string.common_member_number, member.index.toInt())
}

/**
 * Each member of the group with its role. An admin opens the
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
        BackBar(stringResource(R.string.group_members_title, members.size), onBack = onBack)
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
                        SecondaryButton(stringResource(R.string.group_add_members)) {
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
        // A member that is a contact shows the picture of that contact.
        val contact = member.contact?.takeIf { !member.isSelf }?.let { id ->
            Core.chats.firstOrNull { it.conversation.id.contentEquals(id) }
        }
        if (contact?.picture != null) {
            Avatar(contact, size = 44)
        } else {
            LetterAvatar(memberName(member), member.index.toInt(), size = 44)
        }

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

/** The roles an admin gives, each with the string of its detail. */
private val RoleChoices = listOf(
    FfiRole.MEMBER to R.string.group_role_member_detail,
    FfiRole.MODERATOR to R.string.group_role_moderator_detail,
    FfiRole.ADMIN to R.string.group_role_admin_detail,
)

/** An owner also names owners, which the group keeps at two or more. */
private val OwnerChoice = FfiRole.OWNER to R.string.group_role_owner_detail

/**
 * The role of one member, and the way to its removal. A removal reaches a
 * member below `moderator` (`GRP-382`).
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
        BackBar(stringResource(R.string.group_member_role), onBack = onBack)
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
                            stringResource(detail),
                            style = MaterialTheme.typography.bodySmall,
                            color = Palette.TextSecondary,
                            modifier = Modifier.subline(),
                        )
                    }
                }
                HorizontalDivider(color = Palette.Divider)
            }

            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.group_save_role), enabled = chosen != role && !isSaving) {
                isSaving = true
                Core.setGroupRole(chat.conversation, index, chosen) { onBack() }
            }
            if (role <= FfiRole.MEMBER) {
                Spacer(Modifier.height(10.dp))
                SecondaryButton(stringResource(R.string.group_remove_from_group)) {
                    push(Screen.RemoveMember(chat.conversation, index, name))
                }
            }
            QuietButton(stringResource(R.string.common_block)) { push(Screen.BlockMember(chat.conversation, index, name)) }
        }
    }
}

/**
 * The removal of one member. The group starts a new epoch in the same
 * action, thus the member reads no later record (`GRP-264`).
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
        BackBar(stringResource(R.string.group_membership), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(
                stringResource(R.string.group_remove_title, name),
                stringResource(R.string.group_remove_body),
            )
            Spacer(Modifier.height(20.dp))
            DangerButton(stringResource(R.string.group_remove_member), enabled = !isRemoving) {
                isRemoving = true
                Core.removeFromGroup(chat.conversation, index) { onDone() }
            }
            QuietButton(stringResource(R.string.common_cancel), onBack)
        }
    }
}

/**
 * The way out of a group. An owner leaves only after it gave the role to
 * another member (`GRP-051`).
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
        BackBar(stringResource(R.string.common_leave_group), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(
                stringResource(R.string.group_leave_title, chat.title),
                stringResource(R.string.group_leave_body),
            )
            Spacer(Modifier.height(20.dp))
            if (lastOwner) {
                // GRP-051: a group keeps an owner, thus this one stays.
                Note(stringResource(R.string.group_one_owner_note))
                Spacer(Modifier.height(16.dp))
            }
            DangerButton(stringResource(R.string.common_leave_group), enabled = !isLeaving && !lastOwner) {
                isLeaving = true
                Core.leaveGroup(chat.conversation) { onLeft() }
            }
            QuietButton(stringResource(R.string.group_stay), onBack)
        }
    }
}

/** The contacts of this device, one of which takes an offer of the group. */
@Composable
fun InviteToGroupScreen(chat: Chat, onBack: () -> Unit) {
    var invited by remember { mutableStateOf(setOf<List<Byte>>()) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.group_invite_contact), onBack = onBack)

        val contacts = Core.chats.filter { !it.isGroup }
        if (contacts.isEmpty()) {
            EmptyState(stringResource(R.string.group_no_contacts))
            return
        }

        LazyColumn {
            items(contacts, key = { it.conversation.key }) { contact ->
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
                            stringResource(R.string.group_invited),
                            style = MaterialTheme.typography.labelMedium,
                            color = Palette.TextSecondary,
                        )
                    }
                }
            }
        }
    }
}

/**
 * The introductions that wait for the user (Part 6 §6.6.7): a contact asks
 * to introduce the user, or it introduces the user to a third party. Each
 * one waits for an act of the user (`WIR-196`, `WIR-358`).
 */
@Composable
fun IntroductionPrompt() {
    val intro = Core.introductions.firstOrNull() ?: return
    val from = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(intro.from) }
        ?.title
        ?: stringResource(R.string.common_a_contact)

    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        if (intro.isOffer) {
            Text(stringResource(R.string.group_intro_offer, from, intro.name))
        } else {
            Text(stringResource(R.string.group_intro_ask, from, intro.name))
            Text(
                stringResource(R.string.group_intro_note),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }

        Spacer(Modifier.height(8.dp))
        Row {
            if (intro.isOffer) {
                InlineButton(stringResource(R.string.common_accept)) { Core.acceptIntroduction(intro) }
            } else {
                InlineButton(stringResource(R.string.group_allow)) { Core.allowIntroduction(intro) }
            }
            Spacer(Modifier.width(12.dp))
            InlineButton(stringResource(R.string.group_decline)) { Core.declineIntroduction(intro) }
        }
    }
}

/** The offers of a group that wait for the user. */
@Composable
fun GroupOfferPrompt() {
    // GRP-328: an admission whose roster did not verify shows as failed.
    Core.failedAdmissions.firstOrNull()?.let { failed ->
        Column(
            Modifier
                .fillMaxWidth()
                .background(Palette.Incoming)
                .padding(horizontal = 20.dp, vertical = 12.dp),
        ) {
            Text(stringResource(R.string.group_join_failed, failed.name))
            Text(
                stringResource(R.string.group_roster_not_verified),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
            Spacer(Modifier.height(8.dp))
            InlineButton(stringResource(R.string.common_dismiss)) { Core.dismissFailedAdmission(failed) }
        }
        return
    }

    val offer = Core.groupOffers.firstOrNull() ?: return
    val from = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(offer.from) }
        ?.title
        ?: stringResource(R.string.common_a_contact)

    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(stringResource(R.string.group_offer, from, offer.name))
        Text(
            stringResource(R.string.group_offer_note),
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        InlineButton(stringResource(R.string.group_join)) { Core.acceptGroupOffer(offer) }
    }
}

/** The line under the name of a group. */
fun groupSubtitle(chat: Chat): String =
    UiText.plural(R.plurals.group_subtitle, chat.members, chat.members)
