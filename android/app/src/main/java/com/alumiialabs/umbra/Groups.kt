package com.alumiialabs.umbra

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

/**
 * What this device holds of a group, in the order of the contact details:
 * the settings, then the members, then the way out. A tap on a member opens
 * a sheet, thus no part of a group takes a view of its own.
 */
@Composable
fun GroupDetailsScreen(chat: Chat, onBack: () -> Unit, onLeft: () -> Unit, push: (Screen) -> Unit) {
    var members by remember { mutableStateOf(listOf<FfiGroupMember>()) }
    var blocked by remember { mutableStateOf(setOf<UShort>()) }
    // A change of a role touches no count, thus its answer reads the roster again.
    var reload by remember { mutableStateOf(0) }
    LaunchedEffect(chat.conversation.label, chat.members, Core.revision, reload) {
        Core.groupMembers(chat.conversation) { members = it }
        Core.blockedMembers(chat.conversation) { blocked = it.toSet() }
    }

    // GRP-310: an admin alone brings a contact in.
    val own = members.firstOrNull { it.isSelf }
    val isAdmin = own != null && own.role >= FfiRole.ADMIN
    // GRP-338: the device that owns the channels makes each roster change.
    val owns = Core.ownsChannels

    var noForward by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.forwardRules(chat.conversation) { noForward = it.own }
    }

    var sheet by remember { mutableStateOf<GroupSheet?>(null) }
    var showsAll by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.group_details), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(12.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Avatar(chat, size = EDITABLE_PICTURE_SIZE)
                Spacer(Modifier.height(12.dp))
                Text(chat.title, style = MaterialTheme.typography.headlineMedium)
                Text(
                    groupSubtitle(chat),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Palette.TextSecondary,
                )
            }
            Spacer(Modifier.height(16.dp))

            EntryRow(RowEntry("photo-film", stringResource(R.string.common_media_and_files)) { push(Screen.Media(chat.conversation)) })
            HorizontalDivider(color = Palette.Divider)
            FactRow("file-lines", stringResource(R.string.group_identifier), chat.conversation.label)

            SectionLabel(stringResource(R.string.common_notifications))
            AlertRows(chat)

            SectionLabel(stringResource(R.string.details_privacy))
            // DEV-248: an admin alone sets the timer of a group.
            DisappearingRow(chat, mayChange = chat.isMember && isAdmin)
            // DEV-325: an admin alone sets the forward policy of a group.
            noForward?.let {
                if (chat.isMember && isAdmin) {
                    HorizontalDivider(color = Palette.Divider)
                    ToggleRow(stringResource(R.string.group_no_forwarding), it, icon = "share-nodes") { on ->
                        noForward = on
                        Core.setForwardProhibited(chat.conversation, on)
                    }
                    // DEV-326: the policy is a request and no enforcement.
                    if (it) Note(UiText.get(R.string.umbra_ui_dev_326))
                } else if (it) {
                    HorizontalDivider(color = Palette.Divider)
                    FactRow("share-nodes", stringResource(R.string.group_forwarding), stringResource(R.string.common_off))
                }
            }

            SectionLabel(stringResource(R.string.group_members_title, members.size))
            if (chat.isMember && isAdmin && !chat.isClosed && owns) {
                EntryRow(RowEntry("user-plus", stringResource(R.string.group_add_members)) { push(Screen.InviteToGroup(chat.conversation)) })
                HorizontalDivider(color = Palette.Divider)
            }
            val waiting = Core.groupJoiners.filter { it.groupId.toList() == chat.groupId.toList() }
            for (joiner in waiting) {
                JoinerRow(joiner, mayAdmit = owns)
                HorizontalDivider(color = Palette.Divider)
            }
            // A large group shows its first members, and the rest at a tap.
            val shown = if (showsAll) members else members.take(MEMBERS_SHOWN)
            shown.forEachIndexed { index, member ->
                if (index > 0) HorizontalDivider(color = Palette.Divider)
                // Each other member opens its sheet: its block (Part 13
                // §13.12), and for an admin its role and its removal
                // (`ABU-039`).
                MemberRow(member, isPressable = !member.isSelf) { sheet = GroupSheet.Member(member) }
            }
            if (members.size > shown.size) {
                HorizontalDivider(color = Palette.Divider)
                EntryRow(
                    RowEntry("user-group", stringResource(R.string.group_show_all_members, members.size)) { showsAll = true },
                    leads = false,
                )
            }

            // GRP-434: a closed group takes no self-removal until it opens.
            if (chat.isMember && owns && !chat.isClosed) {
                Spacer(Modifier.height(20.dp))
                EntryRow(RowEntry("xmark", stringResource(R.string.common_leave_group)) { sheet = GroupSheet.Leave }, leads = false)
            }

            GroupStateNote(chat)
            Spacer(Modifier.height(20.dp))
        }
    }

    val close = { sheet = null }
    when (val open = sheet) {
        is GroupSheet.Member -> {
            val member = open.member
            val name = memberName(member)
            val isBlocked = member.index in blocked
            // GRP-382: a removal reaches a member below moderator.
            val mayEdit = own != null && isAdmin && !chat.isClosed && owns && member.role <= own.role
            if (!mayEdit) {
                BlockSheet(name, isBlocked, onSet = { Core.setMemberBlocked(chat.conversation, member.index, it) }, onDismiss = close)
            } else {
                ActionSheet(
                    name,
                    buildList {
                        add(RowEntry("user-group", stringResource(R.string.group_role), roleLabel(member.role)) { sheet = GroupSheet.Role(member) })
                        if (member.role <= FfiRole.MEMBER) {
                            add(RowEntry("xmark", stringResource(R.string.group_remove_from_group)) { sheet = GroupSheet.Remove(member) })
                        }
                        add(
                            RowEntry("ban", stringResource(if (isBlocked) R.string.common_unblock else R.string.common_block)) {
                                sheet = GroupSheet.Block(member)
                            },
                        )
                    },
                    onDismiss = close,
                )
            }
        }
        is GroupSheet.Role -> {
            val member = open.member
            val choices = if (own?.role == FfiRole.OWNER) RoleChoices + OwnerChoice else RoleChoices
            ChoiceSheet(
                stringResource(R.string.group_role_of, memberName(member)),
                choices.map { (role, detail) ->
                    // GRP-441: the role that the member holds goes again when
                    // the path of this device does not back it.
                    SheetChoice(roleLabel(role), role == member.role, stringResource(detail)) {
                        Core.setGroupRole(chat.conversation, member.index, role) { reload++ }
                    }
                },
                onDismiss = close,
            )
        }
        // GRP-264: the group starts a new epoch in the same action.
        is GroupSheet.Remove -> ActionSheet(
            stringResource(R.string.group_remove_title, memberName(open.member)),
            listOf(
                RowEntry("xmark", stringResource(R.string.group_remove_member)) {
                    Core.removeFromGroup(chat.conversation, open.member.index) { reload++ }
                },
            ),
            note = stringResource(R.string.group_remove_body),
            onDismiss = close,
        )
        is GroupSheet.Block -> BlockSheet(
            memberName(open.member),
            open.member.index in blocked,
            onSet = { Core.setMemberBlocked(chat.conversation, open.member.index, it) },
            onDismiss = close,
        )
        // GRP-051, GRP-067: a group keeps an owner, thus its last owner
        // stays while another member stays. The last member leaves.
        GroupSheet.Leave -> {
            val isLastOwner = own?.role == FfiRole.OWNER &&
                members.count { it.role == FfiRole.OWNER } <= 1 &&
                members.size > 1
            ActionSheet(
                stringResource(R.string.group_leave_title, chat.title),
                if (isLastOwner) {
                    emptyList()
                } else {
                    listOf(
                        RowEntry("xmark", stringResource(R.string.common_leave_group)) {
                            Core.leaveGroup(chat.conversation) { onLeft() }
                        },
                    )
                },
                note = stringResource(if (isLastOwner) R.string.group_one_owner_note else R.string.group_leave_body),
                onDismiss = close,
            )
        }
        null -> Unit
    }
}

/** The members that the group details show before a tap shows the rest. */
private const val MEMBERS_SHOWN = 8

/** The sheets that a row of the group details opens. */
private sealed interface GroupSheet {
    data class Member(val member: FfiGroupMember) : GroupSheet
    data class Role(val member: FfiGroupMember) : GroupSheet
    data class Remove(val member: FfiGroupMember) : GroupSheet
    data class Block(val member: FfiGroupMember) : GroupSheet
    data object Leave : GroupSheet
}

/** The one line of a state of the group that the user cannot see elsewhere. */
@Composable
private fun GroupStateNote(chat: Chat) {
    val line = when {
        chat.isLapsed -> stringResource(R.string.group_lapsed_note)
        chat.isClosed -> stringResource(R.string.group_closed_note)
        // GRP-184: the group keeps two owners, thus a silent owner leaves
        // only after another member becomes one.
        chat.ownerNeeded -> stringResource(R.string.group_owner_silent_note)
        chat.isReturning -> stringResource(R.string.group_returning_note)
        chat.needsInvitation -> UiText.get(R.string.umbra_ui_grp_374)
        !chat.isMember -> stringResource(R.string.group_not_member_note)
        // A technical fact that the user cannot see anywhere else.
        !chat.isReady -> stringResource(R.string.group_relay_silent_note)
        else -> return
    }
    Spacer(Modifier.height(12.dp))
    Note(line)
}

/** One contact that asked to come in (§11.9.1 step 3). */
@Composable
private fun JoinerRow(joiner: FfiGroupOffer, mayAdmit: Boolean) {
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
            )
        }
        if ((!joiner.isAdded || isStuck) && mayAdmit) {
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

@Composable
private fun MemberRow(member: FfiGroupMember, isPressable: Boolean, onPress: () -> Unit) {
    val row = Modifier.fillMaxWidth().pressShadeInColumn()
    val pressable = if (isPressable) row.press(onClick = onPress) else row

    Row(
        pressable.padding(horizontal = PressInset, vertical = 12.dp),
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
            )
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

/** The contacts of this device, one of which takes an offer of the group. */
@Composable
fun InviteToGroupScreen(chat: Chat, onBack: () -> Unit) {
    var invited by remember { mutableStateOf(setOf<List<Byte>>()) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.group_add_members), onBack = onBack)

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

    PromptCard {
        if (intro.isOffer) {
            Text(stringResource(R.string.group_intro_offer, from, intro.name))
        } else {
            Text(stringResource(R.string.group_intro_ask, from, intro.name))
            Text(
                stringResource(R.string.group_intro_note),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
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
        PromptCard {
            Text(stringResource(R.string.group_join_failed, failed.name))
            Text(
                stringResource(R.string.group_roster_not_verified),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
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

    PromptCard {
        Text(stringResource(R.string.group_offer, from, offer.name))
        Text(
            stringResource(R.string.group_offer_note),
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
        )
        Spacer(Modifier.height(8.dp))
        InlineButton(stringResource(R.string.group_join)) { Core.acceptGroupOffer(offer) }
    }
}

/** The line under the name of a group. */
fun groupSubtitle(chat: Chat): String =
    UiText.plural(R.plurals.group_subtitle, chat.members, chat.members)
