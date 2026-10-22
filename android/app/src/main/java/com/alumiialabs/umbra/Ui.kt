package com.alumiialabs.umbra

import android.text.format.DateUtils
import android.view.inputmethod.InputMethodManager
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** The views above the tabs. The list is a stack, and Back takes the top. */
sealed interface Screen {
    data object AddContact : Screen
    data object NewGroup : Screen
    data object YourInvitation : Screen
    data object UseInvitation : Screen
    data object ScanInvitation : Screen
    data object AppLock : Screen
    data object Connection : Screen
    data object AutoLock : Screen
    data object Notifications : Screen
    data object Setup : Screen
    data object ResetIdentity : Screen
    data object SocialRecovery : Screen
    data object UserHalf : Screen
    data class HeldShare(val conversation: Conversation) : Screen
    data object AutoDownload : Screen
    data object ChangePassphrase : Screen
    data object RecoveryCode : Screen
    data object RootSeed : Screen
    data object Devices : Screen
    data object LinkDevice : Screen
    data object TakeOver : Screen
    data object PublicLinks : Screen
    data class PublicLinkView(val id: List<Byte>) : Screen
    data object Handle : Screen
    data object Profile : Screen
    data object Requests : Screen

    /** A conversation, at its end or at the message `target`. */
    data class Chat(val conversation: Conversation, val target: List<Byte>? = null) : Screen

    /** The search of one conversation, or of each one. */
    data class Search(val scope: Conversation?) : Screen
    data class ContactDetails(val conversation: Conversation) : Screen
    data class EditName(val conversation: Conversation) : Screen
    data class BlockContact(val conversation: Conversation) : Screen
    data class BlockMember(val conversation: Conversation, val index: UShort, val name: String) : Screen
    data class ConversationSettings(val conversation: Conversation) : Screen
    data class Disappearing(val conversation: Conversation) : Screen
    data class NewPoll(val conversation: Conversation) : Screen
    data class Alerts(val conversation: Conversation) : Screen
    data class Verify(val conversation: Conversation) : Screen
    data class VerifyCode(val conversation: Conversation, val starts: Boolean) : Screen
    data class SafetyNumber(val conversation: Conversation) : Screen
    data class ScanSafetyNumber(val conversation: Conversation) : Screen
    data class Photo(val conversation: Conversation, val line: Line) : Screen
    data class Video(val conversation: Conversation, val line: Line) : Screen
    data class Media(val conversation: Conversation) : Screen
    data class GroupDetails(val conversation: Conversation) : Screen
    data class InviteToGroup(val conversation: Conversation) : Screen
    data class GroupMembers(val conversation: Conversation) : Screen
    data class RemoveMember(
        val conversation: Conversation,
        val index: UShort,
        val name: String,
    ) : Screen
    data class LeaveGroup(val conversation: Conversation) : Screen
    data class MemberRole(
        val conversation: Conversation,
        val index: UShort,
        val name: String,
        val role: uniffi.umbra_ffi.FfiRole,
        val ownRole: uniffi.umbra_ffi.FfiRole,
    ) : Screen

    /** The conversation of a view of one contact. */
    val contact: Conversation?
        get() = when (this) {
            is Chat -> conversation
            is ContactDetails -> conversation
            is EditName -> conversation
            is BlockContact -> conversation
            is BlockMember -> conversation
            is ConversationSettings -> conversation
            is HeldShare -> conversation
            is Disappearing -> conversation
            is NewPoll -> conversation
            is Alerts -> conversation
            is Verify -> conversation
            is VerifyCode -> conversation
            is SafetyNumber -> conversation
            is ScanSafetyNumber -> conversation
            is Photo -> conversation
            is Video -> conversation
            is Media -> conversation
            is GroupDetails -> conversation
            is InviteToGroup -> conversation
            is GroupMembers -> conversation
            is RemoveMember -> conversation
            is LeaveGroup -> conversation
            is MemberRole -> conversation
            else -> null
        }
}

enum class Tab(val label: Int, val icon: String) {
    Chats(R.string.main_tab_chats, "comment"),
    Contacts(R.string.main_tab_contacts, "user-group"),
    Settings(R.string.main_tab_settings, "gear"),
}

@Composable
fun UmbraApp() {
    UmbraTheme {
        // A photo on the whole screen has a dark ground under each bar.
        Surface(Modifier.fillMaxSize(), color = if (Viewer.isOpen) Color.Black else Palette.Surface) {
            Box(Modifier.safeDrawingPadding().imePadding()) {
                if (Core.phase != Core.Phase.Open) {
                    UnlockScreen()
                } else {
                    OpenApp()
                }
            }
        }
    }
}

@Composable
private fun OpenApp() {
    var tab by remember { mutableStateOf(Tab.Chats) }
    var stack by remember { mutableStateOf(listOf<Screen>()) }
    val push: (Screen) -> Unit = { stack = stack + it }
    val pop: () -> Unit = { stack = stack.dropLast(1) }

    BackHandler(enabled = stack.isNotEmpty(), onBack = pop)

    // The keyboard of one view has no field in the next one.
    HideKeyboardOn(stack.lastOrNull())

    // A tapped or shared invitation link opens the view of the link above
    // the open views. Another app can send one, and Back leads to the view
    // that the user left.
    LaunchedEffect(Core.linkedInvitation) {
        if (Core.linkedInvitation != null && stack.lastOrNull() != Screen.UseInvitation) {
            stack = stack + Screen.UseInvitation
        }
    }

    // A contact that is new takes its name before each other view.
    val unnamed = Core.toName
    if (unnamed != null) {
        NameContactScreen(
            unnamed,
            onDone = {
                Core.toName = null
                stack = listOf(Screen.Chat(unnamed))
            },
        )
        return
    }

    val top = stack.lastOrNull()
    Column(Modifier.fillMaxSize()) {
        if (top !is Screen.VerifyCode) VerifyPrompt(push)
        when (top) {
            null -> TabsScreen(tab, onTab = { tab = it }, push)
            Screen.AddContact -> AddContactScreen(pop, push)
            Screen.NewGroup -> NewGroupScreen(pop) { conversation ->
                stack = listOf(Screen.Chat(conversation))
            }
            Screen.YourInvitation -> YourInvitationScreen(pop)
            Screen.UseInvitation -> UseInvitationScreen(pop, push)
            Screen.ScanInvitation -> ScanInvitationScreen(pop)
            Screen.AppLock -> AppLockScreen(pop, push)
            Screen.Connection -> ConnectionScreen(pop)
            Screen.AutoLock -> AutoLockScreen(pop)
            Screen.Notifications -> NotificationsScreen(pop)
            Screen.Setup -> SetupScreen(pop, push)
            Screen.ResetIdentity -> ResetIdentityScreen(pop)
            Screen.SocialRecovery -> SocialRecoveryScreen(pop, push)
            Screen.UserHalf -> SecretDigitsScreen(
                stringResource(R.string.main_user_half_title),
                stringResource(R.string.main_user_half_body),
                pop,
            ) { Core.userHalf(it) }
            Screen.AutoDownload -> AutoDownloadScreen(pop)
            Screen.ChangePassphrase -> ChangePassphraseScreen(pop)
            Screen.RecoveryCode -> RecoveryCodeScreen(pop, push)
            // IDN-003: the seed that rebuilds the identity and no contact.
            Screen.RootSeed -> SecretDigitsScreen(
                stringResource(R.string.main_root_seed_title),
                stringResource(R.string.main_root_seed_body),
                pop,
            ) { loaded -> Core.rootSeed(loaded) }
            Screen.Devices -> DevicesScreen(pop, push)
            Screen.LinkDevice -> LinkDeviceScreen(pop)
            Screen.TakeOver -> TakeOverScreen(pop)
            Screen.PublicLinks -> PublicLinksScreen(pop, push)
            is Screen.PublicLinkView -> PublicLinkScreen(top.id, pop)
            Screen.Handle -> HandleScreen(pop)
            Screen.Profile -> ProfileScreen(pop, push)
            Screen.Requests -> RequestsScreen(pop)
            is Screen.Search -> SearchScreen(top.scope, pop, push)
            else -> {
                val chat = Core.chats.firstOrNull { it.conversation == top.contact }
                // The list loads again after a lock or a new run.
                if (chat == null) {
                    LaunchedEffect(Unit) { pop() }
                } else {
                    ContactView(top, chat, stack, pop, push) { stack = it }
                }
            }
        }
    }
}

/** A view of one contact. */
@Composable
private fun ContactView(
    top: Screen,
    chat: Chat,
    stack: List<Screen>,
    pop: () -> Unit,
    push: (Screen) -> Unit,
    setStack: (List<Screen>) -> Unit,
) {
    when (top) {
        is Screen.Chat -> ChatScreen(chat, pop, push, top.target)
        is Screen.ContactDetails -> ContactDetailsScreen(
            chat,
            onBack = pop,
            onMessage = {
                // The details of a conversation lead back to it, and the
                // details of the contact list lead into it.
                val opened = Screen.Chat(chat.conversation)
                if (stack.dropLast(1).lastOrNull() == opened) pop() else setStack(listOf(opened))
            },
            push = push,
        )
        is Screen.EditName -> RenameContactScreen(chat, pop)
        is Screen.BlockContact -> BlockContactScreen(chat, pop)
        is Screen.BlockMember -> BlockMemberScreen(chat, top.index, top.name, pop)
        is Screen.ConversationSettings -> ConversationSettingsScreen(chat, pop, push)
        is Screen.HeldShare -> SecretDigitsScreen(
            stringResource(R.string.main_held_share_title, chat.title),
            stringResource(R.string.main_held_share_body, chat.title),
            pop,
        ) { Core.heldShareDigits(chat.conversation, it) }
        is Screen.Disappearing -> DisappearingScreen(chat, pop)
        is Screen.NewPoll -> NewPollScreen(chat, pop)
        is Screen.Alerts -> AlertsScreen(chat, pop)
        is Screen.Verify -> VerifyScreen(chat, pop, push)
        is Screen.VerifyCode -> VerifyCodeScreen(chat, top.starts, pop)
        is Screen.SafetyNumber -> SafetyNumberScreen(chat, pop)
        is Screen.Photo -> PhotoScreen(top.line, chat, pop)
        is Screen.Video -> VideoScreen(top.line, pop)
        is Screen.Media -> MediaScreen(chat, pop, push)
        is Screen.GroupDetails -> GroupDetailsScreen(chat, pop, push)
        is Screen.InviteToGroup -> InviteToGroupScreen(chat, pop)
        is Screen.GroupMembers -> GroupMembersScreen(chat, pop, push)
        is Screen.RemoveMember -> RemoveMemberScreen(chat, top.index, top.name, pop) {
            // The role view of a member that left shows nothing true.
            val under = stack.dropLast(1).lastOrNull()
            setStack(stack.dropLast(if (under is Screen.MemberRole) 2 else 1))
        }
        is Screen.LeaveGroup -> LeaveGroupScreen(chat, pop) { setStack(listOf()) }
        is Screen.MemberRole ->
            MemberRoleScreen(chat, top.index, top.name, top.role, top.ownRole, pop, push)
        is Screen.ScanSafetyNumber -> ScanSafetyNumberScreen(chat, pop)
        else -> Unit
    }
}

/** Closes the keyboard of the platform when `key` changes. */
@Composable
fun HideKeyboardOn(key: Any?) {
    val view = LocalView.current
    LaunchedEffect(key) {
        val keyboard = view.context.getSystemService(InputMethodManager::class.java)
        keyboard.hideSoftInputFromWindow(view.windowToken, 0)
    }
}

@Composable
private fun UnlockScreen() {
    val context = LocalContext.current
    val field = rememberPlatformField()
    // A new store takes its passphrase twice: no party resets one with a
    // typing error in it.
    val confirm = rememberPlatformField()
    var mismatch by remember { mutableStateOf(false) }
    val isFirst = remember { !Core.hasStore(context) }
    var isRestoring by remember { mutableStateOf(false) }
    var isJoining by remember { mutableStateOf(false) }
    val isOpening = Core.phase == Core.Phase.Opening

    // The field is gone while the store opens, and its keyboard goes too.
    HideKeyboardOn(isOpening)

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        // The block starts at one height in each state, thus nothing jumps
        // when the field gives way to the progress bar.
        Spacer(Modifier.height(132.dp))
        BrandHero()
        Spacer(Modifier.height(28.dp))
        when {
            isOpening -> Headline(stringResource(R.string.main_opening))
            isFirst && isRestoring -> Headline(stringResource(R.string.main_restore))
            isFirst && isJoining -> Headline(stringResource(R.string.main_link_this_device))
            // The one fact that a user cannot know: no party resets it.
            isFirst -> Headline(
                stringResource(R.string.main_choose_passphrase),
                stringResource(R.string.main_nobody_can_reset),
            )
            else -> Headline(stringResource(R.string.main_welcome_back))
        }
        Spacer(Modifier.height(20.dp))
        if (isFirst && isRestoring && !isOpening) {
            RestoreForm(onCancel = { isRestoring = false })
        } else if (isFirst && isJoining && !isOpening) {
            JoinForm(onCancel = { isJoining = false })
        } else if (isOpening) {
            Text(
                stringResource(if (isFirst) R.string.main_protecting else R.string.main_unlocking),
                style = MaterialTheme.typography.bodySmall,
                color = Palette.TextSecondary,
            )
            Spacer(Modifier.height(10.dp))
            // The time of the key derivation is a few seconds by design, and
            // the client knows no part of it, thus the bar shows no amount.
            LinearProgressIndicator(
                modifier = Modifier.fillMaxWidth().height(5.dp).clip(CircleShape),
                color = Palette.Action,
                trackColor = Palette.Container,
            )
        } else {
            FramedPlatformField(field, stringResource(R.string.main_passphrase), isPassphrase = true)
            if (isFirst) {
                Spacer(Modifier.height(14.dp))
                FramedPlatformField(confirm, stringResource(R.string.main_confirm_passphrase), isPassphrase = true)
            }
            Spacer(Modifier.height(14.dp))
            PrimaryButton(stringResource(if (isFirst) R.string.main_create_and_open else R.string.main_unlock)) {
                val first = field.take()
                if (!isFirst) {
                    first?.let { Core.open(context, it) }
                    return@PrimaryButton
                }

                val second = confirm.take()
                mismatch = first == null || second == null || !first.contentEquals(second)
                second?.fill('\u0000')

                if (mismatch) {
                    first?.fill('\u0000')
                } else {
                    first?.let { Core.open(context, it) }
                }
            }
            if (mismatch) {
                Spacer(Modifier.height(10.dp))
                Note(stringResource(R.string.main_passphrases_differ), isError = true)
            }
            if (isFirst) {
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.main_restore_from_code)) { isRestoring = true }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.main_link_to_another_device)) { isJoining = true }
            }
        }
        Core.fault?.let {
            Spacer(Modifier.height(16.dp))
            Note(it, isError = true)
        }
        if (!isOpening) BuildNetwork.Panel()
    }
}

@Composable
private fun TabsScreen(tab: Tab, onTab: (Tab) -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BrandBar(onConnection = { push(Screen.Connection) }, onProfile = { push(Screen.Profile) })
        Box(Modifier.weight(1f)) {
            when (tab) {
                Tab.Chats -> ChatsTab(push)
                Tab.Contacts -> ContactsTab(push)
                Tab.Settings -> SettingsTab(push)
            }
            // A contact or a group starts on the device that owns the
            // channels (Part 7 DEV-287).
            if (tab != Tab.Settings && Core.ownsChannels) {
                val addContact = stringResource(R.string.main_add_contact)
                Box(
                    Modifier
                        .align(Alignment.BottomEnd)
                        .padding(20.dp)
                        .size(56.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(Palette.Container)
                        .clickable(role = Role.Button, onClickLabel = addContact) {
                            push(Screen.AddContact)
                        },
                    contentAlignment = Alignment.Center,
                ) { FaIcon("user-plus", label = addContact, tint = Palette.Action) }
            }
        }
        Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min).background(Palette.Incoming)) {
            for (entry in Tab.entries) {
                val isSelected = entry == tab
                // The press shade fills the third of the bar that the item
                // holds, square and against its neighbors.
                Column(
                    Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .press(role = Role.Tab) { onTab(entry) }
                        .padding(vertical = 12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Box(
                        Modifier
                            .clip(CircleShape)
                            .background(if (isSelected) Palette.Container else Color.Transparent)
                            .padding(horizontal = 18.dp, vertical = 5.dp),
                    ) { FaIcon(entry.icon, size = 18.dp, tint = Palette.Text) }
                    Spacer(Modifier.height(2.dp))
                    Text(
                        stringResource(entry.label),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    )
                }
            }
        }
    }
}

@Composable
private fun TabTitle(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.headlineMedium,
        modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 12.dp),
    )
}

/**
 * One line for each current degraded state of Part 14 §14.9.2 (`IMP-077`).
 * A client that connects shows no line: the top bar holds that state. The
 * `admission surge` shows as a progress bar (`ABU-008`).
 */
@Composable
private fun ConnectionNote() {
    val fault = Core.fault
    val context = LocalContext.current
    // A degraded state stops nothing, thus it is no error (`IMP-078`).
    val lines = buildList {
        fault?.let { add(it) }
        Core.degraded?.let { add(it) }
        if (BuildNetwork.isProvisional) add(UiText.get(R.string.umbra_ui_rel_126))
        // DEV-181: another device of the set removed this one.
        if (Core.removedFromSet) add(UiText.get(R.string.main_removed_from_set))
        if (Core.online && BuildNetwork.isClockCorrected) add(UiText.get(R.string.umbra_ui_rel_116))
        // GRP-229: a group record outside its slot window.
        // NTF-078: the same line for blobs that did not open while locked.
        if (Core.chats.any { it.isClockSuspect } || WakeStore.isClockSuspect(context)) {
            add(UiText.get(R.string.umbra_ui_grp_229))
        }
        // DEV-076 to DEV-079: a hole of the synced history shows, and a gap
        // takes no dismissal.
        for (hole in Core.historyHoles) {
            val name = hole.label.ifEmpty { UiText.get(R.string.main_a_removed_device) }
            add(
                if (hole.isArriving) {
                    UiText.get(R.string.main_history_arriving, name)
                } else {
                    UiText.plural(R.plurals.main_history_gap, hole.count.toInt(), name, hole.count.toLong())
                },
            )
        }
    }

    if (Core.connection?.admissionSurge == true) {
        LinearProgressIndicator(
            modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 12.dp).height(3.dp),
            color = Palette.Action,
            trackColor = Palette.Pressed,
        )
    }

    for (line in lines) {
        Box(Modifier.padding(start = 20.dp, end = 20.dp, top = 12.dp)) {
            Note(line, isError = line == fault)
        }
    }
}

@Composable
private fun ChatsTab(push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        // A degraded state has its one line above the title.
        ConnectionNote()
        SetupPrompt(push)
        GroupOfferPrompt()
        IntroductionPrompt()
        RosterForkPrompt()
        HeldDeletionsPrompt()
        RequestsPrompt(push)

        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { TabTitle(stringResource(R.string.main_tab_chats)) }
            Box(Modifier.padding(end = 8.dp, top = 8.dp)) {
                IconAction("magnifying-glass", stringResource(R.string.common_search)) { push(Screen.Search(null)) }
            }
        }

        var notice by remember { mutableStateOf<String?>(null) }
        LaunchedEffect(notice) {
            if (notice != null) {
                delay(4_000)
                notice = null
            }
        }
        notice?.let {
            Box(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 8.dp)) { Note(it) }
        }

        var acting by remember { mutableStateOf<Chat?>(null) }
        var muting by remember { mutableStateOf<Chat?>(null) }
        var deleting by remember { mutableStateOf<Chat?>(null) }
        var deletingHere by remember { mutableStateOf<Chat?>(null) }
        var deletingAll by remember { mutableStateOf<Chat?>(null) }

        // DEV-334: a conversation with a contact also goes for everyone. A
        // group offers the deletion for the own devices alone.
        val onDelete = { chat: Chat -> if (chat.isGroup) deletingHere = chat else deleting = chat }

        acting?.let { chat -> ChatOptions(chat, push, { muting = it }, onDelete) { acting = null } }
        muting?.let { chat -> MuteOptions(chat) { muting = null } }
        deleting?.let { chat ->
            ActionSheet(
                stringResource(R.string.main_delete_conversation_q),
                listOf(
                    RowEntry("trash-can", stringResource(R.string.common_delete_on_my_devices)) { deletingHere = chat },
                    RowEntry("trash-can", stringResource(R.string.chat_delete_for_everyone)) { deletingAll = chat },
                ),
                onDismiss = { deleting = null },
            )
        }

        deletingHere?.let { chat ->
            ActionSheet(
                stringResource(R.string.main_delete_on_my_devices_q),
                listOf(
                    RowEntry("trash-can", stringResource(R.string.common_delete_on_my_devices)) {
                        Core.deleteConversation(chat.conversation)
                        // DEV-129: the view says which deletion ran.
                        notice = UiText.get(R.string.main_deleted_on_your_devices)
                    },
                ),
                // DEV-333: the line of a deletion for the own devices.
                note = if (chat.isGroup) {
                    stringResource(R.string.main_delete_note_group)
                } else {
                    stringResource(R.string.main_delete_note_contact)
                },
                onDismiss = { deletingHere = null },
            )
        }

        deletingAll?.let { chat ->
            ActionSheet(
                stringResource(R.string.chat_delete_for_everyone_question),
                listOf(
                    RowEntry("trash-can", stringResource(R.string.chat_delete_for_everyone)) {
                        Core.deleteConversationForEveryone(chat.conversation) {
                            notice = UiText.get(R.string.chat_wait_between_deletions)
                        }
                        // DEV-129: the view says which deletion ran.
                        notice = UiText.get(R.string.main_asked_contact_to_delete_chat, chat.title)
                    },
                ),
                // DEV-334: each limit of the request.
                note = stringResource(R.string.umbra_ui_dev_334),
                onDismiss = { deletingAll = null },
            )
        }

        // A group with no message still shows: the user made it, and its
        // creation is the act that put it here.
        val withMessages = Core.chats.filter { it.preview != null || it.isGroup }
        if (withMessages.isEmpty()) {
            EmptyState(stringResource(R.string.main_no_conversations))
            return
        }

        LazyColumn {
            items(withMessages, key = { it.conversation.key }) { chat ->
                ChatRow(chat, onOpen = { push(Screen.Chat(chat.conversation)) }, onOptions = { acting = chat })
            }
        }
    }
}

/** The options of one conversation, at a long press of its row. */
@Composable
private fun ChatOptions(
    chat: Chat,
    push: (Screen) -> Unit,
    onMute: (Chat) -> Unit,
    onDelete: (Chat) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val entries = buildList {
        add(
            if (chat.isPinned) {
                RowEntry("thumbtack", stringResource(R.string.main_unpin)) { Core.setPinned(chat.conversation, false) }
            } else {
                RowEntry("thumbtack", stringResource(R.string.main_pin_to_top)) { Core.setPinned(chat.conversation, true) }
            },
        )
        add(
            if (chat.isMuted) {
                RowEntry("bell", stringResource(R.string.main_unmute), mutedLabel(context, chat.mutedUntilMs)) {
                    Core.setMutedUntil(chat.conversation, 0u)
                }
            } else {
                RowEntry("bell-slash", stringResource(R.string.main_mute)) { onMute(chat) }
            },
        )
        if (chat.unread > 0) {
            add(RowEntry("check", stringResource(R.string.main_mark_as_read)) { Core.markRead(chat.conversation) })
        }
        if (chat.isGroup) {
            add(RowEntry("circle-info", stringResource(R.string.main_group_details)) { push(Screen.GroupDetails(chat.conversation)) })
        } else {
            add(RowEntry("circle-info", stringResource(R.string.main_contact_details)) { push(Screen.ContactDetails(chat.conversation)) })
            add(RowEntry("gear", stringResource(R.string.common_conversation_settings)) { push(Screen.ConversationSettings(chat.conversation)) })
        }
        add(RowEntry("trash-can", stringResource(R.string.main_delete_conversation)) { onDelete(chat) })
    }

    ActionSheet(chat.title, entries, onDismiss = onDismiss)
}

/** The lengths of a mute (Part 7 `DEV-331`). */
@Composable
private fun MuteOptions(chat: Chat, onDismiss: () -> Unit) {
    fun after(ms: Long) = (System.currentTimeMillis() + ms).toULong()
    val hour = 3_600_000L

    ActionSheet(
        stringResource(R.string.main_mute_title, chat.title),
        listOf(
            RowEntry("clock", stringResource(R.string.main_mute_1_hour)) { Core.setMutedUntil(chat.conversation, after(hour)) },
            RowEntry("clock", stringResource(R.string.main_mute_8_hours)) { Core.setMutedUntil(chat.conversation, after(8 * hour)) },
            RowEntry("clock", stringResource(R.string.main_mute_1_week)) { Core.setMutedUntil(chat.conversation, after(7 * 24 * hour)) },
            RowEntry("bell-slash", stringResource(R.string.main_mute_until_unmute)) { Core.setMutedUntil(chat.conversation, MUTE_FOREVER) },
        ),
        onDismiss = onDismiss,
    )
}

/** The end of a mute, as a row of a sheet names it. */
private fun mutedLabel(context: android.content.Context, untilMs: ULong): String =
    if (untilMs == MUTE_FOREVER) {
        UiText.get(R.string.main_muted)
    } else {
        UiText.get(
            R.string.main_muted_until,
            DateUtils.formatDateTime(
                context,
                untilMs.toLong(),
                DateUtils.FORMAT_SHOW_TIME or DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH,
            ),
        )
    }

@Composable
private fun ChatRow(chat: Chat, onOpen: () -> Unit, onOptions: () -> Unit) {
    // The preview is a view of the platform, thus the press area lies above
    // the content.
    PressOver(
        Modifier.fillMaxWidth().pressShadeInList(),
        onClick = onOpen,
        longLabel = stringResource(R.string.main_conversation_options),
        onLongClick = onOptions,
    ) { ChatRowContent(chat) }
}

@Composable
private fun ChatRowContent(chat: Chat) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = PressInset, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Avatar(chat)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                chat.title,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            chat.preview?.let {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Part 6 §6.6.5: the newest message answers a message.
                    if (chat.isPreviewReply) {
                        FaIcon("reply", label = stringResource(R.string.main_reply), size = 11.dp, tint = Palette.TextSecondary)
                        Spacer(Modifier.width(5.dp))
                    }
                    PlatformText(
                        it,
                        Palette.TextSecondary,
                        sizeSp = 13f,
                        maxLines = 1,
                        prefix = if (chat.isPreviewOutgoing) stringResource(R.string.main_you_prefix) else "",
                    )
                }
            }
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (chat.isMuted) {
                    FaIcon("bell-slash", label = stringResource(R.string.main_muted), size = 12.dp, tint = Palette.TextSecondary)
                    Spacer(Modifier.width(6.dp))
                }
                if (chat.isPinned) {
                    FaIcon("thumbtack", label = stringResource(R.string.main_pinned), size = 12.dp, tint = Palette.TextSecondary)
                    Spacer(Modifier.width(6.dp))
                }
                Text(
                    timeLabel(LocalContext.current, chat.lastAtMs),
                    style = MaterialTheme.typography.labelSmall,
                    color = Palette.TextSecondary,
                )
            }
            if (chat.unread > 0) {
                Spacer(Modifier.height(4.dp))
                Box(
                    Modifier
                        .clip(CircleShape)
                        .background(Palette.Action)
                        .padding(horizontal = 7.dp, vertical = 2.dp),
                ) {
                    Text(
                        "${chat.unread}",
                        color = Palette.OnAction,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
    }
}

@Composable
private fun ContactsTab(push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        TabTitle(stringResource(R.string.main_tab_contacts))
        // A group is no contact, and its details are group details.
        val byName = Core.chats.filter { !it.isGroup }.sortedBy { it.title.lowercase() }
        if (byName.isEmpty()) {
            EmptyState(stringResource(R.string.main_no_contacts))
            return
        }

        LazyColumn {
            items(byName, key = { it.conversation.key }) { chat ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInList()
                        .press { push(Screen.ContactDetails(chat.conversation)) }
                        .padding(horizontal = PressInset, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(chat)
                    Spacer(Modifier.width(14.dp))
                    Text(chat.title, fontWeight = FontWeight.SemiBold)
                    if (chat.isVerified) {
                        Spacer(Modifier.width(8.dp))
                        FaIcon("shield-check", label = stringResource(R.string.common_verified), size = 14.dp, tint = Palette.Action)
                    }
                }
            }
        }
    }
}

@Composable
fun EmptyState(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.bodyLarge,
        color = Palette.TextSecondary,
        modifier = Modifier.padding(horizontal = 20.dp, vertical = 24.dp),
    )
}

@Composable
private fun SettingsTab(push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        TabTitle(stringResource(R.string.main_tab_settings))
        // This row leads to the settings of the lock. The lock
        // itself is the icon of the bar.
        SettingRow("lock", stringResource(R.string.main_app_lock), stringResource(R.string.main_app_lock_detail)) { push(Screen.AppLock) }
        SettingRow("bell", stringResource(R.string.common_notifications), Modes.mode(LocalContext.current).label) { push(Screen.Notifications) }

        var isChoosingLook by remember { mutableStateOf(false) }
        SettingRow("circle-half-stroke", stringResource(R.string.main_appearance), Appearances.choice.label) { isChoosingLook = true }
        if (isChoosingLook) {
            val context = LocalContext.current
            ActionSheet(
                title = stringResource(R.string.main_appearance),
                entries = Appearance.entries.map { look ->
                    RowEntry(if (look == Appearances.choice) "check" else "circle-half-stroke", look.label) {
                        Appearances.choose(context, look)
                        isChoosingLook = false
                    }
                },
                onDismiss = { isChoosingLook = false },
            )
        }

        SettingRow(
            "comment",
            stringResource(R.string.main_typing_indicators),
            stringResource(if (Core.typingEnabled) R.string.common_on else R.string.common_off),
        ) {
            Core.turnTyping(!Core.typingEnabled)
        }

        // DEV-020: the setting states its trade where the user sets it.
        var isChoosingAge by remember { mutableStateOf(false) }
        SettingRow("clock", stringResource(R.string.main_keep_history), historyLabel(Core.historyAge)) { isChoosingAge = true }
        if (isChoosingAge) {
            ActionSheet(
                title = stringResource(R.string.main_keep_history),
                entries = HISTORY_AGES.map { seconds ->
                    RowEntry("clock", historyLabel(seconds)) {
                        Core.keepHistoryFor(seconds)
                        isChoosingAge = false
                    }
                },
                note = stringResource(R.string.main_keep_history_note),
                onDismiss = { isChoosingAge = false },
            )
        }

        // DEV-202: a draft on the other devices is text that no one sent.
        if (Core.devices.size > 1) {
            SettingRow(
                "pen",
                stringResource(R.string.main_draft_sync),
                stringResource(if (Core.draftSync) R.string.common_on else R.string.common_off),
            ) {
                Core.turnDraftSync(!Core.draftSync)
            }
        }

        SettingRow("download", stringResource(R.string.main_automatic_download), autoDownloadLabel(Core.autoDownloadLimit, Core.autoDownloadWifiOnly)) {
            push(Screen.AutoDownload)
        }

        val context = LocalContext.current
        LaunchedEffect(Unit) { Core.readBackup() }
        val backupAt = Core.lastBackupAt
        val backup = if (backupAt == null) {
            stringResource(R.string.main_no_backup_yet)
        } else {
            stringResource(R.string.main_last_backup, timeLabel(context, backupAt * 1_000))
        }

        // The recovery code and the backups belong to the device that owns
        // the channels (Part 7 §7.7).
        if (Core.ownsChannels) {
            SettingRow("key", stringResource(R.string.common_recovery_code), backup) { push(Screen.RecoveryCode) }
        }
        SettingRow("laptop", stringResource(R.string.main_linked_devices), devicesLabel(Core.devices.size)) { push(Screen.Devices) }
        if (Core.ownsChannels) {
            SettingRow(
                "rotate",
                stringResource(R.string.common_reset_identity),
                stringResource(R.string.main_reset_identity_detail),
            ) { push(Screen.ResetIdentity) }
        }

        // DEV-008: a device leaves each set by an explicit local wipe.
        var isErasing by remember { mutableStateOf(false) }
        SettingRow(
            "trash-can",
            stringResource(R.string.main_erase_this_device),
            stringResource(R.string.main_erase_detail),
        ) { isErasing = true }
        if (isErasing) {
            ActionSheet(
                stringResource(R.string.main_erase_q),
                listOf(RowEntry("trash-can", stringResource(R.string.main_erase_this_device)) { Core.eraseDevice(context) }),
                note = stringResource(R.string.main_erase_note),
                onDismiss = { isErasing = false },
            )
        }

        LaunchedEffect(Unit) { Core.readDevices() }
    }
}

/** The periods of the history that the settings offer, in seconds. */
private val HISTORY_AGES = listOf(86_400L, 30L * 86_400, 365L * 86_400, -1L)

private fun historyLabel(seconds: Long): String = when {
    seconds < 0 -> UiText.get(R.string.main_history_forever)
    seconds <= 86_400 -> UiText.get(R.string.main_history_1_day)
    seconds <= 30L * 86_400 -> UiText.get(R.string.main_history_30_days)
    seconds <= 365L * 86_400 -> UiText.get(R.string.main_history_1_year)
    else -> UiText.get(R.string.main_history_forever)
}

/** The line of the devices row: the count of the other devices. */
private fun devicesLabel(count: Int): String = when (count) {
    0, 1 -> UiText.get(R.string.main_no_other_device)
    else -> UiText.plural(R.plurals.main_other_devices, count - 1, count - 1)
}

@Composable
private fun SettingRow(icon: String, title: String, detail: String, onClick: (() -> Unit)?) {
    Row(
        Modifier
            .fillMaxWidth()
            .pressShadeInList()
            .then(if (onClick != null) Modifier.press(onClick = onClick) else Modifier)
            .padding(horizontal = PressInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon(icon, size = 20.dp, tint = Palette.Text)
        Spacer(Modifier.width(18.dp))
        Column {
            Text(title)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = Palette.TextSecondary,
            )
        }
    }
}

/** `MSG_TTL` of Part 3: no record waits at a relay for longer. */
private const val MSG_TTL_MS = 45L * 86_400_000L

/**
 * IMP-181: the time that a message shows, which is the send time that its
 * sender wrote. A record that waited at the relay for the unlock thus shows
 * when it was sent. The value is advisory (`WIR-076`), thus it never shows
 * a time after the store of the message or before a record could wait, and
 * the view orders by the store time alone (`IMP-128`).
 */
val uniffi.umbra_ffi.MsgInfo.shownAtMs: Long
    get() {
        val stored = storedAtMs.toLong()
        val sent = sentAtMs.toLong()
        return if (sent in (stored - MSG_TTL_MS)..stored) sent else stored
    }

/**
 * The time of a list row: the clock today, and the day before that. The
 * platform reads the 12 or 24 hour setting of the user from the context.
 */
fun timeLabel(context: android.content.Context, atMs: Long): String {
    if (atMs == 0L) return ""

    val flags = if (DateUtils.isToday(atMs)) {
        DateUtils.FORMAT_SHOW_TIME
    } else {
        DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH
    }
    return DateUtils.formatDateTime(context, atMs, flags)
}
