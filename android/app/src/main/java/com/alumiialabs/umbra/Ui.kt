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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.saveable.rememberSaveable

/** The views above the tabs. The list is a stack, and Back takes the top. */
sealed interface Screen {
    data object AddContact : Screen
    data object NewGroup : Screen
    data object YourInvitation : Screen
    data object UseInvitation : Screen
    data object ScanInvitation : Screen
    data object Connection : Screen
    data object Notifications : Screen
    data object Setup : Screen
    data object ResetIdentity : Screen
    data object SocialRecovery : Screen
    data object UserHalf : Screen
    data class HeldShare(val conversation: Conversation) : Screen
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
    data object AudioBench : Screen

    /** A conversation, at its end or at the message `target`. */
    data class Chat(val conversation: Conversation, val target: List<Byte>? = null) : Screen

    /** The search of one conversation, or of each one. */
    data class Search(val scope: Conversation?) : Screen
    data class ContactDetails(val conversation: Conversation) : Screen
    data class EditName(val conversation: Conversation) : Screen
    data class NewPoll(val conversation: Conversation) : Screen
    data class Verify(val conversation: Conversation) : Screen
    data class VerifyCode(val conversation: Conversation, val starts: Boolean) : Screen
    data class SafetyNumber(val conversation: Conversation) : Screen
    data class ScanSafetyNumber(val conversation: Conversation) : Screen
    data class Photo(val conversation: Conversation, val line: Line) : Screen
    data class Video(val conversation: Conversation, val line: Line) : Screen
    data class Media(val conversation: Conversation) : Screen
    data class GroupDetails(val conversation: Conversation) : Screen
    data class InviteToGroup(val conversation: Conversation) : Screen

    /** The conversation of a view of one contact. */
    val contact: Conversation?
        get() = when (this) {
            is Chat -> conversation
            is ContactDetails -> conversation
            is EditName -> conversation
            is HeldShare -> conversation
            is NewPoll -> conversation
            is Verify -> conversation
            is VerifyCode -> conversation
            is SafetyNumber -> conversation
            is ScanSafetyNumber -> conversation
            is Photo -> conversation
            is Video -> conversation
            is Media -> conversation
            is GroupDetails -> conversation
            is InviteToGroup -> conversation
            else -> null
        }
}

enum class Tab(val label: Int, val icon: String, val tag: String) {
    Chats(R.string.main_tab_chats, "comment", TestTags.TABS_CHATS),
    Contacts(R.string.main_tab_contacts, "user-group", TestTags.TABS_CONTACTS),
    Settings(R.string.main_tab_settings, "gear", TestTags.TABS_SETTINGS),
}

@Composable
fun UmbraApp() {
    UmbraTheme {
        // A photo on the whole screen has a dark ground under each bar.
        Surface(Modifier.fillMaxSize(), color = if (Viewer.isOpen) Color.Black else Palette.Surface) {
            // The root names each test tag as a resource id.
            Box(Modifier.testRoot().safeDrawingPadding().imePadding()) {
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
    // The tab stays across a change of the configuration, as a new font size.
    var tab by rememberSaveable { mutableStateOf(Tab.Chats) }
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
        val onNamed = {
            Core.toName = null
            stack = listOf(Screen.Chat(unnamed))
        }

        // Back does what the arrow of the bar does. Without this, it would
        // pop a view that this one hides, or leave the app.
        BackHandler(onBack = onNamed)
        NameContactScreen(unnamed, onDone = onNamed)
        return
    }

    val top = stack.lastOrNull()
    Column(Modifier.fillMaxSize()) {
        if (top !is Screen.VerifyCode) VerifyPrompt(push)
        FaultNotice(top)
        when (top) {
            null -> TabsScreen(tab, onTab = { tab = it }, push)
            Screen.AddContact -> AddContactScreen(pop, push)
            Screen.NewGroup -> NewGroupScreen(pop) { conversation ->
                stack = listOf(Screen.Chat(conversation))
            }
            Screen.YourInvitation -> YourInvitationScreen(pop)
            Screen.UseInvitation -> UseInvitationScreen(pop, push)
            Screen.ScanInvitation -> ScanInvitationScreen(pop)
            Screen.Connection -> ConnectionScreen(pop)
            Screen.Notifications -> NotificationsScreen(pop)
            Screen.Setup -> SetupScreen(pop, push)
            Screen.ResetIdentity -> ResetIdentityScreen(pop)
            Screen.SocialRecovery -> SocialRecoveryScreen(pop, push)
            Screen.UserHalf -> SecretDigitsScreen(
                stringResource(R.string.main_user_half_title),
                stringResource(R.string.main_user_half_body),
                pop,
            ) { Core.userHalf(it) }
            Screen.ChangePassphrase -> ChangePassphraseScreen(pop)
            Screen.RecoveryCode -> RecoveryCodeScreen(pop, push)
            // IDN-003: the seed that rebuilds the identity and no contact.
            Screen.RootSeed -> SecretDigitsScreen(
                stringResource(R.string.common_root_seed),
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
            Screen.AudioBench -> if (BuildConfig.AUDIO_BENCH) AudioBenchScreen(pop)
            is Screen.Search -> SearchScreen(top.scope, pop, push)
            else -> {
                val chat = Core.chats.firstOrNull { it.conversation == top.contact }
                // The list loads again after a lock or a new run. A contact
                // that left the list takes each of its views with it, thus
                // no view of it stays below the top.
                if (chat == null) {
                    LaunchedEffect(top) {
                        val gone = top.contact
                        stack = stack.filter { it.contact != gone }
                    }
                } else {
                    ContactView(top, chat, stack, pop, push) { stack = it }
                }
            }
        }
    }
}

/** Whether a view shows the fault of the core in a place of its own. */
private fun showsOwnFault(top: Screen?) = when (top) {
    null, Screen.NewGroup, Screen.YourInvitation, Screen.UseInvitation, Screen.LinkDevice -> true
    // A photo and a video fill the screen with a dark ground.
    is Screen.Chat, is Screen.Photo, is Screen.Video -> true
    else -> false
}

/**
 * The fault of the core on a view that has no place for it. Without this
 * line, a failure there showed nothing, and it showed later in the chat
 * list. A fault that is older than the view is not its fault, thus the
 * view does not show it. A tap takes the line away.
 */
@Composable
private fun FaultNotice(top: Screen?) {
    val older = remember(top) { Core.fault }
    val fault = Core.fault ?: return
    if (fault == older || showsOwnFault(top)) return

    Box(
        Modifier
            .padding(start = PressInset, end = PressInset, top = 12.dp)
            .press(role = Role.Button, label = stringResource(R.string.common_dismiss)) { Core.fault = null },
    ) { Note(fault, isError = true) }
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
        is Screen.HeldShare -> SecretDigitsScreen(
            stringResource(R.string.main_held_share_title, chat.title),
            stringResource(R.string.main_held_share_body, chat.title),
            pop,
        ) { Core.heldShareDigits(chat.conversation, it) }
        is Screen.NewPoll -> NewPollScreen(chat, pop)
        is Screen.Verify -> VerifyScreen(chat, pop, push)
        is Screen.VerifyCode -> VerifyCodeScreen(chat, top.starts, pop)
        is Screen.SafetyNumber -> SafetyNumberScreen(chat, pop)
        is Screen.Photo -> PhotoScreen(top.line, chat, pop)
        is Screen.Video -> VideoScreen(top.line, pop)
        is Screen.Media -> MediaScreen(chat, pop, push)
        is Screen.GroupDetails -> GroupDetailsScreen(chat, pop, onLeft = { setStack(listOf()) }, push = push)
        is Screen.InviteToGroup -> InviteToGroupScreen(chat, pop)
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

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = PressInset)) {
        // The block starts at one height in each state, thus nothing jumps
        // when the field gives way to the progress bar.
        Spacer(Modifier.height(132.dp))
        BrandHero()
        Spacer(Modifier.height(28.dp))
        when {
            isOpening -> Headline(stringResource(R.string.main_opening))
            isFirst && isRestoring -> Headline(stringResource(R.string.common_restore))
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
            WaitBar()
        } else {
            FramedPlatformField(field, stringResource(R.string.main_passphrase), isPassphrase = true, tag = TestTags.UNLOCK_PASSPHRASE)
            if (isFirst) {
                Spacer(Modifier.height(14.dp))
                FramedPlatformField(
                    confirm,
                    stringResource(R.string.main_confirm_passphrase),
                    isPassphrase = true,
                    tag = TestTags.UNLOCK_CONFIRM,
                )
            }
            Spacer(Modifier.height(14.dp))
            PrimaryButton(
                stringResource(if (isFirst) R.string.main_create_and_open else R.string.main_unlock),
                tag = TestTags.UNLOCK_OPEN,
            ) {
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
                SecondaryButton(stringResource(R.string.main_restore_from_code), tag = TestTags.UNLOCK_RESTORE) { isRestoring = true }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.main_link_to_another_device), tag = TestTags.UNLOCK_LINK) { isJoining = true }
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
                        .padding(PressInset)
                        .size(56.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(Palette.Container)
                        .tagged(TestTags.TABS_ADD)
                        .press(role = Role.Button) { push(Screen.AddContact) },
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
                        .tagged(entry.tag)
                        .pressChoice(isSelected, role = Role.Tab) { onTab(entry) }
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
        modifier = Modifier.padding(start = PressInset, end = PressInset, top = 20.dp, bottom = 12.dp),
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
    // REL-034: two signed views of the directory are a proof against its
    // signers. IDN-039: a table of the store did not match its MAC at a
    // move. Each one is an error, and no degraded state.
    val errors = buildList {
        fault?.let { add(it) }
        if (BuildNetwork.isSplitView) add(UiText.get(R.string.main_split_view))
        if (Core.migrationWasUnsound) add(UiText.get(R.string.main_migration_unsound))
    }
    val lines = buildList {
        addAll(errors)
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
            modifier = Modifier.fillMaxWidth().padding(start = PressInset, end = PressInset, top = 12.dp).height(3.dp),
            color = Palette.Action,
            trackColor = Palette.Pressed,
        )
    }

    for (line in lines) {
        Box(Modifier.padding(start = PressInset, end = PressInset, top = 12.dp)) {
            Note(line, isError = line in errors)
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
                IconAction("magnifying-glass", stringResource(R.string.common_search), tag = TestTags.TABS_SEARCH) { push(Screen.Search(null)) }
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
            Box(Modifier.padding(start = PressInset, end = PressInset, bottom = 8.dp)) { Note(it, tag = TestTags.CHATS_NOTICE) }
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
                stringResource(R.string.main_delete_chat_question),
                listOf(
                    RowEntry(
                        "trash-can",
                        stringResource(R.string.common_delete_on_my_devices),
                        tag = TestTags.MESSAGE_DELETE_FOR_ME,
                    ) { deletingHere = chat },
                    RowEntry(
                        "trash-can",
                        stringResource(R.string.chat_delete_for_everyone),
                        tag = TestTags.MESSAGE_DELETE_FOR_EVERYONE,
                    ) { deletingAll = chat },
                ),
                onDismiss = { deleting = null },
            )
        }

        deletingHere?.let { chat ->
            ActionSheet(
                stringResource(R.string.common_delete_on_my_devices_question),
                listOf(
                    RowEntry(
                        "trash-can",
                        stringResource(R.string.common_delete_on_my_devices),
                        tag = TestTags.MESSAGE_DELETE_CONFIRM,
                    ) {
                        Core.deleteConversation(chat.conversation)
                        // DEV-129: the view says which deletion ran.
                        notice = UiText.get(R.string.common_deleted_on_your_devices)
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
                    RowEntry(
                        "trash-can",
                        stringResource(R.string.chat_delete_for_everyone),
                        tag = TestTags.MESSAGE_DELETE_CONFIRM,
                    ) {
                        // DEV-129: the view says which deletion ran, after
                        // the core took the request.
                        val asked = UiText.get(R.string.main_asked_contact_to_delete_chat, chat.title)
                        Core.deleteConversationForEveryone(chat.conversation, onAsked = { notice = asked }) {
                            notice = UiText.get(R.string.chat_wait_between_deletions)
                        }
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
            EmptyState(stringResource(R.string.main_no_chats), tag = TestTags.CHATS_EMPTY)
            return
        }

        LazyColumn(Modifier.tagged(TestTags.CHATS_LIST)) {
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
            add(
                RowEntry("circle-info", stringResource(R.string.common_group_details), tag = TestTags.CHATS_OPTION_DETAILS) {
                    push(Screen.GroupDetails(chat.conversation))
                },
            )
        } else {
            add(
                RowEntry("circle-info", stringResource(R.string.common_contact_details), tag = TestTags.CHATS_OPTION_DETAILS) {
                    push(Screen.ContactDetails(chat.conversation))
                },
            )
        }
        add(RowEntry("trash-can", stringResource(R.string.main_delete_chat), tag = TestTags.CHATS_OPTION_DELETE) { onDelete(chat) })
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
        Modifier.fillMaxWidth().pressShadeInList().tagged(TestTags.CHATS_ROW),
        onClick = onOpen,
        longLabel = stringResource(R.string.main_chat_options),
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
                modifier = Modifier.tagged(TestTags.CHATS_ROW_TITLE),
            )
            chat.preview?.let {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Part 6 §6.6.5: the newest message answers a message.
                    if (chat.isPreviewReply) {
                        FaIcon("reply", label = stringResource(R.string.common_reply), size = 11.dp, tint = Palette.TextSecondary)
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
                        modifier = Modifier.tagged(TestTags.CHATS_ROW_UNREAD),
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
            EmptyState(stringResource(R.string.common_no_contacts))
            return
        }

        LazyColumn(Modifier.tagged(TestTags.CONTACTS_LIST)) {
            items(byName, key = { it.conversation.key }) { chat ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInList()
                        .tagged(TestTags.CONTACTS_ROW)
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
fun EmptyState(title: String, tag: String? = null) {
    Text(
        title,
        style = MaterialTheme.typography.bodyLarge,
        color = Palette.TextSecondary,
        modifier = Modifier.padding(horizontal = PressInset, vertical = 24.dp).tagged(tag),
    )
}

/**
 * The settings of this device in four groups. A setting with a few values
 * opens a sheet and a switch turns in place, thus a view of its own holds
 * more than one control.
 */
@Composable
private fun SettingsTab(push: (Screen) -> Unit) {
    val context = LocalContext.current
    var sheet by remember { mutableStateOf<SettingSheet?>(null) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        TabTitle(stringResource(R.string.main_tab_settings))
        Column(Modifier.padding(horizontal = PressInset)) {
            SectionLabel(stringResource(R.string.settings_general))
            EntryRow(
                RowEntry(
                    "circle-half-stroke",
                    stringResource(R.string.main_appearance),
                    Appearances.choice.label,
                    TestTags.SETTINGS_APPEARANCE,
                ) {
                    sheet = SettingSheet.Appearance
                },
                leads = false,
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry(
                    "bell",
                    stringResource(R.string.common_notifications),
                    Modes.mode(context).label,
                    TestTags.SETTINGS_NOTIFICATIONS,
                ) { push(Screen.Notifications) },
            )
            HorizontalDivider(color = Palette.Divider)
            ToggleRow(
                stringResource(R.string.main_typing_indicators),
                Core.typingEnabled,
                icon = "comment",
                tag = TestTags.SETTINGS_TYPING,
            ) { Core.turnTyping(it) }
            // DEV-202: a draft on the other devices is text that no one sent.
            if (Core.devices.size > 1) {
                HorizontalDivider(color = Palette.Divider)
                ToggleRow(
                    stringResource(R.string.main_draft_sync),
                    Core.draftSync,
                    icon = "pen",
                    tag = TestTags.SETTINGS_DRAFT_SYNC,
                ) { Core.turnDraftSync(it) }
            }

            SectionLabel(stringResource(R.string.settings_storage))
            EntryRow(
                RowEntry(
                    "clock",
                    stringResource(R.string.main_keep_history),
                    historyLabel(Core.historyAge),
                    TestTags.SETTINGS_HISTORY,
                ) {
                    sheet = SettingSheet.History
                },
                leads = false,
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry(
                    "download",
                    stringResource(R.string.common_automatic_download),
                    downloadLimitLabel(Core.autoDownloadLimit),
                    TestTags.SETTINGS_DOWNLOAD,
                ) {
                    sheet = SettingSheet.Download
                },
                leads = false,
            )
            // IMP-168: with no automatic download, no file waits for Wi-Fi.
            if (Core.autoDownloadLimit != 0uL) {
                HorizontalDivider(color = Palette.Divider)
                ToggleRow(stringResource(R.string.lock_only_on_wifi), Core.autoDownloadWifiOnly, icon = "wifi") {
                    Core.setAutoDownload(Core.autoDownloadLimit, it)
                }
            }

            SectionLabel(stringResource(R.string.settings_security))
            EntryRow(
                RowEntry("key", stringResource(R.string.common_change_passphrase), tag = TestTags.SETTINGS_PASSPHRASE) {
                    push(Screen.ChangePassphrase)
                },
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry(
                    "lock",
                    stringResource(R.string.lock_auto_lock),
                    autoLockLabel(Core.autoLockSeconds),
                    TestTags.SETTINGS_AUTO_LOCK,
                ) {
                    sheet = SettingSheet.AutoLock
                },
                leads = false,
            )

            SectionLabel(stringResource(R.string.settings_identity))
            LaunchedEffect(Unit) { Core.readBackup() }
            val backupAt = Core.lastBackupAt
            val backup = if (backupAt == null) {
                stringResource(R.string.main_no_backup_yet)
            } else {
                stringResource(R.string.main_last_backup, timeLabel(context, backupAt * 1_000))
            }
            // The recovery code and the backups belong to the device that
            // owns the channels (Part 7 §7.7).
            if (Core.ownsChannels) {
                EntryRow(
                    RowEntry(
                        "shield-halved",
                        stringResource(R.string.common_recovery_code),
                        backup,
                        TestTags.SETTINGS_RECOVERY,
                    ) { push(Screen.RecoveryCode) },
                )
                HorizontalDivider(color = Palette.Divider)
            }
            EntryRow(
                RowEntry(
                    "laptop",
                    stringResource(R.string.common_linked_devices),
                    devicesLabel(Core.devices.size),
                    TestTags.SETTINGS_DEVICES,
                ) { push(Screen.Devices) },
            )
            HorizontalDivider(color = Palette.Divider)
            if (Core.ownsChannels) {
                EntryRow(
                    RowEntry(
                        "rotate",
                        stringResource(R.string.common_reset_identity),
                        stringResource(R.string.main_reset_identity_detail),
                        TestTags.SETTINGS_RESET,
                    ) {
                        push(Screen.ResetIdentity)
                    },
                )
                HorizontalDivider(color = Palette.Divider)
            }
            // DEV-008: a device leaves each set by an explicit local wipe.
            EntryRow(
                RowEntry(
                    "trash-can",
                    stringResource(R.string.main_erase_this_device),
                    stringResource(R.string.main_erase_detail),
                    TestTags.SETTINGS_ERASE,
                ) {
                    sheet = SettingSheet.Erase
                },
                leads = false,
            )
            if (BuildConfig.AUDIO_BENCH) {
                SectionLabel(stringResource(R.string.bench_section))
                EntryRow(RowEntry("microphone", stringResource(R.string.bench_title)) { push(Screen.AudioBench) })
            }
            Spacer(Modifier.height(20.dp))
        }

        LaunchedEffect(Unit) { Core.readDevices() }
    }

    val close = { sheet = null }
    when (sheet) {
        SettingSheet.Appearance -> ChoiceSheet(
            stringResource(R.string.main_appearance),
            Appearance.entries.map { look ->
                SheetChoice(
                    look.label,
                    look == Appearances.choice,
                    tag = TestTags.choice(TestTags.APPEARANCE_CHOICE, look.name.lowercase()),
                ) { Appearances.choose(context, look) }
            },
            onDismiss = close,
        )
        // DEV-020: the setting states its trade where the user sets it.
        SettingSheet.History -> ChoiceSheet(
            stringResource(R.string.main_keep_history),
            HISTORY_AGES.map { seconds ->
                SheetChoice(
                    historyLabel(seconds),
                    historyLabel(seconds) == historyLabel(Core.historyAge),
                    tag = TestTags.choice(TestTags.HISTORY_CHOICE, seconds),
                ) {
                    Core.keepHistoryFor(seconds)
                }
            },
            note = stringResource(R.string.main_keep_history_note),
            onDismiss = close,
        )
        SettingSheet.Download -> AutoDownloadSheet(close)
        SettingSheet.AutoLock -> AutoLockSheet(close)
        SettingSheet.Erase -> ActionSheet(
            stringResource(R.string.main_erase_question),
            listOf(
                RowEntry("trash-can", stringResource(R.string.main_erase_this_device), tag = TestTags.SETTINGS_ERASE_CONFIRM) {
                    Core.eraseDevice(context)
                },
            ),
            note = stringResource(R.string.main_erase_note),
            onDismiss = close,
        )
        null -> Unit
    }
}

/** The sheets that a row of the settings opens. */
private enum class SettingSheet { Appearance, History, Download, AutoLock, Erase }

/** The periods of the history that the settings offer, in seconds. */
private val HISTORY_AGES = listOf(86_400L, 30L * 86_400, 365L * 86_400, -1L)

private fun historyLabel(seconds: Long): String = when {
    seconds < 0 -> UiText.get(R.string.main_history_forever)
    seconds <= 86_400 -> UiText.get(R.string.common_period_1_day)
    seconds <= 30L * 86_400 -> UiText.get(R.string.common_period_30_days)
    seconds <= 365L * 86_400 -> UiText.get(R.string.main_history_1_year)
    else -> UiText.get(R.string.main_history_forever)
}

/** The line of the devices row: the count of the other devices. */
private fun devicesLabel(count: Int): String = when (count) {
    0, 1 -> UiText.get(R.string.main_no_other_device)
    else -> UiText.plural(R.plurals.main_other_devices, count - 1, count - 1)
}

/** `MSG_TTL` of Part 3: no record waits at a relay for longer. */
private const val MSG_TTL_MS = 45L * 86_400_000L

/**
 * IMP-181: the time that a message shows, which is the send time that its
 * sender wrote. A record that waited at the relay for the unlock thus shows
 * when it was sent. The value is advisory (`WIR-076`), thus it never shows
 * a time after the store of the message or before a record could wait, and
 * the view orders by the order stamp alone (`IMP-128`). The bound is the
 * clock of this device at the store, because the stamp is no time.
 */
val uniffi.umbra_ffi.MsgInfo.shownAtMs: Long
    get() {
        val stored = clockAtMs.toLong()
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
