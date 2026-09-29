package org.umbra.app

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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
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
    data object PublicLinks : Screen
    data class PublicLinkView(val id: List<Byte>) : Screen
    data object Handle : Screen
    data object Requests : Screen
    data class Chat(val conversation: Conversation) : Screen
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

enum class Tab(val label: String, val icon: String) {
    Chats("Chats", "comment"),
    Contacts("Contacts", "user-group"),
    Settings("Settings", "gear"),
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
    // A tapped or shared invitation link opens the view of the link.
    LaunchedEffect(Core.linkedInvitation) {
        if (Core.linkedInvitation != null && stack.lastOrNull() != Screen.UseInvitation) {
            stack = listOf(Screen.UseInvitation)
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
        if (top == null) RecoveryPromptLine(push)
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
            Screen.ResetIdentity -> ResetIdentityScreen(pop)
            Screen.SocialRecovery -> SocialRecoveryScreen(pop, push)
            Screen.UserHalf -> SecretDigitsScreen(
                "Your user half",
                "Keep this half yourself. With the pieces of your contacts it restores your account.",
                pop,
            ) { Core.userHalf(it) }
            Screen.AutoDownload -> AutoDownloadScreen(pop)
            Screen.ChangePassphrase -> ChangePassphraseScreen(pop)
            Screen.RecoveryCode -> RecoveryCodeScreen(pop, push)
            // IDN-003: the seed that rebuilds the identity and no contact.
            Screen.RootSeed -> SecretDigitsScreen(
                "Root seed",
                "These digits rebuild your identity on a new device, with no contact and no message. " +
                    "The recovery code restores the backup.",
                pop,
            ) { loaded -> Core.rootSeed(loaded) }
            Screen.Devices -> DevicesScreen(pop, push)
            Screen.LinkDevice -> LinkDeviceScreen(pop)
            Screen.PublicLinks -> PublicLinksScreen(pop, push)
            is Screen.PublicLinkView -> PublicLinkScreen(top.id, pop)
            Screen.Handle -> HandleScreen(pop)
            Screen.Requests -> RequestsScreen(pop)
            else -> {
                val chat = Core.chats.firstOrNull { it.conversation == top.contact }
                // The list loads again after a lock or a new run.
                if (chat == null) LaunchedEffect(Unit) { pop() } else ContactView(top, chat, stack, pop, push) { stack = it }
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
        is Screen.Chat -> ChatScreen(chat, pop, push)
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
            "Share of ${chat.title}",
            "Read these digits only to ${chat.title}, in person or over a call that you trust.",
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
            isOpening -> Headline("Opening UMBRA")
            isFirst && isRestoring -> Headline("Restore")
            isFirst && isJoining -> Headline("Link this device")
            // The one fact that a user cannot know: no party resets it.
            isFirst -> Headline("Choose a passphrase.", "Nobody can reset it for you.")
            else -> Headline("Welcome back.")
        }
        Spacer(Modifier.height(20.dp))
        if (isFirst && isRestoring && !isOpening) {
            RestoreForm(onCancel = { isRestoring = false })
        } else if (isFirst && isJoining && !isOpening) {
            JoinForm(onCancel = { isJoining = false })
        } else if (isOpening) {
            Text(
                if (isFirst) "Protecting this device…" else "Unlocking this device…",
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
            FramedPlatformField(field, "Passphrase", isPassphrase = true)
            Spacer(Modifier.height(14.dp))
            PrimaryButton(if (isFirst) "Create and open" else "Unlock") {
                field.take()?.let { Core.open(context, it) }
            }
            if (isFirst) {
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Restore from a recovery code") { isRestoring = true }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Link to another device") { isJoining = true }
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
        BrandBar { push(Screen.Connection) }
        Box(Modifier.weight(1f)) {
            when (tab) {
                Tab.Chats -> ChatsTab(push)
                Tab.Contacts -> ContactsTab(push)
                Tab.Settings -> SettingsTab(push)
            }
            // A contact or a group starts on the device that owns the
            // channels (Part 7 DEV-287).
            if (tab != Tab.Settings && Core.ownsChannels) {
                Box(
                    Modifier
                        .align(Alignment.BottomEnd)
                        .padding(20.dp)
                        .size(56.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(Palette.Container)
                        .clickable(role = Role.Button, onClickLabel = "Add a contact") {
                            push(Screen.AddContact)
                        },
                    contentAlignment = Alignment.Center,
                ) { FaIcon("user-plus", label = "Add a contact", tint = Palette.Action) }
            }
        }
        Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min).background(Palette.Incoming)) {
            for (entry in Tab.entries) {
                val isSelected = entry == tab
                // The press shade fills the third of the bar that the item
                // holds, square and against its neighbours.
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
                        entry.label,
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
    // A degraded state stops nothing, thus it is no error (`IMP-078`).
    val lines = buildList {
        fault?.let { add(it) }
        Core.degraded?.let { add(it) }
        if (BuildNetwork.isProvisional) add(UiText.get(R.string.umbra_ui_rel_126))
        if (Core.online && BuildNetwork.isClockCorrected) add(UiText.get(R.string.umbra_ui_rel_116))
        // DEV-076 to DEV-079: a hole of the synced history shows, and a gap
        // takes no dismissal.
        for (hole in Core.historyHoles) {
            val name = hole.label.ifEmpty { "a removed device" }
            add(
                if (hole.isArriving) {
                    "History from $name is still arriving."
                } else {
                    "History from $name has a gap: ${hole.count} items did not arrive."
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
        // Mockup 153: a degraded state has its one line above the title.
        ConnectionNote()
        GroupOfferPrompt()
        IntroductionPrompt()
        RosterForkPrompt()
        RequestsPrompt(push)
        TabTitle("Chats")
        // A group with no message still shows: the user made it, and its
        // creation is the act that put it here.
        val withMessages = Core.chats.filter { it.preview != null || it.isGroup }
        if (withMessages.isEmpty()) {
            EmptyState("No conversations yet.")
            return
        }
        LazyColumn {
            items(withMessages, key = { it.conversation.label }) { chat ->
                ChatRow(chat) { push(Screen.Chat(chat.conversation)) }
            }
        }
    }
}

@Composable
private fun ChatRow(chat: Chat, onOpen: () -> Unit) {
    // The preview is a view of the platform, thus the press area lies above
    // the content.
    PressOver(Modifier.fillMaxWidth().pressShadeInList(), onClick = onOpen) { ChatRowContent(chat) }
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
                PlatformText(
                    it,
                    Palette.TextSecondary,
                    modifier = Modifier.subline(),
                    sizeSp = 13f,
                    maxLines = 1,
                    prefix = if (chat.isPreviewOutgoing) "You: " else "",
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(
                timeLabel(LocalContext.current, chat.lastAtMs),
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
            )
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
                        color = Color.White,
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
        TabTitle("Contacts")
        if (Core.chats.isEmpty()) {
            EmptyState("No contacts yet.")
            return
        }
        val byName = Core.chats.sortedBy { it.title.lowercase() }
        LazyColumn {
            items(byName, key = { it.conversation.label }) { chat ->
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
                        FaIcon("shield-check", label = "Verified", size = 14.dp, tint = Palette.Action)
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
        TabTitle("Settings")
        // Mockup 105: this row leads to the settings of the lock. The lock
        // itself is the icon of the bar.
        SettingRow("lock", "App lock", "Passphrase and auto-lock") { push(Screen.AppLock) }
        SettingRow("bell", "Notifications", Modes.mode(LocalContext.current).label) { push(Screen.Notifications) }
        SettingRow("comment", "Typing indicators", if (Core.typingEnabled) "On" else "Off") {
            Core.turnTyping(!Core.typingEnabled)
        }
        SettingRow("download", "Automatic download", autoDownloadLabel(Core.autoDownloadLimit, Core.autoDownloadWifiOnly)) {
            push(Screen.AutoDownload)
        }
        val context = LocalContext.current
        LaunchedEffect(Unit) { Core.readBackup() }
        val backupAt = Core.lastBackupAt
        val backup = if (backupAt == null) "No backup yet" else "Last backup ${timeLabel(context, backupAt * 1_000)}"
        // The recovery code and the backups belong to the device that owns
        // the channels (Part 7 §7.7).
        if (Core.ownsChannels) {
            SettingRow("key", "Recovery code", backup) { push(Screen.RecoveryCode) }
        }
        SettingRow("laptop", "Linked devices", devicesLabel(Core.devices.size)) { push(Screen.Devices) }
        if (Core.ownsChannels) {
            SettingRow("rotate", "Reset identity", "For a device in hostile hands") { push(Screen.ResetIdentity) }
        }
        // DEV-008: a device leaves each set by an explicit local wipe.
        var isErasing by remember { mutableStateOf(false) }
        SettingRow("trash-can", "Erase this device", "Each key and message on it") { isErasing = true }
        if (isErasing) {
            ActionSheet(
                "Erase this device?",
                listOf(RowEntry("trash-can", "Erase this device") { Core.eraseDevice(context) }),
                note = "This deletes each message, contact, and key on this device. A backup, and each " +
                    "other device of your set, keeps what it holds. The app then starts as new.",
                onDismiss = { isErasing = false },
            )
        }
        LaunchedEffect(Unit) { Core.readDevices() }
    }
}

/** The line of the devices row: the count of the other devices. */
private fun devicesLabel(count: Int): String = when (count) {
    0, 1 -> "No other device"
    2 -> "1 other device"
    else -> "${count - 1} other devices"
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
                modifier = Modifier.subline(),
            )
        }
    }
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
