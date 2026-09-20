package org.umbra.app

import android.text.format.DateUtils
import android.view.inputmethod.InputMethodManager
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** The views above the tabs. The list is a stack, and Back takes the top. */
sealed interface Screen {
    data object AddContact : Screen
    data object YourInvitation : Screen
    data object UseInvitation : Screen
    data class Chat(val conversation: Conversation) : Screen
}

enum class Tab(val label: String, val icon: String) {
    Chats("Chats", "comment"),
    Contacts("Contacts", "user-group"),
    Settings("Settings", "gear"),
}

@Composable
fun UmbraApp() {
    UmbraTheme {
        Surface(Modifier.fillMaxSize(), color = Palette.Surface) {
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
    when (val top = stack.lastOrNull()) {
        null -> TabsScreen(tab, onTab = { tab = it }, push)
        Screen.AddContact -> AddContactScreen(pop, push)
        Screen.YourInvitation -> YourInvitationScreen(pop)
        Screen.UseInvitation -> UseInvitationScreen(pop)
        is Screen.Chat -> {
            val chat = Core.chats.firstOrNull { it.conversation == top.conversation }
            // The list loads again after a lock or a new run.
            if (chat == null) LaunchedEffect(Unit) { pop() } else ChatScreen(chat, pop)
        }
    }
}

/** Closes the keyboard of the platform when `key` changes. */
@Composable
private fun HideKeyboardOn(key: Any?) {
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
    val isOpening = Core.phase == Core.Phase.Opening
    // The field is gone while the store opens, and its keyboard goes too.
    HideKeyboardOn(isOpening)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        // The block starts at one height in each state, thus nothing jumps
        // when the field gives way to the progress bar.
        Spacer(Modifier.height(132.dp))
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { HeroIcon("lock") }
        Spacer(Modifier.height(28.dp))
        when {
            isOpening -> Headline("Opening UMBRA", "Your conversations will be ready in a moment.")
            isFirst -> Headline(
                "Protect this device.",
                "Choose a passphrase. It opens your conversations on this device, and " +
                    "nobody can reset it for you.",
            )
            else -> Headline("Welcome back.", "Enter your passphrase to open your conversations.")
        }
        Spacer(Modifier.height(20.dp))
        if (isOpening) {
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
        BrandBar()
        Box(Modifier.weight(1f)) {
            when (tab) {
                Tab.Chats -> ChatsTab(push)
                Tab.Contacts -> ContactsTab(push)
                Tab.Settings -> SettingsTab()
            }
            if (tab != Tab.Settings) {
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
        Row(Modifier.fillMaxWidth().background(Palette.Incoming).padding(vertical = 8.dp)) {
            for (entry in Tab.entries) {
                val isSelected = entry == tab
                Column(
                    Modifier
                        .weight(1f)
                        .clickable(role = Role.Tab) { onTab(entry) }
                        .padding(vertical = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Box(
                        Modifier
                            .clip(CircleShape)
                            .background(if (isSelected) Palette.Container else Color.Transparent)
                            .padding(horizontal = 18.dp, vertical = 5.dp),
                    ) { FaIcon(entry.icon, size = 18.dp, tint = Palette.Text) }
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

@Composable
private fun ConnectionNote() {
    val context = LocalContext.current
    val fault = Core.fault
    when {
        fault != null -> Box(Modifier.padding(horizontal = 20.dp, vertical = 6.dp)) {
            Note(fault, isError = true)
        }
        !Core.online -> Row(
            Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "Connecting through three relays.",
                style = MaterialTheme.typography.bodySmall,
                color = Palette.TextSecondary,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { Core.connect(context) }) { Text("Try now") }
        }
    }
}

@Composable
private fun ChatsTab(push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        TabTitle("Chats")
        ConnectionNote()
        val withMessages = Core.chats.filter { it.preview != null }
        if (withMessages.isEmpty()) {
            EmptyState(
                "No conversations yet.",
                "Add a contact with a one-time invitation. No phone number and no " +
                    "public name is needed.",
            )
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
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(horizontal = 20.dp, vertical = 12.dp),
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
            EmptyState("No contacts yet.", "An invitation works one time, for one person.")
            return
        }
        val byName = Core.chats.sortedBy { it.title.lowercase() }
        LazyColumn {
            items(byName, key = { it.conversation.label }) { chat ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { push(Screen.Chat(chat.conversation)) }
                        .padding(horizontal = 20.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(chat)
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(chat.title, fontWeight = FontWeight.SemiBold)
                        Text(
                            if (chat.name.isEmpty()) "No name yet" else "Name only you see",
                            style = MaterialTheme.typography.bodySmall,
                            color = Palette.TextSecondary,
                            modifier = Modifier.subline(),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 24.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(body, style = MaterialTheme.typography.bodyMedium, color = Palette.TextSecondary)
    }
}

@Composable
private fun SettingsTab() {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        TabTitle("Settings")
        SettingRow("lock", "App lock", "Locks after 15 minutes with no action. Tap to lock now.") {
            Core.lock()
        }
        SettingRow(
            "signal",
            "Connection",
            if (Core.online) "Connected through three relays" else "Not connected. Tap to try now.",
        ) { Core.connect(context) }
        SettingRow(
            "bell",
            "Notifications",
            "Alerts show no text and no name. They arrive until the app locks.",
            onClick = null,
        )
        SettingRow(
            "shield-halved",
            "About this build",
            "Test build. Contacts and messages stay on this device. " +
                "Icons by Font Awesome, CC BY 4.0.",
            onClick = null,
        )
    }
}

@Composable
private fun SettingRow(icon: String, title: String, detail: String, onClick: (() -> Unit)?) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 20.dp, vertical = 14.dp),
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
    HorizontalDivider(Modifier.padding(start = 58.dp, end = 20.dp), color = Palette.Divider)
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
