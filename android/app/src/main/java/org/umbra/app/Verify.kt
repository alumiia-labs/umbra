package org.umbra.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.umbra_ffi.Receipts

/** The details of one contact: who it is, and what the user can do with it. */
@Composable
fun ContactDetailsScreen(chat: Chat, onBack: () -> Unit, onMessage: () -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar("Contact details", onBack = onBack)
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(12.dp))
            Avatar(chat, size = 84)
            Spacer(Modifier.height(12.dp))
            Text(chat.title, style = MaterialTheme.typography.headlineMedium)
            if (chat.isVerified) {
                Spacer(Modifier.height(6.dp))
                VerifiedMark()
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton("Message", onClick = onMessage)
            Spacer(Modifier.height(8.dp))
            EntryRow(RowEntry("pen", "Edit name") { push(Screen.EditName(chat.conversation)) })
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("shield-check", if (chat.isVerified) "Verify again" else "Verify contact") {
                    push(Screen.Verify(chat.conversation))
                },
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("photo-film", "Media and files") {
                    push(Screen.Media(chat.conversation))
                },
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("gear", "Conversation settings") {
                    push(Screen.ConversationSettings(chat.conversation))
                },
            )
            HorizontalDivider(color = Palette.Divider)
            var isBlocked by remember { mutableStateOf(false) }
            LaunchedEffect(chat.conversation, Core.revision) {
                Core.isBlocked(chat.conversation) { isBlocked = it }
            }
            EntryRow(
                RowEntry("ban", if (isBlocked) "Unblock" else "Block") {
                    push(Screen.BlockContact(chat.conversation))
                },
            )
        }
    }
}

/** The settings of one conversation: its timer, and the receipts that this device sends. */
@Composable
fun ConversationSettingsScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var receipts by remember { mutableStateOf<Receipts?>(null) }
    var timer by remember { mutableStateOf<UInt?>(null) }
    LaunchedEffect(chat.conversation) { Core.receipts(chat.conversation) { receipts = it } }
    LaunchedEffect(chat.conversation, Core.revision) { Core.timer(chat.conversation) { timer = it.seconds } }
    val change = { next: Receipts ->
        receipts = next
        Core.setReceipts(chat.conversation, next)
    }
    Column(Modifier.fillMaxSize()) {
        BackBar("Conversation settings", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            timer?.let {
                EntryRow(
                    RowEntry("clock", "Disappearing messages", timerLabel(it)) {
                        push(Screen.Disappearing(chat.conversation))
                    },
                )
                HorizontalDivider(color = Palette.Divider)
            }
            receipts?.let { now ->
                ToggleRow("Send delivery receipts", now.delivery) { change(Receipts(it, now.read)) }
                HorizontalDivider(color = Palette.Divider)
                ToggleRow("Send read receipts", now.read) { change(Receipts(now.delivery, it)) }
                Spacer(Modifier.height(12.dp))
                // A fact that a user cannot know, and that explains a wait.
                Note("A receipt leaves 30 seconds or more after the message, so its time tells a relay less.")
            }
        }
    }
}

@Composable
private fun VerifiedMark() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        FaIcon("shield-check", size = 14.dp, tint = Palette.Action)
        Spacer(Modifier.width(6.dp))
        Text("Verified", style = MaterialTheme.typography.labelLarge, color = Palette.Action)
    }
}

/** The ways to verify a contact: the code of the two keys, and the short code. */
@Composable
fun VerifyScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var number by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(chat.conversation) { Core.safetyNumber(chat.conversation) { number = it } }
    Column(Modifier.fillMaxSize()) {
        BackBar("Verify contact", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            // The one fact that decides the worth of a comparison: its channel.
            Headline("Compare with ${chat.title}", "In person, or over a call that you trust.")
            Spacer(Modifier.height(20.dp))
            number?.let {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    QrCode(it, "The safety number as a QR code")
                }
                Spacer(Modifier.height(20.dp))
            }
            // IDN-140: the scan is the first way, and the short code the second.
            PrimaryButton("Scan the code of ${chat.title}") { push(Screen.ScanSafetyNumber(chat.conversation)) }
            Spacer(Modifier.height(8.dp))
            SecondaryButton("Compare a short code") { push(Screen.VerifyCode(chat.conversation, starts = true)) }
            Spacer(Modifier.height(8.dp))
            EntryRow(RowEntry("key", "Full safety number") { push(Screen.SafetyNumber(chat.conversation)) })
        }
    }
}

/**
 * The short code of a ceremony. The device of the user that starts sends the
 * first record, and the two devices then show one code. The confirmation is
 * an act of the user, and the code alone verifies nothing.
 */
@Composable
fun VerifyCodeScreen(chat: Chat, starts: Boolean, onBack: () -> Unit) {
    val conversation = chat.conversation
    var isMismatch by remember { mutableStateOf(false) }
    val start = {
        isMismatch = false
        Core.startVerification(conversation)
    }
    LaunchedEffect(conversation) { if (starts) start() }
    // A code that the user left serves no later comparison.
    DisposableEffect(conversation) { onDispose { Core.endVerification() } }

    val code = Core.verifyCode?.takeIf { it.first == conversation }?.second
    val isDone = Core.verifiedNow == conversation
    val failure = Core.verifyFault
    Column(Modifier.fillMaxSize()) {
        BackBar("Verify ${chat.title}", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon(if (isMismatch) "triangle-exclamation" else "shield-check")
            Spacer(Modifier.height(20.dp))
            when {
                isDone -> {
                    Headline("You verified ${chat.title}.")
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Done", onClick = onBack)
                }
                isMismatch -> {
                    // A user cannot know what a mismatch means.
                    Headline(
                        "The codes do not match.",
                        "Another party can be between you and ${chat.title}.",
                    )
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Try again", onClick = start)
                }
                code != null -> {
                    Headline("Do your codes match?")
                    Spacer(Modifier.height(20.dp))
                    Text(
                        "${code.take(3)} ${code.drop(3)}",
                        fontSize = 40.sp,
                        letterSpacing = 4.sp,
                        color = Palette.Action,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(24.dp))
                    PrimaryButton("Yes, the codes match") { Core.confirmVerification(conversation) }
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton("They don't match") {
                        Core.endVerification()
                        isMismatch = true
                    }
                }
                failure != null -> {
                    Headline("No code yet.")
                    Spacer(Modifier.height(12.dp))
                    Note(failure, isError = true)
                    Spacer(Modifier.height(16.dp))
                    PrimaryButton("Try again", onClick = start)
                }
                else -> {
                    // The two devices make the code together.
                    Headline("Waiting for the device of ${chat.title}")
                    Spacer(Modifier.height(20.dp))
                    LinearProgressIndicator(
                        Modifier.fillMaxWidth(),
                        color = Palette.Action,
                        trackColor = Palette.Container,
                    )
                }
            }
        }
    }
}

/** The 60 digits of the two keys, for a comparison at a distance in time. */
@Composable
fun SafetyNumberScreen(chat: Chat, onBack: () -> Unit) {
    val context = LocalContext.current
    var number by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(chat.conversation) { Core.safetyNumber(chat.conversation) { number = it } }
    Column(Modifier.fillMaxSize()) {
        BackBar(chat.title, onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline("Safety number")
            Spacer(Modifier.height(16.dp))
            val groups = number?.split(' ').orEmpty()
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(24.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(24.dp))
                    .padding(vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                groups.chunked(3).forEach { row ->
                    Text(row.joinToString("  "), fontFamily = Fonts.Mono, fontSize = 17.sp)
                }
            }
            Spacer(Modifier.height(16.dp))
            // The number is a public value of the two devices, thus it is
            // no sensitive clip.
            SecondaryButton("Copy", enabled = number != null) {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Safety number", number))
            }
        }
    }
}

/**
 * A contact started a ceremony, and this device holds its code. The line
 * leads to the comparison.
 */
@Composable
fun VerifyPrompt(push: (Screen) -> Unit) {
    val (conversation, _) = Core.verifyCode ?: return
    val chat = Core.chats.firstOrNull { it.conversation == conversation } ?: return
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .background(Palette.Container, RoundedCornerShape(16.dp))
            .clickable(role = Role.Button) { push(Screen.VerifyCode(conversation, starts = false)) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon("shield-check", size = 18.dp, tint = Palette.Action)
        Spacer(Modifier.width(12.dp))
        Text("${chat.title} wants to compare codes", Modifier.weight(1f))
        FaIcon("chevron-right", size = 14.dp, tint = Palette.TextSecondary)
    }
}
