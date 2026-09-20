package org.umbra.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

@Composable
fun AddContactScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar("Add contact", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { HeroIcon("link") }
            Spacer(Modifier.height(24.dp))
            Headline("A private way to say hello.", "Send a one-time invitation to someone you trust.")
            Spacer(Modifier.height(20.dp))
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(16.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(16.dp))
                    .padding(16.dp),
            ) {
                Text(
                    "No phone number or public handle needed.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                )
                Spacer(Modifier.height(10.dp))
                PrimaryButton("Create invitation", enabled = Core.online) {
                    Core.invitation = null
                    Core.invite()
                    push(Screen.YourInvitation)
                }
            }
            if (!Core.online) {
                Spacer(Modifier.height(10.dp))
                Note("An invitation needs a connection. UMBRA is connecting.")
            }
            Spacer(Modifier.height(12.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { push(Screen.UseInvitation) }
                    .padding(vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                FaIcon("qrcode", size = 20.dp, tint = Palette.Text)
                Spacer(Modifier.width(16.dp))
                Column {
                    Text("Use an invitation instead")
                    Text(
                        "Paste a link that someone gave you",
                        style = MaterialTheme.typography.bodySmall,
                        color = Palette.TextSecondary,
                        modifier = Modifier.subline(),
                    )
                }
            }
        }
    }
}

@Composable
fun YourInvitationScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        BackBar("Add contact", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline("Your invitation", "Works once. Expires in 14 days.")
            Spacer(Modifier.height(16.dp))
            val link = Core.invitation
            if (link == null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Asking a relay to hold the invitation.")
                }
                Core.fault?.let {
                    Spacer(Modifier.height(16.dp))
                    Note(it, isError = true)
                }
                return@Column
            }
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { QrCode(link) }
            Spacer(Modifier.height(16.dp))
            Text(
                link,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(16.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(16.dp))
                    .padding(16.dp),
            )
            Spacer(Modifier.height(12.dp))
            PrimaryButton("Share invitation") { share(context, link) }
            Spacer(Modifier.height(8.dp))
            SecondaryButton("Copy link") { copySensitive(context, link) }
            Spacer(Modifier.height(12.dp))
            Note("Share this link privately with the person you want to reach. The first person who opens it becomes the contact.")
        }
    }
}

/** The link as a QR code. The reader of the other device gets the same text. */
@Composable
private fun QrCode(link: String) {
    val matrix: BitMatrix = remember(link) {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 2,
        )
        QRCodeWriter().encode(link, BarcodeFormat.QR_CODE, 0, 0, hints)
    }
    Canvas(
        Modifier
            .size(220.dp)
            .background(Color.White, RoundedCornerShape(16.dp))
            .border(1.dp, Palette.Divider, RoundedCornerShape(16.dp))
            .padding(10.dp)
            .semantics { contentDescription = "The invitation as a QR code" },
    ) {
        val cell = size.minDimension / matrix.width
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix[x, y]) {
                    drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
                }
            }
        }
    }
}

@Composable
fun UseInvitationScreen(onBack: () -> Unit) {
    var pasted by remember { mutableStateOf("") }
    var isWaiting by remember { mutableStateOf(false) }
    // A contact or a fault ends the wait. The naming view opens by itself.
    LaunchedEffect(Core.fault) { if (Core.fault != null) isWaiting = false }
    Column(Modifier.fillMaxSize()) {
        BackBar("Use invitation", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { HeroIcon("qrcode") }
            Spacer(Modifier.height(24.dp))
            Headline("Someone invited you?", "Paste the link they shared.")
            Spacer(Modifier.height(20.dp))
            // An invitation is no message text, thus a composable field holds it.
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Invitation link") },
                placeholder = { Text("Paste a link") },
                // The input method changes no character of the pasted value.
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            if (isWaiting) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Opening the invitation through three relays.")
                }
            } else {
                PrimaryButton("Continue", enabled = Core.online && pasted.isNotBlank()) {
                    Core.fault = null
                    Core.accept(pasted)
                    pasted = ""
                    isWaiting = true
                }
            }
            Core.fault?.let {
                Spacer(Modifier.height(12.dp))
                Note(it, isError = true)
            }
            Spacer(Modifier.height(12.dp))
            Note("The link works for the first person who opens it. If it fails here, tell the person who sent it.")
        }
    }
}

@Composable
fun NameContactScreen(conversation: Conversation, onDone: () -> Unit) {
    var name by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        BackBar("New contact", onBack = onDone)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Box(
                    Modifier.size(84.dp).background(Palette.Avatars[1], CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        name.trim().firstOrNull()?.uppercase() ?: "?",
                        style = MaterialTheme.typography.headlineMedium,
                    )
                }
            }
            Spacer(Modifier.height(20.dp))
            Headline(
                "Make it familiar.",
                "Choose a name for this contact. Only you see this name, and it stays on this device.",
            )
            Spacer(Modifier.height(16.dp))
            // A name is a label of the user and no message text.
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(60) },
                label = { Text("Name for this contact") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Note("An invitation does not prove who is holding the other device.")
            Spacer(Modifier.height(16.dp))
            PrimaryButton("Save and open chat") {
                if (name.isNotBlank()) Core.setName(conversation, name)
                onDone()
            }
            TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
        }
    }
}

/** The edit view of a contact, after mockup 023: the avatar, the name, a note. */
@Composable
fun RenameContactScreen(chat: Chat, onDone: () -> Unit) {
    var name by remember { mutableStateOf(chat.name) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Edit contact", onBack = onDone)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Avatar(chat, size = 84) }
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(60) },
                label = { Text("Name only you see") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Note("This name stays on this device. It is not shared with your contact.")
            Spacer(Modifier.height(16.dp))
            PrimaryButton("Save") {
                Core.setName(chat.conversation, name)
                onDone()
            }
        }
    }
}

/** The share sheet of the platform. The user picks the app that carries the link. */
private fun share(context: Context, link: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, link)
    }
    context.startActivity(Intent.createChooser(send, "Share invitation"))
}

/** IMP-056: the clipboard preview of the platform hides a sensitive clip. */
private fun copySensitive(context: Context, text: String) {
    val clip = ClipData.newPlainText("UMBRA invitation", text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}
