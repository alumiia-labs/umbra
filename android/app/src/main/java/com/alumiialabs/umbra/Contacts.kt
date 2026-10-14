package com.alumiialabs.umbra

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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
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
        BackBar(stringResource(R.string.contacts_add_contact), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("link")
            Spacer(Modifier.height(24.dp))
            Headline(stringResource(R.string.contacts_say_hello))
            Spacer(Modifier.height(20.dp))
            PrimaryButton(stringResource(R.string.contacts_create_invitation), enabled = Core.online) {
                Core.invitation = null
                Core.invite()
                push(Screen.YourInvitation)
            }
            if (!Core.online) {
                Spacer(Modifier.height(10.dp))
                Note(stringResource(R.string.contacts_invitation_needs_connection))
            }
            Spacer(Modifier.height(12.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .pressShadeInColumn()
                    .press { push(Screen.UseInvitation) }
                    .padding(horizontal = PressInset, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                FaIcon("qrcode", size = 20.dp, tint = Palette.Text)
                Spacer(Modifier.width(16.dp))
                Text(stringResource(R.string.contacts_use_invitation_instead))
            }
            // The group of Part 11 starts beside the contacts.
            Row(
                Modifier
                    .fillMaxWidth()
                    .pressShadeInColumn()
                    .press { push(Screen.NewGroup) }
                    .padding(horizontal = PressInset, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                FaIcon("user-group", size = 20.dp, tint = Palette.Text)
                Spacer(Modifier.width(16.dp))
                Text(stringResource(R.string.contacts_new_private_group))
            }
            // Part 9: a link for many people, and a name to look up.
            if (Core.ownsChannels) {
                OpenRow("link", stringResource(R.string.contacts_reusable_link)) { push(Screen.PublicLinks) }
                OpenRow("globe", stringResource(R.string.common_your_handle), Core.myHandle) { push(Screen.Handle) }
            }
        }
    }
}

@Composable
fun YourInvitationScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.contacts_add_contact), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(
                stringResource(R.string.contacts_your_invitation),
                stringResource(R.string.contacts_invitation_expires),
            )
            Spacer(Modifier.height(16.dp))
            val link = Core.invitation
            if (link == null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.contacts_asking_relay))
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
                fontFamily = Fonts.Mono,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(16.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(16.dp))
                    .padding(16.dp),
            )
            Spacer(Modifier.height(12.dp))
            PrimaryButton(stringResource(R.string.contacts_share_invitation)) { share(context, link) }
            Spacer(Modifier.height(8.dp))
            SecondaryButton(stringResource(R.string.common_copy_link)) { copySensitive(context, link) }
            Spacer(Modifier.height(12.dp))
            Note(stringResource(R.string.contacts_first_person))
        }
    }
}

/** A text as a QR code. The reader of the other device gets the same text. */
@Composable
fun QrCode(link: String, description: String = stringResource(R.string.contacts_invitation_qr)) {
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
            .semantics { contentDescription = description },
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
fun UseInvitationScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    var pasted by remember { mutableStateOf("") }
    var isWaiting by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }
    var note by remember { mutableStateOf("") }
    val focus = LocalFocusManager.current
    LaunchedEffect(Unit) {
        Core.requestSent = false
        Core.directoryNote = null
        Core.takeoverOf = null
        Core.profileName { name = it }
    }
    // A reusable link, an `umbra:pub:` string, or a handle starts a request
    // (Part 4 §4.3.3). An invitation link opens as before.
    val isRequest = isRequestTarget(pasted)
    // A link that another app gave, which no tap of the user took yet. Each
    // app of the device can give one, thus it starts no lookup by itself.
    var given by remember { mutableStateOf<String?>(null) }
    // A tapped or shared link fills the field, and it waits for a tap.
    LaunchedEffect(Core.linkedInvitation) {
        Core.linkedInvitation?.let {
            given = it
            pasted = it
        }
        Core.linkedInvitation = null
    }
    val open = { link: String ->
        Core.fault = null
        if (isRequestTarget(link)) {
            pasted = link
        } else {
            Core.accept(link)
            isWaiting = true
        }
    }
    // The scanner gives the link of a code to this view.
    LaunchedEffect(Core.scannedInvitation) {
        Core.scannedInvitation?.let(open)
        Core.scannedInvitation = null
    }
    // A contact or a fault ends the wait. The naming view opens by itself.
    LaunchedEffect(Core.fault) { if (Core.fault != null) isWaiting = false }
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.contacts_use_invitation), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("qrcode")
            Spacer(Modifier.height(24.dp))
            Headline(stringResource(R.string.contacts_someone_invited_you))
            Spacer(Modifier.height(20.dp))
            if (!isWaiting) {
                PrimaryButton(stringResource(R.string.contacts_scan_qr_code), enabled = Core.online) {
                    push(Screen.ScanInvitation)
                }
                Spacer(Modifier.height(16.dp))
            }
            // An invitation is no message text, thus a composable field holds it.
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text(stringResource(R.string.contacts_link_or_handle)) },
                placeholder = { Text(stringResource(R.string.contacts_link_or_handle_hint)) },
                // The input method changes no character of the pasted value.
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            if (isRequest) {
                // Part 9 §9.3.1: a profile link shows the name and the
                // welcome text of its holder before the request.
                var preview by remember { mutableStateOf<uniffi.umbra_ffi.ContactPreview?>(null) }
                val isGiven = given != null && given == pasted.trim()
                LaunchedEffect(pasted) {
                    preview = null
                    if (!isGiven && pasted.trim().startsWith("umbra://h/")) {
                        Core.previewContact(pasted.trim()) { preview = it }
                    }
                }
                preview?.let { shown ->
                    ProfilePreview(shown)
                    Spacer(Modifier.height(12.dp))
                }
                if (isGiven && pasted.trim().startsWith("umbra://h/")) {
                    SecondaryButton(stringResource(R.string.contacts_look_up), enabled = Core.online) {
                        val link = pasted.trim()
                        given = null
                        Core.previewContact(link) { if (pasted.trim() == link) preview = it }
                    }
                    Spacer(Modifier.height(12.dp))
                }
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it.take(32) },
                    label = { Text(stringResource(R.string.contacts_your_name_in_request)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = note,
                    onValueChange = { note = it.take(280) },
                    label = { Text(stringResource(R.string.contacts_note)) },
                    maxLines = 4,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                if (Core.requestSent) {
                    Note(stringResource(R.string.contacts_request_sent))
                } else if (Core.directoryBusy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                        Spacer(Modifier.width(12.dp))
                        Text(stringResource(R.string.contacts_looking_up))
                    }
                } else if (Core.takeoverOf == pasted.trim()) {
                    // DIS-084, DIS-085: the hello goes only after a confirmation.
                    Note(UiText.get(R.string.umbra_ui_dis_084, pasted.trim()), isError = true)
                    Spacer(Modifier.height(12.dp))
                    SecondaryButton(stringResource(R.string.contacts_send_anyway), enabled = Core.online) {
                        Core.sendRequest(pasted.trim(), name, note, confirmed = true)
                    }
                } else {
                    SecondaryButton(stringResource(R.string.contacts_send_request), enabled = Core.online) {
                        // The keyboard leaves, thus the result shows.
                        focus.clearFocus()
                        Core.sendRequest(pasted.trim(), name, note)
                    }
                }
                Core.directoryNote?.let {
                    Spacer(Modifier.height(12.dp))
                    Note(it, isError = true)
                }
            } else if (isWaiting) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.contacts_opening_invitation))
                }
            } else {
                SecondaryButton(
                    stringResource(R.string.contacts_continue),
                    enabled = Core.online && pasted.isNotBlank(),
                ) {
                    open(pasted)
                    pasted = ""
                }
            }
            Core.fault?.let {
                Spacer(Modifier.height(12.dp))
                Note(it, isError = true)
            }
        }
    }
}

/** The profile of a handle, as its link shows it before a request. */
@Composable
private fun ProfilePreview(preview: uniffi.umbra_ffi.ContactPreview) {
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider(color = Palette.Divider)
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            ProfilePicture(preview.picture, preview.name.ifBlank { preview.handle.removePrefix("@") }, 56)
            Spacer(Modifier.width(14.dp))
            Column {
                Text(preview.name.ifBlank { preview.handle }, style = MaterialTheme.typography.titleMedium)
                if (preview.name.isNotBlank()) {
                    Text(preview.handle, style = MaterialTheme.typography.bodySmall, color = Palette.TextSecondary)
                }
            }
        }
        if (preview.welcome.isNotBlank()) {
            Spacer(Modifier.height(8.dp))
            Text(preview.welcome, style = MaterialTheme.typography.bodyMedium)
        }
        // SCP-006, IDN-014: a handle is no proof of a person.
        if (preview.handle.isNotBlank()) {
            Spacer(Modifier.height(8.dp))
            Note(UiText.get(R.string.umbra_ui_idn_014))
        }
        Spacer(Modifier.height(12.dp))
        HorizontalDivider(color = Palette.Divider)
    }
}

/** Whether a text names a reusable link, a Public Address, or a handle. */
fun isRequestTarget(text: String): Boolean {
    val trimmed = text.trim()
    return trimmed.startsWith("umbra://p/") || trimmed.startsWith("umbra:pub:") ||
        trimmed.startsWith("umbra://h/") ||
        (trimmed.startsWith("@") && trimmed.contains("#"))
}

@Composable
fun NameContactScreen(conversation: Conversation, onDone: () -> Unit) {
    // A request gave a name, which the user keeps or changes.
    var name by remember { mutableStateOf(Core.suggestedName.orEmpty().also { Core.suggestedName = null }) }
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.contacts_new_contact), onBack = onDone)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Box(
                    Modifier.size(84.dp).background(Palette.Avatars[1], CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        firstLetter(name.trim()),
                        style = MaterialTheme.typography.headlineMedium,
                    )
                }
            }
            Spacer(Modifier.height(20.dp))
            Headline(stringResource(R.string.contacts_name_this_contact))
            Spacer(Modifier.height(16.dp))
            // A name is a label of the user and no message text.
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(60) },
                label = { Text(stringResource(R.string.common_name)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.contacts_save_and_open_chat)) {
                if (name.isNotBlank()) Core.setName(conversation, name)
                onDone()
            }
            TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.contacts_not_now))
            }
        }
    }
}

/** The edit view of a contact: the avatar, the name, a note. */
@Composable
fun RenameContactScreen(chat: Chat, onDone: () -> Unit) {
    var name by remember { mutableStateOf(chat.name) }
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.contacts_edit_contact), onBack = onDone)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Avatar(chat, size = 84) }
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(60) },
                label = { Text(stringResource(R.string.common_name)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.common_save)) {
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
    context.startActivity(Intent.createChooser(send, UiText.get(R.string.contacts_share_invitation)))
}

/** IMP-056: the clipboard preview of the platform hides a sensitive clip. */
fun copySensitive(context: Context, text: String, label: String = UiText.get(R.string.contacts_umbra_invitation)) {
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}
