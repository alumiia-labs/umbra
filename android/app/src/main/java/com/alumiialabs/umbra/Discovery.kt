package com.alumiialabs.umbra

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.IntrinsicSize
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.text.input.KeyboardCapitalization
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.ContactRequestInfo
import uniffi.umbra_ffi.PublicLink

/** The periods of a timed link, in seconds, and their labels. 0 is a link with no end. */
private val LinkPeriods = listOf(
    3_600uL to R.string.discovery_period_1_hour,
    86_400uL to R.string.discovery_period_1_day,
    604_800uL to R.string.discovery_period_1_week,
    2_592_000uL to R.string.discovery_period_30_days,
    0uL to R.string.common_no_end,
)

/** A row of a list that opens a view. */
@Composable
fun OpenRow(icon: String, title: String, detail: String? = null, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .pressShadeInColumn()
            .press(onClick = onClick)
            .padding(horizontal = PressInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon(icon, size = 20.dp, tint = Palette.Text)
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(title)
            if (detail != null) {
                Text(
                    detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.subline(),
                )
            }
        }
    }
}

/** The small label above a list of a view. */
@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        color = Palette.TextSecondary,
        modifier = Modifier.padding(horizontal = PressInset, vertical = 8.dp),
    )
}

/** DIS-138: the directory shows a version that this device did not write. */
@Composable
private fun TakeoverWarning(label: String) {
    if (label !in Core.directoryWarnings) return

    Spacer(Modifier.height(12.dp))
    Note(stringResource(R.string.discovery_takeover_warning, label), isError = true)
}

/** ABU-087: an entry at its limit of requests offers a new queue. */
@Composable
private fun LimitOffer(label: String) {
    if (label !in Core.entriesAtLimit) return

    Spacer(Modifier.height(12.dp))
    Note(stringResource(R.string.discovery_limit_reached))
    Spacer(Modifier.height(8.dp))
    SecondaryButton(
        stringResource(R.string.discovery_move_to_new_queue),
        enabled = Core.online && !Core.directoryBusy,
    ) {
        Core.rotateEntry(label)
    }
}

/** The line of a directory call that runs, or of its fault. */
@Composable
private fun DirectoryState(working: String) {
    if (Core.directoryBusy) {
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
            Spacer(Modifier.width(12.dp))
            Text(working)
        }
    }

    Core.directoryNote?.let {
        Spacer(Modifier.height(12.dp))
        Note(it, isError = true)
    }
}

/** The time until the end of a timed link, in the largest whole unit. */
private fun remaining(expiresAt: ULong): String {
    if (expiresAt == 0uL) return UiText.get(R.string.common_no_end)

    val left = expiresAt.toLong() - System.currentTimeMillis() / 1_000
    return when {
        left <= 0 -> UiText.get(R.string.discovery_ending)
        left < 3_600 -> UiText.get(R.string.discovery_ends_in_minutes, (left + 59) / 60)
        left < 86_400 -> UiText.get(R.string.discovery_ends_in_hours, (left + 3_599) / 3_600)
        else -> {
            val days = (left + 86_399) / 86_400
            UiText.plural(R.plurals.discovery_ends_in_days, days.toInt(), days)
        }
    }
}

/** The address part of a reusable link, which a list row shows. */
private fun shortLink(link: String): String = link.removePrefix("umbra://p/")

@Composable
fun PublicLinksScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    var period by remember { mutableStateOf(0uL) }

    LaunchedEffect(Unit) {
        Core.directoryNote = null
        Core.readDirectory()
    }

    // A new link opens its own view.
    LaunchedEffect(Core.madeLink) {
        Core.madeLink?.let { push(Screen.PublicLinkView(it)) }
        Core.madeLink = null
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.discovery_reusable_links), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            for ((seconds, title) in LinkPeriods) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInColumn()
                        .press(role = Role.RadioButton) { period = seconds }
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioMark(isChosen = period == seconds)
                    Spacer(Modifier.width(14.dp))
                    Text(stringResource(title))
                }
                HorizontalDivider(color = Palette.Divider)
            }

            Spacer(Modifier.height(14.dp))
            PrimaryButton(
                stringResource(R.string.discovery_create_link),
                enabled = Core.online && !Core.directoryBusy,
            ) {
                Core.createPublicLink(period)
            }
            DirectoryState(stringResource(R.string.discovery_publishing_link))
            Spacer(Modifier.height(14.dp))
            // IDN-024: the UI states the limit of a reusable link.
            Note(UiText.get(R.string.umbra_ui_idn_024))
            Spacer(Modifier.height(8.dp))
            // IDN-010 to IDN-013: a published address against an invitation.
            Note(UiText.get(R.string.umbra_ui_idn_010))

            if (Core.publicLinks.isNotEmpty()) {
                Spacer(Modifier.height(20.dp))
                SectionLabel(stringResource(R.string.discovery_your_links))
                for (link in Core.publicLinks) {
                    OpenRow("link", shortLink(link.link), remaining(link.expiresAt)) {
                        push(Screen.PublicLinkView(link.id.toList()))
                    }
                    HorizontalDivider(color = Palette.Divider)
                }
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
fun PublicLinkScreen(id: List<Byte>, onBack: () -> Unit) {
    val context = LocalContext.current
    val link = Core.publicLinks.firstOrNull { it.id.toList() == id }
    var isRetiring by remember { mutableStateOf(false) }

    // A retired link leaves the list, and its view closes.
    LaunchedEffect(link == null) { if (link == null) onBack() }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.discovery_reusable_link), onBack = onBack)
        link ?: return@Column
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline(stringResource(R.string.discovery_your_link), remaining(link.expiresAt))
            Spacer(Modifier.height(16.dp))
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                QrCode(link.link, description = stringResource(R.string.discovery_reusable_link_qr))
            }
            Spacer(Modifier.height(16.dp))
            MonoBox(link.link)
            TakeoverWarning(link.link)
            LimitOffer(link.link)

            Spacer(Modifier.height(12.dp))
            val shareLink = stringResource(R.string.common_share_link)
            val umbraLink = stringResource(R.string.common_umbra_link)
            PrimaryButton(shareLink) { shareText(context, link.link, shareLink) }
            Spacer(Modifier.height(8.dp))
            SecondaryButton(stringResource(R.string.common_copy_link)) { copySensitive(context, link.link, umbraLink) }
            Spacer(Modifier.height(8.dp))
            QuietButton(
                stringResource(if (isRetiring) R.string.discovery_retiring else R.string.discovery_retire_link),
            ) {
                if (!isRetiring) {
                    isRetiring = true
                    Core.retirePublicLink(link)
                }
            }
            LaunchedEffect(Core.directoryBusy) { if (!Core.directoryBusy) isRetiring = false }
            DirectoryState(stringResource(R.string.discovery_writing_link_end))
        }
    }
}

@Composable
fun HandleScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var name by remember { mutableStateOf("") }
    val focus = LocalFocusManager.current

    LaunchedEffect(Unit) {
        Core.directoryNote = null
        Core.readDirectory()
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_your_handle), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            val handle = Core.myHandle
            if (handle == null) {
                HeroIcon("globe")
                Spacer(Modifier.height(24.dp))
                Headline(stringResource(R.string.discovery_name_to_look_up))
                Spacer(Modifier.height(20.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it.take(32) },
                    label = { Text(stringResource(R.string.common_name)) },
                    prefix = { Text("@") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Ascii,
                        autoCorrectEnabled = false,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                PrimaryButton(
                    stringResource(R.string.discovery_claim_handle),
                    enabled = Core.online && !Core.directoryBusy && name.isNotBlank(),
                ) {
                    focus.clearFocus()
                    Core.claimHandle(name)
                }
                DirectoryState(stringResource(R.string.discovery_publishing_handle))

                Spacer(Modifier.height(14.dp))
                // Part 9 §9.3: the residual leak that the part states.
                Note(stringResource(R.string.discovery_handle_listed))
                Spacer(Modifier.height(8.dp))
                // IDN-010 to IDN-013: a published address against an invitation.
                Note(UiText.get(R.string.umbra_ui_idn_010))
            } else {
                Headline(handle)
                TakeoverWarning(handle)
                LimitOffer(handle)

                Spacer(Modifier.height(16.dp))
                // Part 9 §9.3.1: the link carries the key of the profile, and
                // the bare handle carries none.
                val link = Core.myHandleLink
                if (link != null) {
                    Text(
                        link,
                        style = MaterialTheme.typography.bodySmall,
                        color = Palette.TextSecondary,
                    )
                    Spacer(Modifier.height(12.dp))
                    val shareLink = stringResource(R.string.common_share_link)
                    val umbraLink = stringResource(R.string.common_umbra_link)
                    PrimaryButton(shareLink) { shareText(context, link, shareLink) }
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton(stringResource(R.string.common_copy_link)) {
                        copySensitive(context, link, umbraLink)
                    }
                    Spacer(Modifier.height(8.dp))
                }

                val umbraHandle = stringResource(R.string.discovery_umbra_handle)
                SecondaryButton(stringResource(R.string.discovery_copy_handle)) {
                    copySensitive(context, handle, umbraHandle)
                }

                Spacer(Modifier.height(24.dp))
                // Part 9 §9.9: a new key and a new rendezvous queue at one tap.
                QuietButton(stringResource(R.string.discovery_reset_contact_requests)) { Core.rotateHandleKey() }
                QuietButton(stringResource(R.string.discovery_release_handle)) { Core.releaseHandle() }
                DirectoryState(stringResource(R.string.discovery_writing_release))
            }
        }
    }
}

/**
 * The profile of the user: the picture, the name, and the welcome text of
 * the profile blob (Part 9 §9.3.1), and the ways that people find it.
 */
@Composable
fun ProfileScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    LaunchedEffect(Unit) { Core.readDirectory() }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.discovery_profile), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            ProfileFields()
            Spacer(Modifier.height(16.dp))
            HorizontalDivider(color = Palette.Divider)
            OpenRow(
                "globe",
                stringResource(R.string.common_your_handle),
                Core.myHandle ?: stringResource(R.string.discovery_none),
            ) { push(Screen.Handle) }
            OpenRow("link", stringResource(R.string.discovery_reusable_links)) { push(Screen.PublicLinks) }
        }
    }
}

/** The name and the welcome text of the profile blob (Part 9 §9.3.1). */
@Composable
private fun ProfileFields() {
    var name by remember { mutableStateOf("") }
    var welcome by remember { mutableStateOf("") }
    var picture by remember { mutableStateOf(ByteArray(0)) }
    var saved by remember { mutableStateOf("" to "") }
    val focus = LocalFocusManager.current

    LaunchedEffect(Unit) {
        Core.profile { held, text, image ->
            name = held
            welcome = text
            picture = image
            saved = held to text
        }
    }

    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        EditablePicture(
            hasPicture = picture.isNotEmpty(),
            onSet = { square -> Core.setProfilePicture(square) { picture = it } },
        ) { ProfilePicture(picture, name.ifEmpty { stringResource(R.string.discovery_me) }, EDITABLE_PICTURE_SIZE) }
    }

    Spacer(Modifier.height(20.dp))
    OutlinedTextField(
        value = name,
        onValueChange = { name = it.take(32) },
        label = { Text(stringResource(R.string.common_name)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = welcome,
        onValueChange = { welcome = it.take(280) },
        label = { Text(stringResource(R.string.discovery_welcome_text)) },
        maxLines = 4,
        modifier = Modifier.fillMaxWidth(),
    )

    Spacer(Modifier.height(12.dp))
    PrimaryButton(
        stringResource(R.string.common_save),
        enabled = Core.online && !Core.directoryBusy && (name to welcome) != saved,
    ) {
        focus.clearFocus()
        Core.setProfile(name, welcome)
        saved = name to welcome
    }
    Spacer(Modifier.height(8.dp))
    // A technical fact: the directory holds the sealed blob, not its key.
    Note(stringResource(R.string.discovery_profile_note))
}

@Composable
fun RequestsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    LaunchedEffect(Unit) { Core.readDirectory() }

    // The last request leaves the list, and the view closes.
    LaunchedEffect(Core.contactRequests.isEmpty()) {
        if (Core.contactRequests.isEmpty()) onBack()
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.discovery_contact_requests), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            for (request in Core.contactRequests) {
                RequestRow(context, request)
                HorizontalDivider(color = Palette.Divider)
            }
            Box(Modifier.padding(20.dp)) {
                // Part 9 §9.8: the name of a request is a claim of its sender.
                Note(stringResource(R.string.discovery_request_name_note))
            }
        }
    }
}

@Composable
private fun RequestRow(context: Context, request: ContactRequestInfo) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // DIS-180: the picture and the note that the sender chose.
            ProfilePicture(request.picture, request.name.ifBlank { "?" }, 44)
            Spacer(Modifier.width(14.dp))
            Column {
                Text(request.name.ifBlank { stringResource(R.string.discovery_no_name) })
                Text(
                    "${request.via.removePrefix("umbra://p/")} · " +
                        timeLabel(context, request.receivedAt.toLong() * 1_000),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.subline(),
                )
            }
        }

        if (request.note.isNotBlank()) {
            Spacer(Modifier.height(8.dp))
            Text(request.note, style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            InlineButton(stringResource(R.string.common_accept), enabled = Core.online) { Core.acceptRequest(request) }
            InlineButton(stringResource(R.string.discovery_decline)) { Core.declineRequest(request) }
        }
    }
}

/** The line of the chats that names the requests that wait. */
@Composable
fun RequestsPrompt(push: (Screen) -> Unit) {
    val count = Core.contactRequests.size
    if (count == 0) return

    Row(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .press { push(Screen.Requests) }
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon("user-plus", size = 18.dp, tint = Palette.Text)
        Spacer(Modifier.width(14.dp))
        Text(pluralStringResource(R.plurals.discovery_contact_requests_count, count, count))
    }
}

/** A value in the mono face on a framed ground, as the invitation view shows its link. */
@Composable
fun MonoBox(text: String) {
    Text(
        text,
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
}

/** The share sheet of the platform for a text. */
fun shareText(context: Context, text: String, title: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(send, title))
}
