package org.umbra.app

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import uniffi.umbra_ffi.ContactRequestInfo
import uniffi.umbra_ffi.PublicLink

/** The periods of a timed link, in seconds. 0 is a link with no end. */
private val LinkPeriods = listOf(
    3_600uL to "1 hour",
    86_400uL to "1 day",
    604_800uL to "1 week",
    2_592_000uL to "30 days",
    0uL to "No end",
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
    Note(
        "The directory shows a version of $label that this device did not write. " +
            "Someone else may control it. Retire it, and make a new one.",
        isError = true,
    )
}

/** ABU-087: an entry at its limit of requests offers a new queue. */
@Composable
private fun LimitOffer(label: String) {
    if (label !in Core.entriesAtLimit) return
    Spacer(Modifier.height(12.dp))
    Note("This week's request limit is reached. New requests are dropped until you move to a new queue.")
    Spacer(Modifier.height(8.dp))
    SecondaryButton("Move to a new queue", enabled = Core.online && !Core.directoryBusy) {
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
    if (expiresAt == 0uL) return "No end"
    val left = expiresAt.toLong() - System.currentTimeMillis() / 1_000
    return when {
        left <= 0 -> "Ending"
        left < 3_600 -> "Ends in ${(left + 59) / 60} min"
        left < 86_400 -> "Ends in ${(left + 3_599) / 3_600} h"
        else -> "Ends in ${(left + 86_399) / 86_400} days"
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
        BackBar("Reusable links", onBack = onBack)
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
                    Text(title)
                }
                HorizontalDivider(color = Palette.Divider)
            }
            Spacer(Modifier.height(14.dp))
            PrimaryButton("Create link", enabled = Core.online && !Core.directoryBusy) {
                Core.createPublicLink(period)
            }
            DirectoryState("Publishing the link.")
            Spacer(Modifier.height(14.dp))
            // IDN-024: the UI states the limit of a reusable link.
            Note(
                "Each person with the link can send a request, and you accept each one. " +
                    "A reusable link has no first-open lock. Your device ends a timed link " +
                    "when it is online.",
            )
            if (Core.publicLinks.isNotEmpty()) {
                Spacer(Modifier.height(20.dp))
                SectionLabel("Your links")
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
        BackBar("Reusable link", onBack = onBack)
        link ?: return@Column
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline("Your link", remaining(link.expiresAt))
            Spacer(Modifier.height(16.dp))
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                QrCode(link.link, description = "The reusable link as a QR code")
            }
            Spacer(Modifier.height(16.dp))
            MonoBox(link.link)
            TakeoverWarning(link.link)
            LimitOffer(link.link)
            Spacer(Modifier.height(12.dp))
            PrimaryButton("Share link") { shareText(context, link.link, "Share link") }
            Spacer(Modifier.height(8.dp))
            SecondaryButton("Copy link") { copySensitive(context, link.link, "UMBRA link") }
            Spacer(Modifier.height(8.dp))
            QuietButton(if (isRetiring) "Retiring" else "Retire link") {
                if (!isRetiring) {
                    isRetiring = true
                    Core.retirePublicLink(link)
                }
            }
            LaunchedEffect(Core.directoryBusy) { if (!Core.directoryBusy) isRetiring = false }
            DirectoryState("Writing the end of the link.")
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
        BackBar("Your handle", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            val handle = Core.myHandle
            if (handle == null) {
                HeroIcon("globe")
                Spacer(Modifier.height(24.dp))
                Headline("A name that people can look up.")
                Spacer(Modifier.height(20.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it.take(32) },
                    label = { Text("Name") },
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
                    "Claim handle",
                    enabled = Core.online && !Core.directoryBusy && name.isNotBlank(),
                ) {
                    focus.clearFocus()
                    Core.claimHandle(name)
                }
                DirectoryState("Publishing the handle.")
                Spacer(Modifier.height(14.dp))
                // Part 9 §9.3: the residual leak that the part states.
                Note(
                    "The directory lists each handle. A number after the name keeps it apart " +
                        "from the same name of another person.",
                )
            } else {
                Headline(handle)
                TakeoverWarning(handle)
                LimitOffer(handle)
                Spacer(Modifier.height(16.dp))
                PrimaryButton("Share handle") { shareText(context, handle, "Share handle") }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Copy handle") { copySensitive(context, handle, "UMBRA handle") }
                Spacer(Modifier.height(8.dp))
                QuietButton("Release handle") { Core.releaseHandle() }
                DirectoryState("Writing the release.")
            }
        }
    }
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
        BackBar("Contact requests", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            for (request in Core.contactRequests) {
                RequestRow(context, request)
                HorizontalDivider(color = Palette.Divider)
            }
            Box(Modifier.padding(20.dp)) {
                // Part 9 §9.8: the name of a request is a claim of its sender.
                Note("A request shows the name that its sender chose. No party checks it.")
            }
        }
    }
}

@Composable
private fun RequestRow(context: Context, request: ContactRequestInfo) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
        Text(request.name.ifBlank { "No name" })
        Text(
            "${request.via.removePrefix("umbra://p/")} · " +
                timeLabel(context, request.receivedAt.toLong() * 1_000),
            style = MaterialTheme.typography.bodySmall,
            color = Palette.TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            InlineButton("Accept", enabled = Core.online) { Core.acceptRequest(request) }
            InlineButton("Decline") { Core.declineRequest(request) }
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
        Text(if (count == 1) "1 contact request" else "$count contact requests")
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
