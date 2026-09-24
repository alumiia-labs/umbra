package org.umbra.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import java.nio.CharBuffer
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.Arrangement
import kotlinx.coroutines.delay
import uniffi.umbra_ffi.FfiCommunity

/** The longest name of a community, in bytes of UTF-8 (`META_NAME_MAX`). */
private const val COMMUNITY_NAME_MAX = 64

/** How often a view of a community reads the store again. */
private const val COMMUNITY_REFRESH_MS = 3_000L

/** The name of a community, or a word of the interface before one verifies. */
fun communityTitle(community: FfiCommunity): String =
    community.name.ifEmpty { "Community ${community.communityId.take(4).joinToString("") { "%02x".format(it) }}" }

/** A short name of a pseudonym: no party of a community has another one. */
private fun pseudonymLabel(author: ByteArray): String =
    author.take(4).joinToString("") { "%02x".format(it) }

/** Reads the communities again while the view shows. */
@Composable
private fun RefreshCommunities() {
    LaunchedEffect(Unit) {
        while (true) {
            Core.refreshCommunities()
            delay(COMMUNITY_REFRESH_MS)
        }
    }
}

@Composable
fun CommunitiesTab(push: (Screen) -> Unit) {
    RefreshCommunities()
    Column(Modifier.fillMaxSize()) {
        CommunityOfferPrompt()
        Text(
            "Communities",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 12.dp),
        )
        Row(Modifier.padding(horizontal = 20.dp)) {
            InlineButton("Join with a link") { push(Screen.JoinCommunity) }
            Spacer(Modifier.width(8.dp))
            InlineButton("New community") { push(Screen.NewCommunity) }
        }
        Spacer(Modifier.height(8.dp))
        for (forming in Core.formingCommunities) FormingRow(forming)
        if (Core.communities.isEmpty()) {
            if (Core.formingCommunities.isEmpty()) EmptyState("No communities yet.")
            return
        }
        LazyColumn {
            items(Core.communities, key = { it.communityId.toList() }) { community ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .pressShadeInList()
                        .press { push(Screen.Community(community.communityId.toList())) }
                        .padding(horizontal = PressInset, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    LetterAvatar(communityTitle(community), community.communityId.contentHashCode())
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            communityTitle(community),
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            communitySubtitle(community),
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

/** A community in its creation, with the step that it waits for. */
@Composable
private fun FormingRow(forming: uniffi.umbra_ffi.FfiFormingCommunity) {
    val other = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(forming.contact) }?.title ?: "the other owner"
    val step = when (forming.phase.toInt()) {
        0 -> "Making the report queue"
        1 -> "Waiting for $other"
        2 -> "Waiting for $other to publish it"
        else -> "Publishing · ${forming.relaysDone} of 3 relays" +
            (forming.lastFault?.let { " · $it" } ?: "")
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        LetterAvatar(forming.name, forming.communityId.contentHashCode())
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(forming.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                step,
                style = MaterialTheme.typography.bodySmall,
                color = Palette.TextSecondary,
                modifier = Modifier.subline(),
            )
        }
    }
}

private fun communitySubtitle(community: FfiCommunity): String {
    val role = if (community.isOwner) "Owner" else "Member"
    val relays = "${community.relays} relays"
    val sending = if (community.pending > 0u) " · Sending" else ""
    return "$role · $relays$sending"
}

/** The offers of a co-ownership that wait for the user (§12.5.5). */
@Composable
private fun CommunityOfferPrompt() {
    val offer = Core.communityOffers.firstOrNull() ?: return
    val from = Core.chats
        .firstOrNull { it.conversation.id.contentEquals(offer.from) }?.title ?: "A contact"
    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text("$from asks you to own ${offer.name} with them")
        Text(
            "The roster of the community names both owners. It removes an owner only with the other.",
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        Row {
            InlineButton("Accept") { Core.acceptCommunityOffer(offer.communityId) }
            Spacer(Modifier.width(8.dp))
            InlineButton("Decline") { Core.declineCommunityOffer(offer.communityId) }
        }
    }
}

/** Joins a community by its link (§12.7). */
@Composable
fun JoinCommunityScreen(onBack: () -> Unit, onJoined: (List<Byte>) -> Unit) {
    var pasted by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        BackBar("Join a community", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("people-group")
            Spacer(Modifier.height(24.dp))
            // A link is no message text, thus a composable field holds it.
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Community link") },
                placeholder = { Text("umbra://c/…") },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            PrimaryButton("Join", enabled = Core.online && pasted.isNotBlank()) {
                Core.joinCommunity(pasted.trim()) { id -> onJoined(id.toList()) }
            }
            Spacer(Modifier.height(10.dp))
            Note("A pull names no member. The relays learn that a party read the community.")
        }
    }
}

/** Starts a community with a contact as its second owner (§12.5.5). */
@Composable
fun NewCommunityScreen(onBack: () -> Unit, onMade: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var coOwner by remember { mutableStateOf<Conversation?>(null) }
    var isMaking by remember { mutableStateOf(false) }
    val contacts = Core.chats.filter { !it.isGroup }.sortedBy { it.title.lowercase() }
    Column(Modifier.fillMaxSize()) {
        BackBar("New community", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon("people-group")
            Spacer(Modifier.height(24.dp))
            // A name is public metadata of the community and no message text.
            OutlinedTextField(
                value = name,
                onValueChange = { typed ->
                    if (typed.toByteArray(Charsets.UTF_8).size <= COMMUNITY_NAME_MAX) name = typed
                },
                label = { Text("Community name") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(20.dp))
            Text("Second owner", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            if (contacts.isEmpty()) {
                Note("A community has two owners from its start. Add a contact first.")
            }
            for (chat in contacts) {
                val isChosen = chat.conversation == coOwner
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isChosen) Palette.Container else Color.Transparent)
                        .clickable(role = Role.RadioButton) { coOwner = chat.conversation }
                        .padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(chat, size = 36)
                    Spacer(Modifier.width(12.dp))
                    Text(chat.title, modifier = Modifier.weight(1f))
                    if (isChosen) FaIcon("check", label = "Chosen", size = 16.dp, tint = Palette.Action)
                }
            }
            Spacer(Modifier.height(16.dp))
            val chosen = coOwner
            PrimaryButton(
                "Create community",
                enabled = Core.online && name.isNotBlank() && chosen != null && !isMaking,
            ) {
                if (chosen != null) {
                    isMaking = true
                    Core.createCommunity(name.trim(), chosen) { onMade() }
                }
            }
            Spacer(Modifier.height(10.dp))
            Note("The community forms when the second owner accepts and three relays hold it.")
        }
    }
}

/** The posts of a community, and the composer. */
@Composable
fun CommunityScreen(id: List<Byte>, onBack: () -> Unit, push: (Screen) -> Unit) {
    RefreshCommunities()
    val community = Core.communities.firstOrNull { it.communityId.toList() == id }
    if (community == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }
    val communityId = community.communityId
    var posts by remember { mutableStateOf(emptyList<CommunityLine>()) }
    val listState = rememberLazyListState()
    LaunchedEffect(id, community.records, Core.revision) {
        Core.loadCommunityPosts(communityId) { loaded -> posts = loaded }
    }
    // A new post leads the list to its end.
    LaunchedEffect(posts.size) {
        if (posts.isNotEmpty()) listState.scrollToItem(posts.lastIndex)
    }
    val composer = rememberPlatformField()
    var chosen by remember { mutableStateOf<CommunityLine?>(null) }
    var answered by remember { mutableStateOf<CommunityLine?>(null) }
    val context = LocalContext.current
    val react = { line: CommunityLine, emoji: String ->
        val isMine = line.post.reactions.any { it.isMine && it.emoji == emoji }
        Core.reactToCommunityPost(communityId, line.post.key, emoji, !isMine)
    }
    chosen?.let { line ->
        val entries = buildList {
            add(RowEntry("reply", "Reply") {
                answered = line
                composer.focus()
            })
            add(RowEntry("copy", "Copy text") { copyPost(context, line.text) })
            // COM-273: each post that the client renders takes a report.
            if (!line.post.isOwn) {
                add(RowEntry("flag", "Report") {
                    push(Screen.ReportPost(id, line.post.key.toList()))
                })
            }
            // §12.5.2: an owner acts on the post of another author.
            if (community.isOwner && !line.post.isOwn) {
                add(RowEntry("trash-can", "Remove post") {
                    Core.removeCommunityPost(communityId, line.post.key)
                })
                if (!line.post.isAuthorBanned) {
                    add(RowEntry("ban", "Ban author") {
                        Core.banCommunityAuthor(communityId, line.post.author, false)
                    })
                    add(RowEntry("ban", "Ban author and remove their posts") {
                        Core.banCommunityAuthor(communityId, line.post.author, true)
                    })
                }
            }
        }
        ActionSheet(
            "Post",
            entries,
            top = if (community.reactionsOff) {
                null
            } else {
                {
                    CommunityQuickReactions(line) { emoji ->
                        react(line, emoji)
                        chosen = null
                    }
                }
            },
            onDismiss = { chosen = null },
        )
    }
    Column(Modifier.fillMaxSize()) {
        BackBar(
            communityTitle(community),
            subtitle = communitySubtitle(community),
            onBack = onBack,
            onTitle = { push(Screen.CommunityDetails(id)) },
        )
        Box(Modifier.weight(1f)) {
            if (posts.isEmpty()) EmptyState("No posts yet.")
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                items(posts, key = { it.key }) { line ->
                    val target = line.post.replyTo?.let { key ->
                        posts.firstOrNull { it.post.key.contentEquals(key) }
                    }
                    PostRow(line, target, onReact = { emoji -> react(line, emoji) }) { chosen = line }
                }
            }
        }
        answered?.let { line ->
            val who = if (line.post.isOwn) "yourself" else pseudonymLabel(line.post.author)
            ComposerHeader("reply", "Replying to $who") { answered = null }
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(24.dp))
                    .background(Palette.Container)
                    .heightIn(min = 48.dp)
                    .padding(horizontal = 18.dp, vertical = 12.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                PlatformInput(
                    composer,
                    hint = "Post",
                    isPassphrase = false,
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 5,
                )
            }
            Spacer(Modifier.width(8.dp))
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(Palette.Action)
                    .clickable(role = Role.Button, onClickLabel = "Post") {
                        composer.take()?.let { text ->
                            Core.postToCommunity(communityId, text, answered?.post?.key)
                            answered = null
                        }
                    },
                contentAlignment = Alignment.Center,
            ) { FaIcon("paper-plane", label = "Post", size = 18.dp, tint = Color.White) }
        }
    }
}

/** IMP-056: a copied post is marked as sensitive, as a message is. */
private fun copyPost(context: Context, text: CharArray) {
    val clip = ClipData.newPlainText("UMBRA post", CharBuffer.wrap(text))
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

/** The quick reactions at the top of the sheet of a post. */
@Composable
private fun CommunityQuickReactions(line: CommunityLine, onPick: (String) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        for (emoji in QUICK_REACTIONS) {
            val isMine = line.post.reactions.any { it.isMine && it.emoji == emoji }
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(if (isMine) Palette.Container else Color.Transparent)
                    .press(role = Role.Button, label = if (isMine) "Remove $emoji" else "React $emoji") {
                        onPick(emoji)
                    },
                contentAlignment = Alignment.Center,
            ) { Text(emoji, fontSize = 24.sp) }
        }
    }
}

@Composable
private fun PostRow(
    line: CommunityLine,
    target: CommunityLine?,
    onReact: (String) -> Unit,
    onChoose: () -> Unit,
) {
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxWidth()
            .pressShadeInList()
            .pressLong(onClick = {}, onLongClick = onChoose)
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (line.post.isOwn) "You" else pseudonymLabel(line.post.author),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.width(8.dp))
            Text(
                timeLabel(context, line.post.at.toLong() * 1_000),
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
            )
            if (line.post.isAuthorBanned) {
                Spacer(Modifier.width(6.dp))
                Text(
                    "Banned",
                    style = MaterialTheme.typography.labelSmall,
                    color = Palette.TextSecondary,
                )
            }
            // COM-086: a post with no checkpoint yet has no signature of its
            // author over it.
            if (!line.post.isSettled) {
                Spacer(Modifier.width(6.dp))
                FaIcon("clock", label = "Not signed yet", size = 12.dp, tint = Palette.TextSecondary)
            }
        }
        // COM-161: a reply shows the start of the post it answers.
        if (line.post.replyTo != null) {
            Spacer(Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                FaIcon("reply", size = 11.dp, tint = Palette.TextSecondary)
                Spacer(Modifier.width(6.dp))
                if (target != null) {
                    PlatformText(target.text, Palette.TextSecondary, sizeSp = 13f, maxLines = 1)
                } else {
                    Text(
                        "A post that this device does not hold",
                        style = MaterialTheme.typography.labelSmall,
                        color = Palette.TextSecondary,
                    )
                }
            }
        }
        Spacer(Modifier.height(2.dp))
        PlatformText(line.text, Palette.Text)
        if (line.post.reactions.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Row {
                for (reaction in line.post.reactions) {
                    Box(
                        Modifier
                            .padding(end = 6.dp)
                            .clip(CircleShape)
                            .background(if (reaction.isMine) Palette.Container else Palette.Incoming)
                            .press(role = Role.Button, label = reaction.emoji) { onReact(reaction.emoji) }
                            .padding(horizontal = 10.dp, vertical = 3.dp),
                    ) {
                        Text("${reaction.emoji} ${reaction.count}", style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
        }
    }
}

/** What this device holds of a community: its link, its role, and a way out. */
@Composable
fun CommunityDetailsScreen(id: List<Byte>, onBack: () -> Unit, push: (Screen) -> Unit, onLeft: () -> Unit) {
    val community = Core.communities.firstOrNull { it.communityId.toList() == id }
    if (community == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        BackBar(communityTitle(community), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Text(communitySubtitle(community), color = Palette.TextSecondary)
            Spacer(Modifier.height(20.dp))
            if (community.isOwner) {
                SecondaryButton("Reports") { push(Screen.CommunityReports(id)) }
                Spacer(Modifier.height(12.dp))
            }
            SecondaryButton(if (copied) "Link copied" else "Copy link") {
                Core.communityLink(community.communityId) { link ->
                    // The fragment of the link opens the metadata, thus the
                    // platform shows no preview of the copy.
                    val clip = ClipData.newPlainText("UMBRA community", link)
                    clip.description.extras = PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
                    copied = true
                }
            }
            Spacer(Modifier.height(12.dp))
            DangerButton("Leave community") {
                Core.leaveCommunity(community.communityId) { onLeft() }
            }
            Spacer(Modifier.height(10.dp))
            if (community.isOwner) {
                Note("This device holds an owner key of the community. A leave deletes it, and the roster keeps its entry.")
            } else {
                Note("A leave sends nothing. The relays hold no member list.")
            }
        }
    }
}

/** The causes of a report, in the order of the table of §12.5.3. */
private val REPORT_REASONS = listOf(
    "Spam",
    "Harassment",
    "Illegal content",
    "A breach of the community rules",
    "Other",
)

/** A report of one post to one role holder of the roster (§12.5.3). */
@Composable
fun ReportPostScreen(id: List<Byte>, key: List<Byte>, onBack: () -> Unit) {
    var reason by remember { mutableStateOf<Int?>(null) }
    var isSending by remember { mutableStateOf(false) }
    val note = rememberPlatformField()
    Column(Modifier.fillMaxSize()) {
        BackBar("Report post", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            for ((index, label) in REPORT_REASONS.withIndex()) {
                val isChosen = reason == index
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isChosen) Palette.Container else Color.Transparent)
                        .clickable(role = Role.RadioButton) { reason = index }
                        .padding(horizontal = 12.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(label, modifier = Modifier.weight(1f))
                    if (isChosen) FaIcon("check", label = "Chosen", size = 16.dp, tint = Palette.Action)
                }
            }
            Spacer(Modifier.height(16.dp))
            FramedPlatformField(note, "Note", isPassphrase = false)
            Spacer(Modifier.height(16.dp))
            val chosen = reason
            PrimaryButton("Send report", enabled = Core.online && chosen != null && !isSending) {
                if (chosen != null) {
                    isSending = true
                    Core.reportCommunityPost(
                        id.toByteArray(),
                        key.toByteArray(),
                        (chosen + 1).toUByte(),
                        note.take(),
                    ) { onBack() }
                }
            }
            Spacer(Modifier.height(10.dp))
            Note("One owner or admin of the roster, drawn at random, reads the report. It names no reporter.")
        }
    }
}

/** The reports that the role of this device holds, each one with its post. */
@Composable
fun CommunityReportsScreen(id: List<Byte>, onBack: () -> Unit) {
    var reports by remember { mutableStateOf(emptyList<ReportLine>()) }
    var version by remember { mutableStateOf(0) }
    LaunchedEffect(id, version, Core.revision) {
        Core.loadCommunityReports(id.toByteArray()) { reports = it }
    }
    Column(Modifier.fillMaxSize()) {
        BackBar("Reports", onBack = onBack)
        if (reports.isEmpty()) EmptyState("No reports.")
        LazyColumn {
            items(reports, key = { it.report.id.toList() }) { line ->
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
                    Text(
                        REPORT_REASONS.getOrNull(line.report.reason.toInt() - 1) ?: "Other",
                        fontWeight = FontWeight.SemiBold,
                    )
                    if (line.note.isNotEmpty()) {
                        Spacer(Modifier.height(2.dp))
                        PlatformText(line.note, Palette.TextSecondary, sizeSp = 14f)
                    }
                    Spacer(Modifier.height(8.dp))
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Palette.Container)
                            .padding(12.dp),
                    ) { PlatformText(line.post, Palette.Text) }
                    Spacer(Modifier.height(8.dp))
                    Row {
                        InlineButton("Remove post") {
                            Core.removeCommunityPost(id.toByteArray(), line.report.postKey)
                            Core.dismissCommunityReport(id.toByteArray(), line.report.id) { version++ }
                        }
                        Spacer(Modifier.width(8.dp))
                        InlineButton("Dismiss") {
                            Core.dismissCommunityReport(id.toByteArray(), line.report.id) { version++ }
                        }
                    }
                }
            }
        }
    }
}
