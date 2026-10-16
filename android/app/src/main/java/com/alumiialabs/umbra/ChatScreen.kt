package com.alumiialabs.umbra

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.DisposableEffect
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.border
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.animateColorAsState
import kotlin.math.roundToInt
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.fadeOut
import androidx.compose.animation.fadeIn
import androidx.compose.animation.expandVertically
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.runtime.snapshotFlow
import androidx.compose.foundation.gestures.scrollBy
import java.nio.CharBuffer
import android.os.PersistableBundle
import android.content.Context
import android.content.ClipboardManager
import android.content.ClipData
import uniffi.umbra_ffi.FfiKeyChange
import uniffi.umbra_ffi.FfiModNote
import uniffi.umbra_ffi.FfiRole
import uniffi.umbra_ffi.FfiRosterNote
import uniffi.umbra_ffi.MsgReaction
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource

@Composable
fun ChatScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit, target: List<Byte>? = null) {
    var lines by remember { mutableStateOf(emptyList<Line>()) }
    val listState = rememberLazyListState()
    val conversation = chat.conversation
    // WIR-273: the records of one thread show together, under their root.
    var threadOf by remember(conversation) { mutableStateOf<List<Byte>?>(null) }
    BackHandler(enabled = threadOf != null) { threadOf = null }
    // The count of the messages that the user did not see, at the moment the
    // view opened. The read marker moves at once, and the line stays where
    // it was for this visit.
    val unseenAtOpen = remember(conversation) { chat.unread }
    var newFrom by remember(conversation) { mutableStateOf<ULong?>(null) }
    var isPlaced by remember(conversation) { mutableStateOf(false) }
    // Whether the list follows its end at the next load. A user at the end
    // stays there when a message comes or when the newest bubble grows, by a
    // reaction or an edit. A user who reads further up stays there. A send of
    // this user leads to the end.
    var followsEnd by remember(conversation) { mutableStateOf(false) }
    var jumpsAtNextLoad by remember(conversation) { mutableStateOf(false) }
    LaunchedEffect(conversation, Core.revision) {
        Core.load(conversation) { loaded ->
            if (!isPlaced) {
                // The line sits above the oldest of the received messages
                // that the user did not see.
                newFrom = loaded.filter { !it.info.outgoing }
                    .takeLast(unseenAtOpen)
                    .firstOrNull()
                    ?.info?.storedAtMs
            } else {
                followsEnd = jumpsAtNextLoad || !listState.canScrollForward
                jumpsAtNextLoad = false
            }
            lines = loaded
        }
        // The user looks at the conversation, thus each message is seen.
        Core.markRead(conversation)
    }
    LaunchedEffect(lines) {
        if (lines.isEmpty()) return@LaunchedEffect
        // The item before each message is the chip of the view, and an
        // offset above each height means the end of the list.
        val toEnd = suspend { listState.scrollToItem(lines.lastIndex + 1, END_OF_LIST) }
        if (!isPlaced) {
            isPlaced = true
            // A visit that starts with new messages starts at the line.
            val firstNew = lines.indexOfFirst { it.info.storedAtMs == newFrom && !it.info.outgoing }
            if (firstNew >= 0) listState.scrollToItem(firstNew) else toEnd()
        } else if (followsEnd) {
            toEnd()
        }
    }
    // The keyboard takes the lower part of the list, over several frames.
    // The list moves by each height that it loses, thus the messages that
    // the user looked at stay above the keyboard, as in each messenger.
    LaunchedEffect(listState) {
        var before = listState.layoutInfo.viewportSize.height
        snapshotFlow { listState.layoutInfo.viewportSize.height }.collect { height ->
            val lost = before - height
            before = height
            if (lost > 0) listState.scrollBy(lost.toFloat())
        }
    }
    val readUpTo = lines.indexOfLast { it.info.outgoing && it.info.delivery.toInt() == READ }
    val replyCounts = remember(lines) { lines.mapNotNull { it.threadKey }.groupingBy { it }.eachCount() }
    val composer = rememberPlatformField()
    // Part 6 §6.6.9: the text of the field starts and ends a typing state.
    LaunchedEffect(conversation) {
        composer.onChange = { if (!chat.isGroup) Core.typing(conversation, !composer.isEmpty) }
    }
    // The message under the finger, and the message that the composer answers.
    var chosen by remember(conversation) { mutableStateOf<Line?>(null) }
    var linksOf by remember(conversation) { mutableStateOf<Line?>(null) }
    var forwarding by remember(conversation) { mutableStateOf<Line?>(null) }
    var answered by remember(conversation) { mutableStateOf<Line?>(null) }
    // The message that a jump from an answer shows for a moment.
    var flashed by remember(conversation) { mutableStateOf<List<Byte>?>(null) }
    val scope = rememberCoroutineScope()
    val jumpTo = { target: List<Byte> ->
        val at = lines.indexOfFirst { it.key == target }
        if (at >= 0) {
            scope.launch {
                // The first item of the list is the chip of the view.
                listState.animateScrollToItem(at + 1)
                flashed = target
                delay(900)
                flashed = null
            }
        }
    }
    // A result of a search opens the conversation at its message. The view
    // puts itself at its end first, thus the jump waits for one frame.
    var isAtTarget by remember(conversation, target) { mutableStateOf(false) }
    LaunchedEffect(target, lines.isNotEmpty()) {
        if (target == null || isAtTarget || lines.isEmpty()) return@LaunchedEffect
        val at = lines.indexOfFirst { it.key == target }
        if (at < 0) return@LaunchedEffect
        isAtTarget = true
        androidx.compose.runtime.withFrameNanos { }
        listState.scrollToItem(at + 1)
        flashed = target
        delay(1_500)
        flashed = null
    }
    val context = LocalContext.current
    // The message whose text the composer changes.
    var edited by remember(conversation) { mutableStateOf<Line?>(null) }
    // The message that the user wants to delete, and a word for a user who
    // deletes faster than the rate limit permits.
    var deleting by remember(conversation) { mutableStateOf<Line?>(null) }
    // DEV-127: each of the two deletions has a confirmation of its own.
    var deletingOwn by remember(conversation) { mutableStateOf<Line?>(null) }
    var deletingAll by remember(conversation) { mutableStateOf<Line?>(null) }
    // Part 11 §11.9.6: the role of this member, the epochs of the moderators,
    // a remove that waits for its second confirmation, and each hidden
    // message that the user opened.
    var ownRole by remember(conversation) { mutableStateOf<FfiRole?>(null) }
    // The name of each member, for the bubbles of a group.
    var memberNames by remember(conversation) { mutableStateOf(emptyMap<UShort, String>()) }
    var modNotes by remember(conversation) { mutableStateOf(emptyList<FfiModNote>()) }
    var rosterNotes by remember(conversation) { mutableStateOf(emptyList<FfiRosterNote>()) }
    var removing by remember(conversation) { mutableStateOf<Line?>(null) }
    // Part 4 §4.5.1: a new key of the contact waits for the answer.
    var keyChange by remember(conversation) { mutableStateOf<FfiKeyChange?>(null) }
    // IMP-082: the records to a full queue stay queued, and the chat says why.
    var isQueueFull by remember(conversation) { mutableStateOf(false) }
    LaunchedEffect(conversation, Core.revision, Core.chats.size) {
        if (!chat.isGroup) Core.queueFull(conversation) { isQueueFull = it }
    }
    LaunchedEffect(conversation, Core.revision) {
        if (!chat.isGroup) Core.keyChange(conversation) { keyChange = it }
    }
    // Part 3 `NET-355`: a request for a new connection waits for the answer.
    var asksRenewal by remember(conversation) { mutableStateOf(false) }
    LaunchedEffect(conversation, Core.revision) {
        if (!chat.isGroup) Core.renewalAsk(conversation) { asksRenewal = it }
    }
    val revealed = remember(conversation) { mutableStateListOf<List<Byte>>() }
    LaunchedEffect(conversation, Core.revision) {
        if (chat.isGroup) {
            Core.groupMembers(conversation) { members ->
                ownRole = members.firstOrNull { it.isSelf }?.role
                memberNames = members.associate { member ->
                    val title = member.contact?.let { contact ->
                        Core.chats.firstOrNull { it.conversation.id.contentEquals(contact) }?.title
                    }
                    member.index to (if (member.isSelf) YOU else title ?: UiText.get(R.string.common_member_number, member.index.toInt()))
                }
            }
            Core.moderationNotes(conversation) { modNotes = it }
        }
        // NET-103: a pairwise conversation takes the note of a delivery gap.
        Core.rosterNotes(conversation) { rosterNotes = it }
    }
    var notice by remember(conversation) { mutableStateOf<String?>(null) }
    val save = rememberSave()
    // The sheet of the plus: a photo, a video, or a file.
    var isAttaching by remember(conversation) { mutableStateOf(false) }
    // A voice message under way. A recording that the view leaves goes.
    var recording by remember(conversation) { mutableStateOf<VoiceRecording?>(null) }
    DisposableEffect(conversation) {
        onDispose {
            recording?.discard()
            VoicePlayer.stop()
        }
    }
    val startRecording = {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val made = VoiceRecording(context)
            if (made.start()) recording = made else notice = UiText.get(R.string.chat_microphone_did_not_start)
        }
    }
    // A recording ends when the app leaves the screen, because the platform
    // gives it no sound in the background.
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val watcher = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) recording?.end()
        }
        owner.lifecycle.addObserver(watcher)
        onDispose { owner.lifecycle.removeObserver(watcher) }
    }
    // Part 7 §7.5.3: the draft comes back at the open, and it stays when
    // the view closes or the app leaves the screen. An edit is no draft.
    LaunchedEffect(conversation) {
        Core.readDraft(conversation) { chars ->
            composer.set(chars)
            chars.fill('\u0000')
        }
    }
    DisposableEffect(owner, conversation) {
        val keeper = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && edited == null) Core.keepDraft(conversation, composer.copy())
        }
        owner.lifecycle.addObserver(keeper)
        onDispose {
            owner.lifecycle.removeObserver(keeper)
            if (edited == null) Core.keepDraft(conversation, composer.copy())
        }
    }
    val askMicrophone = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        if (allowed) startRecording() else notice = UiText.get(R.string.chat_no_microphone_access)
    }
    // A send that did not start says why in this view.
    LaunchedEffect(Core.fault) {
        Core.fault?.let {
            notice = it
            Core.fault = null
        }
    }
    LaunchedEffect(notice) {
        if (notice != null) {
            delay(4_000)
            notice = null
        }
    }
    forwarding?.let { line ->
        ActionSheet(
            stringResource(R.string.chat_forward_to),
            Core.chats.filter { !it.conversation.id.contentEquals(conversation.id) && !it.isClosed && it.isMember }.map { target ->
                RowEntry(if (target.isGroup) "user-group" else "comment", target.title) {
                    Core.forward(line.handle, target.conversation) { notice = UiText.get(R.string.chat_forwarded_to, target.title) }
                }
            },
            onDismiss = { forwarding = null },
        )
    }
    linksOf?.let { line ->
        ActionSheet(
            stringResource(R.string.chat_links),
            Links.of(line.text).map { url ->
                RowEntry(if (url.startsWith("umbra:", ignoreCase = true)) "link" else "globe", url) {
                    Links.open(context, url)
                }
            },
            onDismiss = { linksOf = null },
        )
    }
    chosen?.let { line ->
        val entries = if (line.info.deleted) {
            // DEV-105: the user can clear a placeholder.
            listOf(RowEntry("trash-can", stringResource(R.string.chat_remove)) { Core.deleteForMe(line.handle) })
        } else if (line.info.moderation == MOD_HIDE && line.key !in revealed) {
            // A hidden message that the user did not open gives no content.
            buildList {
                if (chat.isGroup && (ownRole ?: FfiRole.MEMBER) >= FfiRole.MODERATOR) {
                    add(RowEntry("eye", stringResource(R.string.chat_show_for_everyone)) { Core.moderate(line.handle, MOD_UNHIDE) })
                    add(RowEntry("ban", stringResource(R.string.common_remove_for_everyone)) { removing = line })
                }
                add(RowEntry("trash-can", stringResource(R.string.common_delete)) { deleting = line })
            }
        } else {
            buildList {
                // IMP-075: a failed text goes again at the action of the user.
                if (line.info.outgoing && line.info.delivery.toInt() == FAILED && line.info.file == null) {
                    add(RowEntry("rotate", stringResource(R.string.chat_send_again)) { Core.sendAgain(line.handle) })
                }
                add(
                    RowEntry("reply", stringResource(R.string.chat_reply)) {
                        edited = null
                        answered = line
                    },
                )
                // The core says whether the text can change: a text of this
                // device, inside 24 hours, below the limit of revisions.
                if (line.info.editable) {
                    add(
                        RowEntry("pen", stringResource(R.string.chat_edit)) {
                            answered = null
                            edited = line
                            // IMP-017: the field copies the text, and zeros
                            // overwrite this copy.
                            val copy = line.text.copyOf()
                            composer.set(copy)
                            copy.fill('\u0000')
                        },
                    )
                }
                val file = line.info.file
                if (file == null) {
                    add(RowEntry("copy", stringResource(R.string.chat_copy_text)) { copyMessage(context, line.text) })
                    // WIR-177: a text goes to another chat as a forward.
                    // DEV-322: the sender of the message can prohibit it.
                    if (line.poll == null && !line.info.noForward) {
                        add(RowEntry("share-nodes", stringResource(R.string.chat_forward)) { forwarding = line })
                    }
                } else if (file.state.toInt() == FILE_READY || line.info.outgoing) {
                    // IMP-045: the user saves one file.
                    add(RowEntry("download", stringResource(R.string.chat_save_to_device)) { save(line) })
                }
                // ATT-054: the sender sends a file again as a new upload.
                if (file != null && line.info.outgoing && file.state.toInt() == FILE_READY) {
                    add(RowEntry("rotate", stringResource(R.string.chat_send_again)) { Core.resendFile(line.handle) })
                }
                // GRP-085: a hide is the first act of a moderator, and a
                // remove asks again (GRP-086).
                if (chat.isGroup && (ownRole ?: FfiRole.MEMBER) >= FfiRole.MODERATOR) {
                    if (line.info.moderation == MOD_HIDE) {
                        add(RowEntry("eye", stringResource(R.string.chat_show_for_everyone)) { Core.moderate(line.handle, MOD_UNHIDE) })
                    } else {
                        add(
                            RowEntry(
                                "eye",
                                stringResource(R.string.chat_hide_for_everyone),
                                stringResource(R.string.chat_hide_for_everyone_detail),
                            ) { Core.moderate(line.handle, MOD_HIDE) },
                        )
                    }
                    add(RowEntry("ban", stringResource(R.string.common_remove_for_everyone)) { removing = line })
                }
                add(RowEntry("trash-can", stringResource(R.string.common_delete)) { deleting = line })
            }
        }
        ActionSheet(
            stringResource(R.string.common_message),
            entries,
            // A placeholder takes no reaction, and Part 11 gives a group no
            // reaction path.
            top = if (line.info.deleted || chat.isGroup) {
                null
            } else {
                {
                    QuickReactions(line.reactions) { emoji ->
                        Core.react(line.handle, emoji)
                        chosen = null
                    }
                }
            },
            onDismiss = { chosen = null },
        )
    }
    // ATT-083, ATT-084: a large file names its cost, and the user can drop
    // it. ATT-157: an original says that it keeps its metadata.
    Core.pendingSend?.takeIf { it.conversation == conversation }?.let { pending ->
        val notes = buildList {
            if (pending.bytes > LARGE_FILE_WARN) {
                add(stringResource(R.string.chat_send_uses_data, Files.uplink(context, pending.bytes)))
            }
            if (pending.bytes < 0) add(stringResource(R.string.chat_file_has_no_size))
            if (pending.isOriginal) add(UiText.get(R.string.umbra_ui_att_157))
        }
        ActionSheet(
            if (pending.bytes > 0) {
                stringResource(R.string.chat_send_size_question, Files.size(context, pending.bytes))
            } else {
                stringResource(R.string.chat_send_this_file_question)
            },
            listOf(RowEntry("paper-plane", stringResource(R.string.common_send)) { Core.confirmSend(pending) }),
            note = notes.joinToString(" "),
            onDismiss = { Core.cancelSend() },
        )
    }
    removing?.let { line ->
        ActionSheet(
            stringResource(R.string.chat_remove_this_message_question),
            listOf(RowEntry("ban", stringResource(R.string.common_remove_for_everyone)) { Core.moderate(line.handle, MOD_REMOVE) }),
            // GRP-087: a remove is not reversible, and the sheet says so.
            note = UiText.get(R.string.umbra_ui_grp_087),
            onDismiss = { removing = null },
        )
    }
    deleting?.let { line ->
        // DEV-127, DEV-128: two labels, and neither looks the safer one.
        val entries = buildList {
            add(RowEntry("trash-can", stringResource(R.string.common_delete_on_my_devices)) { deletingOwn = line })
            // A contact takes a deletion for a message of this device alone.
            if (line.info.outgoing) add(RowEntry("trash-can", stringResource(R.string.chat_delete_for_everyone)) { deletingAll = line })
        }
        ActionSheet(stringResource(R.string.chat_delete_this_message_question), entries, onDismiss = { deleting = null })
    }
    deletingOwn?.let { line ->
        ActionSheet(
            stringResource(R.string.chat_delete_on_my_devices_question),
            listOf(
                RowEntry("trash-can", stringResource(R.string.common_delete_on_my_devices)) {
                    Core.deleteForMe(line.handle)
                    // DEV-129: the view says which deletion ran.
                    notice = UiText.get(R.string.chat_deleted_on_your_devices)
                },
            ),
            note = stringResource(R.string.chat_delete_on_my_devices_note),
            onDismiss = { deletingOwn = null },
        )
    }
    deletingAll?.let { line ->
        ActionSheet(
            stringResource(R.string.chat_delete_for_everyone_question),
            listOf(
                RowEntry("trash-can", stringResource(R.string.chat_delete_for_everyone)) {
                    if (answered?.key == line.key) answered = null
                    Core.deleteForEveryone(line.handle) {
                        notice = UiText.get(R.string.chat_wait_between_deletions)
                    }
                    // DEV-129: the view says which deletion ran.
                    notice = if (chat.isGroup) {
                        UiText.get(R.string.chat_asked_each_member_to_delete)
                    } else {
                        UiText.get(R.string.chat_asked_contact_to_delete, chat.title)
                    }
                },
            ),
            // DEV-126: each limit of a deletion for the other party. The
            // spread of a sweep (DEV-107) has no action here, since one
            // deletion goes to one conversation at once.
            note = (
                if (chat.isGroup) {
                    stringResource(R.string.chat_delete_for_everyone_group_note)
                } else {
                    UiText.get(R.string.umbra_ui_dev_126)
                }
            ) + if (line.info.file != null) "\n\n" + UiText.get(R.string.umbra_ui_dev_126_file) else "",
            onDismiss = { deletingAll = null },
        )
    }
    Column(Modifier.fillMaxSize()) {
        // The name leads to the details of the contact, and that view holds
        // each action of a conversation. The search sits beside it.
        BackBar(
            chat.title,
            subtitle = when {
                threadOf != null -> stringResource(R.string.chat_thread)
                chat.isGroup -> groupSubtitle(chat)
                conversation.id.toList() in Core.typingNow -> stringResource(R.string.chat_typing)
                else -> null
            },
            onBack = { if (threadOf != null) threadOf = null else onBack() },
            isVerified = chat.isVerified,
            leading = { Avatar(chat, size = 36) },
            onTitle = {
                push(
                    if (chat.isGroup) {
                        Screen.GroupDetails(chat.conversation)
                    } else {
                        Screen.ContactDetails(chat.conversation)
                    },
                )
            },
            actions = { IconAction("magnifying-glass", stringResource(R.string.common_search)) { push(Screen.Search(chat.conversation)) } },
        )
        BlockedLine(chat)
        // GRP-199, GRP-200: the line ends at the first answer of a relay.
        if (chat.isUnreachable) {
            Box(Modifier.padding(start = 20.dp, end = 20.dp, top = 8.dp)) {
                Note(UiText.get(R.string.umbra_ui_grp_199))
            }
        }
        if (isQueueFull) {
            Box(Modifier.padding(start = 20.dp, end = 20.dp, top = 8.dp)) {
                Note(UiText.get(R.string.umbra_ui_imp_082))
            }
        }
        // GRP-050, GRP-070, GRP-089: each change of a group shows at its time.
        val notes = remember(modNotes, rosterNotes, memberNames) { chatNotes(modNotes, rosterNotes, memberNames) }
        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
        ) {
            item {
                // One line, and no more: the top of a conversation is for
                // its messages.
                Box(Modifier.fillMaxWidth().padding(top = 8.dp), contentAlignment = Alignment.Center) {
                    Row(
                        Modifier
                            .background(Palette.Incoming, CircleShape)
                            .padding(horizontal = 12.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FaIcon("lock", size = 10.dp, tint = Palette.TextSecondary)
                        Spacer(Modifier.width(6.dp))
                        Text(
                            stringResource(R.string.chat_end_to_end_encrypted),
                            style = MaterialTheme.typography.labelSmall,
                            color = Palette.TextSecondary,
                        )
                    }
                }
            }
            itemsIndexed(lines) { index, line ->
                // A thread shows its root and its replies alone.
                if (threadOf != null && line.key != threadOf && line.threadKey != threadOf) return@itemsIndexed
                val before = lines.getOrNull(index - 1)
                if (before == null || !isSameDay(before.info.storedAtMs, line.info.storedAtMs)) {
                    DayLabel(line.info.storedAtMs.toLong())
                }
                if (!line.info.outgoing && line.info.storedAtMs == newFrom) NewLabel()
                // GRP-089: each moderation epoch shows at its time.
                if (index == 0) {
                    for (note in notes.filter { it.atMs < line.info.storedAtMs }) NoteLine(note)
                }
                // DEV-207: a timer change is a row of the conversation.
                if (line.info.timer != null) {
                    TimerLine(line, chat)
                } else if (line.info.forwardPolicy != null) {
                    // DEV-324: a policy change is a row of the conversation.
                    ForwardLine(line, chat)
                } else if (line.info.cleared) {
                    ClearedLine(chat)
                } else Bubble(
                    line,
                    chat,
                    isFlashed = flashed == line.key,
                    // A press opens a photo that is there, and it starts a
                    // transfer that failed again. A press on an answer leads to
                    // the message that it answers.
                    onQuote = when {
                        line.info.deleted -> null
                        // A tap opens a hidden message on this device alone.
                        line.info.moderation == MOD_HIDE && line.key !in revealed -> ({ revealed.add(line.key) })
                        // IMP-167: a tap fetches a file that waits above the
                        // limit, and a file that failed.
                        // ATT-050: an expired file has nothing to fetch.
                        isExpired(line) -> null
                        line.info.file?.state?.toInt() == FILE_FAILED ||
                            line.info.file?.state?.toInt() == FILE_HELD -> ({ Core.fetchFile(line.handle) })
                        line.info.file?.state?.toInt() == FILE_READY -> when (line.info.file?.mimeClass) {
                            CLASS_IMAGE -> ({ push(Screen.Photo(conversation, line)) })
                            CLASS_VIDEO -> ({ push(Screen.Video(conversation, line)) })
                            CLASS_VOICE, CLASS_AUDIO -> ({ VoicePlayer.toggle(line) })
                            else -> ({ save(line) })
                        }
                        // NET-146: a tap shows the links of the message.
                        Links.ranges(line.text).isNotEmpty() -> ({ linksOf = line })
                        else -> line.quote?.let { quote -> { jumpTo(quote.key) } }
                    },
                    onLongPress = { chosen = line },
                    // A placeholder has no content to answer.
                    onReply = if (line.info.deleted) null else ({ answered = line }),
                    isRevealed = line.key in revealed,
                    // A group names the sender of a run of its messages.
                    author = line.info.sender?.takeIf {
                        chat.isGroup && (before == null || before.info.outgoing || before.info.sender != it)
                    }?.let { memberNames[it] ?: stringResource(R.string.common_member_number, it.toInt()) },
                    // A quote in a group names the member who wrote it.
                    quoteAuthor = line.quote?.let { quote ->
                        when {
                            quote.isOutgoing -> stringResource(R.string.common_you)
                            chat.isGroup -> quote.sender?.let { memberNames[it] ?: stringResource(R.string.common_member_number, it.toInt()) }
                            else -> chat.title
                        }
                    },
                )
                // WIR-273: a root names its replies, and a tap opens them.
                val replies = replyCounts[line.key] ?: 0
                if (replies > 0 && threadOf == null) {
                    Text(
                        pluralStringResource(R.plurals.chat_replies, replies, replies),
                        style = MaterialTheme.typography.labelMedium,
                        color = Palette.Action,
                        modifier = Modifier
                            .padding(start = 12.dp, bottom = 4.dp)
                            .press(role = Role.Button) { threadOf = line.key },
                    )
                }
                // The contact saw each message up to this one. The mark
                // sits under it and under no other, as a read marker does.
                if (index == readUpTo) ReadMark(chat)
                val next = lines.getOrNull(index + 1)
                for (note in notes) {
                    if (note.atMs >= line.info.storedAtMs && (next == null || note.atMs < next.info.storedAtMs)) {
                        NoteLine(note)
                    }
                }
            }
        }
        notice?.let {
            Box(Modifier.padding(horizontal = 12.dp)) { Note(it) }
        }
        // DEV-126: the limits of an edit show while the user edits. They go
        // at the confirmation and at the cancel, and they wait for no relay.
        if (edited != null) {
            Box(Modifier.padding(horizontal = 12.dp)) {
                Note(
                    UiText.get(
                        if (chat.isGroup) R.string.umbra_ui_dev_126_edit_group else R.string.umbra_ui_dev_126_edit,
                    ),
                )
            }
        }
        // An answer and an edit start with the keyboard open, as a user
        // expects it.
        LaunchedEffect(answered, edited) { if (answered != null || edited != null) composer.focus() }
        // WIR-535: the text of the composer goes with a file as its
        // caption. A caption above CAPTION_MAX stays in the composer, and
        // the file does not go.
        val takeCaption = takeCaption@{
            val chars = composer.take() ?: CharArray(0)
            if (utf8Length(chars) > CAPTION_MAX) {
                composer.set(chars)
                chars.fill('\u0000')
                notice = UiText.get(R.string.chat_caption_too_long)
                return@takeCaption null
            }
            chars
        }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { picked ->
            if (picked != null) {
                Core.sendPhoto(context, conversation, picked, takeCaption() ?: return@rememberLauncherForActivityResult)
                jumpsAtNextLoad = true
            }
        }
        val videoPicker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { picked ->
            if (picked != null) {
                Core.sendVideo(context, conversation, picked, takeCaption() ?: return@rememberLauncherForActivityResult)
                jumpsAtNextLoad = true
            }
        }
        val audioPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { picked ->
            if (picked != null) {
                Core.sendAudio(context, conversation, picked, takeCaption() ?: return@rememberLauncherForActivityResult)
                jumpsAtNextLoad = true
            }
        }
        val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { picked ->
            if (picked != null) {
                Core.sendDocument(context, conversation, picked, takeCaption() ?: return@rememberLauncherForActivityResult)
                jumpsAtNextLoad = true
            }
        }
        if (isAttaching) {
            // The pickers of the platform give this app the picked item alone,
            // and no access to the gallery or to the files.
            val entries = buildList {
                add(
                    RowEntry("image", stringResource(R.string.common_photo)) {
                        picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                    },
                )
                if (Files.canSendVideo) {
                    add(
                        RowEntry("film", stringResource(R.string.common_video)) {
                            videoPicker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.VideoOnly))
                        },
                    )
                    add(RowEntry("music", stringResource(R.string.chat_audio)) { audioPicker.launch(arrayOf("audio/*")) })
                }
                add(RowEntry("file", stringResource(R.string.common_file)) { filePicker.launch(arrayOf("*/*")) })
                // GRP-149: a group above POLL_GROUP_MAX members takes no poll.
                if (!chat.isGroup || chat.members <= POLL_GROUP_MAX) {
                    add(RowEntry("chart-bar", stringResource(R.string.chat_poll)) { push(Screen.NewPoll(conversation)) })
                }
            }
            ActionSheet(stringResource(R.string.common_attach), entries, onDismiss = { isAttaching = false })
        }
        // GRP-210: a group whose two relays hold it no more takes no new
        // message, and the composer would promise one. A group that
        // removed this device takes none either.
        val stopped = when {
            // GRP-297: the keys of the group moved on while this device was
            // away, and no member could give them to it.
            chat.isLapsed ->
                stringResource(R.string.chat_membership_lapsed)
            chat.isClosed -> stringResource(R.string.chat_group_closed)
            // GRP-373, GRP-374: a removed device took the index of this member.
            chat.isReturning ->
                stringResource(R.string.chat_device_took_your_place)
            chat.needsInvitation -> UiText.get(R.string.umbra_ui_grp_374)
            chat.isGroup && !chat.isMember ->
                stringResource(R.string.chat_no_longer_member)
            // An observer reads the group and posts nothing to it.
            chat.isGroup && ownRole == FfiRole.OBSERVER -> stringResource(R.string.chat_role_observer)
            else -> null
        }
        if (stopped != null) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                Note(stopped)
            }
            return@Column
        }
        // IDN-025: a key change blocks the conversation until the answer.
        keyChange?.let { pending ->
            KeyChangePanel(chat, pending)
            return@Column
        }
        // NET-355: the question blocks nothing, and the composer stays.
        if (asksRenewal) RenewalPanel(chat)
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            // The send button stays beside the line of the text.
            verticalAlignment = Alignment.Bottom,
        ) {
            // The answer is a part of the composer: the box of the field
            // grows upward and holds the name at its top.
            Column(Modifier.weight(1f).background(Palette.Incoming, RoundedCornerShape(24.dp))) {
                AnimatedVisibility(
                    visible = answered != null || edited != null,
                    enter = expandVertically() + fadeIn(),
                    exit = shrinkVertically() + fadeOut(),
                ) {
                    // The words stay for the time of the exit.
                    val header = remember { mutableStateOf("reply" to "") }
                    val quoted = remember { mutableStateOf(CharArray(0)) }
                    // A reply in a group names the member who wrote the message.
                    answered?.let {
                        header.value = "reply" to when {
                            it.info.outgoing -> stringResource(R.string.common_you)
                            chat.isGroup -> it.info.sender?.let { sender -> memberNames[sender] ?: stringResource(R.string.common_member_number, sender.toInt()) } ?: chat.title
                            else -> chat.title
                        }
                        quoted.value = quoteWords(it)
                    }
                    if (edited != null) {
                        header.value = "pen" to stringResource(R.string.chat_edit_message)
                        quoted.value = CharArray(0)
                    }
                    ComposerHeader(header.value.first, header.value.second, quoted.value) {
                        if (edited != null) composer.clear()
                        answered = null
                        edited = null
                    }
                }
                val active = recording
                if (active != null) {
                    RecordingBar(
                        active,
                        onDiscard = {
                            active.discard()
                            recording = null
                        },
                        modifier = Modifier.heightIn(min = 48.dp),
                    )
                } else Row(verticalAlignment = Alignment.Bottom) {
                    // The plus sits inside the box, and it opens
                    // the sheet of a photo, a video, and a file.
                    Box(
                        Modifier
                            .padding(start = 4.dp)
                            .size(48.dp)
                            .clip(CircleShape)
                            .press(role = Role.Button, label = stringResource(R.string.common_attach)) { isAttaching = true },
                        contentAlignment = Alignment.Center,
                    ) { FaIcon("plus", label = stringResource(R.string.common_attach), size = 18.dp, tint = Palette.TextSecondary) }
                    Box(
                        Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .padding(start = 2.dp, end = 18.dp, top = 12.dp, bottom = 12.dp),
                        contentAlignment = Alignment.CenterStart,
                    ) {
                        // With no network the record waits in the store.
                        PlatformInput(
                            composer,
                            hint = stringResource(R.string.common_message),
                            isPassphrase = false,
                            modifier = Modifier.fillMaxWidth(),
                            maxLines = 5,
                        )
                    }
                }
            }
            Spacer(Modifier.width(8.dp))
            // An empty composer records a voice message in the place of a
            // send. An answer and an edit take a text.
            val offersVoice = recording == null && composer.isEmpty && answered == null && edited == null &&
                Files.canSendVideo
            val sendLabel = stringResource(if (offersVoice) R.string.chat_record_voice_message else R.string.common_send)
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(Palette.Action)
                    .clickable(role = Role.Button, onClickLabel = sendLabel) {
                        val active = recording
                        if (active != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            recording = null
                            Core.sendVoice(conversation, active)
                            jumpsAtNextLoad = true
                            return@clickable
                        }
                        if (offersVoice) {
                            val state = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO)
                            if (state == PackageManager.PERMISSION_GRANTED) {
                                startRecording()
                            } else {
                                askMicrophone.launch(Manifest.permission.RECORD_AUDIO)
                            }
                            return@clickable
                        }
                        composer.take()?.let { text ->
                            val target = edited
                            if (target != null) {
                                Core.edit(conversation, target.handle, text)
                            } else {
                                Core.send(conversation, text, answered?.handle)
                                jumpsAtNextLoad = true
                            }
                            answered = null
                            edited = null
                        }
                    },
                contentAlignment = Alignment.Center,
            ) {
                // An edit ends with a check, and a message with the plane.
                val icon = when {
                    edited != null -> "check"
                    offersVoice -> "microphone"
                    else -> "paper-plane"
                }
                FaIcon(icon, label = sendLabel, size = 18.dp, tint = Palette.OnAction)
            }
        }
    }
}

/**
 * IMP-056: a copied message is marked as sensitive, thus the platform shows
 * no preview of it. The text goes from its array, and this code makes no
 * `String` of it.
 */
private fun copyMessage(context: Context, text: CharArray) {
    val clip = ClipData.newPlainText(UiText.get(R.string.chat_clipboard_label), CharBuffer.wrap(text))
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

private fun isSameDay(a: ULong, b: ULong): Boolean {
    val day = DateUtils.DAY_IN_MILLIS
    val zone = java.util.TimeZone.getDefault()
    val dayOf = { at: Long -> (at + zone.getOffset(at)) / day }
    return dayOf(a.toLong()) == dayOf(b.toLong())
}

@Composable
private fun DayLabel(atMs: Long) {
    val context = LocalContext.current
    val label = if (DateUtils.isToday(atMs)) {
        stringResource(R.string.chat_today)
    } else {
        DateUtils.formatDateTime(context, atMs, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_WEEKDAY)
    }
    Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = Palette.TextSecondary)
    }
}

/** The line above the first message that the user did not see yet. */
@Composable
private fun NewLabel() {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        HorizontalDivider(Modifier.weight(1f), color = Palette.Action.copy(alpha = 0.35f))
        Text(
            stringResource(R.string.chat_new_label),
            style = MaterialTheme.typography.labelMedium,
            color = Palette.Action,
            modifier = Modifier.padding(horizontal = 12.dp),
        )
        HorizontalDivider(Modifier.weight(1f), color = Palette.Action.copy(alpha = 0.35f))
    }
}

@Composable
private fun Bubble(
    line: Line,
    chat: Chat,
    isFlashed: Boolean,
    onQuote: (() -> Unit)?,
    onLongPress: () -> Unit,
    onReply: (() -> Unit)?,
    isRevealed: Boolean = false,
    author: String? = null,
    quoteAuthor: String? = null,
) {
    val isOutgoing = line.info.outgoing
    // A slide to the right answers the message. The bubble follows the
    // finger a short way, and it springs back at the release.
    val slide = remember { Animatable(0f) }
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    val reach = with(LocalDensity.current) { SLIDE_REACH.toPx() }
    val isPast = slide.value >= reach * SLIDE_POINT
    // The tick tells the finger that a release now starts the answer.
    LaunchedEffect(isPast) {
        if (isPast) haptics.performHapticFeedback(HapticFeedbackType.LongPress)
    }
    val drag = rememberDraggableState { delta ->
        // The finger moves more than the bubble, thus the end feels firm.
        val next = (slide.value + delta * 0.55f).coerceIn(0f, reach)
        scope.launch { slide.snapTo(next) }
    }
    // A jump to a message shows it for a moment, and the mark fades.
    val flash by animateColorAsState(
        if (isFlashed) Palette.Action.copy(alpha = 0.22f) else Color.Transparent,
        tween(durationMillis = if (isFlashed) 120 else 700),
        label = "jump flash",
    )
    Box(
        Modifier.fillMaxWidth().draggable(
            state = drag,
            enabled = onReply != null,
            orientation = Orientation.Horizontal,
            onDragStopped = {
                if (slide.value >= reach * SLIDE_POINT) onReply?.invoke()
                slide.animateTo(0f, spring(stiffness = Spring.StiffnessMediumLow))
            },
        ),
        contentAlignment = Alignment.CenterStart,
    ) {
        // The arrow grows behind the bubble as the slide goes on.
        val progress = (slide.value / (reach * SLIDE_POINT)).coerceIn(0f, 1f)
        FaIcon(
            "reply",
            size = 18.dp,
            tint = Palette.Action,
            modifier = Modifier.padding(start = 6.dp).graphicsLayer {
                alpha = progress
                scaleX = 0.6f + 0.4f * progress
                scaleY = 0.6f + 0.4f * progress
            },
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .offset { IntOffset(slide.value.roundToInt(), 0) }
                .padding(vertical = 4.dp),
            horizontalArrangement = if (isOutgoing) Arrangement.End else Arrangement.Start,
        ) {
            Column(horizontalAlignment = if (isOutgoing) Alignment.End else Alignment.Start) {
                // The text is a view of the platform, thus the press area lies above
                // the content, as in a row of the chat list. A press on an answer
                // leads to the message that it answers.
                PressOver(
                    Modifier
                        .widthIn(max = 300.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .drawWithContent {
                            drawContent()
                            drawRect(flash)
                        },
                    onClick = onQuote,
                    longLabel = stringResource(R.string.chat_message_actions),
                    onLongClick = onLongPress,
                    // The options of a poll take their own press.
                    isOver = line.poll == null,
                ) { BubbleContent(line, chat, isRevealed, author, quoteAuthor) }
                if (line.reactions.isNotEmpty()) ReactionPills(line)
            }
        }
    }
}

/** The six reactions of the sheet, the first choices of the other messengers. */
private val QUICK_REACTIONS = listOf("\u2764\uFE0F", "\uD83D\uDC4D", "\uD83D\uDC4E", "\uD83D\uDE02", "\uD83D\uDE2E", "\uD83D\uDE22")

/** One row of reactions at the top of the sheet of a message. */
@Composable
private fun QuickReactions(held: List<MsgReaction>, onPick: (String) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        for (emoji in QUICK_REACTIONS) {
            val isMine = held.any { it.mine && it.emoji == emoji }
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(if (isMine) Palette.Container else Color.Transparent)
                    .press(role = Role.Button, label = if (isMine) stringResource(R.string.chat_remove_reaction, emoji) else stringResource(R.string.chat_react, emoji)) {
                        onPick(emoji)
                    },
                contentAlignment = Alignment.Center,
            ) { Text(emoji, fontSize = 24.sp) }
        }
    }
}

/**
 * The reactions under a bubble: one pill for each emoji, with a count when
 * the two parties chose it. A press adds the reaction of this device or
 * takes it away.
 */
@Composable
private fun ReactionPills(line: Line) {
    Row(
        Modifier.padding(top = 4.dp, start = 6.dp, end = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        for ((emoji, parties) in line.reactions.groupBy { it.emoji }) {
            val isMine = parties.any { it.mine }
            val shape = RoundedCornerShape(12.dp)
            Row(
                Modifier
                    .clip(shape)
                    .background(if (isMine) Palette.Container else Palette.Surface)
                    .border(1.dp, if (isMine) Palette.Action else Palette.Divider, shape)
                    .press(role = Role.Button, label = if (isMine) stringResource(R.string.chat_remove_reaction, emoji) else stringResource(R.string.chat_react, emoji)) {
                        Core.react(line.handle, emoji)
                    }
                    .padding(horizontal = 8.dp, vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(emoji, fontSize = 14.sp)
                if (parties.size > 1) {
                    Spacer(Modifier.width(4.dp))
                    Text("${parties.size}", style = MaterialTheme.typography.labelSmall, color = Palette.TextSecondary)
                }
            }
        }
    }
}

/** How far a bubble follows a slide, and the part of that way that answers. */
private val SLIDE_REACH = 72.dp
private const val SLIDE_POINT = 0.8f

@Composable
private fun BubbleContent(
    line: Line,
    chat: Chat,
    isRevealed: Boolean = false,
    author: String? = null,
    quoteAuthor: String? = null,
) {
    val isOutgoing = line.info.outgoing
    // Part 11 §11.9.6: a hidden message shows its placeholder until a tap.
    val isHidden = line.info.moderation == MOD_HIDE && !isRevealed
    val isGone = line.info.deleted || isHidden
    // A photo and a video fill the bubble to a thin rim, as each messenger
    // shows one. A file sits in a bubble as a text does.
    val shownClass = line.info.file?.mimeClass
    val isPhoto = !line.info.deleted && (shownClass == CLASS_IMAGE || shownClass == CLASS_VIDEO)
    Column(
        modifier = Modifier
            .background(if (isOutgoing) Palette.Container else Palette.Incoming)
            // The quote spans the bubble, thus the bubble is as wide as its
            // widest part.
            .width(IntrinsicSize.Max)
            .padding(horizontal = if (isPhoto) 4.dp else 14.dp, vertical = if (isPhoto) 4.dp else 10.dp),
        horizontalAlignment = Alignment.End,
    ) {
        if (author != null) {
            Text(
                author,
                style = MaterialTheme.typography.labelMedium,
                color = Palette.Action,
                modifier = Modifier.align(Alignment.Start).padding(bottom = 2.dp),
            )
        }
        if (isHidden) {
            Row(Modifier.align(Alignment.Start), verticalAlignment = Alignment.CenterVertically) {
                FaIcon("eye", size = 13.dp, tint = Palette.TextSecondary)
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.chat_role_hid_message, roleWord(line.info.moderatorRole)),
                    style = MaterialTheme.typography.bodyMedium,
                    fontStyle = FontStyle.Italic,
                    color = Palette.TextSecondary,
                )
            }
        } else if (line.info.deleted) {
            // The placeholder of Part 7 §7.5.6. It names the party only
            // where this device held the message (DEV-102, DEV-103).
            Row(Modifier.align(Alignment.Start), verticalAlignment = Alignment.CenterVertically) {
                FaIcon("ban", size = 13.dp, tint = Palette.TextSecondary)
                Spacer(Modifier.width(8.dp))
                Text(
                    when {
                        line.info.moderation == MOD_REMOVE -> stringResource(R.string.chat_role_removed_message, roleWord(line.info.moderatorRole))
                        isOutgoing -> stringResource(R.string.chat_you_deleted_message)
                        else -> stringResource(R.string.chat_message_was_deleted)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    fontStyle = FontStyle.Italic,
                    color = Palette.TextSecondary,
                )
            }
        } else if (line.isReply) {
            val quote = line.quote
            QuoteBlock(
                author = quoteAuthor,
                text = quote?.text,
                modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
            )
        }
        // The text starts at the left edge, and the time sits at the right.
        val file = line.info.file
        if (!isGone && file != null) {
            when (file.mimeClass) {
                CLASS_IMAGE -> PhotoTile(line, file, Modifier.align(Alignment.Start))
                CLASS_VIDEO -> VideoTile(line, file, Modifier.align(Alignment.Start))
                CLASS_VOICE, CLASS_AUDIO -> VoiceTile(line, file, Modifier.align(Alignment.Start))
                // ATT-193: a class that this device does not know is a file.
                else -> FileTile(line, file, Modifier.align(Alignment.Start))
            }
            Spacer(Modifier.height(4.dp))
            // WIR-535: the caption sits under the file.
            if (line.text.isNotEmpty()) {
                PlatformText(
                    line.text,
                    Palette.Text,
                    modifier = Modifier
                        .align(Alignment.Start)
                        .padding(horizontal = if (isPhoto) 10.dp else 0.dp, vertical = 2.dp),
                )
            }
        } else if (!isGone && line.poll != null) {
            PollContent(line, line.poll, Modifier.align(Alignment.Start))
        } else if (!isGone) {
            // WIR-177: a forward says so, and it names no earlier sender.
            if (line.info.forwardDepth.toInt() > 0) {
                Text(
                    stringResource(R.string.chat_forwarded),
                    style = MaterialTheme.typography.labelMedium,
                    color = Palette.TextSecondary,
                    modifier = Modifier.align(Alignment.Start).padding(bottom = 2.dp),
                )
            }
            // A mention of this member in a group (Part 11 §11.11).
            if (line.info.mentionsMe) {
                Text(
                    stringResource(R.string.chat_mentions_you),
                    style = MaterialTheme.typography.labelMedium,
                    color = Palette.Action,
                    modifier = Modifier.align(Alignment.Start).padding(bottom = 2.dp),
                )
            }
            PlatformText(line.text, Palette.Text, modifier = Modifier.align(Alignment.Start), showsLinks = true)
        }
        Spacer(Modifier.height(2.dp))
        val clock = DateUtils.formatDateTime(
            LocalContext.current,
            line.info.shownAtMs,
            DateUtils.FORMAT_SHOW_TIME,
        )
        // A read message carries no word: the mark under the newest
        // one says it for each of them.
        val state = line.info.delivery.toInt()
        Text(
            // A placeholder shows its time and no state of a delivery. DEV-090:
            // an edited message says so, on the two devices.
            buildString {
                if (line.info.edited) append(stringResource(R.string.chat_edited)).append(" · ")
                append(clock)
                // WIR-463: a record that a key supply opened says so.
                if (line.info.recovered) append(" · ").append(stringResource(R.string.chat_recovered))
                // A timed message says when it goes.
                line.info.expiresAt?.let { at ->
                    append(" · ").append(leftLabel(at.toLong() - System.currentTimeMillis() / 1_000))
                }
                if (isOutgoing && state != READ && !line.info.deleted) {
                    // A file goes to the relays first, and its record follows.
                    val isUploading = file?.state?.toInt() == FILE_UPLOADING
                    val share = file?.let(::progressOf)
                    append(" · ").append(
                        when {
                            isUploading && share != null -> stringResource(R.string.chat_sending_percent, share)
                            isUploading -> stringResource(R.string.chat_sending)
                            else -> deliveryLabel(line.info.delivery, line.info.failure)
                        },
                    )
                }
            },
            style = MaterialTheme.typography.labelSmall,
            color = if (state == FAILED) Palette.Error else Palette.TextSecondary,
            // The time of a photo keeps the place that the time of a text has.
            modifier = if (isPhoto) Modifier.padding(end = 10.dp, bottom = 4.dp).subline() else Modifier.subline(),
        )
    }
}

/**
 * The message that a message answers, as each messenger shows it: a bar in
 * the accent color, the name of the author, and the start of the text. An
 * answer to a message that this device does not hold has no author
 * (`WIR-173`).
 */
@Composable
private fun QuoteBlock(author: String?, text: CharArray?, modifier: Modifier = Modifier) {
    Row(
        modifier
            .height(IntrinsicSize.Min)
            .clip(RoundedCornerShape(10.dp))
            .background(Palette.Pressed),
    ) {
        Box(Modifier.width(4.dp).fillMaxHeight().background(Palette.Action))
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            if (author != null) {
                Text(
                    author,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Action,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (text == null) {
                Text(
                    stringResource(R.string.chat_message_not_on_device),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                )
            } else {
                PlatformText(text, Palette.TextSecondary, sizeSp = 13f, maxLines = 2)
            }
        }
    }
}

/**
 * What the composer does beside a new message, at the top of the box of the
 * field: the reply arrow with the name of the author, or the pen with "Edit
 * message", and a small way to take it back. A line divides it from the
 * text.
 */
@Composable
private fun ComposerHeader(icon: String, words: String, quoted: CharArray, onCancel: () -> Unit) {
    Column {
        Row(
            Modifier.fillMaxWidth().padding(start = 18.dp, end = 6.dp, top = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon(icon, size = 14.dp, tint = Palette.Action)
            Spacer(Modifier.width(8.dp))
            Text(
                words,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = Palette.Action,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Box(
                Modifier.size(36.dp).clip(CircleShape).press(role = Role.Button, label = stringResource(R.string.common_cancel), onClick = onCancel),
                contentAlignment = Alignment.Center,
            ) { FaIcon("xmark", label = stringResource(R.string.common_cancel), size = 14.dp, tint = Palette.TextSecondary) }
        }
        // The message that the answer names, in one line.
        if (quoted.isNotEmpty()) {
            PlatformText(
                quoted,
                Palette.TextSecondary,
                modifier = Modifier.padding(start = 18.dp, end = 18.dp, bottom = 6.dp),
                sizeSp = 13f,
                maxLines = 1,
            )
        }
        HorizontalDivider(Modifier.padding(horizontal = 18.dp), color = Palette.Outline.copy(alpha = 0.5f))
    }
}

/**
 * The words of a message in the strip of its answer: its text, the question
 * of a poll, the caption of a file, or the word of a file with no caption.
 */
private fun quoteWords(line: Line): CharArray {
    val file = line.info.file
    return if (file != null && line.text.isEmpty()) fileWord(file).toCharArray() else line.text
}

/** The preview of a forward policy change in the list of chats. */
fun forwardPreview(prohibits: Boolean): String =
    UiText.get(if (prohibits) R.string.chat_forwarding_off else R.string.chat_forwarding_on)

/** The row of a forward policy change (`DEV-324`), in the form of a timer change. */
@Composable
private fun ForwardLine(line: Line, chat: Chat) {
    val prohibits = line.info.forwardPolicy ?: return
    val who = timerAuthor(chat, line.info.outgoing)
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier
                .background(Palette.Incoming, CircleShape)
                .padding(horizontal = 12.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon("share-nodes", size = 10.dp, tint = Palette.TextSecondary)
            Spacer(Modifier.width(6.dp))
            Text(
                stringResource(
                    if (prohibits) R.string.chat_turned_forwarding_off else R.string.chat_turned_forwarding_on,
                    who,
                ),
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** The trace of a deletion of the whole conversation by the contact (`DEV-336`). */
@Composable
private fun ClearedLine(chat: Chat) {
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier
                .background(Palette.Incoming, CircleShape)
                .padding(horizontal = 12.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FaIcon("trash-can", size = 10.dp, tint = Palette.TextSecondary)
            Spacer(Modifier.width(6.dp))
            Text(
                stringResource(R.string.chat_contact_deleted_chat, chat.title),
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** A scroll offset above the height of each item: the end of the list. */
private const val END_OF_LIST = 1_000_000
private const val FAILED = 4
private const val READ = 3

/** The small picture of the contact under the newest message that it saw. */
@Composable
private fun ReadMark(chat: Chat) {
    val readLabel = stringResource(R.string.chat_read)
    Row(
        Modifier.fillMaxWidth().padding(end = 4.dp, bottom = 2.dp).semantics { contentDescription = readLabel },
        horizontalArrangement = Arrangement.End,
    ) { Avatar(chat, size = 16) }
}

/**
 * The closed list of Part 14 §14.9.1. "Accepted" means that a relay took the
 * record. It does not mean that the contact has it.
 */
private fun deliveryLabel(state: UByte, failure: UByte): String = when (state.toInt()) {
    0 -> UiText.get(R.string.chat_delivery_waiting)
    1 -> UiText.get(R.string.chat_delivery_accepted)
    2 -> UiText.get(R.string.chat_delivery_delivered)
    // IMP-074: a failed record names its cause.
    FAILED -> UiText.get(
        when (failure.toInt()) {
            1 -> R.string.umbra_ui_imp_074_refused
            2 -> R.string.umbra_ui_imp_074_no_path
            3 -> R.string.umbra_ui_imp_074_upload
            4 -> R.string.umbra_ui_imp_074_no_replica
            5 -> R.string.umbra_ui_imp_074_full
            else -> R.string.umbra_ui_imp_074
        },
    )
    // A read message shows the mark of the contact and no word.
    else -> ""
}

