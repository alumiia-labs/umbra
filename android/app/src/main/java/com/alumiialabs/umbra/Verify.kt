package com.alumiialabs.umbra

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
import kotlinx.coroutines.delay
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.umbra_ffi.ForwardRules
import uniffi.umbra_ffi.Receipts

/** The details of one contact: who it is, and what the user can do with it. */
@Composable
fun ContactDetailsScreen(chat: Chat, onBack: () -> Unit, onMessage: () -> Unit, push: (Screen) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.verify_contact_details), onBack = onBack)
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(12.dp))
            // Part 9 §9.8: the user gives the contact a picture.
            EditablePicture(
                hasPicture = chat.picture != null,
                onSet = { square -> Core.setContactPicture(chat.conversation, square) },
            ) { Avatar(chat, size = EDITABLE_PICTURE_SIZE) }
            Spacer(Modifier.height(12.dp))
            Text(chat.title, style = MaterialTheme.typography.headlineMedium)
            if (chat.isVerified) {
                Spacer(Modifier.height(6.dp))
                VerifiedMark()
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.common_message), onClick = onMessage)
            Spacer(Modifier.height(8.dp))
            EntryRow(RowEntry("pen", stringResource(R.string.verify_edit_name)) { push(Screen.EditName(chat.conversation)) })
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("shield-check", if (chat.isVerified) stringResource(R.string.verify_verify_again) else stringResource(R.string.verify_verify_contact)) {
                    push(Screen.Verify(chat.conversation))
                },
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("photo-film", stringResource(R.string.common_media_and_files)) {
                    push(Screen.Media(chat.conversation))
                },
            )
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("gear", stringResource(R.string.common_conversation_settings)) {
                    push(Screen.ConversationSettings(chat.conversation))
                },
            )
            // Part 6 §6.6.7: an introduction asks the other contact first.
            var isIntroducing by remember { mutableStateOf(false) }
            var introduced by remember { mutableStateOf<String?>(null) }
            HorizontalDivider(color = Palette.Divider)
            EntryRow(
                RowEntry("user-plus", stringResource(R.string.verify_introduce), introduced) { isIntroducing = true },
            )
            if (isIntroducing) {
                ActionSheet(
                    stringResource(R.string.verify_introduce_title, chat.title),
                    Core.chats.filter { !it.isGroup && !it.conversation.id.contentEquals(chat.conversation.id) }
                        .map { other ->
                            RowEntry("comment", other.title) {
                                Core.requestIntroduction(to = other, about = chat) {
                                    introduced = UiText.get(R.string.verify_asked, other.title)
                                }
                            }
                        },
                    onDismiss = { isIntroducing = false },
                )
            }
            // Part 4 §4.7.3: a piece of the recovery of this contact.
            var held by remember { mutableStateOf<uniffi.umbra_ffi.FfiHeldShare?>(null) }
            LaunchedEffect(chat.conversation, Core.revision) { Core.heldShare(chat.conversation) { held = it } }
            held?.let { share ->
                HorizontalDivider(color = Palette.Divider)
                EntryRow(
                    RowEntry(
                        "key",
                        stringResource(R.string.verify_recovery_share),
                        stringResource(R.string.verify_share_piece, share.index.toInt(), share.count.toInt(), share.threshold.toInt()),
                    ) {
                        push(Screen.HeldShare(chat.conversation))
                    },
                )
            }
            HorizontalDivider(color = Palette.Divider)
            var isBlocked by remember { mutableStateOf(false) }
            LaunchedEffect(chat.conversation, Core.revision) {
                Core.isBlocked(chat.conversation) { isBlocked = it }
            }
            EntryRow(
                RowEntry("ban", if (isBlocked) stringResource(R.string.common_unblock) else stringResource(R.string.common_block)) {
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
    var alert by remember { mutableStateOf<UByte?>(null) }
    var isSecure by remember { mutableStateOf<Boolean?>(null) }
    var mode by remember { mutableStateOf<Int?>(null) }
    var isChoosingMode by remember { mutableStateOf(false) }
    var forward by remember { mutableStateOf<ForwardRules?>(null) }
    // DEV-326: the limit of the policy shows when the user turns it on.
    var forwardNotice by remember { mutableStateOf(false) }
    LaunchedEffect(forwardNotice) {
        if (forwardNotice) {
            delay(6_000)
            forwardNotice = false
        }
    }
    LaunchedEffect(chat.conversation, Core.revision) { Core.forwardRules(chat.conversation) { forward = it } }
    LaunchedEffect(chat.conversation) { Core.privacyMode(chat.conversation) { mode = it } }
    LaunchedEffect(chat.conversation) { Core.receipts(chat.conversation) { receipts = it } }
    LaunchedEffect(chat.conversation, Core.revision) { Core.screenshotBlocked(chat.conversation) { isSecure = it } }
    LaunchedEffect(chat.conversation, Core.revision) { Core.alertSetting(chat.conversation) { alert = it } }
    LaunchedEffect(chat.conversation, Core.revision) { Core.timer(chat.conversation) { timer = it.seconds } }
    val change = { next: Receipts ->
        receipts = next
        Core.setReceipts(chat.conversation, next)
    }
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_conversation_settings), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            alert?.let {
                EntryRow(
                    RowEntry("bell", stringResource(R.string.common_notifications), alertLabel(it)) {
                        push(Screen.Alerts(chat.conversation))
                    },
                )
                HorizontalDivider(color = Palette.Divider)
            }
            timer?.let {
                EntryRow(
                    RowEntry("clock", stringResource(R.string.common_disappearing_messages), timerLabel(it)) {
                        push(Screen.Disappearing(chat.conversation))
                    },
                )
                HorizontalDivider(color = Palette.Divider)
            }
            // Part 3 §3.9, NET-081: the mode is a control of speed and of
            // timing cover. A group takes the mode of the device.
            if (!chat.isGroup) {
                mode?.let {
                    EntryRow(RowEntry("hourglass-half", stringResource(R.string.verify_delivery_speed), modeLabel(it)) { isChoosingMode = true })
                    HorizontalDivider(color = Palette.Divider)
                }
            }
            // The switches stay in one group, below the rows that open a screen.
            isSecure?.let {
                ToggleRow(stringResource(R.string.verify_block_screenshots), it) { on -> Core.blockScreenshots(chat.conversation, on) }
                HorizontalDivider(color = Palette.Divider)
            }
            receipts?.let { now ->
                ToggleRow(stringResource(R.string.verify_delivery_receipts), now.delivery) { change(Receipts(it, now.read)) }
                HorizontalDivider(color = Palette.Divider)
                ToggleRow(stringResource(R.string.verify_read_receipts), now.read) { change(Receipts(now.delivery, it)) }
                HorizontalDivider(color = Palette.Divider)
            }
            // DEV-321: the user prohibits the forward of the messages of
            // the user. A group has its switch in the group details.
            if (!chat.isGroup) {
                forward?.let { now ->
                    ToggleRow(stringResource(R.string.verify_no_forwarding), now.own) { on ->
                        forward = ForwardRules(on, now.peer)
                        forwardNotice = on
                        Core.setForwardProhibited(chat.conversation, on)
                    }
                }
            }
            if (forwardNotice) {
                Spacer(Modifier.height(12.dp))
                Note(UiText.get(R.string.umbra_ui_dev_326))
            }
        }
    }
    if (isChoosingMode) {
        ActionSheet(
            title = stringResource(R.string.verify_delivery_speed),
            entries = listOf(0, 1, 2).map { choice ->
                RowEntry("hourglass-half", modeLabel(choice)) {
                    mode = choice
                    Core.keepPrivacyMode(chat.conversation, choice)
                    isChoosingMode = false
                }
            },
            note = stringResource(R.string.verify_speed_note),
            onDismiss = { isChoosingMode = false },
        )
    }
}

private fun modeLabel(mode: Int): String = when (mode) {
    0 -> UiText.get(R.string.verify_speed_fast)
    2 -> UiText.get(R.string.verify_speed_slow)
    else -> UiText.get(R.string.verify_speed_balanced)
}

@Composable
private fun VerifiedMark() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        FaIcon("shield-check", size = 14.dp, tint = Palette.Action)
        Spacer(Modifier.width(6.dp))
        Text(stringResource(R.string.common_verified), style = MaterialTheme.typography.labelLarge, color = Palette.Action)
    }
}

/** The ways to verify a contact: the code of the two keys, and the short code. */
@Composable
fun VerifyScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var number by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(chat.conversation) { Core.safetyNumber(chat.conversation) { number = it } }
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.verify_verify_contact), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            // The one fact that decides the worth of a comparison: its channel.
            Headline(stringResource(R.string.verify_compare_with, chat.title), stringResource(R.string.verify_trusted_channel))
            Spacer(Modifier.height(20.dp))
            number?.let {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    QrCode(it, stringResource(R.string.verify_qr_description))
                }
                Spacer(Modifier.height(20.dp))
            }
            // IDN-140: the scan is the first way, and the short code the second.
            PrimaryButton(stringResource(R.string.verify_scan_code_of, chat.title)) { push(Screen.ScanSafetyNumber(chat.conversation)) }
            Spacer(Modifier.height(8.dp))
            SecondaryButton(stringResource(R.string.verify_compare_short_code)) { push(Screen.VerifyCode(chat.conversation, starts = true)) }
            Spacer(Modifier.height(8.dp))
            EntryRow(RowEntry("key", stringResource(R.string.verify_full_safety_number)) { push(Screen.SafetyNumber(chat.conversation)) })
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
    val failure = Core.verifyFault?.takeIf { it.first == conversation }?.second
    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.verify_title, chat.title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            HeroIcon(if (isMismatch) "triangle-exclamation" else "shield-check")
            Spacer(Modifier.height(20.dp))
            when {
                isDone -> {
                    Headline(stringResource(R.string.verify_done, chat.title))
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.common_done), onClick = onBack)
                }
                isMismatch -> {
                    // A user cannot know what a mismatch means.
                    Headline(
                        stringResource(R.string.verify_mismatch),
                        stringResource(R.string.verify_mismatch_body, chat.title),
                    )
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.common_try_again), onClick = start)
                }
                code != null -> {
                    Headline(stringResource(R.string.verify_codes_match_question))
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
                    PrimaryButton(stringResource(R.string.verify_codes_match)) { Core.confirmVerification(conversation) }
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton(stringResource(R.string.verify_codes_differ)) {
                        Core.endVerification()
                        isMismatch = true
                    }
                }
                failure != null -> {
                    Headline(stringResource(R.string.verify_no_code))
                    Spacer(Modifier.height(12.dp))
                    Note(failure, isError = true)
                    Spacer(Modifier.height(16.dp))
                    PrimaryButton(stringResource(R.string.common_try_again), onClick = start)
                }
                else -> {
                    // The two devices make the code together.
                    Headline(stringResource(R.string.verify_waiting, chat.title))
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
            Headline(stringResource(R.string.verify_safety_number))
            Spacer(Modifier.height(16.dp))
            val groups = number?.split(' ').orEmpty()
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(24.dp))
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
            SecondaryButton(stringResource(R.string.verify_copy), enabled = number != null) {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText(UiText.get(R.string.verify_safety_number), number))
            }
        }
    }
}

/**
 * This device holds the code of a ceremony, and no view shows it. A start of
 * a contact alone makes no code (`IDN-170`). The code is here after the user
 * started too, thus this line shows for a ceremony of the user alone. The
 * line leads to the comparison.
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
        Text(stringResource(R.string.verify_prompt, chat.title), Modifier.weight(1f))
        FaIcon("chevron-right", size = 14.dp, tint = Palette.TextSecondary)
    }
}

/**
 * The blocking notice of a key change (Part 4 §4.5.1). It states that an
 * acceptance ends the healing of the channel (`IDN-089`), and it offers the
 * new safety number for a comparison first (`IDN-090`). The acceptance is
 * no default action (`IDN-091`), and it answers for this contact alone
 * (`IDN-092`).
 */
@Composable
fun KeyChangePanel(chat: Chat, pending: uniffi.umbra_ffi.FfiKeyChange) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(stringResource(R.string.verify_new_key, chat.title), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(R.string.verify_key_change_body, chat.title, UiText.get(R.string.umbra_ui_idn_089)),
            style = MaterialTheme.typography.bodyMedium,
            color = Palette.TextSecondary,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            pending.newSafetyNumber,
            style = MaterialTheme.typography.bodyLarge,
            fontFamily = Fonts.Mono,
        )
        Spacer(Modifier.height(12.dp))
        SecondaryButton(stringResource(R.string.verify_accept_new_key)) { Core.acceptKeyChange(chat.conversation) }
    }
}

/**
 * The question of a renewal that came with no proof of the renewal guard
 * (Part 3 `NET-355`). It states what an acceptance gives away, and the
 * acceptance is no default action (`NET-359`). It answers for this contact
 * alone.
 */
@Composable
fun RenewalPanel(chat: Chat) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(stringResource(R.string.verify_renewal, chat.title), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            UiText.get(R.string.umbra_ui_net_359),
            style = MaterialTheme.typography.bodyMedium,
            color = Palette.TextSecondary,
        )
        Spacer(Modifier.height(12.dp))
        SecondaryButton(stringResource(R.string.common_accept)) { Core.answerRenewal(chat.conversation, true) }
        QuietButton(stringResource(R.string.verify_refuse)) { Core.answerRenewal(chat.conversation, false) }
    }
}
