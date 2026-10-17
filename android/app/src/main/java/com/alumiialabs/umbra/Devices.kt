package com.alumiialabs.umbra

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import uniffi.umbra_ffi.Device
import uniffi.umbra_ffi.FfiTakeOverCount
import uniffi.umbra_ffi.LinkStatus

/**
 * A fork of the roster (Part 7 §7.7): the view names the device that signed
 * the other epoch (`DEV-170`), and it selects nothing in silence (`DEV-171`).
 */
@Composable
fun RosterForkPrompt() {
    val fork = Core.rosterForks.firstOrNull() ?: return
    val name = fork.label.ifEmpty { stringResource(R.string.devices_a_removed_device) }

    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(
            when (fork.kind.toInt()) {
                1 -> stringResource(R.string.devices_fork_two_versions, name)
                2 -> stringResource(R.string.devices_fork_different_removal, name)
                else -> stringResource(R.string.devices_fork_different_list, name)
            },
        )
        Text(
            stringResource(R.string.devices_fork_advice, name),
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        InlineButton(stringResource(R.string.common_dismiss)) { Core.dismissRosterFork(fork) }
    }
}

/**
 * The deletions of the other devices that postdate a restore (Part 7
 * `DEV-117`, `DEV-118`): the count shows, and none applies before the user
 * says so.
 */
@Composable
fun HeldDeletionsPrompt() {
    val count = Core.heldDeletions
    if (count == 0) return

    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(pluralStringResource(R.plurals.devices_held_deletions, count, count))
        Spacer(Modifier.height(8.dp))
        Row {
            InlineButton(stringResource(R.string.common_delete)) { Core.applyHeldDeletions(apply = true) }
            Spacer(Modifier.width(12.dp))
            InlineButton(stringResource(R.string.devices_keep)) { Core.applyHeldDeletions(apply = false) }
        }
    }
}

/** The devices of the set (Part 7), and the start of a link. */
@Composable
fun DevicesScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    LaunchedEffect(Unit) { Core.readDevices() }

    // DEV-315: a take-over waits for a run that read the sync channel, thus
    // its row can come while the view shows.
    LaunchedEffect(Core.ownsChannels) {
        while (!Core.ownsChannels) {
            delay(5_000)
            Core.readTakeOver()
        }
    }

    var removing by remember { mutableStateOf<Device?>(null) }
    removing?.let { device ->
        // DEV-119, DEV-120: the deletions of that device since the last
        // change of the set, and what brings them back.
        var deletions by remember(device) { mutableStateOf(0) }
        LaunchedEffect(device) { Core.deletionsFrom(device.deviceId) { deletions = it } }
        val removed = when (deletions) {
            0 -> ""
            else -> " " + pluralStringResource(R.plurals.devices_removal_deletions, deletions, deletions)
        }

        // Part 7 DEV-137 and DEV-138: the two limits of a removal, in
        // those words.
        ActionSheet(
            title = if (device.label.isEmpty()) {
                stringResource(R.string.devices_remove_this_device)
            } else {
                stringResource(R.string.devices_remove_named, device.label)
            },
            entries = listOf(
                RowEntry("trash-can", stringResource(R.string.devices_remove)) { Core.removeDevice(device.deviceId) },
            ),
            note = UiText.get(R.string.umbra_ui_dev_137) +
                " " + stringResource(R.string.devices_hostile_hands) + removed,
            onDismiss = { removing = null },
        )
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.devices_linked_devices), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            for (device in Core.devices) {
                // The device that owns the channels removes another one.
                val canRemove = Core.ownsChannels && !device.isSelf
                Row(
                    Modifier
                        .fillMaxWidth()
                        .then(if (canRemove) Modifier.press(role = Role.Button) { removing = device } else Modifier)
                        .padding(horizontal = PressInset, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    FaIcon("mobile", size = 20.dp, tint = Palette.Text)
                    Spacer(Modifier.width(18.dp))
                    Column {
                        Text(device.label.ifEmpty { stringResource(R.string.devices_device) })
                        if (device.isSelf) {
                            Text(
                                stringResource(R.string.devices_this_device),
                                style = MaterialTheme.typography.bodySmall,
                                color = Palette.TextSecondary,
                                modifier = Modifier.subline(),
                            )
                        }
                    }
                }
            }

            if (Core.canTakeOver) {
                EntryRow(
                    RowEntry("triangle-exclamation", stringResource(R.string.devices_owning_device_lost_question)) {
                        push(Screen.TakeOver)
                    },
                )
            }

            Column(Modifier.padding(20.dp)) {
                if (Core.ownsChannels) {
                    PrimaryButton(stringResource(R.string.devices_link_a_device)) { push(Screen.LinkDevice) }
                }
            }
        }
    }
}

/**
 * The take-over of a set whose owning device is lost (Part 7 §7.7): what
 * that device owns (`DEV-235`), what changes (`DEV-318`), one confirmation,
 * and then the new recovery code.
 */
@Composable
fun TakeOverScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var count by remember { mutableStateOf<FfiTakeOverCount?>(null) }
    var digits by remember { mutableStateOf<CharArray?>(null) }
    var isRunning by remember { mutableStateOf(false) }
    var isRefused by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { Core.takeOverCount { count = it } }

    digits?.let { held ->
        SecretDigitsScreen(
            stringResource(R.string.devices_new_recovery_code),
            stringResource(R.string.devices_lost_code_note),
            onBack,
        ) { show ->
            show(held)
        }
        return
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.devices_owning_device_lost), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Text(stringResource(R.string.devices_takeover_intro))
            Spacer(Modifier.height(12.dp))

            val lines = buildList {
                count?.let { held ->
                    val contacts = UiText.plural(
                        R.plurals.devices_takeover_contacts,
                        held.contacts.toInt(),
                        held.contacts.toLong(),
                    )
                    val groups = UiText.plural(
                        R.plurals.devices_takeover_groups,
                        held.groups.toInt(),
                        held.groups.toLong(),
                    )
                    add(UiText.get(R.string.devices_takeover_move, contacts, groups))
                }
                add(UiText.get(R.string.devices_takeover_new_connection))
                count?.unreachable?.takeIf { it > 0u }?.let { late ->
                    add(UiText.plural(R.plurals.devices_takeover_unreachable, late.toInt(), late.toLong()))
                }
                add(UiText.get(R.string.devices_takeover_devices_leave))
                add(UiText.get(R.string.devices_takeover_code_changes))
            }
            for (line in lines) {
                Text("· $line", color = Palette.TextSecondary, modifier = Modifier.padding(bottom = 6.dp))
            }

            Spacer(Modifier.height(16.dp))
            if (isRefused) {
                Note(stringResource(R.string.devices_takeover_not_lost), isError = true)
                Spacer(Modifier.height(12.dp))
            }
            DangerButton(stringResource(R.string.devices_take_over), enabled = !isRunning) {
                isRunning = true
                isRefused = false
                Core.takeOver(context) { code ->
                    isRunning = false
                    if (code == null) {
                        isRefused = true
                    } else {
                        RecoveryPrompt.seen(context)
                        digits = code
                    }
                }
            }
        }
    }
}

/** The six digits of a link code, as two groups of three. */
@Composable
private fun LinkCode(code: String) {
    Text(
        "${code.take(3)} ${code.drop(3)}",
        fontSize = 40.sp,
        letterSpacing = 4.sp,
        color = Palette.Action,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Progress() {
    LinearProgressIndicator(
        modifier = Modifier.fillMaxWidth().height(5.dp).clip(CircleShape),
        color = Palette.Action,
        trackColor = Palette.Container,
    )
}

/**
 * The link as the existing device (Part 7 §7.4): the ticket as a QR code,
 * the code that the user compares (`DEV-283`), and the copy to the new
 * device. A view that closes before the end ends the link.
 */
@Composable
fun LinkDeviceScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var attempt by remember { mutableStateOf(0) }
    LaunchedEffect(attempt) {
        Core.startLink(context)
        while (true) {
            delay(1_000)
            Core.readLink()
        }
    }
    DisposableEffect(Unit) {
        onDispose { if (Core.linkStatus !is LinkStatus.Linked) Core.cancelLink() }
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.devices_link_a_device), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            when (val status = Core.linkStatus) {
                is LinkStatus.Ticket -> {
                    Headline(stringResource(R.string.devices_scan_on_new_device))
                    Spacer(Modifier.height(20.dp))
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        QrCode(status.text, stringResource(R.string.devices_link_qr))
                    }
                    Spacer(Modifier.height(16.dp))
                    Text(
                        status.text,
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
                    SecondaryButton(stringResource(R.string.devices_copy_the_code)) {
                        copySensitive(context, status.text, UiText.get(R.string.common_umbra_link))
                    }
                    Spacer(Modifier.height(12.dp))
                    Note(stringResource(R.string.devices_link_expires))
                }
                is LinkStatus.Code -> {
                    Headline(stringResource(R.string.devices_codes_match_question))
                    Spacer(Modifier.height(20.dp))
                    LinkCode(status.code)
                    Spacer(Modifier.height(24.dp))
                    PrimaryButton(stringResource(R.string.devices_codes_match)) { Core.confirmLink() }
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton(stringResource(R.string.devices_codes_do_not_match)) {
                        Core.cancelLink()
                        onBack()
                    }
                }
                is LinkStatus.Sending, is LinkStatus.Waiting -> {
                    Headline(stringResource(R.string.devices_copying))
                    Spacer(Modifier.height(20.dp))
                    Progress()
                }
                is LinkStatus.Linked -> {
                    HeroIcon("check")
                    Spacer(Modifier.height(20.dp))
                    Headline(stringResource(R.string.devices_linked))
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.common_done), onClick = onBack)
                }
                is LinkStatus.Expired, is LinkStatus.Failed -> {
                    HeroIcon("triangle-exclamation")
                    Spacer(Modifier.height(20.dp))
                    Headline(
                        if (status is LinkStatus.Expired) {
                            stringResource(R.string.devices_code_ran_out)
                        } else {
                            stringResource(R.string.common_link_failed)
                        },
                    )
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.common_try_again)) { attempt++ }
                }
                // A refused start (DEV-302) shows its fault below, and no
                // wait that never ends.
                is LinkStatus.Idle -> PrimaryButton(stringResource(R.string.common_try_again)) { attempt++ }
                else -> {
                    // The offer goes up to a relay before the code exists.
                    Headline(stringResource(R.string.devices_preparing_code))
                    Spacer(Modifier.height(20.dp))
                    Progress()
                }
            }

            Core.fault?.let {
                Spacer(Modifier.height(16.dp))
                Note(it, isError = true)
            }
        }
    }
}

/**
 * The link of a first launch as the new device: a passphrase for this
 * device, the scan of the code of the other device, and the code that the
 * user compares there. The store comes from the snapshot (`DEV-284`).
 */
@Composable
fun JoinForm(onCancel: () -> Unit) {
    val context = LocalContext.current
    val passphrase = rememberPlatformField()
    var held by remember { mutableStateOf<CharArray?>(null) }
    var isPasting by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }
    DisposableEffect(Unit) { onDispose { held?.fill('\u0000') } }

    val code = Core.joinCode
    val note = Core.joinNote
    // The keyboard of the passphrase has no field in the scanner.
    HideKeyboardOn(held != null)

    Column(Modifier.fillMaxWidth()) {
        when {
            code != null -> {
                LinkCode(code)
                Spacer(Modifier.height(16.dp))
                Text(
                    stringResource(R.string.devices_confirm_on_other),
                    color = Palette.TextSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            note != null -> {
                Text(note, style = MaterialTheme.typography.bodySmall, color = Palette.TextSecondary)
                Spacer(Modifier.height(10.dp))
                Progress()
            }
            held != null && isPasting -> {
                // A ticket is no message text, thus a composable field
                // holds it.
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    label = { Text(stringResource(R.string.devices_code_of_link)) },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false,
                    ),
                    maxLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                PrimaryButton(stringResource(R.string.devices_link), enabled = pasted.isNotBlank()) {
                    val phrase = held ?: return@PrimaryButton
                    held = null
                    Core.join(context, phrase, pasted.trim())
                }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.common_back)) { isPasting = false }
            }
            held != null -> {
                Scanner { text ->
                    val phrase = held ?: return@Scanner
                    held = null
                    Core.join(context, phrase, text)
                }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.devices_paste_code_instead)) { isPasting = true }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.common_back)) {
                    held?.fill('\u0000')
                    held = null
                }
            }
            else -> {
                FramedPlatformField(passphrase, stringResource(R.string.common_new_passphrase), isPassphrase = true)
                Spacer(Modifier.height(14.dp))
                PrimaryButton(stringResource(R.string.devices_scan_the_code)) { held = passphrase.take() }
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.common_back), onClick = onCancel)
            }
        }
    }
}
