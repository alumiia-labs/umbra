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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import uniffi.umbra_ffi.Device
import uniffi.umbra_ffi.LinkStatus

/**
 * A fork of the roster (Part 7 §7.7): the view names the device that signed
 * the other epoch (`DEV-170`), and it selects nothing in silence (`DEV-171`).
 */
@Composable
fun RosterForkPrompt() {
    val fork = Core.rosterForks.firstOrNull() ?: return
    val name = fork.label.ifEmpty { "A removed device" }
    Column(
        Modifier
            .fillMaxWidth()
            .background(Palette.Incoming)
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Text(
            when (fork.kind.toInt()) {
                1 -> "$name signed two versions of your device list"
                2 -> "$name removed a different device than another of your devices did"
                else -> "$name holds a different device list than this device"
            },
        )
        Text(
            "If you did not make this change, remove $name and reset your identity.",
            style = MaterialTheme.typography.labelMedium,
            color = Palette.TextSecondary,
            modifier = Modifier.subline(),
        )
        Spacer(Modifier.height(8.dp))
        InlineButton("Dismiss") { Core.dismissRosterFork(fork) }
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
        Text(
            if (count == 1) {
                "Your other devices deleted 1 message that this restore brought back"
            } else {
                "Your other devices deleted $count messages that this restore brought back"
            },
        )
        Spacer(Modifier.height(8.dp))
        Row {
            InlineButton("Delete") { Core.applyHeldDeletions(apply = true) }
            Spacer(Modifier.width(12.dp))
            InlineButton("Keep") { Core.applyHeldDeletions(apply = false) }
        }
    }
}

/** The devices of the set (Part 7), and the start of a link. */
@Composable
fun DevicesScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    LaunchedEffect(Unit) { Core.readDevices() }
    var removing by remember { mutableStateOf<Device?>(null) }
    removing?.let { device ->
        // DEV-119, DEV-120: the deletions of that device since the last
        // change of the set, and what brings them back.
        var deletions by remember(device) { mutableStateOf(0) }
        LaunchedEffect(device) { Core.deletionsFrom(device.deviceId) { deletions = it } }
        val removed = when (deletions) {
            0 -> ""
            1 -> " It deleted 1 message here since the last change of your devices." +
                " A restore from a backup made before now brings it back."
            else -> " It deleted $deletions messages here since the last change of your devices." +
                " A restore from a backup made before now brings them back."
        }
        // Part 7 DEV-137 and DEV-138: the two limits of a removal, in
        // those words.
        ActionSheet(
            title = "Remove ${device.label.ifEmpty { "this device" }}?",
            entries = listOf(
                RowEntry("trash-can", "Remove") { Core.removeDevice(device.deviceId) },
            ),
            note = UiText.get(R.string.umbra_ui_dev_137) +
                " For a device in hostile hands, reset the identity in the settings." + removed,
            onDismiss = { removing = null },
        )
    }
    Column(Modifier.fillMaxSize()) {
        BackBar("Linked devices", onBack = onBack)
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
                        Text(device.label.ifEmpty { "Device" })
                        if (device.isSelf) {
                            Text(
                                "This device",
                                style = MaterialTheme.typography.bodySmall,
                                color = Palette.TextSecondary,
                                modifier = Modifier.subline(),
                            )
                        }
                    }
                }
            }
            Column(Modifier.padding(20.dp)) {
                if (Core.ownsChannels) {
                    PrimaryButton("Link a device") { push(Screen.LinkDevice) }
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
        BackBar("Link a device", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            when (val status = Core.linkStatus) {
                is LinkStatus.Ticket -> {
                    Headline("Scan this code on the new device")
                    Spacer(Modifier.height(20.dp))
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        QrCode(status.text, "The link as a QR code")
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
                    SecondaryButton("Copy the code") { copySensitive(context, status.text, "UMBRA link") }
                    Spacer(Modifier.height(12.dp))
                    Note("Works once. Expires in 2 minutes.")
                }
                is LinkStatus.Code -> {
                    Headline("Do the codes match?")
                    Spacer(Modifier.height(20.dp))
                    LinkCode(status.code)
                    Spacer(Modifier.height(24.dp))
                    PrimaryButton("Yes, the codes match") { Core.confirmLink() }
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton("They don't match") {
                        Core.cancelLink()
                        onBack()
                    }
                }
                is LinkStatus.Sending, is LinkStatus.Waiting -> {
                    Headline("Copying to the new device")
                    Spacer(Modifier.height(20.dp))
                    Progress()
                }
                is LinkStatus.Linked -> {
                    HeroIcon("check")
                    Spacer(Modifier.height(20.dp))
                    Headline("Linked")
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Done", onClick = onBack)
                }
                is LinkStatus.Expired, is LinkStatus.Failed -> {
                    HeroIcon("triangle-exclamation")
                    Spacer(Modifier.height(20.dp))
                    Headline(if (status is LinkStatus.Expired) "The code ran out." else "The link failed.")
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Try again") { attempt++ }
                }
                else -> {
                    Headline("Link a device")
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
                    "Confirm on your other device.",
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
                    label = { Text("Code of the link") },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false,
                    ),
                    maxLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                PrimaryButton("Link", enabled = pasted.isNotBlank()) {
                    val phrase = held ?: return@PrimaryButton
                    held = null
                    Core.join(context, phrase, pasted.trim())
                }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Back") { isPasting = false }
            }
            held != null -> {
                Scanner { text ->
                    val phrase = held ?: return@Scanner
                    held = null
                    Core.join(context, phrase, text)
                }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Paste the code instead") { isPasting = true }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Back") {
                    held?.fill('\u0000')
                    held = null
                }
            }
            else -> {
                FramedPlatformField(passphrase, "New passphrase", isPassphrase = true)
                Spacer(Modifier.height(14.dp))
                PrimaryButton("Scan the code") { held = passphrase.take() }
                Spacer(Modifier.height(8.dp))
                SecondaryButton("Back", onClick = onCancel)
            }
        }
    }
}
