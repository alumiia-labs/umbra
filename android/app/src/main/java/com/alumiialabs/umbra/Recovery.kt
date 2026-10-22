package com.alumiialabs.umbra

import android.app.Activity
import android.content.Context
import android.util.TypedValue
import android.view.Gravity
import android.view.WindowManager
import android.widget.TextView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView

/**
 * The prompts of Part 4 §4.7.6: the user can dismiss the one that asks for
 * the recovery code, and after two dismissals it comes no more (`IDN-052`,
 * `IDN-053`). A user that looked at the code gets none.
 */
object RecoveryPrompt {
    private const val PREFERENCES = "umbra-recovery"
    private const val DISMISSED = "dismissed"
    private const val SEEN = "seen"

    /** Whether this launch dismissed the prompt. */
    private var isHiddenNow by mutableStateOf(false)

    fun isDue(context: Context): Boolean {
        if (isHiddenNow) return false

        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        return !preferences.getBoolean(SEEN, false) && preferences.getInt(DISMISSED, 0) < 2
    }

    fun dismiss(context: Context) {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        preferences.edit().putInt(DISMISSED, preferences.getInt(DISMISSED, 0) + 1).apply()
        isHiddenNow = true
    }

    fun seen(context: Context) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(SEEN, true)
            .apply()
        isHiddenNow = true
    }
}

/**
 * The recovery code as the 87 digits of Part 4 §4.7.7. The digits stay in
 * a `CharArray` that the view wipes when it leaves, the window takes no
 * screenshot while it shows, and no copy goes to the clipboard.
 */
@Composable
fun RecoveryCodeScreen(onBack: () -> Unit, push: (Screen) -> Unit = {}) {
    val context = LocalContext.current
    var digits by remember { mutableStateOf<CharArray?>(null) }

    LaunchedEffect(Unit) {
        Core.recoveryCode { digits = it }
        RecoveryPrompt.seen(context)
    }
    DisposableEffect(Unit) {
        val window = (context as? Activity)?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            digits?.fill('\u0000')
        }
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_recovery_code), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            val shown = digits
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(24.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(24.dp))
                    .padding(vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (shown != null) DigitRows(shown)
            }

            Spacer(Modifier.height(16.dp))
            Note(backupLine(context, Core.lastBackupAt))
            Spacer(Modifier.height(8.dp))
            // IMP-050: the backup of the platform holds nothing of UMBRA.
            Note(UiText.get(R.string.umbra_ui_imp_050))

            Spacer(Modifier.height(16.dp))
            EntryRow(
                RowEntry("user-group", stringResource(R.string.recovery_with_contacts)) { push(Screen.SocialRecovery) },
            )
            EntryRow(RowEntry("key", stringResource(R.string.recovery_root_seed)) { push(Screen.RootSeed) })
        }
    }
}

/**
 * Digits that a view shows once, with no screenshot and no clipboard, and
 * that it wipes when it leaves: the user half, or a share of a contact.
 */
@Composable
fun SecretDigitsScreen(title: String, note: String, onBack: () -> Unit, load: ((CharArray) -> Unit) -> Unit) {
    val context = LocalContext.current
    var digits by remember { mutableStateOf<CharArray?>(null) }
    LaunchedEffect(Unit) { load { digits = it } }
    DisposableEffect(Unit) {
        val window = (context as? Activity)?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            digits?.fill('\u0000')
        }
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(title, onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Palette.Raised, RoundedCornerShape(24.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(24.dp))
                    .padding(vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                digits?.let { DigitRows(it) }
            }
            Spacer(Modifier.height(16.dp))
            Note(note)
        }
    }
}

/**
 * Social recovery of Part 4 §4.7.3: one share of the social half for each
 * chosen contact. The view states which half each holder takes, and that
 * the shares alone recover nothing (`IDN-087`, `IDN-088`).
 */
@Composable
fun SocialRecoveryScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    val contacts = Core.chats.filter { !it.isGroup }
    val chosen = remember { mutableStateListOf<List<Byte>>() }
    var threshold by remember { mutableStateOf(3) }
    var given by remember { mutableStateOf(emptyList<uniffi.umbra_ffi.FfiGivenShare>()) }
    var isSent by remember { mutableStateOf(false) }
    LaunchedEffect(isSent) { Core.sharesGiven { given = it } }

    val count = chosen.size
    val needed = threshold.coerceIn(2, maxOf(2, count))

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.recovery_with_contacts), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(8.dp))
            // IDN-087, IDN-088: which half each holder takes, and what the
            // pieces do alone.
            Note(
                UiText.get(R.string.umbra_ui_idn_088) + " " +
                    pluralStringResource(R.plurals.recovery_pieces_restore, needed, needed) + " " +
                    UiText.get(R.string.umbra_ui_idn_087),
            )

            if (given.isNotEmpty()) {
                val aContact = stringResource(R.string.common_a_contact)
                val names = given.map { share ->
                    contacts.firstOrNull { it.conversation.id.contentEquals(share.conversation) }?.title ?: aContact
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    stringResource(
                        R.string.recovery_held_by,
                        names.joinToString(", "),
                        given.first().threshold.toInt(),
                        given.first().count.toInt(),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                    modifier = Modifier.subline(),
                )
            }

            Spacer(Modifier.height(8.dp))
            for (chat in contacts) {
                val key = chat.conversation.id.toList()
                ToggleRow(chat.title, key in chosen) { on ->
                    if (on) chosen.add(key) else chosen.remove(key)
                }
                HorizontalDivider(color = Palette.Divider)
            }

            if (count >= 2) {
                Text(
                    stringResource(R.string.recovery_pieces_needed),
                    style = MaterialTheme.typography.labelLarge,
                    color = Palette.TextSecondary,
                    modifier = Modifier.padding(top = 16.dp, bottom = 4.dp).subline(),
                )
                for (k in 2..count) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .pressShadeInColumn()
                            .press(role = Role.RadioButton) { threshold = k }
                            .padding(horizontal = PressInset, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioMark(isChosen = needed == k)
                        Spacer(Modifier.width(14.dp))
                        Text(stringResource(R.string.recovery_k_of_n, k, count))
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.recovery_send_pieces), enabled = count >= 2) {
                val holders = contacts.filter { it.conversation.id.toList() in chosen }.map { it.conversation }
                Core.splitSocial(holders, needed) { isSent = !isSent }
                chosen.clear()
            }
            Spacer(Modifier.height(8.dp))
            SecondaryButton(stringResource(R.string.recovery_show_user_half)) { push(Screen.UserHalf) }
            Spacer(Modifier.height(20.dp))
        }
    }
}

/** The time of the last backup, which is a fact that the user cannot know. */
private fun backupLine(context: Context, atSeconds: Long?): String =
    if (atSeconds == null) {
        UiText.get(R.string.recovery_no_backup)
    } else {
        UiText.get(R.string.recovery_last_backup, timeLabel(context, atSeconds * 1_000))
    }

/**
 * The groups of five in rows of three. The breaks go into the array itself,
 * and the view shows that array, thus the wipe of the screen clears it.
 */
@Composable
private fun DigitRows(digits: CharArray) {
    val ink = Palette.Text.toArgb()

    AndroidView(
        factory = { context ->
            TextView(context).apply {
                styleAsApp(this, mono = true)
                gravity = Gravity.CENTER
                setLineSpacing(0f, 1.5f)
            }
        },
        update = { view ->
            view.setTextColor(ink)
            view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)

            var group = 0
            for (at in digits.indices) {
                if (digits[at] == ' ' || digits[at] == '\n') {
                    group++
                    digits[at] = if (group % 3 == 0) '\n' else ' '
                }
            }

            view.setText(digits, 0, digits.size)
        },
    )
}

/**
 * The restore of a first launch (Part 4 §4.7.2): a new passphrase for this
 * device and the recovery code. A restore that finds no identity stays
 * here and shows no message list (`IDN-156`).
 */
@Composable
fun RestoreForm(onCancel: () -> Unit) {
    val context = LocalContext.current
    val passphrase = rememberPlatformField()
    val code = rememberPlatformField()

    // Part 4 §4.7.3: the user half and the shares of contacts, in the place
    // of the whole code.
    var withShares by remember { mutableStateOf(false) }
    var shareCount by remember { mutableStateOf(3) }
    val shares = remember { List(8) { PlatformFieldState() } }
    val isRunning = Core.restoreNote != null

    Column(Modifier.fillMaxWidth()) {
        if (isRunning) {
            Text(Core.restoreNote.orEmpty(), color = Palette.TextSecondary)
            return@Column
        }

        FramedPlatformField(
            code,
            stringResource(if (withShares) R.string.recovery_user_half else R.string.common_recovery_code),
            isPassphrase = false,
        )
        if (withShares) {
            for (index in 0 until shareCount) {
                Spacer(Modifier.height(8.dp))
                FramedPlatformField(
                    shares[index],
                    stringResource(R.string.recovery_share_number, index + 1),
                    isPassphrase = false,
                )
            }
            if (shareCount < shares.size) {
                InlineButton(stringResource(R.string.recovery_add_share)) { shareCount++ }
            }
        }

        Spacer(Modifier.height(12.dp))
        FramedPlatformField(passphrase, stringResource(R.string.common_new_passphrase), isPassphrase = true)
        Spacer(Modifier.height(14.dp))
        PrimaryButton(stringResource(R.string.recovery_restore)) {
            val digits = code.take()
            val phrase = passphrase.take()
            val taken = if (withShares) shares.take(shareCount).mapNotNull { it.take() } else emptyList()

            if (digits != null && phrase != null) {
                Core.restore(context, phrase, digits, taken)
            } else {
                digits?.fill('\u0000')
                phrase?.fill('\u0000')
                taken.forEach { it.fill('\u0000') }
            }
        }

        Spacer(Modifier.height(8.dp))
        SecondaryButton(
            stringResource(if (withShares) R.string.recovery_use_recovery_code else R.string.recovery_use_shares),
        ) {
            withShares = !withShares
        }
        Spacer(Modifier.height(8.dp))
        SecondaryButton(stringResource(R.string.common_back), onClick = onCancel)
    }
}

/**
 * The full identity reset of Part 7 §7.7.1. It is visible and slow on
 * purpose: the screen states what changes, and a second sheet asks again.
 */
@Composable
fun ResetIdentityScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var isAsking by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<String?>(null) }
    var fault by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.common_reset_identity), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Text(stringResource(R.string.recovery_reset_intro))
            Spacer(Modifier.height(12.dp))
            val changes = listOf(
                stringResource(R.string.recovery_reset_new_key),
                stringResource(R.string.recovery_reset_groups),
                stringResource(R.string.recovery_reset_links_end),
                stringResource(R.string.recovery_reset_messages_stay),
            )
            for (line in changes) {
                Text("· $line", color = Palette.TextSecondary, modifier = Modifier.padding(bottom = 6.dp))
            }

            Spacer(Modifier.height(16.dp))
            result?.let {
                Note(it)
                return@Column
            }

            fault?.let {
                Note(it, isError = true)
                Spacer(Modifier.height(12.dp))
            }
            if (Core.devices.size > 1) {
                // DEV-307: the other devices leave the set first.
                Note(stringResource(R.string.recovery_remove_other_devices))
            } else {
                DangerButton(stringResource(R.string.common_reset_identity)) { isAsking = true }
            }
        }
    }

    if (isAsking) {
        ActionSheet(
            stringResource(R.string.recovery_reset_question),
            listOf(
                RowEntry("rotate", stringResource(R.string.common_reset_identity)) {
                    Core.resetIdentity(context) { done ->
                        if (done == null) {
                            fault = UiText.get(R.string.recovery_remove_other_devices)
                        } else {
                            result = done
                        }
                    }
                },
            ),
            note = stringResource(R.string.recovery_cannot_undo),
            onDismiss = { isAsking = false },
        )
    }
}
