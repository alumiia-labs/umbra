package org.umbra.app

import android.app.Activity
import android.content.Context
import android.util.TypedValue
import android.view.Gravity
import android.view.WindowManager
import android.widget.TextView
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
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
            .edit().putBoolean(SEEN, true).apply()
        isHiddenNow = true
    }
}

/** The line that asks for the recovery code. It never blocks a view (`IDN-051`). */
@Composable
fun RecoveryPromptLine(push: (Screen) -> Unit) {
    val context = LocalContext.current
    // The code of a linked device is the code of the device that owns the
    // backup, and the prompt shows there.
    if (!RecoveryPrompt.isDue(context) || !Core.ownsChannels) return
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .background(Palette.Container, RoundedCornerShape(16.dp))
            .clickable(role = Role.Button) { push(Screen.RecoveryCode) }
            .padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon("key", size = 18.dp, tint = Palette.Action)
        Spacer(Modifier.width(12.dp))
        Text("Write down your recovery code", Modifier.weight(1f))
        Box(
            Modifier
                .size(36.dp)
                .clip(CircleShape)
                .press(role = Role.Button, label = "Dismiss") { RecoveryPrompt.dismiss(context) },
            contentAlignment = Alignment.Center,
        ) { FaIcon("xmark", label = "Dismiss", size = 14.dp, tint = Palette.TextSecondary) }
    }
}

/**
 * The recovery code as the 87 digits of Part 4 §4.7.7. The digits stay in
 * a `CharArray` that the view wipes when it leaves, the window takes no
 * screenshot while it shows, and no copy goes to the clipboard.
 */
@Composable
fun RecoveryCodeScreen(onBack: () -> Unit) {
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
        BackBar("Recovery code", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            val shown = digits
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(24.dp))
                    .border(1.dp, Palette.Divider, RoundedCornerShape(24.dp))
                    .padding(vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (shown != null) DigitRows(shown)
            }
            Spacer(Modifier.height(16.dp))
            Note(backupLine(context, Core.lastBackupAt))
        }
    }
}

/** The time of the last backup, which is a fact that the user cannot know. */
private fun backupLine(context: Context, atSeconds: Long?): String =
    if (atSeconds == null) {
        "No backup yet."
    } else {
        "Last backup: ${timeLabel(context, atSeconds * 1_000)}."
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
    val isRunning = Core.restoreNote != null
    Column(Modifier.fillMaxWidth()) {
        if (isRunning) {
            Text(Core.restoreNote.orEmpty(), color = Palette.TextSecondary)
            return@Column
        }
        FramedPlatformField(code, "Recovery code", isPassphrase = false)
        Spacer(Modifier.height(12.dp))
        FramedPlatformField(passphrase, "New passphrase", isPassphrase = true)
        Spacer(Modifier.height(14.dp))
        PrimaryButton("Restore") {
            val digits = code.take()
            val phrase = passphrase.take()
            if (digits != null && phrase != null) {
                Core.restore(context, phrase, digits)
            } else {
                digits?.fill('\u0000')
                phrase?.fill('\u0000')
            }
        }
        Spacer(Modifier.height(8.dp))
        SecondaryButton("Back", onClick = onCancel)
    }
}
