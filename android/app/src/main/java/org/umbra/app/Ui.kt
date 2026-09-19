package org.umbra.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import android.text.InputType
import android.text.TextUtils
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView

@Composable
fun UmbraApp() {
    MaterialTheme(colorScheme = darkColorScheme()) {
        Surface(Modifier.fillMaxSize()) {
            Box(Modifier.safeDrawingPadding().imePadding()) {
                var shown by remember { mutableStateOf<Conversation?>(null) }
                // A conversation of a run that ended has no contact.
                val current = shown?.takeIf { it in Core.conversations }
                when {
                    Core.phase != Core.Phase.Open -> UnlockScreen()
                    current != null -> ChatScreen(current, onBack = { shown = null })
                    else -> HomeScreen(onOpen = { shown = it })
                }
            }
        }
    }
}

/**
 * A text field of the platform, and no composable field, because a
 * composable field holds its text in a `String`. The caller gets the text as
 * a `CharArray` that it overwrites, and the field is empty after that.
 */
@Composable
private fun PlatformField(
    hint: String,
    isPassphrase: Boolean,
    actionLabel: String,
    enabled: Boolean = true,
    onSubmit: (CharArray) -> Unit,
) {
    var field by remember { mutableStateOf<EditText?>(null) }
    val textColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val hintColor = MaterialTheme.colorScheme.onSurfaceVariant.toArgb()
    Row(verticalAlignment = Alignment.CenterVertically) {
        AndroidView(
            modifier = Modifier.weight(1f),
            factory = { context ->
                EditText(context).apply {
                    this.hint = hint
                    setTextColor(textColor)
                    setHintTextColor(hintColor)
                    // IMP-057: the input method learns nothing from this field.
                    imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
                        EditorInfo.IME_FLAG_NO_EXTRACT_UI
                    inputType = if (isPassphrase) {
                        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    } else {
                        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                            InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                    }
                    field = this
                }
            },
        )
        Button(
            enabled = enabled,
            modifier = Modifier.padding(start = 8.dp),
            onClick = {
                val editable = field?.editableText ?: return@Button
                if (editable.isEmpty()) return@Button
                val chars = CharArray(editable.length)
                TextUtils.getChars(editable, 0, editable.length, chars, 0)
                editable.clear()
                onSubmit(chars)
            },
        ) { Text(actionLabel) }
    }
}

/** The text of a message, which goes from a `CharArray` to the platform view. */
@Composable
private fun PlatformText(chars: CharArray, color: Color) {
    val argb = color.toArgb()
    AndroidView(
        factory = { context -> TextView(context).apply { textSize = 16f } },
        update = { view ->
            view.setTextColor(argb)
            view.setText(chars, 0, chars.size)
        },
    )
}

@Composable
private fun UnlockScreen() {
    val context = LocalContext.current
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("UMBRA", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "The passphrase opens the store of this device. The first launch sets it.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(24.dp))
        if (Core.phase == Core.Phase.Opening) {
            CircularProgressIndicator()
        } else {
            PlatformField(hint = "Passphrase", isPassphrase = true, actionLabel = "Open") {
                Core.open(context, it)
            }
        }
        Core.fault?.let {
            Spacer(Modifier.height(16.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        BuildNetwork.Panel()
    }
}

@Composable
private fun HomeScreen(onOpen: (Conversation) -> Unit) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (Core.online) "Online" else "No circuit",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium,
            )
            if (!Core.online) {
                TextButton(onClick = { Core.connect(context) }) { Text("Connect") }
            }
            TextButton(onClick = { Core.lock() }) { Text("Lock") }
        }
        Core.fault?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Spacer(Modifier.height(12.dp))
        InvitePanel()
        Spacer(Modifier.height(12.dp))
        HorizontalDivider()
        Text(
            "Conversations",
            modifier = Modifier.padding(vertical = 12.dp),
            style = MaterialTheme.typography.titleSmall,
        )
        if (Core.conversations.isEmpty()) {
            Text(
                "No contact yet. Make an invitation, or accept one.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        LazyColumn {
            items(Core.conversations, key = { it.label }) { conversation ->
                Text(
                    "Contact ${conversation.label}",
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onOpen(conversation) }
                        .padding(vertical = 14.dp),
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun InvitePanel() {
    val context = LocalContext.current
    var pasted by remember { mutableStateOf("") }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(enabled = Core.online, onClick = { Core.invite() }) { Text("Invite") }
        Core.invitation?.let { link ->
            OutlinedButton(onClick = { copySensitive(context, link) }) {
                Text("Copy the link")
            }
        }
    }
    Core.invitation?.let { link ->
        Text(
            "This link works one time, for 14 days.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
        Text(
            link,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
    }
    Spacer(Modifier.height(12.dp))
    // An invitation is no message text, thus a composable field holds it.
    OutlinedTextField(
        value = pasted,
        onValueChange = { pasted = it },
        label = { Text("The link of a contact") },
        // The input method changes no character of the pasted value.
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            autoCorrectEnabled = false,
        ),
        maxLines = 3,
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        enabled = Core.online && pasted.isNotBlank(),
        modifier = Modifier.padding(top = 8.dp),
        onClick = {
            Core.accept(pasted)
            pasted = ""
        },
    ) { Text("Accept") }
}

@Composable
private fun ChatScreen(conversation: Conversation, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    var lines by remember { mutableStateOf(emptyList<Line>()) }
    val listState = rememberLazyListState()
    LaunchedEffect(conversation, Core.revision) {
        Core.load(conversation) { lines = it }
    }
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Text("Contact ${conversation.label}", style = MaterialTheme.typography.titleMedium)
        }
        HorizontalDivider()
        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp),
        ) {
            items(lines) { line -> Bubble(line) }
        }
        Box(Modifier.padding(8.dp)) {
            PlatformField(
                hint = "Message",
                isPassphrase = false,
                actionLabel = "Send",
                // With no network the record waits in the store.
            ) { Core.send(conversation, it) }
        }
    }
}

@Composable
private fun Bubble(line: Line) {
    val outgoing = line.info.outgoing
    val colors = MaterialTheme.colorScheme
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .background(
                    if (outgoing) colors.primaryContainer else colors.surfaceVariant,
                    RoundedCornerShape(14.dp),
                )
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            PlatformText(
                line.text,
                if (outgoing) colors.onPrimaryContainer else colors.onSurfaceVariant,
            )
            if (outgoing) {
                Text(deliveryLabel(line.info.delivery), style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

/** The closed list of Part 15 §15.9.1. */
private fun deliveryLabel(state: UByte): String = when (state.toInt()) {
    0 -> "Queued"
    1 -> "Accepted by the relay"
    2 -> "Delivered"
    3 -> "Read"
    else -> "Failed"
}

/** IMP-056: the clipboard preview of the platform hides a sensitive clip. */
private fun copySensitive(context: Context, text: String) {
    val clip = ClipData.newPlainText("UMBRA invitation", text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}
