package org.umbra.app

import android.graphics.Typeface
import android.text.InputType
import android.text.TextUtils
import android.util.TypedValue
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.layout
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.PlatformTextStyle
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.snap
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.semantics
import android.view.inputmethod.InputMethodManager

/**
 * The holder of a text field of the platform. A composable field holds its
 * text in a `String`, and message text and a passphrase MUST NOT sit in one
 * (`IMP-037`). The caller takes the text as a `CharArray` that it overwrites,
 * and the field is empty after that.
 */
class PlatformFieldState {
    internal var view: EditText? = null

    /** Puts the cursor into the field and opens the keyboard. */
    fun focus() {
        val field = view ?: return
        field.requestFocus()
        field.context.getSystemService(InputMethodManager::class.java)
            .showSoftInput(field, InputMethodManager.SHOW_IMPLICIT)
    }

    /** The text, or null for an empty field. The field is empty after the call. */
    fun take(): CharArray? {
        val editable = view?.editableText ?: return null
        if (editable.isEmpty()) return null
        val chars = CharArray(editable.length)
        TextUtils.getChars(editable, 0, editable.length, chars, 0)
        editable.clear()
        return chars
    }
}

@Composable
fun rememberPlatformField() = remember { PlatformFieldState() }

/** The view of a [PlatformFieldState], with no frame of its own. */
@Composable
fun PlatformInput(
    state: PlatformFieldState,
    hint: String,
    isPassphrase: Boolean,
    modifier: Modifier = Modifier,
    maxLines: Int = 1,
) {
    val textColor = Palette.Text.toArgb()
    val hintColor = Palette.TextSecondary.toArgb()
    AndroidView(
        modifier = modifier,
        factory = { context ->
            EditText(context).apply {
                this.hint = hint
                background = null
                setPadding(0, 0, 0, 0)
                setTextColor(textColor)
                setHintTextColor(hintColor)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                // IMP-057: the input method learns nothing from this field.
                imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
                    EditorInfo.IME_FLAG_NO_EXTRACT_UI
                inputType = if (isPassphrase) {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                } else {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                        InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                }
                this.maxLines = maxLines
                state.view = this
            }
        },
    )
}

/** A field of the platform inside the outlined frame of the mockups. */
@Composable
fun FramedPlatformField(state: PlatformFieldState, label: String, isPassphrase: Boolean) {
    Column(
        Modifier
            .fillMaxWidth()
            .border(1.dp, Palette.Outline, RoundedCornerShape(10.dp))
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = Palette.TextSecondary)
        PlatformInput(state, hint = "", isPassphrase = isPassphrase, modifier = Modifier.fillMaxWidth())
    }
}

/** Message text, which goes from a `CharArray` to a view of the platform. */
@Composable
fun PlatformText(
    chars: CharArray,
    color: Color,
    modifier: Modifier = Modifier,
    sizeSp: Float = 16f,
    maxLines: Int = Int.MAX_VALUE,
    prefix: String = "",
) {
    val argb = color.toArgb()
    AndroidView(
        modifier = modifier,
        factory = { context ->
            TextView(context).apply {
                typeface = Typeface.DEFAULT
                ellipsize = TextUtils.TruncateAt.END
            }
        },
        update = { view ->
            view.setTextColor(argb)
            view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
            view.maxLines = maxLines
            if (prefix.isEmpty()) {
                view.setText(chars, 0, chars.size)
            } else {
                // The prefix is a word of the interface. The message text
                // joins it in a buffer, and in no `String`. The view keeps that
                // array and makes no copy, thus a wipe here shows an empty line.
                val joined = CharArray(prefix.length + chars.size)
                prefix.toCharArray(joined, 0, 0, prefix.length)
                chars.copyInto(joined, prefix.length)
                view.setText(joined, 0, joined.size)
            }
        },
    )
}

/**
 * The inset of a small line under a larger one: a subtitle under a title, a
 * preview under a name, the time under a message. A large letter has more
 * side bearing than a small one, thus the small line looks outdented with no
 * inset.
 */
fun Modifier.subline(): Modifier = padding(horizontal = 3.dp)

/**
 * The press shade of each row: round, with room around its content, as the
 * press shade of a tab is. The content of a row starts `PressInset` inside
 * the shade.
 */
val PressShape = RoundedCornerShape(16.dp)
val PressInset = 12.dp

/**
 * The press of a row or a tab, with a shade that the app draws itself. The
 * ripple of the platform does not draw in a row that holds a platform text
 * view, thus one row of the app had a shade and the next had none. The shade
 * comes at once and fades, thus a short tap shows it also.
 */
@Composable
fun Modifier.press(role: Role? = null, label: String? = null, onClick: () -> Unit): Modifier {
    val source = remember { MutableInteractionSource() }
    return pressShade(source).clickable(
        interactionSource = source,
        indication = null,
        role = role,
        onClickLabel = label,
        onClick = onClick,
    )
}

/** The same press for a switch. */
@Composable
fun Modifier.pressToggle(isOn: Boolean, onChange: (Boolean) -> Unit): Modifier {
    val source = remember { MutableInteractionSource() }
    return pressShade(source).toggleable(
        value = isOn,
        interactionSource = source,
        indication = null,
        role = Role.Switch,
        onValueChange = onChange,
    )
}

@Composable
private fun Modifier.pressShade(source: MutableInteractionSource): Modifier {
    val isPressed by source.collectIsPressedAsState()
    val shade by animateColorAsState(
        if (isPressed) Palette.Pressed else Color.Transparent,
        if (isPressed) snap() else tween(durationMillis = 260),
        label = "press shade",
    )
    // The shade lies above the content, as the press shade of a tab does.
    return drawWithContent {
        drawContent()
        drawRect(shade)
    }
}

/**
 * The shade of a row in a column with side padding. The shade reaches past
 * the column by `PressInset` on each side, thus the text of the row stays in
 * line with the text above it. The caller adds [press] and then
 * `padding(horizontal = PressInset)`.
 */
fun Modifier.pressShadeInColumn(): Modifier = layout { measurable, constraints ->
    val extra = PressInset.roundToPx() * 2
    val placeable = measurable.measure(
        constraints.copy(
            minWidth = constraints.minWidth + extra,
            maxWidth = constraints.maxWidth + extra,
        ),
    )
    layout(placeable.width - extra, placeable.height) { placeable.place(-PressInset.roundToPx(), 0) }
}.clip(PressShape)

/**
 * The shade of a row that spans the screen. The caller adds [press] and
 * then `padding(horizontal = PressInset)`, which puts the content 20 dp from
 * the edge.
 */
fun Modifier.pressShadeInList(): Modifier = padding(horizontal = 8.dp).clip(PressShape)

@Composable
fun PrimaryButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
    ) { Text(label, fontWeight = FontWeight.SemiBold) }
}

@Composable
fun SecondaryButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        // The mockups give this button the green of an action and a line
        // that the eye finds on the warm ground.
        colors = ButtonDefaults.outlinedButtonColors(contentColor = Palette.Action),
        border = BorderStroke(1.dp, Palette.Outline),
    ) { Text(label, fontWeight = FontWeight.SemiBold) }
}

/** The sage note with an icon, for a fact that the user needs at this point. */
@Composable
fun Note(text: String, isError: Boolean = false) {
    val ground = if (isError) Color(0xFFF6E3E1) else Palette.Incoming
    val ink = if (isError) Palette.Error else Palette.Text
    Row(
        Modifier
            .fillMaxWidth()
            .background(ground, RoundedCornerShape(12.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        FaIcon(if (isError) "triangle-exclamation" else "circle-info", size = 16.dp, tint = ink)
        Text(text, style = MaterialTheme.typography.bodySmall, color = ink)
    }
}

/** The large rounded icon above the headline of a full view, in the middle of its row. */
@Composable
fun HeroIcon(name: String) {
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Box(
            Modifier.size(84.dp).background(Palette.Container, RoundedCornerShape(24.dp)),
            contentAlignment = Alignment.Center,
        ) { FaIcon(name, size = 30.dp, tint = Palette.Action) }
    }
}

/** A letter on a pastel ground. The ground comes from the conversation. */
@Composable
fun Avatar(chat: Chat, size: Int = 44) {
    val ground = Palette.Avatars[(chat.conversation.hashCode() and 0x7FFFFFFF) % Palette.Avatars.size]
    val letter = chat.name.firstOrNull()?.uppercase() ?: "?"
    Box(
        Modifier.size(size.dp).clip(CircleShape).background(ground),
        contentAlignment = Alignment.Center,
    ) {
        // The letter takes its size from the circle and not from the font
        // scale of the system. Its line box is the glyph alone: the line
        // height of the theme is taller than a small circle, and the letter
        // then hangs at the bottom.
        val letterSize = with(LocalDensity.current) { (size * 0.46f).dp.toSp() }
        Text(
            letter,
            color = Palette.Text,
            textAlign = TextAlign.Center,
            style = TextStyle(
                fontSize = letterSize,
                lineHeight = letterSize,
                platformStyle = PlatformTextStyle(includeFontPadding = false),
                lineHeightStyle = LineHeightStyle(
                    alignment = LineHeightStyle.Alignment.Center,
                    trim = LineHeightStyle.Trim.Both,
                ),
            ),
        )
    }
}

/** The bar of a view under the tabs: the word mark and the lock. */
@Composable
fun BrandBar() {
    Row(
        Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "UMBRA",
            letterSpacing = 4.sp,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f),
        )
        IconAction("lock", "Lock now") { Core.lock() }
    }
}

/** The bar of a view above the tabs: a way back and a title. */
@Composable
fun BackBar(
    title: String,
    subtitle: String? = null,
    onBack: () -> Unit,
    isVerified: Boolean = false,
    onTitle: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
) {
    Row(
        Modifier.fillMaxWidth().padding(start = 4.dp, end = 4.dp, top = 8.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconAction("arrow-left", "Back", onBack)
        Spacer(Modifier.width(4.dp))
        val titleArea = Modifier.weight(1f).clip(RoundedCornerShape(12.dp))
        Column(if (onTitle == null) titleArea else titleArea.clickable(onClick = onTitle)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (isVerified) {
                    Spacer(Modifier.width(8.dp))
                    FaIcon("shield-check", label = "Verified", size = 16.dp, tint = Palette.Action)
                }
            }
            subtitle?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.labelMedium,
                    color = Palette.TextSecondary,
                    modifier = Modifier.subline(),
                )
            }
        }
        actions()
    }
}

/** One entry of a sheet or of a detail view: what it does, and where it leads. */
class RowEntry(
    val icon: String,
    val title: String,
    val detail: String? = null,
    val onClick: () -> Unit,
)

/**
 * A sheet from the bottom with a handle, a title, and one row for each
 * entry, as `design/mockups/light` has it. The mockups use no popup menu.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActionSheet(title: String, entries: List<RowEntry>, onDismiss: () -> Unit) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = Palette.Surface,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        dragHandle = {
            Box(
                Modifier
                    .padding(top = 12.dp, bottom = 8.dp)
                    .size(width = 32.dp, height = 4.dp)
                    .background(Palette.Outline, CircleShape),
            )
        },
    ) {
        Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 24.dp)) {
            Text(title, style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(12.dp))
            entries.forEachIndexed { index, entry ->
                if (index > 0) HorizontalDivider(color = Palette.Divider)
                EntryRow(entry, afterClick = onDismiss)
            }
        }
    }
}

/**
 * Content with a press area above it. A view of the platform inside the
 * content, such as message text, takes a touch before a composable does,
 * thus the area lies on top. For a screen reader the content and the
 * actions are one node: the area itself says nothing.
 */
@Composable
fun PressOver(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    longLabel: String? = null,
    onLongClick: (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    Box(
        modifier.semantics(mergeDescendants = true) {
            if (onClick != null) {
                role = Role.Button
                onClick(null) { onClick(); true }
            }
            if (onLongClick != null) onLongClick(longLabel) { onLongClick(); true }
        },
    ) {
        content()
        val area = Modifier.matchParentSize().clearAndSetSemantics {}
        Box(
            when {
                onLongClick != null -> area.pressLong(onClick ?: {}, onLongClick)
                onClick != null -> area.press(onClick = onClick)
                else -> area
            },
        )
    }
}

/**
 * The press of a thing that also takes a long press, with the shade of
 * [press].
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun Modifier.pressLong(onClick: () -> Unit, onLongClick: () -> Unit): Modifier {
    val source = remember { MutableInteractionSource() }
    return pressShade(source).combinedClickable(
        interactionSource = source,
        indication = null,
        onLongClick = onLongClick,
        onClick = onClick,
    )
}

/** A row with a line icon, a title, a smaller line, and a chevron. */
@Composable
fun EntryRow(entry: RowEntry, afterClick: () -> Unit = {}) {
    Row(
        Modifier
            .fillMaxWidth()
            .pressShadeInColumn()
            .press(role = Role.Button) {
                afterClick()
                entry.onClick()
            }
            .padding(horizontal = PressInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FaIcon(entry.icon, size = 20.dp, tint = Palette.Text)
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.title)
            entry.detail?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.TextSecondary,
                    modifier = Modifier.subline(),
                )
            }
        }
        FaIcon("chevron-right", size = 14.dp, tint = Palette.TextSecondary)
    }
}

/**
 * A row with a title and a switch, in the look of the mockups: an outlined
 * track, and a knob that moves to the right on a green track.
 */
@Composable
fun ToggleRow(title: String, isOn: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .pressShadeInColumn()
            .pressToggle(isOn, onChange)
            .padding(horizontal = PressInset, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, Modifier.weight(1f))
        val track = if (isOn) Palette.Action else Palette.Incoming
        Box(
            Modifier
                .size(width = 44.dp, height = 26.dp)
                .background(track, CircleShape)
                .border(1.dp, if (isOn) Palette.Action else Palette.Outline, CircleShape)
                .padding(horizontal = 4.dp),
            contentAlignment = if (isOn) Alignment.CenterEnd else Alignment.CenterStart,
        ) {
            Box(Modifier.size(17.dp).background(if (isOn) Color.White else Palette.TextSecondary, CircleShape))
        }
    }
}

/** An icon that acts. The touch target is 48 dp, and the label is for a screen reader. */
@Composable
fun IconAction(icon: String, label: String, onClick: () -> Unit) {
    Box(
        Modifier
            .size(48.dp)
            .clip(CircleShape)
            .clickable(role = Role.Button, onClickLabel = label, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { FaIcon(icon, label = label, size = 20.dp, tint = Palette.Text) }
}

@Composable
fun Headline(title: String, body: String? = null) {
    Text(title, style = MaterialTheme.typography.headlineMedium)
    if (body != null) {
        Spacer(Modifier.height(8.dp))
        Text(body, style = MaterialTheme.typography.bodyLarge, color = Palette.TextSecondary)
    }
}
