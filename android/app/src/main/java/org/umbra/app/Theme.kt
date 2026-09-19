package org.umbra.app

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** The colors of `design/mockups/light`: warm white, forest green, pale sage. */
object Palette {
    val Surface = Color(0xFFF7F8F2)
    val Raised = Color(0xFFFFFFFF)
    val Text = Color(0xFF202B25)
    val TextSecondary = Color(0xFF58665E)
    val Action = Color(0xFF285C43)
    val Container = Color(0xFFDCECDF)
    val Incoming = Color(0xFFE9EEE3)
    val Outline = Color(0xFFB4BFB3)
    val Divider = Color(0xFFE1E6DB)
    val Error = Color(0xFF963A36)

    /** The pastel grounds of the letter avatars. */
    val Avatars = listOf(
        Color(0xFFD6E8D4), Color(0xFFE2DCF0), Color(0xFFEBDCD3),
        Color(0xFFD9E6EE), Color(0xFFF1E4C3), Color(0xFFE6D9E4),
    )
}

private val Colors = lightColorScheme(
    primary = Palette.Action,
    onPrimary = Color.White,
    primaryContainer = Palette.Container,
    onPrimaryContainer = Palette.Text,
    secondaryContainer = Palette.Container,
    onSecondaryContainer = Palette.Text,
    background = Palette.Surface,
    onBackground = Palette.Text,
    surface = Palette.Surface,
    onSurface = Palette.Text,
    surfaceVariant = Palette.Incoming,
    onSurfaceVariant = Palette.TextSecondary,
    surfaceContainer = Palette.Incoming,
    outline = Palette.Outline,
    outlineVariant = Palette.Divider,
    error = Palette.Error,
)

@Composable
fun UmbraTheme(content: @Composable () -> Unit) {
    // The type scale stays the scale of the platform, thus the font size of
    // the user applies.
    MaterialTheme(colorScheme = Colors, content = content)
}
