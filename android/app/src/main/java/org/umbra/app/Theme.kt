package org.umbra.app

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight

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

    /** The shade of a row or a tab under a finger, above its content. */
    val Pressed = Color(0x14202B25)
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

/**
 * The fonts of the app, which it ships (SIL Open Font License 1.1, in
 * `assets/licenses`). A maker of phones puts its own font in the place of
 * the font of the platform, thus a font of the system would change the look
 * of the app from one phone to the next. Each file holds each weight.
 */
object Fonts {
    private val weights = listOf(
        FontWeight.Light,
        FontWeight.Normal,
        FontWeight.Medium,
        FontWeight.SemiBold,
        FontWeight.Bold,
    )

    private fun family(resource: Int) = FontFamily(
        weights.map { weight ->
            Font(
                resource,
                weight,
                variationSettings = FontVariation.Settings(FontVariation.weight(weight.weight)),
            )
        },
    )

    val Sans = family(R.font.roboto)
    val Mono = family(R.font.roboto_mono)
}

// The type scale stays the scale of the platform, thus the font size of the
// user applies, and each style takes the font of the app.
private val Type = Typography().let { base ->
    Typography(
        displayLarge = base.displayLarge.copy(fontFamily = Fonts.Sans),
        displayMedium = base.displayMedium.copy(fontFamily = Fonts.Sans),
        displaySmall = base.displaySmall.copy(fontFamily = Fonts.Sans),
        headlineLarge = base.headlineLarge.copy(fontFamily = Fonts.Sans),
        headlineMedium = base.headlineMedium.copy(fontFamily = Fonts.Sans),
        headlineSmall = base.headlineSmall.copy(fontFamily = Fonts.Sans),
        titleLarge = base.titleLarge.copy(fontFamily = Fonts.Sans),
        titleMedium = base.titleMedium.copy(fontFamily = Fonts.Sans),
        titleSmall = base.titleSmall.copy(fontFamily = Fonts.Sans),
        bodyLarge = base.bodyLarge.copy(fontFamily = Fonts.Sans),
        bodyMedium = base.bodyMedium.copy(fontFamily = Fonts.Sans),
        bodySmall = base.bodySmall.copy(fontFamily = Fonts.Sans),
        labelLarge = base.labelLarge.copy(fontFamily = Fonts.Sans),
        labelMedium = base.labelMedium.copy(fontFamily = Fonts.Sans),
        labelSmall = base.labelSmall.copy(fontFamily = Fonts.Sans),
    )
}

@Composable
fun UmbraTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Colors, typography = Type, content = content)
}
