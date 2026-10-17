package com.alumiialabs.umbra

import android.app.UiModeManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight

/** The light or dark look of the app. */
enum class Appearance(private val labelId: Int) {
    System(R.string.main_appearance_system),
    Light(R.string.main_appearance_light),
    Dark(R.string.main_appearance_dark),
    ;

    val label: String
        get() = UiText.get(labelId)
}

/** The look that the user chose, and the night mode of the system. */
object Appearances {
    private const val PREFERENCES = "appearance"
    private const val CHOICE = "choice"

    var choice by mutableStateOf(Appearance.System)
        private set
    private var isSystemDark by mutableStateOf(false)

    val isDark: Boolean
        get() = when (choice) {
            Appearance.System -> isSystemDark
            Appearance.Light -> false
            Appearance.Dark -> true
        }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun start(context: Context) {
        choice = preferences(context).getString(CHOICE, null)?.let { held ->
            Appearance.entries.firstOrNull { it.name == held }
        } ?: Appearance.System
        follow(context.resources.configuration)
        tellPlatform(context)
    }

    /** The activity gives each new configuration, thus a change of the system shows at once. */
    fun follow(configuration: Configuration) {
        isSystemDark = configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
    }

    fun choose(context: Context, appearance: Appearance) {
        choice = appearance
        preferences(context).edit().putString(CHOICE, appearance.name).apply()
        tellPlatform(context)
    }

    // Android 12 and later draw the splash before the app runs. The night
    // mode of the app gives the splash the look that the user chose.
    private fun tellPlatform(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        val manager = context.getSystemService(UiModeManager::class.java) ?: return

        manager.setApplicationNightMode(
            when (choice) {
                Appearance.System -> UiModeManager.MODE_NIGHT_AUTO
                Appearance.Light -> UiModeManager.MODE_NIGHT_NO
                Appearance.Dark -> UiModeManager.MODE_NIGHT_YES
            },
        )
    }
}

/**
 * The colors of the app. Light: warm white, forest green, pale sage. Dark:
 * charcoal, mint, deep sage. Each color follows [Appearances], thus a view
 * draws again when the look changes.
 */
object Palette {
    private fun pick(light: Long, dark: Long) = Color(if (Appearances.isDark) dark else light)

    val Surface get() = pick(0xFFF7F8F2, 0xFF121715)
    val Raised get() = pick(0xFFFFFFFF, 0xFF1B221F)
    val Text get() = pick(0xFF202B25, 0xFFE4EAE5)
    val TextSecondary get() = pick(0xFF58665E, 0xFF9BA9A1)
    val Action get() = pick(0xFF285C43, 0xFFB5DDC4)

    /** The text and the icons on a ground of [Action]. */
    val OnAction get() = pick(0xFFFFFFFF, 0xFF10291C)

    val Container get() = pick(0xFFDCECDF, 0xFF25392D)
    val Incoming get() = pick(0xFFE9EEE3, 0xFF202924)
    val Outline get() = pick(0xFFB4BFB3, 0xFF4B5852)
    val Divider get() = pick(0xFFE1E6DB, 0xFF29322D)

    /** The shade of a row or a tab under a finger, above its content. */
    val Pressed get() = pick(0x14202B25, 0x1FE4EAE5)

    val Error get() = pick(0xFF963A36, 0xFFF0A49E)

    /** The ground of a note of an error. */
    val ErrorGround get() = pick(0xFFF6E3E1, 0xFF3A2120)

    /** The dot of a connection that waits for a circuit. */
    val Waiting get() = pick(0xFFB07A1E, 0xFFE2B45E)

    private val AvatarsLight = listOf(
        Color(0xFFD6E8D4), Color(0xFFE2DCF0), Color(0xFFEBDCD3),
        Color(0xFFD9E6EE), Color(0xFFF1E4C3), Color(0xFFE6D9E4),
    )
    private val AvatarsDark = listOf(
        Color(0xFF2D4430), Color(0xFF3A3452), Color(0xFF4A3830),
        Color(0xFF2D4150), Color(0xFF4A4026), Color(0xFF453348),
    )

    /** The grounds of the letter avatars: pastel, or deep in the dark look. */
    val Avatars get() = if (Appearances.isDark) AvatarsDark else AvatarsLight
}

private fun colors(isDark: Boolean): ColorScheme {
    val base = if (isDark) darkColorScheme() else lightColorScheme()

    // Set each color that a part of Material reads, thus no color of the
    // default scheme shows.
    return base.copy(
        primary = Palette.Action,
        onPrimary = Palette.OnAction,
        primaryContainer = Palette.Container,
        onPrimaryContainer = Palette.Text,
        secondary = Palette.Action,
        onSecondary = Palette.OnAction,
        secondaryContainer = Palette.Container,
        onSecondaryContainer = Palette.Text,
        background = Palette.Surface,
        onBackground = Palette.Text,
        surface = Palette.Surface,
        onSurface = Palette.Text,
        surfaceTint = Palette.Action,
        surfaceVariant = Palette.Incoming,
        onSurfaceVariant = Palette.TextSecondary,
        surfaceContainerLowest = Palette.Surface,
        surfaceContainerLow = Palette.Surface,
        surfaceContainer = Palette.Incoming,
        surfaceContainerHigh = Palette.Raised,
        surfaceContainerHighest = Palette.Incoming,
        outline = Palette.Outline,
        outlineVariant = Palette.Divider,
        error = Palette.Error,
    )
}

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
    val isDark = Appearances.isDark
    MaterialTheme(colorScheme = remember(isDark) { colors(isDark) }, typography = Type, content = content)
}
