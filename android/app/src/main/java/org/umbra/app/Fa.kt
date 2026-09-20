package org.umbra.app

import android.content.Context
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import java.io.IOException

/**
 * The icons of Font Awesome, from SVG files in the assets. An icon of
 * `assets/fa-pro` wins over the same name in `assets/fa`. The first folder
 * holds the files of a Pro license and git ignores it. The second one holds
 * the Free set under CC BY 4.0. `android/README.md` says how to add one.
 *
 * A Font Awesome file is one view box and one path, or two paths in a duotone
 * style. The loader reads those two things and no other part of SVG.
 */
object Fa {
    /** The margin of the Font Awesome 7 grid around its view box of 512. */
    private const val BLEED = 32f

    /** The factor that keeps an icon at its size with the margin around it. */
    const val SCALE = (512f + 2 * BLEED) / 512f

    /**
     * The optical correction of an icon, in parts of its size. The box of a
     * paper plane is centered, and its weight sits up and to the right, thus
     * the eye reads it as off the center of a round button.
     */
    val nudge = mapOf("paper-plane" to (-0.09f to 0.07f))

    private val cache = HashMap<String, ImageVector>()
    private val viewBox = Regex("""viewBox="0 0 ([\d.]+) ([\d.]+)"""")
    private val path = Regex("""\sd="([^"]+)"""")

    fun icon(context: Context, name: String): ImageVector = synchronized(cache) {
        cache.getOrPut(name) { parse(name, read(context, name)) }
    }

    private fun read(context: Context, name: String): String {
        for (folder in listOf("fa-pro", "fa")) {
            try {
                return context.assets.open("$folder/$name.svg").bufferedReader().use { it.readText() }
            } catch (absent: IOException) {
                continue
            }
        }
        error("The assets hold no icon named $name")
    }

    private fun parse(name: String, svg: String): ImageVector {
        val (width, height) = viewBox.find(svg)?.destructured
            ?: error("the icon $name has no view box")
        // A path of Font Awesome 7 draws up to BLEED units outside its view
        // box, as the shackle of the lock does, and a vector of Compose
        // clips at its viewport. Thus the viewport takes that margin on each
        // side, and [FaIcon] makes the icon larger by the same factor.
        val viewWidth = width.toFloat() + 2 * BLEED
        val viewHeight = height.toFloat() + 2 * BLEED
        val builder = ImageVector.Builder(
            name = name,
            // The height is the unit, as it is in the Font Awesome grid.
            defaultWidth = 24.dp * (viewWidth / viewHeight),
            defaultHeight = 24.dp,
            viewportWidth = viewWidth,
            viewportHeight = viewHeight,
        )
        builder.addGroup(translationX = BLEED, translationY = BLEED)
        for (found in path.findAll(svg)) {
            builder.addPath(
                pathData = addPathNodes(found.groupValues[1]),
                fill = SolidColor(Color.Black),
            )
        }
        builder.clearGroup()
        return builder.build()
    }
}

/**
 * One icon. `label` is the text for a screen reader, and an icon beside a
 * text that says the same thing takes none.
 */
@Composable
fun FaIcon(
    name: String,
    modifier: Modifier = Modifier,
    label: String? = null,
    size: Dp = 20.dp,
    tint: Color = LocalContentColor.current,
) {
    val context = LocalContext.current
    val vector = remember(name) { Fa.icon(context, name) }
    val (nudgeX, nudgeY) = Fa.nudge[name] ?: (0f to 0f)
    Icon(
        vector,
        contentDescription = label,
        modifier = modifier.offset(size * nudgeX, size * nudgeY).size(size * Fa.SCALE),
        tint = tint,
    )
}
