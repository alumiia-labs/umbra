package com.alumiialabs.umbra

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import java.io.ByteArrayOutputStream
import kotlin.concurrent.thread
import uniffi.umbra_ffi.DraftHandle
import uniffi.umbra_ffi.FileSink
import uniffi.umbra_ffi.MsgFile

/** The media class of an image in a descriptor (Part 12 §12.3). */
const val CLASS_IMAGE: UByte = 1u

/** The states of the file of a message, as the core gives them. */
/** The side of the picture of a profile, in pixels. */
private const val PROFILE_PICTURE_SIDE = 192

/** `PICTURE_MAX` of Part 9 §9.12, in bytes. */
private const val PICTURE_MAX = 6_144

const val FILE_UPLOADING = 1
const val FILE_WANTED = 2
const val FILE_READY = 3
const val FILE_FAILED = 4

/** A received file above the automatic download limit, which waits for a tap (`IMP-167`). */
const val FILE_HELD = 5

/** A received file whose chunk each replica lost (`ATT-052`). */
const val FILE_GONE = 6

/** The longest side of a photo after the re-encode. */
private const val PHOTO_SIDE_MAX = 2_048

/** `IMAGE_REENCODE_BYTES` of Part 12 §12.7. */
private const val PHOTO_BYTES_MAX = 2 * 1_024 * 1_024

/** The longest side of a photo in a bubble. A larger decode wastes memory. */
private const val SHOWN_SIDE_MAX = 1_280

object Photos {
    /**
     * Re-encodes a picked image and gives it to a draft (`ATT-155`,
     * `ATT-156`). The decoder applies the orientation, and the new JPEG holds
     * no metadata field: no place, no device, no time. The bytes go to the
     * core through a pipe, thus the device holds no file of them
     * (`IMP-160`, `IMP-165`).
     */
    /**
     * The picture of the profile blob (Part 9 §9.3.1): the middle square of
     * a picked image at `PROFILE_PICTURE_SIDE`, as a new JPEG of at most
     * `PICTURE_MAX` bytes. A new JPEG holds no metadata field of the source
     * (`DIS-001` to `DIS-003`). The result is null for an image that does
     * not open or does not fit.
     */
    fun profilePicture(context: Context, source: Uri): ByteArray? {
        val decoded = try {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, source)) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val shortest = minOf(info.size.width, info.size.height).coerceAtLeast(1)
                if (shortest > PROFILE_PICTURE_SIDE * 2) {
                    val scale = PROFILE_PICTURE_SIDE * 2f / shortest
                    decoder.setTargetSize(
                        (info.size.width * scale).toInt().coerceAtLeast(1),
                        (info.size.height * scale).toInt().coerceAtLeast(1),
                    )
                }
            }
        } catch (unreadable: Exception) {
            return null
        }
        val side = minOf(decoded.width, decoded.height)
        val square = Bitmap.createBitmap(decoded, (decoded.width - side) / 2, (decoded.height - side) / 2, side, side)
        val picture = Bitmap.createScaledBitmap(square, PROFILE_PICTURE_SIDE, PROFILE_PICTURE_SIDE, true)
        try {
            for (quality in intArrayOf(80, 65, 50, 35, 25)) {
                val out = ByteArrayOutputStream()
                picture.compress(Bitmap.CompressFormat.JPEG, quality, out)
                val bytes = out.toByteArray()
                if (bytes.size <= PICTURE_MAX) return bytes
            }
            return null
        } finally {
            for (made in listOf(picture, square, decoded).distinct()) made.recycle()
        }
    }

    fun attach(context: Context, source: Uri, draft: DraftHandle): Boolean {
        val bitmap = try {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, source)) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val longest = maxOf(info.size.width, info.size.height)
                if (longest > PHOTO_SIDE_MAX) {
                    val scale = PHOTO_SIDE_MAX.toFloat() / longest
                    decoder.setTargetSize(
                        (info.size.width * scale).toInt().coerceAtLeast(1),
                        (info.size.height * scale).toInt().coerceAtLeast(1),
                    )
                }
            }
        } catch (unreadable: Exception) {
            return false
        }
        var encoded = ByteArray(0)
        for (quality in intArrayOf(85, 70, 55, 40)) {
            encoded.fill(0)
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
            encoded = out.toByteArray()
            if (encoded.size <= PHOTO_BYTES_MAX) break
        }
        val (width, height) = bitmap.width to bitmap.height
        // ATT-194: the record carries a thumbnail of the re-encoded photo.
        val preview = Files.thumbnail(bitmap)
        bitmap.recycle()
        if (encoded.size > PHOTO_BYTES_MAX) {
            encoded.fill(0)
            return false
        }
        val (read, write) = ParcelFileDescriptor.createPipe()
        // The core reads to the end of the pipe, thus a second thread writes.
        val writer = thread {
            try {
                ParcelFileDescriptor.AutoCloseOutputStream(write).use { it.write(encoded) }
            } catch (closed: java.io.IOException) {
                // The core read nothing, and the call below says so.
            } finally {
                encoded.fill(0)
            }
        }
        return try {
            draft.attachFile(
                "/proc/self/fd/${read.fd}",
                CLASS_IMAGE,
                width.toUShort(),
                height.toUShort(),
                0u,
                // ATT-192: a photo carries no name.
                null,
                preview,
            )
            true
        } catch (refused: Exception) {
            false
        } finally {
            // A writer that nobody reads ends when the pipe closes.
            read.close()
            writer.join()
        }
    }

    /**
     * The decoder of `IMP-166`. It bounds the size of the decode, and it
     * overwrites the bytes when the decode ends.
     */
    class Decoder : FileSink {
        var image: ImageBitmap? = null

        override fun put(bytes: ByteArray) {
            try {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                var sample = 1
                while (maxOf(bounds.outWidth, bounds.outHeight) / sample > SHOWN_SIDE_MAX) sample *= 2
                val options = BitmapFactory.Options().apply { inSampleSize = sample }
                image = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)?.asImageBitmap()
            } finally {
                bytes.fill(0)
            }
        }
    }
}

/**
 * The photo of a message in its bubble. Its place has the shape of the
 * image from the first moment (`ATT-154`), thus the list does not move when
 * the image comes. A photo that did not arrive asks again at a press.
 */
@Composable
fun PhotoTile(line: Line, file: MsgFile, modifier: Modifier = Modifier) {
    val state = file.state.toInt()
    val width = file.pixelW.toInt().coerceAtLeast(1)
    val height = file.pixelH.toInt().coerceAtLeast(1)
    // A very tall or a very wide image keeps a shape that a bubble can hold.
    val ratio = (width.toFloat() / height).coerceIn(0.5f, 2f)
    // The sender holds its photo in each state. The press of the bubble
    // starts a failed transfer again, and it opens a photo that is there.
    val isHeld = state == FILE_READY || line.info.outgoing
    val image = if (isHeld) Core.image(line) else null
    // A photo that did not come yet shows the thumbnail of its record.
    val preview = if (image == null && file.hasPreview) Core.preview(line) else null
    val canRetry = state == FILE_FAILED
    Box(
        modifier
            .width(if (ratio >= 1f) 240.dp else 200.dp)
            .aspectRatio(ratio)
            // The corner of the bubble less the rim.
            .clip(RoundedCornerShape(12.dp))
            .background(Palette.Pressed),
        contentAlignment = Alignment.Center,
    ) {
        if (image != null) {
            Image(
                image,
                contentDescription = "Photo",
                contentScale = ContentScale.Crop,
                modifier = Modifier.matchParentSize().alpha(if (state == FILE_READY) 1f else 0.55f),
            )
            if (canRetry) FaIcon("rotate", label = "Send the photo again", size = 22.dp, tint = Palette.Text)
        } else if (preview != null) {
            Image(
                preview,
                contentDescription = "Photo preview",
                contentScale = ContentScale.Crop,
                modifier = Modifier.matchParentSize(),
            )
            TransferMark(file, lostLabel(line))
        } else if (state == FILE_HELD) {
            TransferMark(file, lostLabel(line))
        } else {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                FaIcon(if (canRetry) "rotate" else "image", size = 22.dp, tint = Palette.TextSecondary)
                Spacer(Modifier.height(6.dp))
                Text(
                    lostLabel(line) ?: when (state) {
                        FILE_WANTED -> "Receiving"
                        FILE_FAILED -> "Not received"
                        else -> "Photo"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = Palette.TextSecondary,
                )
            }
        }
    }
}

/** Whether a dark view covers the screen, thus the ground under it is dark. */
object Viewer {
    var isOpen by androidx.compose.runtime.mutableStateOf(false)
}

/**
 * One photo on the whole screen, as each messenger shows one: a dark ground,
 * the image at its full fit, a zoom with two fingers or a double tap, and a
 * bar that a tap takes away.
 */
@Composable
fun PhotoScreen(line: Line, chat: Chat, onBack: () -> Unit) {
    androidx.compose.runtime.DisposableEffect(Unit) {
        Viewer.isOpen = true
        onDispose { Viewer.isOpen = false }
    }
    var scale by androidx.compose.runtime.remember { androidx.compose.runtime.mutableFloatStateOf(1f) }
    var offset by androidx.compose.runtime.remember {
        androidx.compose.runtime.mutableStateOf(androidx.compose.ui.geometry.Offset.Zero)
    }
    var showsBar by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(true) }
    val image = Core.image(line)
    Box(
        Modifier
            .fillMaxSize()
            .background(androidx.compose.ui.graphics.Color.Black)
            .pointerInput(Unit) {
                detectTapGestures(
                    onTap = { showsBar = !showsBar },
                    onDoubleTap = {
                        scale = if (scale > 1f) 1f else 2.5f
                        offset = androidx.compose.ui.geometry.Offset.Zero
                    },
                )
            }
            .pointerInput(Unit) {
                detectTransformGestures { _, pan, zoom, _ ->
                    scale = (scale * zoom).coerceIn(1f, 5f)
                    // An image at its fit has no place to move to.
                    offset = if (scale == 1f) androidx.compose.ui.geometry.Offset.Zero else offset + pan
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        if (image != null) {
            Image(
                image,
                contentDescription = "Photo",
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                    translationX = offset.x
                    translationY = offset.y
                },
            )
        }
        if (showsBar) {
            Row(
                Modifier
                    .align(Alignment.TopStart)
                    .fillMaxWidth()
                    .background(androidx.compose.ui.graphics.Color.Black.copy(alpha = 0.45f))
                    .padding(start = 4.dp, end = 16.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                androidx.compose.runtime.CompositionLocalProvider(
                    androidx.compose.material3.LocalContentColor provides androidx.compose.ui.graphics.Color.White,
                ) {
                    // The shared icon button has the ink of a light view.
                    Box(
                        Modifier
                            .size(48.dp)
                            .clip(androidx.compose.foundation.shape.CircleShape)
                            .press(role = androidx.compose.ui.semantics.Role.Button, label = "Back", onClick = onBack),
                        contentAlignment = Alignment.Center,
                    ) {
                        FaIcon(
                            "arrow-left",
                            label = "Back",
                            size = 20.dp,
                            tint = androidx.compose.ui.graphics.Color.White,
                        )
                    }
                    Spacer(Modifier.width(6.dp))
                    Column {
                        Text(
                            if (line.info.outgoing) "You" else chat.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = androidx.compose.ui.graphics.Color.White,
                        )
                        Text(
                            android.text.format.DateUtils.formatDateTime(
                                androidx.compose.ui.platform.LocalContext.current,
                                line.info.storedAtMs.toLong(),
                                android.text.format.DateUtils.FORMAT_SHOW_DATE or
                                    android.text.format.DateUtils.FORMAT_SHOW_TIME,
                            ),
                            style = MaterialTheme.typography.labelMedium,
                            color = androidx.compose.ui.graphics.Color.White.copy(alpha = 0.8f),
                            modifier = Modifier.subline(),
                        )
                    }
                }
            }
        }
    }
}
