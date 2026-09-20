package org.umbra.app

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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import java.io.ByteArrayOutputStream
import kotlin.concurrent.thread
import uniffi.umbra_ffi.DraftHandle
import uniffi.umbra_ffi.FileSink
import uniffi.umbra_ffi.MsgFile

/** The media class of an image in a descriptor (Part 13 §13.3). */
const val CLASS_IMAGE: UByte = 1u

/** The states of the file of a message, as the core gives them. */
const val FILE_UPLOADING = 1
const val FILE_WANTED = 2
const val FILE_READY = 3
const val FILE_FAILED = 4

/** The longest side of a photo after the re-encode. */
private const val PHOTO_SIDE_MAX = 2_048

/** `IMAGE_REENCODE_BYTES` of Part 13 §13.7. */
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
    val image = if (state == FILE_READY || state == FILE_UPLOADING) Core.image(line) else null
    val canRetry = state == FILE_FAILED && !line.info.outgoing
    Box(
        modifier
            .width(if (ratio >= 1f) 240.dp else 200.dp)
            .aspectRatio(ratio)
            // The corner of the bubble less the rim.
            .clip(RoundedCornerShape(16.dp))
            .background(Palette.Pressed)
            .then(
                if (canRetry) {
                    Modifier.press(role = Role.Button, label = "Get the photo again") {
                        Core.fetchFile(line.handle)
                    }
                } else {
                    Modifier
                },
            ),
        contentAlignment = Alignment.Center,
    ) {
        if (image != null) {
            Image(
                image,
                contentDescription = "Photo",
                contentScale = ContentScale.Crop,
                modifier = Modifier.matchParentSize().alpha(if (state == FILE_UPLOADING) 0.55f else 1f),
            )
        } else {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                FaIcon(if (canRetry) "rotate" else "image", size = 22.dp, tint = Palette.TextSecondary)
                Spacer(Modifier.height(6.dp))
                Text(
                    when (state) {
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
