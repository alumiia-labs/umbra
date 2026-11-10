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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlin.concurrent.thread
import uniffi.umbra_ffi.DraftHandle
import uniffi.umbra_ffi.FileSink
import uniffi.umbra_ffi.MsgFile
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import android.text.format.DateUtils
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize

/** The media class of an image in a descriptor (Part 12 §12.3). */
const val CLASS_IMAGE: UByte = 1u

/** The longest side of a picture of a peer that the app decodes, in pixels. */
private const val PEER_PICTURE_SIDE_MAX = 1_024

/** `PICTURE_MAX` of Part 9 §9.12, in bytes. */
private const val PICTURE_MAX = 6_144

/**
 * The sides that the encode of a picture tries, the largest first. A larger
 * side holds more detail at a lower JPEG quality.
 */
private val PICTURE_SIDES = intArrayOf(256, 224, 192, 160)

/**
 * The lowest JPEG quality that the encode takes at a side before the last.
 * Below it the blocks of a JPEG show more than the lost detail of a
 * smaller side.
 */
private const val PICTURE_QUALITY_FLOOR = 50

/** The range of the JPEG quality that the encode of a picture searches. */
private const val PICTURE_QUALITY_MIN = 30
private const val PICTURE_QUALITY_TOP = 95

/** The longest side of a picked image in the crop view, in pixels. */
private const val CROP_SIDE_MAX = 2_048

/** The states of the file of a message, as the core gives them. */
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
const val SHOWN_SIDE_MAX = 1_280

object Photos {
    /** The side of the largest picture, in pixels (`DIS-195`). */
    val PICTURE_SIDE_MAX = PICTURE_SIDES.first()

    /**
     * Decodes a picked image for the crop view, at `CROP_SIDE_MAX` on its
     * longest side at most. The decoder applies the orientation. The result
     * is null for an image that does not open.
     */
    fun forCrop(context: Context, source: Uri): Bitmap? = try {
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, source)) { decoder, info, _ ->
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            // The pixels are erased when the crop ends.
            decoder.isMutableRequired = true
            val longest = maxOf(info.size.width, info.size.height)
            if (longest > CROP_SIDE_MAX) {
                val scale = CROP_SIDE_MAX.toFloat() / longest
                decoder.setTargetSize(
                    (info.size.width * scale).toInt().coerceAtLeast(1),
                    (info.size.height * scale).toInt().coerceAtLeast(1),
                )
            }
        }
    } catch (fault: Throwable) {
        // `OutOfMemoryError` is no `Exception`.
        null
    }

    /**
     * The picture of the profile blob (Part 9 §9.3.1) or of a contact
     * (`DIS-195`) from the square that the user cropped: a new JPEG of at most `PICTURE_MAX` bytes
     * with no metadata field of the source (`DIS-001` to `DIS-003`). The
     * encode takes the largest side of `PICTURE_SIDES` that keeps the
     * quality at `PICTURE_QUALITY_FLOOR`, and the highest quality that fits.
     * The result is null for a square that does not fit. The pixels of the
     * square are erased after the encode.
     */
    fun picture(square: Bitmap): ByteArray? {
        val made = arrayListOf(square)
        try {
            var step = square
            var fallback: ByteArray? = null
            for (side in PICTURE_SIDES) {
                // A small crop gets no larger side than it holds.
                if (side > square.width && side != PICTURE_SIDES.last()) continue

                // Steps of a half keep each pixel an average of the pixels
                // above it. One long step skips most of them, and its edges
                // alias, which costs bytes and shows as noise.
                while (step.width / 2 >= side) {
                    step = Bitmap.createScaledBitmap(step, step.width / 2, step.width / 2, true)
                    made += step
                }
                val scaled = Bitmap.createScaledBitmap(step, side, side, true)
                made += scaled

                // A transparent pixel becomes white and not black.
                val flat = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888)
                made += flat
                flat.eraseColor(android.graphics.Color.WHITE)
                android.graphics.Canvas(flat).drawBitmap(scaled, 0f, 0f, null)

                val (quality, bytes) = bestFit(flat) ?: continue
                if (quality >= PICTURE_QUALITY_FLOOR) {
                    fallback?.fill(0)
                    return bytes
                }
                if (fallback == null) {
                    fallback = bytes
                } else {
                    bytes.fill(0)
                }
            }
            return fallback
        } catch (fault: Throwable) {
            return null
        } finally {
            for (bitmap in made.distinct()) wipe(bitmap)
        }
    }

    /**
     * Erases the pixels of a bitmap and frees it. A scaled copy of the
     * platform can be immutable, and it then takes no erase: the free
     * alone stands for it.
     */
    private fun wipe(bitmap: Bitmap) {
        if (bitmap.isRecycled) return
        if (bitmap.isMutable) bitmap.eraseColor(0)
        bitmap.recycle()
    }

    /** The highest JPEG quality at which [bitmap] fits `PICTURE_MAX`, and its bytes. */
    private fun bestFit(bitmap: Bitmap): Pair<Int, ByteArray>? {
        var low = PICTURE_QUALITY_MIN
        var high = PICTURE_QUALITY_TOP
        var best: Pair<Int, ByteArray>? = null
        val out = WipingOutput()

        try {
            while (low <= high) {
                val quality = (low + high) / 2
                out.wipe()
                bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
                if (out.size() <= PICTURE_MAX) {
                    best?.second?.fill(0)
                    best = quality to out.toByteArray()
                    low = quality + 1
                } else {
                    high = quality - 1
                }
            }
        } finally {
            out.wipe()
        }

        return best
    }

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
                // The pixels are erased when the encode ends.
                decoder.isMutableRequired = true
                val longest = maxOf(info.size.width, info.size.height)
                if (longest > PHOTO_SIDE_MAX) {
                    val scale = PHOTO_SIDE_MAX.toFloat() / longest
                    decoder.setTargetSize(
                        (info.size.width * scale).toInt().coerceAtLeast(1),
                        (info.size.height * scale).toInt().coerceAtLeast(1),
                    )
                }
            }
        } catch (unreadable: Throwable) {
            // `OutOfMemoryError` is no `Exception`.
            return false
        }

        var encoded = ByteArray(0)
        val width: Int
        val height: Int
        val preview: ByteArray?
        val out = WipingOutput(PHOTO_BYTES_MAX / 2)
        try {
            for (quality in intArrayOf(85, 70, 55, 40)) {
                out.wipe()
                bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
                if (out.size() <= PHOTO_BYTES_MAX) {
                    encoded = out.toByteArray()
                    break
                }
            }

            width = bitmap.width
            height = bitmap.height
            // ATT-194: the record carries a thumbnail of the re-encoded photo.
            preview = if (encoded.isEmpty()) null else Files.thumbnail(bitmap)
        } catch (fault: Throwable) {
            // An encode with no memory sends nothing, and it ends no thread.
            encoded.fill(0)
            return false
        } finally {
            // Each path, also a fault, leaves no pixel and no JPEG copy.
            out.wipe()
            wipe(bitmap)
        }

        if (encoded.isEmpty()) return false

        val (read, write) = try {
            ParcelFileDescriptor.createPipe()
        } catch (refused: java.io.IOException) {
            encoded.fill(0)
            return false
        }

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
    class Decoder(private val sideMax: Int = SHOWN_SIDE_MAX) : FileSink {
        var image: ImageBitmap? = null

        // An exception that crosses into Rust ends the process.
        override fun put(bytes: ByteArray) {
            try {
                image = bounded(bytes, sideMax)
            } catch (fault: Throwable) {
                image = null
            } finally {
                bytes.fill(0)
            }
        }
    }

    /**
     * Decodes an image of a peer at `sideMax` on its longest side at most.
     * The header names the size before one pixel has memory, and the decode
     * takes each second, fourth, or eighth pixel of a larger image. A file
     * that does not decode, and a decode with no memory, give null: the
     * bytes of a peer end no thread of the app. The bitmap is mutable, thus
     * a lock erases its pixels (`IMP-166`).
     */
    fun bounded(bytes: ByteArray, sideMax: Int): ImageBitmap? = try {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            null
        } else {
            var sample = 1
            while (maxOf(bounds.outWidth, bounds.outHeight) / sample > sideMax) sample *= 2
            val options = BitmapFactory.Options().apply {
                inSampleSize = sample
                inMutable = true
            }
            val decoded = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)

            // A decoder that did not take the sample gives no bitmap above
            // the bound to a draw.
            if (decoded != null && maxOf(decoded.width, decoded.height) > sideMax * 2) {
                wipe(decoded)
                null
            } else {
                decoded?.let { upright(it, bytes) }?.asImageBitmap()
            }
        }
    } catch (fault: Throwable) {
        // `OutOfMemoryError` is no `Exception`.
        null
    }

    /**
     * Turns a decoded image as its orientation field says. The decoder of
     * the platform reads the pixels and not this field, and a client that
     * sends the file of a camera as it is sets it.
     */
    private fun upright(bitmap: Bitmap, bytes: ByteArray): Bitmap {
        val orientation = try {
            android.media.ExifInterface(java.io.ByteArrayInputStream(bytes))
                .getAttributeInt(android.media.ExifInterface.TAG_ORIENTATION, android.media.ExifInterface.ORIENTATION_NORMAL)
        } catch (noField: Throwable) {
            return bitmap
        }

        val turn = android.graphics.Matrix()
        when (orientation) {
            android.media.ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> turn.postScale(-1f, 1f)
            android.media.ExifInterface.ORIENTATION_ROTATE_180 -> turn.postRotate(180f)
            android.media.ExifInterface.ORIENTATION_FLIP_VERTICAL -> turn.postScale(1f, -1f)
            android.media.ExifInterface.ORIENTATION_TRANSPOSE -> {
                turn.postRotate(90f)
                turn.postScale(-1f, 1f)
            }
            android.media.ExifInterface.ORIENTATION_ROTATE_90 -> turn.postRotate(90f)
            android.media.ExifInterface.ORIENTATION_TRANSVERSE -> {
                turn.postRotate(270f)
                turn.postScale(-1f, 1f)
            }
            android.media.ExifInterface.ORIENTATION_ROTATE_270 -> turn.postRotate(270f)
            else -> return bitmap
        }

        val turned = try {
            Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, turn, true)
        } catch (noMemory: Throwable) {
            return bitmap
        }
        if (turned === bitmap) return bitmap

        wipe(bitmap)
        // The copy of the platform can be immutable, and a lock erases a
        // mutable bitmap alone.
        if (turned.isMutable) return turned
        val mutable = turned.copy(Bitmap.Config.ARGB_8888, true) ?: return turned
        turned.recycle()
        return mutable
    }

    /**
     * The picture of a profile of a peer (`DIS-176`). An honest client sends
     * at most `PICTURE_SIDE_MAX` on each side, thus a header that names more
     * than `PEER_PICTURE_SIDE_MAX` shows no picture.
     */
    fun profileImage(bytes: ByteArray): ImageBitmap? {
        if (bytes.size > PICTURE_MAX) return null

        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        try {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        } catch (fault: Throwable) {
            return null
        }

        if (maxOf(bounds.outWidth, bounds.outHeight) > PEER_PICTURE_SIDE_MAX) return null
        return bounded(bytes, PEER_PICTURE_SIDE_MAX)
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
                contentDescription = stringResource(R.string.common_photo),
                contentScale = ContentScale.Crop,
                modifier = Modifier.matchParentSize().alpha(if (state == FILE_READY) 1f else 0.55f),
            )
            if (canRetry) {
                // The mark of `TransferMark`: a light icon on a dark ground
                // reads on each photo.
                Box(
                    Modifier.size(48.dp).background(Color.Black.copy(alpha = 0.55f), CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    FaIcon("rotate", label = stringResource(R.string.photo_send_again), size = 18.dp, tint = Color.White)
                }
            }
        } else if (preview != null) {
            Image(
                preview,
                contentDescription = stringResource(R.string.photo_preview),
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
                    lostLabel(line) ?: when {
                        state == FILE_WANTED -> stringResource(R.string.common_receiving)
                        state == FILE_FAILED -> stringResource(R.string.common_not_received)
                        isHeld && Core.imageFailed(line) -> stringResource(R.string.core_image_not_open)
                        else -> stringResource(R.string.common_photo)
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
    DisposableEffect(Unit) {
        Viewer.isOpen = true
        onDispose { Viewer.isOpen = false }
    }

    // A photo that a timer or a deletion took away leaves the screen.
    LeavesWhenGone(line, onBack)

    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    var showsBar by remember { mutableStateOf(true) }
    var size by remember { mutableStateOf(IntSize.Zero) }
    // The decode of the bubble is too small for a zoom into the photo.
    val image = Core.image(line, isFull = true)
    val isFailed = image == null && Core.imageFailed(line, isFull = true)

    // A screen reader finds no bar that a tap took away, thus the bar stays.
    val context = LocalContext.current
    val reads = remember {
        val manager = context.getSystemService(android.view.accessibility.AccessibilityManager::class.java)
        manager?.isTouchExplorationEnabled == true
    }
    val zoomLabel = stringResource(R.string.photo_zoom)

    // The image stays on the screen: its middle moves by the part that the
    // zoom put outside of the screen, and no more.
    fun held(to: Offset, at: Float): Offset {
        val reachX = size.width * (at - 1f) / 2f
        val reachY = size.height * (at - 1f) / 2f
        return Offset(to.x.coerceIn(-reachX, reachX), to.y.coerceIn(-reachY, reachY))
    }

    fun zoomAtTap() {
        scale = if (scale > 1f) 1f else 2.5f
        offset = Offset.Zero
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black)
            .onSizeChanged { size = it }
            .semantics {
                customActions = listOf(
                    CustomAccessibilityAction(zoomLabel) {
                        zoomAtTap()
                        true
                    },
                )
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onTap = { showsBar = !showsBar },
                    onDoubleTap = { zoomAtTap() },
                )
            }
            .pointerInput(Unit) {
                detectTransformGestures { _, pan, zoom, _ ->
                    scale = (scale * zoom).coerceIn(1f, 5f)
                    // An image at its fit has no place to move to.
                    offset = if (scale == 1f) Offset.Zero else held(offset + pan, scale)
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        if (isFailed) {
            // A file that does not decode shows no wait without end.
            Text(
                stringResource(R.string.core_image_not_open),
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White,
            )
        } else if (image != null) {
            Image(
                image,
                contentDescription = stringResource(R.string.common_photo),
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                    translationX = offset.x
                    translationY = offset.y
                },
            )
        } else {
            // The decode runs on another thread, and a dark screen alone says nothing.
            CircularProgressIndicator(color = Color.White)
        }

        if (showsBar || reads) {
            Row(
                Modifier
                    .align(Alignment.TopStart)
                    .fillMaxWidth()
                    .background(Color.Black.copy(alpha = 0.45f))
                    .padding(start = 4.dp, end = 16.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconAction("arrow-left", stringResource(R.string.common_back), tint = Color.White, onClick = onBack, tag = TestTags.BACK)
                Spacer(Modifier.width(6.dp))
                Column {
                    Text(
                        if (line.info.outgoing) stringResource(R.string.common_you) else chat.title,
                        style = MaterialTheme.typography.titleMedium,
                        color = Color.White,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        DateUtils.formatDateTime(
                            LocalContext.current,
                            line.info.shownAtMs,
                            DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_TIME,
                        ),
                        style = MaterialTheme.typography.labelMedium,
                        color = Color.White.copy(alpha = 0.8f),
                    )
                }
            }
        }
    }
}

/**
 * Leaves a viewer when its message left: a deletion, the end of a timer, or
 * a removal by a moderator. Each change of the store asks the core again.
 */
@Composable
fun LeavesWhenGone(line: Line, onBack: () -> Unit) {
    // An answer of the core that comes after the viewer went, or a second
    // one, takes no other screen away.
    val isHere = remember { booleanArrayOf(true) }
    DisposableEffect(Unit) {
        onDispose { isHere[0] = false }
    }

    val revision = Core.revision
    LaunchedEffect(line.key, revision) {
        Core.stillShown(line) { isShown ->
            if (!isShown && isHere[0]) {
                isHere[0] = false
                onBack()
            }
        }
    }
}
