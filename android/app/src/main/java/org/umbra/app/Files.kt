package org.umbra.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContract
import android.graphics.Bitmap
import android.media.MediaCodec
import android.media.MediaDataSource
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.media.MediaMuxer
import android.media.MediaPlayer
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.Os
import android.text.format.Formatter
import android.view.Surface
import android.view.TextureView
import android.webkit.MimeTypeMap
import androidx.annotation.RequiresApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.delay
import java.nio.ByteBuffer
import uniffi.umbra_ffi.DraftHandle
import uniffi.umbra_ffi.MediaSource
import uniffi.umbra_ffi.MsgFile

/** The media classes of a descriptor (Part 12 §12.3). */
const val CLASS_VIDEO: UByte = 2u
const val CLASS_DOC: UByte = 5u
const val CLASS_OTHER: UByte = 6u

/** `LARGE_FILE_WARN` of Part 12 §12.7, in bytes. */
const val LARGE_FILE_WARN = 25L * 1_024 * 1_024

/** `MAX_FILE_SIZE` of Part 12 §12.7, in bytes. */
const val MAX_FILE_SIZE = 250L * 1_024 * 1_024

/**
 * The uplink of an upload for each byte of the file: a chunk of 32 634 bytes
 * of segment travels in a cell of 32 860 bytes, and the commands of the
 * chunk path add about 3 % (Part 12 §12.7.2).
 */
private const val UPLINK_FACTOR = 1.04

/** The longest side of the frame of a video in a bubble. */
private const val FRAME_SIDE_MAX = 720

/** A file that the user picked, measured before the send. */
class Picked(val name: String?, val size: Long, val mime: String?)

object Files {
    /** Whether this device can send a video: the remux needs `memfd_create`. */
    val canSendVideo: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    /** The name, the size, and the type of a picked document. */
    fun describe(context: Context, source: Uri): Picked {
        var name: String? = null
        var size = -1L
        context.contentResolver.query(
            source,
            arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
            null,
            null,
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                name = cursor.getString(0)
                if (!cursor.isNull(1)) size = cursor.getLong(1)
            }
        }
        return Picked(name?.let(::fileName), size, context.contentResolver.getType(source))
    }

    /**
     * A name that `WIR-532` takes: no path, no control character, and at
     * most 255 bytes of UTF-8.
     */
    fun fileName(raw: String): String? {
        val clean = raw.substringAfterLast('/').substringAfterLast('\\')
            .filter { !it.isISOControl() }
            .trim()
        if (clean.isEmpty() || clean == "." || clean == "..") return null
        var cut = clean
        while (cut.toByteArray(Charsets.UTF_8).size > 255) cut = cut.dropLast(1)
        return cut
    }

    /**
     * The class of a picked file. The picker of files sends the original,
     * thus an image or a video from it is no media object (`ATT-155`): it
     * goes as a file with its name.
     */
    fun classOf(mime: String?): UByte = when {
        mime == null -> CLASS_OTHER
        mime == "application/pdf" || mime.startsWith("text/") -> CLASS_DOC
        mime.contains("officedocument") || mime.contains("msword") ||
            mime.contains("ms-excel") || mime.contains("ms-powerpoint") ||
            mime.contains("opendocument") || mime == "application/rtf" ||
            mime == "application/epub+zip" -> CLASS_DOC
        else -> CLASS_OTHER
    }

    /** Whether a picked original carries the metadata of a media file (`ATT-157`). */
    fun isMediaOriginal(mime: String?): Boolean =
        mime != null && (mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/"))

    /**
     * Gives a picked document to a draft as it is. The bytes go to the core
     * through a pipe, because the core cannot open the descriptor of a
     * document provider a second time. Thus no copy of it sits in a file
     * (`IMP-165`).
     */
    fun attachDocument(context: Context, source: Uri, picked: Picked, draft: DraftHandle): Boolean {
        val input = try {
            context.contentResolver.openInputStream(source)
        } catch (unreadable: Exception) {
            null
        } ?: return false
        return throughPipe(input) { path ->
            draft.attachFile(path, classOf(picked.mime), 0u, 0u, 0u, picked.name)
        }
    }

    /**
     * Gives the bytes of a stream to the core through a pipe, in pieces. The
     * core opens `/proc/self/fd/<n>` again, which works for a pipe and not
     * for a document provider or a memory file. Thus no copy sits in a file
     * (`IMP-165`).
     */
    private fun throughPipe(input: java.io.InputStream, attach: (String) -> Unit): Boolean {
        val (read, write) = ParcelFileDescriptor.createPipe()
        // The core reads to the end of the pipe, thus a second thread writes.
        val writer = kotlin.concurrent.thread {
            val chunk = ByteArray(64 * 1_024)
            try {
                input.use { from ->
                    ParcelFileDescriptor.AutoCloseOutputStream(write).use { to ->
                        while (true) {
                            val count = from.read(chunk)
                            if (count < 0) break
                            to.write(chunk, 0, count)
                        }
                    }
                }
            } catch (closed: java.io.IOException) {
                // The core read nothing, and the call below says so.
            } finally {
                chunk.fill(0)
            }
        }
        return try {
            attach("/proc/self/fd/${read.fd}")
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
     * Copies the tracks of a picked video into a new MP4 in the memory, and
     * gives it to a draft. The new file holds the samples and no metadata
     * field: no place, no device, no time (`ATT-155`). The copy sits in an
     * anonymous memory file and never on the disk (`IMP-160`). The result is
     * the size of the new file, or -1.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    fun attachVideo(context: Context, source: Uri, draft: DraftHandle): Long {
        val memory = Os.memfd_create("umbra-video", 0)
        try {
            val extractor = MediaExtractor()
            var muxer: MediaMuxer? = null
            try {
                extractor.setDataSource(context, source, null)
                muxer = MediaMuxer(memory, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
                val tracks = HashMap<Int, Int>()
                var width = 0
                var height = 0
                var micros = 0L
                var rotation = 0
                var largest = 1 shl 20
                for (index in 0 until extractor.trackCount) {
                    val format = extractor.getTrackFormat(index)
                    val mime = format.getString(MediaFormat.KEY_MIME) ?: continue
                    if (!mime.startsWith("video/") && !mime.startsWith("audio/")) continue
                    if (mime.startsWith("video/")) {
                        width = format.getInteger(MediaFormat.KEY_WIDTH)
                        height = format.getInteger(MediaFormat.KEY_HEIGHT)
                        if (format.containsKey(MediaFormat.KEY_ROTATION)) {
                            rotation = format.getInteger(MediaFormat.KEY_ROTATION)
                        }
                    }
                    if (format.containsKey(MediaFormat.KEY_DURATION)) {
                        micros = maxOf(micros, format.getLong(MediaFormat.KEY_DURATION))
                    }
                    if (format.containsKey(MediaFormat.KEY_MAX_INPUT_SIZE)) {
                        largest = maxOf(largest, format.getInteger(MediaFormat.KEY_MAX_INPUT_SIZE))
                    }
                    tracks[index] = muxer.addTrack(format)
                    extractor.selectTrack(index)
                }
                if (width == 0 || height == 0) return -1
                // The rotation lives in the track header, which the copy writes
                // new, thus the muxer takes it again.
                muxer.setOrientationHint(rotation)
                muxer.start()
                val buffer = ByteBuffer.allocate(largest)
                val info = MediaCodec.BufferInfo()
                while (true) {
                    val size = extractor.readSampleData(buffer, 0)
                    if (size < 0) break
                    val flags = if (extractor.sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC != 0) {
                        MediaCodec.BUFFER_FLAG_KEY_FRAME
                    } else {
                        0
                    }
                    info.set(0, size, extractor.sampleTime, flags)
                    tracks[extractor.sampleTrackIndex]?.let { muxer.writeSampleData(it, buffer, info) }
                    extractor.advance()
                }
                muxer.stop()
                val bytes = Os.fstat(memory).st_size
                blankPlatformVersion(memory, bytes)
                if (bytes > MAX_FILE_SIZE) return -1
                val (shownW, shownH) = if (rotation % 180 == 0) width to height else height to width
                val seconds = (micros / 1_000_000).coerceIn(0, 65_535)
                Os.lseek(memory, 0, android.system.OsConstants.SEEK_SET)
                val isGiven = throughPipe(java.io.FileInputStream(memory)) { path ->
                    draft.attachFile(
                        path,
                        CLASS_VIDEO,
                        shownW.coerceIn(0, 65_535).toUShort(),
                        shownH.coerceIn(0, 65_535).toUShort(),
                        seconds.toInt().toUShort(),
                        null,
                    )
                }
                return if (isGiven) bytes else -1
            } catch (unreadable: Exception) {
                return -1
            } finally {
                try {
                    muxer?.release()
                } catch (stopped: Exception) {
                    // A muxer that did not start has nothing to release.
                }
                extractor.release()
            }
        } finally {
            // The stream of the pipe closed the memory file when it ended.
            try {
                Os.close(memory)
            } catch (closed: android.system.ErrnoException) {
                // Nothing is left to close.
            }
        }
    }

    /**
     * The muxer of the platform writes the key `com.android.version` with
     * the version of the system into the file. That value names the device,
     * thus it becomes zeros of the same length, and the file keeps its
     * structure (`ATT-155`). The metadata sits in the `moov` box at the end.
     */
    private fun blankPlatformVersion(memory: java.io.FileDescriptor, size: Long) {
        val version = Build.VERSION.RELEASE.toByteArray(Charsets.US_ASCII)
        if (version.isEmpty()) return
        val span = minOf(size, 1L shl 20).toInt()
        val start = size - span
        val tail = ByteArray(span)
        var read = 0
        while (read < span) {
            val count = Os.pread(memory, tail, read, span - read, start + read)
            if (count <= 0) return
            read += count
        }
        val key = "com.android.version".toByteArray(Charsets.US_ASCII)
        if (indexOf(tail, key, 0) < 0) return
        val list = indexOf(tail, "ilst".toByteArray(Charsets.US_ASCII), 0)
        if (list < 0) return
        // A `data` atom of a UTF-8 value: the type 1, the locale 0, then the text.
        val header = "data".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0)
        var at = indexOf(tail, header, list)
        while (at >= 0) {
            val value = at + header.size
            if (tail.copyOfRange(value, minOf(value + version.size, tail.size)).contentEquals(version)) {
                val zeros = ByteArray(version.size) { '0'.code.toByte() }
                Os.pwrite(memory, zeros, 0, zeros.size, start + value)
                return
            }
            at = indexOf(tail, header, at + 1)
        }
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
        outer@ for (i in from..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /** The data that an upload of `bytes` spends (`ATT-083`). */
    fun uplink(context: Context, bytes: Long): String =
        Formatter.formatShortFileSize(context, (bytes * UPLINK_FACTOR).toLong())

    /** A size as a user reads it. */
    fun size(context: Context, bytes: Long): String = Formatter.formatShortFileSize(context, bytes)

    /** A duration as a player shows it. */
    fun duration(seconds: Int): String = "%d:%02d".format(seconds / 60, seconds % 60)

    /** The name that a save of the file of a message suggests. */
    fun suggestedName(file: MsgFile): String = file.name ?: when (file.mimeClass) {
        CLASS_IMAGE -> "Photo.jpg"
        CLASS_VIDEO -> "Video.mp4"
        else -> "File"
    }

    /** The type that a save of the file of a message gives the platform. */
    fun typeOf(file: MsgFile): String = when (file.mimeClass) {
        CLASS_IMAGE -> "image/jpeg"
        CLASS_VIDEO -> "video/mp4"
        else -> file.name?.substringAfterLast('.', "")?.lowercase()
            ?.let { MimeTypeMap.getSingleton().getMimeTypeFromExtension(it) }
            ?: "application/octet-stream"
    }
}

/**
 * The file of a message for a player or a retriever of the platform. It
 * reads ranges from the copy in the core (`IMP-166`), and it holds no byte
 * itself.
 */
class CoreDataSource(private val source: MediaSource) : MediaDataSource() {
    override fun getSize(): Long = source.size().toLong()

    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (size == 0) return 0
        val bytes = try {
            source.readAt(position.toULong(), size.toUInt())
        } catch (locked: Exception) {
            return -1
        }
        if (bytes.isEmpty()) return -1
        System.arraycopy(bytes, 0, buffer, offset, bytes.size)
        bytes.fill(0)
        return bytes.size
    }

    override fun close() = source.release()
}

/** The first frame of a video, at most `FRAME_SIDE_MAX` on its longest side. */
fun firstFrame(source: MediaSource): ImageBitmap? {
    val retriever = MediaMetadataRetriever()
    return try {
        retriever.setDataSource(CoreDataSource(source))
        val frame = retriever.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC) ?: return null
        val longest = maxOf(frame.width, frame.height)
        val shown = if (longest > FRAME_SIDE_MAX) {
            val scale = FRAME_SIDE_MAX.toFloat() / longest
            Bitmap.createScaledBitmap(frame, (frame.width * scale).toInt(), (frame.height * scale).toInt(), true)
                .also { frame.recycle() }
        } else {
            frame
        }
        shown.asImageBitmap()
    } catch (unreadable: Exception) {
        null
    } finally {
        retriever.release()
        source.release()
    }
}

/**
 * The video of a message in its bubble: the first frame, a play mark, and
 * the duration. Its place has the shape of the video from the first moment
 * (`ATT-154`).
 */
@Composable
fun VideoTile(line: Line, file: MsgFile, modifier: Modifier = Modifier) {
    val state = file.state.toInt()
    val width = file.pixelW.toInt().coerceAtLeast(1)
    val height = file.pixelH.toInt().coerceAtLeast(1)
    val ratio = (width.toFloat() / height).coerceIn(0.5f, 2f)
    val isHeld = state == FILE_READY || line.info.outgoing
    val frame = if (isHeld) Core.frame(line) else null
    Box(
        modifier
            .width(if (ratio >= 1f) 240.dp else 200.dp)
            .aspectRatio(ratio)
            .clip(RoundedCornerShape(12.dp))
            .background(Palette.Text),
        contentAlignment = Alignment.Center,
    ) {
        if (frame != null) {
            Image(
                frame,
                contentDescription = "Video",
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize().alpha(if (state == FILE_READY) 1f else 0.55f),
            )
        }
        Box(
            Modifier.size(48.dp).background(Color.Black.copy(alpha = 0.5f), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            val icon = when (state) {
                FILE_FAILED -> "rotate"
                FILE_READY -> "play"
                else -> "film"
            }
            FaIcon(icon, size = 18.dp, tint = Color.White)
        }
        Text(
            buildString {
                append(Files.duration(file.mediaSeconds.toInt()))
                // The time line of a sent video holds its progress.
                if (!line.info.outgoing) progressOf(file)?.let { append(" · ").append(it).append(" %") }
            },
            style = MaterialTheme.typography.labelSmall,
            color = Color.White,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(8.dp)
                .background(Color.Black.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
                .padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}

/** The share of a transfer that runs, in percent, or null. */
fun progressOf(file: MsgFile): Int? {
    val total = file.total.toLong()
    if (total == 0L) return null
    return (file.done.toLong() * 100 / total).toInt().coerceIn(0, 99)
}

/**
 * A file of a message in its bubble: the kind, the name, the size, and the
 * state of its transfer.
 */
@Composable
fun FileTile(line: Line, file: MsgFile, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val state = file.state.toInt()
    val progress = progressOf(file)
    Row(modifier.width(260.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(44.dp).background(Palette.Pressed, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            val icon = when {
                state == FILE_FAILED -> "rotate"
                state == FILE_WANTED -> "download"
                file.mimeClass == CLASS_DOC -> "file-lines"
                else -> "file"
            }
            FaIcon(icon, size = 18.dp, tint = Palette.Action)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                file.name ?: "File",
                style = MaterialTheme.typography.bodyMedium,
                color = Palette.Text,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                buildString {
                    // A size before the download is the padded size, thus
                    // it says "about".
                    if (state == FILE_WANTED) append("About ")
                    append(Files.size(context, file.size.toLong()))
                    when {
                        // The time line of a sent file holds its progress.
                        progress != null && !line.info.outgoing -> append(" · ").append(progress).append(" %")
                        state == FILE_WANTED -> append(" · Receiving")
                        state == FILE_FAILED && !line.info.outgoing -> append(" · Not received")
                    }
                },
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
            )
            if (progress != null) {
                Spacer(Modifier.height(4.dp))
                LinearProgressIndicator(
                    progress = { progress / 100f },
                    modifier = Modifier.fillMaxWidth().height(3.dp).clip(CircleShape),
                    color = Palette.Action,
                    trackColor = Palette.Pressed,
                )
            }
        }
    }
}

/**
 * One video on the whole screen: a dark ground, the video at its fit, a
 * tap that pauses it, and a bar with the time. The player reads the file
 * from the core, and nothing of it goes to a file (`IMP-166`).
 */
@Composable
fun VideoScreen(line: Line, onBack: () -> Unit) {
    DisposableEffect(Unit) {
        Viewer.isOpen = true
        onDispose { Viewer.isOpen = false }
    }
    val player = remember { MediaPlayer() }
    var isReady by remember { mutableStateOf(false) }
    var isPlaying by remember { mutableStateOf(false) }
    var position by remember { mutableFloatStateOf(0f) }
    var length by remember { mutableFloatStateOf(1f) }
    var ratio by remember { mutableFloatStateOf(16f / 9f) }
    var failed by remember { mutableStateOf(false) }
    DisposableEffect(line.key) {
        Core.openMedia(line) { source ->
            if (source == null) {
                failed = true
                return@openMedia
            }
            try {
                player.setDataSource(CoreDataSource(source))
                player.setOnPreparedListener {
                    length = it.duration.coerceAtLeast(1).toFloat()
                    if (it.videoHeight > 0) ratio = it.videoWidth.toFloat() / it.videoHeight
                    isReady = true
                    it.start()
                    isPlaying = true
                }
                player.setOnCompletionListener { isPlaying = false }
                player.setOnErrorListener { _, _, _ ->
                    failed = true
                    true
                }
                player.prepareAsync()
            } catch (unplayable: Exception) {
                failed = true
            }
        }
        onDispose { player.release() }
    }
    LaunchedEffect(isPlaying) {
        while (isPlaying) {
            position = try {
                player.currentPosition.toFloat()
            } catch (released: IllegalStateException) {
                break
            }
            delay(250)
        }
    }
    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black)
            .press(role = Role.Button, label = if (isPlaying) "Pause" else "Play") {
                if (!isReady) return@press
                if (player.isPlaying) {
                    player.pause()
                    isPlaying = false
                } else {
                    player.start()
                    isPlaying = true
                }
            },
        contentAlignment = Alignment.Center,
    ) {
        AndroidView(
            factory = { context ->
                TextureView(context).apply {
                    surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                        override fun onSurfaceTextureAvailable(texture: android.graphics.SurfaceTexture, w: Int, h: Int) {
                            player.setSurface(Surface(texture))
                        }

                        override fun onSurfaceTextureSizeChanged(texture: android.graphics.SurfaceTexture, w: Int, h: Int) = Unit

                        override fun onSurfaceTextureDestroyed(texture: android.graphics.SurfaceTexture): Boolean = true

                        override fun onSurfaceTextureUpdated(texture: android.graphics.SurfaceTexture) = Unit
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().aspectRatio(ratio),
        )
        if (failed) {
            Text("This video does not play on this device.", color = Color.White)
        } else if (isReady && !isPlaying) {
            Box(
                Modifier.size(64.dp).background(Color.Black.copy(alpha = 0.5f), CircleShape),
                contentAlignment = Alignment.Center,
            ) { FaIcon("play", label = "Play", size = 24.dp, tint = Color.White) }
        }
        Row(
            Modifier
                .align(Alignment.TopStart)
                .fillMaxWidth()
                .background(Color.Black.copy(alpha = 0.45f))
                .padding(start = 4.dp, end = 16.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .press(role = Role.Button, label = "Back", onClick = onBack),
                contentAlignment = Alignment.Center,
            ) { FaIcon("arrow-left", label = "Back", size = 20.dp, tint = Color.White) }
        }
        if (isReady) {
            Row(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .background(Color.Black.copy(alpha = 0.45f))
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(Files.duration((position / 1_000).toInt()), color = Color.White, style = MaterialTheme.typography.labelMedium)
                Slider(
                    value = position.coerceIn(0f, length),
                    onValueChange = {
                        position = it
                        player.seekTo(it.toInt())
                    },
                    valueRange = 0f..length,
                    modifier = Modifier.weight(1f),
                    colors = SliderDefaults.colors(
                        thumbColor = Color.White,
                        activeTrackColor = Color.White,
                        inactiveTrackColor = Color.White.copy(alpha = 0.3f),
                    ),
                )
                Text(Files.duration((length / 1_000).toInt()), color = Color.White, style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

/** The creation of one document that the user names, with a suggested name and type. */
class SaveDocument : ActivityResultContract<Pair<String, String>, Uri?>() {
    override fun createIntent(context: Context, input: Pair<String, String>): Intent =
        Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType(input.second)
            .putExtra(Intent.EXTRA_TITLE, input.first)

    override fun parseResult(resultCode: Int, intent: Intent?): Uri? =
        if (resultCode == Activity.RESULT_OK) intent?.data else null
}

private const val FILE_PREFS = "umbra-files"
private const val SAVE_WARNED = "save-warned"

/**
 * The save of the file of a message to a place that the user names
 * (`IMP-045`). The first save shows the warning of `IMP-046` and `IMP-047`.
 */
@Composable
fun rememberSave(): (Line) -> Unit {
    val context = LocalContext.current
    var target by remember { mutableStateOf<Line?>(null) }
    var warning by remember { mutableStateOf<Line?>(null) }
    val launcher = rememberLauncherForActivityResult(SaveDocument()) { uri ->
        val line = target
        target = null
        if (uri != null && line != null) {
            Core.saveFile(context, line, uri) { Toast.makeText(context, "Saved", Toast.LENGTH_SHORT).show() }
        }
    }
    val start = { line: Line ->
        line.info.file?.let { file ->
            target = line
            launcher.launch(Files.suggestedName(file) to Files.typeOf(file))
        }
    }
    warning?.let { line ->
        ActionSheet(
            "Save to this device?",
            listOf(
                RowEntry("download", "Save") {
                    context.getSharedPreferences(FILE_PREFS, Context.MODE_PRIVATE)
                        .edit().putBoolean(SAVE_WARNED, true).apply()
                    start(line)
                },
            ),
            note = "The file leaves the encrypted store. Each app and service of this device can read it there.",
            onDismiss = { warning = null },
        )
    }
    return { line ->
        val warned = context.getSharedPreferences(FILE_PREFS, Context.MODE_PRIVATE).getBoolean(SAVE_WARNED, false)
        if (warned) start(line) else warning = line
    }
}

/**
 * The photos, the videos, and the files of one conversation, newest first:
 * a grid of the media, and a list of the files under it.
 */
@Composable
fun MediaScreen(chat: Chat, onBack: () -> Unit, push: (Screen) -> Unit) {
    var lines by remember(chat.conversation) { mutableStateOf<List<Line>?>(null) }
    LaunchedEffect(chat.conversation, Core.revision) {
        Core.load(chat.conversation) { loaded ->
            lines = loaded.filter { it.info.file != null && !it.info.deleted }.reversed()
        }
    }
    val save = rememberSave()
    val all = lines.orEmpty()
    val media = all.filter { it.info.file?.mimeClass == CLASS_IMAGE || it.info.file?.mimeClass == CLASS_VIDEO }
    val files = all - media.toSet()
    Column(Modifier.fillMaxSize()) {
        BackBar("Media and files", onBack = onBack)
        androidx.compose.foundation.lazy.LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 24.dp),
        ) {
            if (lines != null && all.isEmpty()) {
                item {
                    Text(
                        "Nothing shared yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = Palette.TextSecondary,
                        modifier = Modifier.padding(20.dp),
                    )
                }
            }
            items(media.chunked(3).size) { row ->
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 2.dp),
                    horizontalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    for (line in media.chunked(3)[row]) {
                        MediaCell(line, Modifier.weight(1f)) {
                            val file = line.info.file ?: return@MediaCell
                            when {
                                file.state.toInt() == FILE_FAILED -> Core.fetchFile(line.handle)
                                file.state.toInt() != FILE_READY && !line.info.outgoing -> Unit
                                file.mimeClass == CLASS_VIDEO -> push(Screen.Video(chat.conversation, line))
                                else -> push(Screen.Photo(chat.conversation, line))
                            }
                        }
                    }
                    // The last row keeps the width of a cell for each gap.
                    repeat(3 - media.chunked(3)[row].size) { Spacer(Modifier.weight(1f)) }
                }
                Spacer(Modifier.height(2.dp))
            }
            if (files.isNotEmpty()) {
                item {
                    Text(
                        "Files",
                        style = MaterialTheme.typography.titleSmall,
                        color = Palette.TextSecondary,
                        modifier = Modifier.padding(start = 20.dp, top = 20.dp, bottom = 8.dp),
                    )
                }
            }
            items(files.size) { index ->
                val line = files[index]
                val file = line.info.file ?: return@items
                Box(
                    Modifier
                        .fillMaxWidth()
                        .press(role = Role.Button, label = file.name ?: "File") {
                            when (file.state.toInt()) {
                                FILE_FAILED -> Core.fetchFile(line.handle)
                                FILE_READY -> save(line)
                                else -> if (line.info.outgoing) save(line)
                            }
                        }
                        .padding(horizontal = 20.dp, vertical = 10.dp),
                ) { FileTile(line, file, Modifier.fillMaxWidth()) }
            }
        }
    }
}

/** One square of the grid of media: the photo or the first frame of the video. */
@Composable
private fun MediaCell(line: Line, modifier: Modifier, onOpen: () -> Unit) {
    val file = line.info.file ?: return
    val isHeld = file.state.toInt() == FILE_READY || line.info.outgoing
    val isVideo = file.mimeClass == CLASS_VIDEO
    val image = when {
        !isHeld -> null
        isVideo -> Core.frame(line)
        else -> Core.image(line)
    }
    Box(
        modifier
            .aspectRatio(1f)
            .background(Palette.Pressed)
            .press(role = Role.Button, label = if (isVideo) "Video" else "Photo", onClick = onOpen),
        contentAlignment = Alignment.Center,
    ) {
        if (image != null) {
            Image(image, contentDescription = null, contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize())
        } else {
            FaIcon(if (isVideo) "film" else "image", size = 20.dp, tint = Palette.TextSecondary)
        }
        if (isVideo) {
            Text(
                Files.duration(file.mediaSeconds.toInt()),
                style = MaterialTheme.typography.labelSmall,
                color = Color.White,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(4.dp)
                    .background(Color.Black.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 4.dp, vertical = 1.dp),
            )
        }
    }
}
