package com.alumiialabs.umbra

import android.annotation.SuppressLint
import android.content.Context
import android.media.AudioAttributes
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.os.Build
import android.os.SystemClock
import android.system.Os
import androidx.annotation.RequiresApi
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import uniffi.umbra_ffi.MsgFile

/** The voice class of a descriptor (Part 12 §12.3). */
const val CLASS_VOICE: UByte = 4u

/** `VOICE_MAX_SECONDS` of Part 12 §12.7. */
const val VOICE_MAX_SECONDS = 900

/**
 * One recording of a voice message. The recorder encodes the microphone as
 * Opus in OGG into an anonymous memory file, thus no copy sits on the disk
 * (`IMP-160`). The encode is new, and it carries no metadata field of a file
 * (`ATT-155`).
 */
class VoiceRecording @RequiresApi(Build.VERSION_CODES.R) constructor(context: Context) {
    // Only a device with `memfd_create` makes a recording, thus each other
    // member runs there too.
    @SuppressLint("NewApi")
    val memory: java.io.FileDescriptor = Os.memfd_create("umbra-voice", 0)
    private val recorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        MediaRecorder(context)
    } else {
        @Suppress("DEPRECATION")
        MediaRecorder()
    }
    private var startedAt = 0L
    private var endedAt = 0L

    /** Whether the recorder stopped itself at `VOICE_MAX_SECONDS` (`ATT-071`). */
    var isAtLimit by mutableStateOf(false)
        private set

    /** Whether the recorder ended, and the recording waits for a send or a discard. */
    var isEnded by mutableStateOf(false)
        private set

    /** Whether the recorder closed its file, thus the file holds its samples. */
    private var isWhole = false

    /** Starts the recording, or releases all of it and gives false. */
    fun start(): Boolean = try {
        recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
        recorder.setOutputFormat(MediaRecorder.OutputFormat.OGG)
        recorder.setAudioEncoder(MediaRecorder.AudioEncoder.OPUS)
        recorder.setAudioChannels(1)
        recorder.setAudioSamplingRate(48_000)
        recorder.setAudioEncodingBitRate(32_000)
        recorder.setMaxDuration(VOICE_MAX_SECONDS * 1_000)
        recorder.setOnInfoListener { _, what, _ ->
            if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                endedAt = startedAt + VOICE_MAX_SECONDS * 1_000L
                isAtLimit = true
            }
        }
        recorder.setOutputFile(memory)
        recorder.prepare()
        recorder.start()
        startedAt = SystemClock.elapsedRealtime()
        true
    } catch (refused: Exception) {
        discard()
        false
    }

    /** The time of the recording so far, in milliseconds. */
    fun elapsedMs(): Long = (if (endedAt > 0) endedAt else SystemClock.elapsedRealtime()) - startedAt

    /**
     * Ends the recording, and keeps it for a send or a discard. A platform
     * gives an app in the background no sound of the microphone, thus the
     * view ends a recording when the app leaves the screen.
     */
    fun end() {
        if (isEnded) return
        if (endedAt == 0L) endedAt = SystemClock.elapsedRealtime()
        isWhole = try {
            recorder.stop()
            true
        } catch (stopped: RuntimeException) {
            // A recorder at its limit stopped itself, and a recorder of no
            // sample has no file.
            isAtLimit
        }
        recorder.release()
        isEnded = true
    }

    /**
     * Ends the recording. The result is its length in seconds, or -1 for a
     * recording that holds no sample. The memory file stays for the send.
     */
    fun finish(): Int {
        end()
        if (!isWhole) {
            closeMemory()
            return -1
        }
        // The bubble shows the time that the bar showed.
        return ((endedAt - startedAt) / 1_000).toInt().coerceIn(1, VOICE_MAX_SECONDS)
    }

    /** Ends the recording and drops it. */
    fun discard() {
        if (!isEnded) {
            try {
                recorder.stop()
            } catch (stopped: RuntimeException) {
                // A recorder that did not start has nothing to stop.
            }
            recorder.release()
            isEnded = true
        }
        closeMemory()
    }

    private fun closeMemory() {
        try {
            Os.close(memory)
        } catch (closed: android.system.ErrnoException) {
            // Nothing is left to close.
        }
    }
}

/**
 * The player of the voice messages: one message plays at a time. It reads
 * the file from the core, and nothing of it goes to a file (`IMP-166`).
 */
object VoicePlayer {
    /** The message that the player holds, or null. */
    var key by mutableStateOf<List<Byte>?>(null)
        private set
    var isPlaying by mutableStateOf(false)
        private set
    var positionMs by mutableIntStateOf(0)
        private set
    var lengthMs by mutableIntStateOf(0)
        private set
    private var player: MediaPlayer? = null

    /** Plays a voice message, or pauses it, or plays it on from its place. */
    fun toggle(line: Line) {
        val held = player
        if (key == line.key && held != null) {
            if (held.isPlaying) held.pause() else held.start()
            isPlaying = held.isPlaying
            return
        }
        stop()
        val wanted = line.key
        key = wanted
        lengthMs = (line.info.file?.mediaSeconds?.toInt() ?: 0) * 1_000
        Core.openMedia(line) { source ->
            if (source == null || key != wanted) {
                source?.release()
                if (key == wanted) stop()
                return@openMedia
            }
            val made = MediaPlayer()
            player = made
            val data = CoreDataSource(source)
            try {
                made.setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build(),
                )
                made.setDataSource(data)
                made.setOnPreparedListener {
                    if (player !== it) return@setOnPreparedListener
                    lengthMs = it.duration.coerceAtLeast(1)
                    if (positionMs > 0) it.seekTo(positionMs)
                    it.start()
                    isPlaying = true
                }
                made.setOnCompletionListener { if (player === it) stop() }
                made.setOnErrorListener { player, _, _ ->
                    if (this.player === player) stop()
                    true
                }
                made.prepareAsync()
            } catch (unplayable: Exception) {
                data.close()
                stop()
            }
        }
    }

    /** Moves the message that plays to a part of its length. */
    fun seek(line: Line, fraction: Float) {
        val target = (fraction.coerceIn(0f, 1f) * lengthMs).toInt()
        if (key != line.key) {
            toggle(line)
            positionMs = target
            return
        }
        positionMs = target
        try {
            player?.seekTo(target)
        } catch (unprepared: IllegalStateException) {
            // The prepared player takes the place from `positionMs`.
        }
    }

    /** Reads the place of the message that plays, for the view. */
    fun tick() {
        val held = player ?: return
        positionMs = try {
            if (held.isPlaying) held.currentPosition else return
        } catch (released: IllegalStateException) {
            return
        }
    }

    /** Stops the player and drops the message. */
    fun stop() {
        player?.release()
        player = null
        key = null
        isPlaying = false
        positionMs = 0
    }
}

/**
 * A voice message in its bubble: the button, the line of its time, and its
 * length. A tap on the line moves the message to that place.
 */
@Composable
fun VoiceTile(line: Line, file: MsgFile, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val state = file.state.toInt()
    val progress = progressOf(file)
    val isHeld = VoicePlayer.key == line.key
    LaunchedEffect(isHeld, VoicePlayer.isPlaying) {
        while (isHeld && VoicePlayer.isPlaying) {
            VoicePlayer.tick()
            delay(200)
        }
    }
    Row(modifier.width(240.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(44.dp).background(Palette.Pressed, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            val icon = when {
                state == FILE_FAILED -> "rotate"
                state == FILE_WANTED || state == FILE_HELD -> "download"
                isHeld && VoicePlayer.isPlaying -> "pause"
                else -> "play"
            }
            FaIcon(icon, size = 18.dp, tint = Palette.Action)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            // An audio file keeps the name that the user picked (ATT-192).
            file.name?.let { name ->
                Text(
                    name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = Palette.Text,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            val shown = when {
                progress != null -> progress / 100f
                isHeld && VoicePlayer.lengthMs > 0 -> VoicePlayer.positionMs.toFloat() / VoicePlayer.lengthMs
                else -> 0f
            }
            val isReady = state == FILE_READY
            TimeLine(
                shown,
                showsMark = isReady,
                modifier = if (isReady) {
                    Modifier.pointerInput(line.key) {
                        detectTapGestures { at -> VoicePlayer.seek(line, at.x / size.width) }
                    }.pointerInput(line.key) {
                        detectHorizontalDragGestures { change, _ ->
                            change.consume()
                            VoicePlayer.seek(line, change.position.x / size.width)
                        }
                    }
                } else {
                    Modifier
                },
            )
            Text(
                buildString {
                    val seconds = if (isHeld && VoicePlayer.positionMs > 0) {
                        VoicePlayer.positionMs / 1_000
                    } else {
                        file.mediaSeconds.toInt()
                    }
                    append(Files.duration(seconds))
                    when {
                        progress != null && !line.info.outgoing -> append(" · ").append(progress).append(" %")
                        state == FILE_WANTED -> append(" · Receiving")
                        state == FILE_HELD -> append(" · ").append(Files.size(context, file.size.toLong()))
                        lostLabel(line) != null -> append(" · ").append(lostLabel(line))
                        state == FILE_FAILED && !line.info.outgoing -> append(" · Not received")
                    }
                },
                style = MaterialTheme.typography.labelSmall,
                color = Palette.TextSecondary,
            )
        }
    }
}

/** A thin line of the time, with a small mark at the place. */
@Composable
private fun TimeLine(fraction: Float, showsMark: Boolean, modifier: Modifier = Modifier) {
    val track = Palette.Divider
    val played = Palette.Action
    Canvas(modifier.fillMaxWidth().height(20.dp)) {
        val middle = size.height / 2
        val at = size.width * fraction.coerceIn(0f, 1f)
        val stroke = 3.dp.toPx()
        drawLine(track, Offset(0f, middle), Offset(size.width, middle), stroke)
        drawLine(played, Offset(0f, middle), Offset(at, middle), stroke)
        if (showsMark) drawCircle(played, radius = 5.dp.toPx(), center = Offset(at, middle))
    }
}

/**
 * The composer while it records: the button that drops the recording, a
 * dot, and the time. The send button beside it sends the recording.
 */
@Composable
fun RecordingBar(recording: VoiceRecording, onDiscard: () -> Unit, modifier: Modifier = Modifier) {
    var elapsed by remember { mutableIntStateOf(0) }
    LaunchedEffect(recording) {
        while (true) {
            elapsed = (recording.elapsedMs() / 1_000).toInt().coerceAtMost(VOICE_MAX_SECONDS)
            delay(250)
        }
    }
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .padding(start = 4.dp)
                .size(48.dp)
                .clip(CircleShape)
                .press(role = Role.Button, label = "Discard the recording", onClick = onDiscard),
            contentAlignment = Alignment.Center,
        ) { FaIcon("trash-can", label = "Discard the recording", size = 18.dp, tint = Palette.TextSecondary) }
        val isRecording = !recording.isEnded && !recording.isAtLimit
        Box(Modifier.size(8.dp).background(if (isRecording) Palette.Error else Palette.TextSecondary, CircleShape))
        Spacer(Modifier.width(10.dp))
        Text(
            if (recording.isAtLimit) "${Files.duration(elapsed)} · Limit" else Files.duration(elapsed),
            style = MaterialTheme.typography.bodyLarge,
            color = Palette.Text,
        )
    }
}
