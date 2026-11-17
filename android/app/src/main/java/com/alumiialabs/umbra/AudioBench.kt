package com.alumiialabs.umbra

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * The phone terms of `X` for Stage 0 of the call proposal
 * (`docs/design/real-time-calls.md` §3, §11): Opus at 64 kbit/s, the round
 * trip of the audio system, and the frame cipher. A build with
 * `-Pumbra.bench=true` alone shows it. It uses no network and stores
 * nothing.
 */
object AudioBench {
    private const val RATE = 48_000
    private const val FRAME_MS = 40
    private const val FRAME_SAMPLES = RATE * FRAME_MS / 1_000
    private const val BITRATE = 64_000
    private const val FRAMES = 500

    /** The largest voice item of a `B0` media cell (§6, the bucket rule). */
    private const val B0_VOICE_MAX = 453
    private const val MEDIA_PLAIN = 462
    private const val CIPHER_ROUNDS = 2_000

    private const val LOOP_ROUNDS = 10
    private const val BEEP_MS = 5
    private const val LOOP_WAIT_MS = 700L
    private const val CODEC_WAIT_US = 10_000L

    private fun quantile(values: List<Double>, share: Double): Double {
        val sorted = values.sorted()
        return sorted[((sorted.size - 1) * share).toInt()]
    }

    private fun spread(values: List<Double>): String =
        if (values.isEmpty()) {
            "no sample"
        } else {
            "p50 %.2f ms, p99 %.2f ms, max %.2f ms (%d)".format(
                quantile(values, 0.5),
                quantile(values, 0.99),
                values.max(),
                values.size,
            )
        }

    private fun nowMs() = System.nanoTime() / 1e6

    /** A signal with the shape of a voice: two tones under a slow envelope, and noise. */
    private fun speech(frame: Int): ShortArray {
        val random = java.util.Random(frame.toLong())
        return ShortArray(FRAME_SAMPLES) { index ->
            val t = (frame * FRAME_SAMPLES + index).toDouble() / RATE
            val envelope = 0.5 + 0.5 * sin(2 * PI * 3 * t)
            val tone = 0.4 * sin(2 * PI * 180 * t) + 0.2 * sin(2 * PI * 1_100 * t)
            val noise = 0.1 * (random.nextDouble() * 2 - 1)
            ((envelope * tone + noise) * 12_000).toInt().toShort()
        }
    }

    /** The configuration of the Opus decoder: `OpusHead`, the codec delay, and the seek preroll. */
    private fun decoderFormat(): MediaFormat {
        val head = ByteBuffer.allocate(19).order(ByteOrder.LITTLE_ENDIAN)
        head.put("OpusHead".toByteArray(Charsets.US_ASCII))
        head.put(1.toByte()).put(1.toByte()).putShort(312.toShort()).putInt(RATE).putShort(0.toShort()).put(0.toByte())
        head.flip()
        fun nanos(value: Long): ByteBuffer =
            ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).also { it.flip() }

        return MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, RATE, 1).apply {
            setByteBuffer("csd-0", head)
            setByteBuffer("csd-1", nanos(6_500_000))
            setByteBuffer("csd-2", nanos(80_000_000))
        }
    }

    /** Feeds one input and drains each output that comes within the wait. */
    private fun step(codec: MediaCodec, input: ByteArray, at: Long, onOutput: (ByteArray) -> Unit) {
        val index = codec.dequeueInputBuffer(CODEC_WAIT_US * 10)
        if (index >= 0) {
            val buffer = codec.getInputBuffer(index)!!
            buffer.clear()
            buffer.put(input)
            codec.queueInputBuffer(index, 0, input.size, at, 0)
        }

        val info = MediaCodec.BufferInfo()
        while (true) {
            val out = codec.dequeueOutputBuffer(info, CODEC_WAIT_US)
            if (out < 0) {
                if (out == MediaCodec.INFO_TRY_AGAIN_LATER) return
                continue
            }

            val isConfig = info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
            if (!isConfig && info.size > 0) {
                val bytes = ByteArray(info.size)
                codec.getOutputBuffer(out)!!.get(bytes)
                onOutput(bytes)
            }
            codec.releaseOutputBuffer(out, false)
        }
    }

    private fun opus(report: (String) -> Unit) {
        val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, RATE, 1).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, BITRATE)
            setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
            setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, FRAME_SAMPLES * 2)
        }
        val encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        report("Opus encoder: ${encoder.name}, 64 kbit/s CBR, 48 kHz mono, 40 ms input")
        encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        encoder.start()

        val decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        decoder.configure(decoderFormat(), null, null, 0)
        decoder.start()

        val encodeMs = ArrayList<Double>()
        val decodeMs = ArrayList<Double>()
        val packets = ArrayList<Int>()
        val perCell = ArrayList<Int>()
        try {
            for (frame in 0 until FRAMES) {
                val pcm = ByteBuffer.allocate(FRAME_SAMPLES * 2).order(ByteOrder.LITTLE_ENDIAN)
                speech(frame).forEach { pcm.putShort(it) }
                val at = frame * FRAME_MS * 1_000L

                val encoded = ArrayList<ByteArray>()
                val start = nowMs()
                step(encoder, pcm.array(), at) { encoded.add(it) }
                encodeMs.add(nowMs() - start)

                // One 40 ms cell carries each packet of its frame, each with
                // the 7 B item header of §6.
                packets.addAll(encoded.map { it.size })
                perCell.add(encoded.sumOf { it.size + 7 })
                for (packet in encoded) {
                    val begin = nowMs()
                    step(decoder, packet, at) {}
                    decodeMs.add(nowMs() - begin)
                }
            }
        } finally {
            encoder.stop()
            encoder.release()
            decoder.stop()
            decoder.release()
        }

        // The first frames fill the lookahead of the encoder.
        val steady = perCell.drop(5)
        report("Encode, one 40 ms frame: ${spread(encodeMs.drop(5))}")
        report("Decode, one packet: ${spread(decodeMs.drop(5))}")
        if (packets.isNotEmpty()) {
            report("Packets: ${packets.size} for $FRAMES frames, size p50 ${quantile(packets.map { it.toDouble() }, 0.5).toInt()} B, max ${packets.max()} B")
        }
        if (steady.isNotEmpty()) {
            val largest = steady.max()
            val verdict = if (largest <= B0_VOICE_MAX) "fits B0" else "needs B1"
            report("Voice items of one cell: max $largest B of $B0_VOICE_MAX B in B0, $verdict")
        }
    }

    private fun cipher(report: (String) -> Unit) {
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "ChaCha20")
        val plain = ByteArray(MEDIA_PLAIN)
        val sealMs = ArrayList<Double>()
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        for (round in 0 until CIPHER_ROUNDS) {
            val nonce = ByteBuffer.allocate(12).putInt(4, round).array()
            val start = nowMs()
            cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(nonce))
            cipher.doFinal(plain)
            sealMs.add(nowMs() - start)
        }
        report("Frame cipher, ChaCha20-Poly1305 of $MEDIA_PLAIN B: ${spread(sealMs.drop(100))}")
    }

    /**
     * The time from the write of a beep to the speaker to the read of it from
     * the microphone, inside this app. That is the playout and the capture of
     * a call app, with each buffer of the audio system.
     */
    private fun roundTrip(report: (String) -> Unit) {
        val chunk = RATE / 100
        val recordMin = AudioRecord.getMinBufferSize(RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val trackMin = AudioTrack.getMinBufferSize(RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)

        // UNPROCESSED keeps the echo canceller from removing the beep. A
        // phone with no such source takes the source of speech recognition,
        // which also runs no echo canceller.
        @Suppress("MissingPermission")
        fun recorderOf(source: Int) = AudioRecord(
            source,
            RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(recordMin, chunk * 4),
        )
        var source = "unprocessed"
        var recorder = recorderOf(MediaRecorder.AudioSource.UNPROCESSED)
        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            recorder.release()
            recorder = recorderOf(MediaRecorder.AudioSource.VOICE_RECOGNITION)
            source = "voice recognition"
        }
        val track = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build(),
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(RATE)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build(),
            )
            .setBufferSizeInBytes(trackMin)
            .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()

        val path = if (track.performanceMode == AudioTrack.PERFORMANCE_MODE_LOW_LATENCY) "low latency" else "normal"
        val beep = ShortArray(chunk) { index ->
            if (index < RATE * BEEP_MS / 1_000) (sin(2 * PI * 1_000 * index / RATE) * 30_000).toInt().toShort() else 0
        }
        val silence = ShortArray(chunk)
        // The time of the last beep that the microphone did not hear yet, or -1.
        val beepAt = AtomicReference(-1.0)
        val running = AtomicBoolean(true)
        val trips = ArrayList<Double>()

        val player = Thread {
            track.play()
            var next = nowMs() + LOOP_WAIT_MS
            var sent = 0
            while (running.get() && sent < LOOP_ROUNDS) {
                if (nowMs() >= next && beepAt.get() < 0) {
                    beepAt.set(nowMs())
                    track.write(beep, 0, chunk)
                    sent++
                    next = nowMs() + LOOP_WAIT_MS
                } else {
                    track.write(silence, 0, chunk)
                }
            }
            track.stop()
        }

        recorder.startRecording()
        player.start()
        val read = ShortArray(chunk)
        var noise = 0.0
        var noiseCount = 0
        val deadline = nowMs() + LOOP_ROUNDS * LOOP_WAIT_MS * 3
        try {
            while (trips.size < LOOP_ROUNDS && nowMs() < deadline) {
                val count = recorder.read(read, 0, chunk)
                val readAt = nowMs()
                if (count <= 0) continue

                val written = beepAt.get()
                if (written < 0) {
                    // The noise floor between two beeps.
                    noise += sqrt(read.take(count).sumOf { it.toDouble() * it } / count)
                    noiseCount++
                    continue
                }

                val floor = if (noiseCount > 0) noise / noiseCount else 100.0
                val onset = (0 until count).firstOrNull { abs(read[it].toInt()) > maxOf(floor * 8, 1_500.0) }
                if (onset != null) {
                    val heardAt = readAt - (count - onset) * 1_000.0 / RATE
                    trips.add(heardAt - written)
                    beepAt.set(-1.0)
                } else if (readAt - written > LOOP_WAIT_MS * 0.9) {
                    beepAt.set(-1.0)
                }
            }
        } finally {
            running.set(false)
            player.join(2_000)
            recorder.stop()
            recorder.release()
            track.release()
        }

        report("Audio round trip, speaker to microphone, $path output, $source input: ${spread(trips)}")
        if (trips.size < LOOP_ROUNDS) {
            report("  ${LOOP_ROUNDS - trips.size} of $LOOP_ROUNDS beeps were not heard. Turn the volume up, and keep the speaker and the microphone free.")
        }
    }

    /** Runs each part on this thread and reports each line. */
    fun run(report: (String) -> Unit) {
        report("Device: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE}, app ${BuildConfig.VERSION_NAME}")
        for (part in listOf(::opus, ::cipher, ::roundTrip)) {
            try {
                part(report)
            } catch (fault: Exception) {
                report("${part.name} failed: ${fault.javaClass.simpleName}: ${fault.message}")
            }
        }
        report("Done.")
    }
}

/** The screen of [AudioBench]. */
@Composable
fun AudioBenchScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var lines by remember { mutableStateOf(listOf<String>()) }
    var isRunning by remember { mutableStateOf(false) }

    fun start() {
        isRunning = true
        lines = emptyList()
        val main = Handler(Looper.getMainLooper())
        Thread {
            AudioBench.run { line -> main.post { lines = lines + line } }
            main.post { isRunning = false }
        }.start()
    }

    val askMicrophone = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        if (allowed) start()
    }

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.bench_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = PressInset)) {
            Text(stringResource(R.string.bench_about), style = MaterialTheme.typography.bodyMedium, color = Palette.TextSecondary)
            Spacer(Modifier.height(16.dp))
            PrimaryButton(stringResource(R.string.bench_start), enabled = !isRunning, tag = TestTags.BENCH_START) {
                val state = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO)
                if (state == PackageManager.PERMISSION_GRANTED) start() else askMicrophone.launch(Manifest.permission.RECORD_AUDIO)
            }
            Spacer(Modifier.height(16.dp))
            for (line in lines) {
                Text(line, style = MaterialTheme.typography.bodySmall, fontFamily = Fonts.Mono)
                Spacer(Modifier.height(6.dp))
            }
            if (!isRunning && lines.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                PrimaryButton(stringResource(R.string.bench_copy), tag = TestTags.BENCH_COPY) {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    clipboard?.setPrimaryClip(ClipData.newPlainText("UMBRA audio bench", lines.joinToString("\n")))
                }
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}
