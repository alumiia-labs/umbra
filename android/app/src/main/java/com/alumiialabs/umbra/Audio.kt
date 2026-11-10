package com.alumiialabs.umbra

import android.content.Context
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import android.net.Uri
import android.os.Build
import androidx.annotation.RequiresApi
import java.io.FileDescriptor
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** The media class of an audio file that the user picked (Part 12 §12.3). */
const val CLASS_AUDIO: UByte = 3u

/** The bit rate of a re-encoded audio file: AAC-LC at 128 kbit/s. */
private const val AUDIO_BIT_RATE = 128_000

/** The wait of one call to a codec, in microseconds. */
private const val CODEC_WAIT_US = 10_000L

/**
 * The turns of the loop in sequence that move no sample before the
 * transcode ends. One idle turn takes about 40 ms, thus a codec that
 * stalls ends after about 20 seconds.
 */
private const val IDLE_TURNS_MAX = 500

/** A decoder that changed the form of its samples in the middle of a file. */
private class FormChanged : Exception()

/** A track of a form that the encoder does not take. */
private class FormRefused : Exception()

/**
 * Decodes the first audio track of a picked file and encodes it again as
 * AAC in a new MP4 in `memory` (`ATT-155`). The new file holds the samples
 * and no field of the original: no title, no artist, no cover, and no
 * time. The result is the length in microseconds, or a negative number:
 * [MEDIA_TOO_LARGE] for a file whose encode passes `MAX_FILE_SIZE`,
 * [MEDIA_FORM] for samples that the encoder does not take, and -1 for a
 * file with no audio track that the platform decodes, a stall, or a true
 * result of `isCanceled`.
 */
@RequiresApi(Build.VERSION_CODES.R)
fun transcodeAudio(
    context: Context,
    source: Uri,
    memory: FileDescriptor,
    isCanceled: () -> Boolean = { false },
): Long {
    val extractor = MediaExtractor()
    var decoder: MediaCodec? = null
    var encoder: MediaCodec? = null
    var muxer: MediaMuxer? = null

    try {
        extractor.setDataSource(context, source, null)
        val track = (0 until extractor.trackCount).firstOrNull { index ->
            extractor.getTrackFormat(index).getString(MediaFormat.KEY_MIME)?.startsWith("audio/") == true
        } ?: return -1
        extractor.selectTrack(track)

        val input = extractor.getTrackFormat(track)

        // The length that the container names refuses a file of many hours
        // before the decode of one sample.
        if (input.containsKey(MediaFormat.KEY_DURATION)) {
            val seconds = input.getLong(MediaFormat.KEY_DURATION) / 1_000_000L
            if (seconds > MAX_FILE_SIZE * 8 / AUDIO_BIT_RATE) return MEDIA_TOO_LARGE
        }

        // The encoder reads 16-bit PCM of one or two channels, thus the
        // decoder gets a request for that form.
        input.setInteger(MediaFormat.KEY_PCM_ENCODING, android.media.AudioFormat.ENCODING_PCM_16BIT)
        input.setInteger(MediaFormat.KEY_MAX_OUTPUT_CHANNEL_COUNT, 2)

        val made = MediaCodec.createDecoderByType(input.getString(MediaFormat.KEY_MIME)!!)
        decoder = made
        made.configure(input, null, null, 0)
        made.start()

        val mux = MediaMuxer(memory, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        muxer = mux

        return Transcoder(extractor, made, mux, isCanceled) { rate, channels ->
            val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, rate, channels)
            format.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
            format.setInteger(MediaFormat.KEY_BIT_RATE, AUDIO_BIT_RATE)
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 64 * 1_024)
            MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_AAC).also {
                encoder = it
                it.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                it.start()
            }
        }.run()
    } catch (refused: FormRefused) {
        return MEDIA_FORM
    } catch (unreadable: Exception) {
        return -1
    } finally {
        for (codec in listOf(decoder, encoder)) {
            try {
                codec?.stop()
            } catch (stopped: IllegalStateException) {
                // A codec that did not start has nothing to stop.
            }
            codec?.release()
        }

        try {
            muxer?.release()
        } catch (stopped: IllegalStateException) {
            // A muxer that did not start has nothing to release.
        }

        extractor.release()
    }
}

/**
 * The loop of one transcode: the extractor feeds the decoder, the PCM of
 * the decoder feeds the encoder, and the encoder feeds the muxer. The
 * encoder starts when the decoder names its sample rate and its channels.
 */
private class Transcoder(
    private val extractor: MediaExtractor,
    private val decoder: MediaCodec,
    private val muxer: MediaMuxer,
    private val isCanceled: () -> Boolean,
    private val encoderFor: (rate: Int, channels: Int) -> MediaCodec,
) {
    private var encoder: MediaCodec? = null
    private var rate = 0
    private var channels = 0
    private var framesIn = 0L
    private var pending: ByteBuffer? = null
    private var track = -1
    private var lastUs = 0L
    private var muxedBytes = 0L
    private var hasMoved = false
    private val info = MediaCodec.BufferInfo()

    fun run(): Long {
        var extracted = false
        var decoded = false
        var encoded = false
        var pcmEnded = false
        var idleTurns = 0

        while (!encoded) {
            // A lock, a file above the bound, and a codec that gives no
            // end each end the loop. Without them one bad file holds the
            // media worker for each later send.
            if (isCanceled()) return -1
            if (muxedBytes > MAX_FILE_SIZE) return MEDIA_TOO_LARGE
            idleTurns = if (hasMoved) 0 else idleTurns + 1
            if (idleTurns > IDLE_TURNS_MAX) return -1
            hasMoved = false

            if (!extracted) extracted = feedDecoder()
            if (!decoded) decoded = drainDecoder()
            // A file that ends with no sample has nothing to encode.
            if (decoded && encoder == null) return -1
            if (decoded && !pcmEnded && pending == null) pcmEnded = endEncoder()
            if (pending != null) feedEncoder(pending!!)
            encoded = drainEncoder()
        }

        return lastUs
    }

    private fun feedDecoder(): Boolean {
        val index = decoder.dequeueInputBuffer(CODEC_WAIT_US)
        if (index < 0) return false
        val buffer = decoder.getInputBuffer(index) ?: return false

        val size = extractor.readSampleData(buffer, 0)
        hasMoved = true
        if (size < 0) {
            decoder.queueInputBuffer(index, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
            return true
        }

        decoder.queueInputBuffer(index, 0, size, extractor.sampleTime, 0)
        extractor.advance()
        return false
    }

    /** Takes one buffer of PCM, and gives whether the decoder ended. */
    private fun drainDecoder(): Boolean {
        if (pending != null) return false

        val index = decoder.dequeueOutputBuffer(info, CODEC_WAIT_US)
        if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
            // The encoder starts at the first sample, with the form that
            // stands then. Some decoders name one sample rate first and
            // the true one before the first sample.
            if (encoder != null) checkSame(decoder.outputFormat)
            return false
        }
        if (index < 0) return false

        hasMoved = true
        val ended = info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0
        if (info.size > 0) {
            if (encoder == null) start(decoder.outputFormat)
            val output = decoder.getOutputBuffer(index)!!
            output.position(info.offset)
            output.limit(info.offset + info.size)
            // The PCM goes on, thus the output buffer can go back now.
            pending = ByteBuffer.allocate(info.size).order(ByteOrder.nativeOrder()).put(output).also { it.flip() }
        }

        decoder.releaseOutputBuffer(index, false)
        return ended
    }

    private fun start(format: MediaFormat) {
        if (encoder != null) return

        rate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE)
        channels = format.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
        // AAC of the platform takes one or two channels.
        if (rate <= 0 || channels !in 1..2) throw FormRefused()

        // The encoder reads 16-bit PCM. A decoder that gives another form,
        // such as float samples of a 32-bit file, would encode noise.
        if (pcmOf(format) != android.media.AudioFormat.ENCODING_PCM_16BIT) throw FormRefused()

        encoder = encoderFor(rate, channels)
    }

    /** The form of the samples. A format that names none gives 16-bit PCM. */
    private fun pcmOf(format: MediaFormat): Int = if (format.containsKey(MediaFormat.KEY_PCM_ENCODING)) {
        format.getInteger(MediaFormat.KEY_PCM_ENCODING)
    } else {
        android.media.AudioFormat.ENCODING_PCM_16BIT
    }

    /**
     * Ends the transcode when the decoder changes its form after the
     * encoder started. The encoder keeps its first sample rate, thus the
     * rest of the file would play at a wrong speed.
     */
    private fun checkSame(format: MediaFormat) {
        val isSame = format.getInteger(MediaFormat.KEY_SAMPLE_RATE) == rate &&
            format.getInteger(MediaFormat.KEY_CHANNEL_COUNT) == channels &&
            pcmOf(format) == android.media.AudioFormat.ENCODING_PCM_16BIT
        if (!isSame) throw FormChanged()
    }

    private fun feedEncoder(pcm: ByteBuffer) {
        val codec = encoder ?: return
        val index = codec.dequeueInputBuffer(CODEC_WAIT_US)
        if (index < 0) return

        hasMoved = true
        val buffer = codec.getInputBuffer(index)!!
        buffer.clear()
        val size = minOf(buffer.remaining(), pcm.remaining())
        val slice = pcm.duplicate()
        slice.limit(slice.position() + size)
        buffer.put(slice)
        pcm.position(pcm.position() + size)

        // 16-bit PCM: two bytes for each sample of each channel.
        val presentationUs = framesIn * 1_000_000L / rate
        framesIn += size / (2 * channels)
        codec.queueInputBuffer(index, 0, size, presentationUs, 0)

        if (!pcm.hasRemaining()) pending = null
    }

    private fun endEncoder(): Boolean {
        val codec = encoder ?: return true
        val index = codec.dequeueInputBuffer(CODEC_WAIT_US)
        if (index < 0) return false

        hasMoved = true
        codec.queueInputBuffer(index, 0, 0, framesIn * 1_000_000L / rate, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
        return true
    }

    /** Moves the encoded frames to the muxer, and gives whether they ended. */
    private fun drainEncoder(): Boolean {
        val codec = encoder ?: return false

        val index = codec.dequeueOutputBuffer(info, CODEC_WAIT_US)
        if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
            track = muxer.addTrack(codec.outputFormat)
            muxer.start()
            hasMoved = true
            return false
        }
        if (index < 0) return false

        hasMoved = true
        val ended = info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0
        val isConfig = info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
        if (info.size > 0 && !isConfig && track >= 0) {
            val output = codec.getOutputBuffer(index)!!
            output.position(info.offset)
            output.limit(info.offset + info.size)
            muxer.writeSampleData(track, output, info)
            muxedBytes += info.size
            lastUs = maxOf(lastUs, info.presentationTimeUs)
        }

        codec.releaseOutputBuffer(index, false)
        if (ended && track >= 0) muxer.stop()
        return ended
    }
}
