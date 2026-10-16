package com.alumiialabs.umbra

import android.content.Context
import java.util.concurrent.Executors
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.Watch
import uniffi.umbra_ffi.WatchListener
import uniffi.umbra_ffi.startWatch

/**
 * The watch of a locked client in Direct mode (Part 8 §8.4.3). It holds the
 * notifier credential of each queue and no key of the store, thus it sees
 * that a record arrived and reads none. It runs under the foreground
 * service, and each blob shows that a message waits in its conversation,
 * as a push of Instant mode does (`NTF-136`).
 */
object Watcher : WatchListener {
    // A start reads the keystore, thus it runs off the main thread, and one
    // thread orders each start and stop.
    private val worker = Executors.newSingleThreadExecutor()

    @Volatile
    private var app: Context? = null

    /** The watch that runs. The worker alone touches it. */
    private var watch: Watch? = null

    /**
     * Starts the watch from the sealed table of the last open client. With
     * no table that opens, the service ends, and the user learns that no
     * message arrives until the unlock (`NTF-120`).
     */
    fun start(context: Context) {
        val app = context.applicationContext
        this.app = app
        worker.execute {
            if (watch != null) return@execute
            val table = WakeStore.readWatch(app)
            watch = table?.let {
                try {
                    startWatch(it, this)
                } catch (refused: FfiException) {
                    null
                } finally {
                    it.fill(0)
                }
            }
            if (watch != null) {
                Notifier.refreshCarrier(app)
            } else if (!Core.isOpen()) {
                DeliveryService.stop(app)
                Notifier.locked(app)
            }
        }
    }

    /** Ends the watch: at the unlock, and when the service ends. */
    fun stop() {
        worker.execute {
            watch?.let {
                it.stop()
                it.destroy()
            }
            watch = null
        }
    }

    // An exception that crosses into Rust ends the process.
    override fun wake(blob: ByteArray) {
        try {
            val app = app ?: return
            // An open client takes the record over its own run.
            if (Core.isOpen()) return
            val conversation = WakeStore.openBlob(app, blob)
            if (WakeStore.isSilent(conversation)) return
            Notifier.waiting(app, conversation)
        } catch (fault: Exception) {
            if (BuildConfig.DEBUG) android.util.Log.w("umbra-watch", "a wake failed", fault)
        }
    }

    /**
     * The watch gave up: its table names no session that can connect. The
     * service ends, and the user learns that no message arrives until the
     * unlock (`NTF-120`, `NTF-142`).
     */
    override fun down() {
        try {
            val app = app ?: return
            worker.execute {
                watch?.let {
                    it.stop()
                    it.destroy()
                }
                watch = null
                if (!Core.isOpen()) {
                    DeliveryService.stop(app)
                    Notifier.locked(app)
                }
            }
        } catch (fault: Exception) {
            if (BuildConfig.DEBUG) android.util.Log.w("umbra-watch", "a down failed", fault)
        }
    }
}
