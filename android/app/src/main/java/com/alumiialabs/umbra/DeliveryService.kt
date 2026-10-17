package com.alumiialabs.umbra

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/**
 * The persistent socket carrier of Part 8 §8.4.1. Android closes the sockets
 * of an app a short time after it leaves the screen. A foreground service
 * that the user can see keeps the process and its one connection, thus the
 * client takes a record when it arrives.
 *
 * The service holds no key and no socket of its own. It runs while the client
 * is unlocked, because a locked client holds no key that reads a queue
 * (`IMP-127`). In Direct mode it runs on after the lock, and it holds the
 * [Watcher] of the locked client (`NTF-142`).
 */
class DeliveryService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            startForeground(
                Notifier.CARRIER_ID,
                Notifier.carrier(this),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } catch (refused: IllegalStateException) {
            // The platform permits no foreground service at this moment.
            // The next view on the screen starts the carrier again.
            stopSelf()
            return START_NOT_STICKY
        }

        // A lock or a change to Off that came before this start ends the
        // service here: a stop before `startForeground` ends the process.
        val watches = !Core.wantsCarrier() && Core.wantsWatch(this)
        if (!Core.wantsCarrier() && !watches) {
            stopSelf()
            return START_NOT_STICKY
        }

        Core.carrierRuns(this, true)
        if (watches) Watcher.start(this)

        // A process that the platform starts again holds a locked client.
        // In Direct mode that client holds its watch, thus the platform
        // starts the service again; in each other mode it takes no record.
        return if (Modes.mode(this) == NotifyMode.Direct) START_STICKY else START_NOT_STICKY
    }

    override fun onDestroy() {
        Watcher.stop()
        Core.carrierRuns(this, false)
        super.onDestroy()
    }

    companion object {
        /**
         * Asks the platform for the service. Since Android 12 the platform
         * refuses the start of an app with no view on the screen, with a
         * `ForegroundServiceStartNotAllowedException`. The result is whether
         * the platform took the start.
         */
        fun start(context: Context): Boolean = try {
            context.startForegroundService(Intent(context, DeliveryService::class.java))
            true
        } catch (refused: IllegalStateException) {
            false
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, DeliveryService::class.java))
        }
    }
}
