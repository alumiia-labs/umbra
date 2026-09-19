package org.umbra.app

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
 * (`IMP-127`).
 */
class DeliveryService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(
            Notifier.CARRIER_ID,
            Notifier.carrier(this),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
        Core.carrierRuns(this, true)
        // A process that the platform starts again holds a locked client,
        // and a locked client takes no record. Thus no restart is asked for.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        Core.carrierRuns(this, false)
        super.onDestroy()
    }

    companion object {
        fun start(context: Context) {
            context.startForegroundService(Intent(context, DeliveryService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, DeliveryService::class.java))
        }
    }
}
