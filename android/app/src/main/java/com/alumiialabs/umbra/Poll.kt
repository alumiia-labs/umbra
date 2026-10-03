package com.alumiialabs.umbra

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * The poll: the carrier of a build with no Firebase app, beside the
 * connection of the foreground service. Each 15 minutes, the least period
 * of the platform, an open client whose run the platform ended starts a new
 * one, and the run drains each queue. A locked client holds no key of a
 * queue, thus the poll finds nothing to do then.
 */
object Poll {
    const val NAME = "poll"

    fun schedule(context: Context) {
        val request = PeriodicWorkRequestBuilder<PollWorker>(15, TimeUnit.MINUTES).build()
        // UPDATE replaces a stored schedule, thus one that names a worker of
        // an earlier build moves to this one.
        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }
}

class PollWorker(context: Context, parameters: WorkerParameters) : Worker(context, parameters) {
    override fun doWork(): Result {
        if (Core.isOpen()) Core.wake(applicationContext)
        return Result.success()
    }
}
