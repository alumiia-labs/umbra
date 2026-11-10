package com.alumiialabs.umbra

import android.app.Application

/**
 * The process of the app. A push or a restart of the service starts the
 * process with no activity, and each of them posts a notice.
 */
class UmbraApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // A notice on a channel that does not exist is dropped, and a
        // foreground service on such a channel ends the process. An update
        // can add a channel, thus each start of the process makes them.
        Notifier.makeChannels(this)
    }
}
