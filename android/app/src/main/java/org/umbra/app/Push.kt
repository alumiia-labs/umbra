package org.umbra.app

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * The FCM carrier of Part 8 §8.4.1. A build with the `google-services.json`
 * of the Firebase project of the deployment has a Firebase app, and each
 * other build runs with no push. The token goes to the core, which registers
 * each handle group with the NDR under it; the token of a locked client
 * waits here until the unlock.
 */
object Push {
    private const val PREFERENCES = "push"
    private const val WAITING_TOKEN = "fcm-token"

    /** Whether this build has a Firebase app. */
    fun isAvailable(context: Context) = FirebaseApp.getApps(context).isNotEmpty()

    /** The client opened: it takes the token of this device. */
    fun opened(context: Context) {
        if (!isAvailable(context)) return
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        preferences.getString(WAITING_TOKEN, null)?.let { waiting ->
            Core.setFcmToken(waiting)
            preferences.edit().remove(WAITING_TOKEN).apply()
        }
        FirebaseMessaging.getInstance().token.addOnSuccessListener(Core::setFcmToken)
    }

    /** Firebase gave a new token. A locked client takes it at the unlock. */
    fun tokenChanged(context: Context, token: String) {
        if (Core.isOpen()) {
            Core.setFcmToken(token)
        } else {
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putString(WAITING_TOKEN, token)
                .apply()
        }
    }
}

/** The receiver of FCM: a new token, and a push. */
class PushService : FirebaseMessagingService() {
    override fun onNewToken(token: String) = Push.tokenChanged(applicationContext, token)

    /**
     * NTF-014: each push of high priority shows an alert that the user
     * sees. The blob names no conversation that this build reads while
     * locked, thus the alert names none, and the lock screen shows that it
     * exists and no more (`NTF-119`).
     */
    override fun onMessageReceived(message: RemoteMessage) {
        Notifier.pushed(applicationContext)
        // An open client takes the record over its own run.
        if (Core.isOpen()) Core.wake(applicationContext)
    }
}
