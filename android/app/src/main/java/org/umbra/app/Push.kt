package org.umbra.app

import android.content.Context
import android.util.Base64
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import uniffi.umbra_ffi.openWakeBlob

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
        // Part 8 §8.3: Private mode and Off hold no token.
        if (!isAvailable(context) || Modes.mode(context) != NotifyMode.Instant) return
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        preferences.getString(WAITING_TOKEN, null)?.let { waiting ->
            Core.setFcmToken(waiting)
            preferences.edit().remove(WAITING_TOKEN).apply()
        }
        FirebaseMessaging.getInstance().token.addOnSuccessListener(Core::setFcmToken)
    }

    /** Firebase gave a new token. A locked client takes it at the unlock. */
    fun tokenChanged(context: Context, token: String) {
        if (Modes.mode(context) != NotifyMode.Instant) return
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
     * sees. An open client takes the record over its own run. A locked one
     * opens the blob with the wake table, and the alert of the conversation
     * shows that a message waits, with no name and no text (`NTF-136`); the
     * record stays at the relay. The lock screen shows that an alert exists
     * and no more (`NTF-119`).
     */
    override fun onMessageReceived(message: RemoteMessage) {
        val app = applicationContext
        // The blob opens in each state, thus an open client counts it too
        // (NTF-078, NTF-079).
        val conversation = waiting(app, message.data["b"])
        if (Core.isOpen()) {
            Notifier.pushed(app)
            Core.wake(app)
            return
        }
        // A locked client reads no setting of a conversation, thus each
        // later push of one conversation makes no second sound.
        if (conversation != null) {
            Notifier.message(app, conversation, quiet = true)
        } else {
            Notifier.pushed(app)
        }
    }

    /** The conversation of a blob that the wake table opens, or none. */
    private fun waiting(app: android.content.Context, encoded: String?): Conversation? {
        if (Modes.mode(app) != NotifyMode.Instant) return null
        val blob = encoded?.let {
            runCatching { Base64.decode(it, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }
                .getOrNull()
        } ?: return null
        val table = WakeStore.read(app) ?: return null
        val outcome = try {
            openWakeBlob(table, blob, (System.currentTimeMillis() / 1_000).toULong())
        } finally {
            table.fill(0)
        }
        // NTF-076: a blob outside the window ran no open, thus it counts
        // toward no failure.
        when (outcome.status.toInt()) {
            0 -> WakeStore.opened(app)
            2 -> WakeStore.failed(app)
        }
        return outcome.conversation?.let(::Conversation)
    }
}
