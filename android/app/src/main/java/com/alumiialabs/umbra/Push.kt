package com.alumiialabs.umbra

import android.content.Context
import android.util.Base64
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * The FCM carrier of Part 8 §8.4.1. A build with the `google-services.json`
 * of the Firebase project of the deployment has a Firebase app, and each
 * other build runs with no push. The token goes to the core, which registers
 * each handle group with the NDR under it in Instant mode, or the timer of
 * Periodic mode (§8.2.8); the token of a locked client waits here until the
 * unlock.
 */
object Push {
    private const val PREFERENCES = "push"
    private const val WAITING_TOKEN = "fcm-token"
    private const val TOKEN_HELD = "fcm-token-held"
    /** The mode that the token of Firebase serves now. */
    private const val TOKEN_FOR = "fcm-token-for"

    /** Whether this build has a Firebase app. */
    fun isAvailable(context: Context) = FirebaseApp.getApps(context).isNotEmpty()

    /** Whether the mode holds a token: Instant mode and Periodic mode. */
    private fun holdsToken(mode: NotifyMode) = mode == NotifyMode.Instant || mode == NotifyMode.Periodic

    /** The token goes to the core under the mode that it serves. */
    private fun give(mode: NotifyMode, token: String) = when (mode) {
        NotifyMode.Instant -> Core.setFcmToken(token)
        NotifyMode.Periodic -> Core.setFcmTimerToken(token)
        else -> Unit
    }

    /** The client opened: it takes the token of this device. */
    fun opened(context: Context) {
        // Part 8 §8.3: Direct mode, Private mode, and Off hold no token.
        val mode = Modes.mode(context)
        if (!isAvailable(context) || !holdsToken(mode)) return

        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        // An earlier build held a token in Instant mode alone, and wrote no
        // mode for it.
        val heldFor = preferences.getString(TOKEN_FOR, null)
            ?: NotifyMode.Instant.name.takeIf { preferences.getBoolean(TOKEN_HELD, true) }
        preferences.getString(WAITING_TOKEN, null)?.let { waiting ->
            if (heldFor == mode.name) give(mode, waiting)
            preferences.edit().remove(WAITING_TOKEN).apply()
        }

        // The manifest turns the start of Firebase by itself off, thus a
        // device makes a token in a mode that holds one alone (`NTF-045`).
        val firebase = FirebaseMessaging.getInstance()
        firebase.isAutoInitEnabled = true
        preferences.edit().putBoolean(TOKEN_HELD, true).apply()

        // NTF-151: a change between Instant mode and Periodic mode takes a
        // new token, thus the token of the timer was never the token of a
        // handle group.
        if (heldFor != null && heldFor != mode.name) {
            firebase.deleteToken().addOnCompleteListener { fetch(context, mode) }
        } else {
            fetch(context, mode)
        }
    }

    private fun fetch(context: Context, mode: NotifyMode) {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            // A change of the mode since the call takes its own token.
            if (Modes.mode(context) != mode) return@addOnSuccessListener

            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putString(TOKEN_FOR, mode.name)
                .apply()
            give(mode, token)
        }
    }

    /**
     * The mode left Instant or Periodic: Firebase makes no token by itself,
     * and it deletes the one that it holds. A delete that did not reach
     * Firebase runs again at the next open. After the delete this calls
     * nothing, thus Direct mode, Private mode, and Off give Firebase no time
     * of an open. An earlier build wrote no mark and made a token at each
     * launch, thus no mark reads as a token.
     */
    fun closed(context: Context) {
        if (!isAvailable(context)) return

        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        preferences.edit().remove(WAITING_TOKEN).apply()
        if (!preferences.getBoolean(TOKEN_HELD, true)) return

        val firebase = FirebaseMessaging.getInstance()
        firebase.isAutoInitEnabled = false
        firebase.deleteToken().addOnSuccessListener {
            // A change back to a mode with a token since then holds a new one.
            if (!holdsToken(Modes.mode(context))) {
                preferences.edit().putBoolean(TOKEN_HELD, false).remove(TOKEN_FOR).apply()
            }
        }
    }

    /** Firebase gave a new token. A locked client takes it at the unlock. */
    fun tokenChanged(context: Context, token: String) {
        val mode = Modes.mode(context)
        if (!holdsToken(mode)) return

        if (Core.isOpen()) {
            give(mode, token)
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
     * and no more (`NTF-119`). In each state a push of a blocked contact, of
     * a conversation with its alerts off, and of a sync channel shows none
     * (`ABU-029`).
     */
    override fun onMessageReceived(message: RemoteMessage) {
        val app = applicationContext
        // NTF-153: a tick of the clock of Periodic mode names nothing, and
        // it shows no alert by itself.
        if (message.data["t"] != null) {
            PeriodicTick.run(app)
            return
        }

        // The blob opens in each state, thus an open client counts it too
        // (NTF-078, NTF-079).
        val conversation = waiting(app, message.data["b"])
        // A blob that the table names silent opened, and it shows no
        // alert. An open client writes the table at each change of a block
        // and of an alert setting, thus the table decides for it too.
        val isSilent = WakeStore.isSilent(conversation)

        if (Core.isOpen()) {
            // A view on the screen shows the message itself. The alert of
            // the record takes the place of this one, or ends it.
            if (!isSilent && !Core.isOnScreen()) Notifier.pushed(app, conversation)
            Core.wake(app)
            return
        }

        if (isSilent) return
        Notifier.waiting(app, conversation)
    }

    /** The conversation of a blob that the wake table opens, or none. */
    private fun waiting(app: android.content.Context, encoded: String?): Conversation? {
        if (Modes.mode(app) != NotifyMode.Instant) return null

        val blob = encoded?.let {
            runCatching { Base64.decode(it, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }
                .getOrNull()
        } ?: return null
        return WakeStore.openBlob(app, blob)
    }
}
