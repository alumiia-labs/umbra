package com.alumiialabs.umbra

import android.Manifest
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build

/**
 * The notifications of the app. A message alert holds no text of the message
 * and no name, because the content preview is off in the shipped default
 * (`NTF-083`). The tray groups the alerts by conversation on the device
 * (`NTF-089`), thus no party outside the device sees a conversation count.
 */
object Notifier {
    const val CARRIER_ID = 1
    private const val LOCKED_ID = 2
    private const val PUSH_ID = 3
    private const val REQUEST_ID = 4

    // The platform keeps the settings of a channel that exists, thus the
    // channel with no badge takes a new identifier, and the old one leaves.
    private const val CARRIER_CHANNEL = "connection"
    private const val OLD_CARRIER_CHANNEL = "carrier"
    private const val MESSAGE_CHANNEL = "messages"
    private const val MESSAGE_TAG = "message"

    /**
     * The conversations that the alert of a push stands for, by their key.
     * Null stands for a push that named none.
     */
    private val pushOwed = HashSet<String?>()

    /** Each alert that shows a sender or a text, by its identifier, with its group. */
    private val withContent = HashMap<Int, String>()

    private var watchesScreen = false

    private fun manager(context: Context) =
        context.getSystemService(NotificationManager::class.java)

    fun makeChannels(context: Context) {
        val carrier = NotificationChannel(
            CARRIER_CHANNEL,
            context.getString(R.string.common_connection),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notify_channel_connection_about)
            // The notice of the service is no message, thus the icon of the
            // app shows no count for it.
            setShowBadge(false)
        }

        val messages = NotificationChannel(
            MESSAGE_CHANNEL,
            context.getString(R.string.notify_channel_messages),
            NotificationManager.IMPORTANCE_HIGH,
        )

        manager(context).createNotificationChannels(listOf(carrier, messages))
        // A service whose notice still stands on the old channel keeps it,
        // and a later start deletes it.
        runCatching { manager(context).deleteNotificationChannel(OLD_CARRIER_CHANNEL) }
    }

    private fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    // Below API 33 the platform defines no POST_NOTIFICATIONS, and its check
    // answers denied; the setting of the user decides there (NTF-014).
    private fun mayPost(context: Context) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        } else {
            manager(context).areNotificationsEnabled()
        }

    /**
     * The notice of the foreground service, which the platform requires. A
     * locked client in Direct mode holds the watch under it (`NTF-142`).
     */
    fun carrier(context: Context): Notification {
        val watches = !Core.isOpen() && Modes.mode(context) == NotifyMode.Direct
        val title = when {
            watches -> R.string.notify_locked
            // Private mode holds no connection between two wakes of its clock.
            Modes.mode(context) == NotifyMode.Private -> R.string.notify_unlocked
            else -> when (Core.linkState) {
                LinkState.Connected -> R.string.notify_holds_connection
                LinkState.Connecting -> R.string.connection_connecting
                LinkState.Down -> R.string.connection_offline
            }
        }

        // The notice names the state alone: the user knows the app.
        return Notification.Builder(context, CARRIER_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(context.getString(title))
            .setContentIntent(openApp(context))
            .setOngoing(true)
            .build()
    }

    /** Shows the current state of the client and of its link in the notice of the service. */
    fun refreshCarrier(context: Context) {
        manager(context).notify(CARRIER_ID, carrier(context))
    }

    /**
     * A locked client learned that a message waits: from a push, or from
     * its watch (`NTF-136`). It reads no setting of a conversation, thus
     * each later wake of one conversation makes no second sound.
     */
    fun waiting(context: Context, conversation: Conversation?) {
        if (conversation != null) message(context, conversation, quiet = true) else pushed(context)
    }

    /** The form of an alert on a secure lock screen: that one exists. */
    private fun lockScreen(context: Context): Notification =
        Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(context.getString(R.string.common_new_message))
            .build()

    /**
     * One alert for each conversation. A later record updates that alert,
     * and a `quiet` update makes no second sound (`NTF-018`).
     */
    fun message(
        context: Context,
        conversation: Conversation,
        title: String? = null,
        text: CharArray? = null,
        quiet: Boolean = false,
    ) {
        if (!mayPost(context)) {
            text?.fill('\u0000')
            return
        }

        // NTF-119: the system setting that shows all content ignores the
        // public version, thus a locked device gets the bare alert.
        val shows = (title != null || (text != null && text.isNotEmpty())) && !isDeviceLocked(context)
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(title?.takeIf { shows } ?: context.getString(R.string.common_new_message))
            .apply { if (shows && text != null && text.isNotEmpty()) setContentText(java.nio.CharBuffer.wrap(text)) }
            .setGroup(conversation.label)
            .setOnlyAlertOnce(quiet)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen(context))
            .build()

        val id = conversation.hashCode()
        // NTF-018: the alert of the conversation takes the place of the alert
        // of its push, thus one message shows one alert.
        synchronized(pushOwed) { pushOwed.clear() }
        manager(context).cancel(MESSAGE_TAG, PUSH_ID)
        synchronized(withContent) {
            if (shows) withContent[id] = conversation.label else withContent.remove(id)
        }

        if (shows) watchScreen(context)
        manager(context).notify(MESSAGE_TAG, id, alert)
        text?.fill('\u0000')
    }

    private fun isDeviceLocked(context: Context): Boolean {
        val keyguard = context.getSystemService(KeyguardManager::class.java) ?: return true
        return keyguard.isKeyguardLocked || keyguard.isDeviceLocked
    }

    /**
     * NTF-119: the screen goes off before the lock screen shows, thus each
     * alert with a sender or a text takes its bare form then, with no sound.
     */
    private fun watchScreen(context: Context) {
        val app = context.applicationContext
        synchronized(withContent) {
            if (watchesScreen) return
            watchesScreen = true
        }

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) = hideContent(app)
        }

        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            app.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            app.registerReceiver(receiver, filter)
        }
    }

    private fun hideContent(context: Context) {
        val shown = synchronized(withContent) { HashMap(withContent).also { withContent.clear() } }
        if (shown.isEmpty()) return

        val manager = manager(context)
        val active = manager.activeNotifications.filter { it.tag == MESSAGE_TAG }.map { it.id }.toSet()

        for ((id, group) in shown) {
            if (id !in active) continue

            val bare = Notification.Builder(context, MESSAGE_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_umbra)
                .setContentTitle(context.getString(R.string.common_new_message))
                .setGroup(group)
                .setOnlyAlertOnce(true)
                .setAutoCancel(true)
                .setContentIntent(openApp(context))
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(lockScreen(context))
                .build()
            manager.notify(MESSAGE_TAG, id, bare)
        }
    }

    /**
     * The alert of a push (Part 8 rule `NTF-014`). It names no conversation,
     * and a later push takes its place with no second sound, thus a digest
     * push and a re-push make no alert of each record (`NTF-018`). An open
     * client gives the conversation of the push when the wake table named
     * one.
     */
    fun pushed(context: Context, conversation: Conversation? = null) {
        if (!mayPost(context)) return

        synchronized(pushOwed) { pushOwed.add(conversation?.key) }
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(context.getString(R.string.common_new_message))
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen(context))
            .build()
        manager(context).notify(MESSAGE_TAG, PUSH_ID, alert)
    }

    /**
     * The record of a push arrived, and the setting of its conversation
     * shows no alert for it. The alert of the push ends when it stands for
     * no other push.
     */
    fun pushSettled(context: Context, conversation: Conversation) {
        synchronized(pushOwed) {
            if (!pushOwed.remove(conversation.key) || pushOwed.isNotEmpty()) return
        }

        manager(context).cancel(MESSAGE_TAG, PUSH_ID)
    }

    /** A contact request arrived. The line names no sender. */
    fun request(context: Context) {
        if (!mayPost(context)) return

        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(context.getString(R.string.notify_new_contact_request))
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen(context))
            .build()
        manager(context).notify(MESSAGE_TAG, REQUEST_ID, alert)
    }

    /**
     * A locked client takes no record. The user learns it one time for each
     * lock, and the notice makes no sound.
     */
    fun locked(context: Context) {
        if (!mayPost(context)) return

        val notice = Notification.Builder(context, CARRIER_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(context.getString(R.string.notify_locked))
            .setContentText(context.getString(R.string.notify_open_to_take))
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        manager(context).notify(LOCKED_ID, notice)
    }

    /** The user looks at the app, thus each alert is old. */
    fun clear(context: Context) {
        synchronized(pushOwed) { pushOwed.clear() }
        synchronized(withContent) { withContent.clear() }

        val manager = manager(context)
        manager.activeNotifications
            .filter { it.tag == MESSAGE_TAG || it.id == LOCKED_ID }
            .forEach { manager.cancel(it.tag, it.id) }
    }
}
