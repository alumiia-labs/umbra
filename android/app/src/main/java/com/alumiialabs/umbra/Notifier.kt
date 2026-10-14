package com.alumiialabs.umbra

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
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
    private const val CARRIER_CHANNEL = "carrier"
    private const val MESSAGE_CHANNEL = "messages"
    private const val MESSAGE_TAG = "message"

    /**
     * The conversations that the alert of a push stands for, by their key.
     * Null stands for a push that named none.
     */
    private val pushOwed = HashSet<String?>()

    private fun manager(context: Context) =
        context.getSystemService(NotificationManager::class.java)

    fun makeChannels(context: Context) {
        val carrier = NotificationChannel(
            CARRIER_CHANNEL,
            context.getString(R.string.common_connection),
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = context.getString(R.string.notify_channel_connection_about) }
        val messages = NotificationChannel(
            MESSAGE_CHANNEL,
            context.getString(R.string.notify_channel_messages),
            NotificationManager.IMPORTANCE_HIGH,
        )
        manager(context).createNotificationChannels(listOf(carrier, messages))
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

    /** The notice of the foreground service, which the platform requires. */
    fun carrier(context: Context): Notification =
        Notification.Builder(context, CARRIER_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            // Private mode holds no connection between two wakes of its clock.
            .setContentTitle(
                context.getString(
                    if (Modes.mode(context) == NotifyMode.Private) R.string.notify_unlocked else R.string.notify_holds_connection,
                ),
            )
            .setContentText(context.getString(R.string.notify_arrive_until_lock))
            .setContentIntent(openApp(context))
            .setOngoing(true)
            .build()

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
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(title ?: context.getString(R.string.common_new_message))
            .apply { if (text != null && text.isNotEmpty()) setContentText(java.nio.CharBuffer.wrap(text)) }
            .setGroup(conversation.label)
            .setOnlyAlertOnce(quiet)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            // NTF-119: the lock screen shows that an alert exists, and no
            // more.
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen(context))
            .build()
        // NTF-018: the alert of the conversation takes the place of the alert
        // of its push, thus one message shows one alert.
        synchronized(pushOwed) { pushOwed.clear() }
        manager(context).cancel(MESSAGE_TAG, PUSH_ID)
        manager(context).notify(MESSAGE_TAG, conversation.hashCode(), alert)
        text?.fill('\u0000')
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
        val manager = manager(context)
        manager.activeNotifications
            .filter { it.tag == MESSAGE_TAG || it.id == LOCKED_ID }
            .forEach { manager.cancel(it.tag, it.id) }
    }
}
