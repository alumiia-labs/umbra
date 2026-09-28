package org.umbra.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

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

    private fun manager(context: Context) =
        context.getSystemService(NotificationManager::class.java)

    fun makeChannels(context: Context) {
        val carrier = NotificationChannel(
            CARRIER_CHANNEL,
            "Connection",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "Shows that UMBRA holds a connection to take messages." }
        val messages = NotificationChannel(
            MESSAGE_CHANNEL,
            "Messages",
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

    private fun mayPost(context: Context) =
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    /** The notice of the foreground service, which the platform requires. */
    fun carrier(context: Context): Notification =
        Notification.Builder(context, CARRIER_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle("UMBRA holds a connection")
            .setContentText("Messages arrive until the app locks.")
            .setContentIntent(openApp(context))
            .setOngoing(true)
            .build()

    /** One alert for each conversation. A later record updates that alert. */
    fun message(context: Context, conversation: Conversation, title: String? = null, text: String? = null) {
        if (!mayPost(context)) return
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(title ?: "New message")
            .apply { if (!text.isNullOrEmpty()) setContentText(text) }
            .setGroup(conversation.label)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            // The lock screen shows that an alert exists, and no more.
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        manager(context).notify(MESSAGE_TAG, conversation.hashCode(), alert)
    }

    /**
     * The alert of a push (Part 8 rule `NTF-014`). It names no conversation,
     * and a later push takes its place.
     */
    fun pushed(context: Context) {
        if (!mayPost(context)) return
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle("New message")
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        manager(context).notify(MESSAGE_TAG, PUSH_ID, alert)
    }

    /**
     * A locked client takes no record. The user learns it one time for each
     * lock, and the notice makes no sound.
     */
    /** A contact request arrived. The line names no sender. */
    fun request(context: Context) {
        if (!mayPost(context)) return
        val alert = Notification.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle("New contact request")
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        manager(context).notify(MESSAGE_TAG, REQUEST_ID, alert)
    }

    fun locked(context: Context) {
        if (!mayPost(context)) return
        val notice = Notification.Builder(context, CARRIER_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle("UMBRA is locked")
            .setContentText("Open the app to take messages.")
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        manager(context).notify(LOCKED_ID, notice)
    }

    /** The user looks at the app, thus each alert is old. */
    fun clear(context: Context) {
        val manager = manager(context)
        manager.activeNotifications
            .filter { it.tag == MESSAGE_TAG || it.id == LOCKED_ID }
            .forEach { manager.cancel(it.tag, it.id) }
    }
}
