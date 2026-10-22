package com.alumiialabs.umbra

import android.app.ActivityManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource

/** The battery setting of the app in the system settings. */
enum class BatteryState { Unrestricted, Optimized, Restricted }

/**
 * The battery state as Direct mode needs it. Direct mode holds its own
 * connection with no push. An optimized app can relink late after its link
 * drops in Doze, and a restricted app can lose its service.
 */
object Battery {
    private const val PREFERENCES = "battery"
    private const val NOTED = "noted"

    /** The user changes the state in the system settings, thus each return to the screen reads it again. */
    var state by mutableStateOf(BatteryState.Unrestricted)
        private set

    /** Whether the user answered the card once. */
    var isNoted by mutableStateOf(false)
        private set

    fun read(context: Context) {
        val power = context.getSystemService(PowerManager::class.java)
        val activity = context.getSystemService(ActivityManager::class.java)
        state = when {
            activity.isBackgroundRestricted -> BatteryState.Restricted
            power.isIgnoringBatteryOptimizations(context.packageName) -> BatteryState.Unrestricted
            else -> BatteryState.Optimized
        }
        isNoted = preferences(context).getBoolean(NOTED, false)
    }

    /** Whether Direct mode can deliver late or stop on this device. */
    fun slowsDirect(context: Context): Boolean =
        Modes.mode(context) == NotifyMode.Direct && state != BatteryState.Unrestricted

    fun note(context: Context) {
        preferences(context).edit().putBoolean(NOTED, true).apply()
        isNoted = true
    }

    /**
     * Opens the system answer. An optimized app asks for the exemption in one
     * dialog. A restriction, and the return to optimization, have their
     * switch on the page of the app alone.
     */
    fun open(context: Context) {
        val app = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
        val ask = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}"))
        val intent = if (state == BatteryState.Optimized) ask else app
        try {
            context.startActivity(intent)
        } catch (absent: ActivityNotFoundException) {
            context.startActivity(app)
        }
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
}

@Composable
fun batteryLine(): String =
    if (Battery.state == BatteryState.Restricted) {
        stringResource(R.string.battery_restricted)
    } else {
        stringResource(R.string.battery_optimized)
    }

/** The cost of the battery state under the switch of the notification settings. */
@Composable
fun batteryDetail(): String? = when (Battery.state) {
    BatteryState.Unrestricted -> null
    BatteryState.Optimized -> stringResource(R.string.battery_late)
    BatteryState.Restricted -> stringResource(R.string.battery_stops)
}
