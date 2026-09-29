package org.umbra.app

import android.content.Context
import androidx.compose.runtime.Composable
import uniffi.umbra_ffi.Handle
import uniffi.umbra_ffi.Network

/**
 * The network of the release build. The relay directory of Part 10 gives it,
 * and the client does not read that directory yet, thus this build has none.
 */
object BuildNetwork {
    const val isClockCorrected = false

    const val isProvisional = false

    fun network(context: Context, client: Handle): Network? = null

    /** The release build takes no descriptor from the user. */
    @Composable
    fun Panel() = Unit
}
