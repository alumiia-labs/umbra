package org.umbra.app

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.io.File
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.Handle
import uniffi.umbra_ffi.Network
import uniffi.umbra_ffi.fetchManifest
import uniffi.umbra_ffi.parseNetwork

/**
 * The network of the debug build. With no descriptor it is the six relays
 * of `scripts/devnet.sh` on the machine of the developer. The seven test
 * authorities of that script sign a relay manifest at each start, and the
 * ingress relay gives it over HTTPS. The client verifies it under the key
 * set of those authorities, which this build ships. With no answer the
 * client takes the manifest of the last run. An emulator reaches the
 * ingress relay at 10.0.2.2, under the test authority of the repository. The seeds of those relays and authorities are
 * in the repository, thus that network protects nothing.
 *
 * A tester pastes the descriptor of a deployed test network, and the build
 * then dials that network under the web roots. The release build has no such
 * panel, because the relay directory of Part 10 gives its network.
 */
object BuildNetwork {
    private const val AUTHORITY = "devnet-ca.pem"
    private const val KEYSET = "devnet-keyset.bin"
    private const val MANIFEST = "devnet-manifest.bin"
    private const val DESCRIPTOR = "network-descriptor.txt"

    // No party serves this host.
    private const val INVITATION_HOST = "invite.umbra.test"

    // The carrier of the manifest: the ingress relay of the devnet.
    private const val CARRIER_HOST = "localhost"
    private val CARRIER_ADDRESS = byteArrayOf(10, 0, 2, 2)
    private const val CARRIER_PORT: UShort = 7441u

    /** Whether the time of the last manifest differs from the device clock. */
    var isClockCorrected = false
        private set

    private fun descriptorFile(context: Context) = File(context.filesDir, DESCRIPTOR)

    /** The descriptor of a deployed test network, or null for the local one. */
    fun imported(context: Context): String? =
        descriptorFile(context).takeIf { it.exists() }?.readText()

    /** Keeps a descriptor that parses. A null value goes back to the local network. */
    fun import(context: Context, descriptor: String?): Boolean {
        if (descriptor == null) {
            descriptorFile(context).delete()
            return true
        }
        return try {
            parseNetwork(descriptor, null)
            descriptorFile(context).writeText(descriptor)
            true
        } catch (malformed: FfiException) {
            false
        }
    }

    fun network(context: Context, client: Handle): Network? {
        imported(context)?.let { return parseNetwork(it, null) }
        // The TLS stack of the Rust side reads a file, and an asset is none.
        val authority = File(context.filesDir, AUTHORITY)
        context.assets.open(AUTHORITY).use { source ->
            authority.outputStream().use { source.copyTo(it) }
        }
        val keyset = context.assets.open(KEYSET).use { it.readBytes() }
        val kept = File(context.filesDir, MANIFEST)
        val fresh = try {
            fetchManifest(CARRIER_HOST, CARRIER_ADDRESS, CARRIER_PORT, authority.absolutePath)
        } catch (offline: FfiException) {
            null
        }
        // The fresh manifest first, and then the one of the last run. The
        // file takes a manifest that verified alone (`NET-318`).
        for (manifest in listOfNotNull(fresh, kept.takeIf { it.exists() }?.readBytes())) {
            val verified = try {
                // The debug build ships no epoch, thus the store alone bounds
                // the age of a manifest.
                client.networkOfManifest(
                    manifest,
                    keyset,
                    0uL,
                    INVITATION_HOST,
                    authority.absolutePath,
                )
            } catch (refused: FfiException) {
                continue
            }
            if (manifest === fresh) kept.writeBytes(manifest)
            isClockCorrected = verified.isClockCorrected
            return verified.network
        }
        return null
    }

    /** The panel of the unlock view that takes a descriptor. */
    @Composable
    fun Panel() {
        val context = LocalContext.current
        var isOpen by remember { mutableStateOf(false) }
        var pasted by remember { mutableStateOf("") }
        var note by remember { mutableStateOf<String?>(null) }
        var isImported by remember { mutableStateOf(imported(context) != null) }
        Column(Modifier.padding(top = 24.dp)) {
            TextButton(onClick = { isOpen = !isOpen }) {
                Text(if (isImported) "Test network: imported" else "Test network: local")
            }
            if (!isOpen) return@Column
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("A network descriptor") },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    autoCorrectEnabled = false,
                ),
                maxLines = 6,
                modifier = Modifier.fillMaxWidth(),
            )
            Row {
                Button(
                    enabled = pasted.isNotBlank(),
                    onClick = {
                        val isKept = import(context, pasted)
                        note = if (isKept) "Kept. The next run dials it." else "It does not parse."
                        if (isKept) {
                            isImported = true
                            pasted = ""
                        }
                    },
                ) { Text("Use") }
                TextButton(
                    enabled = isImported,
                    onClick = {
                        import(context, null)
                        isImported = false
                        note = "The next run dials the local network."
                    },
                ) { Text("Back to the local network") }
            }
            note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
