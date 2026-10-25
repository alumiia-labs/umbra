package com.alumiialabs.umbra

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
 * The network of the debug build. With no descriptor it is the seven relays
 * of `scripts/devnet.sh` on the machine of the developer. The seven test
 * authorities of that script sign a relay manifest at each start, and the
 * ingress relay gives it over HTTPS. The client verifies it under the key
 * set of those authorities, which this build ships. With no answer the
 * client takes the manifest of the last run. The client dials the ingress
 * relay at `BuildConfig.DEVNET_HOST`, under the test authority of the
 * repository: 10.0.2.2 for an emulator, or the address of the machine on
 * the local network for a phone. The seeds of those relays and authorities are
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
    private const val NDR_KEY = "devnet-ndr-key.bin"
    private const val DIRECTORY_PINS = "devnet-directory-pins.bin"

    // The OHTTP relay of the NDR of the devnet: its ingress relay.
    private const val NDR_RELAY_URL = "https://localhost:7441/ohttp"

    // The relay of the directory of the devnet: the same ingress relay.
    private const val DIRECTORY_RELAY_URL = "https://localhost:7441/directory"

    // No party serves this host.
    private const val INVITATION_HOST = "invite.umbra.test"

    // The carrier of the manifest: the ingress relay of the devnet.
    private const val CARRIER_HOST = "localhost"
    private val CARRIER_ADDRESS =
        BuildConfig.DEVNET_HOST.split('.').map { it.toInt().toByte() }.toByteArray()
    private const val CARRIER_PORT: UShort = 7441u

    /** Whether the time of the last manifest differs from the device clock. */
    var isClockCorrected = false
        private set

    /** Whether the key set of the directory stands below `AUTHORITY_FLOOR` (`REL-126`). */
    var isProvisional = false
        private set

    /** Whether the last network that `network` gave came from the kept manifest. */
    @Volatile
    var isFromKept = false
        private set

    /**
     * Whether a run from the kept manifest failed. The debug build asks its
     * carrier first at each start, thus the flag changes no order here.
     */
    @Volatile
    var isKeptSuspect = false

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

    /**
     * One call runs at a time. The call writes the kept manifest, and the
     * network thread and the restore thread both come here. The devnet has
     * one carrier on the machine of the developer, thus each start, a wake
     * too, asks it first, and the order of the release build does not apply.
     */
    @Suppress("UNUSED_PARAMETER")
    @Synchronized
    fun network(
        context: Context,
        client: Handle,
        isWake: Boolean = false,
        ingress: List<String> = emptyList(),
    ): Network? {
        imported(context)?.let {
            isFromKept = false
            return parseNetwork(it, null)
        }

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

            if (manifest === fresh) {
                kept.writeBytes(manifest)
                isKeptSuspect = false
            }
            isFromKept = manifest !== fresh
            isClockCorrected = verified.isClockCorrected
            isProvisional = verified.isProvisional

            // NTF-127: the build pins the route to the NDR.
            val ndrKey = context.assets.open(NDR_KEY).use { it.readBytes() }
            // DIS-163: the build pins the directory.
            val directoryPins = context.assets.open(DIRECTORY_PINS).use { it.readBytes() }
            return verified.network.copy(
                ndrRelayUrl = NDR_RELAY_URL,
                ndrKeyConfig = ndrKey,
                ndrRelayIpv4 = CARRIER_ADDRESS,
                directoryRelayUrl = DIRECTORY_RELAY_URL,
                directoryPins = directoryPins,
                directoryRelayIpv4 = CARRIER_ADDRESS,
            )
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
