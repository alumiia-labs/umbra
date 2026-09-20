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
import uniffi.umbra_ffi.Network
import uniffi.umbra_ffi.parseNetwork

/**
 * The network of the debug build. With no descriptor it is the three relays
 * of `scripts/devnet.sh` on the machine of the developer, which an emulator
 * reaches at 10.0.2.2, under the test authority of the repository. The
 * secrets of those relays are in the repository, thus that network protects
 * nothing.
 *
 * A tester pastes the descriptor of a deployed test network, and the build
 * then dials that network under the web roots. The release build has no such
 * panel, because the relay directory of Part 10 gives its network.
 */
object BuildNetwork {
    private const val AUTHORITY = "devnet-ca.pem"
    private const val DESCRIPTOR = "network-descriptor.txt"

    private val LOCAL = """
        umbra-network 2
        relay localhost 10.0.2.2 7441 ad908a8a708aca07588cda7c4ed3e44d4966a80a9abb2f1e4bbac53c67414e34 ${"a1".repeat(32)} layer=1 operator=north country=SE asn=64501 prefix=10.1
        relay localhost 10.0.2.2 7442 f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07 ${"a2".repeat(32)} layer=2 operator=alps country=CH asn=64502 prefix=10.2
        relay localhost 10.0.2.2 7443 261cd9cd2e935f9c2455876a80f02a4d6786b8ab877f07227737ca0b577bf161 ${"a3".repeat(32)} layer=3 operator=geyser country=IS asn=64503 prefix=10.3
        relay localhost 10.0.2.2 7444 94e9c71ccacddd2c6fbf529e263f0d39baf0fed469de0d227d24ad81a4394b70 ${"a4".repeat(32)} layer=2 operator=fjord country=NO asn=64504 prefix=10.4
        relay localhost 10.0.2.2 7445 38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67 ${"a5".repeat(32)} layer=3 operator=maple country=CA asn=64505 prefix=10.5
        # No party serves this host.
        invite invite.umbra.test
    """.trimIndent()

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

    fun network(context: Context): Network? {
        imported(context)?.let { return parseNetwork(it, null) }
        // The TLS stack of the Rust side reads a file, and an asset is none.
        val authority = File(context.filesDir, AUTHORITY)
        context.assets.open(AUTHORITY).use { source ->
            authority.outputStream().use { source.copyTo(it) }
        }
        return parseNetwork(LOCAL, authority.absolutePath)
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
