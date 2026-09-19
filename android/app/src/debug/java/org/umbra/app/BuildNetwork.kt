package org.umbra.app

import android.content.Context
import java.io.File
import uniffi.umbra_ffi.Network
import uniffi.umbra_ffi.RelayEndpoint

/**
 * The network of the debug build: the three relays of `scripts/devnet.sh` on
 * the machine of the developer. An emulator reaches that machine at
 * 10.0.2.2. The secrets of those relays are in the repository, thus this
 * network protects nothing.
 */
object BuildNetwork {
    private const val AUTHORITY = "devnet-ca.pem"
    private val HOST_MACHINE = byteArrayOf(10, 0, 2, 2)

    private val RELAYS = listOf(
        Triple(7441, "a1".repeat(32), "ad908a8a708aca07588cda7c4ed3e44d4966a80a9abb2f1e4bbac53c67414e34"),
        Triple(7442, "a2".repeat(32), "f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07"),
        Triple(7443, "a3".repeat(32), "261cd9cd2e935f9c2455876a80f02a4d6786b8ab877f07227737ca0b577bf161"),
    )

    private fun hex(text: String): ByteArray =
        text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    fun network(context: Context): Network? {
        // The TLS stack of the Rust side reads a file, and an asset is none.
        val authority = File(context.filesDir, AUTHORITY)
        context.assets.open(AUTHORITY).use { source ->
            authority.outputStream().use { source.copyTo(it) }
        }
        return Network(
            relays = RELAYS.map { (port, relayId, staticKey) ->
                RelayEndpoint(
                    // The test certificate names this host.
                    host = "localhost",
                    ipv4 = HOST_MACHINE,
                    port = port.toUShort(),
                    staticKey = hex(staticKey),
                    relayId = hex(relayId),
                )
            },
            rootCaPath = authority.absolutePath,
        )
    }
}
