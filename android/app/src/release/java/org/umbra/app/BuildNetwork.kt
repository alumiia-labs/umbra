package org.umbra.app

import android.content.Context
import androidx.compose.runtime.Composable
import java.io.File
import java.util.Properties
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.Handle
import uniffi.umbra_ffi.Network
import uniffi.umbra_ffi.advanceKeySet
import uniffi.umbra_ffi.fetchKeyChain
import uniffi.umbra_ffi.fetchManifest
import uniffi.umbra_ffi.newestKeySet
import uniffi.umbra_ffi.VerifiedNetwork

/**
 * The network of the release build. The relay directory of Part 10 gives it:
 * the build pins the key set of the directory, and each start fetches the
 * signed manifest from one carrier of Part 3 §3.10 in turn, verifies it, and
 * keeps the last one that verified (`NET-318`). The assets come from
 * `scripts/release-network.sh` after a deployment; a build with none has
 * no network.
 */
object BuildNetwork {
    private const val KEYSET = "umbra-keyset.bin"
    private const val NDR_KEY = "umbra-ndr-key.bin"
    private const val DIRECTORY_PINS = "umbra-directory-pins.bin"
    private const val NETWORK = "umbra-network.properties"
    private const val MANIFEST = "umbra-manifest.bin"
    private const val HELD_KEYSET = "umbra-keyset-held.bin"
    private const val CARRIER_PORT: UShort = 443u

    /** Whether the time of the last manifest differs from the device clock. */
    var isClockCorrected = false
        private set

    /** Whether the key set of the directory stands below `AUTHORITY_FLOOR` (`REL-126`). */
    var isProvisional = false
        private set

    private class Pinned(
        val keyset: ByteArray,
        val ndrKey: ByteArray,
        val directoryPins: ByteArray,
        val carriers: List<Pair<String, ByteArray>>,
        val ndrRelay: Pair<String, ByteArray>,
        val directoryRelay: Pair<String, ByteArray>,
        val invitationHost: String,
    )

    private fun ipv4(text: String): ByteArray? {
        val parts = text.trim().split('.')
        if (parts.size != 4) return null
        val octets = parts.map { it.toIntOrNull()?.takeIf { value -> value in 0..255 } ?: return null }
        return octets.map { it.toByte() }.toByteArray()
    }

    /** A `<name or url>,<IPv4 address>` value. */
    private fun endpoint(value: String?): Pair<String, ByteArray>? {
        val (name, address) = value?.split(',')?.takeIf { it.size == 2 } ?: return null
        return name.trim() to (ipv4(address) ?: return null)
    }

    private fun pinned(context: Context): Pinned? = try {
        val assets = context.assets
        val properties = Properties().apply { assets.open(NETWORK).use { load(it) } }
        val carriers = properties.getProperty("carriers").orEmpty()
            .split(';')
            .mapNotNull { endpoint(it) }
        Pinned(
            keyset = assets.open(KEYSET).use { it.readBytes() },
            ndrKey = assets.open(NDR_KEY).use { it.readBytes() },
            directoryPins = assets.open(DIRECTORY_PINS).use { it.readBytes() },
            carriers = carriers.takeIf { it.isNotEmpty() } ?: return null,
            ndrRelay = endpoint(properties.getProperty("ndr_relay")) ?: return null,
            directoryRelay = endpoint(properties.getProperty("directory_relay")) ?: return null,
            invitationHost = properties.getProperty("invitation_host")?.trim() ?: return null,
        )
    } catch (absent: java.io.IOException) {
        // No deployment gave this build its assets yet.
        null
    }

    /**
     * REL-200: a key set that the chain of a carrier reaches from the one
     * held and that `manifest` verifies under, with the network of that
     * manifest, or null. Each carrier gets its turn, thus a carrier with a
     * short chain stops no rotation.
     */
    private fun advanced(
        pins: Pinned,
        held: ByteArray,
        manifest: ByteArray,
        client: Handle,
    ): Pair<ByteArray, VerifiedNetwork>? {
        for ((host, address) in pins.carriers) {
            val next = try {
                advanceKeySet(held, fetchKeyChain(host, address, CARRIER_PORT, null))
            } catch (unreachable: FfiException) {
                continue
            }
            if (next.contentEquals(held)) continue
            val verified = try {
                client.networkOfManifest(manifest, next, 0uL, pins.invitationHost, null)
            } catch (refused: FfiException) {
                continue
            }
            return next to verified
        }
        return null
    }

    /** Writes a file under another name and renames it, thus a stop leaves the old one. */
    private fun writeWhole(file: File, bytes: ByteArray) {
        val part = File(file.parentFile, file.name + ".part")
        part.writeBytes(bytes)
        if (!part.renameTo(file)) {
            file.delete()
            part.renameTo(file)
        }
    }

    fun network(context: Context, client: Handle): Network? {
        val pins = pinned(context) ?: return null
        val kept = File(context.filesDir, MANIFEST)
        // REL-200: the newer of the set of the last rotation that this
        // device took and the one the build ships; a damaged file gives
        // way to the shipped set.
        val heldFile = File(context.filesDir, HELD_KEYSET)
        val keyset = newestKeySet(heldFile.takeIf { it.exists() }?.readBytes(), pins.keyset)
        // NET-318: one carrier after the other, and the web roots vouch for
        // each; the manifest carries its own signatures, thus a carrier needs
        // no trust.
        val fresh = pins.carriers.firstNotNullOfOrNull { (host, address) ->
            try {
                fetchManifest(host, address, CARRIER_PORT, null)
            } catch (unreachable: FfiException) {
                null
            }
        }
        for (manifest in listOfNotNull(fresh, kept.takeIf { it.exists() }?.readBytes())) {
            val verified = try {
                client.networkOfManifest(manifest, keyset, 0uL, pins.invitationHost, null)
            } catch (refused: FfiException) {
                // A manifest under a later key set: the chain moves the
                // held set to it, and the device keeps the new one.
                val (next, retried) = advanced(pins, keyset, manifest, client) ?: continue
                writeWhole(heldFile, next)
                retried
            }
            if (manifest === fresh) writeWhole(kept, manifest)
            isClockCorrected = verified.isClockCorrected
            isProvisional = verified.isProvisional
            return verified.network.copy(
                // NTF-127: the build pins the route to the NDR.
                ndrRelayUrl = pins.ndrRelay.first,
                ndrKeyConfig = pins.ndrKey,
                ndrRelayIpv4 = pins.ndrRelay.second,
                // DIS-163: the build pins the directory.
                directoryRelayUrl = pins.directoryRelay.first,
                directoryPins = pins.directoryPins,
                directoryRelayIpv4 = pins.directoryRelay.second,
            )
        }
        return null
    }

    /** The release build takes no descriptor from the user. */
    @Composable
    fun Panel() = Unit
}
