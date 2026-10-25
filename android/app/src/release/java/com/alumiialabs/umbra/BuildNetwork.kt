package com.alumiialabs.umbra

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
 * the build pins the key set of the directory, and a start fetches the
 * signed manifest from one carrier of Part 3 §3.10 in turn, verifies it, and
 * keeps the last one that verified (`NET-318`). A start within one epoch of
 * the last fetch, and each wake session, takes the kept one first, until a
 * run from it fails. The assets come from `scripts/release-network.sh` after
 * a deployment; a build with none has no network.
 */
object BuildNetwork {
    private const val KEYSET = "umbra-keyset.bin"
    private const val NDR_KEY = "umbra-ndr-key.bin"
    private const val DIRECTORY_PINS = "umbra-directory-pins.bin"
    private const val NETWORK = "umbra-network.properties"
    private const val MANIFEST = "umbra-manifest.bin"
    private const val HELD_KEYSET = "umbra-keyset-held.bin"
    private const val CARRIER_PORT: UShort = 443u

    /** One epoch of Part 10 §10.11: the directory signs a new manifest each epoch. */
    private const val KEPT_FRESH_MS = 60 * 60_000L

    /** The key of the network file that holds the epoch of `REL-045`. */
    private const val SHIPPED_EPOCH = "shipped_epoch"

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
     * Whether a run from the kept manifest failed. The carriers then come
     * first, at a wake too: a woken client with no current relay fetches a
     * fresh manifest (Part 3 §3.10). A fresh manifest that verifies clears it.
     */
    @Volatile
    var isKeptSuspect = false

    private class Pinned(
        val keyset: ByteArray,
        val ndrKey: ByteArray,
        val directoryPins: ByteArray,
        val carriers: List<Pair<String, ByteArray>>,
        val ndrRelay: Pair<String, ByteArray>,
        val directoryRelay: Pair<String, ByteArray>,
        val invitationHost: String,
        val shippedEpoch: ULong,
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
            // REL-045, REL-046: the epoch at the time of the build is the
            // floor of a device with no verified epoch. A build with none
            // has no network: zero would take each old manifest. The Gradle
            // build refuses a network file with no `shipped_epoch` first.
            shippedEpoch = properties.getProperty(SHIPPED_EPOCH)?.trim()?.toULongOrNull()
                ?.takeIf { it > 0uL } ?: return null,
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
                client.networkOfManifest(manifest, next, pins.shippedEpoch, pins.invitationHost, null)
            } catch (refused: FfiException) {
                continue
            }
            return next to verified
        }

        return null
    }

    /** The hosts of the ingress pins in the order of the next dial, as the kept manifest names them. */
    private fun pinHosts(client: Handle, kept: File): List<String> = try {
        if (kept.exists()) client.ingressHosts(kept.readBytes()) else emptyList()
    } catch (unread: FfiException) {
        emptyList()
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

    /**
     * The network of the newest manifest that verifies, or null. One call
     * runs at a time. The call writes the kept manifest and the held key
     * set, and the network thread and the restore thread both come here.
     * The carriers on the hosts of `ingress` come first, in its order: the
     * ingress relay learns the address and the time anyway (Part 3 §3.10).
     */
    @Synchronized
    fun network(
        context: Context,
        client: Handle,
        isWake: Boolean = false,
        ingress: List<String> = emptyList(),
    ): Network? {
        val pins = pinned(context) ?: return null
        val kept = File(context.filesDir, MANIFEST)

        // REL-200: the newer of the set of the last rotation that this
        // device took and the one the build ships. A damaged file gives
        // way to the shipped set.
        val heldFile = File(context.filesDir, HELD_KEYSET)
        val keyset = newestKeySet(heldFile.takeIf { it.exists() }?.readBytes(), pins.keyset)

        // NET-318: one carrier after the other, and the web roots vouch for
        // each; the manifest carries its own signatures, thus a carrier needs
        // no trust. A carrier whose manifest does not verify gives its turn
        // to the next one. The sort keeps the shipped order of the others.
        // A process with no connection yet takes the order of the stored pins.
        val order = ingress.ifEmpty { pinHosts(client, kept) }
        val carriers = pins.carriers.sortedBy { (host, _) ->
            order.indexOf(host).takeIf { it >= 0 } ?: order.size
        }
        val fresh = carriers.asSequence().mapNotNull { (host, address) ->
            try {
                fetchManifest(host, address, CARRIER_PORT, null)
            } catch (unreachable: FfiException) {
                null
            }
        }
        val held = sequence { kept.takeIf { it.exists() }?.readBytes()?.let { yield(it) } }

        // The kept manifest comes last, but first within one epoch of its
        // fetch and at a wake session: that session lasts seconds
        // (`NET-100`), and a carrier can take 20 s. A kept manifest that no
        // longer verifies, or whose run failed, gives its turn to the carriers.
        val keptAgeMs = System.currentTimeMillis() - kept.lastModified()
        val isKeptFirst = !isKeptSuspect && (isWake || keptAgeMs in 0L until KEPT_FRESH_MS)
        val candidates = if (isKeptFirst) {
            held.map { it to false } + fresh.map { it to true }
        } else {
            fresh.map { it to true } + held.map { it to false }
        }

        for ((manifest, isFresh) in candidates) {
            val verified = try {
                client.networkOfManifest(manifest, keyset, pins.shippedEpoch, pins.invitationHost, null)
            } catch (unverified: FfiException.Unverified) {
                // A manifest under a later key set: the chain moves the
                // held set to it, and the device keeps the new one. A stale
                // manifest asks no carrier for a chain.
                val (next, retried) = advanced(pins, keyset, manifest, client) ?: continue
                writeWhole(heldFile, next)
                retried
            } catch (locked: FfiException.Locked) {
                // A locked client reads no manifest, thus the call asks no carrier.
                return null
            } catch (refused: FfiException) {
                continue
            }

            if (isFresh) {
                writeWhole(kept, manifest)
                isKeptSuspect = false
            }
            isFromKept = !isFresh
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
