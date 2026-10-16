package com.alumiialabs.umbra

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import uniffi.umbra_ffi.SecureElementCallback

/**
 * The keyed function of Part 14 §14.6.4: `HMAC-SHA256(k_se, input)` under a
 * key that the keystore made and that has no export path. StrongBox holds the
 * key when the device has one, and the TEE holds it on each other device.
 * The key asks for no user authentication at each use: the passphrase is the
 * authentication of this step (`IMP-065`).
 *
 * `mayCreate` is false for a store that exists: that store needs the key
 * that wrapped it, and a new key gives a wrong result for each passphrase.
 */
class KeystoreElement(
    private val context: Context,
    private val mayCreate: Boolean = true,
) : SecureElementCallback {

    override fun keyed(input: ByteArray): ByteArray {
        // IMP-125: the result goes to a buffer of this adapter, which it
        // overwrites. The copy that it returns belongs to UniFFI.
        var buffer = ByteArray(0)
        return try {
            val mac = Mac.getInstance(ALGORITHM)
            mac.init(key())
            mac.update(input)
            buffer = ByteArray(mac.macLength)
            mac.doFinal(buffer, 0)
            buffer.copyOf()
        } catch (fault: Exception) {
            // IMP-125: a debug build names the fault of the keystore.
            if (BuildConfig.DEBUG) android.util.Log.w("umbra-keystore", "the keyed function failed", fault)
            // The Rust side reads an empty result as a keystore failure.
            ByteArray(0)
        } finally {
            buffer.fill(0)
            // IMP-037: the stretch of the passphrase leaves no copy here.
            input.fill(0)
        }
    }

    // Two unlocks that run at one time make one key.
    private fun key(): SecretKey = synchronized(LOCK) { keyHeld() }

    private fun keyHeld(): SecretKey {
        val keystore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keystore.getKey(ALIAS, null) as? SecretKey)?.let {
            isKeyLost = false
            return it
        }
        if (!mayCreate) {
            isKeyLost = true
            throw KeyStoreException("the key of the store is gone")
        }
        isKeyLost = false
        val hasStrongBox =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (hasStrongBox) {
            try {
                return generate(inStrongBox = true)
            } catch (unavailable: ProviderException) {
                // The TEE is the fallback that the specification names. A
                // StrongBox that holds no HMAC key throws its own
                // `StrongBoxUnavailableException` on one device and the
                // plain `ProviderException` above it on another.
            }
        }
        return generate(inStrongBox = false)
    }

    private fun generate(inStrongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setIsStrongBoxBacked(inStrongBox)
            .setUnlockedDeviceRequired(true)
            .build()
        val generator = KeyGenerator.getInstance(ALGORITHM, PROVIDER)
        generator.init(spec)
        return generator.generateKey()
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_HMAC_SHA256
        private const val ALIAS = "umbra.k_se"
        private val LOCK = Any()

        /** Whether the last unlock found a store and no key for it. */
        @Volatile
        var isKeyLost = false
            private set
    }
}
