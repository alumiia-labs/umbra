package com.alumiialabs.umbra

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
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
 */
class KeystoreElement(private val context: Context) : SecureElementCallback {

    override fun keyed(input: ByteArray): ByteArray =
        try {
            val mac = Mac.getInstance(ALGORITHM)
            mac.init(key())
            mac.doFinal(input)
        } catch (fault: Exception) {
            // IMP-125: a debug build names the fault of the keystore.
            if (BuildConfig.DEBUG) android.util.Log.w("umbra-keystore", "the keyed function failed", fault)
            // The Rust side reads an empty result as a keystore failure.
            ByteArray(0)
        } finally {
            // IMP-037: the stretch of the passphrase leaves no copy here.
            input.fill(0)
        }

    private fun key(): SecretKey {
        val keystore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keystore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
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

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_HMAC_SHA256
        const val ALIAS = "umbra.k_se"
    }
}
