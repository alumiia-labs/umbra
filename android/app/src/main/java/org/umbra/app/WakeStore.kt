package org.umbra.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The wake table of Part 8 `NTF-135`: each `k_ntf_root` and each queue
 * alias with its conversation, outside `K_store`, under an AES-GCM key of
 * the keystore. The key asks for no user authentication and no unlocked
 * device, because a push arrives on a locked phone. A locked client opens
 * each push blob with it (`NTF-136`).
 */
object WakeStore {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "umbra.wake"
    private const val FILE = "wake.bin"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val NONCE_LEN = 12
    private const val TAG_BITS = 128
    private const val PREFERENCES = "wake"
    private const val FAILURES = "failures"
    private const val RENEW = "renew"
    private const val CLOCK = "clock"

    /** The hash of the table of the last write, thus an equal table costs no seal. */
    private var written: ByteArray? = null

    /** `NTF_FAIL_MAX` of Part 8 §8.4.3. */
    private const val FAIL_MAX = 3

    private fun file(context: Context) = File(context.noBackupFilesDir, FILE)

    // The worker and the receiver of FCM both reach the key, and two makes
    // of one alias would leave a table that no key opens.
    @Synchronized
    private fun key(): SecretKey {
        val keystore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keystore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec)
        return generator.generateKey()
    }

    /**
     * Seals `table` and writes it whole; the caller wipes `table`. The mode
     * is read here, under the lock of [delete], thus a write that waited
     * makes no table after the mode left Instant (`NTF-137`).
     */
    @Synchronized
    fun write(context: Context, table: ByteArray) {
        if (Modes.mode(context) != NotifyMode.Instant) return
        val hash = MessageDigest.getInstance("SHA-256").digest(table)
        if (hash.contentEquals(written) && file(context).exists()) return
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.iv + cipher.doFinal(table)
        val target = file(context)
        val part = File(target.path + ".part")
        part.writeBytes(sealed)
        if (part.renameTo(target)) written = hash else part.delete()
    }

    /**
     * The table, or none when no table is held or it does not open. A read
     * makes no key: a key with no table would outlive a delete.
     */
    fun read(context: Context): ByteArray? {
        try {
            val sealed = file(context).readBytes()
            if (sealed.size <= NONCE_LEN) return null
            val keystore = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val key = keystore.getKey(ALIAS, null) as? SecretKey ?: return null
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, NONCE_LEN))
            return cipher.doFinal(sealed, NONCE_LEN, sealed.size - NONCE_LEN)
        } catch (fault: Exception) {
            // A delete that came between, or a key that is gone.
            return null
        }
    }

    /** NTF-137: the table and its key leave at a wipe and outside Instant mode. */
    @Synchronized
    fun delete(context: Context) {
        written = null
        file(context).delete()
        File(file(context).path + ".part").delete()
        runCatching {
            KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS)
        }
        preferences(context).edit().clear().apply()
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /** NTF-079: one blob that opens sets the count back and ends the clock state. */
    fun opened(context: Context) {
        preferences(context).edit().putInt(FAILURES, 0).putBoolean(CLOCK, false).apply()
    }

    /**
     * NTF-078: a blob inside the window that no root opens. At `NTF_FAIL_MAX`
     * the clock state shows, and the next unlock makes each root again
     * (`NTF-084`).
     */
    fun failed(context: Context) {
        val preferences = preferences(context)
        val count = preferences.getInt(FAILURES, 0) + 1
        val editor = preferences.edit().putInt(FAILURES, count)
        if (count >= FAIL_MAX) editor.putBoolean(CLOCK, true).putBoolean(RENEW, true)
        editor.apply()
    }

    /** Whether the `clock` state of Part 14 §14.9.2 holds for the push path. */
    fun isClockSuspect(context: Context) = preferences(context).getBoolean(CLOCK, false)

    /** Whether the roots wait to be made again (`NTF-084`). */
    fun isRenewDue(context: Context) = preferences(context).getBoolean(RENEW, false)

    /**
     * The roots are due again, thus the count starts over. The clock state
     * holds until a blob opens under a fresh root (Part 14 §14.9.2).
     */
    fun renewed(context: Context) {
        preferences(context).edit().putBoolean(RENEW, false).putInt(FAILURES, 0).apply()
    }
}
