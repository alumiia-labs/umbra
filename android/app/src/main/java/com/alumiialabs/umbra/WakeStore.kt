package com.alumiialabs.umbra

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
import uniffi.umbra_ffi.openWakeBlob

/**
 * The wake table of Part 8 `NTF-135`: each `k_ntf_root` and each queue
 * alias with its conversation, outside `K_store`, under an AES-GCM key of
 * the keystore. The key asks for no user authentication and no unlocked
 * device, because a push arrives on a locked phone. A locked client opens
 * each push blob with it (`NTF-136`). In Direct mode the same key seals the
 * watch table of `NTF-145` beside it.
 */
object WakeStore {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "umbra.wake"
    private const val FILE = "wake.bin"
    private const val WATCH_FILE = "watch.bin"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val NONCE_LEN = 12
    private const val TAG_BITS = 128
    private const val PREFERENCES = "wake"
    private const val FAILURES = "failures"
    private const val RENEW = "renew"
    private const val CLOCK = "clock"

    /** The hash of the table of the last write, thus an equal table costs no seal. */
    private var written: ByteArray? = null

    /** The same for the watch table. */
    private var watchWritten: ByteArray? = null

    /** The conversation of a queue that raises no alert (`ABU-029`). */
    private const val SILENT_ID_LEN = 16
    private const val SILENT_BYTE = 0xFF.toByte()

    /** `NTF_FAIL_MAX` of Part 8 §8.4.2. */
    private const val FAIL_MAX = 3

    private fun file(context: Context) = File(context.noBackupFilesDir, FILE)

    private fun watchFile(context: Context) = File(context.noBackupFilesDir, WATCH_FILE)

    /** Whether the mode holds a wake table: Instant and Direct (`NTF-137`). */
    private fun holdsTable(context: Context) =
        Modes.mode(context).let { it == NotifyMode.Instant || it == NotifyMode.Direct }

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
     * makes no table after the mode left Instant and Direct (`NTF-137`).
     */
    @Synchronized
    fun write(context: Context, table: ByteArray) {
        if (!holdsTable(context)) return
        val hash = MessageDigest.getInstance("SHA-256").digest(table)
        if (hash.contentEquals(written) && file(context).exists()) return
        if (seal(file(context), table)) written = hash
    }

    /**
     * Seals the watch table of `NTF-145` and writes it whole, or deletes it
     * when it holds no watch. The caller wipes `table`.
     */
    @Synchronized
    fun writeWatch(context: Context, table: ByteArray) {
        if (Modes.mode(context) != NotifyMode.Direct || table.isEmpty()) {
            deleteWatch(context)
            return
        }
        val hash = MessageDigest.getInstance("SHA-256").digest(table)
        if (hash.contentEquals(watchWritten) && watchFile(context).exists()) return
        if (seal(watchFile(context), table)) watchWritten = hash
    }

    private fun seal(target: File, table: ByteArray): Boolean {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.iv + cipher.doFinal(table)
        val part = File(target.path + ".part")
        part.writeBytes(sealed)
        if (part.renameTo(target)) return true
        part.delete()
        return false
    }

    /**
     * The table, or none when no table is held or it does not open. A read
     * makes no key: a key with no table would outlive a delete.
     */
    fun read(context: Context): ByteArray? = open(file(context))

    /** The watch table, or none. */
    fun readWatch(context: Context): ByteArray? = open(watchFile(context))

    /** Whether a watch table waits for a lock. */
    fun hasWatch(context: Context) = watchFile(context).exists()

    /** The watch table leaves with the watch of Direct mode. */
    @Synchronized
    fun deleteWatch(context: Context) {
        watchWritten = null
        watchFile(context).delete()
        File(watchFile(context).path + ".part").delete()
    }

    private fun open(target: File): ByteArray? {
        try {
            val sealed = target.readBytes()
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

    /** NTF-137: the tables and their key leave at a wipe and outside Instant and Direct mode. */
    @Synchronized
    fun delete(context: Context) {
        written = null
        file(context).delete()
        File(file(context).path + ".part").delete()
        deleteWatch(context)
        runCatching {
            KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS)
        }
        preferences(context).edit().clear().apply()
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /**
     * Opens the blob of a push or of a watch with the table (`NTF-136`),
     * and counts the result toward `NTF_FAIL_MAX`. The result is the
     * conversation that the blob names, or none.
     */
    fun openBlob(context: Context, blob: ByteArray): Conversation? {
        if (!holdsTable(context)) return null
        val table = read(context) ?: return null
        val outcome = try {
            openWakeBlob(table, blob, (System.currentTimeMillis() / 1_000).toULong())
        } finally {
            table.fill(0)
        }
        // NTF-076: a blob outside the window ran no open, thus it counts
        // toward no failure.
        when (outcome.status.toInt()) {
            0 -> opened(context)
            2 -> failed(context)
        }
        return outcome.conversation?.let(::Conversation)
    }

    /**
     * The wake table names a blocked contact, a conversation with its
     * alerts off, and a sync channel with 16 bytes of 0xFF (`ABU-029`).
     */
    fun isSilent(conversation: Conversation?) = conversation != null &&
        conversation.id.size == SILENT_ID_LEN && conversation.id.all { it == SILENT_BYTE }

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
