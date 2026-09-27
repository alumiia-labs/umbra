package org.umbra.app

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import uniffi.umbra_ffi.Config
import uniffi.umbra_ffi.Connection
import uniffi.umbra_ffi.ContactRequestInfo
import uniffi.umbra_ffi.FfiEvent
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.PublicLink
import uniffi.umbra_ffi.FfiGroupMember
import uniffi.umbra_ffi.FfiGroupOffer
import uniffi.umbra_ffi.FfiRole
import uniffi.umbra_ffi.Handle
import uniffi.umbra_ffi.MsgInfo
import uniffi.umbra_ffi.Receipts
import uniffi.umbra_ffi.RestoreStatus
import uniffi.umbra_ffi.TextSink
import uniffi.umbra_ffi.init
import uniffi.umbra_ffi.initLinked
import uniffi.umbra_ffi.initRestored
import uniffi.umbra_ffi.Device
import uniffi.umbra_ffi.LinkStatus
import uniffi.umbra_ffi.recoveryDigitsKind
import uniffi.umbra_ffi.measureArgon2FloorMs
import uniffi.umbra_ffi.MsgHandle
import uniffi.umbra_ffi.MsgReaction

/** A conversation, by its surrogate identifier. */
class Conversation(val id: ByteArray) {
    override fun equals(other: Any?) = other is Conversation && id.contentEquals(other.id)
    override fun hashCode() = id.contentHashCode()

    /** A stable short name for a contact that the user did not name yet. */
    val label: String
        get() = id.take(4).joinToString("") { "%02x".format(it) }
}

/**
 * One message of a conversation view. The text stays a `CharArray`. `quote`
 * is the text of the message that this one answers. An answer to a message
 * that this device does not hold has `isReply` and no quote.
 */
class Line(
    val handle: MsgHandle,
    val text: CharArray,
    val info: MsgInfo,
    val quote: Quoted?,
    val reactions: List<MsgReaction>,
) {
    /**
     * The identity of the message: two loads of one message give one key. A
     * byte array compares by identity, thus the key is a list.
     */
    val key: List<Byte> = handle.key().toList()

    val isReply: Boolean
        get() = info.isReply
}

/** The message that a line answers: its identity, its author, and its text. */
class Quoted(val key: List<Byte>, val isOutgoing: Boolean, val text: CharArray)

/**
 * One row of the chat list and of the contact list. The name is a label of
 * the user. The preview is message text, thus it stays a `CharArray`.
 */
class Chat(
    val conversation: Conversation,
    val name: String,
    val preview: CharArray?,
    val isPreviewOutgoing: Boolean,
    val lastAtMs: Long,
    val unread: Int,
    val isVerified: Boolean,
    /** Whether the conversation is a private group of Part 11. */
    val isGroup: Boolean = false,
    /** The identifier of a group, which the join flow names. */
    val groupId: ByteArray = ByteArray(0),
    /** The active members of a group. */
    val members: Int = 0,
    /** Whether the two relays of a group hold its queues (`GRP-191`). */
    val isReady: Boolean = true,
    /** Whether each relay of a group refused its queue (`GRP-210`). */
    val isClosed: Boolean = false,
    /** Whether the roster of a group still holds this device. */
    val isMember: Boolean = true,
    /** Whether this owner must name a second owner first (`GRP-184`). */
    val ownerNeeded: Boolean = false,
    /** Whether this device lost the keys of a group and needs a new invitation. */
    val isLapsed: Boolean = false,
    /** Whether a removed device took the index of this member, and an admit waits (`GRP-373`). */
    val isReturning: Boolean = false,
    /** Whether a removed device took the index of this member, and no contact can add it again (`GRP-374`). */
    val needsInvitation: Boolean = false,
) {
    /** What each list shows: the name of the user, or a stable short label. */
    val title: String
        get() = name.ifEmpty {
            if (isGroup) "Group ${conversation.label}" else "Contact ${conversation.label}"
        }
}

/**
 * The one owner of the Rust client. Each call into Rust runs on the worker
 * thread, because a call can run Argon2id or wait for the store. Each write
 * of the state below runs on the main thread.
 */
object Core {
    enum class Phase { Locked, Opening, Open }

    var phase by mutableStateOf(Phase.Locked)
        private set
    var online by mutableStateOf(false)
        private set
    var fault by mutableStateOf<String?>(null)

    /** The line of a degraded state of the link (Part 14 §14.9.2), which is no error. */
    var degraded by mutableStateOf<String?>(null)
        private set

    /** Why the last run of the network ended, for the view of the connection. */
    var linkFault by mutableStateOf<String?>(null)
        private set

    /** The circuits of this device and their relays, as the core gave them last. */
    var connection by mutableStateOf<Connection?>(null)
        private set

    /** What the top bar shows of the link. */
    val linkState: LinkState
        get() = when {
            online -> LinkState.Connected
            linkFault != null -> LinkState.Down
            else -> LinkState.Connecting
        }
    var invitation by mutableStateOf<String?>(null)
    val chats = mutableStateListOf<Chat>()

    /** The idle time of the auto-lock, in seconds. Zero locks when the app leaves the screen. */
    var autoLockSeconds by mutableStateOf(15 * 60L)
        private set

    /** The text of a scanned invitation, which the view of the link takes. */
    var scannedInvitation by mutableStateOf<String?>(null)

    /** A link that a tap or a share gave the app, which waits for a tap. */
    var linkedInvitation by mutableStateOf<String?>(null)

    /** The short code of a ceremony that runs, and its conversation. */
    var verifyCode by mutableStateOf<Pair<Conversation, String>?>(null)
        private set

    /** The words of a ceremony that did not start or did not finish. */
    var verifyFault by mutableStateOf<String?>(null)
        private set

    /** The conversation that the user verified a moment ago. */
    var verifiedNow by mutableStateOf<Conversation?>(null)
        private set

    /** A contact that is new in this run and has no name yet. */
    var toName by mutableStateOf<Conversation?>(null)

    /** Grows at each change of a message, thus a view loads its lines again. */
    var revision by mutableIntStateOf(0)
        private set

    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "umbra-core") }
    private var handle: Handle? = null
    private var draining = false

    /** Whether a run started and did not report its first state yet. */
    private var isStarting = false

    /** Whether a view of the app is on the screen. */
    private var isVisible = false

    /** Whether the foreground service of the socket carrier runs. */
    private var carrierHolds = false
    private var lastTouchMs = 0L
    private var retryDelayMs = FIRST_RETRY_MS
    private const val TOUCH_GAP_MS = 10_000L
    private const val FIRST_RETRY_MS = 2_000L
    private const val LAST_RETRY_MS = 30_000L
    private const val STOPPED = 0
    private const val DIAL_FAILED = 1
    private const val AGED = 6

    /**
     * Opens the client under the passphrase. The first launch makes the
     * store. This call overwrites `passphrase`.
     */
    fun open(context: Context, passphrase: CharArray) {
        val app = context.applicationContext
        phase = Phase.Opening
        fault = null
        worker.execute {
            // UniFFI has no `CharArray` type, thus this list is the one copy
            // that the collector frees (`IMP-124`).
            val units = passphrase.map { it.code.toUShort() }
            passphrase.fill('\u0000')
            try {
                val opened = handle ?: launch(app, units)
                opened.unlock(units)
                begin(app, opened)
            } catch (wrong: FfiException.WrongPassphrase) {
                fail("That passphrase does not open this device.")
            } catch (other: FfiException) {
                fail("The store did not open: ${other.javaClass.simpleName}.")
            }
        }
    }

    /** Takes an open client: its list, its network, and its events. */
    private fun begin(app: Context, opened: Handle) {
        handle = opened
        // The store holds each contact, thus the list needs no network.
        val stored = summaries(opened)
        val idleSeconds = opened.autoLockSeconds().toLong()
        val downloadLimit = opened.autoDownloadLimit()
        val downloadWifiOnly = opened.autoDownloadUnmeteredOnly()
        // IMP-168: the core knows the cost of the network before a record
        // arrives.
        watchNetwork(app)
        opened.setMetered(isMetered(app))
        val backupAt = opened.lastBackupAt()?.toLong()
        val owns = opened.ownsChannels()
        BuildNetwork.network(app, opened)?.let { network ->
            main.post { isStarting = true }
            opened.connect(network)
        }
        drain(opened, app)
        main.post {
            chats.clear()
            chats.addAll(stored)
            autoLockSeconds = idleSeconds
            autoDownloadLimit = downloadLimit
            autoDownloadWifiOnly = downloadWifiOnly
            lastBackupAt = backupAt
            ownsChannels = owns
            restoreNote = null
            phase = Phase.Open
            // The user opened the client, thus a view is on the
            // screen, and the platform permits the start.
            DeliveryService.start(app)
            refreshJoinFlow()
            Push.opened(app)
            Poll.schedule(app)
        }
    }

    /** The devices of the set (Part 7). */
    val devices = mutableStateListOf<Device>()

    /** Whether this device owns the channels, thus it can link another. */
    var ownsChannels by mutableStateOf(true)
        private set

    fun readDevices() = call { client ->
        val list = client.devices()
        val owns = client.ownsChannels()
        main.post {
            devices.clear()
            devices.addAll(list)
            ownsChannels = owns
        }
    }

    /** Whether the contact of a conversation is blocked (Part 13 §13.12). */
    fun isBlocked(conversation: Conversation, onResult: (Boolean) -> Unit) = call { client ->
        val blocked = client.isBlocked(conversation.id)
        main.post { onResult(blocked) }
    }

    fun setBlocked(conversation: Conversation, blocked: Boolean) = call { client ->
        client.setBlocked(conversation.id, blocked)
        main.post { revision++ }
    }

    fun blockedMembers(conversation: Conversation, onResult: (List<UShort>) -> Unit) = call { client ->
        val members = client.blockedMembers(conversation.id)
        main.post { onResult(members) }
    }

    fun setMemberBlocked(conversation: Conversation, index: UShort, blocked: Boolean) = call { client ->
        client.setMemberBlocked(conversation.id, index, blocked)
        main.post { revision++ }
    }

    fun discardedCount(conversation: Conversation, onResult: (ULong) -> Unit) = call { client ->
        val count = client.discardedCount(conversation.id)
        main.post { onResult(count) }
    }

    /** The reusable links of this device (Part 4 §4.3.2). */
    val publicLinks = mutableStateListOf<PublicLink>()

    /** The handle of this device, or none (Part 9 §9.3). */
    var myHandle by mutableStateOf<String?>(null)
        private set

    /** The contact requests that wait (Part 9 §9.6). */
    val contactRequests = mutableStateListOf<ContactRequestInfo>()

    /** Each link or handle whose entry another party wrote (`DIS-138`). */
    val directoryWarnings = mutableStateListOf<String>()

    /** Each link or handle at its limit of requests this week (`ABU-087`). */
    val entriesAtLimit = mutableStateListOf<String>()

    /** Whether a call to the directory runs, and the words of its fault. */
    var directoryBusy by mutableStateOf(false)
        private set
    var directoryNote by mutableStateOf<String?>(null)

    /** The link that the last call made, for its view. */
    var madeLink by mutableStateOf<List<Byte>?>(null)

    /** Whether the last request left, for the view that sent it. */
    var requestSent by mutableStateOf(false)

    /** The name that an accepted request showed, for the naming view. */
    var suggestedName: String? = null

    /** The calls to the directory take seconds each, thus they have a thread of their own. */
    private val directoryWorker = Executors.newSingleThreadExecutor { Thread(it, "umbra-directory") }
    private const val MAINTAIN_MS = 5 * 60_000L
    private var maintains = false

    fun readDirectory() = call { client ->
        val links = client.publicLinks()
        val handle = client.myHandle()
        val requests = client.contactRequests()
        val warnings = client.directoryWarnings()
        val full = client.entriesAtLimit()
        main.post {
            directoryWarnings.clear()
            directoryWarnings.addAll(warnings)
            entriesAtLimit.clear()
            entriesAtLimit.addAll(full)
            publicLinks.clear()
            publicLinks.addAll(links)
            myHandle = handle
            contactRequests.clear()
            contactRequests.addAll(requests)
        }
    }

    private fun directory(action: (Handle) -> Unit) {
        val client = handle ?: return
        directoryBusy = true
        directoryNote = null
        directoryWorker.execute {
            try {
                action(client)
            } catch (locked: FfiException.Locked) {
                // A call that the lock overtook is no fault of the user.
            } catch (failure: FfiException) {
                main.post { directoryNote = directoryFault(failure) }
            } finally {
                main.post { directoryBusy = false }
                readDirectory()
            }
        }
    }

    private fun directoryFault(failure: FfiException): String = when (failure) {
        is FfiException.Offline -> "The directory does not answer."
        is FfiException.Busy -> "The directory takes this change at its next epoch. Try again in a few minutes."
        is FfiException.Stale -> "That is taken, or it changed. Try again."
        is FfiException.NotFound -> "The directory holds no such link or handle."
        is FfiException.Unverified -> "The answer of the directory does not verify."
        is FfiException.Malformed -> "That is no link or handle."
        else -> "That did not work: ${failure.javaClass.simpleName}."
    }

    fun createPublicLink(validSeconds: ULong) = directory { client ->
        val made = client.createPublicLink(validSeconds)
        // The list holds the link before its view opens.
        val links = client.publicLinks()
        main.post {
            publicLinks.clear()
            publicLinks.addAll(links)
            madeLink = made.id.toList()
        }
    }

    fun retirePublicLink(link: PublicLink) = directory { client -> client.retirePublicLink(link.id) }

    fun claimHandle(name: String) = directory { client -> client.claimHandle(name) }

    /** The next key of the handle, at once (Part 9 §9.3). */
    fun rotateHandleKey() = directory { client -> client.rotateHandleKey() }

    /** A new rendezvous queue for a link or the handle, at once. */
    fun rotateEntry(label: String) = directory { client -> client.rotateEntry(label) }

    fun releaseHandle() = directory { client -> client.releaseHandle() }

    /** Sends a request to a reusable link or a handle, under the name of the user. */
    fun sendRequest(target: String, name: String) {
        requestSent = false
        directory { client ->
            client.setProfileName(name)
            client.sendContactRequest(target)
            main.post { requestSent = true }
        }
    }

    fun profileName(onName: (String) -> Unit) = call { client ->
        val name = client.profileName()
        main.post { onName(name) }
    }

    fun acceptRequest(request: ContactRequestInfo) = call { client ->
        client.acceptContactRequest(request.id)
        suggestedName = request.name.ifBlank { null }
        readDirectory()
    }

    fun declineRequest(request: ContactRequestInfo) = call { client ->
        client.declineContactRequest(request.id)
        readDirectory()
    }

    /** The upkeep of the entries: a timed link at its end, and each lease. */
    private fun maintainDirectory() {
        val client = handle ?: return
        directoryWorker.execute {
            try {
                if (client.hasDirectory()) client.maintainDirectory()
            } catch (failure: FfiException) {
                // The next round tries again.
            }
            readDirectory()
        }
    }

    private fun scheduleMaintenance() {
        if (maintains) return
        maintains = true
        main.postDelayed(object : Runnable {
            override fun run() {
                if (!online) {
                    maintains = false
                    return
                }
                maintainDirectory()
                main.postDelayed(this, MAINTAIN_MS)
            }
        }, MAINTAIN_MS)
    }

    /** Removes a device from the set (Part 7 §7.7). */
    fun removeDevice(deviceId: ByteArray) = call { client ->
        client.removeDevice(deviceId)
        val list = client.devices()
        main.post {
            devices.clear()
            devices.addAll(list)
        }
    }

    /** Where the link of a device stands, for the view of the link. */
    var linkStatus by mutableStateOf<LinkStatus>(LinkStatus.Idle)
        private set

    fun startLink(context: Context) {
        fault = null
        linkStatus = LinkStatus.Preparing
        val label = deviceLabel(context)
        call { client ->
            try {
                client.startLink(label)
            } catch (busy: FfiException.Busy) {
                // DEV-302: the last device still opens its sync channel.
                main.post {
                    linkStatus = LinkStatus.Idle
                    fault = "The last device is still finishing its link. Try again in a moment."
                }
            }
        }
    }

    /** The name of this device that the user set, or its model. */
    private fun deviceLabel(context: Context): String =
        android.provider.Settings.Global.getString(
            context.contentResolver,
            android.provider.Settings.Global.DEVICE_NAME,
        )?.takeIf { it.isNotBlank() } ?: Build.MODEL

    fun readLink() = call { client ->
        val status = client.linkStatus()
        main.post { linkStatus = status }
    }

    fun confirmLink() = call { client ->
        client.confirmLink()
        val status = client.linkStatus()
        main.post { linkStatus = status }
    }

    fun cancelLink() {
        linkStatus = LinkStatus.Idle
        call { client -> client.cancelLink() }
    }

    /** The code of a first launch that links, or null. */
    var joinCode by mutableStateOf<String?>(null)
        private set

    /** What the link of a first launch shows while it runs, or null. */
    var joinNote by mutableStateOf<String?>(null)
        private set

    /**
     * Links this device from the scanned code of another (Part 7 §7.4): a
     * first store under the new passphrase with the network, the link, and
     * then the store of the snapshot in its place. This call overwrites
     * `passphrase`.
     */
    fun join(context: Context, passphrase: CharArray, ticket: String) {
        val app = context.applicationContext
        fault = null
        joinNote = "Connecting…"
        worker.execute {
            val units = passphrase.map { it.code.toUShort() }
            passphrase.fill('\u0000')
            var opened: Handle? = null
            try {
                val first = launch(app, units)
                opened = first
                first.unlock(units)
                val network = BuildNetwork.network(app, first)
                if (network == null) {
                    dropStore(app, first)
                    joinFailed("No network.")
                    return@execute
                }
                first.connect(network)
                first.joinLink(ticket, deviceLabel(app))
                val deadline = System.currentTimeMillis() + JOIN_WAIT_MS
                var failure: String? = null
                var isReady = false
                while (!isReady && failure == null) {
                    // No thread drains this handle, thus the clock of the
                    // link comes from here.
                    first.tick()
                    when (val status = first.linkStatus()) {
                        is LinkStatus.Ready -> isReady = true
                        is LinkStatus.Code -> main.post {
                            joinNote = null
                            joinCode = status.code
                        }
                        is LinkStatus.Fetching -> main.post {
                            joinCode = null
                            joinNote = "Copying from the other device…"
                        }
                        is LinkStatus.Expired -> failure = "The code ran out."
                        is LinkStatus.Failed -> failure = "The link failed."
                        else -> Unit
                    }
                    if (!isReady && failure == null) {
                        if (System.currentTimeMillis() > deadline) failure = "The link failed."
                        Thread.sleep(500)
                    }
                }
                if (failure != null) {
                    dropStore(app, first)
                    joinFailed(failure)
                    return@execute
                }
                val linked = first.takeLinked()
                first.disconnect()
                first.close()
                opened = null
                val database = File(app.filesDir, "umbra.db")
                val back = initLinked(
                    Config(database.absolutePath, measureArgon2FloorMs()),
                    KeystoreElement(app),
                    units,
                    linked,
                )
                main.post {
                    joinNote = null
                    joinCode = null
                }
                begin(app, back)
            } catch (malformed: FfiException.Malformed) {
                opened?.let { dropStore(app, it) }
                joinFailed("This is not the code of a link.")
            } catch (other: FfiException) {
                opened?.let { dropStore(app, it) }
                joinFailed("The link failed: ${other.javaClass.simpleName}.")
            }
        }
    }

    private fun joinFailed(message: String) = main.post {
        joinNote = null
        joinCode = null
        fault = message
    }

    private const val JOIN_WAIT_MS = 15 * 60_000L

    /** What the restore of a first launch shows while it runs, or null. */
    var restoreNote by mutableStateOf<String?>(null)
        private set

    /** The time of the last backup, in Unix seconds, or null. */
    var lastBackupAt by mutableStateOf<Long?>(null)
        private set

    fun readBackup() = call { client ->
        val at = client.lastBackupAt()?.toLong()
        main.post { lastBackupAt = at }
    }

    /** The recovery code as digits, in an array that the caller wipes. */
    fun recoveryCode(onLoaded: (CharArray) -> Unit) = call { client ->
        val sink = CharSink()
        client.recoveryCode(sink)
        main.post { onLoaded(sink.chars) }
    }

    /**
     * Restores a device from its recovery code (Part 4 §4.7.2): a first
     * store under the new passphrase with the network, the backup of the
     * code, and then the store of the restored seed in its place. This
     * call overwrites both arrays.
     */
    fun restore(context: Context, passphrase: CharArray, digits: CharArray) {
        val app = context.applicationContext
        fault = null
        restoreNote = "Looking for the backup…"
        worker.execute {
            val units = passphrase.map { it.code.toUShort() }
            passphrase.fill('\u0000')
            val code = digits.map { it.code.toUShort() }
            digits.fill('\u0000')
            // IDN-151 to IDN-154: the check and the type come first, and a
            // wrong type names both types.
            val kind = recoveryDigitsKind(code).toInt()
            if (kind != 1) {
                restoreFailed(
                    when (kind) {
                        2 -> "These are the digits of the user half. The restore takes the recovery code."
                        3 -> "These are the digits of a share. The restore takes the recovery code."
                        else -> "These digits do not check."
                    },
                )
                return@execute
            }
            var opened: Handle? = null
            try {
                val first = launch(app, units)
                opened = first
                first.unlock(units)
                val network = BuildNetwork.network(app, first)
                if (network == null) {
                    dropStore(app, first)
                    restoreFailed("No network.")
                    return@execute
                }
                first.connect(network)
                first.restoreBackup(code)
                val deadline = System.currentTimeMillis() + RESTORE_WAIT_MS
                var failure: String? = null
                var isReady = false
                while (!isReady && failure == null) {
                    when (val status = first.restoreStatus()) {
                        is RestoreStatus.Ready -> isReady = true
                        is RestoreStatus.NotFound -> failure = "No backup opens under this code."
                        // IDN-155: an empty identity is no account.
                        is RestoreStatus.NoIdentity -> failure = "The backup holds no identity."
                        is RestoreStatus.Failed -> failure = "The backup did not come down."
                        is RestoreStatus.Fetching ->
                            main.post { restoreNote = "Restoring ${status.done} of ${status.total}…" }
                        else -> Unit
                    }
                    if (!isReady && failure == null) {
                        if (System.currentTimeMillis() > deadline) failure = "The backup did not come down."
                        Thread.sleep(250)
                    }
                }
                if (failure != null) {
                    dropStore(app, first)
                    restoreFailed(failure)
                    return@execute
                }
                val restored = first.takeRestored()
                first.disconnect()
                first.close()
                opened = null
                val database = File(app.filesDir, "umbra.db")
                val back = initRestored(
                    Config(database.absolutePath, measureArgon2FloorMs()),
                    KeystoreElement(app),
                    units,
                    restored,
                )
                begin(app, back)
            } catch (other: FfiException) {
                opened?.let { dropStore(app, it) }
                restoreFailed("The restore failed: ${other.javaClass.simpleName}.")
            }
        }
    }

    /** Ends the store of a restore that did not complete: a first launch comes again. */
    private fun dropStore(app: Context, opened: Handle) {
        opened.disconnect()
        opened.close()
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            File(app.filesDir, "umbra.db$suffix").delete()
        }
    }

    private fun restoreFailed(message: String) = main.post {
        restoreNote = null
        fault = message
    }

    private const val RESTORE_WAIT_MS = 10 * 60_000L

    /** Whether this device holds a store, thus the unlock view says so. */
    fun hasStore(context: Context) = File(context.filesDir, "umbra.db").exists()

    private fun launch(app: Context, passphrase: List<UShort>): Handle {
        val database = File(app.filesDir, "umbra.db")
        // The first launch alone reads the measurement.
        val floorMs = if (database.exists()) 0uL else measureArgon2FloorMs()
        return init(Config(database.absolutePath, floorMs), KeystoreElement(app), passphrase)
    }

    private fun fail(message: String) = main.post {
        fault = message
        phase = Phase.Locked
    }

    /** One thread drains the event stream, and it gives the clock to Rust. */
    private fun drain(opened: Handle, app: Context) {
        if (draining) return
        draining = true
        thread(name = "umbra-events", isDaemon = true) {
            while (true) {
                opened.tick()
                val event = opened.waitEvent(1_000u) ?: continue
                main.post { apply(event, app) }
            }
        }
    }

    private fun apply(event: FfiEvent, app: Context) {
        when (event) {
            is FfiEvent.Online -> {
                isStarting = false
                online = true
                fault = null
                degraded = null
                linkFault = null
                retryDelayMs = FIRST_RETRY_MS
                readConnection()
                readDirectory()
                maintainDirectory()
                scheduleMaintenance()
            }
            is FfiEvent.Circuits -> readConnection()
            is FfiEvent.Offline -> {
                isStarting = false
                online = false
                readConnection()
                if (event.cause.toInt() == AGED) {
                    // NET-320: the circuits reached their age, and new ones
                    // build now. Nothing failed.
                    if (wantsNetwork()) connect(app)
                } else if (event.cause.toInt() == STOPPED) {
                    // The app stops no run of an open client. A run that
                    // ended so while a view shows gets a new one.
                    if (wantsNetwork()) retryLater(app)
                } else {
                    // The two lines of Part 14 §14.9.2. The cause shows in the
                    // view of the connection.
                    degraded = if (event.cause.toInt() == DIAL_FAILED) {
                        "The relays do not answer. Messages wait."
                    } else {
                        "No connection. Messages wait."
                    }
                    linkFault = cause(event.cause)
                    retryLater(app)
                }
            }
            is FfiEvent.Invitation -> invitation = event.link
            is FfiEvent.Refused -> fault = "This build cannot reach the relay of that link."
            // IDN-023: a fetch by a second party is an attack that the two
            // parties detect, thus the words name that cause first.
            is FfiEvent.InvitationGone -> fault =
                "This link gives no invitation. A second party opened it first, " +
                "or it is older than 14 days. Tell your contact, and ask for a new link."
            is FfiEvent.Contact -> {
                // The link of this device served, or the link of a contact did.
                invitation = null
                val conversation = Conversation(event.conversation)
                refreshChats { list ->
                    val isNamed = list.any { it.conversation == conversation && it.name.isNotEmpty() }
                    if (!isNamed) toName = conversation
                }
            }
            is FfiEvent.VerificationCode ->
                verifyCode = Conversation(event.conversation) to event.code
            is FfiEvent.Verified -> {
                verifyCode = null
                verifiedNow = Conversation(event.conversation)
                refreshChats()
            }
            // The view of the ceremony starts again from its own state.
            is FfiEvent.VerificationRefused -> {
                verifyCode = null
                verifyFault = "The two devices made no code."
            }
            is FfiEvent.Message -> {
                revision++
                refreshChats()
                if (!isVisible) Notifier.message(app, Conversation(event.conversation))
            }
            is FfiEvent.Delivery -> {
                revision++
                refreshChats()
            }
            // The file of a message arrived, left, or failed.
            is FfiEvent.File -> revision++
            // The join flow of a group moved.
            is FfiEvent.GroupOffer, is FfiEvent.GroupJoiner -> {
                refreshJoinFlow()
                refreshChats()
            }
            // A reaction, an edit, and a deletion are no arrival, thus they
            // raise no alert.
            is FfiEvent.Reacted -> revision++
            is FfiEvent.Edited -> {
                revision++
                refreshChats()
            }
            is FfiEvent.Deleted -> {
                revision++
                refreshChats()
            }
            is FfiEvent.Locked -> {
                isStarting = false
                groupOffers.clear()
                groupJoiners.clear()
                images.clear()
                decoding.clear()
                VoicePlayer.stop()
                previews.clear()
                // IMP-161: a draft that waits holds its file in the clear.
                cancelSend()
                online = false
                invitation = null
                toName = null
                verifyCode = null
                verifiedNow = null
                chats.clear()
                publicLinks.clear()
                contactRequests.clear()
                myHandle = null
                suggestedName = null
                phase = Phase.Locked
                // A locked client holds no key that reads a queue, thus the
                // carrier ends, and the user learns it.
                DeliveryService.stop(app)
                if (!isVisible) Notifier.locked(app)
            }
            is FfiEvent.IntegrityFault -> fault = "The local store does not verify."
            // Another device of the set added a conversation, named one, or
            // changed the set.
            is FfiEvent.Conversations -> {
                refreshChats()
                readDevices()
                readDirectory()
            }
            // The sync channel of a device opened.
            is FfiEvent.DeviceLinked -> {
                readDevices()
                readLink()
            }
            is FfiEvent.ContactRequest -> {
                readDirectory()
                if (!isVisible) Notifier.request(app)
            }
        }
        // An event can hold a handle of a message, and this frees it.
        event.destroy()
    }

    private fun cause(code: UByte): String = when (code.toInt()) {
        DIAL_FAILED -> "The ingress relay did not answer."
        2 -> "The link to the ingress relay closed."
        3 -> "A relay ended the circuit."
        5 -> "The store took no batch."
        else -> "A fault in the client."
    }

    private fun readConnection() = call { client ->
        val read = client.connection()
        main.post { connection = read }
    }

    /**
     * Starts a new run after a run ended with a fault. Android closes the
     * sockets of an app that left the screen, thus a run starts while a view
     * is on the screen or the carrier runs. The store holds each contact, and
     * the new run continues them.
     */
    private fun retryLater(app: Context) {
        val delay = retryDelayMs
        retryDelayMs = (retryDelayMs * 2).coerceAtMost(LAST_RETRY_MS)
        main.postDelayed({ if (wantsNetwork() && !online) connect(app) }, delay)
    }

    /** The platform leaves the sockets of a visible app and of the carrier. */
    private fun wantsNetwork() = phase == Phase.Open && (isVisible || carrierHolds)

    /** The foreground service tells the core when it starts and when it ends. */
    fun carrierRuns(context: Context, runs: Boolean) {
        carrierHolds = runs
        if (runs && !online && phase == Phase.Open) connect(context)
    }

    /** The user acted, thus the idle time of the auto-lock starts again. */
    fun touched() {
        val now = SystemClock.elapsedRealtime()
        if (now - lastTouchMs < TOUCH_GAP_MS) return
        lastTouchMs = now
        call { it.touch() }
    }

    /** The activity tells the core when a view enters or leaves the screen. */
    fun visible(context: Context, nowVisible: Boolean) {
        isVisible = nowVisible
        // The client makes cover cells while a view is on the screen only.
        call { it.setForeground(nowVisible) }
        if (nowVisible) Notifier.clear(context)
        // The setting "Immediately" locks when the last view leaves.
        if (!nowVisible && autoLockSeconds == 0L && phase == Phase.Open) lock()
        if (nowVisible && !online && phase == Phase.Open) {
            retryDelayMs = FIRST_RETRY_MS
            connect(context)
        }
    }

    fun lock() = call { it.lock() }

    /** Whether the client is open, thus it holds the keys of its queues. */
    fun isOpen() = phase == Phase.Open

    /** The FCM token of this device goes to the core (Part 8 §8.2.7). */
    fun setFcmToken(token: String) = call { it.setFcmToken(token) }

    /** A push came: an open client with no run starts one and drains. */
    fun wake(context: Context) {
        val app = context.applicationContext
        main.post { if (isOpen() && !online) connect(app) }
    }

    /**
     * The largest file that arrives by itself, in bytes (`IMP-167`). Zero
     * is off, and `ULong.MAX_VALUE` is each file.
     */
    var autoDownloadLimit by mutableStateOf(25uL * 1_024uL * 1_024uL)
        private set

    /** Whether the automatic download waits for a network with no cost by the byte (`IMP-168`). */
    var autoDownloadWifiOnly by mutableStateOf(false)
        private set

    fun setAutoDownload(bytes: ULong, wifiOnly: Boolean) = call { client ->
        client.setAutoDownloadLimit(bytes)
        client.setAutoDownloadUnmeteredOnly(wifiOnly)
        main.post {
            autoDownloadLimit = bytes
            autoDownloadWifiOnly = wifiOnly
        }
    }

    /** Whether the network of the device costs by the byte, as the platform marks it. */
    private fun isMetered(context: Context): Boolean =
        context.getSystemService(android.net.ConnectivityManager::class.java)?.isActiveNetworkMetered ?: true

    private var isWatchingNetwork = false

    /**
     * Tells the core each change of the cost of the network. A move to a
     * network with no cost by the byte starts the files that waited for it.
     */
    private fun watchNetwork(context: Context) {
        if (isWatchingNetwork) return
        val manager = context.getSystemService(android.net.ConnectivityManager::class.java) ?: return
        isWatchingNetwork = true
        manager.registerDefaultNetworkCallback(
            object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: android.net.Network,
                    capabilities: android.net.NetworkCapabilities,
                ) {
                    val metered = !capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    call { client -> client.setMetered(metered) }
                }
            },
        )
    }

    fun setAutoLock(seconds: Long) = call { client ->
        client.setAutoLock(seconds.toULong())
        main.post { autoLockSeconds = seconds }
    }

    /**
     * Changes the passphrase. This call overwrites the two arrays. `onResult`
     * gets null, or the words of the fault.
     */
    fun changePassphrase(current: CharArray, new: CharArray, onResult: (String?) -> Unit) {
        val client = handle ?: return onResult("UMBRA is locked.")
        worker.execute {
            val currentUnits = current.map { it.code.toUShort() }
            val newUnits = new.map { it.code.toUShort() }
            current.fill('\u0000')
            new.fill('\u0000')
            val failure = try {
                client.changePassphrase(currentUnits, newUnits)
                null
            } catch (wrong: FfiException.WrongPassphrase) {
                "The current passphrase is not right."
            } catch (other: FfiException) {
                "The passphrase did not change: ${other.javaClass.simpleName}."
            }
            main.post { onResult(failure) }
        }
    }

    /** Starts the network again after it ended. */
    fun connect(context: Context, force: Boolean = false) {
        val app = context.applicationContext
        // The open, the carrier, and the screen each ask for a run in the
        // first second. A second run replaces the first, and the handshake
        // that the first one started ends with it.
        if (isStarting && !force) return
        isStarting = true
        call { client ->
            val network = BuildNetwork.network(app, client)
            if (network == null) {
                // No manifest verified, fresh or kept, thus no run starts
                // and no run ends to call for a retry. The backoff of a run
                // that ended tries again.
                main.post {
                    isStarting = false
                    degraded = "The relays do not answer. Messages wait."
                    retryLater(app)
                }
                return@call
            }
            try {
                client.connect(network)
            } catch (failure: FfiException) {
                main.post { isStarting = false }
                throw failure
            }
            // A run starts in the foreground tier, thus it takes the state
            // of this moment.
            client.setForeground(isVisible)
        }
    }

    fun invite() = call { it.invite() }

    /**
     * Makes a private group of Part 11. The two relays of its queues come
     * from the relay set, and the group sends nothing until both answered.
     */
    fun createGroup(name: String, onMade: (Conversation) -> Unit) = call { client ->
        val conversation = Conversation(client.createGroup(name))
        val list = summaries(client)
        main.post {
            chats.clear()
            chats.addAll(list)
            onMade(conversation)
        }
    }

    /** The offers of a group that wait for this user (`GRP-170`). */
    val groupOffers = mutableStateListOf<FfiGroupOffer>()

    /** The contacts that asked to come into a group of this device. */
    val groupJoiners = mutableStateListOf<FfiGroupOffer>()

    /** Offers a group to a contact on their pairwise channel. */
    fun offerGroup(group: Conversation, to: Conversation) = call { client ->
        client.offerGroup(group.id, to.id)
    }

    /** Takes an offer: this device makes its group keys and asks to come in. */
    fun acceptGroupOffer(offer: FfiGroupOffer) = call { client ->
        client.acceptGroupOffer(offer.from, offer.groupId)
        refreshJoinFlow()
    }

    /** Lets a contact into a group of this device (§11.9.1 steps 3 and 4). */
    fun admitJoiner(joiner: FfiGroupOffer) = call { client ->
        client.admitJoiner(joiner.from, joiner.groupId)
        refreshJoinFlow()
        refreshChats()
    }

    /** The active members of a group, in index order. */
    fun groupMembers(conversation: Conversation, onLoaded: (List<FfiGroupMember>) -> Unit) =
        call { client ->
            val members = client.groupMembers(conversation.id)
            main.post { onLoaded(members) }
        }

    /** Gives a member a role. The owner credentials follow the admin roles. */
    fun setGroupRole(conversation: Conversation, index: UShort, role: FfiRole, then: () -> Unit) =
        call { client ->
            client.setGroupRole(conversation.id, index, role)
            refreshChats()
            main.post { then() }
        }

    /** Removes a member. The group starts a new epoch in the same action. */
    fun removeFromGroup(conversation: Conversation, index: UShort, then: () -> Unit) =
        call { client ->
            client.removeFromGroup(conversation.id, index)
            refreshChats()
            main.post { then() }
        }

    /** Leaves a group. The group keeps each message this device sent. */
    fun leaveGroup(conversation: Conversation, then: () -> Unit) = call { client ->
        client.leaveGroup(conversation.id)
        refreshChats()
        main.post { then() }
    }

    private fun refreshJoinFlow() = call { client ->
        val offers = client.groupOffers()
        val joiners = client.groupJoiners()
        main.post {
            groupOffers.clear()
            groupOffers.addAll(offers)
            groupJoiners.clear()
            groupJoiners.addAll(joiners)
        }
    }

    /** Accepts the link of a contact. A link that does not parse is a fault. */
    fun accept(link: String) = call { it.accept(link) }

    /** Gives a contact a name that this device alone holds. */
    fun setName(conversation: Conversation, name: String) = call { client ->
        client.setContactName(conversation.id, name)
        refreshChats()
    }

    /** Which receipts this device sends to the contact of a conversation. */
    fun receipts(conversation: Conversation, onLoaded: (Receipts) -> Unit) = call { client ->
        val settings = client.receiptSettings(conversation.id)
        main.post { onLoaded(settings) }
    }

    fun setReceipts(conversation: Conversation, settings: Receipts) =
        call { it.setReceiptSettings(conversation.id, settings) }

    /** The 60 digits of the two keys of a conversation. It needs no network. */
    fun safetyNumber(conversation: Conversation, onLoaded: (String) -> Unit) = call { client ->
        val number = client.safetyNumber(conversation.id)
        main.post { onLoaded(number) }
    }

    /**
     * Compares a scanned safety number with the number of this device. A
     * match records the verification, and `onResult` gets the answer.
     */
    fun verifyByNumber(conversation: Conversation, scanned: String, onResult: (Boolean) -> Unit) =
        call { client ->
            val isMatch = client.verifyByNumber(conversation.id, scanned)
            if (isMatch) refreshChats()
            main.post { onResult(isMatch) }
        }

    /** Starts a ceremony. A fault goes to `verifyFault`. */
    fun startVerification(conversation: Conversation) {
        endVerification()
        val client = handle ?: return
        worker.execute {
            try {
                client.startVerification(conversation.id)
            } catch (failure: FfiException) {
                main.post { verifyFault = "A short code needs a connection." }
            }
        }
    }

    /** The user says that the two codes match. */
    fun confirmVerification(conversation: Conversation) = call { it.confirmVerification(conversation.id) }

    /** The user left the ceremony, thus its code shows no more. */
    fun endVerification() {
        verifyCode = null
        verifiedNow = null
        verifyFault = null
    }

    /** The user looks at the conversation, thus its messages are seen. */
    fun markRead(conversation: Conversation) = call { client ->
        client.markRead(conversation.id)
        refreshChats()
    }

    /**
     * Sends the text of a composer, as an answer to `replyTo` when the user
     * chose one. This call overwrites `text`.
     */
    fun send(conversation: Conversation, text: CharArray, replyTo: MsgHandle? = null) = call { client ->
        val units = text.map { it.code.toUShort() }
        text.fill('\u0000')
        client.newDraft(conversation.id).use { draft ->
            draft.setText(units)
            draft.setReplyTo(replyTo)
            client.sendDraft(draft).destroy()
        }
        main.post { revision++ }
        refreshChats()
    }

    /** Sends a picked image as a message of its own. */
    fun sendPhoto(context: Context, conversation: Conversation, source: android.net.Uri) {
        val app = context.applicationContext
        call { client ->
            client.newDraft(conversation.id).use { draft ->
                if (!Photos.attach(app, source, draft)) {
                    main.post { fault = "That image did not open." }
                    return@call
                }
                client.sendDraft(draft).destroy()
            }
            main.post { revision++ }
            refreshChats()
        }
    }

    /**
     * A file or a video in a draft that waits for the user: it is above
     * `LARGE_FILE_WARN` (`ATT-083`), or it is an original that keeps its
     * metadata (`ATT-157`).
     */
    class PendingSend(
        val conversation: Conversation,
        val draft: uniffi.umbra_ffi.DraftHandle,
        val bytes: Long,
        val isOriginal: Boolean,
    ) {
        /** Whether a send took the draft, thus no drop may destroy it. */
        var isTaken = false
    }

    var pendingSend by mutableStateOf<PendingSend?>(null)
        private set

    /** Sends a picked video after its remux (`ATT-155`). */
    fun sendVideo(context: Context, conversation: Conversation, source: android.net.Uri) {
        val app = context.applicationContext
        call { client ->
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return@call
            val draft = client.newDraft(conversation.id)
            val bytes = Files.attachVideo(app, source, draft)
            if (bytes < 0) {
                draft.destroy()
                main.post { fault = "That video did not open, or it is above 250 MB." }
                return@call
            }
            offer(client, PendingSend(conversation, draft, bytes, isOriginal = false))
        }
    }

    /** Sends a voice message that the composer recorded. */
    @RequiresApi(Build.VERSION_CODES.R)
    fun sendVoice(conversation: Conversation, recording: VoiceRecording) {
        val seconds = recording.finish()
        if (seconds < 0) {
            fault = "That recording is too short."
            return
        }
        call { client ->
            val draft = client.newDraft(conversation.id)
            val bytes = Files.attachVoice(recording, seconds, draft)
            if (bytes < 0) {
                draft.destroy()
                main.post { fault = "That recording did not open." }
                return@call
            }
            offer(client, PendingSend(conversation, draft, bytes, isOriginal = false))
        }
    }

    /** Sends a picked file as it is, with its name. */
    fun sendDocument(context: Context, conversation: Conversation, source: android.net.Uri) {
        val app = context.applicationContext
        call { client ->
            val picked = Files.describe(app, source)
            if (picked.size > MAX_FILE_SIZE) {
                main.post { fault = "A file can be 250 MB at most." }
                return@call
            }
            val draft = client.newDraft(conversation.id)
            if (!Files.attachDocument(app, source, picked, draft)) {
                draft.destroy()
                main.post { fault = "That file did not open." }
                return@call
            }
            offer(client, PendingSend(conversation, draft, picked.size, Files.isMediaOriginal(picked.mime)))
        }
    }

    /** Sends a draft at once, or holds it for the view to ask. */
    private fun offer(client: uniffi.umbra_ffi.Handle, pending: PendingSend) {
        if (pending.bytes > LARGE_FILE_WARN || pending.isOriginal) {
            main.post {
                pendingSend?.draft?.destroy()
                pendingSend = pending
            }
            return
        }
        client.sendDraft(pending.draft).destroy()
        pending.draft.destroy()
        main.post { revision++ }
        refreshChats()
    }

    /** The user took the draft that waits. */
    fun confirmSend(pending: PendingSend) {
        if (pending.isTaken) return
        pending.isTaken = true
        if (pendingSend === pending) pendingSend = null
        call { client ->
            try {
                client.sendDraft(pending.draft).destroy()
            } finally {
                pending.draft.destroy()
            }
            main.post { revision++ }
            refreshChats()
        }
    }

    /**
     * The user dropped the draft that waits (`ATT-084`). A sheet runs its
     * dismissal before the action of a row, thus the draft goes after the
     * event, when no send took it.
     */
    fun cancelSend() {
        val pending = pendingSend ?: return
        pendingSend = null
        main.post { if (!pending.isTaken) pending.draft.destroy() }
    }

    /**
     * Writes the file of a message to a document that the user created, as
     * the save of one file (`IMP-045`).
     */
    fun saveFile(context: Context, line: Line, target: android.net.Uri, onSaved: () -> Unit) {
        val app = context.applicationContext
        call { client ->
            val output = try {
                app.contentResolver.openOutputStream(target, "wt")
            } catch (unwritable: Exception) {
                null
            }
            if (output == null) {
                main.post { fault = "That place does not take a file." }
                return@call
            }
            // The core cannot open the descriptor of a document provider a
            // second time, thus its bytes go through a pipe, in pieces.
            val (read, write) = android.os.ParcelFileDescriptor.createPipe()
            var copied = true
            val copier = kotlin.concurrent.thread {
                val chunk = ByteArray(64 * 1_024)
                try {
                    android.os.ParcelFileDescriptor.AutoCloseInputStream(read).use { from ->
                        output.use { to ->
                            while (true) {
                                val count = from.read(chunk)
                                if (count < 0) break
                                to.write(chunk, 0, count)
                            }
                        }
                    }
                } catch (failed: java.io.IOException) {
                    copied = false
                } finally {
                    chunk.fill(0)
                }
            }
            try {
                client.saveFile(line.handle, "/proc/self/fd/${write.fd}")
            } finally {
                write.close()
                copier.join()
            }
            main.post { if (copied) onSaved() else fault = "The file did not save." }
        }
    }

    /** Opens the file of a message for a player, and gives the source on the main thread. */
    fun openMedia(line: Line, onOpened: (uniffi.umbra_ffi.MediaSource?) -> Unit) = call { client ->
        val source = try {
            client.openMedia(line.handle)
        } catch (absent: FfiException) {
            null
        }
        main.post { onOpened(source) }
    }

    /**
     * The first frame of the video of a message, or null while a worker
     * reads it. The frames live in the memory alone, and a lock drops them.
     */
    fun frame(line: Line): androidx.compose.ui.graphics.ImageBitmap? {
        images[line.key]?.let { return it }
        if (decoding.add(line.key)) {
            call { client ->
                val frame = try {
                    firstFrame(client.openMedia(line.handle))
                } catch (absent: FfiException) {
                    // The store holds no file yet. A later event asks again.
                    null
                }
                main.post {
                    decoding.remove(line.key)
                    frame?.let { images[line.key] = it }
                }
            }
        }
        return null
    }

    /** Asks again for the file of a message that did not arrive. */
    fun fetchFile(message: MsgHandle) = call { client ->
        client.fetchFile(message)
        main.post { revision++ }
    }

    /**
     * The decoded photo of a message, or null while a worker decodes it.
     * The images live in the memory alone, and a lock drops them
     * (`IMP-166`).
     */
    fun image(line: Line): androidx.compose.ui.graphics.ImageBitmap? {
        images[line.key]?.let { return it }
        if (decoding.add(line.key)) {
            call { client ->
                val decoder = Photos.Decoder()
                try {
                    client.msgFile(line.handle, decoder)
                } catch (absent: FfiException) {
                    // The store holds no file yet. A later event asks again.
                }
                main.post {
                    decoding.remove(line.key)
                    decoder.image?.let { images[line.key] = it }
                }
            }
        }
        return null
    }

    private val images = androidx.compose.runtime.mutableStateMapOf<List<Byte>, androidx.compose.ui.graphics.ImageBitmap>()

    /**
     * The thumbnail that the sender put in the record of a photo or a video
     * (`WIR-533`), or null while a worker decodes it. A lock drops it.
     */
    fun preview(line: Line): androidx.compose.ui.graphics.ImageBitmap? {
        previews[line.key]?.let { return it }
        if (decoding.add(listOf<Byte>(0x70) + line.key)) {
            call { client ->
                val decoder = Photos.Decoder()
                try {
                    client.msgPreview(line.handle, decoder)
                } catch (absent: FfiException) {
                    // The record carries no preview.
                }
                main.post { decoder.image?.let { previews[line.key] = it } }
            }
        }
        return null
    }

    private val previews = androidx.compose.runtime.mutableStateMapOf<List<Byte>, androidx.compose.ui.graphics.ImageBitmap>()
    private val decoding = mutableSetOf<List<Byte>>()

    /** Adds a reaction of this device to a message, or takes it away. */
    fun react(message: MsgHandle, emoji: String) = call { client ->
        client.react(message, emoji)
        main.post { revision++ }
    }

    /** Changes the text of a message of this device. This call overwrites `text`. */
    fun edit(conversation: Conversation, message: MsgHandle, text: CharArray) = call { client ->
        val units = text.map { it.code.toUShort() }
        text.fill('\u0000')
        client.newDraft(conversation.id).use { draft ->
            draft.setText(units)
            client.editMessage(message, draft)
        }
        main.post { revision++ }
        refreshChats()
    }

    /** Removes a message, or a placeholder, from this device alone. */
    fun deleteForMe(message: MsgHandle) = call { client ->
        client.deleteForMe(message)
        main.post { revision++ }
        refreshChats()
    }

    /**
     * Asks the contact to delete a message of this device. One request goes
     * in 10 seconds for one conversation, and `onBusy` tells a user who is
     * faster than that.
     */
    fun deleteForEveryone(message: MsgHandle, onBusy: () -> Unit) {
        val client = handle ?: return
        worker.execute {
            try {
                client.deleteForEveryone(message)
                main.post { revision++ }
                refreshChats()
            } catch (busy: FfiException.Busy) {
                main.post(onBusy)
            } catch (failure: FfiException) {
                main.post { fault = "That did not work: ${failure.javaClass.simpleName}." }
            }
        }
    }

    /** Loads the lines of a conversation, and gives them on the main thread. */
    fun load(conversation: Conversation, onLoaded: (List<Line>) -> Unit) = call { client ->
        // A line keeps the handle of its message, because the user can
        // answer it. The collector frees a handle that no line holds.
        val lines = client.messages(conversation.id).map { message ->
            val sink = CharSink()
            val info = client.msgInfo(message)
            // A placeholder of a deleted message has no text.
            if (!info.deleted) client.msgRender(message, sink)
            val quote = info.replyTo?.let { target ->
                val quoted = CharSink()
                // A target of a kind with no text gives an empty quote.
                try {
                    client.msgRender(target, quoted)
                } catch (noText: FfiException) {
                    quoted.chars = CharArray(0)
                }
                val of = client.msgInfo(target)
                // The quote of a file is a word of the interface, or its name.
                val quotedFile = of.file
                if (quotedFile != null && !of.deleted) {
                    quoted.chars = when (quotedFile.mimeClass) {
                        CLASS_IMAGE -> "Photo"
                        CLASS_VIDEO -> "Video"
                        CLASS_VOICE -> "Voice message"
                        else -> quotedFile.name ?: "File"
                    }.toCharArray()
                }
                Quoted(target.key().toList(), of.outgoing, quoted.chars)
            }
            Line(message, sink.chars, info, quote, client.reactions(message))
        }
        main.post { onLoaded(lines) }
    }

    /** Reads the list again, and gives it to `then` on the main thread. */
    private fun refreshChats(then: (List<Chat>) -> Unit = {}) = call { client ->
        val list = summaries(client)
        main.post {
            chats.clear()
            chats.addAll(list)
            then(list)
        }
    }

    private fun summaries(client: Handle): List<Chat> = client.summaries().map { summary ->
        val last = summary.lastMessage
        val sink = CharSink()
        var isOutgoing = false
        last?.use {
            // A record of a kind with no text gives no preview.
            try {
                val info = client.msgInfo(it)
                isOutgoing = info.outgoing
                // The words of a placeholder are words of the interface.
                when {
                    info.deleted -> sink.chars = "Message deleted".toCharArray()
                    info.file != null -> sink.chars = when (info.file?.mimeClass) {
                        CLASS_IMAGE -> "Photo"
                        CLASS_VIDEO -> "Video"
                        CLASS_VOICE -> "Voice message"
                        else -> info.file?.name ?: "File"
                    }.toCharArray()
                    else -> client.msgRender(it, sink)
                }
            } catch (noText: FfiException) {
                sink.chars = CharArray(0)
            }
        }
        val group = if (client.isGroup(summary.conversation)) {
            client.groupInfo(summary.conversation)
        } else {
            null
        }
        Chat(
            conversation = Conversation(summary.conversation),
            name = summary.name,
            preview = sink.chars.takeIf { last != null },
            isPreviewOutgoing = isOutgoing,
            lastAtMs = summary.lastAtMs.toLong(),
            unread = summary.unread.toInt(),
            isVerified = summary.verified,
            isGroup = group != null,
            groupId = group?.groupId ?: ByteArray(0),
            members = group?.members?.toInt() ?: 0,
            isReady = group?.isReady ?: true,
            isClosed = group?.isClosed ?: false,
            isMember = group?.isMember ?: true,
            ownerNeeded = group?.ownerNeeded ?: false,
            isLapsed = group?.isLapsed ?: false,
            isReturning = group?.isReturning ?: false,
            needsInvitation = group?.needsInvitation ?: false,
        )
    }

    private fun call(action: (Handle) -> Unit) {
        val client = handle ?: return
        worker.execute {
            try {
                action(client)
            } catch (locked: FfiException.Locked) {
                // A read that the lock overtook is no fault of the user.
            } catch (failure: FfiException) {
                main.post { fault = "That did not work: ${failure.javaClass.simpleName}." }
            }
        }
    }

    private class CharSink : TextSink {
        var chars = CharArray(0)

        override fun put(codeUnits: List<UShort>) {
            chars = CharArray(codeUnits.size) { codeUnits[it].toInt().toChar() }
        }
    }
}
