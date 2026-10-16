package com.alumiialabs.umbra

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import uniffi.umbra_ffi.Config
import uniffi.umbra_ffi.Connection
import uniffi.umbra_ffi.ContactRequestInfo
import uniffi.umbra_ffi.ConversationTimer
import uniffi.umbra_ffi.FfiGivenShare
import uniffi.umbra_ffi.FfiHeldShare
import uniffi.umbra_ffi.FfiKeyChange
import uniffi.umbra_ffi.FfiModNote
import uniffi.umbra_ffi.FfiRosterNote
import uniffi.umbra_ffi.FfiPoll
import uniffi.umbra_ffi.FfiEvent
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.ForwardRules
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
import uniffi.umbra_ffi.initFromRootSeed
import uniffi.umbra_ffi.recoveryDigitsKind
import uniffi.umbra_ffi.measureArgon2FloorMs
import uniffi.umbra_ffi.storeHasHeader
import uniffi.umbra_ffi.MsgHandle
import uniffi.umbra_ffi.MsgReaction

/** A conversation, by its surrogate identifier. */
class Conversation(val id: ByteArray) {
    override fun equals(other: Any?) = other is Conversation && id.contentEquals(other.id)
    override fun hashCode() = id.contentHashCode()

    /** A stable short name for a contact that the user did not name yet. */
    val label: String
        get() = id.take(4).joinToString("") { "%02x".format(it) }

    /** The whole identifier as text, a key that no two conversations share. */
    val key: String
        get() = id.joinToString("") { "%02x".format(it) }
}

/**
 * One message of a conversation view. The text stays a `CharArray`. `quote`
 * is the text of the message that this one answers. An answer to a message
 * that this device does not hold has `isReply` and no quote.
 */
/** `TYPING_TTL` of Part 6 §6.6.9, in milliseconds. */
const val TYPING_TTL_MS = 15_000L

class Line(
    val handle: MsgHandle,
    val text: CharArray,
    val info: MsgInfo,
    val quote: Quoted?,
    val reactions: List<MsgReaction>,
    /** The poll of the line, with the count that this device holds. */
    val poll: FfiPoll? = null,
) {
    /**
     * The identity of the message: two loads of one message give one key. A
     * byte array compares by identity, thus the key is a list.
     */
    val key: List<Byte> = handle.key().toList()

    /** The key of the root of the thread of a group record, or null (`WIR-273`). */
    val threadKey: List<Byte>? = info.thread?.key()?.toList()

    val isReply: Boolean
        get() = info.isReply
}

/** The message that a line answers: its identity, its author, and its text. */
class Quoted(
    val key: List<Byte>,
    val isOutgoing: Boolean,
    val text: CharArray,
    /** The member index of the sender of a quoted group message. */
    val sender: UShort? = null,
)

/** The word of the interface for a file with no text: its kind, or its name. */
fun fileWord(file: uniffi.umbra_ffi.MsgFile): String = when (file.mimeClass) {
    CLASS_IMAGE -> UiText.get(R.string.common_photo)
    CLASS_VIDEO -> UiText.get(R.string.common_video)
    CLASS_VOICE -> UiText.get(R.string.core_file_voice_message)
    CLASS_AUDIO -> file.name ?: UiText.get(R.string.core_file_audio)
    else -> file.name ?: UiText.get(R.string.common_file)
}

/**
 * One row of the chat list and of the contact list. The name is a label of
 * the user. The preview is message text, thus it stays a `CharArray`.
 */
/** The end of a mute with no end (Part 7 `DEV-332`). */
val MUTE_FOREVER: ULong = ULong.MAX_VALUE

class Chat(
    val conversation: Conversation,
    val name: String,
    val preview: CharArray?,
    val isPreviewOutgoing: Boolean,
    /** Whether the newest message answers a message (Part 6 §6.6.5). */
    val isPreviewReply: Boolean = false,
    /** The picture that the user gave the contact, or null (Part 9 §9.8). */
    val picture: androidx.compose.ui.graphics.ImageBitmap? = null,
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
    /** Whether no relay of a group answers, thus its messages wait (`GRP-199`). */
    val isUnreachable: Boolean = false,
    /** Whether a record of a group waits for a clock check (`GRP-229`). */
    val isClockSuspect: Boolean = false,
    /** Whether the user pinned the conversation (Part 7 `DEV-329`). */
    val isPinned: Boolean = false,
    /** The end of the mute in milliseconds of the Unix time, 0 for none (Part 7 `DEV-331`). */
    val mutedUntilMs: ULong = 0u,
) {
    /** Whether a mute holds now. */
    val isMuted: Boolean
        get() = mutedUntilMs > System.currentTimeMillis().toULong()

    /** What each list shows: the name of the user, or a stable short label. */
    val title: String
        get() = name.ifEmpty {
            UiText.get(if (isGroup) R.string.core_title_group else R.string.core_title_contact, conversation.label)
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

    /** The words of a ceremony that did not start or did not finish, and its conversation. */
    var verifyFault by mutableStateOf<Pair<Conversation, String>?>(null)
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
    // The keys of ML-DSA and ML-KEM take a deep stack, as the tokio runtime
    // of the network gives its own threads.
    private val worker = Executors.newSingleThreadExecutor { Thread(null, it, "umbra-core", 16L shl 20) }

    /**
     * The fetch of a manifest and of a key chain waits for a carrier, 20 s
     * at most for each one. It has a thread of its own, thus no view and no
     * send waits for a carrier (`IMP-079`).
     */
    private val networkWorker = Executors.newSingleThreadExecutor { Thread(null, it, "umbra-network", 16L shl 20) }

    /** The remux of a video, the encode of an audio file, and the save of a file take seconds each. */
    private val mediaWorker = Executors.newSingleThreadExecutor { Thread(null, it, "umbra-media", 16L shl 20) }

    /** The lock waits for no call of the worker (`IMP-127`). */
    private val lockWorker = Executors.newSingleThreadExecutor { Thread(null, it, "umbra-lock", 16L shl 20) }
    private var handle: Handle? = null

    /** The handle of an unlock that failed. The next unlock takes it, thus one store opens one time. */
    private var waiting: Handle? = null
    private var draining = false

    init {
        // A debug build moves the lines of the core into the log of the
        // platform. A release build has none to move.
        if (BuildConfig.DEBUG) {
            Thread({
                while (true) {
                    uniffi.umbra_ffi.takeDebugLines().forEach { android.util.Log.d("umbra-core", it) }
                    SystemClock.sleep(1_000)
                }
            }, "umbra-debug-lines").apply { isDaemon = true }.start()
        }
    }

    /** Whether a run started and did not report its first state yet. */
    private var isStarting = false

    /**
     * Whether `dropRun` ended the run of Private mode or of Off, and no
     * view asked for a new one since. The network thread reads it before
     * and after it starts a run. Thus a start that waited for a carrier
     * makes no run that the app dropped.
     */
    @Volatile
    private var runDropped = false

    /** Whether a push or the Private clock asked for a session while a start waited. */
    private var wakeWaits = false

    /** Whether the run that starts or stands is a wake session (`NET-100`). */
    private var isWakeSession = false

    /** Whether a view of the app is on the screen. */
    @Volatile
    private var isVisible = false

    /** The mode of this device (Part 8 §8.3), as `Modes` gave it last. */
    private var mode = NotifyMode.Instant

    /** The ingress relays of the last connection that named one (`NTF-053`). */
    private var ingressPair: Set<String>? = null

    /** Whether the foreground service of the socket carrier runs. */
    private var carrierHolds = false
    private var lastTouchMs = 0L
    private var retryDelayMs = FIRST_RETRY_MS
    private const val TOUCH_GAP_MS = 10_000L

    /** How long a run stands after the last view left, in Private mode and in Off. */
    private const val OFF_SCREEN_MS = 30_000L
    private const val FIRST_RETRY_MS = 2_000L
    private const val LAST_RETRY_MS = 30_000L
    private const val STOPPED = 0
    private const val DIAL_FAILED = 1
    private const val AGED = 6
    private const val WAKE_DONE = 7

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
            var unlocked: Handle? = null
            try {
                val opened = handle ?: waiting ?: launch(app, units).also { waiting = it }
                opened.unlock(units)
                unlocked = opened
                begin(app, opened)
            } catch (wrong: FfiException.WrongPassphrase) {
                fail(UiText.get(R.string.core_wrong_passphrase))
            } catch (other: FfiException) {
                // IMP-127: a fault after the unlock closes the store again,
                // thus no key stays in RAM behind a locked screen.
                try {
                    unlocked?.lock()
                } catch (ignored: FfiException) {
                }
                fail(UiText.get(R.string.core_store_not_open, other.javaClass.simpleName))
            }
        }
    }

    /** Takes an open client: its list, its network, and its events. */
    private fun begin(app: Context, opened: Handle) {
        handle = opened
        waiting = null
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
            mode = Modes.mode(app)
            // NTF-142: the open client takes each record over its own run.
            Watcher.stop()
            if (carrierHolds) Notifier.refreshCarrier(app)
            // The store is open before the network starts: the fetch of the
            // manifest waits for a carrier, and the list does not wait for
            // it. A network that does not start leaves the store open, and
            // the retry of the run starts it later.
            connect(app)
            renewRoots(app)
            refreshJoinFlow()
            readDevices()
            readProfile()
            // Part 8 §8.3: the carriers of the mode of this device.
            Modes.apply(app)
            readTyping()
            readDraftSync()
            readHistoryAge()
        }
    }

    /** NTF-084: three blobs in a row did not open, thus the client makes each root again. */
    private fun renewRoots(app: Context) {
        if (!WakeStore.isRenewDue(app)) return
        call {
            it.renewPushRoots()
            WakeStore.renewed(app)
        }
    }

    /** Whether the mode and the state of the client hold the carrier (Part 8 §8.3). */
    fun wantsCarrier() = phase == Phase.Open && mode != NotifyMode.Off

    /**
     * Starts the foreground service of the carrier (`NTF-116`). The platform
     * permits the start while a view is on the screen alone. An unlock, a
     * restore, or a link can end after the user left. Thus a start that
     * has no view waits for the next one.
     */
    private fun holdCarrier(app: Context) {
        if (carrierHolds || !isVisible || !wantsCarrier()) return
        DeliveryService.start(app)
    }

    /**
     * The mode of this device, at an open and at each change (Part 8 §8.3).
     * Off holds no carrier. A change between the two other modes writes the
     * notice of the service again.
     */
    fun modeIs(context: Context, now: NotifyMode) {
        val app = context.applicationContext
        val changed = mode != now
        mode = now
        if (now == NotifyMode.Off) {
            if (carrierHolds) DeliveryService.stop(app)
        } else if (carrierHolds && changed && isVisible) {
            DeliveryService.start(app)
        } else {
            holdCarrier(app)
        }
        leftScreen()
    }

    /** Whether a view of the app is on the screen. */
    fun isOnScreen() = isVisible

    /** The devices of the set (Part 7). */
    val devices = mutableStateListOf<Device>()

    /** Whether this device owns the channels, thus it can link another. */
    var ownsChannels by mutableStateOf(true)
        private set

    /** The forks of the roster that wait for the user (Part 7 §7.7). */
    val rosterForks = mutableStateListOf<uniffi.umbra_ffi.FfiRosterFork>()

    /** The deletions of the other devices that wait after a restore (`DEV-117`). */
    var heldDeletions by mutableStateOf(0)
        private set

    fun applyHeldDeletions(apply: Boolean) = call { client ->
        if (apply) client.applyHeldDeletions() else client.keepRestoredMessages()
        readDevices()
        refreshChats()
    }

    /** The deletions that a device made here since the last change of the set. */
    fun deletionsFrom(deviceId: ByteArray, onCount: (Int) -> Unit) = call { client ->
        val count = client.deletionsFrom(deviceId).toInt()
        main.post { onCount(count) }
    }

    /** The holes in the synced history (Part 7 §7.5.5). */
    val historyHoles = mutableStateListOf<uniffi.umbra_ffi.FfiHistoryHole>()

    /** Whether another device of the set removed this one (`DEV-181`). */
    var removedFromSet by mutableStateOf(false)
        private set

    /** Whether this device can take the set over now (Part 7 `DEV-231`, `DEV-315`). */
    var canTakeOver by mutableStateOf(false)
        private set

    fun readTakeOver() = call { client ->
        val can = !client.ownsChannels() && client.canTakeOver()
        main.post { canTakeOver = can }
    }

    /** What the lost device owns (Part 7 `DEV-235`). */
    fun takeOverCount(onCount: (uniffi.umbra_ffi.FfiTakeOverCount) -> Unit) = call { client ->
        val count = client.takeOverCount()
        main.post { onCount(count) }
    }

    /**
     * Takes the set over (Part 7 `DEV-314`). The view gets the digits of the
     * new recovery code, or nothing when the core refused. The network runs
     * again as the device that owns the channels.
     */
    fun takeOver(context: Context, onDone: (CharArray?) -> Unit) {
        val app = context.applicationContext
        call { client ->
            val sink = CharSink()
            try {
                client.takeOver(sink)
            } catch (refused: FfiException) {
                main.post { onDone(null) }
                return@call
            }
            main.post {
                canTakeOver = false
                connect(app, force = true)
                readDevices()
                refreshChats()
                onDone(sink.chars)
            }
        }
    }

    fun readDevices() = call { client ->
        val list = client.devices()
        val owns = client.ownsChannels()
        val takes = !owns && client.canTakeOver()
        val removed = client.removedFromSet()
        val forks = client.rosterForks()
        val holes = client.historyHoles()
        val held = client.heldDeletions().toInt()
        main.post {
            heldDeletions = held
            removedFromSet = removed
            canTakeOver = takes
            historyHoles.clear()
            historyHoles.addAll(holes)
            devices.clear()
            devices.addAll(list)
            ownsChannels = owns
            rosterForks.clear()
            rosterForks.addAll(forks)
        }
    }

    fun dismissRosterFork(fork: uniffi.umbra_ffi.FfiRosterFork) = call { client ->
        client.dismissRosterFork(fork.id)
        readDevices()
    }

    /** Whether the contact of a conversation is blocked (Part 13 §13.12). */
    fun isBlocked(conversation: Conversation, onResult: (Boolean) -> Unit) = call { client ->
        val blocked = client.isBlocked(conversation.id)
        main.post { onResult(blocked) }
    }

    fun setBlocked(context: Context, conversation: Conversation, blocked: Boolean) = call { client ->
        client.setBlocked(conversation.id, blocked)
        // The wake table names a blocked contact silent.
        refreshWake(context)
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

    /** The link of the handle with the fragment of its profile. */
    var myHandleLink by mutableStateOf<String?>(null)
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

    /**
     * The calls to the directory take seconds each, thus they have a thread of their own. The
     * proofs of work of the token upkeep run on it, at a priority below the view.
     */
    private val directoryWorker = Executors.newSingleThreadExecutor { work ->
        Thread(null, {
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
            work.run()
        }, "umbra-directory", 16L shl 20)
    }
    private const val MAINTAIN_MS = 5 * 60_000L
    private var maintains = false

    fun readDirectory() = call { client ->
        val links = client.publicLinks()
        val handle = client.myHandle()
        val handleLink = client.myHandleLink()
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
            myHandleLink = handleLink
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
        is FfiException.Offline -> UiText.get(R.string.core_directory_offline)
        is FfiException.Busy -> UiText.get(R.string.core_directory_busy)
        is FfiException.Stale -> UiText.get(R.string.core_directory_stale)
        is FfiException.NotFound -> UiText.get(R.string.core_directory_not_found)
        is FfiException.Unverified -> UiText.get(R.string.core_directory_unverified)
        is FfiException.Malformed -> UiText.get(R.string.core_directory_malformed)
        else -> UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName)
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

    /** The name and the welcome text that the profile link of the handle shows. */
    fun profile(onProfile: (String, String, ByteArray) -> Unit) = call { client ->
        val name = client.profileName()
        val welcome = client.welcome()
        val picture = client.profilePicture()
        main.post { onProfile(name, welcome, picture) }
    }

    /**
     * Encodes the square that the user cropped anew as the picture of the
     * profile, and writes the profile blob (Part 9 §9.3.1). Null removes it.
     */
    fun setProfilePicture(square: android.graphics.Bitmap?, onPicture: (ByteArray) -> Unit) {
        directory { client ->
            val picture = if (square == null) {
                ByteArray(0)
            } else {
                Photos.picture(square) ?: run {
                    main.post { directoryNote = UiText.get(R.string.core_image_did_not_fit) }
                    return@directory
                }
            }
            client.setProfilePicture(picture)
            main.post {
                onPicture(picture)
                myPicture = picture
            }
        }
    }

    /** Sets the name and the welcome text, and writes the profile blob (Part 9 §9.3.1). */
    fun setProfile(name: String, welcome: String) = directory { client ->
        client.setProfileName(name)
        client.setWelcome(welcome)
        main.post { myName = name.trim() }
    }

    /** The name of the profile, for the picture of the top bar. */
    var myName by mutableStateOf("")
        private set

    /** The picture of the profile, or none. */
    var myPicture by mutableStateOf(ByteArray(0))
        private set

    /** Reads the name and the picture that the top bar shows. */
    fun readProfile() = call { client ->
        val name = client.profileName()
        val picture = client.profilePicture()
        main.post {
            myName = name
            myPicture = picture
        }
    }

    /** What a profile link shows, or nothing when the lookup fails. */
    fun previewContact(link: String, onPreview: (uniffi.umbra_ffi.ContactPreview) -> Unit) = call { client ->
        val preview = try {
            client.previewContact(link)
        } catch (failure: FfiException) {
            null
        }
        preview?.let { main.post { onPreview(it) } }
    }

    /** The handle that a different party now holds (Part 9 §9.9.2), which waits for a confirmation. */
    var takeoverOf by mutableStateOf<String?>(null)

    /**
     * Sends a request to a reusable link or a handle, under the name of the user. A handle that
     * a different party now holds waits in [takeoverOf] until the user confirms (`DIS-085`).
     */
    fun sendRequest(target: String, name: String, note: String, confirmed: Boolean = false) {
        requestSent = false
        takeoverOf = null
        directory { client ->
            client.setProfileName(name)
            try {
                client.sendContactRequest(target, note, confirmed)
                main.post { requestSent = true }
            } catch (takeover: FfiException.Takeover) {
                main.post { takeoverOf = target }
            }
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

    private fun scheduleMaintenance(app: Context) {
        if (maintains) return
        maintains = true
        main.postDelayed(object : Runnable {
            override fun run() {
                if (!online) {
                    maintains = false
                    return
                }
                maintainDirectory()
                // NTF-135: a run rotates roots and makes queues, thus the
                // table follows each change within one round.
                refreshWake(app)
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
                    fault = UiText.get(R.string.core_link_busy)
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
        joinNote = UiText.get(R.string.core_connecting)
        worker.execute {
            val units = passphrase.map { it.code.toUShort() }
            passphrase.fill('\u0000')
            var opened: Handle? = null
            try {
                dropWaiting()
                val first = launch(app, units)
                opened = first
                first.unlock(units)
                val network = BuildNetwork.network(app, first)
                if (network == null) {
                    dropStore(app, first)
                    joinFailed(UiText.get(R.string.core_no_network))
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
                            joinNote = UiText.get(R.string.core_copying)
                        }
                        is LinkStatus.Expired -> failure = UiText.get(R.string.core_code_ran_out)
                        is LinkStatus.Failed -> failure = UiText.get(R.string.common_link_failed)
                        else -> Unit
                    }
                    if (!isReady && failure == null) {
                        if (System.currentTimeMillis() > deadline) failure = UiText.get(R.string.common_link_failed)
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
                joinFailed(UiText.get(R.string.core_not_link_code))
            } catch (other: FfiException) {
                opened?.let { dropStore(app, it) }
                joinFailed(UiText.get(R.string.core_link_failed_kind, other.javaClass.simpleName))
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
    /** The user half of the recovery code as its 49 digits (Part 4 §4.7.7). */
    fun userHalf(onLoaded: (CharArray) -> Unit) = call { client ->
        val sink = CharSink()
        client.userHalf(sink)
        main.post { onLoaded(sink.chars) }
    }

    /** The share that a contact gave to this user, as its 51 digits. */
    fun heldShareDigits(conversation: Conversation, onLoaded: (CharArray) -> Unit) = call { client ->
        val sink = CharSink()
        client.heldShareDigits(conversation.id, sink)
        main.post { onLoaded(sink.chars) }
    }

    /** The share that a contact gave to this user, or none. */
    fun heldShare(conversation: Conversation, onLoaded: (FfiHeldShare?) -> Unit) = call { client ->
        val held = client.heldShare(conversation.id)
        main.post { onLoaded(held) }
    }

    /** The holders of the current split of the social half. */
    fun sharesGiven(onLoaded: (List<FfiGivenShare>) -> Unit) = call { client ->
        val given = client.sharesGiven()
        main.post { onLoaded(given) }
    }

    /** Sends one share of the social half to each holder (Part 4 §4.7.3). */
    fun splitSocial(holders: List<Conversation>, threshold: Int, onDone: () -> Unit) = call { client ->
        client.splitSocial(holders.map { it.id }, threshold.toUByte())
        main.post { onDone() }
    }

    fun rootSeed(onLoaded: (CharArray) -> Unit) = call { client ->
        val sink = CharSink()
        client.rootSeed(sink)
        main.post { onLoaded(sink.chars) }
    }

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
    fun restore(
        context: Context,
        passphrase: CharArray,
        digits: CharArray,
        shares: List<CharArray> = emptyList(),
    ) {
        val app = context.applicationContext
        fault = null
        restoreNote = UiText.get(R.string.core_looking_for_backup)
        worker.execute {
            val units = passphrase.map { it.code.toUShort() }
            passphrase.fill('\u0000')
            val code = digits.map { it.code.toUShort() }
            digits.fill('\u0000')
            val shareUnits = shares.map { share -> share.map { it.code.toUShort() }.also { share.fill('\u0000') } }
            // IDN-151 to IDN-154: the check and the type come first, and a
            // wrong type names both types. A restore with shares takes the
            // user half (IDN-191).
            val wanted = if (shareUnits.isEmpty()) 1 else 2
            val kind = recoveryDigitsKind(code).toInt()
            val names = mapOf(
                1 to R.string.core_digits_recovery_code,
                2 to R.string.core_digits_user_half,
                3 to R.string.core_digits_share,
                4 to R.string.core_digits_root_seed,
            )
            // IDN-003: the root seed makes a store with the identity alone.
            if (kind == 4 && shareUnits.isEmpty()) {
                try {
                    dropWaiting()
                    val database = File(app.filesDir, "umbra.db")
                    val made = initFromRootSeed(
                        Config(database.absolutePath, measureArgon2FloorMs()),
                        KeystoreElement(app),
                        units,
                        code,
                    )
                    main.post { restoreNote = null }
                    begin(app, made)
                } catch (failure: FfiException) {
                    restoreFailed(UiText.get(R.string.core_root_seed_not_open, failure.javaClass.simpleName))
                }
                return@execute
            }
            if (kind != wanted) {
                restoreFailed(
                    if (kind == 0) {
                        // IDN-152: a check that fails says so.
                        UiText.get(R.string.umbra_ui_idn_152)
                    } else {
                        UiText.get(
                            R.string.core_digits_wrong_kind,
                            names[kind]?.let { UiText.get(it) }.toString(),
                            UiText.get(names.getValue(wanted)),
                        )
                    },
                )
                return@execute
            }
            if (shareUnits.any { recoveryDigitsKind(it).toInt() != 3 }) {
                restoreFailed(UiText.get(R.string.core_share_no_check))
                return@execute
            }
            var opened: Handle? = null
            try {
                dropWaiting()
                val first = launch(app, units)
                opened = first
                first.unlock(units)
                val network = BuildNetwork.network(app, first)
                if (network == null) {
                    dropStore(app, first)
                    restoreFailed(UiText.get(R.string.core_no_network))
                    return@execute
                }
                first.connect(network)
                if (shareUnits.isEmpty()) {
                    first.restoreBackup(code)
                } else {
                    first.restoreBackupWithShares(code, shareUnits)
                }
                val deadline = System.currentTimeMillis() + RESTORE_WAIT_MS
                var failure: String? = null
                var isReady = false
                while (!isReady && failure == null) {
                    when (val status = first.restoreStatus()) {
                        is RestoreStatus.Ready -> isReady = true
                        is RestoreStatus.NotFound -> failure = UiText.get(R.string.core_backup_not_found)
                        // IDN-155: an empty identity is no account.
                        is RestoreStatus.NoIdentity -> failure = UiText.get(R.string.core_backup_no_identity)
                        is RestoreStatus.Failed -> failure = UiText.get(R.string.core_backup_not_down)
                        is RestoreStatus.Fetching ->
                            main.post {
                                restoreNote = UiText.get(R.string.core_restoring, status.done.toInt(), status.total.toInt())
                            }
                        else -> Unit
                    }
                    if (!isReady && failure == null) {
                        if (System.currentTimeMillis() > deadline) failure = UiText.get(R.string.core_backup_not_down)
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
                restoreFailed(UiText.get(R.string.core_restore_failed, other.javaClass.simpleName))
            }
        }
    }

    /** Closes the handle of an unlock that failed, before another call opens the store. */
    private fun dropWaiting() {
        waiting?.close()
        waiting = null
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

    /**
     * The local wipe of Part 7 `DEV-008`: the run ends, and the platform
     * deletes each file, preference, and key of the app, and it ends the
     * process. The next start is a first launch.
     */
    fun eraseDevice(context: Context) {
        val app = context.applicationContext
        worker.execute {
            handle?.let {
                it.disconnect()
                it.close()
            }
            handle = null
            waiting = null
            // NTF-137: the wake table lies outside the store.
            runCatching { WakeStore.delete(app) }
            (app.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager)
                .clearApplicationUserData()
        }
    }

    /**
     * Whether this device holds a store, thus the unlock view says so. A
     * first launch that ended before its key left a file that holds none.
     */
    fun hasStore(context: Context) =
        handle != null || storeHasHeader(File(context.filesDir, "umbra.db").absolutePath)

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
                // NTF-135: a binding changed, and the table follows it here,
                // before the next tick can run the auto-lock.
                if (event is FfiEvent.WakeTable) {
                    writeWake(app, opened)
                    event.destroy()
                    continue
                }
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
                readConnection(app)
                readDirectory()
                maintainDirectory()
                scheduleMaintenance(app)
            }
            is FfiEvent.Circuits -> readConnection(app)
            is FfiEvent.Offline -> {
                isStarting = false
                isWakeSession = false
                online = false
                readConnection(app)
                if (event.cause.toInt() == WAKE_DONE) {
                    // NET-100: the push-wake session ended on time. A view
                    // on the screen takes a full run.
                    if (wantsNetwork()) connect(app)
                } else if (event.cause.toInt() == AGED) {
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
                    degraded = UiText.get(
                        if (event.cause.toInt() == DIAL_FAILED) {
                            R.string.umbra_ui_imp_077_ingress
                        } else {
                            R.string.umbra_ui_imp_077_offline
                        },
                    )
                    linkFault = cause(event.cause)
                    retryLater(app)
                }
            }
            is FfiEvent.Invitation -> invitation = event.link
            is FfiEvent.Refused -> fault = UiText.get(R.string.core_refused_relay)
            // IDN-023: a fetch by a second party is an attack that the two
            // parties detect, thus the words name that cause first.
            is FfiEvent.InvitationGone -> fault = UiText.get(R.string.core_invitation_gone)
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
                val conversation = Conversation(event.conversation)
                // The ceremony of one contact ends no code of another.
                if (verifyCode?.first == conversation) verifyCode = null
                verifyFault = conversation to UiText.get(R.string.core_verify_no_code)
            }
            is FfiEvent.Message -> {
                revision++
                // The message that the contact typed ends its typing state.
                typingNow.remove(event.conversation.toList())
                refreshChats()
                // DEV-223: the device woke on its mode, and the setting of the
                // conversation decides what it shows.
                // Part 8 §8.3: Off shows a message when the user opens the app.
                val client = handle
                if (!isVisible && client != null && mode != NotifyMode.Off) {
                    // GRP-229: while the clock may be wrong, no alert
                    // shows a preview (Part 14 §14.9.2).
                    val preview = Modes.preview(app) && chats.none { it.isClockSuspect } &&
                        !WakeStore.isClockSuspect(app)
                    val title = chats.firstOrNull { it.conversation.id.contentEquals(event.conversation) }?.title
                    // The worker reads the handle of the message, thus the
                    // worker frees the event after that read.
                    worker.execute {
                        try {
                            if (client.shouldAlert(event.message)) {
                                // NTF-083: the sender and the text only when
                                // the user turned the preview on.
                                // IMP-017: the text stays a CharArray, and
                                // the alert wipes it after the post.
                                val text = if (preview) {
                                    val sink = CharSink()
                                    runCatching { client.msgRender(event.message, sink) }
                                    sink.chars
                                } else {
                                    null
                                }
                                main.post {
                                    // A lock that came since takes the text
                                    // of no alert to the shade.
                                    if (phase == Phase.Open) {
                                        Notifier.message(app, Conversation(event.conversation), title.takeIf { preview }, text)
                                    } else {
                                        text?.fill('\u0000')
                                    }
                                }
                            } else {
                                // The push of this record showed an alert
                                // before the client read the setting.
                                Notifier.pushSettled(app, Conversation(event.conversation))
                            }
                        } catch (_: FfiException) {
                            // A lock that overtook the read shows no alert.
                        } finally {
                            event.destroy()
                        }
                    }
                    return
                }
            }
            is FfiEvent.Delivery -> {
                revision++
                refreshChats()
            }
            // The file of a message arrived, left, or failed.
            is FfiEvent.File -> revision++
            // The join flow of a group moved.
            is FfiEvent.GroupOffer, is FfiEvent.GroupJoiner, is FfiEvent.Introduction -> {
                refreshJoinFlow()
                refreshChats()
            }
            // A reaction, an edit, and a deletion are no arrival, thus they
            // raise no alert.
            is FfiEvent.Reacted -> revision++
            // NET-355: the question of an open conversation shows or goes.
            is FfiEvent.RenewalAsk -> revision++
            is FfiEvent.Voted -> revision++
            is FfiEvent.Typing -> if (typingEnabled) {
                val key = event.conversation.toList()
                if (event.isTyping) {
                    val until = System.currentTimeMillis() + TYPING_TTL_MS
                    typingNow[key] = until
                    // WIR-286: the state clears TYPING_TTL after the record.
                    main.postDelayed({ if (typingNow[key] == until) typingNow.remove(key) }, TYPING_TTL_MS)
                } else {
                    typingNow.remove(key)
                }
            }
            is FfiEvent.Edited -> {
                revision++
                refreshChats()
            }
            // DEV-114: an edit or a deletion of this device reached no relay.
            is FfiEvent.ChangeFailed -> {
                fault = UiText.get(
                    if (event.isDelete) R.string.umbra_ui_dev_114 else R.string.umbra_ui_dev_114_edit,
                )
                revision++
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
                // A picture of a contact is private data of the user.
                on(worker) { pictures.clear() }
                // IMP-180: the query of a search leaves with the key.
                searchBuilds++
                searchTurns++
                searchQuery?.fill('\u0000')
                searchQuery = null
                // IMP-161: a draft that waits holds its file in the clear.
                cancelSend()
                online = false
                isWakeSession = false
                wakeWaits = false
                invitation = null
                // A scanned invitation is a capability.
                scannedInvitation = null
                joinCode = null
                // The run ended with the lock, thus its two lines are old.
                // `fault` stays: the lock view shows it, as for a store
                // that does not verify.
                degraded = null
                linkFault = null
                toName = null
                verifyCode = null
                verifyFault = null
                verifiedNow = null
                // IMP-017: the preview of a row is message text.
                chats.forEach { it.preview?.fill('\u0000') }
                chats.clear()
                publicLinks.clear()
                contactRequests.clear()
                myHandle = null
                suggestedName = null
                // A locked client holds no name, no picture, and no list of
                // the store in its memory.
                myHandleLink = null
                myName = ""
                myPicture.fill(0)
                myPicture = ByteArray(0)
                devices.clear()
                historyHoles.clear()
                rosterForks.clear()
                heldDeletions = 0
                introductions.clear()
                failedAdmissions.clear()
                directoryWarnings.clear()
                entriesAtLimit.clear()
                directoryNote = null
                madeLink = null
                takeoverOf = null
                requestSent = false
                typingNow.clear()
                connection = null
                linkStatus = LinkStatus.Idle
                main.removeCallbacks(dropRun)
                phase = Phase.Locked
                // A locked client holds no key that reads a queue, thus the
                // carrier ends, and the user learns it. A service that did
                // not start yet ends itself at its start. In Direct mode
                // the service holds the watch of the locked client in its
                // place (`NTF-142`).
                val watches = wantsWatch(app)
                if (carrierHolds) {
                    if (watches) Watcher.start(app) else DeliveryService.stop(app)
                }
                // A lock takes the text of each alert off the shade.
                Notifier.clear(app)
                if (!isVisible && !(watches && carrierHolds)) Notifier.locked(app)
            }
            is FfiEvent.IntegrityFault -> fault = UiText.get(R.string.core_store_no_verify)
            // The drain thread wrote the table already.
            is FfiEvent.WakeTable -> {}
            // Another device of the set added a conversation, named one, or
            // changed the set.
            is FfiEvent.Conversations -> {
                // A note of a roster shows in an open conversation too.
                revision++
                refreshChats()
                readDevices()
                readDirectory()
                // A block or an alert setting of another device changes
                // which conversations the wake table names silent.
                refreshWake(app)
            }
            // The sync channel of a device opened.
            is FfiEvent.DeviceLinked -> {
                readDevices()
                readLink()
            }
            is FfiEvent.ContactRequest -> {
                readDirectory()
                if (!isVisible && mode != NotifyMode.Off) Notifier.request(app)
            }
        }
        // An event can hold a handle of a message, and this frees it.
        event.destroy()
    }

    private fun cause(code: UByte): String = when (code.toInt()) {
        DIAL_FAILED -> UiText.get(R.string.core_cause_ingress_no_answer)
        2 -> UiText.get(R.string.core_cause_ingress_closed)
        3 -> UiText.get(R.string.core_cause_circuit_ended)
        5 -> UiText.get(R.string.core_cause_store_no_batch)
        else -> UiText.get(R.string.core_cause_client_fault)
    }

    private fun readConnection(app: Context) = call { client ->
        val read = client.connection()
        main.post {
            connection = read
            // NTF-053: a new ingress relay pair draws a new phase of the
            // Private clock. The two pins change places with no new pair.
            val pair = setOfNotNull(read.ingress?.host, read.standby?.host)
            if (pair.isNotEmpty() && pair != ingressPair) {
                ingressPair = pair
                Modes.ingressChanged(app)
            }
        }
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

    /**
     * The platform leaves the sockets of a visible app and of the carrier.
     * Instant mode and Direct mode alone hold a run with no view (Part 8
     * §8.3). The fixed clock of Private mode starts each run of that mode,
     * and Off has none.
     */
    private fun wantsNetwork() =
        phase == Phase.Open && (isVisible || (carrierHolds && mode.holdsConnection))

    /** The foreground service tells the core when it starts and when it ends. */
    fun carrierRuns(context: Context, runs: Boolean) {
        carrierHolds = runs
        if (runs && !online && wantsNetwork()) connect(context)
    }

    /** Ends the run of Private mode and of Off after the last view left. */
    private val dropRun = Runnable {
        if (isVisible || phase != Phase.Open || mode.holdsConnection) return@Runnable
        // NET-100: a wake session ends by itself, and no drop cuts its drain.
        if (isWakeSession) return@Runnable
        // A start that waits on the network thread makes no run after this.
        runDropped = true
        call { client -> if (!isVisible) client.disconnect() }
    }

    /**
     * Private mode and Off hold no run with no view. The run stands a short
     * time, thus a picker of the platform or a send that the user started
     * ends first.
     */
    private fun leftScreen() {
        main.removeCallbacks(dropRun)
        if (!isVisible && phase == Phase.Open && !mode.holdsConnection) {
            main.postDelayed(dropRun, OFF_SCREEN_MS)
        }
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
        val app = context.applicationContext
        isVisible = nowVisible
        // The client makes cover cells while a view is on the screen only.
        call { it.setForeground(nowVisible) }
        if (nowVisible) Notifier.clear(context)
        // The setting "Immediately" locks when the last view leaves.
        // NTF-135: the client writes the table before a lock can take the keys.
        if (!nowVisible && autoLockSeconds == 0L && phase == Phase.Open) {
            lock(app)
        } else if (!nowVisible) {
            refreshWake(context)
        }
        leftScreen()
        if (nowVisible && phase == Phase.Open) {
            // NTF-084: three blobs in a row did not open in this session.
            renewRoots(app)
            // A carrier that had no view at the unlock starts now.
            holdCarrier(app)
        }
        if (nowVisible && !online && phase == Phase.Open) {
            retryDelayMs = FIRST_RETRY_MS
            connect(context)
        }
    }

    /**
     * Locks the client at once. The lock has a thread of its own: a call
     * that waits on the worker keeps `K_store` in RAM no longer (`IMP-127`).
     * With a context the lock writes the wake table first (`NTF-135`).
     */
    fun lock(context: Context? = null) {
        val client = handle ?: return
        val app = context?.applicationContext
        lockWorker.execute {
            if (app != null && holdsWakeTable(app)) writeWake(app, client)
            client.lock()
        }
    }

    /**
     * Whether the mode holds a wake table (Part 8 `NTF-135`): Instant mode
     * on a build with push, and Direct mode, whose watch takes the blobs.
     */
    private fun holdsWakeTable(app: Context) = when (Modes.mode(app)) {
        NotifyMode.Instant -> Push.isAvailable(app)
        NotifyMode.Direct -> true
        else -> false
    }

    /**
     * Writes the wake table, thus a locked client opens each blob, and in
     * Direct mode the watch table beside it (`NTF-145`).
     */
    fun refreshWake(context: Context) {
        val app = context.applicationContext
        if (!holdsWakeTable(app)) return
        call { client -> writeWake(app, client) }
    }

    /** One write of the tables. `WakeStore` checks the mode at the write itself. */
    private fun writeWake(app: Context, client: Handle) {
        if (!holdsWakeTable(app)) return
        // A lock that came first leaves the tables of the last write.
        val (table, watch) = try {
            val table = client.wakeTable()
            table to if (Modes.mode(app) == NotifyMode.Direct) client.watchTable() else null
        } catch (locked: FfiException) {
            return
        }
        try {
            WakeStore.write(app, table)
            watch?.let { WakeStore.writeWatch(app, it) }
        } catch (fault: Exception) {
            // The tables of the last write serve until the next one.
            if (BuildConfig.DEBUG) android.util.Log.w("umbra-core", "the wake table did not write", fault)
        } finally {
            table.fill(0)
            watch?.fill(0)
        }
    }

    /**
     * Whether a locked client holds the watch of Direct mode (`NTF-142`):
     * the mode, and a table that the last open client wrote.
     */
    fun wantsWatch(context: Context) =
        phase != Phase.Open && Modes.mode(context) == NotifyMode.Direct && WakeStore.hasWatch(context)

    /** Turns the watch of Direct mode on or off in the store (`NTF-142`). */
    fun setWatch(on: Boolean) = call { it.setWatch(on) }

    /** Whether the client is open, thus it holds the keys of its queues. */
    fun isOpen() = phase == Phase.Open

    /** The push state for the view of the connection. */
    fun pushStatus(onStatus: (uniffi.umbra_ffi.PushStatus) -> Unit) = call { client ->
        val status = client.pushStatus()
        main.post { onStatus(status) }
    }

    /** The link-fault counts of this device (Part 10 §10.4.2). */
    fun linkFaultStatus(onStatus: (uniffi.umbra_ffi.LinkFaultStatus) -> Unit) = call { client ->
        val status = client.linkFaultStatus()
        main.post { onStatus(status) }
    }

    /** The digests of contacts that differ from the view of this device. */
    fun gossipWarnings(onWarnings: (List<uniffi.umbra_ffi.GossipWarningInfo>) -> Unit) = call { client ->
        val warnings = client.gossipWarnings()
        main.post { onWarnings(warnings) }
    }

    /** The FCM token of this device goes to the core (Part 8 §8.2.7). */
    fun setFcmToken(token: String) = call { it.setFcmToken(token) }

    /** The key-change notice that waits in a conversation (Part 4 §4.5.1). */
    fun keyChange(conversation: Conversation, onLoaded: (FfiKeyChange?) -> Unit) = call { client ->
        val pending = client.keyChange(conversation.id)
        main.post { onLoaded(pending) }
    }

    /** Accepts the new key of one contact (`IDN-062`). */
    fun acceptKeyChange(conversation: Conversation) = call { client ->
        client.acceptKeyChange(conversation.id)
        main.post { revision++ }
        refreshChats()
    }

    /** Whether a request of the contact for a new connection waits (Part 3 `NET-355`). */
    fun renewalAsk(conversation: Conversation, onLoaded: (Boolean) -> Unit) = call { client ->
        val waits = client.renewalAsk(conversation.id) != null
        main.post { onLoaded(waits) }
    }

    /** Answers the request of one contact for a new connection (`NET-355`). */
    fun answerRenewal(conversation: Conversation, accept: Boolean) = call { client ->
        client.answerRenewal(conversation.id, accept)
        main.post { revision++ }
    }

    /** Sends a failed message again (`IMP-075`). */
    fun sendAgain(message: MsgHandle) = call { client ->
        client.sendAgain(message)
        main.post { revision++ }
    }

    /** Whether this device sends and shows typing indicators (Part 6 `WIR-077`). */
    var typingEnabled by mutableStateOf(false)
        private set

    /** Each conversation whose contact types, until `TYPING_TTL` (`WIR-286`). */
    val typingNow = mutableStateMapOf<List<Byte>, Long>()

    /** The privacy mode of a conversation: 0 Fast, 1 Balanced, 2 Private (Part 3 §3.9). */
    fun privacyMode(conversation: Conversation, onMode: (Int) -> Unit) = call { client ->
        val mode = client.privacyMode(conversation.id).toInt()
        main.post { onMode(mode) }
    }

    fun keepPrivacyMode(conversation: Conversation, mode: Int) = call { client ->
        client.setPrivacyMode(conversation.id, mode.toUByte())
    }

    /** The period of the history on this device, in seconds (Part 7 §7.5.2). */
    var historyAge by mutableStateOf(365L * 86_400)
        private set

    fun readHistoryAge() = call { client ->
        val seconds = client.historyAge().toLong()
        main.post { historyAge = seconds }
    }

    fun keepHistoryFor(seconds: Long) = call { client ->
        client.setHistoryAge(seconds.toULong())
        main.post { historyAge = seconds }
    }

    /** Whether the drafts go to the other devices of the set (Part 7 §7.5.3). */
    var draftSync by mutableStateOf(true)
        private set

    fun readDraftSync() = call { client ->
        val isOn = client.draftSync()
        main.post { draftSync = isOn }
    }

    fun turnDraftSync(isOn: Boolean) = call { client ->
        client.setDraftSync(isOn)
        main.post { draftSync = isOn }
    }

    /** The draft of a conversation, as characters that `onDraft` overwrites. */
    fun readDraft(conversation: Conversation, onDraft: (CharArray) -> Unit) = call { client ->
        val units = client.draft(conversation.id)
        if (units.isEmpty()) return@call
        val chars = CharArray(units.size) { units[it].toInt().toChar() }
        main.post { onDraft(chars) }
    }

    /** Keeps the draft of a conversation; the characters are overwritten. */
    fun keepDraft(conversation: Conversation, text: CharArray) {
        val units = text.map { it.code.toUShort() }
        text.fill('\u0000')
        call { client -> client.setDraft(conversation.id, units) }
    }

    fun readTyping() = call { client ->
        val isOn = client.typingEnabled()
        main.post { typingEnabled = isOn }
    }

    fun turnTyping(isOn: Boolean) = call { client ->
        client.setTypingEnabled(isOn)
        main.post {
            typingEnabled = isOn
            if (!isOn) typingNow.clear()
        }
    }

    /** The user typed in a conversation, or emptied the field. */
    fun typing(conversation: Conversation, started: Boolean) {
        if (!typingEnabled) return
        call { it.typing(conversation.id, started) }
    }

    /** Private mode and Off hold no token, thus the NDR holds no handle. */
    fun clearPushToken() = call { it.setFcmToken(null) }

    /** A push came: an open client with no run starts one and drains. */
    fun wake(context: Context) {
        val app = context.applicationContext
        main.post { if (isOpen() && !online) connect(app, isWake = !wantsNetwork()) }
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
        val client = handle ?: return onResult(UiText.get(R.string.core_locked))
        worker.execute {
            val currentUnits = current.map { it.code.toUShort() }
            val newUnits = new.map { it.code.toUShort() }
            current.fill('\u0000')
            new.fill('\u0000')
            val failure = try {
                client.changePassphrase(currentUnits, newUnits)
                null
            } catch (wrong: FfiException.WrongPassphrase) {
                UiText.get(R.string.core_current_passphrase_wrong)
            } catch (other: FfiException) {
                UiText.get(R.string.core_passphrase_not_changed, other.javaClass.simpleName)
            }
            main.post { onResult(failure) }
        }
    }

    /**
     * Resets the identity (Part 7 §7.7.1). The network runs again under the
     * new root, and the public links and the handle of the old root end.
     */
    fun resetIdentity(context: Context, onDone: (String?) -> Unit) {
        val app = context.applicationContext
        call { client ->
            val result = try {
                val counts = client.resetIdentity()
                val contacts = counts.contacts.toInt()
                val groups = counts.groups.toInt()
                UiText.plural(R.plurals.core_reset_contacts, contacts, contacts) + " " +
                    UiText.plural(R.plurals.core_reset_groups, groups, groups)
            } catch (busy: FfiException.Busy) {
                main.post { onDone(null) }
                return@call
            }
            client.disconnect()
            main.post {
                connect(app, force = true)
                for (link in publicLinks.toList()) retirePublicLink(link)
                releaseHandle()
                onDone(result)
            }
        }
    }

    /** Starts the network again after it ended. */
    fun connect(context: Context, force: Boolean = false, isWake: Boolean = false) {
        val app = context.applicationContext
        // The open, the carrier, and the screen each ask for a run in the
        // first second. A second run replaces the first, and the handshake
        // that the first one started ends with it.
        if (isStarting && !force) {
            // The start that waits serves this call too. A full run that
            // the app asks for again stays, and a wake waits for the end
            // of a start that the app dropped.
            if (isWake) wakeWaits = true else runDropped = false
            return
        }
        isStarting = true
        isWakeSession = isWake
        wakeWaits = false
        runDropped = false
        on(networkWorker) { client ->
            val network = BuildNetwork.network(app, client)
            if (network == null) {
                // No manifest verified, fresh or kept, thus no run starts
                // and no run ends to call for a retry. The backoff of a run
                // that ended tries again.
                main.post {
                    isStarting = false
                    isWakeSession = false
                    degraded = UiText.get(R.string.umbra_ui_imp_077_ingress)
                    retryLater(app)
                }
                return@on
            }
            // The fetch can wait 20 s for each carrier, and Private mode
            // and Off drop their run 30 s after the last view left.
            if (!isWake && runDropped) {
                startDropped(app)
                return@on
            }
            try {
                // NET-100: a push wake is a session of 6 s at most.
                if (isWake) client.connectWake(network) else client.connect(network)
            } catch (failure: FfiException) {
                // A run that did not start calls for a retry, as one that
                // ended does.
                main.post {
                    isStarting = false
                    isWakeSession = false
                    retryLater(app)
                }
                throw failure
            }
            // The drop came while the run started, and its disconnect ran
            // before the run stood. The run ends here.
            if (!isWake && runDropped) {
                client.disconnect()
                startDropped(app)
                return@on
            }
            // A run starts in the foreground tier, thus it takes the state
            // of this moment.
            client.setForeground(isVisible)
        }
    }

    /**
     * The network thread started no run, because the app dropped it. A view
     * that came back since gets its run, and a wake that waited gets its
     * session.
     */
    private fun startDropped(app: Context) = main.post {
        isStarting = false
        val waited = wakeWaits
        wakeWaits = false
        if (phase == Phase.Open && !online) {
            if (wantsNetwork()) connect(app) else if (waited) connect(app, isWake = true)
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

    /** The introductions that wait for the user (Part 6 §6.6.7). */
    val introductions = mutableStateListOf<uniffi.umbra_ffi.FfiIntroduction>()

    /** Asks `to` to be introduced to `about`, by the names of this user. */
    fun requestIntroduction(to: Chat, about: Chat, onDone: () -> Unit) = call { client ->
        client.requestIntroduction(to.conversation.id, about.conversation.id, about.title, to.title)
        main.post(onDone)
    }

    /** WIR-196: a fresh invitation goes to the introducer in the grant. */
    fun allowIntroduction(intro: uniffi.umbra_ffi.FfiIntroduction) = call { client ->
        client.allowIntroduction(intro.id)
        refreshJoinFlow()
    }

    /** WIR-358: the offer opens its invitation, and the name comes with it. */
    fun acceptIntroduction(intro: uniffi.umbra_ffi.FfiIntroduction) = call { client ->
        val name = client.acceptIntroduction(intro.id)
        suggestedName = name.ifBlank { null }
        refreshJoinFlow()
    }

    fun declineIntroduction(intro: uniffi.umbra_ffi.FfiIntroduction) = call { client ->
        client.declineIntroduction(intro.id)
        refreshJoinFlow()
    }

    /** The admissions whose roster did not verify (`GRP-328`). */
    val failedAdmissions = mutableStateListOf<FfiGroupOffer>()

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

    fun dismissFailedAdmission(offer: FfiGroupOffer) = call { client ->
        client.dismissFailedAdmission(offer.from, offer.groupId)
        refreshJoinFlow()
    }

    private fun refreshJoinFlow() = call { client ->
        val offers = client.groupOffers()
        val joiners = client.groupJoiners()
        val failed = client.failedAdmissions()
        val intros = client.introductions()
        main.post {
            introductions.clear()
            introductions.addAll(intros)
            groupOffers.clear()
            groupOffers.addAll(offers)
            failedAdmissions.clear()
            failedAdmissions.addAll(failed)
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

    /** The forward policy of a conversation (Part 7 §7.5.10). */
    fun forwardRules(conversation: Conversation, onLoaded: (ForwardRules) -> Unit) = call { client ->
        val rules = client.forwardRules(conversation.id)
        main.post { onLoaded(rules) }
    }

    /** Sets the forward policy of the user, and the change goes to each party. */
    fun setForwardProhibited(conversation: Conversation, isOn: Boolean) = call { client ->
        client.setForwardProhibited(conversation.id, isOn)
        main.post { revision++ }
        refreshChats()
    }

    /**
     * Encodes the square that the user cropped anew as the picture of a
     * contact (`DIS-195`). Null removes the picture. The bytes go from the
     * picker to the store, and the device holds no file of them (`DIS-196`).
     */
    fun setContactPicture(conversation: Conversation, square: android.graphics.Bitmap?) {
        call { client ->
            val picture = if (square == null) {
                ByteArray(0)
            } else {
                Photos.picture(square) ?: run {
                    main.post { fault = UiText.get(R.string.core_image_did_not_fit) }
                    return@call
                }
            }
            client.setContactPicture(conversation.id, picture)
            picture.fill(0)
            refreshChats()
        }
    }

    /** The timer of a conversation (Part 7 §7.5.8). */
    fun timer(conversation: Conversation, onLoaded: (ConversationTimer) -> Unit) = call { client ->
        val timer = client.conversationTimer(conversation.id)
        main.post { onLoaded(timer) }
    }

    /** Sets the timer of a conversation, and the change goes to each party. */
    fun setTimer(conversation: Conversation, seconds: UInt) = call { client ->
        client.setConversationTimer(conversation.id, seconds)
        main.post { revision++ }
        refreshChats()
    }

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
                main.post { verifyFault = conversation to UiText.get(R.string.core_short_code_needs_connection) }
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

    /** Pins or unpins a conversation on each device of the set (Part 7 `DEV-329`). */
    fun setPinned(conversation: Conversation, isPinned: Boolean) = call { client ->
        client.setPinned(conversation.id, isPinned)
        refreshChats()
    }

    /**
     * Mutes a conversation on each device of the set until `untilMs`, with
     * no end at [MUTE_FOREVER], or ends the mute at 0 (Part 7 `DEV-331`).
     */
    fun setMutedUntil(conversation: Conversation, untilMs: ULong) = call { client ->
        client.setMutedUntil(conversation.id, untilMs)
        refreshChats()
    }

    /** Deletes each message of a conversation on the devices of this user (Part 7 `DEV-333`). */
    fun deleteConversation(conversation: Conversation) = call { client ->
        client.deleteConversation(conversation.id)
        main.post { revision++ }
        refreshChats()
    }

    /** Part 7 `DEV-334`: the deletion of the own devices, and a request to the contact. */
    fun deleteConversationForEveryone(conversation: Conversation, onBusy: () -> Unit) {
        val client = handle ?: return
        worker.execute {
            try {
                client.deleteConversationForEveryone(conversation.id)
                main.post { revision++ }
                refreshChats()
            } catch (busy: FfiException.Busy) {
                main.post(onBusy)
            } catch (failure: FfiException) {
                main.post { fault = UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName) }
            }
        }
    }

    /**
     * Sends the text of a composer, as an answer to `replyTo` when the user
     * chose one. This call overwrites `text`.
     */
    fun send(conversation: Conversation, text: CharArray, replyTo: MsgHandle? = null) {
        // The names of the contacts, read on the main thread.
        val titles = chats.associate { it.conversation.id.toList() to it.title }
        call { client ->
            // GRP-334: an @name of a member of a group names that member.
            val mentions = try {
                if (client.isGroup(conversation.id)) {
                    client.groupMembers(conversation.id)
                        .filter { !it.isSelf }
                        .filter { member ->
                            val name = member.contact?.let { titles[it.toList()] } ?: UiText.get(R.string.common_member_number, member.index.toInt())
                            mentions(text, name)
                        }
                        .map { it.index }
                } else {
                    emptyList()
                }
            } catch (failure: FfiException) {
                // A lock that overtook the send leaves no text in the array.
                text.fill('\u0000')
                throw failure
            }
            val units = text.map { it.code.toUShort() }
            text.fill('\u0000')
            client.newDraft(conversation.id).use { draft ->
                draft.setText(units)
                draft.setReplyTo(replyTo)
                if (mentions.isNotEmpty()) draft.setMentions(mentions)
                client.sendDraft(draft).destroy()
            }
            main.post { revision++ }
            refreshChats()
        }
    }

    /** Whether `text` holds `@name` as a word. The text stays a `CharArray`. */
    private fun mentions(text: CharArray, name: String): Boolean {
        val needle = "@$name"
        var at = 0
        while (at + needle.length <= text.size) {
            val isMatch = needle.indices.all { text[at + it].equals(needle[it], ignoreCase = true) }
            val end = at + needle.length
            if (isMatch && (end == text.size || !text[end].isLetterOrDigit())) return true
            at++
        }
        return false
    }

    /** The notification setting of a conversation (Part 7 §7.5.9). */
    fun alertSetting(conversation: Conversation, onLoaded: (UByte) -> Unit) = call { client ->
        val value = client.alertSetting(conversation.id)
        main.post { onLoaded(value) }
    }

    fun setAlert(context: Context, conversation: Conversation, value: UByte) = call { client ->
        client.setAlertSetting(conversation.id, value)
        // The wake table names a conversation with its alerts off silent.
        refreshWake(context)
    }

    /** Hides, removes, or puts back a message of a group (Part 11 §11.9.6). */
    fun moderate(message: MsgHandle, action: UByte) = call { client ->
        client.moderate(message, action)
        main.post { revision++ }
    }

    /** The changes of the roster of a group that this device applied. */
    fun rosterNotes(conversation: Conversation, onLoaded: (List<FfiRosterNote>) -> Unit) = call { client ->
        val notes = client.rosterNotes(conversation.id)
        main.post { onLoaded(notes) }
    }

    /** The moderation epochs that this device applied in a conversation. */
    fun moderationNotes(conversation: Conversation, onLoaded: (List<FfiModNote>) -> Unit) = call { client ->
        val notes = client.moderationNotes(conversation.id)
        main.post { onLoaded(notes) }
    }

    /** Sends a poll to a conversation. */
    fun sendPoll(
        conversation: Conversation,
        question: String,
        options: List<String>,
        multiple: Boolean,
        hidden: Boolean,
        openSeconds: UInt,
    ) = call { client ->
        client.sendPoll(conversation.id, question, options, multiple, hidden, openSeconds).destroy()
        main.post { revision++ }
        refreshChats()
    }

    /** Votes on a poll, or changes the vote of the user. */
    fun vote(poll: MsgHandle, choices: List<UByte>) = call { client ->
        client.vote(poll, choices.map { it.toByte() }.toByteArray())
        main.post { revision++ }
    }

    /** Sends a picked image as a message of its own. */
    fun sendPhoto(context: Context, conversation: Conversation, source: android.net.Uri, caption: CharArray? = null) {
        val app = context.applicationContext
        call { client ->
            client.newDraft(conversation.id).use { draft ->
                if (!Photos.attach(app, source, draft)) {
                    caption?.fill('\u0000')
                    main.post { fault = UiText.get(R.string.core_image_not_open) }
                    return@call
                }
                putCaption(draft, caption)
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
    fun sendVideo(context: Context, conversation: Conversation, source: android.net.Uri, caption: CharArray? = null) {
        val app = context.applicationContext
        on(mediaWorker) { client ->
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return@on
            // ATT `MAX_FILE_SIZE`: the size that the provider names refuses
            // a video before the remux copies one sample.
            val named = runCatching { Files.describe(app, source).size }.getOrDefault(-1L)
            if (named > MAX_FILE_SIZE) {
                caption?.fill('\u0000')
                main.post { fault = UiText.get(R.string.core_video_not_open) }
                return@on
            }
            val draft = client.newDraft(conversation.id)
            val bytes = Files.attachVideo(app, source, draft)
            if (bytes < 0) {
                draft.destroy()
                caption?.fill('\u0000')
                main.post { fault = UiText.get(R.string.core_video_not_open) }
                return@on
            }
            putCaption(draft, caption)
            offer(client, PendingSend(conversation, draft, bytes, isOriginal = false))
        }
    }

    /** Sends a picked audio file, encoded again with no field of the original. */
    fun sendAudio(context: Context, conversation: Conversation, source: android.net.Uri, caption: CharArray? = null) {
        val app = context.applicationContext
        on(mediaWorker) { client ->
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return@on
            val picked = Files.describe(app, source)
            val draft = client.newDraft(conversation.id)
            val bytes = Files.attachAudio(app, source, picked, draft)
            if (bytes < 0) {
                draft.destroy()
                caption?.fill('\u0000')
                main.post { fault = UiText.get(R.string.core_audio_not_open) }
                return@on
            }
            putCaption(draft, caption)
            offer(client, PendingSend(conversation, draft, bytes, isOriginal = false))
        }
    }

    /**
     * Gives the text of the composer to a draft with a file, as its caption
     * (Part 6 rule `WIR-535`). The array is zeros after the call.
     */
    private fun putCaption(draft: uniffi.umbra_ffi.DraftHandle, caption: CharArray?) {
        caption ?: return
        if (caption.isNotEmpty()) draft.setText(caption.map { it.code.toUShort() })
        caption.fill('\u0000')
    }

    /** Sends a voice message that the composer recorded. */
    @RequiresApi(Build.VERSION_CODES.R)
    fun sendVoice(conversation: Conversation, recording: VoiceRecording) {
        val seconds = recording.finish()
        if (seconds < 0) {
            fault = UiText.get(R.string.core_recording_short)
            return
        }
        // IMP-172: a lock that overtakes the send leaves no recording in
        // the memory. `attachVoice` closes the file of a draft that exists.
        val client = handle ?: return recording.discard()
        worker.execute {
            val draft = try {
                client.newDraft(conversation.id)
            } catch (failure: FfiException) {
                recording.discard()
                return@execute
            }
            try {
                val bytes = Files.attachVoice(recording, seconds, draft)
                if (bytes < 0) {
                    draft.destroy()
                    main.post { fault = UiText.get(R.string.core_recording_not_open) }
                    return@execute
                }
                offer(client, PendingSend(conversation, draft, bytes, isOriginal = false))
            } catch (locked: FfiException.Locked) {
                // A send that the lock overtook is no fault of the user.
            } catch (failure: FfiException) {
                main.post { fault = UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName) }
            }
        }
    }

    /** Sends a picked file as it is, with its name. */
    fun sendDocument(context: Context, conversation: Conversation, source: android.net.Uri, caption: CharArray? = null) {
        val app = context.applicationContext
        on(mediaWorker) { client ->
            val picked = Files.describe(app, source)
            if (picked.size > MAX_FILE_SIZE) {
                caption?.fill('\u0000')
                main.post { fault = UiText.get(R.string.core_file_too_big) }
                return@on
            }
            val draft = client.newDraft(conversation.id)
            if (!Files.attachDocument(app, source, picked, draft)) {
                draft.destroy()
                caption?.fill('\u0000')
                main.post { fault = UiText.get(R.string.core_file_not_open) }
                return@on
            }
            putCaption(draft, caption)
            offer(client, PendingSend(conversation, draft, picked.size, Files.isMediaOriginal(picked.mime)))
        }
    }

    /** Sends a draft at once, or holds it for the view to ask. */
    private fun offer(client: uniffi.umbra_ffi.Handle, pending: PendingSend) {
        // ATT-083: a provider that names no size may hand a large file.
        if (pending.bytes < 0 || pending.bytes > LARGE_FILE_WARN || pending.isOriginal) {
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
        on(mediaWorker) { client ->
            val output = try {
                app.contentResolver.openOutputStream(target, "wt")
            } catch (unwritable: Exception) {
                null
            }
            if (output == null) {
                main.post { fault = UiText.get(R.string.core_place_no_file) }
                return@on
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
            var written = false
            try {
                client.saveFile(line.handle, "/proc/self/fd/${write.fd}")
                written = true
            } finally {
                write.close()
                copier.join()
                // IMP-045: a save that failed leaves no part of the file at
                // the place that the user chose.
                if (!written || !copied) {
                    runCatching { android.provider.DocumentsContract.deleteDocument(app.contentResolver, target) }
                }
            }
            main.post { if (copied) onSaved() else fault = UiText.get(R.string.core_file_not_saved) }
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
    /** Whether a relay named the queue of the contact full (Part 14 §14.9.2). */
    fun queueFull(conversation: Conversation, onLoaded: (Boolean) -> Unit) = call { client ->
        val isFull = client.queueFull(conversation.id)
        main.post { onLoaded(isFull) }
    }

    /** Forwards a text to a conversation (`WIR-177`). */
    fun forward(message: MsgHandle, to: Conversation, onDone: () -> Unit) = call { client ->
        client.forward(message, to.id)
        refreshChats()
        main.post { revision++; onDone() }
    }

    fun resendFile(message: MsgHandle) = call { client ->
        client.resendFile(message)
        main.post { revision++ }
    }

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
                main.post { fault = UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName) }
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
            // A placeholder of a deleted message has no text, and a record
            // of a peer that gives no text shows none: one such record
            // leaves each other line of the conversation in place.
            if (!info.deleted) {
                try {
                    client.msgRender(message, sink)
                } catch (noText: FfiException) {
                    sink.chars = CharArray(0)
                }
            }
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
                if (quotedFile != null && !of.deleted) quoted.chars = fileWord(quotedFile).toCharArray()
                Quoted(target.key().toList(), of.outgoing, quoted.chars, of.sender)
            }
            val poll = if (info.poll && !info.deleted) client.pollView(message) else null
            Line(message, sink.chars, info, quote, client.reactions(message), poll)
        }
        main.post { onLoaded(lines) }
    }

    /** One result of a search: the message, its text, and the match in it. */
    class Found(
        val conversation: Conversation,
        val key: List<Byte>,
        val text: CharArray,
        val atMs: Long,
        val isOutgoing: Boolean,
        /** The member index of the sender of a group message. */
        val sender: UShort?,
        /** The match, as a range of [text]. An empty range marks nothing. */
        val start: Int,
        val end: Int,
    )

    /**
     * The query of the open search view. A view that the user leaves for a
     * result and comes back to shows it again. It sits in memory alone, and
     * it is zeros after the view closes and after a lock (`IMP-180`).
     */
    private var searchQuery: CharArray? = null

    /** The scope of [searchQuery]: a query of one view shows in no other one. */
    private var searchScope: Conversation? = null

    /** The query that the search view of `scope` held, or null. */
    fun searchQueryOf(scope: Conversation?): CharArray? = searchQuery.takeIf { searchScope == scope }

    /** The newest build and the newest query: an older one gives no result. */
    @Volatile
    private var searchBuilds = 0

    @Volatile
    private var searchTurns = 0

    /**
     * Builds the search index in the memory of the core (`IMP-176`), one
     * conversation in each turn of the worker. Thus each other call runs
     * between two steps.
     */
    fun searchBuild(onReady: () -> Unit) {
        val build = ++searchBuilds
        call { it.searchBegin() }
        searchStep(build, onReady)
    }

    private fun searchStep(build: Int, onReady: () -> Unit) {
        call { client ->
            if (build != searchBuilds) return@call
            if (client.searchStep()) main.post(onReady) else searchStep(build, onReady)
        }
    }

    /**
     * The limits of a search. The order is 0 for the best match first, 1 for
     * the newest first, and 2 for the oldest first. The side is 0 for each
     * sender, 1 for this user, and 2 for the other senders.
     */
    class SearchLimits(val order: Int, val from: Int, val isFilesOnly: Boolean, val sinceMs: Long)

    /** Searches the messages of one conversation, or of each one. */
    fun search(query: CharArray, scope: Conversation?, limits: SearchLimits, onFound: (List<Found>) -> Unit) {
        searchQuery?.fill('\u0000')
        searchQuery = query.copyOf()
        searchScope = scope
        val units = query.map { it.code.toUShort() }
        val turn = ++searchTurns
        call { client ->
            if (turn != searchTurns) return@call
            val options = uniffi.umbra_ffi.FfiSearchOptions(
                scope?.id,
                limits.order.toUByte(),
                limits.from.toUByte(),
                limits.isFilesOnly,
                limits.sinceMs.coerceAtLeast(0L).toULong(),
            )
            val found = client.search(units, options).map { hit ->
                hit.message.use { message ->
                    val sink = CharSink()
                    try {
                        client.msgRender(message, sink)
                    } catch (noText: FfiException) {
                        sink.chars = CharArray(0)
                    }
                    val info = client.msgInfo(message)
                    // A match in the name of a file marks nothing, and a
                    // file with no caption shows as its kind.
                    val file = info.file
                    val text = if (sink.chars.isEmpty() && file != null) fileWord(file).toCharArray() else sink.chars
                    val end = hit.end.toInt().coerceAtMost(sink.chars.size)
                    Found(
                        Conversation(hit.conversation),
                        message.key().toList(),
                        text,
                        info.storedAtMs.toLong(),
                        info.outgoing,
                        info.sender,
                        hit.start.toInt().coerceAtMost(end),
                        end,
                    )
                }
            }
            main.post { if (turn == searchTurns) onFound(found) }
        }
    }

    /** Ends the search: the index and the query leave the memory. */
    fun searchClose() {
        searchBuilds++
        searchTurns++
        searchQuery?.fill('\u0000')
        searchQuery = null
        call { it.searchClose() }
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
        var isReply = false
        last?.use {
            // A record of a kind with no text gives no preview.
            try {
                val info = client.msgInfo(it)
                isOutgoing = info.outgoing
                // A placeholder and a hidden message show no property of
                // the record.
                isReply = info.isReply && !info.deleted && info.moderation != MOD_HIDE
                // The words of a placeholder are words of the interface.
                when {
                    info.deleted -> sink.chars = UiText.get(R.string.core_message_deleted).toCharArray()
                    // GRP-085: a message that a moderator hid shows no text
                    // outside its conversation.
                    info.moderation == MOD_HIDE -> sink.chars = UiText.get(R.string.core_hidden_message).toCharArray()
                    info.timer != null -> sink.chars = timerPreview(info.timer!!).toCharArray()
                    info.forwardPolicy != null -> sink.chars = forwardPreview(info.forwardPolicy!!).toCharArray()
                    info.cleared -> sink.chars = UiText.get(R.string.core_chat_deleted).toCharArray()
                    info.file != null -> sink.chars = fileWord(info.file!!).toCharArray()
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
            isPreviewReply = isReply,
            picture = if (group == null) pictureOf(client, summary.conversation) else null,
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
            isUnreachable = group?.isUnreachable ?: false,
            isClockSuspect = group?.isClockSuspect ?: false,
            isPinned = summary.pinned,
            mutedUntilMs = summary.mutedUntilMs,
        )
    }

    /**
     * The decoded picture of each contact, under its conversation, with the
     * hash of its bytes. The worker thread alone reads and writes it, and a
     * lock clears it.
     */
    private val pictures = HashMap<List<Byte>, Pair<Int, androidx.compose.ui.graphics.ImageBitmap>>()

    /** The picture of a contact, decoded one time for each value. */
    private fun pictureOf(client: Handle, conversation: ByteArray): androidx.compose.ui.graphics.ImageBitmap? {
        val key = conversation.toList()
        val bytes = client.contactPicture(conversation)
        if (bytes.isEmpty()) {
            pictures.remove(key)
            return null
        }
        val hash = bytes.contentHashCode()
        pictures[key]?.let { (held, image) -> if (held == hash) return image }
        val image = Photos.profileImage(bytes) ?: return null
        pictures[key] = hash to image
        return image
    }

    private fun call(action: (Handle) -> Unit) = on(worker, action)

    /** Runs a call of the client on one thread of the core, and shows its fault. */
    private fun on(thread: java.util.concurrent.Executor, action: (Handle) -> Unit) {
        val client = handle ?: return
        thread.execute {
            try {
                action(client)
            } catch (locked: FfiException.Locked) {
                // A read that the lock overtook is no fault of the user.
            } catch (failure: FfiException) {
                // A debug build names the call that failed.
                if (BuildConfig.DEBUG) android.util.Log.w("umbra-core", "a call failed", failure)
                main.post { fault = UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName) }
            } catch (failure: Exception) {
                // A fault of the platform, as a content provider that
                // refuses a file, ends the call and not the app.
                if (BuildConfig.DEBUG) android.util.Log.w("umbra-core", "a call failed", failure)
                main.post { fault = UiText.get(R.string.core_did_not_work, failure.javaClass.simpleName) }
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
