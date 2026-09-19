package org.umbra.app

import android.content.Context
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
import uniffi.umbra_ffi.FfiEvent
import uniffi.umbra_ffi.FfiException
import uniffi.umbra_ffi.Handle
import uniffi.umbra_ffi.MsgInfo
import uniffi.umbra_ffi.TextSink
import uniffi.umbra_ffi.init
import uniffi.umbra_ffi.measureArgon2FloorMs

/** A conversation, by its surrogate identifier. */
class Conversation(val id: ByteArray) {
    override fun equals(other: Any?) = other is Conversation && id.contentEquals(other.id)
    override fun hashCode() = id.contentHashCode()

    /** A stable short name for a contact that the user did not name yet. */
    val label: String
        get() = id.take(4).joinToString("") { "%02x".format(it) }
}

/** One message of a conversation view. The text stays a `CharArray`. */
class Line(val text: CharArray, val info: MsgInfo)

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
) {
    /** What each list shows: the name of the user, or a stable short label. */
    val title: String
        get() = name.ifEmpty { "Contact ${conversation.label}" }
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
    var invitation by mutableStateOf<String?>(null)
    val chats = mutableStateListOf<Chat>()

    /** A contact that is new in this run and has no name yet. */
    var toName by mutableStateOf<Conversation?>(null)

    /** Grows at each change of a message, thus a view loads its lines again. */
    var revision by mutableIntStateOf(0)
        private set

    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "umbra-core") }
    private var handle: Handle? = null
    private var draining = false

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
                handle = opened
                // The store holds each contact, thus the list needs no network.
                val stored = summaries(opened)
                BuildNetwork.network(app)?.let(opened::connect)
                drain(opened, app)
                main.post {
                    chats.clear()
                    chats.addAll(stored)
                    phase = Phase.Open
                    // The user opened the client, thus a view is on the
                    // screen, and the platform permits the start.
                    DeliveryService.start(app)
                }
            } catch (wrong: FfiException.WrongPassphrase) {
                fail("That passphrase does not open this device.")
            } catch (other: FfiException) {
                fail("The store did not open: ${other.javaClass.simpleName}.")
            }
        }
    }

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
                online = true
                fault = null
                retryDelayMs = FIRST_RETRY_MS
            }
            is FfiEvent.Offline -> {
                online = false
                if (event.cause.toInt() != STOPPED) {
                    fault = "No connection: ${cause(event.cause)}. UMBRA tries again."
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
            is FfiEvent.Message -> {
                revision++
                refreshChats()
                if (!isVisible) Notifier.message(app, Conversation(event.conversation))
            }
            is FfiEvent.Delivery -> {
                revision++
                refreshChats()
            }
            is FfiEvent.Locked -> {
                online = false
                invitation = null
                toName = null
                chats.clear()
                phase = Phase.Locked
                // A locked client holds no key that reads a queue, thus the
                // carrier ends, and the user learns it.
                DeliveryService.stop(app)
                if (!isVisible) Notifier.locked(app)
            }
            is FfiEvent.IntegrityFault -> fault = "The local store does not verify."
        }
        // An event can hold a handle of a message, and this frees it.
        event.destroy()
    }

    private fun cause(code: UByte): String = when (code.toInt()) {
        1 -> "the first relay did not answer"
        2 -> "the link to the first relay closed"
        3 -> "a relay ended the circuit"
        5 -> "the store took no batch"
        else -> "a fault in the client"
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
        if (nowVisible) Notifier.clear(context)
        if (nowVisible && !online && phase == Phase.Open) {
            retryDelayMs = FIRST_RETRY_MS
            connect(context)
        }
    }

    fun lock() = call { it.lock() }

    /** Starts the network again after it ended. */
    fun connect(context: Context) {
        val app = context.applicationContext
        call { client -> BuildNetwork.network(app)?.let(client::connect) }
    }

    fun invite() = call { it.invite() }

    /** Accepts the link of a contact. A link that does not parse is a fault. */
    fun accept(link: String) = call { it.accept(link) }

    /** Gives a contact a name that this device alone holds. */
    fun setName(conversation: Conversation, name: String) = call { client ->
        client.setContactName(conversation.id, name)
        refreshChats()
    }

    /** The user looks at the conversation, thus its messages are seen. */
    fun markRead(conversation: Conversation) = call { client ->
        client.markRead(conversation.id)
        refreshChats()
    }

    /** Sends the text of a composer. This call overwrites `text`. */
    fun send(conversation: Conversation, text: CharArray) = call { client ->
        val units = text.map { it.code.toUShort() }
        text.fill('\u0000')
        client.newDraft(conversation.id).use { draft ->
            draft.setText(units)
            client.sendDraft(draft).destroy()
        }
        main.post { revision++ }
        refreshChats()
    }

    /** Loads the lines of a conversation, and gives them on the main thread. */
    fun load(conversation: Conversation, onLoaded: (List<Line>) -> Unit) = call { client ->
        val lines = client.messages(conversation.id).map { message ->
            message.use {
                val sink = CharSink()
                client.msgRender(it, sink)
                Line(sink.chars, client.msgInfo(it))
            }
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
                client.msgRender(it, sink)
                isOutgoing = client.msgInfo(it).outgoing
            } catch (noText: FfiException) {
                sink.chars = CharArray(0)
            }
        }
        Chat(
            conversation = Conversation(summary.conversation),
            name = summary.name,
            preview = sink.chars.takeIf { last != null },
            isPreviewOutgoing = isOutgoing,
            lastAtMs = summary.lastAtMs.toLong(),
            unread = summary.unread.toInt(),
        )
    }

    private fun call(action: (Handle) -> Unit) {
        val client = handle ?: return
        worker.execute {
            try {
                action(client)
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
