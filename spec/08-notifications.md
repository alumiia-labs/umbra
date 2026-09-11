# UMBRA Protocol Specification — Part 8: Notifications and Mobile Delivery

**Status:** Draft
**Version:** 0.1.0-draft

---

## 8.1 The honest framing

On iOS there is **no lawful alternative to APNs**. The Legal Process Guidelines
of Apple (October 2025) confirm that "the Apple ID associated with a registered
APNs token and associated records may be obtained with an order under 18 U.S.C.
§2703(d) or a search warrant". Before the disclosure of Senator Wyden on 6
December 2023, a subpoena alone was sufficient. The push-token transparency
numbers of Apple increase monotonically. In 2022 H2 there were 70 requests for
794 tokens. In 2025 H1 there were 393 requests for 966 tokens, and Apple gave
278.

Thus the design goal of UMBRA is **not** to hide from APNs, which is impossible.
The goal is this:

> **[NTF-001]** **One infrastructure party MUST NOT hold a passive database of push-token
> bindings.** That prohibition covers a binding to a queue, to a contact, and to
> a messaging identity.

That wording is deliberate. Instant notification delivery makes a live
correlation point. The queue relay knows `(handle_i, k_tok_i)` for a queue. The
NDR decrypts the platform push token transiently at the dispatch. A live
wiretap, a prospective logging order against the NDR, or collusion between the
NDR and the queue relay can recover the token-to-queue mapping. Private
notification mode exists because the instant path cannot meet the stronger
claim.

The empirical baseline for the field is poor. A PETS 2024 study of 21 secure
messengers (Samarin and others, arXiv:2407.10589) found that 20 of the 21 used
FCM. The study found that **11 leaked metadata**, which was 10 user IDs, 7
names, and 2 phone numbers. The study also found that **4 leaked plaintext
message content**. The total install count was 15.03 billion or more. Only the
push-to-sync designs leaked nothing.

## 8.2 The Notification Delivery Relay

The NDR is a **protocol entity that differs from a queue relay**. It has its own
threat model and its own trust boundary.

```
  Queue Relay R                NDR                     APNs/FCM        Device
       │                        │                          │              │
       │  (handle_i, k_tok_i,   │                          │              │
       │   69-byte blob)        │                          │              │
       │  over OHTTP  ─────────▶│                          │              │
       │                        │ decrypt ct_token         │              │
       │                        │ with k_tok_i,            │              │
       │                        │ zeroize immediately      │              │
       │                        │ ────────────────────────▶│─────────────▶│
```

- The NDR holds the APNs JWT signing key and the FCM service account. **A queue
  relay does not touch a provider credential.**
- The NDR stores `(handle, ct_token)` pairs only. It does not hold `k_tok`.
- **[NTF-002]** The hop from the queue relay to the NDR MUST use Oblivious HTTP (RFC 9458) or
  a second mix hop. Thus the NDR cannot learn which relay holds a given handle.
  Without this hop, the NDR learns that the relays R1 and R2 serve the token T,
  which shows the relay set of the user.

### 8.2.1 Token blinding

The device makes a fresh 32-byte `k_tok` **for each group of at most
`MAX_QUEUES_PER_HANDLE` queues that it subscribes from on one relay**:

```
ct_token_i = XChaCha20-Poly1305(k_tok_i, nonce, apns_or_fcm_token)
handle_i   = 16 random bytes
```

**[NTF-031]** A device MUST make one `k_tok` and one `handle` for each group of
at most `MAX_QUEUES_PER_HANDLE` queues. **[NTF-032]** A device MUST NOT put more
than `MAX_QUEUES_PER_HANDLE` queues under one handle. **[NTF-033]** A device
MUST set `MAX_QUEUES_PER_HANDLE` equal to the `MAX_QUEUES_PER_SESSION` of Part 3
§3.2.5, which is 8. **[NTF-034]** A device MUST divide its queues across handles
again at each rotation of NTF-007.

> *Cause.* An earlier draft made one `k_tok` and one `handle` for each **relay**.
> §8.2.4 gives each queue its own `notifier_id`, thus a queue relay held a map
> from each `notifier_id` to that one handle. That map grouped **each** notifiable
> queue of one device on that relay, and NTF-007 held it for 7 days. Part 2 §2.7,
> Part 3 §3.11, and Part 16 §16.3 each bound the queue linkage of a queue relay
> at 8 queues in one transport session. Goal G7 of Part 2 §2.3 says that no relay
> can link two queues to one person, thus the wider group was a leak that no
> table recorded. The rule above makes the notification linkage equal to the
> transport linkage that those three tables already state.
>
> The cost is one registration for each group of 8 queues, in place of one for
> each relay. A user with 300 queues holds 38 registrations, and NTF-007 rotates
> them each 7 days.

The device then registers `(handle_i, ct_token_i)` with the NDR. The queue relay
*R* gets a notifiable message. That relay then POSTs `(handle_i, k_tok_i,
blob)`. The NDR decrypts the token, dispatches the notification, and **zeroizes
`k_tok_i` immediately**. The value stays in memory only. The NDR does not log it
and does not write it to disk.

The result is that **the seizure of the NDR, or a subpoena for the stored push
registrations, gives ciphertext.** A prospective order is a different adversary.
Such an order forces the NDR to log the `k_tok_i` values at the dispatch. That
order recovers the token-to-handle mapping at the NDR. With the records of the
queue relay, it recovers the token-to-queue mapping. The device registers an
independent handle for each group of at most `MAX_QUEUES_PER_HANDLE` queues,
thus ordinary relays cannot correlate with each other and one relay cannot group
more than that count.

### 8.2.2 Fixed-size notification blob

The blob is **69 bytes**, always, for each push:

```
ver          1 B
epoch        4 B    big-endian u32
nonce       24 B
ciphertext  24 B    XChaCha20-Poly1305
tag         16 B
────────────────
            69 B      → base64url = 92 chars; APNs JSON < 400 B of a 4096 B ceiling

plaintext (24 B):
    relay_idx      2 B
    queue_alias   16 B    device-local random alias, meaningless to every server
    waiting_count  1 B
    relay_ts       4 B
    flags          1 B    bit 0 urgent, bit 1 digest, bits 2-7 reserved
```

**[NTF-003]** Implementations MUST NOT emit a variable-length payload. **[NTF-004]** Implementations MUST
NOT put a field that carries content outside the AEAD envelope. Four of the
eight "end-to-end encrypted" applications in the PETS 2024 study made that
error.

The fields `ver` and `epoch` are outside the ciphertext, because a receiver
needs `epoch` to select the key of §8.2.3. **[NTF-035]** An implementation MUST
bind `ver || epoch` as the associated data of the AEAD. **[NTF-036]** An
implementation MUST set each reserved bit of `flags` to zero. **[NTF-037]** A
receiver MUST reject a blob whose reserved bits are not zero.

> *Cause.* An earlier draft forbade **each** field outside the AEAD envelope,
> and the structure above carries two. The associated data closes that gap: the
> two cleartext fields are authenticated, and no field that carries content sits
> outside the envelope.

> **Deviation note.** An earlier draft gave `flags` a decoy bit and said that the
> blob is 69 bytes "also for a decoy". No section named the party that makes a
> decoy, the rate of a decoy, or the mode that uses one. §8.3 gives Instant mode
> one push for each event, and a decoy in that mode costs a radio promotion and
> a share of the Apple ceiling of 2 to 3 silent pushes in one hour. This
> document withdraws the decoy. Private mode gives the same property with a
> fixed clock and no extra push, and §8.3 states it. The bit is now reserved.

### 8.2.3 Notification key schedule

The **calendar epoch** gives the key schedule, and the ratchet does not. Thus an
unstable network cannot desynchronize the schedule:

```
k_epoch = HKDF-SHA3-256(k_ntf_root, salt = epoch_be32, info = "umbra/v1/ntf")
   where epoch = floor(unix_time / 86400)
```

The device keeps the current epoch key and the two epoch keys before it, and
deletes the older keys. This method gives coarse forward secrecy, and it needs
no state negotiation.

**The acceptance window.** The relay and the device hold two clocks, and Part
1 §1.9 lets them differ by `CLOCK_SKEW`. Thus a blob can name the epoch before
or after the one that the device computes.

- **[NTF-075]** A receiver MUST accept a blob whose `epoch` is inside the
  window. The window is the epoch of the clock of the receiver, the one before
  it, and the one after it. **[NTF-076]** A receiver MUST reject a blob outside
  that window without an AEAD open.
- **[NTF-077]** A receiver MUST count the consecutive failed opens of blobs
  inside the window. **[NTF-078]** At `NTF_FAIL_MAX` consecutive failures, the
  client MUST show the `clock` state of Part 15 §15.9.2. **[NTF-084]** The
  client MUST then establish `k_ntf_root` again at the next foreground session.
  **[NTF-079]** One open that succeeds MUST reset the count.

| Parameter | Value |
| --- | --- |
| `NTF_FAIL_MAX` | 3 consecutive failed opens, counted by the device from the last open that succeeded |

> *Cause.* An earlier draft gave the epoch key no acceptance window and no
> failure rule. A device whose clock ran a day behind opened no blob, showed
> "New message" at each wake, and no party learned why. Three failures inside
> the window point at a lost root or a moved clock, and a fresh root repairs
> both. Part 1 §1.9 gives the clock rules.

**[NTF-042]** An iOS client MUST give the notification extension the keys of
the current epoch and of the next epoch only. Part 15 §15.6.6
gives the Keychain class of that item. A wake under an older key shows the
"New message" fallback of §8.4.2.

> *Cause.* The extension reads the item on a locked device, thus the item sits
> at the after-first-unlock tier. One key bounds what that tier gives. The next
> key is there because the application does not run at midnight. Without it, a
> wake in a new epoch would show the "New message" fallback each morning.

The device establishes `k_ntf_root` one time at the subscription, with
`UMBRA-KEM` in HPKE. The KEM ciphertext of about 1.1 KB is a one-time cost. The
path for each notification stays symmetric only, and a symmetric path at 256-bit
keys is post-quantum safe. Thus the design meets the harvest-now-decrypt-later
requirement, and the push payload stays small.

### 8.2.4 Separate notifier credentials

A queue carries an independent notifier keypair (`NKEY`), which returns a
different `notifier_id`. Thus the NDR subscribes and receives arrival signals,
and the NDR **cannot read a message and cannot acknowledge a message**. **[NTF-005]** A party
MUST NOT be able to derive the notifier ID from the `RecipientId` of the queue.
**[NTF-006]** A party MUST NOT be able to derive the notifier ID from the `SenderId` of the
queue.

### 8.2.5 Rotation

**[NTF-007]** The triple `(handle, k_tok, notifier_id)` and `k_ntf_root` MUST
rotate each **7 days**. **[NTF-008]** The triple MUST also rotate at each
change of the contact set. The rotation costs one round trip for each relay,
and it can travel with a wake in periodic mode.

- **[NTF-080]** A device MUST rotate one handle group of §8.2.1 at a time.
  **[NTF-081]** A device MUST NOT rotate two handle groups inside one session.
  Thus one rotation shows a relay one group of at most 8 queues, and no session
  shows the full set.

> *Cause.* An earlier draft rotated the triple and left `k_ntf_root` in place.
> Each epoch key of §8.2.3 derives from that root, thus one seized root opened
> each past and future blob, and the 7-day rotation of the triple bounded
> nothing on the payload. The root now rotates with the triple. The earlier
> draft also rotated each group at one moment, and a relay that saw 38
> registrations arrive together read them as one device.

### 8.2.6 The rendezvous queue

A published handle of Part 9 §9.3 and a published address of Part 9 §9.3.3 each
name a rendezvous queue. That queue address is public, thus a crawl of the
directory holds it. Part 9 rule `DIS-014` polls that queue through a different
relay chain from the pairwise queues. The rules below give its wake.

- **[NTF-043]** In Instant mode, a client MUST register a rendezvous queue
  under a notification handle of its own.
  **[NTF-044]** A client MUST NOT put a rendezvous queue and a pairwise queue
  under one `(handle, k_tok)` of §8.2.1.
- **[NTF-045]** In Private mode, a client MUST NOT register a rendezvous queue
  with the Notification Delivery Relay. **[NTF-046]** In Private mode, a client
  MUST drain each rendezvous queue at least one time in each 24 h. The client
  measures that period from the previous drain of that queue, and it uses the
  schedule of Part 9 rule `DIS-015`.
- **[NTF-047]** In Off mode, a client MUST drain each rendezvous queue at each
  foreground session.

A drain costs one transport handshake of about 6 000 bytes, one circuit build
of 12 576 bytes, and two `B0` cells, which is 19 696 bytes. A daily drain is
about 0.59 MB each month. Part 3 §3.12 does not count it, because a published
handle is an opt-in surface, and the margin of that table covers it. A hello in
Instant mode is one push wake, and it is rare, thus that table adds no row for
it. Part 2 §2.4.2 goal S1 sets the
latency of each mode.

> *Cause.* Part 9 §9.6 defined the hello and no rule drained the queue that
> receives it. A contact request then waited for a foreground session. The
> queue relay of a rendezvous queue reads a public queue address, thus it knows
> that the queue belongs to a published handle. Under one shared `k_tok` that
> relay and the Notification Delivery Relay together link the push token to the
> pairwise queues of the same registration. `NTF-044` keeps that group apart.
> The residual that stays is the link between one push token and one published
> handle, and Part 16 §16.3 records it. Private mode registers nothing, thus
> that mode gives the residual to no party, and it pays a latency of up to 24 h.

## 8.3 The three modes

UMBRA ships the three modes. The user selects one for each profile.

| | **Instant** | **Private** | **Off** |
| --- | --- | --- | --- |
| Mechanism | One push for each event | Constant-rate wakes | Drain when the user opens the application |
| Cadence | On arrival | Fixed 20 or 30 min | — |
| Latency | ~1 s | up to the interval | until the user opens the application |
| Apple and Google learn | The wake time for each event | Nothing beyond a fixed clock | The application is installed |
| Default | The shipped default | The high-risk configuration | A build with no carrier |

**Private mode is the interesting mode.** §8.4.1 gives its Android carrier, and
NTF-039 keeps it off high-priority FCM. The wakes fire on a fixed schedule,
and the arrival of a message does not change that schedule. Thus the wake time
carries **no information** about a message arrival. The documented ceiling of
Apple for a silent push is 2–3 in one hour. Thus a constant cadence of 20
minutes stays in that ceiling.

**Private mode has its own U3 latency, and the cadence above gives it.** A
message stays invisible for a maximum of 20 min at the 20 min cadence. A message
stays invisible for a maximum of 30 min at the 30 min cadence. The 15 min
invariant of U3 does not hold in this mode, because the ceiling of Apple sets a
floor of 20 min under the cadence. Part 2 §2.4 scopes U3 to Instant
notifications and Balanced mode, and it states that trade.

**[NTF-052]** A client in Private mode MUST draw the phase of its fixed clock
from the CSPRNG at each network change. **[NTF-053]** The client MUST draw it
again at each change of its ingress relay pair. The phase is the offset of the
wake inside the interval. One phase across two networks links the two, and Part
16 §16.3 states that residual.

**[NTF-009]** The UI MUST show the trade in one honest line, and **[NTF-010]**
the UI MUST NOT hide Private mode. **[NTF-011]** Onboarding MUST NOT ask the
user to select a threat model. **[NTF-082]** The settings MUST offer the
high-risk configuration, which selects Private notifications and disables the
content preview. **[NTF-083]** A build MUST ship Instant mode with the content
preview off as the default of each Profile. That default applies to each build
that holds a carrier of §8.4.1.

> *Cause.* An earlier draft put a high-risk profile into onboarding. A user at
> the first launch cannot weigh a threat model, and U1 of Part 2 §2.4 permits
> no security decision before the inbox. The word "profile" also named the
> identity object of Part 4 §4.2.5, and Part 1 §1.6.1 now registers the
> configuration under its own name. The default is one value on each build,
> thus a tester and a user see the same behavior.

The high-risk configuration also explains the cost of Instant mode. Instant mode
gives a better latency. But Instant mode shows the wake time of each event to
Apple and Google. Instant mode also gives a live token-to-handle mapping to the
NDR.

## 8.4 Platform specifics

### 8.4.1 Android

**Default path: a bounded foreground service.** A high-priority FCM message
wakes a `specialUse` foreground service. That service drains the queues and then
stops. On a de-Googled build, UnifiedPush replaces FCM.

- Declare `specialUse`, and **do not declare `dataSync`**. Android 15 limits
  `dataSync` to 6 hours in 24 hours, and it then throws a
  `RemoteServiceException`.
- Implement `Service.onTimeout()` and call `stopSelf()`. **[NTF-012]** **A client MUST NOT
  hold the push-wake session longer than 6 s.** Part 3 §3.12 derives that
  bound from the U4 idle background budget. That bound is a ceiling, and Part 3
  §3.12 models a wake of 3 s.
- **[NTF-013]** **A client MUST NOT build a spare circuit in a push-wake session.** Part 3
  §3.12 gives the cause, which is the same U4 budget. A wake needs one circuit,
  because no interactive send waits on a rotation.
- Track the budget of 6 h in 24 h as a local counter with no telemetry. Thus the
  client can detect starvation.
- **[NTF-014]** A high-priority FCM message MUST always cause a notification that the user can
  see. If it does not, the 7-day behavioral heuristic of Google silently
  downgrades the application to normal priority and breaks the delivery in Doze.

**UnifiedPush** is a first-class alternative. It is the default on the F-Droid
builds and on the direct-download builds, and UMBRA includes its own
distributor.

A **persistent socket** is the third fallback, behind the same Rust trait.

**Private mode does not use FCM on Android.** §8.3 wakes the device on a fixed
clock of 20 or 30 minutes, and a message arrival does not change that clock.

- **[NTF-038]** A client MUST carry a Private-mode wake over UnifiedPush or over
  a persistent socket. **[NTF-039]** A client MUST NOT carry a fixed-cadence
  wake over a high-priority FCM message.
- **[NTF-040]** A client that holds neither carrier MUST show that Private mode
  is not available on that build. **[NTF-041]** That client MUST NOT show
  Private mode as active.

> *Cause.* NTF-014 makes each high-priority FCM message cause a notification
> that the user can see, because the 7-day heuristic of Google downgrades an
> application that does not. Private mode makes 48 to 72 wakes each day, and
> almost every one of those wakes carries no message. Thus a Private mode over
> high-priority FCM shows 48 to 72 notifications each day that name nothing.
>
> A normal-priority FCM message is the other option, and Doze defers it. The
> note below states that limit, and a deferred wake destroys the fixed cadence
> that gives Private mode its property. A carrier that UMBRA controls has
> neither problem, and §8.4.1 already ships two of them.

> Note: Doze ignores a partial wake lock and suspends the network access. Doze
> also limits `setExactAndAllowWhileIdle` to one call in 9 minutes. App Standby
> gives an idle application the network about one time each day. A cover-polling
> schedule shorter than 9 minutes needs a foreground service that the user can
> see, or it needs a platform push. No method removes this limit. A
> specification that says differently gives an application that does not deliver
> messages.

### 8.4.2 iOS

iOS gives an application two wake paths. An alert push starts the Notification
Service Extension, which renders the alert and holds no network stack. A
background push starts the application for about 30 seconds, and Apple defers
that push at its own discretion. UMBRA uses the two paths for two jobs.

**The extension renders and does nothing else.**

- **[NTF-015]** The Notification Service Extension MUST NOT link one of the four
  stacks below. The four are the onion stack of Part 3, the TLS stack of Part 15
  §15.2.8, SQLite, and the directory logic of Part 10. **[NTF-054]** The
  extension MUST NOT open a socket.
- **[NTF-016]** Implementations MUST NOT try to fetch and decrypt the message
  in the extension. SimpleX has spent more than two years on that problem, and
  it describes its iOS notification reliability as insufficient today.

Ship `umbra-nse` as a separate minimal Rust crate:

```
keychain read → one AEAD open of ≤ 128 B → look up queue_alias in a small
read-only alias map in the shared App Group → render
```

The target is less than 4 MB RSS and less than 20 ms, against the ceiling of
about 24 MB and 30 s. Part 15 §15.6.6 gives the protection class of the Keychain
item and of the App Group container. Rule `NTF-042` of §8.2.3 bounds the keys
in that item.

> *Cause of the narrowing.* An earlier draft forbade each network I/O in the
> extension. That rule was wider than its cause. The cause is that the onion
> stack, the TLS stack, the database, and the directory logic each carry state
> and code that the extension cannot hold inside 24 MB and 30 s. The four named
> prohibitions state that cause, and `NTF-054` keeps the socket out on the same
> ground.

**The application fetches on a background push.** The content preview is an
opt-in feature, and it is best-effort. When the user opts in, the queue relay
hands a background push beside the alert push, and the application makes one
fetch.

- **[NTF-055]** On a background push, an iOS client MUST resume the session of
  the pushed queue under Part 6 rule `WIR-361`. **[NTF-085]** The client MUST
  fetch that one queue in that wake. **[NTF-056]** The client MUST NOT open a
  session to another relay in that wake. **[NTF-057]** The fetch MUST take the
  fixed-count response of `NTF-017`.
- **[NTF-058]** If the fetch does not complete inside 10 seconds, the client
  MUST leave the "New message" alert in place. **[NTF-059]** The client MUST
  NOT show a partial content preview.

**Padding requirement.** **[NTF-017]** The response path for a message fetch
MUST carry padding to a constant number of fixed cells. This rule applies for
each state of the server. Trail of Bits found that the iOS `GET` of SimpleX
gives a different packet count when the relay holds a message. That behavior is
a message-existence oracle for a network observer. The finding got a low
rating, and SimpleX argued it away. UMBRA corrects it.

**Private mode on iOS.** A fixed cadence needs a carrier that UMBRA controls,
and iOS gives none in the background. UnifiedPush does not exist there, and the
platform ends a background socket.

- **[NTF-060]** An iOS client MUST show that Private mode has no background
  delivery on iOS. **[NTF-061]** An iOS client in Private mode MUST drain on the
  fixed clock of §8.3 in the foreground. **[NTF-062]** An iOS client in Private
  mode MUST NOT register a queue with the Notification Delivery Relay. Rule
  `NTF-040` gives the line that the client shows, and Part 16 §16.2.8 states the
  limit.

**Grouping and collapse.**

- **[NTF-063]** A queue relay MUST NOT set `apns-collapse-id` on a message
  push. **[NTF-064]** The extension MUST set `threadIdentifier` from the
  conversation of `queue_alias` after the AEAD open. Thus the tray groups the
  alerts of one conversation, and APNs sees one push kind.

> *Cause.* A collapse identifier for each push kind is a fingerprint that APNs
> can see, and a collapse identifier for each conversation is a conversation
> count that APNs can see. The thread identifier does the grouping on the
> device, after the open, thus APNs sees nothing.

### 8.4.3 Expiry, the re-push, and the peek

- **[NTF-065]** A queue relay MUST set the push expiry to `PUSH_TTL_MESSAGE` for
  a message push. **[NTF-086]** A queue relay MUST set it to `PUSH_TTL_DIGEST`
  for a digest push. The expiry is `apns-expiration` and the FCM TTL.
  **[NTF-066]** If no drain of a handle follows a message push inside
  `REPUSH_INTERVAL`, the queue relay MUST hand one more push. **[NTF-067]** A
  queue relay MUST NOT hand more than `REPUSH_MAX` re-pushes for one message.
- **[NTF-068]** At each session open and at each session resume, a client MUST
  run the peek of Part 3 §3.7 item 4 on each queue of that session. Thus a
  push that expired at the provider loses no message.

| Parameter | Value |
| --- | --- |
| `PUSH_TTL_MESSAGE` | 86 400 s. The provider measures it from the hand-off |
| `PUSH_TTL_DIGEST` | 3 600 s. The provider measures it from the hand-off |
| `REPUSH_INTERVAL` | 1 h. The queue relay measures it from the hand-off of the previous push for that handle |
| `REPUSH_MAX` | 3 re-pushes for one message |

> *Cause.* An earlier draft set one expiry of 3 600 seconds for each push, and
> it gave no rule for a device that was off for longer. A device that is off
> for lunch then lost its wake, and the message waited for the next foreground
> session. The blob of §8.2.2 holds no content, thus a longer expiry exposes
> 69 bytes under an epoch key and nothing more. The re-push bounds the wait at
> `REPUSH_INTERVAL` for a device that is reachable, and the peek covers a
> device that is not.

## 8.5 Coalescing, groups, and communities

FCM permits 5 000 messages in one hour to one device. The iOS silent push has a
limit near 3 in one hour. A conversation that makes one push for each record
uses that budget. A busy one breaks the notifications of each other conversation
on the device.

**The coalescing applies to each handle.** A queue relay sees queues and
handles, and it does not see the conversation class. Thus the window below
applies to a 1:1 conversation, to a group of each size, and to a community
digest alike.

| Parameter | Value |
| --- | --- |
| `WAKE_COALESCE_WINDOW` | 10 s. The queue relay measures it from the moment that it hands a push for a handle to the Notification Delivery Relay |

- **[NTF-048]** A queue relay MUST NOT hand a second push for one handle to the
  Notification Delivery Relay inside `WAKE_COALESCE_WINDOW`. **[NTF-049]** If
  an event arrives inside the window, the queue relay MUST hand one push at the
  end of the window. **[NTF-050]** A revision that changes
  `WAKE_COALESCE_WINDOW` MUST derive the U3 target and the idle table of Part 3
  §3.12 again.
- **[NTF-019]** A queue relay MUST apply the window to each handle, whatever
  the class of the conversation behind it. **[NTF-018]** A group above `T1_MAX`
  members MUST NOT make one alert for each record at the device. Part 7 rule
  `DEV-221` defaults such a group to `mentions`, and the setting acts after the
  drain.

> *Cause.* An earlier draft let a small group stay at one push for each
> message, and it keyed the digest threshold on 1000 community members. A relay
> cannot tell a group from a 1:1 conversation, thus the first rule bound
> nothing that the relay could apply. `T1_MAX` of Part 11 §11.10 is the bound
> at which a group leaves the pairwise fan-out, and the notification setting of
> Part 7 §7.5.9 already changes at that bound.

> *The derivation of the 10 s.* U3 of Part 2 §2.4 gives a p95 of 15 s, and §8.8
> gives the alert a p95 of about 4 s. Thus the window can hold a coalesced event
> for 11 s at most, and 10 s leaves 1 s. Part 3 §3.12 spreads the 184 background
> arrivals of its model day about 274 s apart. Thus about 4 % of them fall
> inside the window of the previous arrival. The window saves that share of the
> wakes, and Part 3 §3.12 takes no credit for it. **That share is unverified.**
> **[NTF-051]** An implementation MUST measure the coalesced share in a real
> deployment before a revision re-tunes the window.

### 8.5.1 The community digest queue

A community relay holds no subscriber list, and it holds no `k_tok`. Thus it
cannot push. A subscriber in Instant mode gives each community one queue of its
own at a queue relay. The community relay writes a digest into that queue. The
queue relay then pushes as for any queue. Part 12 §12.6 gives the registration
command and the digest record.

- **[NTF-069]** A client in Instant mode MUST register one notification queue
  for each community at `mentions` or `all`. Part 7 §7.5.9 gives the setting.
  **[NTF-070]** A client MUST put that queue under a notification handle of its
  own. That handle holds no pairwise queue and no rendezvous queue.
  **[NTF-071]** A client MUST rotate that queue with the triple of `NTF-007`,
  and it MUST register the new queue before it drops the old one.
- **[NTF-072]** A community relay MUST NOT write more than
  `COMMUNITY_DIGEST_BUDGET` digests into one queue in one day. **[NTF-073]** A
  community relay MUST NOT write a digest into a queue when no post arrived
  since the previous digest to that queue.
- **[NTF-074]** A client in Private mode or in Off mode MUST NOT register a
  community notification queue. Those modes find a post at the pull.

| Parameter | Value |
| --- | --- |
| `COMMUNITY_DIGEST_BUDGET` | 4 digests in one day for one queue. The community relay measures the day from its first digest to that queue |

**The cost.** A digest is one push wake, and Part 3 §3.12 prices a wake at about
19.7 KB with its drain. The model user of Part 3 §3.12 follows 2 communities at
the default setting. Thus the budget bounds the day at 8 wakes and about 158 KB,
which is about 4.7 MB each month. Part 3 §3.12 does not count that row, and the
margin of U4 covers it. A revision of that table adds the row.

**Which party learns what.** The community relay learns the count of the
registered queues, which is close to the count of the Instant-mode subscribers.
It also learns the queue relay of each one. It cannot link a queue to a
pseudonym or to a pull, because a registration carries neither. Part 16 §16.3
states that residual.

> *Cause.* An earlier draft said that the default is a digest on the server,
> and no section named the server, the carrier, or the queue. A community
> relay cannot push, and a queue relay holds no community. The queue above is
> the carrier. The budget keeps a busy community inside the U4 margin, and the
> `mentions` default of Part 7 rule `DEV-222` keeps the tray quiet after the
> wake. A digest names no post, thus a device that wakes on a digest pulls
> under Part 12 §12.3.3 and renders a mention only.

## 8.6 Web Push (PWA target only)

Part 15 §15.7 says today that a browser target does not ship. **[NTF-020]** If
such a target ships later, Web Push MUST obey the five rules below.
**[NTF-021]** Web Push MUST use a **fresh VAPID P-256 keypair for each
subscription**. **[NTF-022]** Web Push MUST set `sub` to one constant HTTPS URI
that identifies no party. **[NTF-023]** Web Push MUST set `exp` well below the
24-hour ceiling of RFC 8292. **[NTF-024]** Web Push MUST NOT send a `Topic`
header. **[NTF-025]** Web Push MUST pad the payloads to a constant length under
the RFC 8291 encryption. The content encoding is the `aes128gcm` of RFC 8188.

**[NTF-026]** The client MUST tell the user plainly that on iOS the endpoint resolves to
`web.push.apple.com`. Web Push removes the token from the servers of UMBRA, and
it does not remove Apple from the path.

## 8.7 Residual leak — normative statement

**[NTF-027]** This text is normative, and it MUST appear in the security documentation that
the user reads:

> Apple learns that a given Apple ID has UMBRA installed. On the Play build,
> Google learns that a given Google account has UMBRA installed. Apple and
> Google also learn the exact time and the count of each notification that they
> deliver to that account.
>
> In Instant mode, the Notification Delivery Relay of UMBRA learns the mapping
> token↔handle↔arrival time. It learns this mapping transiently and in memory
> only. A queue relay learns the handle, `k_tok`, the `notifier_id`, and the
> notification times for each queue. One handle covers at most
> `MAX_QUEUES_PER_HANDLE` queues, thus that relay groups at most 8 of your queues
> under one handle. Part 3 §3.2.5 gives a transport session the same bound.
> **No stored database at one party holds token↔queue.**
>
> Three events recover token↔queue, and thus Apple-ID↔queue. The events are a
> live wiretap on the NDR, a prospective logging order against the NDR, and
> collusion between the NDR and a queue relay.

**The policy requirements that follow:**

- **[NTF-028]** The NDR of the nonprofit and its core queue relays MUST be in different legal
  jurisdictions.
- **[NTF-029]** The client MUST let the user pin an NDR independently of the relays of that
  user.
- **[NTF-030]** The NDR MUST publish a no-logging policy, a warrant canary, and a transparency
  log of its software builds.

### 8.7.1 Self-hosting is partially untenable here — say so

A third party can operate an UMBRA queue relay. **A third party cannot operate
iOS notification delivery**, because the APNs certificates are not public. The
whitepaper of Threema states this limit directly. On iOS the NDR is necessarily
a chokepoint with one operator. That limit is the sharpest tension between the
infrastructure model of UMBRA and its "no single trusted party" goal.

This tension is the cause that the NDR is a separate trust role with its own
attestation track (Part 10 §10.10). UMBRA does not put the NDR into the general
relay reputation.

## 8.8 Estimated cost

| Metric | Instant mode | Private mode |
| --- | --- | --- |
| Median notification latency | 0.8–2.0 s | ≤ the interval |
| p95, the alert | ~4 s | ≤ the interval |
| p95, the message content, Android | ~7 s | ≤ the interval, and ~3 s more |
| p95, the message content, iOS | No figure. The content arrives at the background fetch of §8.4.2, and Apple defers a background push at its own discretion | No background delivery, §8.4.2 |
| Radio promotions each day | One for each background arrival, which is 184 on the model day | 48 at 30 min, 72 at 20 min |
| Battery with no arrival | 0 %/day | 2.8 %/day at 30 min, 4.3 %/day at 20 min |
| Battery for each arrival | 9.1 mWh, which is 10.9 %/day on the model day | 0 |

The three latency values of the Instant column meet the usability goal U3, which
is p50 ≤ 3 s and p95 ≤ 15 s. The values also leave a margin. Part 2 §2.4 scopes
U3 to Instant notifications and Balanced mode, thus U3 does not measure the
Private column. The U3 row states the latency of Private mode, and §8.3 gives
the cadence that sets it.

**The promotion row and the battery row.** Part 3 §3.12 derives the battery
cost, and these two rows repeat that derivation. Part 3 §3.6.2 gives about
9.1 mWh for each radio promotion, and U5 names a battery of 15.4 Wh. Instant
mode makes one wake for each background arrival, which is 9.1 mWh. The model
day of Part 3 §3.12 holds 184 arrivals, which is 1.67 Wh and 10.9 % of that
battery. With no arrival Instant mode makes no wake. Private mode makes one
wake for each interval of §8.3. At a 30 min interval that count is 48 wakes,
which is 0.44 Wh and 2.8 %. At a 20 min interval that count is 72 wakes, which
is 0.66 Wh and 4.3 %.

**The cheaper mode depends on the arrival count, and this table states that
plainly.** Private mode at 30 min costs less battery than Instant mode above 48
arrivals each day. Private mode at 20 min costs less above 72. An earlier draft
stated that Private mode costs more battery than Instant mode, and it asserted
30 Instant wakes each day. This document withdraws both statements. Part 2 §2.4
scopes U5 to Instant notifications, thus U5 measures the Instant column only. U5
has a fixed term and a term for each arrival, and the two battery rows above
give them.

> *The pacing term.* The push path itself is not paced. Part 3 §3.5.2 paces the
> session that carries the message body, at a `PACING_MEAN` of 1 s. That wait is
> exponential, and Part 3 §3.9 gives its 95th percentile as 3 s. Thus the
> content of a notification can reach the device about 3 s after the alert. The
> worst case is about 7 s, which stays inside the U3 p95 of 15 s. U3 does not
> change.
