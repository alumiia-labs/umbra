# UMBRA Protocol Specification — Part 8: Notifications and Mobile Delivery

**Status:** Draft
**Version:** 0.25.2
**Date:** 2026-10-13

---

## 8.1 The honest framing

Android is the v1 client platform (Part 1 §1.1). An Android client in Instant
mode receives a push through Firebase Cloud Messaging (FCM). It also holds a
persistent socket of its own and a periodic poll. §8.4.1 gives the
three carriers. FCM puts Google on the path of each push, and a legal process
against Google can obtain the account behind a registration token. A device
with no FCM takes its wakes from the socket and the poll, and no platform
party is on that path. UMBRA carries no UnifiedPush.

Thus the design goal of UMBRA is **not** to hide from the push provider that a
build carries. The goal is this:

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
  Queue Relay R                NDR                      FCM             Device
       │                        │                          │              │
       │  (handle_i, k_tok_i,   │                          │              │
       │   69-byte blob)        │                          │              │
       │  over OHTTP  ─────────▶│                          │              │
       │                        │ decrypt ct_token         │              │
       │                        │ with k_tok_i,            │              │
       │                        │ zeroize immediately      │              │
       │                        │ ────────────────────────▶│─────────────▶│
```

- The NDR holds the FCM service account, and it posts to FCM alone. **A queue
  relay does not touch a provider credential.**
- The NDR stores `(handle, ct_token)` pairs only. It does not hold `k_tok`.
- **[NTF-002]** The hop from the queue relay to the NDR MUST use Oblivious HTTP (RFC 9458) or
  a second mix hop. Thus the NDR cannot learn which relay holds a given handle.
  Without this hop, the NDR learns that the relays R1 and R2 serve the token T,
  which shows the relay set of the user. **[NTF-115]** The OHTTP of that hop
  MUST use the HPKE of AUX-6, and its key configuration and its request header
  MUST carry the suite identifiers of Part 5 §5.4 in place of the registry
  values of RFC 9180.
  **[NTF-126]** The inner message of that OHTTP MUST be one `NdrRequest` of
  §8.2.7 and its response one `NdrResponse`, with no Binary HTTP around
  them. The request label MUST be `"message/umbra-ndr request"` and the
  response label `"message/umbra-ndr response"` in place of the
  `message/bhttp` labels of RFC 9458 §4.3 and §4.4, as RFC 9458 §4.6 permits
  for another media type. The key configuration of the gateway MUST list one
  suite, the UMBRA suite.
  **[NTF-127]** A client build and the settings of a queue relay MUST pin
  the route to the NDR: the URL of the OHTTP relay, the key id, and the key
  configuration of the gateway. A party MUST NOT take that key from a fetch
  that no signature covers, because an OHTTP relay that handed its own key
  would read each request. A relay with the OHTTP relay role MUST forward
  each request to the gateway without a change, MUST keep no request and no
  response, and MUST write no log line that names a sender. The reference
  relay serves the role at `POST /ohttp` beside its WebSocket upgrade, and
  the reference NDR serves the gateway at `POST /gateway`.

### 8.2.1 Token blinding

The device makes a fresh 32-byte `k_tok` **for each group of at most
`MAX_QUEUES_PER_HANDLE` queues that it subscribes from on one relay**:

```
handle_i   = 16 random bytes
ct_token_i = XChaCha20-Poly1305(k_tok_i, nonce, push_token, ad = handle_i)
```

**[NTF-031]** A device MUST make one `k_tok` and one `handle` for each group of
at most `MAX_QUEUES_PER_HANDLE` queues. **[NTF-032]** A device MUST NOT put more
than `MAX_QUEUES_PER_HANDLE` queues under one handle. **[NTF-033]** A device
MUST set `MAX_QUEUES_PER_HANDLE` equal to the `MAX_QUEUES_PER_SESSION` of Part 3
§3.2.5, which is 8. **[NTF-034]** A device MUST divide its queues across handles
again at each rotation of NTF-007.

> *Cause.* One `k_tok` and one `handle` for each **relay** is the alternative.
> §8.2.4 gives each queue its own `notifier_id`, thus a queue relay would hold a
> map from each `notifier_id` to that one handle. That map groups **each**
> notifiable queue of one device on that relay, and NTF-007 holds it for 7 days.
> Part 2 §2.7, Part 3 §3.11, and Part 15 §15.3 each bound the queue linkage of a
> queue relay at 8 queues in one transport session. Goal G7 of Part 2 §2.3 says
> that no relay can link two queues to one person, thus the wider group is a
> leak that no table records. The rule above makes the notification linkage
> equal to the transport linkage that those three tables state.
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
            69 B      → base64url = 92 chars; the FCM data message < 400 B of the 4 096 B data limit

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

> *Cause.* The structure above carries two fields outside the AEAD envelope.
> The associated data authenticates the two cleartext fields, and no field that
> carries content sits outside the envelope.

> *Cause.* The blob carries no decoy bit, and no party makes a decoy push.
> §8.3 gives Instant mode one push for each event, and a decoy in that mode
> costs a radio promotion against the U5 term of Part 2 §2.4. Private mode
> gives the same property with a fixed clock and no extra push, and §8.3
> states it.

### 8.2.3 Notification key schedule

The **calendar epoch** gives the key schedule, and the ratchet does not. Thus an
unstable network cannot desynchronize the schedule:

```
k_epoch = HKDF-SHA3-256(k_ntf_root, salt = epoch_be32, info = "umbra/v1/ntf")
   where epoch = floor(unix_time / 86400)
```

The device holds `k_ntf_root` and derives the key of each epoch of the window
of `NTF-075` from it. That window is the epoch of its clock, the one before
it, and the one after it. The method needs no state negotiation. It gives no forward secrecy
inside the life of one root, because each epoch key derives from the root that
the device holds. The rotation of `NTF-007` bounds that life at 7 days. The
wake table of `NTF-135` holds each root in use outside `K_store`. Thus a party
that seizes an Android device in Instant mode opens each blob of those roots
that it recorded before.

**The acceptance window.** The relay and the device hold two clocks, and Part
1 §1.9 lets them differ by `CLOCK_SKEW`. Thus a blob can name the epoch before
or after the one that the device computes.

- **[NTF-075]** A receiver MUST accept a blob whose `epoch` is inside the
  window. The window is the epoch of the clock of the receiver, the one before
  it, and the one after it. **[NTF-076]** A receiver MUST reject a blob outside
  that window without an AEAD open.
- **[NTF-077]** A receiver MUST count the consecutive failed opens of blobs
  inside the window. **[NTF-078]** At `NTF_FAIL_MAX` consecutive failures, the
  client MUST show the `clock` state of Part 14 §14.9.2. **[NTF-084]** The
  client MUST then establish `k_ntf_root` again at the next foreground session.
  **[NTF-079]** One open that succeeds MUST reset the count.

| Parameter | Value |
| --- | --- |
| `NTF_FAIL_MAX` | 3 consecutive failed opens, counted by the device from the last open that succeeded |
| `NDR_REG_TTL` | 60 days after the `NREG` that made or last moved a registration (`NTF-138`) |

> *Cause.* Without an acceptance window and a failure rule, a device whose
> clock runs a day behind opens no blob. It shows "New message" at each wake,
> and no party learns why. Three failures inside the window point at a lost
> root or a moved clock, and a fresh root repairs both. Part 1 §1.9 gives the
> clock rules.

The device establishes `k_ntf_root` one time at the subscription, with
`UMBRA-KEM` in HPKE. The relay descriptor of Part 10 §10.5.3 carries no KEM
key, thus the relay hands its notification key in the session, and the device
answers with the binding below.

```
NotifyBinding {                   // 98 bytes, sealed under NBIND
    k_ntf_root     [32]u8
    handle         [16]u8         // the handle of the group of §8.2.1
    k_tok          [32]u8         // the token key of that group
    queue_alias    [16]u8         // the alias the blob carries
    relay_idx      u16            // the index the blob carries
}
```

- **[NTF-112]** A queue relay MUST hold an `UMBRA-KEM` notification key pair,
  and it MUST answer the `NKEY` of a queue with an `NPK` that carries the
  public half, before the `NID`. **[NTF-113]** A device MUST seal a
  `NotifyBinding` to that key with HPKE of AUX-6 in the base mode, with
  `"umbra/v1/ntf"` as the HPKE info and the `RecipientId` of the queue as the
  associated data, and MUST send it as the `NBIND` of that queue. The payload
  is the encapsulation, then the ciphertext with its tag, which is 1 234 bytes.
  **[NTF-114]** A queue relay MUST seal the blobs of that queue under the
  fields of the binding, and it MUST NOT hold a binding after the queue is
  deleted or after the rotation of `NTF-007` replaces it.
- **[NTF-128]** A queue relay MUST NOT push for a record that it sends at
  once on a live subscription of the queue, and a subscription and an `ACK`
  of the queue each count as a drain of its handle for `NTF-066`. A drain
  also ends the push that `NTF-049` holds for the end of a window. A device
  that holds the record needs no wake.

  > *Residual.* A record that the relay writes to a live subscription whose
  > link was lost already gets no push. A dead link takes a `MSG` for some
  > time before the relay sees its end. The record stays in the queue, and
  > the next subscription of the queue takes it. The relay cannot push at
  > the end of a subscription in its place. `NET-048` and `NET-050` of Part 3
  > make a client hold each `ACK` for `RECEIPT_MIN_DELAY` and forbid a flush
  > when the client leaves. The end of a circuit carries no cause. Thus
  > the relay cannot tell an orderly end from a lost link. A push at each
  > end would wake a device for a record that it holds. A wake session is
  > shorter than the `ACK` floor, thus that wake would cause the next push
  > too. A reason field in the `CircuitDestroy` of Part 6 §6.2.3, which lets
  > the queue relay tell a lost link from an orderly close, is a planned
  > change of a later version. v1 does not carry it. Part 15 §15.3 holds the
  > row.
- **[NTF-129]** A queue relay MUST keep the binding of each queue in the
  store of Part 3 §3.2.4, thus a restart keeps the pushes of each queue. An
  `NBIND` gets no answer, and a binding that does not open under the
  notification key of the relay is refused under `WIR-317`. The notification
  key MUST survive a restart, thus the reference relay derives it from its
  static secret. The blob of a push carries the alias of the queue of the
  last arrival under its handle.

The KEM ciphertext of about 1.1 KB is a one-time cost. The
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

> *Cause.* Each epoch key of §8.2.3 derives from `k_ntf_root`. A root that
> stays in place while the triple rotates lets one seized root open each past
> and future blob, and the 7-day rotation of the triple then bounds nothing on
> the payload. Thus the root rotates with the triple. A relay that sees 38
> registrations arrive together reads them as one device. Thus a device
> rotates one group at a time.

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

> *Cause.* Part 9 §9.6 defines the hello. Without a rule that drains the queue
> that receives it, a contact request waits for a foreground session. The
> queue relay of a rendezvous queue reads a public queue address, thus it knows
> that the queue belongs to a published handle. Under one shared `k_tok` that
> relay and the Notification Delivery Relay together link the push token to the
> pairwise queues of the same registration. `NTF-044` keeps that group apart.
> The residual that stays is the link between one push token and one published
> handle, and Part 15 §15.3 records it. Private mode registers nothing, thus
> that mode gives the residual to no party, and it pays a latency of up to 24 h.

### 8.2.7 The requests of the NDR

§8.2.1 names a registration and a push, and this section gives their formats.
The NDR takes three requests. `NDR_REQUEST_LEN` is 640 bytes and `PUSH_TOKEN_MAX` is 512 bytes. Each
request travels inside the OHTTP of `NTF-002`, and the
NDR answers each with a response of 16 bytes.

```
NdrRequest {                      // NDR_REQUEST_LEN = 640 bytes
    kind          u8              // 0x01 NREG, 0x02 NUNREG, 0x03 NPUSH
    handle        [16]u8
    body                          // by kind, below
    padding                       // zero bytes to 640
}
NREG   body: nonce [24]u8, ct_len u16, ct_token [ct_len]u8 (17..=528),
             removal_hash [32]u8, prior [32]u8
NUNREG body: removal [32]u8
NPUSH  body: k_tok [32]u8, ttl u32, blob [69]u8

NdrResponse { status u8, padding [15]u8 }  // 0x00 taken, 0x01 refused, 0x02 gone
PushToken   { carrier u8, target }         // the plaintext of ct_token, at most 512 bytes
```

- **[NTF-122]** A party MUST pad each request to `NDR_REQUEST_LEN` with zero
  bytes, and the NDR MUST refuse a request whose padding is not zero. Thus
  the OHTTP relay cannot tell a registration from a push by its length.
- **[NTF-123]** The plaintext of `ct_token` MUST be a `PushToken`: carrier
  `0x02` is FCM and its target is the registration token. The
  target MUST be printable ASCII. Carrier `0x01` is reserved, and no
  version serves it. The value does not return for another carrier. A device MUST NOT register carrier `0x01`.
- **[NTF-124]** A device MUST draw a fresh 32-byte removal secret for the
  first registration of a handle, and each later registration of that
  handle MUST take `SHA3-256("umbra/v1/ndr-removal" || prior)` as its
  removal secret, where `prior` is the secret of the registration before
  it. The device sends the `SHA3-256` of the secret as `removal_hash`, and
  it carries the secret that it holds for the handle in `prior` in each
  request. The NDR MUST drop a registration at an `NUNREG` whose `removal`
  opens it, MUST answer `taken` to an `NUNREG` for a handle that it does not
  hold, and MUST refuse any other `NUNREG`. The NDR MUST take an `NREG` for a
  handle that it holds only when `prior` opens that registration. A secret
  opens a registration when its `SHA3-256`, or the `SHA3-256` of the next
  secret of the chain, equals the `removal_hash` held: the second form
  repeats a move whose answer the device did not see.

  > *Cause.* Without the chain, an answer that the network loses leaves the
  > device with a request that the NDR refuses at each later try: a first
  > `NREG` that landed, an `NUNREG` that landed, or a move that landed. The
  > chain of
  > secrets makes each request safe to send again. The NDR reads each
  > secret in `prior` and can compute the chain, but a queue relay reads
  > the handle alone and never a secret, and no party that reads the hashes
  > alone moves a handle.
- **[NTF-125]** The NDR MUST bound the `ttl` of an `NPUSH` at
  `PUSH_TTL_MESSAGE`, and it MUST answer `gone` and drop the registration
  when the provider names the target gone. It MUST answer `gone` to an
  `NPUSH` for a handle that it does not hold, thus a device that left
  Instant mode stops the pushes of its queue relays. A queue relay MUST
  stop pushing to a handle that got the answer `gone`.
- **[NTF-138]** The NDR MUST drop a registration `NDR_REG_TTL` after the
  `NREG` that made or last moved it, and it MUST answer `gone` to an `NPUSH`
  for it from then on. A device rotates each handle in 7 days under
  `NTF-007`, thus a live device never meets the bound, and a lost device
  leaves no registration behind for good. A device that stays locked past
  the bound registers each handle group again as its rotation comes due
  after the unlock, one group in each session under `NTF-081`.
- **[NTF-134]** An NDR MUST refuse an `NPUSH` whose carrier it does not
  serve, and it MUST NOT post to an address that no provider of its own
  names. An NDR serves carrier `0x02` alone, thus a caller that registered
  an address under the reserved carrier `0x01` cannot make it post to an
  address of its choice.

**The bounds of the NDR.** A first `NREG` carries no admission, and the OHTTP
relay hides its sender, thus the NDR cannot bound one device. It bounds its
own work with the four limits below, and it holds them in memory alone.

- The NDR holds at most 2^20 registrations. It takes an `NREG` that moves a
  handle that it holds. An `NREG` for one more handle at the bound takes the
  place of the oldest registration that took no push since the start of the
  NDR. The NDR refuses that `NREG` when each registration took one. A bound
  that refuses each new handle lets a flood of first `NREG` requests leave
  each new device with no push for the life of a registration.
- The NDR registers at most 1 200 new handles in one minute, and at most 300
  of them from one OHTTP relay. It tells an OHTTP relay by the address of the
  connection. It refuses a first `NREG` above either bound, and the device
  sends it again. A flood thus needs more than 14 hours to reach the bound
  of the registrations. One OHTTP relay that a flood passes through
  leaves the devices behind each other relay their part.
- The NDR takes at most 16 pushes for one handle inside one
  `WAKE_COALESCE_WINDOW`, which is two for each of the
  `MAX_QUEUES_PER_HANDLE` queues. The window of a relay and the window of
  the NDR start at different times. It refuses a push above the bound, and
  that push goes to no provider.
- The NDR holds the hash of each of the last 262 144 requests that proved a
  right, over the handle and the encapsulated bytes. A request that
  repeats one does nothing. A request proves a right when it is a push
  whose token opened and that went to the provider, or when it changed a
  registration. Thus an OHTTP relay that kept the bytes of an `NPUSH` wakes
  no device with them a second time (RFC 9458 §6.5). A memory that holds
  the hash of each request that the gateway opens lets any party push the
  hash of a kept `NPUSH` out with requests that do nothing.

> *Residual.* A flood of first `NREG` requests at the rate above takes the
> place of the oldest registrations that took no push. A device that
> registered long before and got no push is among them. A queue relay that
> pushes for that device gets the answer `gone` and drops its binding under
> `NTF-125`. Thus the device gets no push until the rotation of `NTF-007`
> gives it a new handle, inside 7 days. A restart of the NDR takes each registration for one
> that took no push, and it empties the memory of the requests. So does a
> party that brings 262 144 requests that prove a right. Each one is a push
> under a `k_tok`, or a new handle under the rate above, which is more than
> three hours for all of them. A kept `NPUSH` that passes again after either
> is one push of its handle under the bound of 16 in one window, until the
> rotation of `NTF-007` ends its `k_tok`. v1 puts no admission on a first
> `NREG`. That admission is a planned change of a later version.

- **[NTF-130]** The NDR MUST send an FCM push through the HTTP v1 API of
  FCM as a data message with no `notification` field: the one data field
  `b` holds the blob in base64url with no padding, `android.priority` is
  `HIGH`, and `android.ttl` is the expiry of the push in seconds. The NDR
  MUST take a status 404 from FCM whose error body names the error code
  `UNREGISTERED` as the answer that the token is gone. FCM gives a 404 for
  other faults too, as for a project that does not exist. Such an answer
  MUST drop no registration. The
  NDR MUST sign the assertion of its access token with the key of the service
  account of the deployment, and it MUST NOT give that account or its token
  to any other party.

> *Cause of `NTF-124`.* A queue relay knows each handle of its queues. A
> removal or a replacement that needed the handle alone would let that relay
> end the pushes of a device, or point them at a token of its own. The hash
> of a secret that only the device holds closes both.

## 8.3 The three modes

UMBRA ships the three modes. The user selects one for the device.

| Mode | The carrier on Android |
| --- | --- |
| Instant | FCM, the persistent socket of §8.4.1, and the poll of `NTF-131` |
| Private | A timer of the platform on a fixed clock. Each tick starts one run that drains each queue and ends. The client holds no push token, no socket between two ticks, and no poll |
| Off | None. A run starts when the user opens the application |

| | **Instant** | **Private** | **Off** |
| --- | --- | --- | --- |
| Mechanism | One push for each event | Constant-rate wakes | Drain when the user opens the application |
| Cadence | On arrival | Fixed 30 min | — |
| Latency | ~1 s | up to the interval, and longer when the platform defers the timer | until the user opens the application |
| Google learns | The wake time for each event, on a device with FCM | Nothing: the client holds no push token | Nothing: the client holds no push token |
| A locked client | Shows which conversation waits (`NTF-136`), and fetches nothing | Receives nothing and shows nothing until the unlock | Receives nothing until the unlock |
| Default | The shipped default | The high-risk configuration | Never a default |

**A locked client in Private mode receives nothing.** Part 14 rule `IMP-119`
locks the client after 15 minutes with no action of the user, and a locked
client holds no key of a queue. A tick of the fixed clock of a locked client
does nothing, and Private mode holds no wake table of `NTF-135`, because it
holds no push. Thus the latency of Private mode is the interval only while
the client is unlocked. After the lock it is the time to the next unlock,
and `NTF-120` tells the user so one time. Part 15 §15.3 holds that row.

**A run with no view.** In Private mode and in Off mode a client holds no run
while no view is on the screen. A client MAY keep the run for 30 s after the
last view left the screen. Thus a picker of the platform or a send that the
user started ends first. The client then ends the run.

**Private mode is the interesting mode.** §8.4.1 gives its Android carrier, and
NTF-039 keeps it off high-priority FCM. The wakes fire on a fixed schedule,
and the arrival of a message does not change that schedule. Thus the wake time
carries **no information** about a message arrival.

**The floor of the cadence.** Two bounds set the floor of the cadence, and no
platform push ceiling is one of them. The first bound is Doze. §8.4.1 states
that Doze limits `setExactAndAllowWhileIdle` to one call in each 9 min, thus a
fixed clock shorter than 9 min needs a foreground service that the user can
see. The second bound is the U5 battery row of Part 3 §3.12. Part 3 §3.6.2
derives about 9.1 mWh for each radio promotion, and the fixed term of U5 in
Part 2 §2.4 permits 0.308 Wh in each day with no arrival. A 20 min cadence
makes 72 wakes in each day. If each wake promoted the radio, the cost is
72 × 9.1 mWh, which is about 0.655 Wh, and that is more than twice the U5 fixed
term. A 30 min cadence makes 48 wakes, which is about 0.437 Wh under the same
model. The carrier of Private mode holds no connection between two ticks.
Thus each tick promotes the radio, and the model above is its cost and not
an upper bound only. **The figure of 0.655 Wh is a
model and not a measurement.** Part 3 §3.12 states the same figure as the
Private row of its battery table, and §8.8 repeats it as the upper bound. Part
2 §2.4 scopes U5 to Instant mode, thus U5 does not measure the Private column.

**[NTF-087]** An implementation MUST measure the wake cost of the fixed clock
on a mid-range Android device, with a power monitor, before a revision re-tunes
the cadence of Private mode.

**Private mode has its own U3 latency, and the cadence above gives it.** A
message stays invisible for a maximum of 20 min at the 20 min cadence. A message
stays invisible for a maximum of 30 min at the 30 min cadence. The 15 min
invariant of U3 does not hold in this mode, because a cadence at or below 15
min makes 96 wakes or more in each day, and the model above prices those wakes
above the U5 fixed term. Part 2 §2.4 scopes U3 to Instant notifications and
Balanced mode, and it states that trade.

> *Cause.* The derivation above rests on Doze and on U5, which are the bounds
> that an Android client meets. `NTF-087` puts a measurement before the next
> change.

**[NTF-052]** A client in Private mode MUST draw the phase of its fixed clock
from the CSPRNG at each network change. **[NTF-053]** The client MUST draw it
again at each change of its ingress relay pair. The phase is the offset of the
wake inside the interval. One phase across two networks links the two, and Part
15 §15.3 states that residual.

**[NTF-009]** The UI MUST show the trade in one honest line, and **[NTF-010]**
the UI MUST NOT hide Private mode. **[NTF-011]** Onboarding MUST NOT ask the
user to select a threat model. **[NTF-082]** The settings MUST offer the
high-risk configuration, which is Private notifications with the content
preview off: one screen holds the two controls, and a shortcut that sets both
adds nothing that the user cannot do. **[NTF-083]** A build MUST ship Instant mode with the content
preview off as the default of each Profile. That default applies to each build
that holds a carrier of §8.4.1.

> *Cause.* A user at the first launch cannot weigh a threat model, and U1 of
> Part 2 §2.4 permits no security decision before the inbox. Thus onboarding
> offers no high-risk configuration. The word "profile" names the identity
> object of Part 4 §4.2.5, thus Part 1 §1.6.1 registers the configuration
> under its own name. The default is one value on each build, thus a tester
> and a user see the same behavior.

The high-risk configuration also explains the cost of Instant mode. Instant mode
gives a better latency. But Instant mode shows the wake time of each event to
Google on an FCM build. Instant mode also gives a live token-to-handle mapping
to the NDR.

## 8.4 Platform specifics

### 8.4.1 Android

**Default path: a bounded foreground service.** A high-priority FCM message
wakes a `specialUse` foreground service. That service drains the queues and then
stops. On a device with no FCM, the persistent socket and the poll below
carry the wakes.

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

A **persistent socket** is the second carrier of Instant mode, behind the
same Rust trait. It needs no Notification Delivery Relay and no provider,
thus it is the carrier of a device that holds no FCM. The poll of `NTF-131`
is the third.

- **[NTF-116]** A client that carries its wakes over a persistent socket MUST
  hold that socket in a `specialUse` foreground service, with a notice that the
  user can see for the whole time. Android closes the sockets of an
  application a short time after it leaves the screen, and a test on an
  emulator of API 35 showed the close after 45 seconds. The 6 s bound of
  `NTF-012` applies to a push-wake session, and it does not apply to this
  service.
- **[NTF-117]** That service MUST hold no key and no socket of its own. The
  one run of the network of Part 14 §14.6.1 continues under it.
- **[NTF-118]** A client MUST start a new run after a run ends with a fault,
  while a view is on the screen or the service runs. The delay before a new
  run MUST double from 2 s to a ceiling of 30 s, and a run that reaches the
  ready state MUST set it back to 2 s.
- **[NTF-119]** A message alert MUST show no text of the message and no name
  of a contact while the content preview is off (`NTF-083`). On the lock
  screen it MUST show that an alert exists, and no more.
- **[NTF-120]** A client MUST end the service at a lock, because a locked
  client holds no key that reads a queue (Part 14 rule `IMP-127`). A client
  that locks with no view on the screen MUST tell the user one time, with no
  sound, that no message arrives until the unlock.
- **[NTF-131]** A client that holds no push carrier MAY poll: a periodic
  job of the platform, no more often than its least period, starts a run of
  an open client that has none, and that run drains each queue under
  Part 3 §3.7 item 4. A locked client holds no key of a queue, thus a poll
  of a locked client MUST do nothing. The Android build holds FCM and this
  poll beside the persistent socket in Instant mode. It ends the poll in
  Private mode and in Off mode.
- **[NTF-121]** A record that arrives MUST NOT start the idle time of the
  auto-lock again. An action of the user alone does that. Thus a peer that
  writes each 10 minutes does not keep `K_store` in RAM.

**The wake of a locked client.** Part 14 rule `IMP-119` locks the client
after 15 minutes with no action of the user. A locked client holds no
`K_store`, thus it holds no queue key and no ratchet, and no carrier of this
section delivers a record to it. The **wake key** lets it open the blob of
§8.2.2 all the same, and show which conversation waits.

- **[NTF-135]** An Android client in Instant mode MUST hold a **wake table**
  outside `K_store`: each `k_ntf_root` that a binding of §8.2.3 uses, and
  each `queue_alias` with the conversation of its queue. It MUST seal the
  table under a key of the platform keystore that needs no user
  authentication, and it MUST write the table again while it is open, after
  each change of a binding and when it leaves the foreground.
- **[NTF-136]** A locked client MUST open each blob with that table under
  `NTF-075` to `NTF-079`. It MUST show that a message waits in the
  conversation of `queue_alias`, grouped under `NTF-089`, with no text of a
  message and no name of a contact. It MUST NOT fetch or acknowledge the
  record, which stays at the relay until the unlock.
- **[NTF-137]** A client MUST delete the wake table and its keystore key at a
  local wipe of Part 7 `DEV-008`, and when the mode leaves Instant.

> *Cause.* Without a wake key, each push to a locked client shows a line that
> names nothing, and the record waits for the unlock in silence. A client
> that keeps the queue keys and the ratchets in RAM under the lock gives each
> later message to a party that seizes the device in the AFU state. The wake
> key gives such a party the roots of the blobs alone: which conversation
> took a push, and no message. Thus the claim of Part 14 §14.6.4 holds, and
> Part 15 §15.3 records the rest.

**Private mode does not use FCM on Android.** §8.3 wakes the device on a fixed
clock of 30 minutes, and a message arrival does not change that clock.

- **[NTF-038]** A client MUST carry a Private-mode wake on a timer of the
  platform that no arrival moves. Each tick MUST start one run of an
  open client that drains each queue under Part 3 §3.7 item 4 and then ends.
  A client in Private mode MUST hold no push token. It MUST end its
  registration at the NDR and its wake table when it enters the mode
  (`NTF-137`). A tick of a locked client MUST do nothing. The reference
  Android build uses an alarm that Doze permits and that needs no exact-alarm
  permission, at the 30 min cadence. **[NTF-039]** A client MUST NOT carry a
  fixed-cadence wake over a high-priority FCM message.
- **[NTF-040]** A client on a platform that gives it no such timer MUST show
  that Private mode is not available on that build. **[NTF-041]** That client
  MUST NOT show Private mode as active.

The platform can defer such a timer in Doze, and it batches the timers of
several applications. A deferral is a function of the device state and not of
an arrival, thus it gives an observer no arrival time. It makes the
latency of the mode longer than the interval. An exact timer would hold the
interval, and it needs a permission that the user grants in the platform
settings. v1 does not ask for that permission.

> *Cause.* NTF-014 makes each high-priority FCM message cause a notification
> that the user can see, because the 7-day heuristic of Google downgrades an
> application that does not. Private mode makes 48 to 72 wakes each day, and
> almost every one of those wakes carries no message. Thus a Private mode over
> high-priority FCM shows 48 to 72 notifications each day that name nothing.
>
> A normal-priority FCM message is the other option, and Doze defers it. The
> note below states that limit, and a deferred wake destroys the fixed cadence
> that gives Private mode its property. A timer on the device has neither
> problem, and it puts no party on the path. A persistent socket is not a
> carrier of this mode. A socket that stays open between two ticks would
> give the ingress relay a session for the whole day in the place of one
> short session for each tick.

**Grouping and collapse.**

- **[NTF-088]** A party that dispatches a push MUST NOT set a collapse key on
  a message push. **[NTF-089]** An Android client MUST group the tray by the
  conversation of `queue_alias` after the AEAD open, with a notification group
  of the platform. Thus the tray groups the alerts of one conversation, and the
  provider sees one push kind.

> *Cause.* A collapse key for each push kind is a fingerprint that the provider
> can see, and a collapse key for each conversation is a conversation count that
> the provider can see. The group on the device does the grouping after the
> open, thus the provider sees nothing.

> Note: Doze ignores a partial wake lock and suspends the network access. Doze
> also limits `setExactAndAllowWhileIdle` to one call in 9 minutes. App Standby
> gives an idle application the network about one time each day. A cover-polling
> schedule shorter than 9 minutes needs a foreground service that the user can
> see, or it needs a platform push. No method removes this limit. A
> specification that says differently gives an application that does not deliver
> messages.

### 8.4.2 Padding, expiry, the re-push, and the peek

**Padding requirement.** **[NTF-017]** The response path for a message fetch
MUST carry padding to a constant number of fixed cells. This rule applies for
each state of the server. Trail of Bits found that the iOS `GET` of SimpleX
gives a different packet count when the relay holds a message. That behavior is
a message-existence oracle for a network observer. The rule names no
platform.

- **[NTF-065]** A queue relay MUST set the push expiry to `PUSH_TTL_MESSAGE` for
  a message push. **[NTF-086]** A queue relay MUST set the same
  `PUSH_TTL_MESSAGE` for a digest push. It MUST NOT give a push a field
  outside the blob that differs by the kind of the push. The `digest` flag
  travels inside the AEAD of the blob of §8.2.2 alone. A device that opens a
  blob bounds its staleness itself, from `relay_ts` of the blob. A device
  MAY drop the alert of a digest whose `relay_ts` is older than one hour.
  The drain of the wake still finds each record. The expiry is
  the FCM `ttl`.
  **[NTF-066]** If no drain of a handle follows a push inside
  `REPUSH_INTERVAL`, the queue relay MUST hand one more push. The rule
  covers a message push and a digest push alike, and the push that
  `NTF-049` hands at the end of a window. The interval runs from that
  push. A re-push carries no `digest` flag. **[NTF-067]** A
  queue relay MUST NOT hand more than `REPUSH_MAX` re-pushes for one message.
- **[NTF-068]** At each session open, and at each session resume, a client MUST
  run the peek of Part 3 §3.7 item 4 on each queue of that session. Thus a
  push that expired at the provider loses no message.

| Parameter | Value |
| --- | --- |
| `PUSH_TTL_MESSAGE` | 86 400 s. The provider measures it from the hand-off |
| `REPUSH_INTERVAL` | 1 h. The queue relay measures it from the hand-off of the previous push for that handle |
| `REPUSH_MAX` | 3 re-pushes for one message |

> *Cause.* An expiry of 3 600 seconds with no re-push loses the wake of a
> device that is off for longer. The message then waits for the next
> foreground session. The blob of §8.2.2 holds no content, thus a longer expiry exposes
> 69 bytes under an epoch key and nothing more. The re-push bounds the wait at
> `REPUSH_INTERVAL` for a device that is reachable, and the peek covers a
> device that is not.
>
> *Cause of the one expiry.* The alternative is a shorter expiry for a digest
> push than for a message push. The `NPUSH` carries `ttl` in the clear to
> the NDR, and the NDR hands it to the provider. Thus the NDR and Google
> would read, for each push token, which wake is the activity of a group and
> which is a pairwise message. That is against the purpose of
> `NTF-088` and of the `digest` flag inside the blob. One expiry gives the
> two parties one push kind. The cost is a digest push that the provider
> holds for a day for a device that is off, which is 69 bytes.

## 8.5 Coalescing and groups

FCM permits 5 000 messages in one hour to one device. A conversation that makes
one push for each record uses that budget. A busy one breaks the notifications of each other conversation
on the device.

**The coalescing applies to each handle.** A queue relay sees queues and
handles, and it does not see the conversation class. Thus the window below
applies to a 1:1 conversation, to a group of each size, and to a group
digest alike.

| Parameter | Value |
| --- | --- |
| `WAKE_COALESCE_WINDOW` | 10 s. The queue relay measures it from the moment that it hands a push for a handle to the Notification Delivery Relay |

- **[NTF-048]** A queue relay MUST NOT hand a second push for one handle to the
  Notification Delivery Relay inside `WAKE_COALESCE_WINDOW`. **[NTF-049]** If
  an event arrives inside the window, the queue relay MUST hand one push at the
  end of the window, unless a drain of the handle or a later push for it came
  first: that one push covers each event before it. **[NTF-050]** A revision
  that changes
  `WAKE_COALESCE_WINDOW` MUST derive the U3 target and the idle table of Part 3
  §3.12 again.
- **[NTF-019]** A queue relay MUST apply the window to each handle, whatever
  the class of the conversation behind it. **[NTF-018]** A group above
  `GROUP_ALL_NOTIFY_MAX` members MUST NOT make one alert for each record at the
  device. Part 7 rule `DEV-221` defaults such a group to `mentions`, and the
  setting acts after the drain. Part 11 §11.10 owns `GROUP_ALL_NOTIFY_MAX`.

> *Cause.* A relay cannot tell a group from a 1:1 conversation. Thus a rule
> that lets a small group stay at one push for each message binds nothing
> that the relay can apply. `GROUP_ALL_NOTIFY_MAX` of Part 11 §11.10 is the
> member count above which one alert for each record floods the tray, and the
> notification setting of Part 7 §7.5.9 changes at that bound.

> *The derivation of the 10 s.* U3 of Part 2 §2.4 gives a p95 of 15 s, and §8.8
> gives the alert a p95 of about 4 s. Thus the window can hold a coalesced event
> for 11 s at most, and 10 s leaves 1 s. Part 3 §3.12 spreads the 184 background
> arrivals of its model day about 274 s apart. Thus about 4 % of them fall
> inside the window of the previous arrival. The window saves that share of the
> wakes, and Part 3 §3.12 takes no credit for it. **That share is unverified.**
> **[NTF-051]** An implementation MUST measure the coalesced share in a real
> deployment before a revision re-tunes the window.

### 8.5.1 The notify digest

A group-queue relay holds no `k_tok`, thus it cannot push. It wakes a member
device with a digest in a notify queue, and §8.5.2 gives that path. This
section gives the digest record.

```
NotifyDigest {                    // the L6 record of kind 0x04, Part 6 §6.4.2
    version          u8           // 0x01
    group_queue_id   [32]u8       // the GroupQueueId of Part 6 §6.4.5
    post_count       u8           // records since the previous digest, at most 255
}
```

A `NotifyDigest` is 34 bytes, and it travels sealed under `K_QE` of Part 6
§6.4.2 in one `B0` cell. The queue relay of the notify queue reads
ciphertext, thus it does not learn the group.

### 8.5.2 The notify queue of a group

A group queue of Part 3 §3.2.7 holds no membership list and no `k_tok`. Thus a
group-queue relay cannot push. A member device in Instant mode gives each
group one notify queue of its own at a queue relay, and it registers that
queue with each replica of the group queue. The group-queue relay writes a
`NotifyDigest` of §8.5.1 into the notify queue, and the queue relay of the
notify queue pushes as for any queue. Part 6 §6.4.5 gives the commands
`GNREG` and `GNUNREG`.

- **[NTF-090]** A client in Instant mode MUST make one notify queue for each
  group at `mentions` or `all`, on each device. Part 7 §7.5.9 gives the
  setting. **[NTF-091]** A client MUST put a group notify queue under a
  notification handle that holds no pairwise queue and no rendezvous queue.
  **[NTF-092]** A client MAY put the notify queues of several groups under one
  handle. A client SHOULD place the notify queues of different groups at
  different queue relays and under different handles while its count of
  handles permits it. It shares a handle or a relay between two groups
  only when that count does not permit it. One queue relay that holds the notify queues of
  several groups on one session learns that one client is in groups at each
  of the depositing relays. With two of those relays it joins one
  member across two groups. Part 15 §15.3 holds that residual.
- **[NTF-093]** A client MUST register the `QueueAddress` of the notify queue
  with each replica of the group queue by `GNREG`. **[NTF-094]** A
  registration MUST NOT carry a member index, a pseudonym, or a device
  identifier. **[NTF-095]** A group-queue relay MUST NOT link a registration
  to a reader session or to a writer session.
- **[NTF-096]** A group-queue relay MUST write one `NotifyDigest` as a `SEND`
  into each registered notify queue when it accepts a `GPOST`. **[NTF-097]**
  A group-queue relay MUST NOT write a second digest to one registration
  inside `GROUP_DIGEST_MIN_GAP`. **[NTF-098]** If a record arrives inside the
  gap, the group-queue relay MUST write one digest at the end of the gap.
  **[NTF-099]** A group-queue relay MUST NOT write a digest that names a
  record, a member index, or a sequence number. The relay writes its
  `GroupQueueId` in `group_queue_id`, and it writes the count of records
  since the previous digest in `post_count`.
  The digest travels to the queue relay of the notify queue as an
  `UMBRA_DEPOSIT` of Part 6 rule `WIR-526`. That relay learns the address of
  the group-queue relay that deposits into the queue, thus it learns that the
  queue is a notify queue and which relay holds its group queue; it learns no
  group and no member. Part 15 §15.3 holds that residual.
- **[NTF-100]** A group-queue relay MUST hold a registration in memory only.
  **[NTF-101]** A group-queue relay MUST NOT hold more than
  `GROUP_NOTIFIER_MAX` registrations for one group queue. Part 3 §3.2.7 owns
  that constant. **[NTF-102]** A group-queue relay MUST discard a registration
  7 days plus `CLOCK_SKEW` after the `GNREG` that made it. **[NTF-103]** A
  group-queue relay MUST discard a registration at a `GNUNREG` that names its
  queue. A group-queue relay takes at most 4 new registrations for one group
  queue from one circuit. It refuses a further `GNREG` of that circuit
  for that queue with `LIMIT`. A device holds one notify queue for a group,
  and two while it rotates that queue under `NTF-105`. Thus a party that
  fills the notifier set of a group builds one circuit for each 4
  registrations.
- **[NTF-104]** A client MUST rotate a group notify queue with the triple of
  `NTF-007`. **[NTF-105]** A client MUST register the new queue before it
  drops the old one.
- **[NTF-132]** A client that leaves a group, that the group removes, or
  whose group closes MUST send a `GNUNREG` for its notify queue to each
  replica while it holds a read key of the group. A client that holds no read
  key sends none, and the replica discards the registration under `NTF-102`.
  **[NTF-133]** A client MUST end a notify queue that it drops with a `DEL`
  of Part 6 §6.4. At the start of a run, a client MUST end each notify queue
  that no group of its store names. Such a queue is left from a run that
  ended before the client wrote the queue to its group.
- **[NTF-106]** A client in Private mode or in Off mode MUST NOT register a
  group notify queue. Those modes find a record at the next drain of the group
  queue.
- **[NTF-107]** On a wake, a client MUST drain the notify queue under Part 6
  §6.4.3. **[NTF-108]** The client MUST then open a session to one replica of
  the group queue with `GSUB` from its cursor. Part 11 §11.2.2 gives the
  cursor.

| Parameter | Value |
| --- | --- |
| `GROUP_DIGEST_MIN_GAP` | 10 s. The group-queue relay measures it from the moment that it writes a digest to one registration |

A group-queue relay hands out at most 512 digests in each second over all its
group queues. Each digest costs the relay a seal, and a digest for another
relay costs a connection. A digest above the bound waits for the next
second, and the relay drops none. The digests that wait for one registration
are one digest, whose `post_count` counts each record. The group queues that
wait take the bound in turns and in equal shares. Thus a group with
`GROUP_NOTIFIER_MAX` registrations holds back neither the relay nor the
digests of another group.

A group has no daily digest budget, and it defaults to `all` under Part 7
rule `DEV-259`. The gap bounds the digests at one in each 10 s for each
registration, and the window of §8.5 then bounds the pushes at one in each 10 s
for each handle at the queue relay of the notify queue. A digest is one push
wake, and Part 3 §3.12 prices a wake at about 19.7 KB with its drain.

**Which party learns what.** The group-queue relay learns the count of the
registrations, which is close to the count of the member devices in Instant
mode, and the `relay_id` of each notify queue. It learns no handle, no push
token, and no `k_tok`. It cannot link a registration to a member index or to a
reader session, because a registration carries neither. Part 15 §15.3 states
that residual, and Part 11 §11.5 gives the full list of what a group-queue
relay learns.

> *Cause.* The group queue of Part 3 §3.2.7 holds the records of a group at
> a relay that cannot push, thus a group needs a carrier of its own. The
> notify queue is that carrier. The gap is the value of `WAKE_COALESCE_WINDOW`, thus a busy
> group costs no more pushes than a busy pairwise queue.

## 8.6 The web client

Part 1 §1.1 defers the web client of Part 14 §14.7, and the two rules
of this section bind it when it ships. It holds a live session while its browser runs,
and that session carries each arrival. **[NTF-110]** A web client MUST NOT
register a push token with the NDR, and it MUST NOT hold a registration of
§8.5.2 of its own. **[NTF-111]** A web client MUST take each arrival
from its live session, and it MUST show an alert through the notification API
of the browser while the browser runs. The phone of the user carries the
notification of the device set at each other time, under §8.4.1.

> *Cause.* Web Push needs a push service that the browser vendor operates, and
> a subscription there is a durable identifier at a party that Part 15 §15.1
> would have to list. A linked device with an open socket needs no such party,
> and the phone already wakes for the device set.

## 8.7 Residual leak — normative statement

**[NTF-027]** This text is normative, and it MUST appear in the security documentation that
the user reads:

> In Instant mode on a device with FCM, Google learns that a given Google
> account has UMBRA installed. Google also learns the exact time and the count
> of each notification that it delivers to that account. Each push looks the
> same to Google, thus Google does not learn which one is a group message.
> In Private mode and in Off mode UMBRA holds no push token, and Google
> learns from the push path no time and no count. In Private mode a locked
> UMBRA receives nothing until you unlock it.
>
> In Instant mode, the Notification Delivery Relay of UMBRA learns the mapping
> token↔handle↔arrival time. It learns this mapping transiently and in memory
> only. A queue relay learns the handle, `k_tok`, the `notifier_id`, and the
> notification times for each queue. One handle covers at most
> `MAX_QUEUES_PER_HANDLE` queues, thus that relay groups at most 8 of your queues
> under one handle. Part 3 §3.2.5 gives a transport session the same bound.
> **No stored database at one party holds token↔queue.**
>
> Three events recover token↔queue, and thus account↔queue on an FCM build. The
> events are a live wiretap on the NDR, a prospective logging order against the
> NDR, and collusion between the NDR and a queue relay.

**The policy requirements that follow:**

- **[NTF-029]** The client MUST take the route to the NDR from the pin of its
  build (`NTF-127`) and from no relay. Thus the NDR does not follow the relays
  that the user chose, and a relay cannot point the client at another NDR.
- **[NTF-109]** A deployment MAY operate its own Notification Delivery Relay.
  The NDR of the project is one such deployment, and a self-hosted build that
  operates no NDR points at it.

> *Cause of `NTF-029`.* A pin of an NDR by the user is the alternative. A
> deployment operates one NDR (Part 10 §10.10), thus the user has no second NDR
> to pin. The carrier also forbids one: on FCM the holder of the service
> account of the project of the build alone can wake the app, thus an NDR of a
> third party cannot serve that build. The pin of the build keeps the
> property: the choice of relays gives no party a route to the push token. A
> version that lets a third party operate an NDR beside the one of the deployment gives the
> user the choice between the two, and §10.10 then enters that NDR in the
> relay reputation.

> *Cause of `NTF-109`.* FCM gives a service account to each registered
> project, thus a deployment can operate the full notification path. The NDR stays a separate trust role with its own
> attestation track, and Part 10 §10.10 gives the cause that keeps it out of
> the relay reputation.

## 8.8 Estimated cost

| Metric | Instant mode | Private mode |
| --- | --- | --- |
| Median notification latency | 0.8–2.0 s | ≤ the interval |
| p95, the alert | ~4 s | ≤ the interval |
| p95, the message content, Android, the client unlocked | ~7 s | ≤ the interval, and ~3 s more |
| The message content, the client locked | At the unlock. The alert names the conversation under `NTF-136` | At the unlock, with no alert before it |
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
is 0.66 Wh and 4.3 %. The two Private figures count one promotion for each
wake, which is the upper bound of §8.3, and `NTF-087` puts a measurement
before a revision re-tunes the cadence.

**The cheaper mode depends on the arrival count, and this table states that
plainly.** Private mode at 30 min costs less battery than Instant mode above 48
arrivals each day. Private mode at 20 min costs less above 72. Part 2 §2.4
scopes U5 to Instant notifications, thus U5 measures the Instant column only. U5
has a fixed term and a term for each arrival, and the two battery rows above
give them.

> *The pacing term.* The push path itself is not paced. Part 3 §3.5.2 paces the
> session that carries the message body, at a `PACING_MEAN` of 1 s. That wait is
> exponential, and Part 3 §3.9 gives its 95th percentile as 3 s. Thus the
> content of a notification can reach the device about 3 s after the alert. The
> worst case is about 7 s, which stays inside the U3 p95 of 15 s. U3 does not
> change.
