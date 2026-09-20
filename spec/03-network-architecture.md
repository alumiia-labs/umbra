# UMBRA Protocol Specification — Part 3: Network Architecture

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 3.0 The governing constraint

A formal result bounds each decision in this part. Das, Meiser, Mohammadi, and
Kate give this result in "Anonymity Trilemma" (IEEE S&P 2018) and in
"Comprehensive Anonymity Trilemma" (PoPETs 2020(3):356–383). For a latency
overhead ℓ and a per-user noise β, strong anonymity needs `2ℓβ ≥ 1 − ε`. Their
classification puts Tor-like designs in the *strong anonymity impossible* cell,
because such designs have constant latency and negligible cover. The 2020 result
is sharper, and it applies directly to UMBRA:

> If c > 0 then strong anonymity is impossible if the latency overhead is
> constant (ℓ ∈ O(1)).

UMBRA accepts third-party relays, thus `c > 0` by assumption. **An UMBRA with no
added delay and no cover cannot give strong anonymity against a global
adversary. This specification does not make that claim.** Part 2 states the
claims that UMBRA does make, and §3.11 states them again in a concrete form.

Thus the design uses the axis that costs less. For a mobile messenger, latency
costs little and bandwidth costs much.

- Measured usability bound (Davitt, Ristea, Murdoch, arXiv 2601.17845, Jan 2026,
  n=288): a mean added delay of **1 s and of 4 s keeps usability**. A delay of 7
  s is marginal. A delay of 10 s damages usability.
- Measured battery bound: the LTE/NR RRC tail timer is the binding limit, and
  the data cap is not. The documented radio model of Android gives **18 s or
  more of elevated radio draw for each transfer**. One cover packet in each 30 s
  interval gives a radio duty cycle of about 60 % at only 5.8 MB/day.

Thus UMBRA spends seconds and does not spend gigabytes.

## 3.1 Entities and roles

| Role | Operated by | Sees | Does not see |
| --- | --- | --- | --- |
| **Queue Relay** | Nonprofit or third party | Queue IDs, ciphertext, delivery time. For a group queue (§3.2.7): that the queue exists, the count of reader sessions and of writer sessions, the arrival time and the bucket of each record, the member count at each rotation from the slot count of the epoch-key record, and the notifier count | Client IP address (when chained), identities, content. For a group queue: the membership list, the identity or the pairwise queue of any member, the sender of a record, and the content of a record |
| **Chain Relay** | Nonprofit or third party | Adjacent hop addresses, cell time | Queue IDs, content, endpoints |
| **Ingress Relay** | Nonprofit or third party | Client IP address, cell time, cell sizes, and the client class of §3.8.1, which is web or native | Destination queue, content, contact graph |
| **Notification Relay (NDR)** | Nonprofit only (refer to Part 8) | Push handles, blinded tokens in transit | Queue-to-token binding, content |
| **Directory Authority** | Seven legal persons under separate control (Part 10 §10.5.1) | Relay descriptors, measurements | Nothing about users |

**[NET-001]** One physical server MAY implement more than one role. **[NET-002]** But a relay MUST NOT
operate as a Chain Relay and as a Directory Authority at the same time. **[NET-003]** A relay
MUST NOT operate as a Chain Relay and as the Notification Relay for the same
client.

## 3.2 Queues

A **queue** is a one-direction, anonymous mailbox on a server. It is the
smallest unit of the network layer of UMBRA. It is also the cause that the
seizure of a relay gives nothing of use. §3.2.1 to §3.2.6 give the pairwise
queue, which has one reader. §3.2.7 gives the group queue, which has many
readers and which the same relays serve.

### 3.2.1 Queue identifiers

Each queue has two identifiers. The relay makes the two identifiers
independently from its CSPRNG:

```
RecipientId   32 bytes   known only to the queue owner
SenderId      32 bytes   known only to parties authorized to write
```

**[NET-004]** `RecipientId` and `SenderId` MUST be independent CSPRNG outputs. **[NET-005]** A party MUST
NOT be able to derive one identifier from the other. **[NET-006]** A party MUST NOT be able to
derive an identifier from a key or from an earlier queue. **[NET-007]** A relay MUST NOT
store a value that links the two identifiers outside of the one queue record.
**[NET-117]** A recipient MUST NOT give `RecipientId` to a sender.

> *Cause of NET-117.* The queue address of Part 6 §6.6.10 carries `SenderId`,
> `QS_auth_sk`, and `QE`, and it carries no `RecipientId`. Part 6 §6.4.2 rule 1 therefore derives
> `K_QE` from `SenderId` alone. An earlier draft put `RecipientId` in that
> derivation. A sender has to compute `K_QE` to seal a `SEND`, thus that draft
> made the sender hold a value that this section keeps at the queue owner.

> *Rationale.* This construction is the SMP construction of SimpleX, which uses
> two unrelated 24-byte IDs. UMBRA increases the width to 32 bytes, for
> uniformity with the other identifiers of UMBRA. The construction defeats the
> obvious attack against a seized relay, which joins the sender table to the
> recipient table. The construction also costs nothing.

### 3.2.2 Per-queue keys

A queue carries three keys. All three keys are **fresh for each queue**:

| Key | Type | Held by | Function |
| --- | --- | --- | --- |
| `QR_auth` | X25519 | Recipient | Authorizes recipient commands, deniably |
| `QS_auth` | X25519 | Sender | Authorizes sender commands, deniably |
| `QE` | 32-byte secret | The two parties | Per-queue end-to-end layer below the ratchet (Part 6 §6.4.2) |

The recipient makes the three keys with the device CSPRNG. It gives
`QS_auth_sk` and `QE` to the sender in the queue address, and Part 6 §6.6.10
gives that address its wire form. §3.2.6 gives the carriers of the address.
**[NET-008]** A recipient MUST NOT give `QE` to a relay. The
relay-to-recipient direction carries no separate wrapping key. The per-hop
cipher of §3.4.4 re-encrypts each cell at each hop in the two directions.

**[NET-009]** **A queue key MUST NOT come from the Root Identity or from a device key. [NET-010] A queue
key MUST NOT come from the key of a different queue. [NET-011] A queue key MUST NOT be
equal to one of these keys. [NET-012] A queue key MUST NOT be linkable to one of these
keys.**

This rule is the mechanism that stops a seized relay from the collection of the
queues of one user by repeated key material. **[NET-013]** Implementations MUST make queue
keys from the device CSPRNG. **[NET-014]** Implementations MUST NOT derive queue keys from a
per-user seed.

### 3.2.3 Deniable command authorization

A command uses a **deniable authenticator** for authorization. A command does
not use a signature:

```
auth = HMAC-SHA3-256(k, corr_id || authorized_bytes)
  where k       = HKDF("umbra/v1/cmd-auth", X25519(Q*_auth_sk, RelaySession_pk))
        corr_id = 16 random bytes, unique for each command
```

**The authorized bytes.** Part 6 §6.4 gives the command header. The
authenticator covers each field of that header but `auth` itself, and it covers
the payload. **[NET-278]** A party MUST derive `k` as
`HKDF-SHA3-256(salt = "", ikm = X25519(Q*_auth_sk, RelaySession_pk),
info = "umbra/v1/cmd-auth", L = 32)`, and it MUST abort on a
non-contributory Diffie-Hellman output, as Part 5 rule `CRY-040` does.

**[NET-118]** A party MUST compute `authorized_bytes` as the concatenation
below:

```
authorized_bytes = version || cmd || queue_id || BE16(payload_len)
                || payload || bind
```

**[NET-119]** A party MUST set `bind` to the empty byte string for each command
of Part 6 §6.4. **[NET-120]** For a `CPUT` of Part 13 §13.3.3, a party MUST set
`bind` to the 32-byte `storage_token` of that section. Part 13 rule `ATT-042`
states the same binding, and this rule gives its encoding. **[NET-149]** For a
community command of Part 12 §12.3.3, a party MUST use `pull_sk` in the place of
`Q*_auth_sk`. Part 12 rule `COM-175` states the same binding. A community has no
queue secret, and `pull_sk` comes from `community_id`.

**The session key.** A command reaches its relay over a circuit of §3.4, and
that relay is the last hop of the circuit. The handshake of §3.4.3 gives that
hop one fresh X25519 key, and both ends hold it.

- **[NET-284]** `RelaySession_pk` of a circuit MUST be the `er` field of the
  `HopReply` of its last hop. **[NET-285]** That hop MUST keep the private half
  of `er` as `RelaySession_sk` until the circuit ends, and it MUST erase it
  then. Part 5 rule `CRY-136` keeps the `er_sk` of a pairwise handshake in the
  same manner. **[NET-286]** Each other hop MUST erase the private half of its
  `er` at the end of the handshake, under `CRY-059`.
- **[NET-287]** For the rules `NET-122` and `NET-123`, and for each rule of
  Part 6 that names the transport session of a command, the session of a
  command that arrives over a circuit is that circuit.
- **[NET-288]** A client MUST reject an `IDS` whose `relay_session_pk` differs
  from the `er` of the circuit that carried it.

> *Cause.* An earlier draft gave `RelaySession_pk` to a recipient in the `IDS`
> of Part 6 §6.4, and it gave it to no other party. A sender holds a
> `QueueAddress` and no `IDS`, and a recipient in a later session holds the key
> of an earlier one. Thus no sender could compute `auth`. The flight-2
> ephemeral is fresh for each circuit, both ends hold it, and the client
> verified it inside the handshake transcript. It adds no byte to the wire.

**[NET-121]** A relay MUST reject a command whose `auth` does not verify.
**[NET-122]** A relay MUST reject a command whose `corr_id` that relay accepted
before in the same transport session. **[NET-123]** A relay MUST NOT retain a
`corr_id` after that session ends.

> *Cause.* `cmd` and `queue_id` are inside the authorized bytes, thus a party
> cannot move an authenticator from one command to another command, or from one
> queue to another queue. `corr_id` is unique for each command, thus the
> rejection of a repeated value stops a replay inside one session. The session
> scope bounds the state that a relay holds, and NET-123 keeps that state out of
> the compellable set of Part 16 §16.1.

A relay verifies the authenticator when it computes the shared secret again. The
authenticator is symmetric, and a shared secret keys it. Thus **the logs of a
seized relay contain no cryptographic proof that a given device wrote a given
command.**

**[NET-015]** Implementations MUST NOT use a digital signature for a queue command. Signatures
are for objects that a third party with no earlier relation has to verify. These
objects are relay descriptors, directory documents, and community roster
operations (Part 12).

### 3.2.4 Queue lifecycle and parameters

| Parameter | Value | Note |
| --- | --- | --- |
| `QUEUE_QUOTA` | 256 messages | **[NET-016]** The relay MUST reject more than this number. **[NET-017]** The relay MUST signal the quota |
| `MSG_TTL` | **45 days** | Undelivered messages expire. The 14 days of Session is too short, because a restore then recovers almost nothing. The floor is 21 days. 45 days is the same as the media window of Signal, and U6 needs it. Stored ciphertext is not compellable identity data, thus the retention cost is storage and not exposure. |
| `STORE_TIME_GRAIN` | 3 600 s | The unit of each time in the store of a relay (`NET-301`) |
| `QUEUE_IDLE_TTL` | 60 days | The relay deletes a queue with no activity. **[NET-195]** A relay MUST count an accepted `SEND` and a `SUB` on a queue as activity. **[NET-196]** A relay MUST NOT count a `COVER` as activity |
| `ROTATE_AFTER` | 90 days **or** 10 000 messages | The first limit to occur applies |
| `ROTATE_JITTER` | ±20 % | **[NET-018]** A client MUST NOT synchronize the rotation across queues |
| `ACK_HOLE_TIMEOUT` | 24 h | Part 6 §6.4.3 rule 7 bounds a hole in the sequence. **[NET-102]** After that period a recipient MAY acknowledge above the hole. **[NET-103]** That recipient MUST show a delivery gap |

Queue rotation makes a fresh queue on the relay of a **different operator** and
moves the channel. **[NET-019]** A client MUST use independent jitter for each queue rotation.
A client that rotates all its queues at the same time gives the relay a signal
for collection.

**[NET-020]** At the end of a rotation, a client MUST send `DEL` to the old relay. Part 6
§6.4.3 gives the teardown rules and the delay rules for that command. **[NET-021]** A client
MUST NOT send `DEL` at a device revocation.

> **Reliability requirement (U6).** SimpleX has a documented failure. A stale
> backup and a rotated address break a conversation silently and permanently. In
> UMBRA this behavior is a conformance bug. Refer to Part 7 §7.6 for the
> mandatory rotation-safe backup rule.

**The store of a queue relay.** A client names a contact by the identifiers
of two queues, and those identifiers exist at one relay each. A relay that
loses its queues at a restart ends each contact that it served, and no action
of a client brings one back. Thus the queues of a relay outlive its process.

- **[NET-298]** A queue relay MUST commit a change to durable storage before
  it sends the answer of the command that made the change. The `IDS` follows
  the commit of the queue, the `QUOTA` follows the commit of the record, and
  the `ILINK` and the `IBLOB` of Part 6 §6.4 follow the commit of the
  invitation. A `QUOTA` for a record that the store does not hold is a false
  acknowledgment under Part 6 rule `WIR-496`.
- **[NET-299]** A relay MUST commit the changes of one command as a whole or
  not at all. A relay whose store takes no commit MUST stop, and it MUST NOT
  answer the command.
- **[NET-300]** The store MUST hold, for each queue: the two identifiers, the
  two authorization keys with a lock key of Part 4 §4.3.1 in the place of
  `QS_auth`, the next sequence number, the last `ACK`, the notifier
  credential, the time of the last activity, and each record that no `ACK`
  covers. It MUST hold each invitation with its blob. It MUST NOT hold a
  circuit, a session, a subscription, an address of a client, or a link
  between two queues. Each of those ends with its process, and §3.11 gives a
  queue relay none of the last two.
- **[NET-301]** A relay MUST write each time to its store as a multiple of
  `STORE_TIME_GRAIN`, which is 3 600 s. The lifetimes that read those times
  are 14 days and more. A seized file then gives no arrival time to the
  second, and a live relay learns that time in each design.
- **[NET-302]** A relay MUST erase from its storage a record that an `ACK`
  covers, a record past `MSG_TTL`, a queue after its `DEL` or its idle
  lifetime, and an invitation after its first fetch or its lifetime. The
  erased bytes MUST NOT stay in the file, in a journal, or in a log of the
  storage engine. Part 6 rules `WIR-039` to `WIR-042` state that duty for the
  `DEL`, and this rule gives it to each other case.
- **[NET-303]** At its start a relay MUST drop a stored queue whose form does
  not parse, whose record sits at or below its last `ACK`, or whose record
  sits at or above its next sequence number. It MUST serve each other queue.

> *Cause.* An earlier draft gave a relay no storage rule, and the reference
> relay held each queue in RAM. The reference client stores its ratchets
> since 0.2.0-draft, thus a restart of a client cost nothing and a restart of
> a relay cost each contact. `NET-302` repeats the erase duty for the
> storage engine, because a deleted row of a database stays in its free pages
> and in its write-ahead log until the engine overwrites them. The reference
> relay runs SQLite under `secure_delete`, and it truncates the log after
> each commit that deletes.

### 3.2.5 Transport isolation

**[NET-022]** A client MUST NOT multiplex more than `MAX_QUEUES_PER_SESSION = 8` queues onto
one transport session to one relay. **[NET-023]** A client MUST divide its queues across
independent sessions over independent relay chains. **[NET-024]** A client MUST do this
division again at each rotation.

**[NET-295]** A client MUST count a queue toward that bound from its `NEW` or
its `SUB`, because a relay binds the queue to the session at those two
commands. A `SEND` binds no queue. **[NET-296]** A client that holds no
session with room MUST build one more circuit, and the `NEW` MUST wait for
that circuit. **[NET-297]** A client SHOULD put the `SEND` to a contact on a
circuit that does not serve the inbound queue of that contact. Thus one
session shows a relay one queue of the pair, and not the two.

**The chains of one client.** A queue lives at one relay of layer 3, and a
command for that queue reaches it through a circuit that ends at that relay.

- **[NET-308]** A client MUST put each command for a queue on a circuit whose
  last relay holds that queue: the `NEW`, the `SUB`, and the `ACK` of its own
  queue, and the `SEND` to the queue of a peer. A queue that a `NEW` makes
  lives at the last relay of the circuit that carried the `NEW`. **[NET-309]**
  A client that holds no such circuit MUST build one, and the command MUST
  wait for it. A handshake flight and a record of the user wait in the same
  manner. A `SEND` is signed for the session of one circuit, thus a client
  seals a record when it makes it and signs it when the circuit is ready.
- **[NET-310]** A client MUST give the candidates of §3.4.6 to the selection
  in a random order, and a relay that no other circuit of that client uses
  MUST come before a relay that one uses. Thus two circuits of one client
  share no relay but the pinned ingress where the relay set permits it, and
  that is the independence that `NET-023` asks for. **[NET-311]** A client MUST
  build each chain again at the start of a run, and it MUST NOT store a
  chain: the store names the relay of a queue, and no relay of a path to it.

The reference client of 0.2.0-draft takes its relay set from a descriptor of
its build and not from the signed directory of Part 10. Thus it meets
`NET-022`, `NET-023`, and the invariants of §3.4.6 over that set, and it does
not verify the set.

That descriptor is a text of lines. The first line is `umbra-network 2`. Each
relay has one line, and the last line names the host of the invitation links.

```
relay <host> <ipv4> <port> <static key, hex> <relay_id, hex> layer=<1..3>
      operator=<name> country=<two capital letters> asn=<number> [prefix=<a.b>]
invite <host>
```

The facts of a relay line are the inputs of the selection of §3.4.6. The
`prefix` is the `/16` of the relay, and a line with no `prefix` takes the
first two bytes of its address.

- **[NET-312]** A client MUST reject a descriptor that has a relay line with
  no `layer`, no `operator`, no `country` or no `asn`, with one fact two
  times, or with a word that is no fact. It MUST reject a descriptor that
  holds no relay of one of the three layers. A fact that is absent must not
  become a default, because a default would let two relays of one operator
  look like two operators.
- **[NET-313]** A client MUST take the first relay of layer 1 as its pinned
  ingress of `NET-022`. It dials no other relay.
- **[NET-314]** A client MUST read a descriptor with the first line
  `umbra-network 1`. That version holds three relay lines with no facts, and
  the lines are the layers 1, 2 and 3 in their order. Such a set holds one
  chain. The client gives each of its lines an operator, a bloc and a
  network of its own, thus that chain satisfies §3.4.6. A client MUST reject
  a descriptor of that version with a count of relay lines that is not
  three, and it MUST reject each other first line.

> *Rationale.* This leak is the largest unfixed leak in the system that UMBRA
> inherits. The overview of SimpleX states that a malicious router "records all
> queues ... sent via the same transport connection to gain a partial knowledge
> of the user's communications graph." Connection management alone corrects the
> leak, and no cryptography is necessary. Thus the rule is **mandatory in UMBRA
> v1**, and it is not a developer-tools beta.

### 3.2.6 Queue establishment and re-establishment

A queue serves one direction of one pairwise channel. The owner makes the queue
with a `NEW`, and the sender learns it from a `QueueAddress` of Part 6 §6.6.10.
The address travels on four carriers.

| Carrier | The address that it carries |
| --- | --- |
| The invitation bundle of Part 5 §5.4.1 | The first queue of the responder |
| The payload `app_1` of flight 1, Part 5 §5.4.8 | The first queue of the initiator |
| A record of kind `0x33` inside the established ratchet | Each later queue of the owner |
| The dead-channel blob below | The current queue of a party that has no live channel |

| Parameter | Value |
| --- | --- |
| `ROTATE_GRACE` | 7 days. The queue owner measures it from the send of the new address |
| `DEAD_CHANNEL_SILENCE` | 7 days. The sender measures it from the send of a record that holds no delivery receipt |
| `DEAD_CHANNEL_PROBE` | 4 relays for each handle |

**The first two queues.**

1. **[NET-170]** A client MUST send a `NEW` for a queue before it gives the
   `QueueAddress` of that queue to a party. **[NET-171]** A client MUST fill
   `relay_id` and `sender_id` from the relay that answered the `IDS`. The
   descriptor of that relay gives `relay_id`, and the `IDS` gives `sender_id`.
2. **[NET-172]** A responder MUST put the `QueueAddress` of its first queue in
   the invitation bundle of Part 5 §5.4.1. **[NET-173]** An initiator MUST put
   the `QueueAddress` of its first queue in `app_1` of flight 1.
3. **[NET-174]** A responder MUST send flight 2 to the queue that `app_1`
   names. **[NET-175]** A responder MUST NOT store that queue as the outbound
   queue of the contact before flight 3 verifies. A replayed flight 1 fails at
   Part 5 rule `CRY-055`, thus a responder sends flight 2 to a replayed address
   at most one time.

**The first ratchet record.** Part 5 §5.5.1 makes the flight-2 ephemeral of
the responder its first ratchet key, and the initiator takes a ratchet step
against it at the start of the session. Thus the initiator holds a sending
chain at once. The responder holds none before a record of the initiator
gives it the ratchet key of the initiator.

- **[NET-292]** After flight 3, an initiator MUST send a record of kind `0x33`
  as its first ratchet record, with the `QueueAddress` that `app_1` carried.
  The record opens the sending chain of the responder, and it gives that
  address again under the complete session.
- **[NET-293]** A responder MUST hold a record of its user that comes before
  that first record, and it MUST send it when the chain opens. It MUST NOT
  show that record as failed.
- **[NET-294]** A client MUST NOT show a record of kind `0x33` in a
  conversation.

> *Cause.* An earlier draft gave the responder no way to write first. The user
> that made the invitation is the responder, and that user often writes first.
> A reference client showed such a record as failed. A ratchet key of the
> initiator inside the handshake would open the two chains at once, and it
> would change the key schedule of Part 5 §5.4.8. One record of a kind that
> Part 6 holds already costs one `B0` cell and changes no schedule.

**A rotation.** §3.2.4 gives the schedule.

4. **[NET-176]** At a rotation, the queue owner MUST send the new
   `QueueAddress` to the contact as a record of kind `0x33`. The record travels
   on the established ratchet with that contact. **[NET-177]** The owner MUST hold the old queue until a record
   arrives on the new queue, or until `ROTATE_GRACE` ends. **[NET-178]** The
   owner MUST then send the `DEL` of `NET-020`.
5. **[NET-179]** A sender MUST use the newest `QueueAddress` that it accepted
   for a contact for each later `SEND` to that contact. Part 7 §7.5.3 gives the
   order of two records, which is the sender-chain position.
6. **[NET-180]** If one operation rotates queues of more than one contact, the
   client MUST draw an independent delay for each.
   **[NET-181]** A client MUST draw that delay from an exponential distribution
   with a mean of `SWEEP_SPREAD`. Part 7 §7.5.6 gives that parameter, and Part
   4 rule `IDN-063` uses the same rule for a key-change notice. A revocation of
   Part 7 §7.7 and a restore under `DEV-135` are two such operations.

**A dead channel.** A channel to a contact is **dead** for a client when one of
two conditions holds. The first condition is a `NACK` with reason `REJECTED`
(Part 6 §6.4.4) for a `SEND` under the newest address of that contact. The
second condition is a stale queue state at a restore, under Part 7 rule
`DEV-135`. A channel is **silent** when a record that the client sent holds no
delivery receipt `DEAD_CHANNEL_SILENCE` after the send. Part 3 §3.5.4 rule
`NET-041` makes a delivery receipt mandatory. Thus a silent channel shows a
peer that is offline, or a peer that cannot read the queue.

The two parties hold the pairwise identities of Part 4 §4.2.2, and a restore
keeps them. Each party derives one secret from the two X25519 keys. From that
secret, it derives the handle, the read key, and the content key of a
**dead-channel blob**. The blob is one handle-addressed chunk of Part 13
§13.4.2, and it holds the `QueueAddress` of the current queue of the writer.

```
ss_pair       = X25519( own_pairwise_x25519_sk, peer_pairwise_x25519_pk )
week          = floor( consensus_epoch / 168 )
prk           = HKDF-SHA3-256-Extract( salt = "umbra/v1/dead-channel", ikm = ss_pair )
handle(P, w)  = HKDF-Expand( prk, 0x01 || BE32(w) || P_pairwise_x25519_pk, 32 )
read_sk(P, w) = HKDF-Expand( prk, 0x02 || BE32(w) || P_pairwise_x25519_pk, 32 )
blob_key(P,w) = HKDF-Expand( prk, 0x03 || BE32(w) || P_pairwise_x25519_pk, 32 )

DeadChannelBlob {                 // the sealed object, before the padding of
                                  // Part 13 rule ATT-147
    version       u8              // 0x01
    nonce         [24]u8          // from the device CSPRNG
    sealed        [145]u8         // XChaCha20-Poly1305( blob_key, nonce, QueueAddress )
}
```

The party `P` is the writer. Thus each party writes under a handle of its own,
and it reads under the handle of the peer. Part 5 §5.11 holds the label
`"umbra/v1/dead-channel"`. `consensus_epoch` is the `epoch` field of the most
recent `DirectoryRoot` of Part 10 §10.5.2 that the client accepted, and 168
such epochs make one week. **[NET-203]** A client MUST compute `week` from the
most recent `DirectoryRoot` that it accepted. The device clock does not enter
the derivation.

7. **[NET-182]** A client whose channel to a contact is dead MUST make a new
   queue for that contact. **[NET-183]** That client MUST write a
   `DeadChannelBlob` with the `QueueAddress` of that queue under
   `handle(own, week)` and `read_sk(own, week)`. Part 13 §13.4.2 gives the
   chunk, and `read_pk` is the public key of that `read_sk`. **[NET-184]**
   That client MUST write the blob again under the handle of each new week
   while the channel stays dead. **[NET-185]** That client MUST send a `CDEL`
   for the blob of the earlier week when it writes the new one.
8. **[NET-186]** If a channel is dead or silent, the client MUST fetch
   `handle(peer, week)` and `handle(peer, week - 1)`. The `peer` is the contact
   of that channel. The fetch of a week `w` uses `read_sk(peer, w)` under Part
   13 §13.4.2.
   **[NET-187]** A client MUST repeat that fetch one time in each week while
   the condition holds. **[NET-188]** A client MUST draw the time of each
   fetch from a uniform distribution over 24 hours. The 24 hours start at the
   start of the condition, or at the start of the week. **[NET-189]** A client MUST NOT fetch a
   dead-channel handle of a contact whose channel is neither dead nor silent.
9. **[NET-190]** A client that opens a `DeadChannelBlob` of a peer MUST take
   its `QueueAddress` as the newest address of that peer. **[NET-191]** That
   client MUST then send its own current `QueueAddress` as a record of kind
   `0x33` on that channel. **[NET-192]** A client MUST treat a
   `DeadChannelBlob` whose `sealed` field does not open under `blob_key` as an
   empty handle.
10. **[NET-193]** After a client accepts a `QueueAddress` of a contact, it MUST
    send again each record that holds no delivery receipt. §3.7 gives the
    schedule of a retransmission.
11. **[NET-194]** A client MUST NOT write a `DeadChannelBlob` for a contact
    that the user blocked under Part 14 §14.12. **[NET-197]** A client MUST
    NOT fetch the dead-channel handle of a blocked contact.

> *Cause.* `QUEUE_IDLE_TTL` is 60 days, thus two contacts that lapse for two
> months hold valid pairwise identities, a valid backup, and no reachable
> queue. §3.2.4 calls that failure a conformance bug, and no earlier section
> supplied the mechanism against it. A handle from the two pairwise keys needs
> no third party, no directory entry, and no new invitation. The secret
> `ss_pair` is classical, and Part 16 §16.3 records the quantum residual. A
> full identity reset of Part 7 §7.7.1 replaces the pairwise keys. Thus an
> attacker that holds a seized device loses the handle at that reset. A
> restore of a backup from before such a reset restores the old keys, and that
> pair recovers no channel. The user abandoned that identity on purpose.
>
> A fetch of a missing chunk costs one `B0` command and one `B0` `NACK`. Thus
> the weekly fetch of `NET-187` costs about 1.1 KB for each silent contact.
> Rule `NET-189` keeps the fetch off a live contact, thus a relay sees a
> dead-channel handle only when a pair has lost its channel.

### 3.2.7 Group queues

A **group queue** is a relay-held, retained, many-reader mailbox. It is a queue
kind beside the pairwise queue of §3.2.1 to §3.2.6, and one group of Part 11
holds one group queue on each of two relays. A member uploads one record for
each message, and each reader fetches that record. No relay receives a
recipient list. **[NET-223]** A relay that serves queues MUST serve group
queues. No new relay role exists, and the role table of §3.1 gives what such a
relay sees. Part 6 §6.4.5 gives the commands of a group queue, Part 6 §6.4.6
gives the record, and Part 11 gives the member-side rules.

**Identifiers and credentials.**

```
GroupQueueId        [32]u8   made by the relay from its CSPRNG at a GNEW
read_pk / read_sk   X25519   the reader credential, one pair for each group epoch
write_pk / write_sk X25519   the writer credential, one pair for each group epoch
own_pk / own_sk     X25519   the owner credential, made by the creator from its
                             CSPRNG, held by each member of role admin or above
```

**[NET-224]** A relay MUST make `GroupQueueId` from its CSPRNG at a `GNEW`.
**[NET-225]** A party MUST NOT be able to derive `GroupQueueId` from a key or
from an earlier queue. **[NET-226]** A relay MUST hold, for a group queue,
`GroupQueueId`, the three public keys, the previous `read_pk` and `write_pk`
under the grace below, the records, and the notifier set of Part 8 §8.5.2.
**[NET-227]** A relay MUST NOT hold per-reader state of a group queue other than
the live sessions and the notifiers. **[NET-228]** A relay MUST NOT hold a list
of the members of a group queue, and no command of Part 6 §6.4.5 carries a
member identifier.

**[NET-229]** A party MUST authorize a group-queue command with the
authenticator of §3.2.3, with `read_sk`, `write_sk`, or `own_sk` in the place
of `Q*_auth_sk` and with `GroupQueueId` in `queue_id`. Part 6 §6.4.5 gives the
key of each command. `NET-015` holds, thus no group-queue command carries a
signature.

**The credential exception.** **[NET-230]** A member MUST derive `read_sk` and
`write_sk` of a group queue from the group epoch secret `K_e` under Part 11
§11.3.1. That derivation is the one exception to `NET-009` to `NET-014`.
**[NET-231]** A creator MUST make `own_sk` from the device CSPRNG, and a party
MUST NOT derive it.

> *Cause.* `NET-009` to `NET-014` exist against a seized relay that collects
> the queues of one user by repeated key material. The writer set and the
> reader set of a group queue are the membership, and the membership holds
> `K_e` by definition. A credential that each member derives from `K_e`
> repeats no material of any one user, and it rotates with the epoch. A
> credential from the device CSPRNG would need a distribution to each member
> at each rotation, which the epoch-key record of Part 11 §11.4.2 already
> carries for `K_e`.

**The sequence.** **[NET-232]** A relay MUST assign `seq` for each group queue
as a `u32` that starts at 1, that increases strictly, and that it never
reissues. `seq` is relay-local, thus the two replicas of one group give two
unrelated sequences. **[NET-233]** A client MUST NOT use `seq` as a message
identifier or as an order across replicas. Part 11 §11.7 gives the order of a
group.

**No reader acknowledgment.** **[NET-234]** A relay MUST retain a record of a
group queue by time and by quota only, under the table below. **[NET-235]** A
relay MUST NOT erase a record because a reader read it. **[NET-236]** A reader
MUST hold its own cursor for each replica, as mutable state of Part 7 §7.5.3,
for each device. **[NET-237]** If a `GSUB` names a backlog above
`DRAIN_THRESHOLD` of §3.5.2, the relay MUST answer it in one unpaced response,
as `NET-037` gives for a pairwise queue.

**The acknowledgment of a post.** **[NET-238]** A relay MUST answer an accepted
`GPOST` with a `GSEQ`. §3.7 makes that `GSEQ` the relay acknowledgment of the
ARQ. **[NET-239]** If a `GPOST` carries record bytes that the relay already
holds, the relay MUST answer with the `seq` that it holds for those bytes.
**[NET-240]** A relay MUST apply `GROUP_POST_RATE` for each group queue.
**[NET-241]** A relay MUST answer a `GPOST` above that rate with a `NACK` of
reason `LIMIT` (Part 6 §6.4.4). A `GNEW` carries an `Admission` of Part 14
§14.2, and a `GPOST` carries none.

**The rotation of the credentials.** **[NET-242]** After a `GKEY`, a relay
MUST keep the previous `read_pk` for `GROUP_READ_GRACE` and the previous
`write_pk` for `GROUP_WRITE_GRACE`. **[NET-243]** Inside that grace, a relay
MUST accept a `GSUB`, a `GUNSUB`, a `GNREG`, or a `GNUNREG` under either read
key, and a `GPOST` under either write key. **[NET-244]** At a `GDEL`, a relay
MUST erase the group queue, each record, and each notifier. **[NET-245]** A
relay MUST NOT retain an identifier of a deleted group queue.

**Retention and quota.**

| Parameter | Value | Note |
| --- | --- | --- |
| `GROUP_RETENTION` | 30 days from acceptance | **[NET-246]** A relay MUST erase a record `GROUP_RETENTION` after its acceptance. The value equals `GROUP_SILENT_EVICT` of Part 11 §11.10: a member silent for 30 days is evicted, thus no member needs a record older than the retention |
| `GROUP_QUEUE_QUOTA` | 32 MiB of records for each group queue | **[NET-247]** If the records of a group queue exceed this quota, the relay MUST erase the oldest record first. **[NET-248]** A relay MUST NOT erase a record below `GROUP_RETENTION` for a cause other than this quota or a `GDEL` |
| `GROUP_POST_RATE` | 60 records in each 60 s for each group queue, relay-local | `NET-240` and `NET-241` apply it |
| `GROUP_READ_GRACE` | 30 days | `NET-242` keeps the previous `read_pk` for this period |
| `GROUP_WRITE_GRACE` | 24 h | `NET-242` keeps the previous `write_pk` for this period |
| `GROUP_IDLE_TTL` | 60 days without an accepted `GPOST` or a `GSUB` | **[NET-249]** A relay MUST delete a group queue with no activity for this period. **[NET-250]** A relay MUST count an accepted `GPOST` and a `GSUB` as activity. **[NET-251]** A relay MUST NOT count a `COVER` as activity |
| `GROUP_NOTIFIER_MAX` | 4 096 notifiers for each group queue | **[NET-252]** A relay MUST reject a `GNREG` that would exceed this count. Part 8 §8.5.2 gives the notifier |

A member that was offline for longer than `GROUP_RETENTION` has missed records,
and Part 11 §11.8 makes the client show that gap.

**Replicas.** Part 11 §11.10 sets `GROUP_REPLICAS` to 2.

- **[NET-253]** A creator MUST make one group queue on each of `GROUP_REPLICAS`
  relays. **[NET-254]** The entries of those relays MUST carry different
  `operator_id` values and different jurisdiction blocs, under invariant 1 and
  invariant 2 of §3.4.6. Part 10 §10.5.3 gives `operator_id`, and Part 10
  §10.6.3 gives the bloc list. **[NET-255]** A creator MUST NOT apply the
  relaxation of `NET-200` to the two replicas.
- **[NET-256]** A sender MUST send the same record bytes to each replica, each
  under the ARQ of §3.7. **[NET-257]** A client MUST put a record in the
  `accepted` state of Part 15 §15.9.1 when the first replica returns a `GSEQ`.
  **[NET-258]** The client MUST continue the ARQ to the other replica in the
  background. **[NET-259]** If the ARQ to one replica ends under `NET-220` after
  the other replica accepted, the client MUST report that replica as a link
  fault under Part 10 §10.4.2.
- **[NET-260]** A reader MUST subscribe to one replica in each session, and it
  MUST select that replica at random. **[NET-261]** A reader MUST alternate
  replicas across sessions. **[NET-262]** If a reader observes a gap in the
  `counter` of one sender for longer than `GROUP_GAP_TIMEOUT` of Part 11
  §11.10, it MUST open a session to the other replica and fetch from its cursor
  there. Part 11 §11.2.2 gives the gap repair, and a duplicate across replicas
  falls to the `msg_id` rule of Part 6 §6.6 (`WIR-065`).

**Transport isolation.** The rules below are the analog of `NET-022` and
`NET-023` for a group-queue session.

- **[NET-263]** A client MUST NOT carry more than one group queue on one
  transport session. **[NET-264]** A client MUST NOT carry a command of a range
  other than Part 6 §6.4.5 on a session that carries a group-queue command.
  **[NET-265]** A client MAY send a `COVER` of Part 6 §6.3 on a group-queue
  session. **[NET-266]** A client MUST put each group-queue session on its own
  relay chain, under the invariants of §3.4.6.
- **[NET-267]** For each cell of a group-queue session, a client MUST treat the
  group-queue relay as the queue relay of `NET-124`. Thus hop 3 of that chain
  is the group-queue relay, and the innermost layer ends there.

> *Cause.* `NET-022` and `NET-023` exist because a relay that sees two queues
> on one session learns that they belong to one client. A group-queue relay
> that sees a group queue and a pairwise queue on one session learns that one
> member of the group holds that pairwise queue, which §3.11 does not permit
> it to learn. One group queue for each session keeps the two apart, and the
> two replicas of one group sit on two chains for the same cause.

> *Cause of the group queue.* An earlier draft gave a group of up to 500
> members a pairwise fan-out, thus a member of six 25-member groups held 144
> inbound group queues over 18 sessions, and one text to a 500-member group
> cost 499 `B1` cells of uplink. The ingress relay then read the recipient
> count of a group from the size of the burst. This draft gives the group one
> relay-held record for each message. The group-queue relay reads the member
> count from the slot count of an epoch-key record in the place of that burst,
> and §3.11 states that trade. The transport session count of the model user
> of §3.12 falls from 20 to 9.

## 3.3 The cell — fixed-size units on the wire

Each unit that a relay can see is a **cell**. UMBRA pads a cell to one of four
sizes:

| Bucket | Size | Carries |
| --- | --- | --- |
| `B0` | 512 B | Text up to 155 B, receipts, control, ratchet headers, cover, loops |
| `B1` | 2 KiB | Text above 155 B, PQ ratchet chunks, handshake flights, small media metadata, group records of a group up to about 120 members (Part 11 §11.3.3) |
| `B2` | 8 KiB | Thumbnails, link previews, small attachments, group records of a group above about 120 members |
| `B3` | 32 KiB | Attachment chunks (the only attachment size), inline epoch-key records (Part 11 §11.4.2) |

Part 6 §6.9 gives bucket `B0` a text capacity of 155 bytes. A text above that
capacity needs bucket `B1`. §3.3.1 and §3.12 put the modal text of about 350
bytes in bucket `B1`.

UMBRA applies the padding **after the onion encryption**, thus each relay hop
sees only these four sizes. **[NET-025]** Implementations MUST also pad at the
transport-record layer (§3.8). If they do not, the TLS record sizes show the
length directly.

### 3.3.1 Why not one uniform 16 KiB block

SimpleX uses one block of 16 384 bytes. UMBRA does not use one block, and there
are three measured causes:

1. **Padding overhead.** Use a realistic mix of message sizes. The mix is 80 %
   text at about 350 B and 5 % PQ-ratchet at about 1 500 B. The mix also has 5 %
   thumbnail at about 6 000 B and 10 % attachment chunk at about 32 000 B. With
   this mix the ladder costs **40.8 %** padding overhead, because a 350 B text
   needs bucket `B1` (Part 6 §6.9). A uniform 16 KiB block costs **368 %**,
   which is a bandwidth penalty of 3.3×. §3.12 shows the arithmetic.
2. **Cover traffic economics.** Cover packets are the largest recurring cost of
   metadata resistance. At 16 KiB each, cover costs 32 times more than
   necessary. PoPETs 2026(2):436–451 quantifies this cost for Nym. Packets of 2
   413 bytes make each cover packet 4.7 times more expensive than a Tor cell of
   514 bytes.
3. **Group posts.** A group record carries one 12-byte tag for each member
   (Part 11 §11.3.3). A text record of a 500-member group is **8 240 B** at
   `B2` with the ladder, against **16 454 B** with a uniform block. A text
   record of a 25-member group carries a 300-byte tag vector, thus it stays in
   `B1` at **2 096 B**, against the same 16 454 B with a uniform block. The
   wire cost of a 16 KiB block is the block and 70 B of framing across two TLS
   records (Part 6 §6.2.1). Each reader of a group downloads each record, thus
   the 120 group receives of the §3.12 day cost 252 KB with the ladder and
   1.97 MB with a uniform block. This difference decides if the group feature
   operates on mobile data.

**[NET-026]** An attachment MUST use chunks of `CHUNK_SIZE` (Part 13 §13.7). That chunk fills
the payload of one command at bucket `B3`. Only the last chunk carries padding.
Thus no party can infer the file size from the chunk sizes (Part 13).

### 3.3.2 A link preview: the sender fetches, and the receiver does not

The `B2` row above names a link preview. This section names the party that
fetches the URL, because that party gives its network address to the site.

- **[NET-142]** A receiver MUST NOT fetch a URL that a record carries.
  **[NET-143]** A client MUST NOT fetch a URL to render a preview.
- **[NET-144]** A sender MAY attach a preview that the sender made. That
  preview travels as an attachment descriptor of Part 6 §6.6, and Part 13 gives
  the transfer.
- **[NET-145]** A sender MUST re-encode a preview image under the rules of Part
  9 §9.3.1, thus the image carries no metadata field.
- **[NET-146]** A client MUST show the URL to the user before the user opens it.
  **[NET-147]** A client MUST open a URL of a scheme other than `umbra` in the
  browser of the platform. A link of the `umbra` scheme of Part 4 §4.3 and of
  Part 12 §12.7 stays in the application. The application is the only handler of
  that scheme.

> *Cause.* An automatic fetch at the receiver gives the linked site the network
> address of that receiver, at the moment the message arrives. A site that a
> sender controls then confirms delivery and reads a rough location, with no
> relay and no cooperation. That is an out-of-band deanonymization of the kind
> that Part 2 §2.5 says UMBRA cannot prevent, and this rule stops the client
> from building it.
>
> The sender already visited the URL, thus a sender-side fetch gives the site no
> address that it does not hold. The cost is that a preview is a statement by
> the sender, and a hostile sender pairs a true URL with a false preview.
> **[NET-148]** Thus a client MUST render the host of the URL beside the
> preview. Part 16 §16.3 records the residual.

## 3.4 Relay chaining

### 3.4.1 Topology

UMBRA uses a **stratified topology**. Each chain uses one relay from layer 1,
one relay from layer 2, and one relay from layer 3.

Layer 1 is the ingress population of Part 10 §10.5.4. That population is the
set of relays whose entry carries the ingress flag of Part 10 §10.5.3. The
directory sets that flag from three verified facts. A public hash over the most
recent accepted consensus root assigns each other chain relay to layer 2 or to
layer 3. Part 10 §10.5.4 gives that function. Each party computes the same
value, and no party predicts the root before the authorities sign it.
**[NET-027]** The operator MUST NOT select the layer (§10.5).

> *Rationale.* Piotrowska (arXiv 2107.12172) shows that a stratified topology
> with continuous mixing is the **only** topology where the anonymity entropy
> *increases* with the user base. The cause is forced route intersection, which
> puts each packet into one anonymity set. Free-route topologies and P2P meshes
> need client-generated cover ratios of 5:1 to 10:1 to reach a usable entropy. A
> phone cannot pay that cost. An incorrect topology is not correctable later.

### 3.4.2 Hop count is fixed at three

`HOPS = 3` for all traffic, all privacy modes, and all message types. The hop
count is not configurable, it is not negotiable, and the UI does not show it.

> **Deviation note.** An earlier draft gave a 2-hop "Fast" mode. This document
> withdraws that mode. A variable hop count increases the packet size. A
> variable hop count also divides the anonymity set into populations that an
> adversary can tell apart.
>
> Layered packets decrease in size at each hop unless they carry padding. Thus a
> variable hop count tells each relay its own position in the chain.
>
> The privacy modes in §3.9 thus differ only in *the per-hop delay*, and not in
> path length. This decision costs Fast mode about 40–80 ms against a 2-hop
> path, and UMBRA accepts that cost.

### 3.4.3 Session circuits, not per-packet onions

**UMBRA uses long-lived telescoped onion circuits. UMBRA does NOT use a
per-packet onion format such as Sphinx, KEM-Sphinx, or Outfox.**

This decision has the largest consequences in this part, and the arithmetic
gives the answer. A post-quantum per-packet header has to carry **one hybrid KEM
ciphertext for each hop**. This ciphertext is 1 120 B for X25519 with
ML-KEM-768. The table below gives the result:

| Design | Header for each packet |
| --- | --- |
| Classical Sphinx, 3 hops | 1 320 B |
| Outfox / KEM-Sphinx, 3 hops | ~3 400 B (the packet size decreases at each hop, which shows the circuit position) |
| Outfox + Sphinx-style constant padding, 3 hops | **~7 800 B** |
| **UMBRA telescoped circuit, steady state** | **32 B** |

A chat message is about 250 bytes. Against such a message, a per-packet header
of 3.4–7.8 KB is the full cost of the protocol. Such a header also makes the
512-byte `B0` cell of §3.3 arithmetically impossible.

Telescoping divides the KEM cost over the lifetime of the circuit. A per-packet
format pays the KEM cost for each message.

#### Circuit build

The circuit uses a 3-hop telescoped hybrid handshake, one hop at a time. Each
hop runs `UMBRA-NKhfs` (Part 5 §5.4.9). The client has no static key, thus the
identity-hiding grade is `-` for the initiator and 3 for the responder. Part 5
§5.4.9 gives flight 1 as 1 232 bytes and flight 2 as 1 136 bytes, which is
2 368 bytes for one hop. The total build is 3 × 2 368 = **7 104 bytes** of
handshake material and three round trips. The client pays this cost one time
for each circuit, and not one time for each message. On the wire the six build
cells of NET-150 and NET-151 cost 6 × 2 096 = 12 576 bytes, and §3.12 counts
that figure.

**The two build cells.** Flight 1 travels in an `EXTEND` cell, and flight 2
travels in an `EXTENDED` cell. Part 6 §6.3 gives the two command bytes, and
Part 1 §1.8 lists the two payloads. The payloads follow the command byte.

```
HopHello {                        // the EXTEND payload, 1 264 bytes
    relay_id        [32]u8        // the relay_id of the hop that answers
    e               [32]u8        // flight 1 of Part 5 §5.4.9
    e1              [1184]u8
    tag1            [16]u8
}

HopReply {                        // the EXTENDED payload, 1 136 bytes
    er              [32]u8        // flight 2 of Part 5 §5.4.9
    ekem1           [1088]u8
    tag2            [16]u8
}
```

With the command byte the two bodies are 1 265 bytes and 1 137 bytes. Each one
fits the `B1` command area of 2 014 bytes (Part 6 §6.9), and each one exceeds
the `B0` command area. Thus a build costs six `B1` cells.

**The build of one hop.** A build cell to hop *n* travels under the layers of
hops 1 to *n* − 1, and under no other layer. Thus the `HopHello` to hop 1
travels with a `tag` of 16 zero bytes and a plaintext body. The relay before
hop *n* moves the cell onto a new circuit of its link to hop *n*, and it moves
the answer back. A relay whose circuit has no next hop is the endpoint of each
forward cell on that circuit. §3.4.4 rule `NET-114` gives it the check.

1. **[NET-150]** A client MUST send each `EXTEND` cell in bucket `B1`.
   **[NET-151]** A relay MUST send each `EXTENDED` cell in bucket `B1`.
2. **[NET-152]** A client MUST set `relay_id` to the `relay_id` of the
   descriptor that gave `s` for that hop. **[NET-153]** A relay MUST drop an
   `EXTEND` cell whose `relay_id` differs from its own `relay_id`.
3. **[NET-154]** A party that opens a circuit on a link MUST draw `circ_id`
   from its CSPRNG. **[NET-155]** That party MUST NOT use a value that a live
   circuit of that link holds.
4. **[NET-156]** A relay MUST treat a cell that arrives on a `circ_id` that it
   does not hold as a build cell. **[NET-157]** A relay MUST drop a build cell
   whose command byte is not `EXTEND`. **[NET-158]** A relay MUST drop a build
   cell whose `tag` is not 16 zero bytes.
5. **[NET-159]** A relay that accepts an `EXTEND` cell on a new `circ_id` MUST
   run the responder side of Part 5 §5.4.9. **[NET-160]** That relay MUST
   answer with an `EXTENDED` cell on that `circ_id`, with a `tag` of 16 zero
   bytes. **[NET-161]** That relay MUST hold the circuit from that answer on.
6. **[NET-162]** A relay that recovers an `EXTEND` cell on a held circuit MUST
   send the body to the relay of `relay_id`. **[NET-163]** That relay MUST
   send the body on a new circuit of its link to that relay. **[NET-198]**
   Before it sends the body, that relay MUST bind the new circuit to the held
   circuit as its next hop.
7. **[NET-164]** A relay that receives an `EXTENDED` cell on a circuit of
   `NET-198` MUST send that body on the held circuit. **[NET-199]** That relay
   MUST send that body under its backward layer, with `X_L` of 16 zero bytes.
   §3.4.4 gives the backward direction.
   - **[NET-289]** A relay of layer 1 or 2 whose circuit holds no next hop is
     the endpoint of a forward cell, and it makes the check of `NET-114`. It
     MUST NOT run the key update of `NET-205` and `NET-206`, because that
     update belongs to the hop 3 layer. The client runs no update on a build
     cell for the same cause.
   - **[NET-290]** A relay reaches a relay of the next layer as a client of
     the session of Part 6 §6.2.3. It MAY hold one session for each such
     relay and put each circuit on it. It holds no resend window there: a
     lost link ends its circuits, and each client builds again.
8. **[NET-165]** A relay MUST drop an `EXTEND` cell at the endpoint of a
   circuit that holds a next hop already. **[NET-166]** A relay in layer 3 MUST
   drop an `EXTEND` cell at the endpoint of a circuit. **[NET-167]** A relay
   MUST drop an `EXTEND` cell whose `relay_id` names a relay outside the layer
   after its own. §3.4.1 gives the layers, and §3.4.2 fixes the hop count.
9. **[NET-168]** Before the `EXTENDED` cell of hop 3 arrives, a client MUST
   NOT send a cell other than `EXTEND` or `DESTROY`. The rule applies to the
   circuit under build, and not to another circuit of the client.
10. **[NET-169]** If no `EXTENDED` cell arrives in `CIRCUIT_BUILD_TIMEOUT`, the
    client MUST send a `DESTROY` cell and discard the circuit.

> *Cause.* In each design, a relay learns that it is a hop of a new circuit.
> Thus the build cell hides nothing from it that steady state would hide. Rule
> `NET-153` binds the handshake to the relay that the client selected. Thus a
> relay on the path cannot answer in the place of the next hop. Rules `NET-165`
> to `NET-167` make each relay enforce the three-hop stratified path that the
> client selects. A replayed `EXTEND` cell opens a circuit under a fresh `er`,
> thus the replay yields no key. Part 14 bounds the cost of such a cell.

#### Steady-state cell

The cell is the same at each hop:

```
Cell {
    circ_id     16 B     // rewritten by each hop; unlinkable across hops
    tag         16 B     // rugged-PRP authentication tag, see 3.4.4
    body         L B     // L in {480, 2016, 8160, 32736} → cell = 512 / 2048 / 8192 / 32768
}
```

The onion overhead is **32 bytes for each cell**. The overhead is constant, and
the size does not change at a hop. Thus the path length and the circuit position
show nothing. The dilemma between constant padding and efficiency that Outfox
causes does not occur.

#### Circuit lifetime

| Parameter | Value |
| --- | --- |
| `CIRCUIT_MAX_AGE` | 4 hours. The client measures it from the moment that it sends the first `EXTEND` cell |
| `CIRCUIT_MAX_CELLS` | 8 192 |
| `CIRCUIT_BUILD_TIMEOUT` | 5 s from the first `EXTEND` cell. Three round trips over a 200 ms path take about 0.6 s, thus the value has a wide margin |
| Preemptive build | keep 2 spare circuits in the foreground, thus a rotation does not block a send. §3.12 forbids a spare circuit in a push-wake session |

> *Cause of the 4 hours.* An earlier draft set `CIRCUIT_MAX_AGE` to 10 minutes,
> and each push wake then paid a fresh build. §3.12 puts the background
> arrivals at one group-queue relay about 48 minutes apart and at one pairwise
> queue relay about 21 minutes apart, thus a circuit of 4 hours serves almost
> all of them. Part 6 §6.2.3 sets `SESSION_RESUME_WINDOW` to the same
> 4 hours, because a circuit does not outlive its session. The cost is a longer
> window for a seized hop 1 or hop 2 key set, and Part 16 §16.3 records it.
> Part 2 §2.4 states the trade.

**[NET-028]** A client MUST NOT use one circuit for more than one privacy mode. **[NET-029]** A client MUST
NOT carry interactive traffic and bulk traffic on the same circuit (§3.8).

### 3.4.4 Per-hop layer encryption

**[NET-030]** Per-hop encryption MUST use a **rugged-PRP or wide-block construction**. This
construction is a tweakable, updatable, split-domain cipher in the UIV+ family.
UMBRA instantiates it as AES-256-CTR with POLYVAL. **[NET-031]** Per-hop encryption MUST NOT
use a stream cipher with a separate MAC.

This design follows the Counter Galois Onion of Tor (Degabriele, Melloni, Münch,
Stam, eprint 2025/583). The construction is fully symmetric, thus it needs no post-quantum design. The construction also
gives the non-malleability that defeats tagging attacks. An adversary that
controls the first relay and the last relay uses a tagging attack to confirm a
chain. The earlier construction of Tor was malleable with a 32-bit tag for
thirteen years, and UMBRA does not repeat that error.

The cost is 16 bytes for each cell and 20–50 % more CPU at the intermediate
relays. UMBRA accepts this cost.

**The per-hop key material.** The circuit build of §3.4.3 gives each hop the
shared secret `ss_hop` from the split of Part 5 §5.4.9. **[NET-106]** A client and a relay MUST derive the
hop key material from that secret with one HKDF-SHA3-256 invocation. The
derivation follows.

```
t              <- HKDF-SHA3-256( salt = ss_hop, ikm = "",
                                 info = "umbra/v1/onion-hop" || BE32(hop_index),
                                 L = 208 )
K_prp_fwd      <- t[0..32]      // AES-256, the left block, client to relay
K_str_fwd      <- t[32..64]     // AES-256-CTR, the right part
K_hash_fwd     <- t[64..80]     // POLYVAL
C_fwd          <- t[80..96]     // the chaining value
K_prp_bwd      <- t[96..128]    // relay to client
K_str_bwd      <- t[128..160]
K_hash_bwd     <- t[160..176]
C_bwd          <- t[176..192]
T              <- t[192..208]   // the tweak of the layer, both directions
```

The value `hop_index` is the layer of the relay under §3.4.1, from 1 to 3.
Part 10 §10.5.4 gives each party that value, thus no cell carries it.

**[NET-107]** An implementation MUST use a different key set for each direction,
and it MUST NOT use one key set for the two directions.

**The construction operates on a pair.** One layer takes a 16-byte left block
`X_L` and a right part `X_R` of *L* bytes. It gives a 16-byte left block `Y_L`
and a right part `Y_R` of *L* bytes. The two widths do not change. Each body
length is a whole multiple of 16 bytes, thus no step needs padding.

**[NET-108]** A sender MUST encipher one layer with the steps below, where `T`
is the tweak of the layer and `C` is the chaining value of that direction:

```
S    = AES-256-Enc( K_prp, X_L XOR C XOR T )
Y_R  = X_R XOR AES-256-CTR( K_str, counter = S )
Y_L  = S XOR POLYVAL( K_hash, Y_R )
```

**[NET-113]** A receiver MUST decipher one layer with the inverse steps:

```
S    = Y_L XOR POLYVAL( K_hash, Y_R )
X_R  = Y_R XOR AES-256-CTR( K_str, counter = S )
X_L  = AES-256-Dec( K_prp, S ) XOR C XOR T
```

**[NET-279]** A party MUST take `T` from the derivation of `NET-106`, and it
MUST NOT take `T` from `circ_id`. The key update below keeps `T`.

> *Cause.* An earlier draft made `T` the `circ_id` of the cell. `NET-109`
> makes each hop rewrite that value, and `NET-154` makes the relay before hop
> *n* draw the value on its link to hop *n*. Thus the client never held the
> `circ_id` of the links to hop 2 and hop 3, and it could not compute those
> two layers. A tweak from the hop derivation is a value that both parties of
> the hop hold, and it differs for each hop and each circuit, which is what
> the tweak of the construction of `NET-030` needs.

**The nesting.** The left block carries the tag of the layer below it. Thus the
three layers fit one cell and the width stays constant.

**[NET-124]** For a cell to the queue relay, a client MUST set `X_L` of the
innermost layer to 16 zero bytes. **[NET-125]** A client MUST then apply the
steps of NET-108 for hop 3, for hop 2, and for hop 1, in that order.
**[NET-126]** A client MUST write the `Y_L` of hop 1 into the `tag` field and
the `Y_R` of hop 1 into the `body` field.

**[NET-127]** A relay MUST take `Y_L` from the `tag` field and `Y_R` from the
`body` field. **[NET-128]** A relay MUST write the recovered `X_L` into the
`tag` field and the recovered `X_R` into the `body` field. **[NET-109]** A relay
MUST rewrite `circ_id` at each hop, and §3.4.3 makes that value unlinkable
across hops.

**The check is at the endpoint, and not at each hop.** A relay in the middle
position holds no value against which it can check `X_L`, because that value is
the tag of the layer below and only the client computed it.

**[NET-114]** The party that removes the innermost layer MUST compare `X_L`
against the 16 zero bytes in constant time. **[NET-115]** That party MUST drop
the cell and tear the circuit down when the two values differ. **[NET-129]** A
relay in the middle position MUST NOT check `X_L`. **[NET-130]** A party MUST
NOT act on a recovered payload before the comparison of NET-114 succeeds.

The backward direction is the mirror. The queue relay sets `X_L` to 16 zero
bytes, each hop applies NET-108 with its backward key set, and the client
removes the three layers and makes the comparison of NET-114.

**The update rule.** **[NET-116]** A sender and a receiver MUST set `C` of one
layer to the `Y_L` of that layer, after they process the cell. Thus each cell
chains onto the one before it, and the construction is *updatable* in the UIV+
sense. The client holds one chaining value for each hop and for each direction.
A relay holds one chaining value for each direction.

**The key update at hop 3.** The chaining value moves at each cell, and the
key set does not. A party that holds the key set of a layer and a recorded
cell opens that layer of the cell. At the hop 3 layer the payload sits under
no further layer. Thus that layer replaces its key set after each cell, and the
key that opened a cell no longer exists after the cell.

```
u          <- HKDF-SHA3-256( salt = K_str, ikm = Y_L,
                             info = "umbra/v1/onion-hop-update", L = 96 )
K_prp      <- u[0..32]
K_str      <- u[32..64]
K_hash     <- u[64..80]
C          <- u[80..96]
```

The values `K_str` and `Y_L` are those of the hop 3 layer in the direction of
the cell, before the update. At that layer the value `C` comes from the update,
and not from NET-116.

**[NET-204]** A client MUST run the update on the forward key set of hop 3
after the hop 3 step of NET-125. **[NET-205]** A queue relay MUST
run the update on its forward key set after the comparison of NET-114
succeeds. **[NET-206]** A queue relay MUST run the update on its backward key
set after it enciphers a cell. **[NET-207]** A client MUST run the update on
the backward key set of hop 3 after the comparison of NET-114 succeeds.
**[NET-208]** A party MUST erase the key set that the update replaces.
**[NET-209]** A relay in the middle position MUST NOT run the update.
**[NET-211]** A client MUST NOT run the update on the key set of hop 1 or of
hop 2.

> *Cause.* The paper of `NET-030` runs its update at the destination layer
> only, and a middle layer chains its tweak. A middle layer gives the
> ciphertext of the next layer, and not a payload. Thus a seized key set of hop
> 1 or hop 2 opens no cell beyond what that relay saw in transit. Part 16 §16.1 records what each relay holds. A key update at
> each middle hop costs one HKDF at each relay for each cell, and it buys no
> payload confidentiality. An earlier draft chained the value `C` and
> replaced no key. Under that draft a queue relay that an adversary seized
> after a session opened each recorded cell of the live circuits.
> `CIRCUIT_MAX_AGE` bounds that window at 4 hours only.

**[NET-131]** A party MUST process the cells of one circuit in the order that it
receives them. **[NET-132]** A party MUST tear the circuit down when a cell of
that circuit does not arrive. The transport of §3.8 L1 gives the order and the
retransmission below the cell layer.

> *Why this shape gives non-malleability.* A change of one bit of `Y_R` changes
> `POLYVAL`, thus it changes `S`. A changed `S` randomizes the full right part
> and the recovered `X_L`. A change of one bit of `Y_L` has the same result.
> Thus no adversary edits a cell into a related cell, and the tagging attack
> that confirms a chain does not operate. This is the protected-IV shape of the
> rugged-PRP family, and it is the property that `NET-030` requires.
>
> A change at any hop randomizes the innermost `X_L`. Thus the endpoint rejects
> the cell, and the adversary learns nothing about which hop the cell passed.
>
> `S` is the counter block of the stream, and it is pseudorandom for each cell,
> because `C` never repeats inside one circuit. `K_str` is a separate key from
> `K_prp`, thus the block cipher and the stream never share a key.

> **Deviation note.** An earlier draft made `X_L` the chaining value itself and
> made each hop compare it. Under that text the left block carried no data.
> A relay that removed its layer then held `L` bytes only, and it held no value
> for the `tag` field of the next hop. Thus the cell had to lose 16 bytes at
> each hop, or it had to carry one tag for each hop. The first result shows the
> circuit position, and §3.4.2 gives that result as the cause to fix the hop
> count. The second result breaks the 32-byte overhead that §3.4.3, Part 5 §5.6,
> and Part 6 §6.9 each quote. The text above puts the tag of the layer below in
> the left block, which is the shape of the Counter Galois Onion paper, and the
> width then stays constant across the three layers.
>
> **[NET-110]** A maintainer MUST get a `/crypto-review` of this construction
> against the Counter Galois Onion paper (eprint 2025/583) before a release tag.
> This specification writes the construction, and the paper is the reference
> that a reviewer checks it against. **[NET-111]** Before a release tag, an implementation MUST add a
> known-answer test for four cells. The four cells are a forward cell, a
> backward cell, a cell after one chaining step, and a cell after one key
> update.
> **[NET-112]** Two implementations MUST produce byte-identical
> cells for one key set and one chaining value. **[NET-210]** Two
> implementations MUST hold one hop 3 key set after `CIRCUIT_MAX_CELLS` cells
> in one direction.

### 3.4.5 Replay protection

Replay protection is a **free result of the rugged-PRP construction**, and it is
not a separate mechanism. The per-hop cipher state advances at each cell. Thus a
replayed cell decrypts under a state that has moved, and the innermost left
block does not hold the 16 zero bytes. There is no Bloom filter, no per-relay
replay table, and no key-epoch reset.

A1, A2, and A3 can each replay a cell (Part 2 §2.2). **The endpoint rejects that
cell, and a relay in the middle position does not.** §3.4.4 gives the cause,
which is that a middle relay holds no value against which it can check the left
block. A replayed cell therefore travels to the endpoint and dies there. No
party keeps a replay table.

A replayed cell also moves the chaining value of each hop after the point of the
injection. Each later cell then fails the check of NET-114, and NET-115 tears
the circuit down. Thus an active adversary that holds one link stops a circuit
with one cell. The loop cover of §3.6.1 measures that event, and §10.4 feeds it
to the relay reputation. Part 16 §16.3 records the residual, and Part 2 §2.5
gives guaranteed availability as a non-goal.

This property is one of the concrete advantages of session circuits over a
per-packet format. Outfox gives no replay protection. A per-packet design has to
add a replay-tag store. Such a store is state about traffic that a relay has to
keep. Such a store is also a new object to size, to expire, and to leak from.

The one-time ephemeral keys of the telescoped handshake protect the
circuit-build messages separately.

### 3.4.6 Path-selection invariants

**[NET-032]** A client MUST refuse to build a chain that disobeys one of the invariants below:

1. **Operator disjointness.** No two hops share an operator identity or a
   family. The `operator_id` of the relay entry carries the identity (Part 10
   §10.5.3), and the family certificate of Part 10 §10.6.3 carries the family.
2. **Jurisdiction disjointness.** No two hops declare a jurisdiction code in
   one jurisdiction bloc. Part 10 §10.6.3 gives the bloc list, and `REL-091`
   makes the directory publish it.
3. **AS and prefix disjointness.** No two hops share an autonomous system. No
   two hops share an IPv4 /16 or an IPv6 /48.
4. **Layer order.** The pinned ingress relay of Part 10 §10.6.1 at hop 1, then
   one relay of layer 2, then one relay of layer 3.

**The graduated relaxation.** Part 10 §10.6.3 sets a feasibility floor of
three blocs. A relay set below that floor holds no chain that satisfies
invariant 2 at each pair of hops. **[NET-200]** If no chain satisfies every
invariant, a client MAY relax invariant 2 at hop 2 alone. Under that relaxation
hop 2 may share a bloc with hop 1 or with hop 3. Hop 1 and hop 3 stay in
different blocs. **[NET-201]** A client that relaxes invariant 2 MUST show the
user that relaxation. **[NET-202]** A client MUST NOT relax invariant 1,
invariant 3, invariant 4, or invariant 2 between hop 1 and hop 3.

**[NET-033]** If no conformant chain is available under `NET-200`, the client
MUST **fail closed** and show the cause. **[NET-034]**
The client MUST NOT degrade silently to a single-operator path.

> **Deviation note.** An earlier draft gave invariant 3 an IPv4 /24 here and an
> IPv4 /16 in Part 10 §10.6. It also gave invariant 2 a jurisdiction code here
> and a jurisdiction bloc in Part 10 §10.6. Two client implementations that read
> the two parts built different chains, and NET-033 makes that difference
> visible as a failure. This document takes the wider rule in each pair. These
> two invariants exist against A3 and against A5, and a wider rule is the rule
> that those two adversaries have to defeat. The cost is a smaller conformant
> chain set, and Part 10 §10.6 holds the family and ASN ceilings that keep that
> set large. Part 10 §10.3 keeps the /24 for the measurement cluster, because
> that rule detects co-residency and a wider prefix over-clusters it.
>
> A later draft failed closed at the first relay set that satisfied no chain,
> and the bloc list of Part 10 §10.6.3 then held no content. A launch network
> in two blocs failed closed on each client. `NET-200` relaxes the one pair
> that does not join the two ends of the chain. §3.11 names the two colluding
> relays at the ends of the chain as the pair that a bloc order joins. Hop 1
> with hop 3 is that pair. The user sees the relaxation under `NET-201`,
> and `NET-033` still fails closed below it.

> *Rationale.* In SimpleX, the two-hop unlinkability depends fully on the two
> relays under different legal control. But only the client-side default
> configuration and the promise of an operator hold this property. The user
> cannot see the property, and the two threat-model documents do not contain it.
> In UMBRA the property is a protocol invariant, and the client verifies it.

## 3.5 Delivery, retrieval, and inbound pacing

### 3.5.1 Push over a held session, not polling

The recipient holds a subscription over a live transport session. The relay
pushes each message on arrival. Polling is the degraded fallback (Part 8).

### 3.5.2 Inbound pacing is mandatory

**[NET-035]** **A relay MUST deliver to a client on a schedule. [NET-036] That schedule MUST NOT depend
on the arrival times of the messages.** A per-client Poisson clock emits the
deliveries. §3.9 gives `PACING_MEAN`, which is the mean of that clock. If the
clock fires and no real message is in the queue, the relay emits a `B0` cover
cell. This cover cell is bit-indistinguishable from a real `B0` delivery.

**[NET-291]** A relay MUST send each cell that it starts on a circuit that ends
at it on a tick of that clock. An answer, a `MSG`, a `NACK`, and a reflected
loop cell each take one tick. The two exceptions are the `EXTENDED` cell of a
build and the drain of `NET-037`.

**The clock governs each held session.** A push-wake session is a held session,
thus the clock runs during it. The one exception is the reconnect drain of §3.7
item 4. **[NET-037]** If that batched peek finds more than `DRAIN_THRESHOLD` messages, the
relay MUST answer it in one unpaced response. `DRAIN_THRESHOLD` is 60 messages.

**A group-queue session is a held session.** The `GSUB` of Part 6 §6.4.5 is
the subscription of that session, and the relay pushes each new record on it.
**[NET-268]** A relay MUST run the clock of `NET-035` and `NET-036` on a
group-queue session of §3.2.7 as on a pairwise session. **[NET-269]** The cover
cell of a group-queue session MUST have the shape of a `GMSG`, thus it is
bit-indistinguishable from a real `B0` delivery on that session. `NET-037` and
`DRAIN_THRESHOLD` apply to a `GSUB` under `NET-237`. The push wake of Part 8
§8.5.2 opens a group-queue session, and that session is a held session of this
rule.

> *The derivation of `DRAIN_THRESHOLD`.* One tick delivers one cell. At a
> `PACING_MEAN` of 1 s a paced session delivers about 60 messages in 60 s. U6
> needs 99.9 % of a backlog in 60 s after the recipient comes online. Thus a
> paced drain meets U6 up to 60 messages, and it fails above that count.
>
> A backlog above 60 messages accumulates over an offline interval. The relay
> already measures that interval, thus the unpaced response tells the relay
> nothing new. A local observer reads the drain as one burst, and Part 16
> §16.3 records that residual.

> *What the `B0` cover cell does not conceal.* The mix model of §3.12 puts the
> modal text in bucket `B1`. Thus a real text delivery is a 2 096-byte cell
> against a 560-byte cover cell, and an observer reads the bucket of each
> inbound cell.
>
> Bucket-matched cover is not affordable. Under the §3.12 mix the mean inbound
> wire cost is 0.85 × 2 096 + 0.05 × 8 240 + 0.10 × 32 860 = 5 480 B. At 7 200
> ticks that cost is about 39.5 MB for each 2 h session, against 4.03 MB for
> the `B0` stream. UMBRA does not spend that, and Part 16 §16.3 records the
> residual.

This measure has the highest value of one measure in the design. The relay
originates each pacing cell on mains power, thus the origination cost does not
fall on a phone. The byte cost does fall on the client data plan, and §3.12
gives that cost. The table below gives the evidence:

| Nym configuration (PoPETs 2026-0055) | WF attack F1 |
| --- | --- |
| No delay, no cover | 0.91 |
| 50 ms/hop delay, **no cover** | **0.97** ← worse |
| 100 ms/hop delay, no cover | 0.98 |
| Nym default (outbound paced, **inbound disabled**) | 0.87 |
| Inbound paced at 10 ms | 0.75 |
| Inbound paced at 20 ms | 0.64 |

Two conclusions are normative:

- **Do not ship jitter without cover.** Per-hop delay alone *increases* the F1
  of the attack from 0.91 to 0.97. The delay makes the inbound packets and the
  outbound packets easy to separate in time. Delay and cover are one feature,
  and not two switches.
- **The inbound direction carries the leakage.** Nym ships with inbound pacing
  off by default. **[NET-038]** UMBRA MUST NOT copy that default.

### 3.5.3 Bounded randomized delivery delay

**[NET-039]** The destination relay MUST take a delay for each message from an exponential
distribution before it emits the message. The mean of the distribution comes
from the active privacy mode (§3.9).

Trail of Bits gave the equivalent SimpleX issue a **medium** rating in July
2024. That issue is latency-injection correlation by an ISP, a VPN, a hosting
      provider, or an entry-node operator. In 2026 the issue is not mitigated,
      and randomized latency is only "considered". That adversary is fully in
      the model of Part 2.

### 3.5.4 Acknowledgments and receipts

An acknowledgment deletes a message, thus an acknowledgment is a state change
that a relay can see. A delivery receipt and a read receipt each make a round
trip that follows an arrival. The sealed sender of Signal failed against a
statistical disclosure attack that needed **fewer than 5 messages**. Delivery
receipts were on by default, and they made a round-trip correlation signal with
a median of 1 480 ms (NDSS 2021).

| Parameter | Value |
| --- | --- |
| `RECEIPT_MIN_DELAY` | 30 s |
| `RECEIPT_MAX_HOLD` | 3 600 s. The value is four times the U3 invisibility invariant of 900 s |
| `RECEIPT_BATCH_MAX` | 9 for each peer for each cell |

> *The derivation of `RECEIPT_BATCH_MAX`.* Part 6 §6.9 gives bucket `B0` a body
> capacity of 155 bytes at the default 64-byte chunk. That value is the `Text,
> default chunk` row, and a receipt body uses the same space. A receipt body of
> Part 6 §6.6.9 is two fixed bytes plus 16 bytes for each `msg_id`. Thus the
> maximum is 9. **[NET-040]** A
> revision MUST derive this value again if the bucket ladder or the default
> chunk width changes.

**Trigger.** **[NET-041]** A client MUST emit a delivery receipt when that client holds the
message. **[NET-042]** A client MUST emit a read receipt only after the user opens the
conversation. **[NET-043]** **A client MUST NOT emit a read receipt because it rendered a
notification.**

> *Cause.* The notification path of Part 8 decrypts on the device. Without this
> rule a client emits a read receipt at the moment of that decryption. The
> receipt is then a response with a tight timing bond to the arrival, and this
> section exists to prevent that shape. This rule is a security rule, and it is
> not only a product rule. No comparable product marks a message as read from a
> notification.

**Emission.** **[NET-044]** The client MUST batch acknowledgments for each queue.
**[NET-045]** The client MUST batch receipts for each peer up to
`RECEIPT_BATCH_MAX`. **[NET-046]** The client MUST emit a
queued acknowledgment or a queued receipt in one of two places. The first place
is a scheduled cover slot (§3.6.2). The second place is a session that the
client opened for another cause. **[NET-047]** The client MUST NOT open a transport session
for the only purpose of an acknowledgment or a receipt.

**[NET-048]** **A client MUST NOT flush a held receipt because the application moved to the
background.** **[NET-049]** The emission time MUST NOT follow the attention of the user. An
emission that follows a user action carries that action to an observer.

**Delay.** **[NET-050]** The client MUST NOT emit an acknowledgment or a receipt sooner than
`RECEIPT_MIN_DELAY` after the arrival that it reports. **[NET-051]** The client MUST use the
first opportunity that occurs after that floor.

**Why the floor is not the defense.** The cover clock is memoryless and it fires
whether or not a cell waits. Thus a receipt cell replaces the cover cell of that
slot and the outbound cell process does not change. That property is the
defense, and the floor is not. A fixed delay alone moves the correlation peak to
a new lag. §3.5.2 shows that a delay with no cover raises the attack F1 from
0.91 to 0.97.

**Discard.** **[NET-052]** If the client holds an acknowledgment or a receipt for longer than
`RECEIPT_MAX_HOLD`, the client MUST discard it. A held receipt names the arrival
time and the read time of each message, thus a seized device gives that record
to A6. **[NET-053]** The client MUST hold a receipt in the encrypted store only. **[NET-054]** The client
MUST erase a receipt when it emits or discards it.

**[NET-307]** A client MUST hold at most one read receipt for each peer. A
read that follows replaces the receipt that waits, and the time of the hold
starts again at that read. Under `WIR-514` the later receipt covers the
earlier one, thus a user that reads 50 messages costs one target in one cell,
and not six cells.

**Padding.** **[NET-055]** The client MUST pad a receipt cell to `B0` at each receipt count.
**[NET-056]** If the queued receipts do not fit the current bucket, the client MUST split them
across two opportunities. **[NET-057]** A client MUST NOT select a larger bucket to carry more
receipts, because the bucket then names the count.

**A group and a community.** A group carries no delivery receipt, no read
receipt, and no typing indicator, and Part 11 §11.6 gives the cause. Each such
signal is a record that every reader of the group queue downloads, thus the
aggregate cost is quadratic in the member count. Part 12 §12.3.1 prohibits a
receipt in a community. Thus a receipt goes to one peer, and this section
needs no fan-out rule.

> *Cause.* An earlier draft made a client apply the fan-out jitter of the
> group tier to a receipt that went to more than one peer. That draft gave a
> group a receipt to the sender only. This draft removes the group receipt and
> the fan-out, thus the rule has no case.

**Defaults.** **[NET-059]** Delivery receipts and read receipts MUST be off by default for a
new contact.

> **Deviation note.** An earlier draft required an acknowledgment to leave in a
> different transport session from the arrival. This document withdraws that
> requirement. §3.2.5 permits 8 queues on one transport session, thus the rule
> cannot prevent the queue linkage that it names. A session rotation for each
> acknowledgment also defeats the connection-independent session of §3.8 L2,
> which is not negotiable. The rotation pattern also names the acknowledgment.
> `RECEIPT_MIN_DELAY` and the two-place rule replace it.

## 3.6 Cover traffic

### 3.6.1 Cover packets are loops, not drops

**[NET-060]** Cover cells MUST be **loops**. The onion routing sends a loop cell back to the
queue of the originator. The marginal cost over drop-cover is zero. The benefit
is the detection of n−1 attacks and blending attacks. A relay that delays or
drops the traffic of a target causes loop failures, and the originator measures
those failures.

The loop-failure rate feeds the relay reputation signal (Part 10). A client
makes a cover cell in the foreground only (§3.6.2). Thus the loop sampling is a
foreground measurement, and it gives about 72 samples each day.

### 3.6.2 Client-side budget (small, by necessity)

The client selects a cover tier from the application state. The privacy mode
does not change the cover rate.

| Tier | Condition | Rate | Uplink cost |
| --- | --- | --- | --- |
| **A** | Application in the foreground | Poisson, λ = 0.05 `B0`/s | ≈97 KB/h |
| **C** | Application in the background, or not resident | none. The push wakes the client | 0 |

**[NET-061]** A client MUST use one cover rate in each privacy mode. **[NET-062]** A client MUST NOT change
the cover rate because of the mode. §3.9.1 forbids a mode that is visible in the
cell count.

**[NET-063]** About 20 % of the cover cells in tier A MUST be loops.
**[NET-304]** Each other cover cell of a client MUST carry one `COVER` command
of Part 6 §6.3 to the queue relay of the circuit, in the shape of a `B0`
`SEND`. `NET-060` names the cover cell that measures a path and `NET-063`
gives its share. An earlier draft gave the other cells no shape.

**[NET-305]** A client MUST draw the time to the next slot from an exponential
distribution with the mean of the tier, and it MUST draw it again at each
slot, whether or not the slot carried an item.

**[NET-306]** A client in the background that holds an open session MUST keep
the slot clock for the items 1 to 6 of `NET-065`, and it MUST make no cover
cell. An acknowledgment that never leaves fills the queue of the peer's
records at the relay under `QUEUE_QUOTA`. Such a cell is a real event, as each
background cell is, and the loss that this section states below covers it.

**[NET-064]** A client MUST carry a queued acknowledgment, a queued receipt, a
queued transparency digest, or a queued link-fault report in a scheduled cover
slot. Such a cell replaces the cover cell of that slot (§3.5.4), thus it adds no
cell to the outbound process. Part 9 §9.5.3 gives the transparency digest and
Part 10 §10.4.2 gives the link-fault report. Each of the four is one `B0` cell.
**[NET-065]** If two such items are due in one slot, the client MUST use the
order below.

1. The first retransmission of a record.
2. An acknowledgment.
3. A later retransmission of a record.
4. A receipt.
5. A link-fault report.
6. A transparency digest.
7. A cover cell.

> *Cause of the order.* An acknowledgment frees a queue slot at the relay of
> the peer under `QUEUE_QUOTA`, and it ends the hold of a receipt. A second
> retransmission of one record points at a lost link, and one more try does
> not repair a link. Thus one retransmission goes first, and the
> acknowledgment goes before each later one.

**[NET-133]** A client MUST NOT carry a backup write in a cover slot. Part 4
§4.7.2 gives the backup the chunk path of Part 13 §13.3.3, and Part 4 §4.7.2
gives the cause. A backup object is much larger than a `B0` cell, thus a cover
slot cannot carry it.

**Tier B is deleted, and the causes are stated.** At the derived cost of about
9.1 mWh for each radio promotion, the earlier tier B spent 188 promotions in an
idle day. With the hourly directory refresh and the push wakes, an idle day cost
242 promotions. That cost is 2.20 Wh, which is 14.3 % of the 15.4 Wh battery
that U5 names.

The fixed term of U5 permits 0.308 Wh with no arrival, which is 34 promotions.
No cadence of a background cover clock fits that budget. Part 8 §8.4.1 also
documents that Doze and App Standby already prevent a reliable background timer
on a current Android device.

**[NET-066]** A client MUST fetch the directory diff only when the radio is on for another
cause. **[NET-067]** A client MUST NOT open a session for the only purpose of a directory
diff.

With these two changes an idle day with no arrival spends no radio promotion
in Instant mode. Each background arrival then costs one promotion, which is
9.1 mWh against the 10 mWh that U5 permits. §3.12 gives the promotion count of
each mode.
**[NET-068]** **Implementations MUST test these constants against a real handset with a power
monitor before a release.**
The duty-cycle model is derived, and no party measured it on 2026 hardware.

> **What the deletion of tier B costs, stated.** In the background a client
> makes no cover cell. Thus a background outbound cell is always a real event,
> and an ingress relay reads the send times of a backgrounded user. §3.11 states
> that loss and Part 16 §16.3 records it. The loop sampling of §3.6.1 becomes a
> foreground measurement and it gives about 72 samples each day. Part 10 §10.4
> states that the loop-failure input comes from the foreground only.

### 3.6.3 Relay-side cover carries the load

The core relays of the nonprofit operate on mains power with flat-rate
bandwidth. **[NET-069]** These relays MUST make loop cover at or above
`RELAY_LOOP_RATE`. **[NET-070]** These relays MUST also make the inbound pacing
cover of §3.5.2.

| Parameter | Value |
| --- | --- |
| `RELAY_LOOP_RATE` | 1 loop cell each 10 s on each live chain that the relay holds. The relay measures it from its previous loop on that chain |

This property is the structural advantage of the infrastructure model of UMBRA.
In a stratified mixnet, the nodes can make the cover. The cover requirement *for
each user* **decreases as the real user base increases**. Figure 4 of arXiv
2107.12172 gives the data. The cover packets for each user to hold 10 bits of
entropy fall from about 10 at 10² users to about 0 at 10⁵ users. A design that
puts the cover budget on the phone becomes worse as it grows, and the design of
UMBRA becomes better.

## 3.7 Reliability

Deployed relay-chained networks lose packets. Nym Mainnet measures a
retransmission rate of about 5 %. Thus UMBRA specifies an explicit ARQ:

1. Acknowledgments travel on single-use reply blocks, thus an acknowledgment
   does not name the recipient.
2. In tier A the **cover clock** schedules a retransmission (§3.6.2). **[NET-071]** A client
   MUST NOT send a retransmission at a timeout, because a retransmission burst
   at the timeout is a signature. In tier C the client holds no cover slot. **[NET-072]** A
   client MUST then carry a retransmission in the next session that it opens
   for another cause. That session is the push-wake session of Part 8 §8.4.1. A
   background retransmission is a real outbound event, and §3.11 states that
   loss.
3. Multi-chunk transfers are **all-or-nothing**. A partly completed transfer
   completes, or it fails without an observable signal.
4. Resubscription after a reconnect uses one batched peek on the server. The
   client keeps the last acknowledged sequence number for each queue as its
   cursor, with an in-flight window of 1 000. There is **no response timeout for
   each subscription**, because the connection carries the liveness.

> *Rationale for item 4.* SimpleX measured **more than one hour** to resubscribe
> about 300 K queues. SimpleX also measured a **retry rate of about 36 %** at
> 1.1 M subscriptions. The cause was the dispatch of about 2 200 batches at the
> same time, thus each response timer started at the same moment. This behavior
> is a self-inflicted DDoS at reconnect. It makes a messenger unusable for an
> ordinary user after a subway ride, and UMBRA includes the correction from the
> first commit.

**The end of the ARQ.** A retransmission that never ends is a signature, and a
record that no relay accepts needs a user and not a timer.

| Parameter | Value |
| --- | --- |
| `SEND_MAX_ATTEMPTS` | 16 sends of one record, the first send included |
| `SEND_GIVE_UP` | 7 days. The sender measures it from the first send of the record |

- **[NET-217]** A client MUST stop the ARQ of a record at a `NACK` with reason
  `REJECTED` or `VERSION`. Part 6 §6.4.4 gives the two reasons, and rule
  `WIR-324` forbids the same bytes again. **[NET-218]** A client MUST continue
  the ARQ after a `LIMIT`, a `BUSY`, or an `ADMISSION`, under the rules of
  that section.
- **[NET-219]** A client MUST NOT send one record more than
  `SEND_MAX_ATTEMPTS` times. **[NET-220]** If a record holds no relay
  acknowledgment `SEND_GIVE_UP` after its first send, the client MUST stop the
  ARQ of that record.
- **[NET-221]** When the ARQ of a record stops, the client MUST put the record
  in the `failed` state of Part 15 §15.9. **[NET-222]** A client MUST NOT send
  a `failed` record again without a user action.

A `failed` record is a record that no relay accepted. U6 of Part 2 §2.4 counts a
record from the moment a relay accepts it, thus a `failed` record is outside U6.
The interface rule of Part 15 §15.9 shows it to the user. `SEND_GIVE_UP` equals
`DEAD_CHANNEL_SILENCE` of §3.2.6, because a channel that accepts nothing for 7
days is a channel that the dead-channel probe examines.

**A post to a group queue.** A `GPOST` of §3.2.7 travels to two replicas, and
the rules above apply to each replica.

- **[NET-270]** A client MUST take a `GSEQ` as the relay acknowledgment of a
  `GPOST` under this section. **[NET-271]** A client MUST count
  `SEND_MAX_ATTEMPTS` and `SEND_GIVE_UP` for each replica of a `GPOST`
  separately. **[NET-272]** A client MUST put a `GPOST` in the `failed` state
  only when no replica returned a `GSEQ` before `SEND_GIVE_UP`. A `GPOST` that
  one replica accepted is `accepted` under `NET-257`, and `NET-259` reports
  the other replica.

> *Cause.* An earlier draft gave the ARQ no end. A record to a deleted queue
> got a `REJECTED`, and the client sent it again at the next cover slot for
> the life of the session. Each try was a real outbound cell, and §3.11 counts
> it. A user saw one mark for a record that no relay held, and U6 read as met.

## 3.8 Transport

UMBRA uses three transport layers, and a developer can replace each layer
independently:

| Layer | Content |
| --- | --- |
| **L1 Wire** | TLS 1.3 over TCP/443 by default. The ClientHello is the ClientHello of the rustls stack that Part 15 §15.2.8 names, with an `X25519MLKEM768` (RFC 10024) key share first and GREASE ECH. Each client sends the same ClientHello. The frame is an HTTP/1.1 Upgrade to a WebSocket-shaped stream, co-tenant with a real website behind a reverse proxy. The stream carries RFC 9297 capsules, used identically over TCP and QUIC, thus one parser serves the two transports (Part 6 §6.2.1). The web client of Part 15 §15.7 sends the same stream through the WebSocket API of its browser, and §3.8.1 states what that changes |
| **L2 Session** | Connection-independent session (64-bit session ID, monotonic sequence, and resend window). A TCP RST, a middlebox timeout, a QUIC migration, or a Wi-Fi-to-cellular handover rotates the connection **without a drop of the session**. Part 6 §6.2.3 gives the open, the resume, and the close |
| **L3 Cell** | Fixed-size cells (§3.3) over the 3-hop chain into queues |

Part 6 §6.2 numbers the same three layers L1 to L3 and continues the count to
L8. The capsule of RFC 9297 is the format that the CONNECT-UDP proxy of RFC 9298
also uses.

> *Rationale for L1.* The `X25519MLKEM768` key share carries G2 into the
> transport layer. All the clients send the same ClientHello, thus no client
> carries a unique fingerprint. That ClientHello is not the ClientHello of a
> browser, and §3.8.1 states that trade. A client pins two ingress relays
> (Part 10 §10.6.1). GREASE ECH and co-tenancy hide that pinned pair from a
> local observer, thus the pair does not link the client across networks (G7,
> G9). Port 443 and the HTTP/1.1 Upgrade framing pass an ordinary proxy and
> an ordinary carrier middlebox, which U1 and U6 need.

> *Cause of the named stack.* An earlier draft shaped the ClientHello as
> Chrome on Android, in the manner of uTLS. No Rust TLS stack shapes a
> ClientHello in that manner, and Part 15 §15.2.6 then rejected both providers
> of rustls. Thus no client could send the L1 flight. Part 15 §15.2.8 now
> names the stack, and the ClientHello is the one that the stack sends. Part 2
> §2.5 already gives undetectable use as a non-goal, thus the change removes a
> claim that the design did not make.

L2 is not negotiable. It has the highest value for robustness on unstable mobile
networks.

**Transport requirements:**

- Race TCP/443 against QUIC/443, and give TCP a head start of about 250 ms.
  Cache the winner for each network, keyed by SSID or PLMN, with a TTL of 24 h.
  Some networks do not carry UDP/443. On other networks QUIC completes the
  handshake more reliably than TCP. A hard-coded
  choice loses users on one network type or on the other (U1, U6).
- **The key share.** **[NET-214]** A client MUST offer `X25519MLKEM768` as the
  first key share of the ClientHello. **[NET-215]** A client MUST NOT offer a
  group other than `X25519MLKEM768` and `X25519`. **[NET-216]** A relay
  operator MUST terminate TLS with a stack that accepts `X25519MLKEM768`. The
  reverse proxy of the co-tenant site is that stack, thus the operator selects
  a proxy build that holds the group. The second group keeps a client
  connected to a relay whose proxy fails that rule. The inner layer of Part 6
  §6.2.3 carries G2 in that case.
- **The web client.** **[NET-275]** A web client MUST send the L1 stream
  through the WebSocket API of its browser, over TLS to port 443, and it MUST
  NOT use WebTransport in v1. The browser owns the ClientHello, thus `NET-214`
  and `NET-215` bind the native client only, and the second group of `NET-216`
  carries G2 for a browser that offers no post-quantum share. **[NET-276]** A
  relay MUST NOT accept TLS early data on its L1 listener. Thus the property
  of `NET-073` holds for a web client whose browser offers early data, because
  the relay refuses it. **[NET-277]** A web client MUST NOT race QUIC, because
  the browser gives it no QUIC stream in v1.
- **The upgrade and the name.** **[NET-280]** A client MUST open the
  WebSocket-shaped stream with `GET /umbra HTTP/1.1`, a `Host` header that
  carries the `host` of the descriptor of Part 10 §10.5.3, `Upgrade:
  websocket`, `Connection: Upgrade`, a `Sec-WebSocket-Key` of 16 bytes from
  the CSPRNG in base64, `Sec-WebSocket-Version: 13`, and
  `Sec-WebSocket-Protocol: umbra.v1`, and no extension header. **[NET-281]**
  A relay MUST answer an upgrade it accepts with status `101`, the
  `Sec-WebSocket-Accept` of RFC 6455 §4.2.2, and the same subprotocol, and
  it MUST NOT accept an extension. The accept token uses SHA-1 as RFC 6455
  gives it. The token proves that the relay read the key and it carries no
  secret, thus it is not a primitive of Part 5 §5.1, and the browser of the
  web client of Part 15 §15.7 checks it under that rule. **[NET-282]** A
  client MUST verify the TLS certificate of a relay against the `host` of
  its descriptor under the public CA roots, and it MUST NOT accept a
  connection without that check. **[NET-283]** A QUIC connection MUST
  negotiate the ALPN `umbra.v1`, and the TCP connection negotiates none.
- **[NET-073]** **Implementations MUST disable 0-RTT** in TLS and in QUIC. A replayed `SEND`
  duplicates a message, and a replayed `ACK` deletes one. Resumption tickets are
  also a linkability vector across networks. To recover the round trip, pipeline
  the first queue operation into the first 1-RTT flight.
- **[NET-074]** Interactive traffic and bulk traffic MUST use separate connections, or
  separate QUIC streams. Head-of-line blocking on the retransmit of one chunk
  stalls chat delivery. Such a stall occurs on the lossy links where UMBRA
  has to operate.
- **No OS VPN mode.** **[NET-075]** UMBRA MUST open userspace sockets in the application
  process. **[NET-076]** UMBRA MUST NOT capture the device traffic with the Android
  `VpnService`. Tolley and others (2026)
  tested six tools on Android 16. All six leak internal IP addresses and accept
  injected TCP resets through the OS tunnel semantics, and payload encryption
  does not prevent this.
- **No WebRTC or DTLS transport in v1.** A WebRTC stack does not fit the
  dependency budget of Part 15 §15.2. TLS 1.3 and QUIC give the same
  transport service at a lower cost. A third transport also divides the client
  population into classes that an adversary can tell apart (§3.9.1).

### 3.8.1 Detectability: an explicit trade

UMBRA does **not** try to be undetectable at the flow level. AEGIS-class
classifiers reach a TPR of 99.50 % at an FPR of 0.21 %. They use six features
and 262 µs. Padding-only defenses move the deep-learning result from 96.5 % to
about 93.5–95.9 % only. UMBRA cannot win against those classifiers, and such an
effort uses the full bandwidth budget.

UMBRA spends its bandwidth on the *who-speaks-to-whom* question, which those six
features cannot answer. This document states the trade here, thus no reader
opens it again in silence.

The ClientHello of §3.8 is the ClientHello of the rustls stack, and not the
ClientHello of a browser. A classifier tells an UMBRA client from a browser on
that flight alone, and this document accepts that under the same trade.

The web client of Part 15 §15.7 sends the ClientHello of its browser. Thus a
classifier tells a web client from a native client on that flight, and it
tells a web client from a page load of the co-tenant site by the WebSocket
upgrade and by the cell sizes. The two classes send the same cells above L1,
and the class names no user. The web client is a second class under §3.9.1,
and this document accepts that under the same trade.

Two properties of the deployment limit the damage from a lost relay. Each relay
shares its IP address and port 443 with a genuine website, thus one IP address
does not name one relay (G7, G9). A client pins two ingress relays (Part 10
§10.6.1), thus the loss of one relay does not stop delivery (U6). UMBRA does not
claim unblockability (Part 2 §2.5).

## 3.9 Privacy modes

A user selects the mode for each conversation. All the modes use 3 hops, the
same bucket ladder, and the same inbound pacing. The modes differ only in the
per-hop delay.

| | **Fast** | **Balanced** (default) | **Private** |
| --- | --- | --- | --- |
| Hops | 3 | 3 | 3 |
| Per-hop delay | none | Exp, mean 150 ms | Exp, mean 700 ms |
| End-to-end added delay | 0 | Erlang(3), mean 450 ms | Erlang(3), mean 2.1 s |
| Inbound pacing | Poisson, mean `PACING_MEAN` | Poisson, mean `PACING_MEAN` | Poisson, mean `PACING_MEAN` |
| Client cover | Tier by state (§3.6.2) | Tier by state (§3.6.2) | Tier by state (§3.6.2) |
| Send batching | no | no | no |
| Expected p50 delivery | ~1.1 s | ~1.6 s | ~3.3 s |
| Expected p95 delivery | ~3.4 s | ~3.9 s | ~6.5 s |

**`PACING_MEAN` is 1 s.** **[NET-077]** A relay MUST use this one mean in each privacy mode.
**[NET-078]** A relay MUST NOT change the mean because of the mode. §3.9.1 forbids a mode that
is visible in the cell count, and the inbound cell rate is a cell count. A relay
does not learn the mode, and this rule needs no mode knowledge.

> *The derivation of `PACING_MEAN`.* §3.5.2 makes the delivery clock a
> per-client Poisson process, and that process is memoryless. Thus a message
> waits an exponential time for the next tick. The mean of that wait is
> `PACING_MEAN`, and its 95th percentile is three times `PACING_MEAN`.
>
> §3.0 gives the measured usability band, where a mean added delay of 1 s and of
> 4 s keeps usability. Private mode spends 2.1 s of that band on the per-hop
> delay. **[NET-079]** Thus a revision MUST NOT set `PACING_MEAN` above 1.9 s.
>
> The clock also runs faster than the inbound message rate. If a backlog builds,
> the delivery times follow the arrival times, and the pacing then hides
> nothing. A live exchange delivers about one inbound message each 7 s. At a
> mean of 1 s the clock is 7 times faster than that rate. The mean delay then
> grows by a factor of 1.17. At a mean of 2 s the clock is 3.5 times faster, and
> the factor is 1.40.
>
> Each tick costs one `B0` cell, which is 560 bytes (Part 6 §6.9). A held
> session of 2 h spends 7 200 ticks and 4.03 MB. Each halving of the mean
> doubles that cost. §3.12 gives the full budget.

All three modes are in the measured usability band. The mean added delay is
1.0 s in Fast mode, 1.45 s in Balanced mode, and 3.1 s in Private mode.

> **Deviation note.** An earlier draft gave Private mode a send that waits for a
> cover slot. This document withdraws that mechanism. It forced a cover rate
> that differs by mode, and §3.9.1 forbids a mode that is visible in the cell
> count. The property that a Private-mode send hides inside a cover slot is
> gone. Part 16 §16.3 records that residual.

> **Deviation note.** An earlier draft also gave Fast mode and Balanced mode a
> pacing mean of 2 s. It gave Private mode a constant-rate clock. This document
> withdraws both. A pacing shape that differs by mode puts the mode in the
> inbound cell count, and §3.9.1 forbids that result. Private mode gives up the
> tighter delivery tail of a constant-rate clock, and Part 16 §16.3 records that
> residual.

> **Deviation note.** An earlier draft gave three p50 delivery figures with no
> pacing term, on a propagation model of 220 ms for the two legs. §3.12 now
> models 210 ms of propagation in each direction, and the table above counts
> the pacing term. Part 2 §2.4 sets U2 at a p50 of 2.0 s and a p95 of 4.5 s
> from that model, and rule `NET-139` keeps the two in step.

### 3.9.1 Anonymity-set fragmentation

A set of modes divides the population into classes that an adversary can tell
apart, and this division is a real cost. UMBRA limits the cost:

- **[NET-080]** The mode MUST NOT be visible in the cell size, the cell count, or the chain
  length. The mode is visible only in the timing, and only to an adversary that
  monitors the client link at that time.
- Baseline cover and inbound pacing are **always on in each mode**. Thus no mode
  is the "no protection" mode, and no user becomes conspicuous because that user
  has protection.
- **[NET-081]** The UI MUST NOT label Private mode in a manner that implies that the user
  hides something. The UI shows the mode as a speed and privacy control for each
  conversation.

## 3.10 Bootstrapping and relay discovery

**[NET-082]** An implementation MUST NOT hardcode a relay list in the binary. A hardcoded
list names a fixed set of relays, thus legal process gets a permanent target
list (A5, G13). A
hardcoded list also cannot rotate, thus it breaks the path invariants of §3.4.6
when an operator leaves. An application-store release cycle is too slow to carry
a relay change, and U6 needs a faster path.

UMBRA uses independent bootstrap carriers behind one interface. No one legal
order against one carrier stops the distribution of the relay manifest (A5,
G13). If one carrier is unavailable, a client uses another carrier and stays
reachable (U6). Part 10 §10.5 states the same property for the directory
manifest. The carriers are:

1. **Social or out-of-band.** A QR code or an invite link from an existing
   contact carries a signed relay bundle. *A client that gets a bundle from a
   contact makes no directory query at the first contact. Thus no directory
   operator learns that a new client joined at that time (G8, G13). This carrier
   also removes a step from the first launch, which U1 measures.*
2. **Push-notification wake.** The platform push path is already open for a
   resident application. A push wakes a client that has no current relay, and
   that client then fetches a fresh manifest over another carrier. Google
   already learns that the application is installed (Part 8 §8.7), thus this
   carrier adds no new party.
3. **DoH TXT and HTTPS-RR** lookups at large resolvers.
4. **Serverless HTTPS endpoint (optional).** **[NET-083]** A deployment MAY use a function URL
   at a large cloud provider. This carrier needs no dedicated host, thus an
   operator adds it and removes it at a low cost.

UMBRA distributes the relay list as a multi-signed, Merkle-rooted, and
timestamped manifest. Thus a carrier can deliver the list without trust.

### 3.10.1 One relay population

UMBRA has one relay population. The directory lists each relay, measures each
relay, and ranks each relay by reputation (Part 10). The listing, the operator
dossier (Part 10 §10.5.1), and the measurements are a public record. Legal
process can name each relay, and an adversary can select each relay for an
attack (A2, A5). Part 16 §16.1 and §16.3 record that exposure.

**[NET-084]** An operator MUST NOT operate an UMBRA relay that the directory does not list. **[NET-085]** A
client MUST NOT build a chain through a relay that the signed manifest of §3.10
does not carry.

**[NET-086]** A client MUST select an ingress relay under the rules of Part 10 §10.6.1. **[NET-087]** A
client MUST keep an ingress relay for the minimum lifetime that Part 10 §10.6.1
gives. **[NET-088]** A client MUST NOT replace an ingress relay because of local performance
(Part 10 §10.6.2).

**[NET-089]** An operator MAY retire a relay. **[NET-090]** If an operator retires more than one relay, that
operator MUST separate the retirements in time. A retirement of many relays at
one time moves many clients at one time, and an observer reads that event as a
collection signal (§3.2.4).

**[NET-091]** An operator MUST NOT derive a relay identity from the IP address of the relay.
Thus a relay keeps its identity across a move, and an address does not name a
relay (G7).

> **Deviation note.** An earlier draft gave a second and unpublished relay tier.
> This document withdraws that tier, and there are four causes. First, the tier
> put a cheap relay at the ingress position. Part 10 §10.6.1 sets a class C2
> floor at that position. A cheap Sybil attack at the one position that sees a
> client IP address has to stay too expensive. Second, the tier bypassed the
> staging of Part 10 §10.7.1, the operator dossier of §10.6, and the measurement
> of §10.3.
>
> Third, a fast replacement cadence at the ingress position is a loss. Part 16
> §16.1.1 shows that a compelled operator collects from the moment of the order.
> A client that replaces an ingress relay 30 times each year meets 30 operators
> each year. Each one of those operators can hold that order (G7, G9, A5).
> Fourth, the cause for a fast cadence was censorship resistance, and Part 2
> §2.5 withdraws that goal.

## 3.11 What each party actually learns

This section is the normative answer to G6, G7, G8, and G13 of Part 2.

**One Ingress Relay** learns the client IP address, the connection time, the
cell counts, and that the client runs UMBRA. It does **not** learn the
destination queue, because the innermost layer blocks it. It also does not learn
the recipient, the content, or how many conversations the client has.

**One Ingress Relay also reads the send times of a backgrounded user.** In tier
C the client makes no cover cell (§3.6.2), thus each background outbound cell is
a real event. UMBRA accepts this loss, and Part 16 §16.3 records it.

**One Chain Relay** learns two adjacent relay addresses and the cell times. It
learns nothing else.

**One Queue Relay** learns the queue identifiers, the ciphertext at rest, and
the delivery time, which UMBRA randomizes. For a maximum of 8 queues at a time,
it also learns that those queues share a transport session. It does not learn a
client IP address, an identity, or content.

**One group-queue relay learns** that the group queue exists, the count of its
reader sessions and of its writer sessions, the arrival time and the bucket of
each record, the exact member count at each rotation, and the notifier count.
The member count comes from the slot count of the epoch-key record of Part 11
§11.4.2, which the relay reads. The notifier count comes from the `GNREG` set
of Part 8 §8.5.2, and each notifier names a queue relay and no handle. It does
**not** learn an identity, a pairwise queue of any member, content, the sender
of a record, or a membership list, because no command of §3.2.7 carries one.
Part 11 §11.5 states the same bound from the side of the group. Part 2 §2.2
THR-002 covers the **count of conversations**, and it does not cover the
**size of one conversation**. UMBRA accepts this loss, and Part 16 §16.3
records it.

> *Cause.* An earlier draft let the ingress relay read the recipient count of
> a group from the burst of a pairwise fan-out, and no measure of that draft
> concealed the count. This draft moves that leak from the ingress relay to
> the group-queue relay, which reads a count and no address. Part 11 §11.2
> replicates the queue on two relays under different operators, and a reader
> alternates replicas under `NET-261`, thus one relay holds half of the
> reader timeline.

**Two colluding relays at the ends of the chain** recover this fact: *a client
at IP address X delivered to queue Q at time T*. The ingress relay of a reader
and its group-queue relay are one such pair, and together they recover that
*a client at IP address X reads group queue G*. This fact is a real
deanonymization risk, and it is the cause of the path invariants in §3.4.6.
UMBRA does not claim security against an adversary that controls the majority of
the relay capacity.

**The nonprofit** learns from its own relays the same data that another operator
learns, and it also gets aggregate directory statistics. It holds **no user
database, because no user database exists**. There is no account, no
registration, no phone number, no email address, and no global identifier.

**A global passive adversary** can do end-to-end confirmation against Fast mode
and Balanced mode. This is a theoretical result and not an engineering gap.
DeepCoFFEA (IEEE S&P 2022) shows it empirically on Tor at a TPR of 93 % and an
FPR of 2·10⁻⁴. It also reaches a TPR of 84–95 % against obfs4, WTF-PAD, and
FRONT. Private mode increases the cost, but it does not close the gap.

**Legal process against one party** gives the column of that party and nothing
else.

### 3.11.1 What an active relay learns

§3.11 gives the passive case. Part 2 §2.2 gives A2 and A3 the power to drop a
cell, to delay a cell, to reorder a cell, and to inject a cell. This section
collects what those powers add. Part 16 §16.3 holds the same rows as residuals.

| The probe | What the relay learns | The bound |
| --- | --- | --- |
| Delay one queue and watch the other queues of one transport session | That those queues belong to one client | §3.2.5 caps a session at 8 queues |
| Delay one reader session of a group queue and watch the other sessions | Nothing beyond the reader count that it already holds (§3.11) | A reader's cursor is local under `NET-236`, thus no session answers for another |
| Drop each cell of one circuit | That the client rebuilds, and the timing of that rebuild | §3.4.3 gives `CIRCUIT_MAX_AGE` of 4 hours, thus a rebuild is normal |
| Inject one cell on one link | The circuit dies (§3.4.5), and the loop cover of §3.6.1 measures the death | §10.4 feeds the loop-failure rate to the relay reputation |
| Withhold a `MSG` and watch the acknowledgment point | The reconnect cadence of the recipient | Part 6 §6.4.3 rule 7 gives one boundary for each batch |

**[NET-134]** A revision that gives A2 or A3 a new active capability MUST add a
row to this table. Part 16 §16.8 makes §3.11 a published promise, and this
section carries the same standing.

Two properties limit each row above. First, an active probe is an act, and the
loop cover of §3.6.1 and the link reputation of Part 10 §10.4 measure it.
Second, no row gives the relay the identity of a party. Each row links a queue
to another queue, and Part 4 §4.2.2 keeps a queue apart from an identity.

## 3.12 Quantified daily budget

The budget below applies to a moderate user. That user sends 60 direct messages
and receives 90. That user has 6 groups with a mean of 25 members, and sends 8
group messages and receives 120. That user sends 2 attachments and receives 4,
at about 400 KB each. That user follows 2 communities, and each community takes
50 posts each day. The application is about 2 h in the foreground and about
14 h in the background. The device is a mid-range Android device on LTE in
Balanced mode.

**The model uses a device set of 2 devices, which is a phone and a laptop.**
This paragraph is the one place that sets the count. Each row below uses it. Two
devices are the common case, and Part 7 §7.5.2 names the phone and the laptop as
the typical pair. `MAX_DEVICES` is 8, and that limit is the worst case and not the
moderate case. The scaling rule below gives the cost at each device count, and
it gives the cost at 8 devices.

The modeled device is the phone. The phone holds the ratchet ownership of Part 7
§7.5.4 for each contact. Thus each record of the mix enters the device set at
the phone, and the phone sends that record on each of its sync channels.

**The model user holds 16 pairwise queues and 6 group queues over 9 sessions.**
The user has 16 direct contacts, and each contact holds one pairwise queue.
`MAX_QUEUES_PER_SESSION` of §3.2.5 puts 8 queues in one session, thus the 16
queues need 2 sessions. Each of the 6 groups holds one group queue of §3.2.7
on 2 replicas, and the user reads one replica of each group in one session
under `NET-263`, which is 6 group-queue sessions. In Instant mode the user
holds one notify queue for each group under one handle (Part 8 §8.5.2), and
that handle holds no pairwise queue, thus the 6 notify queues take one more
session. That is 9 sessions. `NET-023` and `NET-266` put each session on its
own chain, and `NET-124` and `NET-267` put hop 3 at the relay of the queue. The
model spreads the 9 sessions over 9 relays: 2 queue relays hold the pairwise
queues, 6 group-queue relays each hold the replica that the user reads, and 1
queue relay holds the notify queues. The recipients of the day sit on 22 other
relays, which are the 16 queue relays of the direct contacts and the 6 relays
that hold the second replica of each group. An earlier draft gave a member one
pairwise queue with each other member, thus the user held 160 queues over 20
sessions.

**Those relay counts are a model and not a measurement.** **[NET-212]** An
implementation MUST measure the queue-relay spread of a real deployment before a
revision re-tunes this table. **[NET-273]** An implementation MUST measure the
group-queue relay spread of a real deployment before a revision re-tunes this
table. The session count sets the handshake row, the circuit-build row, and
the entry row below. Thus the spread is the largest unverified figure of this
section.

**The foreground holds one paced session at a time.** That session is the
session of the conversation that the user reads, and the 26 foreground
receives arrive on it. The user moves between conversations, and the model
opens each of the 8 conversation sessions one time in the 2 h. A message on
another session arrives as a push, and the client drains it as a wake of the
kind below. The inbound cover row grows with the held-session count, and the
cover derivation below states that dependency.

**The background holds 184 arrivals.** Of the 210 receives, 184 arrive in the
14 h of background, which is 79 of the 90 direct receives and 105 of the 120
group receives. The model spreads those arrivals as a Poisson process with a
mean gap of 274 s, which is 50 400 s / 184. In Instant mode each arrival wakes
the device one time. `WAKE_COALESCE_WINDOW` of Part 8 §8.5 is 10 s, and about
4 % of the gaps are shorter than that window. The table uses the ceiling of
184 wakes, and it takes no credit for that window. An earlier draft asserted
30 wakes each day, and no arithmetic supported that count.

**A wake in Instant mode costs one transport handshake.** The push names the
session that holds the queue. The client opens one connection to the ingress of
that session, and it resumes the session under Part 6 §6.2.3 rule `WIR-361`.
The connection costs one TCP handshake, one TLS 1.3 handshake, and one HTTP
Upgrade under §3.8. The model prices that handshake at 6 000 bytes, which is
2 400 bytes up and 3 600 bytes down. The `X25519MLKEM768` key share and the
certificate chain set most of that figure.

**A group wake opens two sessions.** The push of a group record names the
notify session, and Part 8 §8.5.2 gives that path. The client resumes the
notify session, drains the `NotifyDigest`, and acknowledges it. It then opens
the group-queue session of that group with a `GSUB` from its cursor, and the
record arrives on it. The two circuits share one connection to one ingress,
as the handshake derivation below permits, thus a group wake pays one
handshake and two session opens. The 184 wakes open 79 + 2 × 105 = 289
sessions.

**That handshake figure is unverified.** **[NET-213]** An implementation MUST
measure the handshake cost of the L1 stack of §3.8 before a revision re-tunes
this table. The client then resubscribes the queues of the session in one
`B0` cell, under §3.7 item 4, and on a group-queue session that cell is the
`GSUB`. Each session holds about 3 s, which is 3 pacing ticks at
`PACING_MEAN` of 1 s. One tick carries the real drain, which is a `B1` record
on a pairwise or a group-queue session and a `B0` digest on the notify
session, and 2 ticks carry `B0` cover. The client sends one `B0`
acknowledgment for the queue that it drained, and it closes the connection
under rule `WIR-360`. A group queue takes no reader acknowledgment under
`NET-235`. NET-100 below caps each session at 6 s.

**A circuit lives from one wake to the next.** §3.4.3 sets `CIRCUIT_MAX_AGE` to
4 hours, and Part 6 §6.2.3 sets `SESSION_RESUME_WINDOW` to the same value. Each
of the 2 pairwise queue relays takes 79 / 2 = 39.5 background arrivals each
day, which is 2.8 arrivals each hour over 14 h. The chance that one gap
exceeds 4 hours is e^(−11.3), which is 0 to three places, thus each pays one
build at the first arrival of the day. The notify relay takes 105 arrivals,
and it pays one build for the same cause. Each of the 6 group-queue relays
takes 105 / 6 = 17.5 arrivals each day, which is 1.25 arrivals each hour. The
chance that one gap exceeds 4 hours is e^(−5.0) = 0.0067. Thus each one pays
one build at the first arrival and 17.5 × 0.0067 = 0.12 more at a lapsed
circuit, and the 6 pay 6.7. The background pays 2 + 1 + 6.7 = 9.7 builds each
day, and the table uses 10. An earlier draft set `CIRCUIT_MAX_AGE` to 10
minutes, and each wake then paid a build.

A build is 3 `EXTEND` cells and 3 `EXTENDED` cells under NET-150 and NET-151.
Each cell is a `B1` cell, thus a build costs 6 × 2 096 = 12 576 bytes on the
wire. That is 6 288 bytes in each direction. An earlier draft priced a build at
7 104 bytes of handshake material, and it did not count the cells.

**A build fetches relay entries.** Part 10 §10.5.3 gives a `RelayEntry` 5 498
bytes and its proof 384 bytes, which is 5 882 bytes. A build selects a fresh hop
2, thus it fetches that entry. Hop 3 needs a fresh entry when the accepted
`DirectoryRoot` is newer than the entry that the client holds.
`CONSENSUS_VALIDITY` is 3 hours, thus that fetch occurs at most one time for
each build, and at most 8 times each day for each relay. The table uses 2
entries for each build in Instant mode. Hop 1 is the pinned ingress of Part 10
§10.6.1, and its 2 entries amortize over 60 to 120 days. Rule `REL-138` of Part
10 forbids a client fetch of a family certificate, thus that row is 0 bytes.

### Bandwidth

Part 6 §6.9 gives the wire cost of each cell. A `B0` cell costs **560 B**, and
a `B1` cell costs **2 096 B**. A `B2` cell costs **8 240 B**, and a `B3` cell
costs **32 860 B**. Each row below uses those four figures.

| Uplink | |
| --- | --- |
| 1:1 sends (60 `B1` cells) | 126 KB |
| Group posts (8 × 2 replicas × `B1` cells) | 34 KB |
| Epoch rotations as a member (6 groups × 1 `B3` cell each day) | 0 KB, an admin uploads the record |
| Presence records (6 groups × 1 `B0` × 2 replicas in each 7 days) | 1 KB |
| Attachment upload (2 files, 13 chunks each, 1 copy, §13.4.1) | 885 KB |
| Device-set sync records (1 channel, 278 `B1` cells) | 583 KB |
| Device-set sync acknowledgments (1 channel, 0 cells) | 0 KB, §7.5.5 of Part 7 forbids one here |
| Ownership claims (1 channel, 4 `B2` cells) | 33 KB |
| Backup writes (Part 4 §4.7.2, 9 `B3` cells) | 493 KB |
| Circuit builds, the `EXTEND` cells (45 builds × 3 `B1` cells) | 283 KB |
| Transport handshakes, the client half (219 × 2 400 B) | 526 KB |
| Session resubscriptions (297 `B0` cells) | 166 KB |
| Community pulls (2 communities, 138 `B0` cells) | 77 KB |
| Tier A cover (2 h at 0.05/s, 360 `B0` cells) | 202 KB |
| Foreground receipts and acknowledgments | 0 KB, carried in the cover slots above (§3.5.4) |
| Background acknowledgments of the drains (184 `B0` cells) | 103 KB |
| Notifier rotation, the client half (Part 8 §8.2.5) | 3 KB |
| Directory requests, measurement, token refill | 80 KB |
| **Total up** | **≈ 3.59 MB** |

> *The derivation of the group rows.* A group post is one `GPOST` of the same
> record to each of the 2 replicas under `NET-256`. A 25-member group carries
> a 300-byte tag vector (Part 11 §11.3.3), thus a 350-byte text stays in
> bucket `B1`. The 8 posts are 16 cells and 16 × 2 096 = 33 536 bytes. An
> earlier draft sent one cell to each of the 24 recipients, which was 192
> cells and 402 432 bytes.
>
> The 120 group receives arrive on the 6 group-queue sessions as `GMSG` cells
> of bucket `B1`, which is 120 × 2 096 = 251 520 bytes. The relay of each
> group queue writes one `NotifyDigest` of Part 8 §8.5.2 into the notify queue
> of the reader at each accepted `GPOST`, and the reader drains it as a `B0`
> cell, which is 120 × 560 = 67 200 bytes. The 15 foreground receives arrive
> on the held session, and their digests drain at the next open of the notify
> session.
>
> Part 11 §11.4.1 rotates the epoch of a group at a removal and at
> `GROUP_EPOCH_MAX_AGE`. The model gives each group one rotation each day as
> an upper figure. At 25 members the epoch-key record of Part 11 §11.4.2 is
> inline, and it is one `B3` record on the group-queue session. Above about
> 27 members the member fetches one `B3` chunk on the chunk path of Part 13
> §13.3.3. Each carrier costs 32 860 bytes, thus the downlink row is
> 6 × 32 860 = 197 160 bytes. A member of role `admin` uploads the record, and
> the model user holds no such role, thus the uplink row is 0 bytes. The model
> counts the record among the 120 group receives for the wake arithmetic.
>
> Part 11 §11.9.7 makes a member post one `GroupPresence` record in each
> `PRESENCE_INTERVAL` of 7 days of silence. It is a sparse record with at most
> `ROLE_HOLDER_MAX` tags, thus it fits bucket `B0`. The model takes one record
> for each group each week as the ceiling, which is 6 records to each of 2
> replicas, 12 × 560 = 6 720 bytes each week, and 960 bytes each day.
> **[NET-274]** A revision that changes `GROUP_MAX`, `GROUP_REPLICAS`,
> `PRESENCE_INTERVAL`, or the group-record layout of Part 11 §11.3 MUST derive
> these rows again.

> *The derivation of the ownership claim row.* Part 7 §7.3.1 gives an
> `OwnerClaimRecord` 3 763 bytes at `OWNER_CLAIM_MAX`, thus it uses bucket `B2`
> at 8 240 bytes on the wire. Part 7 §7.8 sets `OWNER_CLAIM_RATE` to 4 records
> for each device each day. The phone sends 4 on its 1 channel, which is
> 32 960 bytes. The laptop sends 4, and the downlink row holds them.
>
> A claim record is a control record, thus §7.5.1 does not pace it from the
> cover clock and it takes no cover slot. **[NET-135]** A revision that changes
> `OWNER_CLAIM_RATE` or the `OwnerClaimRecord` width MUST derive this row again.
>
> An absence claim of Part 7 §7.3.1 is not in the model day. Part 7 §7.8 bounds
> it at `OWNER_ABSENCE_RATE`, which is 1 record each hour. Thus the day of a
> loss costs at most 24 × 8 240 = 197 760 bytes on one channel.
>
> A catch-up object of Part 7 §7.5.1 is not in the model day. A peer that was
> absent for 7 days holds 1 946 records at about 350 bytes, which is about
> 681 KB. Part 13 §13.3.3 gives a chunk 32 650 bytes, thus the object is 21
> chunks at `B3` and about 690 KB on the wire. NET-133 keeps that object out
> of a cover slot in the same manner as the backup.

> *The derivation of the backup row.* Part 4 §4.7.2 writes the backup as chunks
> under Part 13 §13.3.3, and NET-133 keeps it out of a cover slot. Part 4 §4.8
> sets `BACKUP_HISTORY_DAYS` to 45, `BACKUP_FULL_INTERVAL` to 30 days,
> `BACKUP_INTERVAL` to 24 h, and `BACKUP_REPLICAS` to 2.
>
> The mix holds 278 records each day at about 350 bytes. Over 45 days that is
> 12 510 records and about 4 378 500 bytes. That object needs 135 chunks at the
> `CHUNK_SIZE` of 32 650 bytes. At 2 replicas a full write is 270 cells and
> 8 872 200 bytes, and it occurs one time in 30 days. The amortized cost is
> 295 740 bytes each day.
>
> A delta holds one day of records, which is 97 300 bytes and 3 chunks. At 2
> replicas that is 6 cells and 197 160 bytes each day. The row is 295 740 plus
> 197 160, which is 492 900 bytes.
>
> A restore reads one full object and up to 30 deltas at one replica, which is
> 225 chunks and about 7.39 MB. That cost occurs one time. **[NET-136]** A
> revision that changes one of the four backup constants MUST derive this row
> again.

The message rows above use bucket `B1`. Part 6 §6.9 gives bucket `B0` a text
capacity of 162 bytes. The mix model of this section uses a text of about 350
bytes, which needs bucket `B1`. **That 350-byte figure is unverified.** **[NET-092]** An
implementation MUST measure the text length distribution of a real deployment
before a revision re-tunes the bucket ladder. The padding overhead of 40.8 %
below rests on the same unverified figure, and it carries the same mark.

> *The derivation of the circuit-build rows.* The background pays 10 builds, and
> the model paragraphs above derive that count. The 2 h foreground pays one
> build for each circuit that it opens, because `CIRCUIT_MAX_AGE` of 4 hours
> exceeds the foreground period. The foreground opens 35 circuits. Those are
> the 8 conversation sessions, 2 spare circuits of §3.4.3, and one send
> circuit to each of the 22 recipient relays. The 2 community circuits and one
> attachment circuit complete the count. A `GPOST` to the replica that the
> user reads travels on the group-queue session, thus it opens no circuit of
> its own. The day holds 45 builds. The 135 `EXTEND` cells cost 282 960 bytes
> on the uplink, and the 135 `EXTENDED` cells cost the same on the downlink.

> *The derivation of the two handshake rows.* Each connection of the day pays
> one handshake. The 184 wakes pay 184 handshakes, and a group wake carries
> its two sessions on one connection. The 35 foreground circuits pay at most
> 35 handshakes, because two circuits to one ingress can share a connection.
> The day holds 219 handshakes. The client half is 219 × 2 400 = 525 600
> bytes, and the relay half is 219 × 3 600 = 788 400 bytes.
>
> A resubscription follows each session open. The 184 wakes open 289 sessions,
> and the foreground opens the 8 conversation sessions, which is 297 `B0`
> cells and 166 320 bytes. On a group-queue session the cell is the `GSUB`. A
> send session, a community session, and an attachment session carry no
> subscription.

> *The derivation of the two community rows.* Part 12 §12.3.1 pulls through the
> ordinary chain, and `COM-173` holds one community in each session. The
> `PULL_INTERVAL` of Part 12 §12.9 has a mean of 105 s while the client is
> active. The 2 h foreground gives 7 200 / 105 = 69 pulls for each community,
> which is 138 pulls. A pull request is one `B0` cell, thus the uplink row is
> 138 × 560 = 77 280 bytes. A page that holds the posts since the last pull
> fits bucket `B1`, because 50 posts each day give under one post for each
> pull. The downlink row is 138 × 2 096 = 289 248 bytes.

> *The derivation of the two rotation rows.* Rule `NTF-007` of Part 8 §8.2.5
> rotates the notifier triple of each queue each 7 days. The 16 pairwise
> queues and the 6 group notify queues send at most 22 `NKEY` cells and take
> 22 `NID` cells, which is 12 320 bytes in each direction. The 3 handles
> register again at the Notification Delivery Relay, at about 1 000 bytes
> each. The client registers the new notify queue of each group with each of
> the 2 replicas by a `GNREG` before it drops the old one (Part 8 §8.5.2),
> which is 12 `B0` cells and 6 720 bytes. The week costs 22 040 bytes up and
> 12 320 bytes down. Each day the client half is 3 149 bytes and the relay
> half is 1 760 bytes. A group queue holds no notifier triple of its own, and
> the notify queue holds it.

> *The derivation of the attachment rows.* Part 13 §13.7 sets `CHUNK_SIZE` to
> 32 650 bytes. A file of 400 KB needs 13 chunks, because 12 chunks hold
> 391 800 bytes only. Part 6 §6.9 gives a `B3` cell a wire cost of 32 860 bytes.
>
> **A client uploads one copy, and the relay makes the others.** Part 13 §13.4.1
> gives that flow. The 2 uploads are 2 × 13 = 26 `B3` cells, which is 854 360
> bytes. The `CNEW` traffic is 2 × 13 × 3 = 78 commands, batched 3 to a `B0`
> cell, which is 26 cells and 14 560 bytes. The `CREP` traffic is 26 commands,
> batched 2 to a `B0` cell, which is 13 cells and 7 280 bytes. The `CVFY` sample
> is 4 chunks for each of the 2 replica relays of each file, which is 16 cells
> and 8 960 bytes. The row is 885 160 bytes.
>
> `REPLICAS` stays at 3, and the relay carries the two copies on a direct
> session. Part 13 §13.4.1 gives that traffic as about 504.0 MiB for a 250 MiB
> object, and no row of this table holds it, because no byte of it crosses the
> link of the device. **[NET-104]** A revision that changes `REPLICAS`, the
> verify sample, or the `CREP` batching MUST derive this row again.
>
> A download reads one replica of each chunk, and §13.4 tries a second replica
> only after a failure. The 4 downloads are 52 chunks, which is 1 708 720 bytes.
> The `CID` responses and the `CPRF` responses add 20 and 16 `B0` cells, which
> is 20 160 bytes on the downlink.
>
> An earlier draft made the client write each of the 3 replicas. That row was
> 2 558 166 bytes, which is 2.9 times the row above.
>
> *The derivation of the two sync rows.* The mix holds 278 records each day.
> That count is the 60 direct sends and the 8 group sends, which is 68. It also
> holds the 90 direct receives and the 120 group receives, which is 210. Part 7
> §7.5.3 keeps a peer signal off a sync channel, thus no receipt is in that
> count.
>
> Part 7 §7.5.1 gives a set of *d* devices *d(d − 1)/2* sync channels. Thus each
> device holds *d − 1* channels. The phone sends each record on each of those
> channels, under a full ratchet and on the same bucket ladder. A 350-byte
> record needs bucket `B1`, thus each sync cell costs 2 096 bytes. At 2 devices
> the row is 278 × 1 × 2 096 = 582 688 bytes.
>
> A sync record uses bucket `B1`, thus it does not replace a `B0` cover cell.
> §3.6.2 gives the replacement rule for a `B0` item only, which is an
> acknowledgment, a receipt, or a backup write. Thus a sync record adds a cell to
> the outbound process, and the tier A cover row does not change.
>
> Part 7 §7.5.5 gives the acknowledgment count on one channel each day. That
> count is the batch term plus the idle term. The batch term gives one
> acknowledgment for each completed batch of `SYNC_ACK_BATCH` of 32 records. The
> idle term is 24 h divided by `SYNC_ACK_MAX_DELAY` of 6 h, which is 4.
>
> Each record of the mix enters the device set at the phone. Thus the phone
> takes no record from the laptop. Part 7 §7.5.5 states that a device MUST NOT
> send a sync acknowledgment if no new record arrived. That rule sets the batch
> term and the idle term of the phone to zero, and the uplink row is 0 bytes.
>
> The laptop takes 278 records. Those records complete 8 batches, because
> 8 × 32 = 256 records. The remaining 22 records do not complete a batch, thus
> they fall to the idle term. The batch term of the laptop is 8 and its idle
> term is 4. The downlink row is 1 × (8 + 4) × 560 = 6 720 bytes.
>
> An attachment chunk does not travel on a sync channel. Part 13 §13.3 puts the
> file key and the chunk references in the record, and bucket `B1` holds them.
> Each device that opens an attachment downloads the chunks under Part 13. That
> device pays a download cost of its own, and this table does not hold it.
>
> This count holds the message records only. Part 7 §7.5.3 also syncs the
> mutable state, which is the read markers, the mutes, and the contact names. **[NET-093]** A
> revision MUST count those records.

> *The derivation of the two acknowledgment rows of §3.5.4.* §3.5.4 batches an
> acknowledgment for each queue. That section gives an acknowledgment two
> places. The first place is a scheduled cover slot. The second place is a
> session that the client opened for another cause. §3.6.2 gives tier C no cover
> slot, thus the background client has the second place only. A push wake is
> such a session.
>
> §3.5.4 also discards a held acknowledgment after `RECEIPT_MAX_HOLD` of
> 3 600 s. The 184 wakes come about 274 s apart, and that period is inside
> `RECEIPT_MAX_HOLD`. Thus the client emits each background acknowledgment in a
> push wake, and no background acknowledgment reaches the foreground.
>
> A background acknowledgment is a `B0` cell at 560 bytes. §3.6.2 gives tier C
> no cover cell, thus no cover cell absorbs it. Each wake drains one queue,
> thus each wake sends one acknowledgment. In a group wake that queue is the
> notify queue, because a group queue takes no reader acknowledgment under
> `NET-235`. The uplink row is 184 × 560 = 103 040 bytes. A wake that drains two queues of one session sends two, and
> `WAKE_COALESCE_WINDOW` makes such a wake rare.
>
> **That cell count is unverified.** **[NET-094]** An implementation MUST measure the queue
> spread of the drains in a real deployment before a revision re-tunes this row.
> The foreground row stays at 0 bytes. §3.6.2 gives tier A a cover slot, and a
> `B0` item replaces the cover cell of that slot.

> *The scaling rule for a set of d devices.* The cost for one device grows with
> *d − 1*. For *r* records each day, the device that first holds a record sends
> *r × (d − 1)* cells. Each other device takes *r* cells. If each device
> originates *r* records, the whole set sends *d × r × (d − 1)* cells each day.
>
> At `MAX_DEVICES` of 8 the sync record row is 278 × 7 × 2 096 = 4 078 816
> bytes, which is about 4.08 MB. The phone still takes no sync record, thus the
> uplink acknowledgment row stays at 0 bytes. Each of the 7 peers takes 278
> records and returns 8 + 4 = 12 acknowledgments. Thus the downlink row is
> 7 × 12 × 560 = 47 040 bytes. The ownership claim rows also grow with *d* − 1.
> The phone sends 4 claims on each of its 7 channels, which is 28 × 8 240 =
> 230 720 bytes, and it takes 4 from each of its 7 peers for the same figure.
> The uplink total is then about 7.29 MB, and the downlink total is about
> 9.12 MB.

| Downlink | |
| --- | --- |
| 1:1 receives (90 `B1` cells) | 189 KB |
| Group receives (120 `B1` cells, on the group-queue sessions) | 252 KB |
| Group notify digests (120 `B0` cells, Part 8 §8.5.2) | 67 KB |
| Epoch rotations as a member (6 groups × 1 `B3` cell each day) | 197 KB |
| Attachment download (4 files, 52 chunks) | 1 709 KB |
| Device-set sync acknowledgments (1 channel, 12 cells) | 7 KB |
| Attachment registration and verify responses (36 cells) | 20 KB |
| Ownership claims (1 channel, 4 `B2` cells) | 33 KB |
| Loop returns (72 `B0` cells) | 40 KB |
| Relay-paced inbound cover (7 752 `B0` cells) | 4 341 KB |
| Circuit builds, the `EXTENDED` cells (45 builds × 3 `B1` cells) | 283 KB |
| Transport handshakes, the relay half (219 × 3 600 B) | 788 KB |
| Relay entries with proofs (90 × 5 818 B) | 524 KB |
| Directory (8 `DirectoryRoot` objects and 8 `RelaySetDiff` objects) | 142 KB |
| Community pages (138 `B1` cells) | 289 KB |
| Notifier rotation, the relay half (Part 8 §8.2.5) | 2 KB |
| Family certificates (Part 10 rule `REL-138`) | 0 KB |
| **Total down** | **≈ 8.88 MB** |

> *The derivation of the two cover rows.* §3.6.2 makes about 20 % of the 360
> tier A cover cells loops. That count is 72 cells, which is 40 320 B.
>
> §3.9 gives `PACING_MEAN` as 1 s. The 2 h foreground session holds 7 200
> ticks. Of those ticks 26 carry a real message, which is the 210 daily receives
> scaled by 2 h of 16 waking hours. The other 7 174 ticks carry cover.
>
> The 184 wakes open 289 sessions, and each session holds about 3 s, which is
> 867 more ticks. Of those ticks 289 carry a real delivery, which is the 184
> remaining receives and the 105 digests, and 578 carry cover. The two cover
> counts total 7 752 cells, which is 4 341 120 B.
>
> The foreground count holds one held session at a time. A client that holds
> each of its 9 sessions in the foreground takes 9 × 7 200 ticks, which is
> 36.3 MB each day. No rule of this specification makes a client hold each
> session, and the model holds one. A revision that holds more sessions in the
> foreground has to derive this row again.

> *The derivation of the entry row.* The model paragraphs above give 2 entries
> for each build in Instant mode. The 10 background builds fetch 20 entries. The
> 35 foreground builds fetch 70 entries. Each foreground circuit selects a fresh
> hop 2, and it reaches a hop 3 whose entry the client verifies against the root
> of that period. The day holds 90 entries, which is 90 × 5 818 = 523 620
> bytes. Part 10 rule `REL-059` names this row.

> *The derivation of the directory row.* Part 10 §10.11 gives the consensus a
> validity of 3 hours, thus a client verifies at most 8 consensus objects each
> day. Part 10 §10.5.2 gives a `DirectoryRoot` 16 665 bytes at the 5-signature
> minimum. The 8 fetches are 133 320 bytes. Part 10 §10.5.3 gives a
> `RelaySetDiff` 1 029 bytes at 3 000 relays and 8 changes, thus the 8 diffs add
> 8 232 bytes. The row is 141 552 bytes. An earlier draft added an amortized
> weekly manifest of about 21 KB each day. Part 10 §10.5 carries the manifest on
> a bootstrap carrier and not on this row. The entry fetches sit in their own
> row above. **[NET-105]** A revision that changes the signature count, the
> validity, or the diff width MUST derive this row again.

**The grand total is about 12.48 MB each day and about 374 MB each month. For
text only, the total is about 9.86 MB each day and about 296 MB each month.**
The grand total is 3.59 MB up and 8.88 MB down. The text-only total removes the
885 KB of attachment upload, the 1 709 KB of attachment download, and the 20 KB
of attachment responses. An earlier draft gave 13.07 MB each day, of which
4.08 MB was uplink. The group queue of §3.2.7 removes the 402 KB fan-out row
and 11 of the 20 sessions, and it adds the digest row, the rotation row, and
the presence row. The day falls by about 0.6 MB.

At `MAX_DEVICES` of 8 the grand total is about 16.41 MB each day and about
492 MB each month. **A device set at `MAX_DEVICES` is not affordable on a
metered mobile plan, and this section states that plainly.** The sync record row
alone is 4.08 MB each day. That row is about 1.5 times the 2.71 MB text-only
uplink of the 2-device day. No usability goal of Part 2 §2.4 caps a monthly
total, thus no goal forbids that figure. This specification states the cost, and
it does not claim that a user can pay it. The cost grows with *d − 1*. Thus a
revision that wants 8 devices at this message volume has to change the sync
topology. A revision can also lower `MAX_DEVICES`.

**The pacing rule blocks that row before the bandwidth does.** Part 7 §7.5.1
paces a sync record from the cover clock, and §3.6.2 gives a 2 h tier A session
360 cover-clock slots. At 8 devices the sync record row is 278 × 7 = 1 946 `B1`
cells each day, and that row needs 1 946 slots. The session holds 360 slots,
thus the row is not schedulable under the present pacing rule. At 2 devices the
278 sync cells take 278 / 360 = 77 percent of those slots already. **[NET-095]** Thus a
revision MUST change the pacing rule, the foreground time of the model, or the
sync topology before it raises the device count.

U4 measures idle background data, and the grand total is not that quantity. In
tier C the client makes no cover cell and fetches no scheduled directory diff.
The table below holds the background subset of the two tables above. Its rows
are the transport handshakes, the resubscriptions, the circuit builds, the
relay entries, the drains, and the pacing cover of the wake sessions. The
table also holds the sync acknowledgments, the acknowledgments of the drains,
the ownership claims, the directory objects, the notifier rotation, and the
family certificates. Part 4 §4.7.2 makes a backup write a foreground
operation, thus no backup row is in this table.

The table gives three columns, one for each wake count of Part 8 §8.3. Instant
mode wakes at each of the 184 background arrivals, and each wake opens the
session that the push names, and after a digest the group-queue session too.
Private mode wakes on a fixed clock, and the push names no session. A client in
Private mode registers no notify queue (Part 8 §8.5.2), thus each wake opens
each of the 8 conversation sessions, and the digest row is 0. At the 30 min
cadence that is 48 × 8 = 384 session opens, and at the 20 min cadence it is
72 × 8 = 576. Each session open costs one handshake, one resubscription, and 3
pacing ticks. The 184 drains do not change, because an arrival does not depend
on the cadence. In Private mode the client acknowledges the 79 pairwise drains
only, because a group queue takes no reader acknowledgment. Private mode
renews each of the 8 circuits at each `CIRCUIT_MAX_AGE` of 4 hours, which is
48 builds each day. It fetches 48 hop 2 entries and 8 × 8 = 64 hop 3 entries.

| Idle background component, bytes each day | Instant, 184 wakes | Private, 48 wakes | Private, 72 wakes |
| --- | --- | --- | --- |
| Transport handshakes (6 000 B each) | 184 × 6 000 = 1 104 000 | 384 × 6 000 = 2 304 000 | 576 × 6 000 = 3 456 000 |
| Session resubscriptions (`B0`) | 289 × 560 = 161 840 | 384 × 560 = 215 040 | 576 × 560 = 322 560 |
| Circuit builds (6 `B1` cells each, §3.4.3) | 10 × 12 576 = 125 760 | 48 × 12 576 = 603 648 | 48 × 12 576 = 603 648 |
| Relay entries with proofs (Part 10 §10.5.3) | 20 × 5 818 = 116 360 | 112 × 5 818 = 651 616 | 112 × 5 818 = 651 616 |
| Push-wake drains (`B1`) | 184 × 2 096 = 385 664 | 184 × 2 096 = 385 664 | 184 × 2 096 = 385 664 |
| Group notify digests (`B0`, Part 8 §8.5.2) | 105 × 560 = 58 800 | 0 | 0 |
| Pacing cover in the wake sessions (`B0`) | 578 × 560 = 323 680 | 968 × 560 = 542 080 | 1 544 × 560 = 864 640 |
| Sync acknowledgments (Part 7 §7.5.5) | 12 × 560 = 6 720 | 6 720 | 6 720 |
| Acknowledgments of the drains (§3.5.4) | 184 × 560 = 103 040 | 79 × 560 = 44 240 | 79 × 560 = 44 240 |
| Ownership claims, sent and taken (Part 7 §7.3.1) | 8 × 8 240 = 65 920 | 65 920 | 65 920 |
| Directory, 8 roots and 8 diffs (Part 10 §10.5) | 141 552 | 141 552 | 141 552 |
| Notifier rotation (Part 8 §8.2.5) | 4 909 | 4 909 | 4 909 |
| Family certificates (Part 10 rule `REL-138`) | 0 | 0 | 0 |
| **Total each day** | **2 598 245** | **4 965 389** | **6 547 469** |
| **Total each month** | **77.95 MB** | **148.96 MB** | **196.42 MB** |

The Instant month is 2 598 245 × 30 = 77 947 350 bytes, which is about
**77.95 MB**. That figure is inside the U4 limit of 100 MB each month, and the
margin is about 22 percent. The transport handshake row is 42 percent of the
Instant day, and the seven wake rows together are 88 percent of it. **The
per-relay session of NET-023 and NET-266 is the cause of that limit of 100 MB,
and Part 2 §2.4 states the trade.** An earlier draft of this table modeled
88.30 MB over 20 sessions, and the group queue of §3.2.7 removes 11 of them. A
draft before that modeled 22.88 MB against a limit of 25 MB. That draft
asserted 30 wakes, priced a build at 7 104 bytes, and held no handshake row
and no entry row.

**[NET-096]** A revision that changes one of the inputs below MUST derive this
table again. The model inputs are the background arrival count, the queue-relay
count, the group-queue relay count, the session count of a wake, the wake
session length, the queue spread, and the transport handshake figure. The
constant inputs are `WAKE_COALESCE_WINDOW`, `CIRCUIT_MAX_AGE`,
`SESSION_RESUME_WINDOW`, `PACING_MEAN`, `CONSENSUS_VALIDITY`, `GROUP_REPLICAS`,
the signature count of a `DirectoryRoot`, the `RelayEntry` width, and
`OWNER_CLAIM_RATE`.

**Private notifications.** The two Private columns are about **148.96 MB** at
30 min and about **196.42 MB** at 20 min. Goal U4b of Part 2 §2.4 sets no target
for that mode in this draft, and it states those two figures. The cause is the
session model of NET-023 and NET-266. A fixed-clock push names no queue, thus a
Private wake opens each of the 8 sessions. The handshake row alone is then
2.30 MB or 3.46 MB each day. An earlier draft of this table gave 350.31 MB and
468.96 MB over 20 sessions. A revision that lets one wake reach each queue of
the client over one session changes that row, and that revision sets the U4b
target. Part 8 §8.2.6 adds a rendezvous drain for a published handle, and that
drain is outside this table.

The sync record row is not in that count, and a schedule rule is the cause. Part
7 §7.5.1 paces a sync record from the cover clock. §3.6.2 gives tier C no cover
clock, thus a background client has no scheduled send opportunity for a sync
record. The phone then holds a sync record until the next foreground session,
and the 583 KB uplink row falls in the foreground.

That cause covers the sync record row only. The two sync acknowledgment rows do
fall in the background, and the table above counts both of them. The uplink row
is 0 cells and the downlink row is 12 cells. The rule below permits a control
record in a push-wake session, and the sync acknowledgment is a control record.

**[NET-097]** **A client MUST NOT carry a conversation record on a sync channel
in a push-wake session.** U4 then loses its margin, and the arithmetic below
gives that result. Part 7 §7.5.3 gives the class of each record. **[NET-098]** A
client MAY carry a control record of that section in such a session. The sync
acknowledgment is a control record, thus convergence signaling continues in the
background. Part 10 rule `REL-078` also permits one `LinkFaultReport` in such a
session, and `REL-107` bounds it to one.

The arithmetic below gives the loss that the rule prevents. Of the 210 daily
receives, 184 arrive in the push wakes. If a client carried those records at 2
devices, they cost 184 × 1 × 2 096 = 385 664 bytes each day. The idle background
then reaches 2 598 245 + 385 664 = 2 983 909 bytes each day. That is about
**89.52 MB each month**, which leaves a margin of 10.5 percent. At 3 devices
the records cost 771 328 bytes each day, and the month is about **101.09 MB**,
which is 1.01 times the U4 limit. **Thus a client that syncs in the background
fails U4 at 3 devices, and it holds U4 at 2 devices with half of its margin.**

At `MAX_DEVICES` of 8 the same records cost 184 × 7 × 2 096 = 2 699 648 bytes
each day. The idle background then reaches 2 598 245 + 2 699 648 = 5 297 893
bytes each day. That is about **158.94 MB each month**, which is 1.6 times the
U4 limit. **U4 keeps its margin at each device count only because the rule above
keeps the sync records in the foreground.**

That rule has a cost, and this section states it. A peer device gets a
background receive at the next foreground session of the phone, and not sooner.
A user who reads on the laptop while the phone is in the background sees that
delay.

**[NET-099]** **A client MUST NOT build a spare circuit in a push-wake session.** §3.4.3 keeps
2 spare circuits for a rotation that would block a send. A push-wake session
carries a drain and an acknowledgment, and no interactive send waits on a
rotation. Thus one circuit is sufficient for a wake.

The arithmetic below gives the cost that this rule prevents. With 2 spares at
each build the circuit-build row is 30 × 12 576 = 377 280 bytes each day. The
entry row is 60 × 5 818 = 349 080 bytes. The idle background then reaches
3 082 485 bytes each day and about **92.47 MB each month**, which leaves U4 a
margin of 7.5 percent in the place of 22 percent. Under the earlier table of
20 sessions the same spares took the month to 136.24 MB, which failed U4. The
group queue of §3.2.7 lowers the build count, and the rule stays, because a
spare circuit buys a wake nothing.

**[NET-100]** **A client MUST NOT hold a push-wake session longer than 6 s,
because U4 then fails.** U4 permits 100 000 000 bytes each month, which is about
3 333 333 bytes each day. At a session length *W* the 289 session opens of the
184 wakes give 289 × *W* pacing ticks. Of those ticks 289 carry a real
delivery, and each other tick carries a `B0` cover cell.

Twelve rows of the Instant column do not change with *W*. Those rows are each
row above except the pacing cover, and their total is 2 274 565 bytes each
day:

```
2 274 565 + (W − 1) × 289 × 560 ≤ 3 333 333     gives   W ≤ 7.54 s

W = 6 s → 1 445 cover cells → 3 083 765 bytes each day →  92.51 MB each month   holds
W = 7 s → 1 734 cover cells → 3 245 605 bytes each day →  97.37 MB each month   holds
W = 8 s → 2 023 cover cells → 3 407 445 bytes each day → 102.22 MB each month   fails
```

The rule keeps the 6 s of the earlier table, which derived a bound of 6.78 s
over 20 sessions. The session-open count of a wake is an unverified input
under `NET-096` and `NET-273`, and the 1.5 s between the rule and the bound is
the margin that such an input needs. Part 8 §8.4.1 gives the same 6 s for the
Android service. A group wake holds its two sessions on one connection, and
the rule bounds each session.

That test counts each row of the table above. Thus 6 s is a ceiling, and it is
not the operating point. The model above uses a session of 3 s, and the table
above measures that session. The push blob of Part 8 §8.2.2 carries
`waiting_count`, thus a client can close the wake after the last expected
drain and its acknowledgment. The test also uses the 184 wakes of Instant mode,
and the two Private columns give their own figures.

The privacy mode of §3.9 does not change the cover component (§3.6.2) or the
inbound pacing (§3.9), thus the three privacy modes carry the same daily budget.
That statement covers Fast mode, Balanced mode, and Private mode of §3.9. It
does not cover the notification modes of Part 8 §8.3, which set the wake count.

### Padding overhead

The mix is 80 % text at about 350 B of useful data and 5 % PQ-heavy ratchet at
about 1 500 B. The mix also has 5 % preview at about 6 000 B and 10 % attachment
chunk at about 32 000 B:

| Design | Mean wire for each message | Overhead |
|---|---|---|
| **UMBRA ladder (512 / 2 K / 8 K / 32 K)** | 5 427 B | **40.8 %** |
| Uniform 16 KiB block (SimpleX) | 18 022 B | **368 %** |

The text row uses bucket `B1`, because a 350-byte text does not fit `B0`. The
ladder mean is 0.80 × 2 048 + 0.05 × 2 048 + 0.05 × 8 192 + 0.10 × 32 768 =
5 427 B. The uniform mean is 0.90 × 16 384 + 0.10 × 32 768 = 18 022 B, because a
32 000-byte chunk needs two blocks. The useful mean is 0.80 × 350 + 0.05 ×
1 500 + 0.05 × 6 000 + 0.10 × 32 000 = 3 855 B. The two overhead figures are
5 427 / 3 855 and 18 022 / 3 855.

For a group, one text record costs each reader one download, and the tag
vector of Part 11 §11.3.3 sets its bucket. A 500-member record is **8 240 B**
at `B2` with the ladder and **16 454 B** with a uniform block. A 25-member
record is **2 096 B** at `B1` with the ladder and the same 16 454 B with a
uniform block (§3.3.1). The 120 group receives of the model day cost 252 KB
with the ladder and 1.97 MB with a uniform block. This difference decides if
the group feature operates on mobile data.

### Latency

UMBRA uses LAMP-style latency-bounded relay selection. The propagation times are
these:

- Client to ingress: about 60 ms
- Ingress to middle: about 75 ms
- Middle to queue: about 75 ms

The total is about **210 ms of propagation** in each direction, and **420 ms**
for the send leg and the delivery leg together.

> **Deviation note.** An earlier draft gave the three legs 30 ms, 40 ms, and
> 40 ms, which is 220 ms for the two legs. No measurement supports that model.
> §3.4.6 makes a chain cross three operators, three jurisdiction blocs, three
> autonomous systems, and three IPv4 /16 prefixes. Those four invariants force a
> geographic spread, thus a conformant chain is longer than a shortest path. The
> figures above are a model and not a measurement. **[NET-137]** An
> implementation MUST measure the propagation of a real relay population before
> a release, and it MUST derive the two tables of §3.9 again.

| Mode | Mixing | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Fast | Inbound pacing | ~1.1 s | ~3.4 s | ~5.0 s |
| **Balanced** | Erlang(3, 150 ms) + inbound pacing | **~1.6 s** | **~3.9 s** | **~5.5 s** |
| Private | Erlang(3, 700 ms) + inbound pacing | ~3.3 s | ~6.5 s | ~8.3 s |

Each row is the quantile of one sum. That sum is 420 ms of propagation, an
Erlang(3) per-hop delay from §3.9, and one exponential pacing wait with a mean
of `PACING_MEAN`. **[NET-138]** A revision MUST take a quantile of the sum, and
it MUST NOT add the quantile of each term. The p95 of a sum is below the sum of
the three p95 values, because the three terms do not reach their tails together.

A cold start with no live circuit adds one 3-RTT telescoped build. This build
costs about +810 ms of propagation and less than 2 ms of computation. The three
round trips reach hop 1, then hop 2, then hop 3, which is 2 × 60 + 2 × 135 +
2 × 210 ms against the leg model above. Two spare circuits (§3.4.3) keep this
cost off the common path.

The mean added delay is 1.42 s in Fast mode, 1.87 s in Balanced mode, and 3.52 s
in Private mode. The first two are in the measured band of §3.0, where 1 s and
4 s keep usability. Private mode is above 1 s and below the marginal point of
7 s.

### The pacing clock sets the latency floor and the data floor together

This section states one link that no other section holds in one place.
`PACING_MEAN` of §3.9 is the largest term of the p50 above, and it is the
largest row of the downlink budget of this section.

| `PACING_MEAN` | Median pacing wait | Balanced p50 | Ticks in a 2 h session | Downlink cover |
| --- | --- | --- | --- | --- |
| 0.5 s | 347 ms | ~1.2 s | 14 400 | 8.06 MB |
| **1.0 s** | **693 ms** | **~1.6 s** | **7 200** | **4.03 MB** |
| 1.9 s | 1 317 ms | ~2.3 s | 3 789 | 2.12 MB |

The median wait of an exponential clock is `ln(2)` times its mean. The tick
count of a session is the session length divided by the mean, and each tick
costs one `B0` cell at 560 bytes (Part 6 §6.9).

- **[NET-139]** A revision that changes `PACING_MEAN` MUST derive the U2 target
  of Part 2 §2.4 again. **[NET-140]** That revision MUST also derive the U4
  budget of §3.12 again.
- **[NET-141]** That revision MUST state the change against goal G6 and goal G7
  of Part 2 §2.3. NET-035 and NET-036 make the delivery schedule independent of
  the arrival times, and the mean is the strength of that measure.

> *Cause.* An earlier draft set `PACING_MEAN` in §3.9, gave the latency table in
> this section, and gave the cover row in the downlink table above. No sentence
> said that one constant moves the three. NET-079 already caps the mean at
> 1.9 s against the usability band, and the row above gives the data cost of
> that cap.

### Battery

The comparison uses the U5 battery, which is 4 000 mAh at 3.85 V, which is
15.4 Wh. The radio duty cycle is the largest component, at 18 s or more of
elevated draw for each transfer. §3.6.2 derives about 9.1 mWh for each radio
promotion. U5 measures the idle background, thus the tier A cover of the
foreground is not in this table.

| Notification mode (Part 8 §8.3) | Radio promotions each day | Energy | Share |
| --- | --- | --- | --- |
| **Instant, no arrival** | **0** | **0 Wh** | **0 %** |
| Instant, the model day of 184 arrivals | 184 | 1.67 Wh | 10.9 % |
| Private, at a 30 min interval | 48 | 0.44 Wh | 2.8 % |
| Private, at a 20 min interval | 72 | 0.66 Wh | 4.3 % |
| Client compute, in each mode | — | 0.02 Wh | 0.1 % |

Part 8 §8.3 gives the wake cadence of each mode. Instant mode wakes on an
arrival, thus its count is the arrival count of the day. With no arrival the
client opens no session, because NET-067 forbids a session for a directory diff
alone and tier C holds no cover clock. Private mode wakes on a fixed clock,
thus its count is 24 h divided by the interval. The energy of a row is the
promotion count times 9.1 mWh. The share is that energy divided by 15.4 Wh.
The Instant arithmetic is 184 × 9.1 mWh = 1.67 Wh, and 1.67 / 15.4 = 10.9 %.

**U5 has two terms, and Instant mode meets both.** Part 2 §2.4 permits 2 % with
no arrival and 10 mWh for each background arrival. Instant mode spends 0 % with
no arrival and 9.1 mWh for each arrival. Part 2 §2.4 scopes U5 to Instant
notifications, thus U5 does not measure the two Private rows. An earlier draft
gave Instant mode 30 promotions and 1.8 %, and it stated that Private mode
costs more battery than Instant mode. This draft withdraws that statement.

**The cheaper mode depends on the arrival count.** Instant mode pays one
promotion for each arrival, and Private mode pays one for each interval. Thus
Private mode at 30 min costs less battery than Instant mode above 48 arrivals
each day. Private mode at 20 min costs less above 72. The model day of 184
arrivals is above both counts, thus Private mode is the cheaper mode on that
day. The user who receives 20 messages each day sees the opposite order.

**Client compute.** The compute row holds the 45 circuit builds at less than 2
ms each, the ratchet steps of the 278 records, the tag checks of the 120 group
records, and the 6 decapsulations of the rotation slots (Part 11 §11.4.2). It
holds the signature verifications of the 8 roots and the 90 entries. It holds
about 10 Argon2id
unlocks of Part 15 §15.6.4 at about 3 s each. That work is under 1 minute of CPU
each day. At about 1 W of CPU draw it is about 0.02 Wh, which is 0.1 % of the
battery. That figure is a model, and the measure rule below covers it.

**[NET-101]** **Implementations MUST measure this cost on real handsets with a power monitor
before a release.** The duty-cycle model is derived, and no party measured it on
2026 hardware. The conformance test for U5 uses stock Android *and* GrapheneOS.
This test exists because the drain of 35 % in 10 h of SimpleX occurred on
GrapheneOS only, and stock devices did not show it.

### Client storage

No usability goal caps the client store, and this table states the model
figure. Each figure is a model and not a measurement.

| Store component | Basis | Size |
| --- | --- | --- |
| Message records | 278 records each day at about 1 KB with the index, over 365 days | about 100 MB each year |
| Attachments | 6 files each day at about 400 KB, over 365 days | about 880 MB each year |
| Ratchet state | 16 pairwise channels and 1 sync channel at about 3 KB each | under 0.1 MB |
| Group state | 6 groups of 25 members: the roster entry, the pair key, and the KEM key of each member at about 1.4 KB (Part 11 §11.9.1), and the slot-chain state of each group | about 0.2 MB |
| Relay entries | The entries of the 9 session relays, the 6 second replicas, the 16 recipient relays, and the ingress pins | about 0.2 MB |
| Directory objects | One `DirectoryRoot`, one `RelaySetDiff`, and the tree of 3 000 leaves | about 0.2 MB |
| Skipped keys and cursors | `SKIP_TTL` of Part 5 §5.5.4, one cursor for each queue, and one cursor for each replica of each group queue | under 0.1 MB |

The message store grows with the record count, and the attachment store grows
with the file count. A record holds the 350-byte text, the ratchet metadata,
the read marker, and the index entry. Part 4 §4.8 keeps 45 days in the backup,
and the local store keeps each record until the user deletes it. A client that
keeps one year of the model day holds about 1 GB, and the attachments are about
90 % of that figure. The retained records of a group queue are a relay cost and
not a client cost, and §3.2.7 bounds them at `GROUP_QUEUE_QUOTA` for each
group queue and at `GROUP_RETENTION` in time.
