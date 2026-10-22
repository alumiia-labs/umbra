# UMBRA Protocol Specification — Part 15: Security Considerations and Known Limitations

**Status:** Draft
**Version:** 0.42.2
**Date:** 2026-10-21

---

## 15.0 The finding that gives this part its structure

> **No "secure messenger" that has fallen since 2020 was broken by
> cryptanalysis.**

EncroChat, Sky ECC, ANOM, and Exclu were all broken by three non-cryptographic
items:

1. **The infrastructure was central, in one jurisdiction.**
2. **The party that broke them controlled the software distribution channel and
   the update channel.**
3. **The operator held a key.**

The architecture of UMBRA removes item 3 fully. It mitigates item 1 in a
substantial manner, through the operator-disjointness invariant and the
jurisdiction-disjointness invariant of Part 3 §3.4.6 and Part 10 §10.6. It does
**nothing** about item 2 in v1, and §15.5 states that limit.

**The update channel is the largest compromise vector of UMBRA.** It is not a
protocol problem, and that property is the cause that a project can
under-invest in it. §15.5 states what v1 does about it.

## 15.1 The Compellable Set

This section is the normative answer to goal G13. For each party it gives what
that party holds, for how long, and what that party gives under legal process.

**Each row that is not "nothing that identifies a user" is a design bug, and the
project tracks it as one.**

| Party | Holds | Retention | Gives under EPO / s.121 / TCN / RIPA s.49 / grand-jury subpoena |
| --- | --- | --- | --- |
| **Client device** | All the data: the root identity, the contacts, the history, the keys, and the spent-nonce set of the hellos of Part 13 §13.4 | Until a wipe | All the data, if the device is unlocked. Under RIPA s.49, or under French art. 434-15-2, a court can compel the **user** to decrypt. **UMBRA cannot help here.** |
| **Ingress relay** | The client IP address, the connection times, the cell counts, and the cell sizes. The count of the circuits of the client, and the hop 1 key set of each live circuit. The circuit count bounds the count of the groups that the user reads from above (Part 3 §3.11). The client class of Part 3 §3.8.1 joins this row when the deferred web client ships. That key set opens the hop 1 layer of a recorded cell, which gives the hop 2 ciphertext (Part 3 §3.4.4) | A conformant relay keeps the connection lifetime. A malicious or compelled relay can log for an unlimited period. A client pins two ingress relays, and each pin lasts 60 days confirmed and 120 days unconfirmed (Part 10 §10.6.1). Thus a prospective order against either operator captures that client for that period. | An IP address that ran UMBRA at the time T, and how many circuits it held. Not the party, not the destination, and not the content. In a provisional network of Part 3 rule `NET-340` the operator of the ingress relay runs the queue relay too. That operator gives the address joined to the queue (§15.3). |
| **Chain relay** | Two adjacent relay addresses, the cell times, and the hop 2 key set of each live circuit. That key set opens the hop 2 layer of a recorded cell, which gives the hop 3 ciphertext | In memory only | Nothing that identifies a user. |
| **Queue relay** | Queue IDs, ciphertext, delivery times, a per-queue sequence counter, the last acknowledged sequence, and a maximum of 8 queues for each session. In Instant mode its store holds, for each registered queue, the notifier credential and the notification binding of Part 8 §8.2.3. The binding is `k_ntf_root`, the handle, `k_tok`, the queue alias, and the relay index (Part 3 rule `NET-300`). It holds the private half of its `UMBRA-KEM` notification key (Part 8 rules `NTF-112` and `NTF-129`). It holds each invitation with its blob and its lock key (Part 4 §4.3.1). The hop 3 key set of a live circuit opens no recorded cell. Part 3 §3.4.4 rule `NET-208` erases each key set after its cell | `MSG_TTL` 45 d, `QUEUE_IDLE_TTL` 60 d. A relay destroys the sequence counter with the queue, and a `DEL` destroys the queue record (Part 6 §6.4.3). The triple rotates each 7 d under `NTF-007` | A set of random 32-byte identifiers, and ciphertext that the two endpoints of the channel alone can decrypt. In Instant mode, the binding of each registered queue and its notification times (Part 8 §8.7). The binding names the notification handle of at most 8 queues, and with the NDR it gives the push token of that handle. Its `k_ntf_root` opens each notification blob of that queue until the rotation of `NTF-007`. A blob holds a queue alias, a count, and a time, and no content. An invitation blob that waits is ciphertext under a key of the link fragment, which the relay never holds. A relay does not hold a device-set acknowledgment point. Part 7 §7.5.5 makes that acknowledgment an application record inside the L6 AEAD. Thus it is one `B0` cell on a sync queue. It reads as any other sync record. |
| **Group-queue relay** | The `GroupQueueId`, the three public credentials of the group queue and the two superseded ones under grace, the retained records, the count of live reader sessions and writer sessions, and the notify registrations of Part 8 §8.5.2. No membership list, no member index, and no identity (Part 3 §3.2.7) | `GROUP_RETENTION` 30 d for a record, `GROUP_IDLE_TTL` 60 d for the queue, `GROUP_READ_GRACE` 30 d and `GROUP_WRITE_GRACE` 24 h for a superseded credential. A registration lives 7 d plus `CLOCK_SKEW` in memory, at most `GROUP_NOTIFIER_MAX` for each queue | 30 days of ciphertext that the members alone can decrypt, the session counts at the time of the order, the member count of the group at each retained rotation from the slot count of the epoch-key record, and the `relay_id` of each registered notify queue. No member, no sender, and no content |
| **Attachment relay** | Opaque chunks of one fixed size, under a random credential for each chunk. Part 12 §12.7 gives `CHUNK_SIZE`. The same store holds the backup objects of Part 4 §4.7.2 under a rotating handle | `CHUNK_TTL` 14 d for a chunk, `CHUNK_LIFE_MAX` 28 d for a chunk that a reader renews, `BACKUP_TTL` 180 d for a backup object | Opaque chunks. It cannot link a chunk to a file or to a user. A backup object is ciphertext under a key that the two halves of the Recovery Code give |
| **Notification relay (NDR)** | Stored `(handle, ct_token)` pairs. In Instant mode it holds `k_tok` and the token-to-handle mapping in memory at the dispatch. A deployment can operate its own NDR (Part 8 §8.7), thus no one NDR sees each dispatch | The stored handles rotate each 7 d. A malicious or compelled NDR can log the dispatch mappings prospectively. | A subpoena for "all push tokens" returns encrypted blobs. Prospective logging, a wiretap, or collusion with a relay recovers the token-to-queue mapping. |
| **Directory authorities** | Relay descriptors, class measurements, aggregates with added noise, and the signed operator dossier of each relay (Part 10 §10.6) | The consensus history. The dossier while the relay is listed | Nothing about a user. The legal entity, the beneficial-control declaration, the ASN, the jurisdiction, and the legal-process contact of each relay operator. Part 3 §3.10.1 makes the dossier a public record |
| **Handle directory**, which is the OPRF evaluator | Handle strings, rotatable handle keys, and rotatable rendezvous addresses. The blinded element of each OPRF evaluation, the token or the proof of work that paid for it, and the connection time of each lookup | The entries until a rotation. A conformant directory keeps no query log. A compelled directory can log each blinded query from the moment of the order | The handle list, which §9.3 makes worthless deliberately. A prospective log of blinded queries, which names no handle, because the directory never sees the plaintext (Part 9 §9.4) |
| **Queue relay of a rendezvous queue** | The queue address of a published handle or address, which any party that resolves the entry can name. The arrival time and the count of each hello | Until the rotation of `RENDEZVOUS_ROTATE` (Part 9 §9.9) | That a published entry received hellos at the times T. Nothing about a sender, because a hello is a padded message under the key of the entry (Part 9 §9.6) |
| **Token issuer** | The payment record of each purchase on path 1 of Part 13 §13.9, the batch count on each path, and the issuer keys | The payment processor defines the payment record. The keys rotate each 7 d | Who paid for a token batch, and when. Nothing about where a token was spent, because the signature is blind (Part 13 §13.3.3) |
| **A social-recovery share holder** | One Shamir share of `C_social` (Part 4 §4.7.3) | Until the user replaces the share set | One share. Three share holders reconstruct `C_social`, and that half alone opens nothing. Part 4 §4.7.1 splits the Recovery Code, and `C_user` stays with the user or in the platform-cloud item of `IDN-042` |
| **A platform-cloud item that holds `C_user`** | `C_user` only, and the user opts in (Part 4 §4.7.1) | The provider defines it | The user half of the Recovery Code. That half alone opens nothing, and `IDN-086` keeps a `C_social` share out of the same item |
| **A moderator or an owner of a private group** | The group history on that device, the `GroupRosterKey_g` of that group, and the granting chain that Part 11 §11.9.3 bounds | Until a wipe | The power to publish a signed moderation epoch that hides or removes a message on the device of each member. **This party is a named natural person, and Part 11 §11.9.6 creates it deliberately.** That section gives the four mitigations and states the residual |
| **The project** | The data that its own relays hold, from the rows above | As above | **No user database, because no user database exists.** There is no account, no registration, no phone number, no email address, and no global identifier. |
| **Google (FCM)** | The mapping from a device push token to an account. The wake times and the wake count. Each push has one form and one expiry (Part 8 rule `NTF-086`), thus not which wake is a group message. A client in Direct mode, in Private mode, or in Off mode holds no push token. A device with no FCM takes its wakes from the socket and the poll of Part 8 §8.4.1. Each gives Google nothing | The provider defines it | Which accounts have UMBRA installed in Instant mode under FCM, and at what times UMBRA woke them. Over many wakes, those times link two accounts that write to each other. **Treat this mapping as adversarial.** |
| **Platform cloud services (backup and sync)** | No UMBRA data, under Part 14 §14.6.6. A file that the user saved to the media store, and a screenshot | The provider defines it | Part 2 §2.2 models this party as A7. The platform backup carries no container of the client, because `IMP-048` excludes it. A saved file is a user action, and `IMP-046` warns before the first one |
| **Invitation host** | The time and the client address of each browser open of an invitation link, without the fragment | The project defines it | Part 4 §4.3.1. A device with the client opens no browser, thus the host sees an open by a party without the client only. The host cannot read the fragment, because a browser does not send it |
| **App stores, and extension stores when the deferred web client ships** | The legal identity of the developer, the registration of the signing key, and then the listing of the web extension | Permanent | The power to remove or replace the application, or the extension, in a jurisdiction. Refer to §15.5 and §15.2.9. |
| **Build infrastructure** | The release signing authority | Permanent | **The power to ship a malicious update.** This is the target with the highest value in the system. |

### 15.1.1 "We keep no logs" is not a defense

ProtonMail (2021) and Tutanota (2020) each prove this. A court did not order
them to give the existing logs. A court ordered them to **start collection** for
a named target, from that moment. A court also ordered Tutanota to **write new
code** for that collection.

The only defense that has operated in a court is **architectural emptiness**.
The raid on Mullvad in April 2023 gave nothing. The subpoena responses of Signal
give two timestamps.

The structural answer of UMBRA to a prospective order is that **the pairwise
tier holds no durable identifier to name in such an order.** The queue
identifiers rotate (Part 3 §3.2.4). The notification handles rotate each 7 days.
A pairwise identity applies to one contact. An order to "log everything for the
user X" has no X to bind to at that tier.

One tier above the pairwise tier holds a durable identifier, and §15.1 states
it. A published handle or Public Address of Part 9 is durable for its lease,
because the user chose to publish it. A court can name it in an order against
the directory or against the relay of its rendezvous queue. The directory gives
the entry, which is public. The relay gives the hello times of one period,
because Part 9 §9.9 rotates the rendezvous queue at each `RENDEZVOUS_ROTATE`.
Neither one gives the person.

**[SEC-001]** An anonymous credential MUST authorize a queue rotation.
**[SEC-002]** A long-lived key MUST NOT authorize it. Thus the rotation does
not make the linkage that it exists to break.

## 15.2 What UMBRA does not defend against

This section states the limits plainly. A specification that hides a limit is
worse than a specification that has that limit.

### 15.2.1 Endpoint compromise and coercion

- **The seizure of an unlocked device (the AFU state).** This is the dominant
  forensic variable. The Cellebrite chain that Amnesty documented gets kernel
  code execution over USB, on an Android device that is locked and in the AFU
  state. The short auto-lock and the secure-element entanglement of Part 14
  §14.6.4 increase the cost. They do not remove the risk.
- **The platform of an honest device.** UMBRA operates on an operating system
  that UMBRA does not control. Part 2 §2.2 models that platform as A7, and Part
  14 §14.6.6 states what the client gives to each platform interface. A scan
  at the OS level reads what that section lets out, and no more.
- **Compelled key disclosure by the user.** The instruments are UK RIPA Part III
  s.49, French art. 434-15-2, and Australian TOLA. The protocol cannot help.
- **A malicious local change to the database.** Part 4 §4.6 makes such a change
  *detectable*, with a table MAC under the key `K_tab`. It does not make the
  change impossible. No keystore holds `K_tab`: it derives from `K_store`.
  Thus a party with code execution before the auto-lock of Part 14 §14.6.4
  reads `K_store` and computes a table MAC again. Part 4 §4.6 also does not
  detect a rollback of the full database file to an earlier state.

> **UMBRA does not ship a duress feature or a panic feature as a defense against
> key-disclosure law.** Such a defense is untested, and it invites a charge of
> obstruction. To offer it as protection is dishonest.

### 15.2.2 Global passive adversary

Part 3 §3.11 states this limit, and this part states it again. An adversary that
observes the two access links makes an end-to-end confirmation. UMBRA does
**not** defeat that confirmation in Fast mode or in Balanced mode. Private mode
makes the confirmation more expensive only.

This limit is a theorem and not a gap. With `c > 0` and a constant latency
overhead, strong anonymity is impossible (Das and others, PoPETs 2020(3)).
Empirically, DeepCoFFEA (IEEE S&P 2022) reaches a TPR of 93 % at an FPR of
2·10⁻⁴ on Tor. It reaches a TPR of 84–95 % against obfs4, WTF-PAD, and FRONT.

### 15.2.3 A majority of the relay capacity

An adversary that controls each relay in a chain recovers the tuple *(client IP
address, queue, time)*. The invariants of Part 3 §3.4.6 and the diversity limits
of Part 10 §10.6 make that control expensive. They do not make it impossible.

### 15.2.4 Transcript consistency in a group

A malicious group member sends different content to different members. UMBRA
does not detect that behavior in v1 (Part 11 §11.7).

**Key equivocation by a rotator.** The same limit holds for the group key. An
epoch-key record of Part 11 §11.4.2 holds no commitment to one `K_e`, and a
member verifies its own slot alone. A member that rotates can thus give two
members two keys. A member with a low index wins the race of `GRP-273` against
an honest rotator. The group then splits into sets that cannot read each other
until an honest member rotates. The insider reads nothing that it did not read
before, and no party outside the group gains a key. A commitment to `K_e` in
the clear part of `EpochKeyBody` is a planned wire change of a later
version, and §15.3 holds the row until then.

### 15.2.5 The handle directory is enumerable

Part 9 §9.1 states this limit. A human-readable name has low entropy. The
mitigation is that a full crawl gives nothing of value.

The address index of Part 9 §9.3.3 is different. Its label is a 160-bit hash,
thus a crawl that enumerates the handle labels finds no address label. Only a
party that holds the address string reaches that entry.

### 15.2.6 The key-transparency VRF is not post-quantum

`ECVRF-EDWARDS25519-SHA512-TAI` is classically secure only. **A harvested log
and a future quantum computer together de-blind the full historical handle
directory** (Part 9 §9.5.4). The message-content confidentiality path of UMBRA
is post-quantum. Discovery and anti-abuse contain classical auxiliary primitives
today, because no deployable post-quantum alternative is available. There is no
practical PQ VRF today.

### 15.2.7 Protocol detectability

A top-tier network classifier detects UMBRA at the flow level. Part 3 §3.8.1
makes this an explicit trade. The ClientHello of Part 3 §3.8 is the
ClientHello of the rustls stack, and not the ClientHello of a browser.

v1 defers the web client of Part 14 §14.7. When it ships it sends the
ClientHello of its browser, thus the ingress relay tells the two client
classes apart. The class names no user.

UMBRA does not claim to be unblockable. Refer to the non-goals in Part 2 §2.5.

Two properties of the design limit the damage from a lost relay:

1. A relay shares its IP address and port 443 with a genuine website. Thus a
   destination address does not give a list of the users of UMBRA (G8).
2. A client holds two pinned ingress relays (Part 10 §10.6.1). Thus the loss
   of one relay does not stop delivery (U6).

### 15.2.8 Multi-device history exposure

The seizure of one linked device exposes the synced history of that device
(Part 7 §7.2). Part 7 §7.2 accepts this trade for multi-device operation with
history sync. The mitigations limit the exposure, and they do not remove it.

### 15.2.9 Web distribution has one gatekeeper for each browser

v1 defers the web client (Part 1 §1.1), and this section holds when it ships.
The web client of Part 14 §14.7 is a browser extension, and each browser
vendor operates the one store that its browser installs from without a policy
change. A vendor can remove or replace the extension for each user of that
browser. UMBRA accepts this residual, and §15.3 holds the row.

## 15.3 Residual leaks, enumerated

| Leak | Who sees it | Bounded by |
| --- | --- | --- |
| An IP address ran UMBRA at the time T | The ingress relay, and a local observer | Nothing, and the exposure to each of the two named ingress operators lasts the pin lifetime of 60 to 120 days (Part 10 §10.6.1). UMBRA accepts this leak. |
| The cell sizes, from a ladder of 4 values | Each hop | Part 3 §3.3 bucketing |
| A maximum of 8 queues share a session | The queue relay | Part 3 §3.2.5 isolation limit |
| An approximate padded file size, from the chunk count | All the chunk relays in collusion | Part 12 §12.9 |
| Up to `POW_CHUNK_ALLOWANCE` chunks of one upload share one proof-of-work solution at one relay. Thus that relay joins those chunks to each other, and it learns a lower bound of the padded size of one file | The chunk relay that admitted them | Part 13 `ABU-107` and `ABU-108`, Part 12 §12.9 — no solution serves two uploads |
| The list of the handles | Each party | Part 9 §9.3 — worthless deliberately |
| A device has UMBRA installed, and the wake times and the wake count | Google, in Instant mode on a device with FCM | Part 8 §8.7. Each push has one form and one expiry under `NTF-086`, thus Google does not learn which wake is a group message. Over many wakes, the wake times of two accounts that write to each other link the two accounts. A client in Direct mode (Part 8 `NTF-139`), in Private mode, or in Off mode holds no push token. A device with no FCM takes its wakes from the socket and the poll. Each gives Google nothing |
| The link of an invitation, in the channel that the user picks to pass it | Each party that reads that channel before the intended party opens the link | Part 4 §4.3.1. The link works one time, and the first fetch locks the queue (Part 6 rule `WIR-510`). A party that fetches first becomes the contact, the intended party learns it under `IDN-167`, and the verification of Part 4 §4.5 shows it to the inviter |
| No delivery to a locked client: a record waits at the relay from the auto-lock to the next unlock | The user, as latency. No party learns more from it | Part 8 §8.4.1. In Instant mode the alert of `NTF-136` names the conversation that waits, and the record arrives at the unlock. In Direct mode the watch of Part 8 §8.4.3 gives the same alert. In Private mode and in Off mode a locked client shows nothing until the unlock (Part 8 §8.3). The auto-lock of Part 14 rule `IMP-119` sets the time. U3 of Part 2 §2.4 measures the alert and not the record |
| No send, no read, and no sync in a device set whose owner device is locked. A linked device waits for the unlock of the owner | The user, as latency on each device of the set. No party learns more from it | Part 7 §7.5.4. The owner alone holds each ratchet and reads each pairwise queue. The ownership claim of Part 7 §7.3.1 is the designed bound at `OWNER_TIMEOUT`, and v1 builds no claim of that scope (`DEV-287`). Thus the unlock is the one bound in v1 below `OWNER_ABSENCE`, and the take-over of Part 7 §7.7 is the bound from there. The second clause of U2 covers an unlocked owner alone |
| A device set whose owning device is lost: each other linked device leaves the set at the take-over. A contact that moved its queue after the last record of the lost device waits, and a contact whose channel item did not reach the claimant is lost to the set | The user, as devices to link again and contacts to invite again. Each contact of the last kind sees no answer | Part 7 §7.7 rules `DEV-314` and `DEV-316`. The claimant renews each channel from the item of `DEV-319`, and it has a sync channel to the absent device alone. UMBRA accepts this residual |
| The pairwise key of each contact, the credentials that write to the queue of each contact, and the secret of the renewal guard of each contact, on each linked device | A6 that seizes a linked device. That device can write to those queues. Until the user revokes it, its renewal bundle opens the guard of each contact, thus each contact answers it with no question (Part 3 `NET-327`, `NET-355`). A device that a revocation removed keeps the pairwise identity, the queue credentials, and the secret of the guard before the revocation | Part 7 §7.5.3 rule `DEV-319`, and Part 3 rules `NET-354` to `NET-358`. The item holds no ratchet, thus it opens no record of a channel that stands. The snapshot of a link gives the same values for the contacts of that moment. The queue credentials of one contact end when that contact moves its queue. A revocation sets a new guard for each contact (Part 7 §7.7 step 2f). From then on a bundle of the removed device runs no handshake by itself: the contact asks its user. Five cases stay. A user that accepts that question gives the channel to the device that sent the bundle. A contact that holds no guard of the user answers each bundle that passes `NET-327`. From the revocation until the guard record reaches a contact, a bundle of the removed device still opens the guard of that contact. That time holds the delay of `NET-181`, with a mean of `SWEEP_SPREAD`. A removed device that works with the relay of the queue of a contact reads the secret from the bundle of a renewal that runs, and it puts a bundle of its own in its place. The guard binds the party that offers a bundle and not the party that answers one, and the row of the dead-channel handle below gives that case. The full identity reset of Part 7 §7.7.1 ends the pairwise identity, and each case with it. UMBRA accepts this residual |
| Two sets from one, when two linked devices take the set over at the same time | The user. Each contact follows the renewal that ended last | Part 7 §7.7. Neither device has a channel to the other. Each one waits for `OWNER_ABSENCE` and for `DRAIN_QUIET` first (`DEV-231`, `DEV-315`). UMBRA accepts this residual |
| A take-over with no absence, by a linked device in hostile hands. The device that owns the channels stops and shows the event | A6 that holds a linked device, before the user revokes it | Part 7 §7.7 rule `DEV-317`. No verifier measures an absence. That device holds the `RootIdentity` already (Part 7 §7.2), thus the epoch gives it no key. The fix is the restore of Part 4 §4.7 and the full identity reset of Part 7 §7.7.1. UMBRA accepts this residual |
| A record written to a live subscription whose link was lost already gets no push | The user, as latency to the next subscription of that queue | Part 8 rule `NTF-128`. The record stays in the queue and the next subscription takes it. The relay cannot tell a lost link from an orderly end, and a reason field in `CircuitDestroy` is a planned change of a later version |
| The conversation of each push that arrives, at a device seized in the AFU state, from the wake table of `NTF-135` | A6 | Part 8 §8.4.1. The table holds the blob roots and the queue aliases, and no queue key, ratchet, or message. A new root each 7 days under `NTF-007` bounds it. UMBRA accepts this residual |
| The arrivals at each queue of a device in Direct mode, from the watch table of `NTF-145` at a device seized in the AFU state. The party can watch each queue until the next rotation of its root | A6 | Part 8 §8.4.3. The table holds the relays and the notifier secrets, which see an arrival and read, fetch, and acknowledge no record. A new root each 7 days under `NTF-007` ends each notifier key. Only an unlocked client of the set rotates a root, thus for a set of one seized device the watch lasts until a restore moves its queues. UMBRA accepts this residual |
| The battery cost of Direct mode, the default, is not measured | The user, as battery use. No party learns more from it | Part 8 `NTF-141`. The held socket and the watch of Part 8 §8.4.3 cost battery that no measurement bounds yet. The project took Direct mode as the default with that cost open. §8.8 states the result after the measurement |
| The time of each wake of a locked client in Direct mode | The ingress relay, and a local observer | Part 8 §8.4.3. The watch carries no cover traffic, thus a cell toward the device at a quiet time is an arrival. The ingress relay learns no account, no queue, and no conversation. UMBRA accepts this residual, against the push time that Instant mode gives Google |
| A queue is watched, and the notifier identifiers of one watch circuit belong to one device | The queue relay | Part 8 §8.4.3. One circuit carries at most `MAX_QUEUES_PER_SESSION` watches, which is the bound of a transport session (Part 3 §3.2.5) |
| A record that arrives while no watch of its queue lives gets no wake when its queue relay restarts before the next `NSUB` | The user, as latency to the unlock | Part 8 §8.4.3. The next `NSUB` gives the wake of each other such record (`NTF-146`). The relay holds that mark in memory alone |
| A contact that gets no answer, after a run of the inviter ended between flight 1 and flight 3 | The invitee | Part 14 `IMP-169`: the inviter keeps a handshake that waits in the store, thus its next run answers flight 1. Until that run, the invitee sees no delivery. A handshake that fails ends under `IMP-170`, and a new invitation makes a new contact |
| The code units of a draft, of a rendered message, and of the passphrase, as a list on the JVM heap and in the buffer that UniFFI lowers it through, for the length of one call | A party that reads the memory of the Android process | Part 14 §14.6.1 rule `IMP-124`. UniFFI has no `CharArray` type. The Rust side overwrites its copy, and the collector of the JVM frees the list. The wrapper makes a new list for each call and empties it after the call. A link of Part 7 §7.4 and a restore of Part 4 §4.7 wait up to 15 minutes between two calls, and they keep the passphrase as a `CharArray` that they overwrite at the end |
| The output of the keyed function of the secure element, as the byte array that the Android adapter returns to UniFFI, until the collector frees it | A party that reads the memory of the Android process at the unlock | Part 14 §14.6.1 rule `IMP-125`. The keystore has a Java interface only. The adapter overwrites its own buffer, and the Rust side overwrites its copy after it derives `K_wrap`. Such a party reads `K_store` in RAM after the unlock too (§15.2.1). UMBRA accepts this residual |
| The groups of one member, joined across groups: the notify queues of several groups under one handle or on one session at one queue relay | That queue relay alone learns that one client is in groups at each depositing relay, with the activity timeline of each. With two group-queue relays it joins one member across two groups | Part 8 §8.5.2. `NTF-092` permits the shared handle. Its SHOULD places the notify queues of different groups at different relays and under different handles while the handle count permits. `NTF-095` and the row of the notify queue below cover one relay only. UMBRA accepts this residual |
| A published rendezvous queue filled to `QUEUE_QUOTA` with records that pass no check, thus the relay refuses an honest hello until the addressee drains | Any party that holds the published queue address | Part 9 §9.6 and Part 13 §13.4. A send to a queue carries no admission. The addressee verifies the token or the proof of work of a hello only after the drain. The fill costs the attacker 256 cells for each drain, and it costs the addressee the drain and 256 failed opens. In Private mode the drain is one in each 24 h under `NTF-046`. A rotation of the queue publishes the new address to the same party. UMBRA accepts this residual |
| A push token belongs to a party with a published handle or address | The Notification Delivery Relay and the queue relay of the rendezvous queue, in collusion | Part 8 §8.2.6. The rendezvous queue registers under a notification handle of its own, thus the pairwise queues stay apart. Private mode registers no rendezvous queue |
| The linkage of the queues of one transport session, from a delay probe on one queue | An active A2 or A3 | Part 3 §3.2.5 bounds the set at 8 queues. That isolation limit binds a passive recorder only. UMBRA accepts this residual |
| The cursor of one reader session of a group, from a delay probe on that session | An active A2 at the group-queue relay | Part 3 §3.11.1. The relay already holds the session and its cursor, and the probe joins that session to no identity and to no pairwise queue. UMBRA accepts this residual |
| The reconnect cadence of a recipient, from the boundary of a cumulative acknowledgment | The queue relay | Part 6 §6.4.3 rule 7. A cumulative acknowledgment gives one boundary for each batch, and not one for each message. UMBRA accepts this residual |
| The send times of a user with the application in the background | The ingress relay, and a local observer | Nothing. Part 3 §3.6.2 makes no cover cell outside the foreground, thus a background outbound cell is a real event. UMBRA accepts this residual |
| The send time of a Private-mode message on the client link | The ingress relay, and a local observer | Part 3 §3.9. A Private-mode send does not wait for a cover slot. The per-hop delay and the inbound pacing stay. UMBRA accepts this residual |
| The delivery tail of a Private-mode message | The recipient, and a local observer | Part 3 §3.9. A constant-rate inbound clock gives a tighter tail at the same cell rate. UMBRA gives it up, because a pacing shape that differs by mode names the mode in the inbound cell count. UMBRA accepts this residual |
| The bucket of each inbound cell | A local observer | Part 3 §3.5.2. The inbound pacing cover cell is bucket `B0` at 560 B, and the modal text delivery is bucket `B1` at 2 096 B. Thus the cover does not conceal the bucket. Bucket-matched cover costs about 39.5 MB for each 2 h session against 4.03 MB. UMBRA accepts this residual |
| The shape of a large reconnect drain | A local observer | Part 3 §3.5.2. A backlog above `DRAIN_THRESHOLD` leaves the relay in one unpaced response, and the observer reads it as one burst. A paced drain of that backlog would fail U6. UMBRA accepts this residual |
| A client with no clock correction takes the correction of a replayed old `DirectoryRoot` at or above the shipped epoch, thus its clock runs behind until a fresh root arrives | The ingress relay that serves the root, at the first launch or after a clock movement | Part 10 §10.5.2 rules `REL-113`, `REL-114`, `REL-044`, `REL-045`, and `REL-115`. The root is a signed object of the authorities, and the shipped epoch bounds its age to the age of the build. The next fresh root starts more than `CLOCK_SKEW` after that clock and gives a new correction under `REL-044`. A client with no correction has no trusted time to test a root against. UMBRA accepts this residual |
| A token of the epoch before a clock step spends a second time at one verifier, when the clock of the verifier steps ahead past the epochs of its spent set, takes a token there, and then steps back | A party that holds a spent token, at that verifier alone | Part 13 rule `ABU-114`. The set holds two epochs, and a token at the far epoch needs the place of one of them. Only a clock fault of the verifier opens the window, and the window ends one epoch after the clock is right again. UMBRA accepts this residual |
| The tombstone table on a seized device, which names each deletion inside the retention window | A6 | Part 7 §7.5.2 and §7.5.3. The source watermark bounds that table by the retention window. The table is not a permanent record of every deletion of the user |
| A transferable proof of the current role grants of a group, on a seized device | A6 | Part 11 §11.9.3. A granting epoch is signed, and the retention rule keeps the authority path only. G10 does not cover the group administration. UMBRA accepts this residual |
| A signed statement that a named role acted on a named `msg_id`, on a seized device | A6 | Part 11 §11.9.6. The preimage names no author, and rule GRP-181 keeps the current statements only. UMBRA accepts this residual |
| The blinded subject list of the roster, on a seized device that holds `K_set` | A6 | Part 7 §7.3.1. Rule DEV-226 blinds each subject under `K_set`, and a seized device holds that key. The blinding protects the archive of Part 7 §7.6.1 and a roster that left the set. UMBRA accepts this residual |
| The handle that a lookup names, when the handle is registered: the search key maps to its label | The directory | Part 9 §9.4. OHTTP hides the party that asks, thus the directory learns which handle someone looked up and not who. UMBRA accepts this residual |
| An edit whose new text is above 138 bytes, because the cell steps from `B0` to `B1` | The queue relay | Part 6 §6.6.1 gives the band. **[SEC-003]** A client MAY split the text, and this specification does not require that split. UMBRA accepts this residual |
| A selected profile picture, which is the same bytes at each party that resolves one Profile | Two parties that resolve one Profile | Part 4 §4.2.5. Those two parties hold one Public Address string already, thus they can already link. The concession stays inside one Profile, and a generated picture does not have it. UMBRA accepts this residual |
| A rollback of the local database file to an earlier state, on a seized device | A6 | Nothing. Part 4 §4.6 gives a table MAC over a row count, a commit counter, and an accumulator of the record tag of each live row. That MAC detects a change to one row and a rollback of one row. A rollback of the full file restores each of the three together. The platforms give no monotonic counter that survives a device restore. UMBRA accepts this residual |
| One `msg_id` at each member of a group, thus two members can prove that they hold one send from one member | Two colluding group members | Part 11 §11.3. A member holds the roster already, thus the two members know that they share the sender. The value stays inside the AEAD of the group record, and no party outside the group reads it. UMBRA accepts this residual |
| The signing device of each roster epoch, on a seized device of the same device set | A6 | Part 7 §7.3.1. The `signer_id` field and the ML-DSA-65 signature name one device of the user. The roster never leaves the device set, thus no relay and no contact reads it. UMBRA accepts this residual |
| A split device set, when a hostile linked device revokes one honest device and not the other | A6, before the user revokes that device | Part 7 §7.3.1 rule DEV-177 and Part 7 §7.7 rule DEV-182. The two honest devices then disagree, and each one shows the fork at the next epoch. In a set of three devices the hostile device can revoke the two honest devices in two competing epochs. Rule DEV-178 makes each honest device show that fork. The fix is the full identity reset of Part 7 §7.7.1. UMBRA accepts this residual |
| A change to the local database by a party with code execution before the auto-lock | A6 | Nothing. Part 4 §4.6 derives `K_tab` from `K_store`, which that party reads from RAM, thus that party computes a table MAC again. Part 15 §15.2.1 states this limit. UMBRA accepts this residual |
| A permanent channel takeover, when a user accepts a key-change notice that an attacker sent | A6, transient, and then permanent | Part 4 §4.5.1. The notice carries no signature, thus the ratchet is the only authentication. IDN-089 through IDN-092 put the weight on the prompt. G5 does not hold across an accepted notice. UMBRA accepts this residual |
| A skipped-message key that lives 45 days | A6 | Part 5 §5.5.4. `SKIP_TTL` equals `MSG_TTL`, because a shorter value makes a delivered message undecryptable against U9. `MAX_SKIP`, `MAX_STORED`, `MAX_BYTES`, and `MAX_STORED_DEVICE` bound the count. UMBRA accepts this residual |
| A circuit that one injected cell tears down | An active A1, A2, or A3 | Part 3 §3.4.5. The chained construction makes any change fatal to the circuit, which is the property that defeats the tagging attack. The loop cover of Part 3 §3.6.1 measures the event and Part 10 §10.4.2 reports it. Part 2 §2.5 gives guaranteed availability as a non-goal |
| A group presence record, which shows an administrator that a member is live | An administrator of that group, and A6 against that device | Part 11 §11.9.7. The record names the group and nothing else, and it goes to the `admin` role and above only. §11.8 needs that signal for the eviction that RFC 9420 §16.6 makes necessary. UMBRA accepts this residual |
| A link preview that a sender made, which a hostile sender pairs with a true URL | The receiver | Part 3 §3.3.2. NET-142 keeps the receiver from a fetch, thus the linked site gets no address. NET-148 renders the host beside the preview. UMBRA accepts this residual |
| A draft on a sync channel, which is text that no party sent | A peer device of the same set, and A6 against it | Part 7 §7.5.3. DEV-199 holds a draft under the record encryption and DEV-200 keeps it out of a backup. DEV-202 lets the user turn the sync off. UMBRA accepts this residual |
| A live queue and an ordinary delivery receipt for a blocked contact | The blocked party, and the queue relay | Part 13 §13.12. The alternative is a `DEL` that names the moment of the block, and ABU-025 gives the cause. The cost is the bytes of a live queue. UMBRA accepts this residual |
| The mention list of a record, which reaches each member of a group | Each member of that group | Part 11 §11.11. GRP-141 keeps a client from rendering the list to a member that it does not name. The bytes still reach that member inside the AEAD. UMBRA accepts this residual |
| The replica set of one chunk | The relay that took the `CPUT` of that chunk | Part 12 §12.4.1. The three replicas hold byte-identical ciphertext, thus §12.3.3 already concedes that a comparison links them. The rule removes the collusion step and adds no capability. ATT-122 keeps the replica set of each chunk independent, thus no relay learns a second chunk of one file. UMBRA accepts this residual |
| The dead-channel handle and blob key of each contact of a user, at a device that an ordinary revocation removed. The secret is the static pairwise X25519 secret, which a revocation keeps | A revoked or seized device, until a full identity reset of Part 7 §7.7.1 | Part 3 §3.2.6. That device writes a blob with a queue of its own under the handle of the user, or takes the handle first under `ATT-058`. `NET-190` holds a blob address as a candidate and sends no record of the user to it. A ratchet record of the peer confirms a candidate on a dead channel alone, and the revoked device holds no ratchet. On a channel that is silent and not dead such a record ends the candidate with no adoption. Thus an honest record of a returning peer confirms no blob of that device. Only a stale channel offers its renewal bundle to a candidate, thus a healthy channel gives that device no handshake to answer. Three things stay. The device keeps the honest blob out for one week at a time. It learns the time of the one `0x33` record of each contact that probes. It can answer the renewal bundle that a restored contact with a stale channel sends to its candidate. That handshake runs under the pairwise identities alone. The renewal guard of Part 3 rule `NET-354` binds the party that offers a bundle, thus it does not stop that answer. The full identity reset of Part 7 §7.7.1 ends each of the three. UMBRA accepts this residual |
| The chain keys of each pairwise channel, at a device that a revocation removed, from the revocation until the next record of the peer steps the ratchet (Part 7 §7.5.4, §7.7 step 2b) | A revoked or seized device | Part 7 §7.7 step 2c. No sender steps the ratchet alone. Thus the removed device still derives the message key of each record that the peer sends under the old chain. It reads none of them, because the rotation of step 2c leaves it no queue: the new queue has credentials that it never held. The window of that bound has two parts. The first is the delay of Part 3 `NET-181`, with a mean of `SWEEP_SPREAD`. The second is the hold of the old queue under `NET-177`, at most `ROTATE_GRACE`. In that window a removed device that reads the old queue before the owner opens the records that the peer still writes there. A relay of the new queue that colludes with the removed device gives it the ciphertext with no such bound, until the step. The step comes with the first record of the peer under a new ratchet key. UMBRA accepts this residual |
| A fetch of a dead-channel handle for a contact that reads and never writes | The relay that holds the handle | Part 3 §3.2.6. Receipts are off by default, thus a silent channel is one with no record of the peer in `DEAD_CHANNEL_SILENCE`, and a quiet contact is silent. The handle names no party and changes each week. UMBRA accepts this residual |
| The dead-channel handle of a contact pair, which a classical static-static X25519 derives | A quantum adversary that holds the two pairwise public keys, and the relay that holds the blob | Part 3 §3.2.6. The pairwise public keys travel inside an AEAD, thus the adversary needs a seized device or the invitation. The blob holds a `QueueAddress` under a key from the same secret. The relay learns that one pair lost its channel, and not who the pair is. UMBRA accepts this residual |
| A tombstone version of a handle, which shows that the holder let the lease lapse | Each party that passes the lookup chokepoint of Part 9 §9.4 for that handle | Part 9 §9.9.2. The log already publishes each version of the label under `DIS-007`, and a tombstone is one more version. The version shows no date, because Part 9 §9.3 keeps a timestamp out of the entry |
| The admission backlog of a relay, from the `effort` of its `PowChallenge` | Each party that fetches the descriptor of that relay | Part 13 §13.8 rule `ABU-060`. The effort is one 32-bit value from the admission backlog of the relay, and it names no client. The descriptor of Part 10 §10.5.3 already publishes the capacity class of the relay |
| One onion layer of each recorded cell of a live circuit, when an adversary seizes the hop 1 or hop 2 key set | A6 at a middle relay | Part 3 §3.4.4. That layer gives the ciphertext of the next layer, and `CIRCUIT_MAX_AGE` of 4 hours ends the key set. The hop 3 key set updates at each cell under rule NET-204. Part 3 §3.4.3 gives the cause of that value. UMBRA accepts this residual |
| A parked session of a client, with the hop 1 key set of each circuit of it, for up to 4 hours after the connection of that client closed | The ingress relay, and a party that seizes it | Part 6 §6.2.3 rules `WIR-541` to `WIR-543`. The relay holds the same state while the connection is open, and `CIRCUIT_MAX_AGE` of 4 hours ends each key set in each case. The park thus adds the time after the close and no key. The relay holds a parked session in RAM alone (`WIR-548`). UMBRA accepts this residual |
| The session secret and each key set of each kept circuit, in the memory of a client process between two connections | A party that reads the memory of an unlocked client | Part 6 §6.2.3 rule `WIR-549`. The client writes none of it to its store, and a lock erases it. A locked client holds no key of a circuit. UMBRA accepts this residual |
| The wakes of one client at one ingress across 4 hours, and across a network change, which one session links | The ingress relay | Part 6 §6.2.3. `SESSION_RESUME_WINDOW` of 4 hours lets a push wake resume its session, and Part 3 §3.12 gives the builds that the resume saves. The ingress already links the wakes of one live circuit, thus the resume adds the link across a network change only. UMBRA accepts this residual |
| The bloc of hop 2 equals the bloc of hop 1 or of hop 3, under the relaxation of `NET-200` | The two relays that share the bloc, and the order that reaches both | Part 3 §3.4.6. Hop 1 and hop 3 stay in different blocs, thus no one order joins the client address to the queue. The client shows the relaxation under `NET-201`, and `NET-033` fails closed below it. Part 10 §10.6.3 sets the floor that ends the relaxation, and §15.6.1 sets the recruitment target that reaches the floor |
| The client clock follows a stale but valid `DirectoryRoot` at the first launch | An ingress relay that serves the stale root, and each relay that the retired set names | Part 10 §10.5.2. `REL-046` bounds the staleness to the age of the build, and `REL-034` keeps the epochs monotone under it. `REL-044` takes a new correction at the first fresh root. A holder of the only path of a client can replay a sequence of roots at the true cadence for the age of the build. `REL-008` detects the divergence on the first other channel. UMBRA accepts this residual |
| A relay outside the measured sample of a large cluster lends capacity to a relay inside it | The directory authority, as an inflated class of the sampled relay | Part 10 §10.3. The measurer draws the selection from its CSPRNG under `REL-100`, and `REL-102` shows no selection before its slot ends, thus the cluster feeds the lender blind. `REL-101` measures each relay inside `ceil(n / CLUSTER_SAMPLE)` slots, and `REL-001` limits the payoff to one class step in each epoch. UMBRA accepts this residual |
| The selection of a sampled cluster has no proof. A measurer that colludes with a cluster selects the relays that the cluster feeds, and no party can show it | The directory authority, as an inflated class of each relay of that cluster | Part 10 §10.3. v1 holds no verifiable selection. The authorities issue each `MeasurerCert` under `REL-103` and revoke one under `REL-105`, and `REL-001` limits the payoff to one class step in each epoch. UMBRA accepts this residual |
| A measurer whose capacity holds a part of a slot measures a cluster in more slots, thus more relays of that cluster stay outside each slot and can lend capacity | The directory authority, as an inflated class | Part 10 §10.3. The launch network is such a case: a slot of two relays for a cluster of six. The one operator of that network runs each relay, and it gains nothing from a false class of its own relay. UMBRA accepts this residual for the launch |
| The typed text of each message, and the passphrase, at the input method | A7, as the input method | Part 14 §14.6.6. `IMP-057` sets the no-learning flag. The input method is a process that the user selected, and UMBRA cannot replace it. UMBRA accepts this residual |
| Each rendered message, at an enabled accessibility service | A7, as an accessibility service | Part 14 §14.6.6. `IMP-060` keeps the accessibility tree whole, because a hidden message is a hidden conversation for a user that cannot see the screen. The user enables each such service. UMBRA accepts this residual |
| A message of a party that prohibits the forward, at each place that the other party moves it to | The other party, and each party that it gives the message to | Part 7 §7.5.10. `DEV-322` binds a conformant client, and a changed client ignores the record. A copy of the text, a screenshot, and a save of a file stay possible on each client. `DEV-326` keeps the interface from a claim of enforcement. UMBRA accepts this residual |
| The record of a pairwise conversation at the other party, at a deletion of the whole conversation | The other party, as a victim that keeps a record for a report | Part 7 §7.5.6. `DEV-335` erases the messages of both parties on each device of the other party, thus a harasser can erase the record of Part 13 §13.10. A changed client ignores the request, and a copy and a screenshot stay. `DEV-336` keeps a trace that names the party. UMBRA accepts this residual |
| A saved file and a screenshot, at each platform service | A7, as the platform cloud service | Part 14 §14.6.6. `IMP-045` makes the save an explicit action on one file, and `IMP-046` warns before the first one. UMBRA accepts this residual |
| A page image below the file system, at the flash layer | A6, with the flash chips | Part 14 §14.6.4. `IMP-042` and `IMP-043` overwrite a freed page and truncate the log. The flash translation layer keeps an old page that no file system call reaches. The record key of that page is a value that `IMP-041` overwrote, thus the page opens under no key. UMBRA accepts this residual |
| The rebuild timing of a circuit, from a drop of each cell of that circuit | An active A2 or A3 | Part 3 §3.11.1. `CIRCUIT_MAX_AGE` of 4 hours makes a rebuild normal, and the loop cover of Part 3 §3.6.1 measures the drop. UMBRA accepts this residual |
| The hello count and the hello times of a published handle or address | The queue relay of the rendezvous queue | Part 9 §9.6. The queue address is public by the choice of the holder. `RENDEZVOUS_ROTATE` of Part 9 §9.11 moves the queue on a schedule, thus one relay holds that count for one period. UMBRA accepts this residual |
| The blinded element and the time of each lookup, at a compelled directory | The handle directory, under a prospective order | Part 9 §9.4. The directory never sees the plaintext handle, and the token of Part 13 §13.3.2 names no client. The log gives a lookup count and the lookup times, and no handle. UMBRA accepts this residual |
| The payment record of a token purchase | The token issuer, and the payment processor | Part 13 §13.9. The signature is blind, thus the record links to no token and to no relay. A purchase is one of three paths, and path 3 costs time and makes no record. UMBRA accepts this residual |
| The count of tokens that one party holds in an epoch, which no rule bounds | The issuer, which cannot count for one party | Part 13 §13.9. A payer is anonymous, thus no cap for one payer exists. The epoch of `ABU-004` bounds the life of a token, and the price bounds the count. UMBRA accepts this residual |
| The metadata fields of an original that the user selected for one send | The recipient, and each party that the recipient gives the file to | Part 12 rule `ATT-155` removes each field by default, and `ATT-157` keeps them for the original that a user selects. The sender sees that statement at the selection. UMBRA accepts this residual |
| The phase of the fixed clock of Private mode, which is one value for each install between two draws | The ingress relay, and a local observer | Part 8 §8.3. The wakes fall at one offset inside each interval, thus two networks that see one phase see one client. `NTF-052` and `NTF-053` draw a new phase at each network change and at each ingress change. UMBRA accepts this residual |
| A match of two six-digit codes under an active adversary at the first contact, with a probability of one in 10⁶ for each ceremony | An active A3 at the first contact | Part 4 §4.5.2. The commit binds each nonce before the reveal, thus the adversary cannot select a nonce. `IDN-170` makes a client answer a start only for an action of its own user. Thus the adversary gets one online guess for each such action and none between them. The 60-digit safety number stays available for a comparison that needs more. UMBRA accepts this residual |
| The invitation landing document, at a hostile invitation host | The invitation host, against a party without the client | Part 4 §4.3.1. `IDN-120` and `IDN-121` fix a static document with no script, and a host that serves a different document breaks that rule. The fragment never reaches the host. A fetch that the host makes from a link locks the queue under `IDN-023`, and the two parties detect it. UMBRA accepts this residual |
| The member count of a group at each rotation, from the slot count | The group-queue relay | The count and no identity. UMBRA accepts this residual |
| The client address joined to the queue, at the one operator of a provisional network. That operator runs hop 1 and hop 3 of a chain, and each hop between | The operator of the network, A5 against it, and a party that breaks into its servers | Part 3 rules `NET-340`, `NET-350` and `NET-351`. G6, G7 and G8 do not hold against that operator. The client shows the `provisional directory` line and marks each such circuit "one operator" in the route view (Part 14 §14.9.2). `NET-342` takes a chain of different operators when one exists, and `NET-351` keeps the two ends off one server while it can. The state ends at the first key set at `AUTHORITY_FLOOR`. Part 10 rule `REL-142` permits that key set only over a relay set that carries a conformant chain. UMBRA accepts this residual for the launch |
| The two replicas of a group at one operator, for the life of a group that a creator made in a provisional network | That operator | Part 3 rule `NET-345`. A group queue cannot move, thus only a new group places the replicas again. That operator holds the whole reader timeline of the group in the place of half. UMBRA accepts this residual for the launch |
| The queues and the link removals of a relay manifest sit outside the signed root, thus a carrier can strip them | A carrier of the manifest | Part 10 §10.5.5. A manifest with no report queue drops each link-fault report of that client, and one with no removal leaves a removed link in its chains. Each object carries the signatures of the authorities, thus a carrier forges none. UMBRA accepts this residual |
| A relay class above the class that the measurers of a provisional directory can test | Each client, as a relay whose declared class is false | Part 10 §10.2 rule `REL-206` and §10.3. A measurer on a launch server of 500 Mbit/s tests C0 alone, and each class above C0 stays as the operator declares it. The one operator of a provisional network declares each class itself. UMBRA accepts this residual for the launch |
| The chain count of each relay before its noise, in a provisional directory | The one operator of that directory | Part 10 §10.4.2 and §10.8. One tool of that operator is both aggregators, thus it holds the two shares of each count. That operator runs each relay, and it holds each count at its relay too. UMBRA accepts this residual for the launch |
| A measurement session at each relay, for a party that holds a leaked measurer key and its certificate | Each relay, as echo load of up to `MEAS_CIRCUITS_MAX` circuits for `MEAS_SESSION_MAX` at a time | Part 10 §10.3.1. `REL-202` bounds the sessions of one relay, the certificate ends at `MEASURER_CERT_TTL` at most, and the `revoked` list of `REL-105` ends it at the next consensus. UMBRA accepts this residual |
| Each hop of each circuit, while the provisional directory lists relays of one country or of one provider | A5 in that country. The provider, and a party that watches its network, which reads the timing of each hop | Part 3 rule `NET-350`. The route view of Part 14 §14.9.2 names the country of each hop. It ends when the relay set reaches the floor of Part 10 §10.6.3. UMBRA accepts this residual for the launch |
| The activity timeline and the bucket of each record of a group | The group-queue relay, and A5 against it | Part 11 §11.2 replicates the queue on two relays under different operators, and a reader alternates them. UMBRA accepts this residual |
| A reader circuit and the group it reads, joined to an IP address | The ingress relay and the group-queue relay in collusion | The same class as the two-ended collusion of Part 3 §3.11 |
| The ciphertext of a group for `GROUP_READ_GRACE` after a removal | The removed member | It holds no slot key of the new epoch. It reads timing and buckets only |
| The retained records of the current epoch from `t_e`, at most `GROUP_EPOCH_MAX_AGE` of 30 days, at a member that holds `K_e`. That is each member that installed the epoch from its epoch-key record. The retained records from `t_join` at a member that joined inside the epoch. The 24 h of `GROUP_SLOT_WINDOW` bound a member of the second kind alone | A6, with the device and the relay's retained ciphertext | Part 11 §11.3.2. `K_e` serves the key supply and the credentials, and the slot chain is one-way from the slot a member holds. The rotation of `GRP-360` bounds it. UMBRA accepts this residual |
| Every record of every group of a member, at a device in hostile hands, from the seizure until the first other member rotates after the `RekeyRecord` | A6 | Part 11 §11.12. A revocation heals a pairwise channel and no group key, thus the re-key is a second step. Any member rotates it, one backoff after the first member comes online. Part 7 rule `DEV-262` starts it. UMBRA accepts this residual |
| The membership of a user in a group, when the attacker's device posts a `RekeyRecord` first and wins the hash of `GRP-369` | A6, until an admin acts on the pairwise path | Part 11 §11.12. The attacker must unlock the device first, at the cost of Part 14 §14.6.4 for each passphrase attempt. The user's self-removal rotates the attacker's keys out at once. UMBRA accepts this residual |
| The relay credentials of the old epoch, at an excluded party, until an admin sends `GKEY`, and the write credential for `GROUP_WRITE_GRACE` after it | The excluded party | Part 11 §11.4.1. It fetches ciphertext it cannot open, and every receiver rejects its posts under §11.3.5. Its posts are not harmless at the relay, and the row below gives what they do. UMBRA accepts this residual |
| A group silenced and its retained history evicted. A holder of a write credential posts at `GROUP_POST_RATE`, which the group shares. The records fill `GROUP_QUEUE_QUOTA`, which erases the oldest record first | Each current member, and a removed member until `GROUP_WRITE_GRACE` of 24 h after the `GKEY`, or with no bound while no admin sends `GKEY` | Part 3 §3.2.7 rules `NET-240`, `NET-241`, `NET-243` and `NET-247`. 60 `B3` records each minute fill 32 MiB in about 17 minutes. Each honest post then gets `LIMIT`, and a member that was offline loses each record that the quota erased. Each receiver rejects the flood, and the relay cannot tell the flooder from a member. The two replicas of `NET-253` are no bound, because the credential serves both. A `GKEY` and the end of the grace stop a removed member, and nothing stops a current one but its removal. UMBRA accepts this residual |
| A joiner parted from its group one time. A member that joined inside the current epoch can hold the chain of its admit and no `K_e`. That member installs one epoch-key record of the number above its own that names no trigger. Each member that holds `K_e` refuses that record | An active member of the group, against the availability of that joiner | Part 11 §11.4.2, the cause note of the first epoch of a joiner after `GRP-288`. The admit carries no pending trigger, thus the joiner cannot count `GRP-357` for its first epoch. The insider gains no key, because it holds each key of the group already. The split lasts until an epoch of a higher number that each member installs, or a key supply of Part 11 §11.4.3. The epoch that the joiner installs holds `K_e`, thus the exemption serves one time. The bound of `GRP-288` keeps the record from a number that would end each later epoch. UMBRA accepts this residual |
| A member on a roster head that no other member builds on. A member can post a roster epoch above a limit of `GRP-076` deliberately. Each member that knows the window of that limit discards that epoch. A member whose roster came from a snapshot inside that window applies it | A current member of the group, against the availability of a member that joined, or took a snapshot under `GRP-329`, at most 24 slots before. An honest member that paces a grant or a re-key to a count that started at its snapshot can do the same to itself | Part 11 §11.9.4. The snapshot carries no count of the limits. A count that starts inside a window can pass a limit that the count of the group did not pass. Thus that member discards nothing for the window. The limits bind at the sender and at each member that knows the window. The split ends when the order of `GRP-117` displaces that head or the member takes a snapshot. The sender gains no key and no role. A count in the snapshot is a wire change of a later version. UMBRA accepts this residual |
| The group of a member whose device left its set stays readable to that device while the member cannot build its `RekeyRecord`. In one case its roster came from a snapshot under `GRP-329`, and no add or `RekeyRecord` of another member gave it the index of the group yet. In the other case `REKEY_RATE` holds the record back | A6 against the device that left the set | Part 11 §11.9.8 and §11.12. A record under an index that the member only bounds would stand at that member alone. The client keeps the re-key and posts it when it knows the index or the rate takes it. A self-removal ends the reading at once. UMBRA accepts this residual |
| Different group keys at different members after one rotation, from a rotator that seals a different `k_e` in each slot | A member that rotates, against the availability and the consistency of its group | Part 11 §11.7 and §15.2.4. An epoch-key record holds no commitment to one `K_e`, and `GRP-273` prefers the lower member index. The group does not converge before an honest member rotates. No key leaves the group. A commitment in `EpochKeyBody` is a planned wire change of a later version. UMBRA accepts this residual |
| Owner credentials that the relay no longer takes, at an admin, after two admins drew new ones for two departures at once | The admin whose `GKEY` came second | Part 11 `GRP-402`. That admin cannot send `GKEY` or `GDEL` until an admin of the first draw delivers the credentials again. It is an availability loss and no confidentiality loss |
| No queue credential that the relay holds, at a member, after two rotations inside one `GROUP_EPOCH_GRACE` with no `GKEY` | Each member that installed the second epoch | Part 11 `GRP-398`. The member cannot post until an admin sends `GKEY`, and its client shows the group closed under `GRP-210`. It is an availability loss and no confidentiality loss |
| A forged tag between two members, by an insider that holds a quantum computer | A quantum insider | The posture of Part 5 §5.4.4, and the agility of `sig_id` |
| The group of a leaving member stays readable to it until any other member rotates | The leaving member | Part 11 §11.4.1. One backoff after the first other member comes online |
| The slot chunk that one member fetched, at the chunk relay | The chunk relay | Part 12 §12.9. One anonymous fetch for each member at each rotation |
| The `relay_id` of the notify queue of each reader, at the group-queue relay | The group-queue relay | Part 8 §8.5.2 |
| A queue is a notify queue, and the address of the relay that deposits into it | The queue relay of the notify queue | Part 6 rule `WIR-526`. A deposit travels on a direct connection of the depositing relay, not over a circuit. The sealed digest names no group to that relay, and a registration names no member to the depositing relay. UMBRA accepts this residual |
| The names that a user types for display, the verification code, the link ticket and code, and the invitation bundle. The question and the options of a poll, and the wake table. Each one is a Kotlin string or bytes on the JVM heap | A party that reads the memory of the Android process | Part 14 §14.6.1, the stated exceptions to `IMP-037`. Each one but the poll is a value that the platform draws, scans, or seals in each design. The poll text is message text that crosses as a string in v1, and that exception is a limit that a later version removes |
| The rows below this one hold when the deferred web client ships, and they bind no v1 claim (Part 1 §1.1) | — | — |
| The class of a client, web or native, at the ingress relay from the ClientHello | A1, A2, as the ingress relay | Part 3 §3.8.1. The two classes send the same cells, and the class names no user. UMBRA accepts this residual |
| The bytes of a deleted record in the storage engine of the browser, until that engine compacts | A6, with the browser profile | Part 14 §14.7.4. `IMP-108` overwrites the salt and the ciphertext before the delete, and no rule of the engine bounds the compaction. UMBRA accepts this residual |
| The passphrase rate of a web client, against a party that runs script inside the browser profile | A6, A7 | Part 14 §14.7.4. `IMP-106` binds the wrap to a non-extractable key, which stops a copied store and not a script in the profile. UMBRA accepts this residual |
| The constant-time property of the web client, at the compiler of the browser | A6 | Part 14 §14.7.6. The source-level ban of Part 14 §14.5.1 holds at the source, and no test runs against the code that the browser executes. UMBRA accepts this residual |
| The extension listing, at each browser vendor | The browser vendor | §15.2.9 and §15.5. No rule checks the listed bundle |

**[SEC-018]** A revision that adds a residual leak MUST add a row to this table.
**[SEC-019]** A revision that removes a leak MUST remove its row in the same
commit. §15.8 makes this table a published promise.

## 15.4 Attacks that this design anticipates

| Attack | Where this specification addresses it |
| --- | --- |
| Relay seizure and log correlation | Part 3 §3.2 — two unrelated queue IDs, and a key set for each queue |
| A join of the sender and the recipient across two relays | Part 3 §3.4.6 — operator, jurisdiction, and ASN disjointness, enforced in code |
| Latency-injection correlation (ToB #7, not corrected upstream) | Part 3 §3.5.3 — a randomized delivery delay, with named distributions |
| A message-existence oracle from the packet counts (ToB #2) | Part 8 §8.4.2 — a fetch response with a constant size and a constant count |
| Compulsion of a TLS key (Lavabit) | Part 5 §5.4.9 and Part 3 §3.4.4 — the circuit handshake at each hop and the onion layers sit below TLS. Thus a TLS key of a relay opens the cells of its links and no layer. The key set of a circuit lives at most `CIRCUIT_MAX_AGE`. The `identity_pk` and the `ntor_pk` of a relay have no stated lifetime in v1, and `relay_id` is the hash of `identity_pk`. Thus a compelled static key of a relay lets its holder act as that relay from then on |
| Deanonymization of a sealed sender through delivery receipts | Part 3 §3.5.4 — a receipt is an ordinary padded message, and it is off by default. A receipt rides a cover slot, and it replaces the cover cell of that slot |
| Bandwidth inflation (177×, 420×, 28×) | Part 10 §10.2 — discrete classes limit it to 2.5× in one 7-day epoch and to 10× over the ladder |
| Sybil flooding (KAX17) | Part 10 §10.7 — staging with an automated sybilhunter |
| A flood of connections, TLS handshakes, or circuit builds at an ingress relay | Part 3 §3.4.3 — `NET-331` to `NET-335` cap the circuits and the builds of one link, the connections of one address, and the handshakes that run at once. An attacker with many addresses still costs the relay the work of those caps, and §15.3 records it |
| A flood of attachment storage | Part 13 §13.8.1 — a solution admits `POW_CHUNK_ALLOWANCE` registrations of one upload and no more, thus a flood pays a puzzle for each 2 MiB |
| Directory equivocation (IEEE S&P 2024) | Part 10 §10.5 — a 5-of-7 Byzantine broadcast with in-band gossip |
| Performance-adaptive selection as an oracle (PETS 2011) | Part 10 §10.6.2 — **[SEC-004]** local performance MUST NOT replace a relay |
| A group-membership beacon (the "flurry" attack) | Part 11 §11.3.4 — a member posts one record for each message, thus no burst exists to observe. The timeline of the group-queue relay is the observable that remains, and §15.3 records it |
| KEM re-encapsulation and key confusion (PQXDH) | Part 5 §5.3 and §5.11 — full transcript binding and domain separation |
| A tagging attack on the onion layer | Part 3 §3.4.4 — rugged-PRP per-hop encryption, with the tag of the layer below in the left block |
| A delivery beacon from a link preview fetch | Part 3 §3.3.2 — the receiver MUST NOT fetch a URL |
| A queue teardown that names the moment of a block | Part 13 §13.12 — the queue stays live and the acknowledgments continue |
| A reflector or a relay-detection probe from `MEAS_ECHO` | Part 10 §10.3.1 — a measurement session needs a `MeasurerCert` |
| A prekey-trial amplification against a responder | Part 5 §5.4.8 — flight 1 names one prekey with `pid` |
| A cross-command replay of a queue authenticator | Part 3 §3.2.3 — the authorized bytes and the `corr_id` rule |
| A break of deniability from a prekey signature | Part 5 §5.4.1 — no party signs a prekey |
| A DoS from skipped keys | Part 5 §5.5.4 — hard limits, and one of them is device-global |
| Invisible salamanders in franking | Part 12 §12.3.1 — key-committing AEAD with a negative test vector |
| An attestation relay (Quarkslab 2026) | Part 14 §14.6.5 — no hardware attestation for anti-abuse |

## 15.5 The update channel

This channel is the largest compromise vector that each system in this list
does not address. The party that signs a release and the store that serves it can
each replace the application. A court can compel each of them.

v1 gives no control for this channel. The v1 client verifies no transparency
proof for an update, and no independent party rebuilds a release. Trust
assumption 4 of Part 2 §2.6 thus rests on the release signer and on the
store. §15.1 holds the row of the app stores.

## 15.6 Legal and governance requirements

**Closed-world routing.** A relay speaks UMBRA only, to a client and to
another relay. A relay does not speak to an arbitrary internet destination.
This rule removes the accomplice-liability problem of a Tor exit node fully,
and it is a real advantage of the architecture.

A secret software-modification power exists in the United Kingdom under a
technical capability notice, and in Australia under TOLA. No rule of this
part makes a modified release impossible, and §15.5 states that v1 does not
make it detectable.

### 15.6.1 Funding

Part 10 §10.9.1 sizes the outbound budget of a relay from the held sessions
and the cover rate. Rule `REL-022` forbids a budget against the real message
count. Thus the cost model of a relay is a cost for each held session, and
not a cost for each message. Onion-chained relays multiply the hosting cost
of a central single-hop architecture.

A launch below `AUTHORITY_FLOOR` shows a `provisional directory` state on
each client under `REL-126`. Under that state Part 3 rule `NET-340` lets a
client build a chain of one operator, thus a launch can start with the relays
of the project alone, in three blocs and three autonomous systems. Rule
`NET-350` also lets that launch start in one country and at one provider. One
legal order of that country then reaches each relay, as one order to the one
operator already does, and the provider sees each hop of each circuit.

## 15.7 Open problems

This section names the open problems honestly. A specification that claims to
have no open problem is not finished. Such a specification is unexamined.

1. **Post-quantum online deniability.** No QROM-secure construction exists at a
   practical size. UMBRA gives offline deniability only (Part 5 §5.7).
2. **A post-quantum VRF for key transparency** (§15.2.6).
3. **Transcript consistency in a group**, at a cost that UMBRA can pay (Part 11
   §11.7).
4. **Verifiable relay session multiplexing.** The unlinkability in Part 3 rests
   in part on a *behavioral* rule. A relay can disobey that rule silently, and a
   client cannot detect that. UMBRA inherits this problem from SimpleX, and the
   problem has no solution today.
5. **Signature monoculture.** ML-DSA-65 alone signs the long-lived objects that
   a third party verifies. Those objects are the directory roots and the
   transparency tree heads. A lattice break permits a retroactive rewrite of
   the archived state.

   The `sig_id` field is negotiable, thus a deployment can add a hybrid. But
   in the message core this is one point of cryptanalytic failure. UMBRA
   accepts that risk to keep the set of signed-object primitives minimal
   (Part 5 §5.1).
6. **Formal analysis.** No peer-reviewed analysis of SimpleX exists. Thus UMBRA
   inherits no assurance from its closest reference system. No formal
   analysis of the handshake, the ratchet, or the group key schedule of UMBRA
   exists.

## 15.8 A standing instruction

The table in Part 3 §3.11 and the Compellable Set in §15.1 are **published
promises**. A change to this protocol can make a row of one of those tables
false. **[SEC-016]** Such a change MUST come with a specification change and a
version increment. **[SEC-017]** A revision MUST NOT make a silent amendment.

A drift in those tables, one convenience at a time, is the failure mode that
ends this project.
