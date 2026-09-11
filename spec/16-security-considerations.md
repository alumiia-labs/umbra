# UMBRA Protocol Specification — Part 16: Security Considerations and Known Limitations

**Status:** Draft
**Version:** 0.1.0-draft

---

## 16.0 The finding that gives this part its structure

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
**nothing** about item 2, and only Part 15 §15.8 gives a control.

**The update channel is the largest compromise vector of UMBRA.** It is not a
protocol problem, and that property is the cause that a project can under-invest
in it. §16.5 treats it as a first-class requirement, and not as an operational
footnote.

## 16.1 The Compellable Set

This section is the normative answer to goal G13. For each party it gives what
that party holds, for how long, and what that party gives under legal process.

**Each row that is not "nothing that identifies a user" is a design bug, and the
project tracks it as one.**

| Party | Holds | Retention | Gives under EPO / s.121 / TCN / RIPA s.49 / grand-jury subpoena |
| --- | --- | --- | --- |
| **Client device** | All the data: the root identity, the contacts, the history, the keys, and the spent-nonce set of the hellos of Part 14 §14.4 | Until a wipe | All the data, if the device is unlocked. Under RIPA s.49, or under French art. 434-15-2, a court can compel the **user** to decrypt. **UMBRA cannot help here.** |
| **Ingress relay** | The client IP address, the connection times, the cell counts, the cell sizes, and the hop 1 key set of each live circuit. That key set opens the hop 1 layer of a recorded cell, which gives the hop 2 ciphertext (Part 3 §3.4.4) | A conformant relay keeps the connection lifetime. A malicious or compelled relay can log for an unlimited period. A client pins two ingress relays, and each pin lasts 60 days confirmed and 120 days unconfirmed (Part 10 §10.6.1). Thus a prospective order against either operator captures that client for that period. | An IP address that ran UMBRA at the time T. Not the party, not the destination, and not the content. |
| **Chain relay** | Two adjacent relay addresses, the cell times, and the hop 2 key set of each live circuit. That key set opens the hop 2 layer of a recorded cell, which gives the hop 3 ciphertext | In memory only | Nothing that identifies a user. |
| **Queue relay** | Queue IDs, ciphertext, delivery times, a per-queue sequence counter, the last acknowledged sequence, and a maximum of 8 queues for each session. In Instant mode it holds the `(handle, k_tok, notifier_id)` triple of each registered queue. The hop 3 key set of a live circuit opens no recorded cell. Part 3 §3.4.4 rule `NET-208` erases each key set after its cell | `MSG_TTL` 45 d, `QUEUE_IDLE_TTL` 60 d. A relay destroys the sequence counter with the queue, and a `DEL` destroys the queue record (Part 6 §6.4.3). The triple rotates each 7 d under `NTF-007` | A set of random 32-byte identifiers, and ciphertext that the two endpoints of the channel alone can decrypt. In Instant mode, the `(handle, k_tok, notifier_id)` triple of each registered queue and its notification times (Part 8 §8.7). The triple names the notification handle of at most 8 queues, and with the NDR it gives the push token of that handle. A relay does not hold a device-set acknowledgment point. Part 7 §7.5.5 makes that acknowledgment an application record inside the L6 AEAD. Thus it is one `B0` cell on a sync queue. It reads as any other sync record. |
| **Community relay** | Post bodies, post hashes, per-author chain indexes, checkpoints, post stubs, community rosters, moderation epochs, encrypted metadata records, and pull volumes. It holds the notification queue registrations of Part 12 §12.6.4. A pull carries no client identifier (Part 12 §12.3.3), and a registration carries none. The moderation epoch chain is a **signed removal ledger** and a **signed ban ledger** (Part 12 §12.5.2) | `COMMUNITY_RETENTION` 90 d for a post, a stub, and a checkpoint (Part 12 §12.4.6). The control chain and the metadata stay while the relay serves the community. The chain is append-only by construction | The full public post history of a named pseudonym, and prospectively each future post of that pseudonym. A pull carries no pseudonym and no client identifier (Part 12 §12.3.3), thus no pull is attributable to that pseudonym. A community pseudonym does not rotate (Part 12 §12.9), thus this is the one durable identifier in the system. It also gives the signed removal ledger and the signed ban ledger, which name each removed post and each banned pseudonym under a signature |
| **Attachment relay** | Opaque chunks of one fixed size, under a random credential for each chunk. Part 13 §13.7 gives `CHUNK_SIZE`. The same store holds the backup objects of Part 4 §4.7.2 under a rotating handle | `CHUNK_TTL` 45 d for a chunk, `CHUNK_LIFE_MAX` 90 d for a chunk that a reader renews, `BACKUP_TTL` 180 d for a backup object | Opaque chunks. It cannot link a chunk to a file or to a user. A backup object is ciphertext under a key that the two halves of the Recovery Code give |
| **Notification relay (NDR)** | Stored `(handle, ct_token)` pairs. In Instant mode it holds `k_tok` and the token-to-handle mapping in memory at the dispatch | The stored handles rotate each 7 d. A malicious or compelled NDR can log the dispatch mappings prospectively. | A subpoena for "all push tokens" returns encrypted blobs. Prospective logging, a wiretap, or collusion with a relay recovers the token-to-queue mapping. |
| **Directory authorities** | Relay descriptors, class measurements, aggregates with added noise, and the signed operator dossier of each relay (Part 10 §10.6) | The consensus history. The dossier while the relay is listed | Nothing about a user. The legal entity, the beneficial-control declaration, the ASN, the jurisdiction, and the legal-process contact of each relay operator. Part 3 §3.10.1 makes the dossier a public record |
| **Handle directory**, which is the OPRF evaluator | Handle strings, rotatable handle keys, and rotatable rendezvous addresses. The blinded element of each OPRF evaluation, the token or the proof of work that paid for it, and the connection time of each lookup | The entries until a rotation. A conformant directory keeps no query log. A compelled directory can log each blinded query from the moment of the order | The handle list, which §9.3 makes worthless deliberately. A prospective log of blinded queries, which names no handle, because the directory never sees the plaintext (Part 9 §9.4) |
| **Queue relay of a rendezvous queue** | The queue address of a published handle or address, which any party that resolves the entry can name. The arrival time and the count of each hello | Until the rotation of `RENDEZVOUS_ROTATE` (Part 9 §9.9) | That a published entry received hellos at the times T. Nothing about a sender, because a hello is a padded message under the key of the entry (Part 9 §9.6) |
| **Token issuer** | The payment record of each purchase on path 1 of Part 14 §14.9, the batch count on each path, and the issuer keys | The payment processor defines the payment record. The keys rotate each 7 d | Who paid for a token batch, and when. Nothing about where a token was spent, because the signature is blind (Part 14 §14.3.3) |
| **A role holder of a community** | The reports of Part 12 §12.5.3 that reached its report queue, and its role pseudonym key | Until a wipe | The reported posts, the reasons, and the notes. No reporter, because a report names none |
| **A social-recovery share holder** | One Shamir share of `C_social` (Part 4 §4.7.3) | Until the user replaces the share set | One share. Three share holders reconstruct `C_social`, and that half alone opens nothing. Part 4 §4.7.1 splits the Recovery Code, and `C_user` stays with the user or in the platform-cloud item of `IDN-042` |
| **A platform-cloud item that holds `C_user`** | `C_user` only, and the user opts in (Part 4 §4.7.1) | The provider defines it | The user half of the Recovery Code. That half alone opens nothing, and `IDN-086` keeps a `C_social` share out of the same item |
| **A moderator or an owner of a private group** | The group history on that device, the `GroupRosterKey_g` of that group, and the granting chain that Part 11 §11.9.3 bounds | Until a wipe | The power to publish a signed moderation epoch that hides or removes a message on the device of each member. **This party is a named natural person, and Part 11 §11.9.6 creates it deliberately.** That section gives the four mitigations and states the residual |
| **The nonprofit** | The data that its own relays hold, from the rows above | As above | **No user database, because no user database exists.** There is no account, no registration, no phone number, no email address, and no global identifier. |
| **Apple and Google** | The mapping from a device push token to an account. The wake times and the wake count | The provider defines it | Which accounts have UMBRA installed, and at what times UMBRA woke them. **Treat this mapping as adversarial.** |
| **Platform cloud services (backup and sync)** | No UMBRA data, under Part 15 §15.6.6. A file that the user saved to the media store, and a screenshot | The provider defines it | Part 2 §2.2 models this party as A7. The platform backup carries no container of the client, because `IMP-048` and `IMP-049` exclude it. A saved file is a user action, and `IMP-046` warns before the first one |
| **Invitation host** | The time and the client address of each browser open of an invitation link, without the fragment | The nonprofit defines it | Part 4 §4.3.1. A device with the client opens no browser, thus the host sees an open by a party without the client only. The host cannot read the fragment, because a browser does not send it |
| **App stores** | The legal identity of the developer and the registration of the signing key | Permanent | The power to remove or replace the application in a jurisdiction. Refer to §16.5. |
| **Build infrastructure** | The release signing authority | Permanent | **The power to ship a malicious update.** This is the target with the highest value in the system. |

### 16.1.1 "We keep no logs" is not a defense

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

Two tiers above the pairwise tier hold a durable identifier, and §16.1 states
each one. A community pseudonym of Part 12 is durable, because a rotation loses
the post history of the author. A court can name that pseudonym in a
prospective order against a community relay. That order gets the public posts
of that pseudonym, and it gets no pull, because a pull names no pseudonym. It
does not get the person, because Part 12 §12.3.2 makes
`CommunityIdentitySeed_g` from the device CSPRNG.

A published handle or Public Address of Part 9 is durable for its lease,
because the user chose to publish it. A court can name it in an order against
the directory or against the relay of its rendezvous queue. The directory gives
the entry, which is public. The relay gives the hello times of one period,
because Part 9 §9.9 rotates the rendezvous queue at each `RENDEZVOUS_ROTATE`.
Neither one gives the person.

**[SEC-001]** An anonymous credential MUST authorize a queue rotation. **[SEC-002]** A long-lived key MUST
NOT authorize it. Thus the rotation does not make the linkage that it exists to
break.

## 16.2 What UMBRA does not defend against

This section states the limits plainly. A specification that hides a limit is
worse than a specification that has that limit.

### 16.2.1 Endpoint compromise and coercion

- **The seizure of an unlocked device (the AFU state).** This is the dominant
  forensic variable. The Cellebrite chain that Amnesty documented gets kernel
  code execution over USB, on an Android device that is locked and in the AFU
  state. The short auto-lock and the secure-element entanglement of Part 15
  §15.6.4 increase the cost. They do not remove the risk.
- **The platform of an honest device.** UMBRA operates on an operating system
  that UMBRA does not control. Part 2 §2.2 models that platform as A7, and Part
  15 §15.6.6 states what the client gives to each platform interface. A scan
  at the OS level reads what that section lets out, and no more.
- **Compelled key disclosure by the user.** The instruments are UK RIPA Part III
  s.49, French art. 434-15-2, and Australian TOLA. The protocol cannot help.
- **A malicious local change to the database.** Part 4 §4.6 makes such a change
  *detectable*, with a table MAC under a keystore key. It does not make the
  change impossible. The key `K_tab` derives from `K_store`. Thus a party with
  code execution before the auto-lock of Part 15 §15.6.4 reads `K_store` and
  computes a table MAC again. Part 4 §4.6 also does not detect a rollback of
  the full database file to an earlier state.

> **UMBRA does not ship a duress feature or a panic feature as a defense against
> key-disclosure law.** Such a defense is untested, and it invites a charge of
> obstruction. To offer it as protection is dishonest.

### 16.2.2 Global passive adversary

Part 3 §3.11 states this limit, and this part states it again. An adversary that
observes the two access links makes an end-to-end confirmation. UMBRA does
**not** defeat that confirmation in Fast mode or in Balanced mode. Private mode
makes the confirmation more expensive only.

This limit is a theorem and not a gap. With `c > 0` and a constant latency
overhead, strong anonymity is impossible (Das and others, PoPETs 2020(3)).
Empirically, DeepCoFFEA (IEEE S&P 2022) reaches a TPR of 93 % at an FPR of
2·10⁻⁴ on Tor. It reaches a TPR of 84–95 % against obfs4, WTF-PAD, and FRONT.

### 16.2.3 A majority of the relay capacity

An adversary that controls each relay in a chain recovers the tuple *(client IP
address, queue, time)*. The invariants of Part 3 §3.4.6 and the diversity limits
of Part 10 §10.6 make that control expensive. They do not make it impossible.

### 16.2.4 Transcript consistency in a group

A malicious group member sends different content to different members. UMBRA
does not detect that behavior in v1 (Part 11 §11.7).

### 16.2.5 The handle directory is enumerable

Part 9 §9.1 states this limit. A human-readable name has low entropy. The
mitigation is that a full crawl gives nothing of value.

The address index of Part 9 §9.3.3 is different. Its label is a 160-bit hash,
thus a crawl that enumerates the handle labels finds no address label. Only a
party that holds the address string reaches that entry. The listing of Part 9
§9.12 is the reverse case. A browse enumerates it by design, and Part 12
§12.7.2 states that a listed community is a public statement.

### 16.2.6 The key-transparency VRF is not post-quantum

`ECVRF-EDWARDS25519-SHA512-TAI` is classically secure only. **A harvested log
and a future quantum computer together de-blind the full historical handle
directory** (Part 9 §9.5.4). The message-content confidentiality path of UMBRA
is post-quantum. Discovery and anti-abuse contain classical auxiliary primitives
today, because no deployable post-quantum alternative is available. There is no
practical PQ VRF today.

### 16.2.7 Protocol detectability

A top-tier network classifier detects UMBRA at the flow level. Part 3 §3.8.1
makes this an explicit trade. The ClientHello of Part 3 §3.8 is the ClientHello
of the rustls stack, and not the ClientHello of a browser. UMBRA does not claim
to be unblockable. Refer to the non-goals in Part 2 §2.5.

Two properties of the design limit the damage from a lost relay. First, a relay
shares its IP address and port 443 with a genuine website. Thus a destination
address does not give a list of the users of UMBRA (G8). Second, a client holds
two pinned ingress relays (Part 10 §10.6.1). Thus the loss of one relay does not
stop delivery (U6).

### 16.2.8 iOS notification delivery has one operator

A third party can operate a queue relay. A third party cannot operate iOS
notification delivery, because the APNs certificates are not public (Part 8
§8.7.1). Private mode has no background carrier on iOS, thus an iOS user in
Private mode drains in the foreground only (Part 8 §8.4.2). This limit is the
sharpest tension between the infrastructure model and the
no-single-trusted-party goal.

### 16.2.9 Multi-device history exposure

The seizure of one linked device exposes the synced history of that device (Part
7 §7.2). The owner made this decision with full information. The mitigations
limit the exposure, and they do not remove it.

### 16.2.10 iOS distribution has one gatekeeper

Apple notarizes each iOS application, on the App Store and on an alternative
marketplace under the EU DMA. Thus no iOS channel is outside the control of
Apple, and `SEC-008` binds Android only. An order against Apple removes the
application from each iOS channel in a jurisdiction. The controls that stay are
the reproducible static library of Part 15 rule `IMP-070`, the published hash
of `IMP-071`, and the transparency log of `SEC-006`. Those three make a
modified iOS release detectable, and they do not make it deliverable.

## 16.3 Residual leaks, enumerated

| Leak | Who sees it | Bounded by |
| --- | --- | --- |
| An IP address ran UMBRA at the time T | The ingress relay, and a local observer | Nothing, and the exposure to each of the two named ingress operators lasts the pin lifetime of 60 to 120 days (Part 10 §10.6.1). UMBRA accepts this leak. |
| The cell sizes, from a ladder of 4 values | Each hop | Part 3 §3.3 bucketing |
| A maximum of 8 queues share a session | The queue relay | Part 3 §3.2.5 isolation limit |
| An approximate padded file size, from the chunk count | All the chunk relays in collusion | Part 13 §13.9 |
| The group membership, from the fan-out times | Two colluding queue relays | Part 11 §11.3.0 jitter |
| The list of the handles | Each party | Part 9 §9.3 — worthless deliberately |
| A device has UMBRA installed, and the wake times | Apple and Google | Part 8 §8.7 |
| The community content | The community relays | Part 12 §12.1 — public by design |
| A push token belongs to a party with a published handle or address | The Notification Delivery Relay and the queue relay of the rendezvous queue, in collusion | Part 8 §8.2.6. The rendezvous queue registers under a notification handle of its own, thus the pairwise queues stay apart. Private mode registers no rendezvous queue |
| The name, the topic, the language, and the activity of a listed community | Each party | Part 12 §12.7.2 — a listing is opt-in and off by default |
| The pseudonyms that reacted to a post, and the count | Each subscriber and each community relay | Part 12 §12.6.2 — a reaction is a chain record, and it is public in the same manner as a post |
| The linkage of the queues of one transport session, from a delay probe on one queue | An active A2 or A3 | Part 3 §3.2.5 bounds the set at 8 queues. That isolation limit binds a passive recorder only. UMBRA accepts this residual |
| The membership of a group, from a delay probe on one queue | An active A2 or A3 | Part 11 §11.3.0 jitter randomizes an emission time. It does not randomize a response to a probe. UMBRA accepts this residual |
| The reconnect cadence of a recipient, from the boundary of a cumulative acknowledgment | The queue relay | Part 6 §6.4.3 rule 7. A cumulative acknowledgment gives one boundary for each batch, and not one for each message. UMBRA accepts this residual |
| The send times of a user with the application in the background | The ingress relay, and a local observer | Nothing. Part 3 §3.6.2 makes no cover cell outside the foreground, thus a background outbound cell is a real event. UMBRA accepts this residual |
| The send time of a Private-mode message on the client link | The ingress relay, and a local observer | Part 3 §3.9. A Private-mode send no longer waits for a cover slot. The per-hop delay and the inbound pacing stay. UMBRA accepts this residual |
| The delivery tail of a Private-mode message | The recipient, and a local observer | Part 3 §3.9. A constant-rate inbound clock gives a tighter tail at the same cell rate. UMBRA gives it up, because a pacing shape that differs by mode names the mode in the inbound cell count. UMBRA accepts this residual |
| The bucket of each inbound cell | A local observer | Part 3 §3.5.2. The inbound pacing cover cell is bucket `B0` at 560 B, and the modal text delivery is bucket `B1` at 2 096 B. Thus the cover does not conceal the bucket. Bucket-matched cover costs about 39.5 MB for each 2 h session against 4.03 MB. UMBRA accepts this residual |
| The shape of a large reconnect drain | A local observer | Part 3 §3.5.2. A backlog above `DRAIN_THRESHOLD` leaves the relay in one unpaced response, and the observer reads it as one burst. A paced drain of that backlog would fail U6. UMBRA accepts this residual |
| Up to `SENDER_KEY_GENERATIONS` live chain keys of each group member, on a seized device | A6 | Part 11 §11.3.2. `SENDER_KEY_GENERATIONS` is 3 and `SENDER_KEY_MAX_AGE` is 7 days. UMBRA accepts this residual |
| The tombstone table on a seized device, which names each deletion inside the retention window | A6 | Part 7 §7.5.2 and §7.5.3. The source watermark bounds that table by the retention window. The table is not a permanent record of every deletion of the user |
| A transferable proof of the current role grants of a group, on a seized device | A6 | Part 11 §11.9.3. A granting epoch is signed, and the retention rule keeps the authority path only. G10 does not cover the group administration after this change. UMBRA accepts this residual |
| A signed statement that a named role acted on a named `msg_id`, on a seized device | A6 | Part 11 §11.9.6. The preimage names no author, and rule GRP-181 keeps the current statements only. UMBRA accepts this residual |
| A recovered record in a group, whose sender key came from a key supply and not from an ordered chain | A6, a member that replays a supply | Part 6 §6.6.11 and Part 11 §11.3.3. Rule WIR-334 binds the supply to the channel of the request, and rule WIR-335 marks the record. UMBRA accepts this residual |
| The channel of a joiner to one member, when the inviting admin opens the invitation of that member itself | A hostile admin | Part 11 §11.9.1. The first-access lock of Part 4 rule IDN-023 fails at the joiner, and rule GRP-178 names the admin. UMBRA accepts this residual |
| The blinded subject list of the roster, on a seized device that holds `K_set` | A6 | Part 7 §7.3.1. Rule DEV-226 blinds each subject under `K_set`, and a seized device holds that key. The blinding protects the archive of Part 7 §7.6.1 and a roster that left the set. UMBRA accepts this residual |
| The linkage of two queues to one group, from two `B2` cells inside the jitter window | Two colluding queue relays | Part 11 §11.9.4. `GRANT_RATE` bounds the frequency of a granting epoch. It does not conceal the event. UMBRA accepts this residual |
| A delayed settlement of a community post, from a withheld checkpoint | One community relay, for as long as that relay serves the community | Nothing prevents the withholding. Part 2 §2.5 gives guaranteed availability as a non-goal. The detection is the cross-relay check of Part 12 §12.4.3.1, and the remedy is to drop the relay. UMBRA accepts this residual |
| An edit that follows a group message, inside the same jitter window | Two colluding queue relays | Part 11 §11.3.0. The jitter randomizes each fan-out alone. It does not decorrelate two fan-outs that one user action couples in time. UMBRA accepts this residual |
| An edit whose new text is above 145 bytes, because the cell steps from `B0` to `B1` | The queue relay | Part 6 §6.6.1 gives the band. **[SEC-003]** A client MAY split the text, and this specification does not require that split. UMBRA accepts this residual |
| A permanent and public pointer at a withdrawn community post | Each community relay, and each subscriber | Part 12 §12.4.5. The pointer sits inside a checkpoint that publishes anyway, and the field has a fixed width. The feature does not work against a party that archived the community. UMBRA accepts this residual |
| A selected profile picture, which is the same bytes at each party that resolves one Profile | Two parties that resolve one Profile | Part 4 §4.2.5. Those two parties hold one Public Address string already, thus they can already link. The concession stays inside one Profile, and a generated picture does not have it. UMBRA accepts this residual |
| A rollback of the local database file to an earlier state, on a seized device | A6 | Nothing. Part 4 §4.6 gives a table MAC over a row count, a commit counter, and an accumulator of the record tag of each live row. That MAC detects a change to one row and a rollback of one row. A rollback of the full file restores each of the three together. The platforms give no monotonic counter that survives a device restore. UMBRA accepts this residual |
| One `msg_id` at each member of a group, thus two members can prove that they hold one send from one member | Two colluding group members | Part 11 §11.2.1. A member holds the roster already, thus the two members know that they share the sender. The value stays inside the AEAD of a pairwise channel, and no party outside the group reads it. UMBRA accepts this residual |
| The signing device of each roster epoch, on a seized device of the same device set | A6 | Part 7 §7.3.1. The `signer_id` field and the ML-DSA-65 signature name one device of the user. The roster never leaves the device set, thus no relay and no contact reads it. UMBRA accepts this residual |
| A split device set, when a hostile linked device revokes one honest device and not the other | A6, before the user revokes that device | Part 7 §7.3.1 rule DEV-177 and Part 7 §7.7 rule DEV-182. The two honest devices then disagree, and each one shows the fork at the next epoch. In a set of three devices the hostile device can revoke the two honest devices in two competing epochs. Rule DEV-178 makes each honest device show that fork. The fix is the full identity reset of Part 7 §7.7.1. UMBRA accepts this residual |
| A change to the local database by a party with code execution before the auto-lock | A6 | Nothing. Part 4 §4.6 derives `K_tab` from `K_store`, which that party reads from RAM, thus that party computes a table MAC again. Part 16 §16.2.1 states this limit. UMBRA accepts this residual |
| The size of one conversation, from a group fan-out of *N* − 1 cells | The ingress relay, and a local observer | Part 11 §11.3.0 randomizes the order inside the burst and it does not conceal the count. Part 2 §2.2 THR-002 covers the **count of conversations**, and Part 3 §3.11 states that this residual is the **size of one conversation**. UMBRA accepts this residual |
| The queue set of a private group, at a tier T3 re-broadcaster | The re-broadcaster operator (A2), and A5 against it | Part 11 §11.6. G11 holds for tier T1 and tier T2. GRP-027 makes a re-broadcaster optional, GRP-028 requires more than one, and GRP-123 states the concession to each member. UMBRA accepts this residual |
| A permanent channel takeover, when a user accepts a key-change notice that an attacker sent | A6, transient, and then permanent | Part 4 §4.5.1. The notice carries no signature, thus the ratchet is the only authentication. IDN-089 through IDN-092 put the weight on the prompt. G5 does not hold across an accepted notice. UMBRA accepts this residual |
| A skipped-message key that lives 45 days in place of 14 | A6 | Part 5 §5.5.4. `SKIP_TTL` now equals `MSG_TTL`, because a shorter value made a delivered message undecryptable against U9. `MAX_SKIP`, `MAX_STORED`, `MAX_BYTES`, and `MAX_STORED_DEVICE` bound the count, and only the age changes. UMBRA accepts this residual |
| A circuit that one injected cell tears down | An active A1, A2, or A3 | Part 3 §3.4.5. The chained construction makes any change fatal to the circuit, which is the property that defeats the tagging attack. The loop cover of Part 3 §3.6.1 measures the event and Part 10 §10.4.2 reports it. Part 2 §2.5 gives guaranteed availability as a non-goal |
| A group presence record, which shows an administrator that a member is live | An administrator of that group, and A6 against that device | Part 11 §11.9.7. The record names the group and nothing else, and it goes to the `admin` role and above only. §11.8 needs that signal for the eviction that RFC 9420 §16.6 makes necessary. UMBRA accepts this residual |
| A link preview that a sender made, which a hostile sender pairs with a true URL | The receiver | Part 3 §3.3.2. NET-142 keeps the receiver from a fetch, thus the linked site gets no address. NET-148 renders the host beside the preview. UMBRA accepts this residual |
| A draft on a sync channel, which is text that no party sent | A peer device of the same set, and A6 against it | Part 7 §7.5.3. DEV-199 holds a draft under the record encryption and DEV-200 keeps it out of a backup. DEV-202 lets the user turn the sync off. UMBRA accepts this residual |
| A live queue and an ordinary delivery receipt for a blocked contact | The blocked party, and the queue relay | Part 14 §14.12. The alternative is a `DEL` that names the moment of the block, and ABU-025 gives the cause. The cost is the bytes of a live queue. UMBRA accepts this residual |
| A poll vote fan-out of *N* × (*N* − 1) cells | Two colluding queue relays | Part 11 §11.11. `POLL_GROUP_MAX` caps a poll at 100 members, which is 9 900 cells. §11.3.0 jitters each fan-out. UMBRA accepts this residual |
| The mention list of a record, which reaches each member of a group | Each member of that group | Part 11 §11.11. GRP-141 keeps a client from rendering the list to a member that it does not name. The bytes still reach that member inside the AEAD. UMBRA accepts this residual |
| The pulls of one transport session at a community relay | The community relay | Part 12 §12.3.3. A pull carries no client identifier, and COM-173 holds one community in each session. The relay links the pulls of one session to each other, and it links nothing across two sessions. UMBRA accepts this residual |
| A renewal of a chunk at each fetch of a community attachment | The relay that holds the chunk | Part 13 §13.3.3 rule 8 and Part 12 §12.4.6. A `CRNW` follows a `CGET` in one session, thus it shows the relay nothing that the fetch did not show. UMBRA accepts this residual |
| The replica set of one chunk | The relay that took the `CPUT` of that chunk | Part 13 §13.4.1. The three replicas hold byte-identical ciphertext, thus §13.3.3 already concedes that a comparison links them. The rule removes the collusion step and adds no capability. ATT-122 keeps the replica set of each chunk independent, thus no relay learns a second chunk of one file. UMBRA accepts this residual |
| The dead-channel handle of a contact pair, which a classical static-static X25519 derives | A quantum adversary that holds the two pairwise public keys, and the relay that holds the blob | Part 3 §3.2.6. The pairwise public keys travel inside an AEAD, thus the adversary needs a seized device or the invitation. The blob holds a `QueueAddress` under a key from the same secret. The relay learns that one pair lost its channel, and not who the pair is. UMBRA accepts this residual |
| A tombstone version of a handle, which shows that the holder let the lease lapse | Each party that passes the lookup chokepoint of Part 9 §9.4 for that handle | Part 9 §9.9.2. The log already publishes each version of the label under `DIS-007`, and a tombstone is one more version. The version shows no date, because Part 9 §9.3 keeps a timestamp out of the entry |
| The admission backlog of a relay, from the `effort` of its `PowChallenge` | Each party that fetches the descriptor of that relay | Part 14 §14.8 rule `ABU-060`. The effort is one 32-bit value from the admission backlog of the relay, and it names no client. The descriptor of Part 10 §10.5.3 already publishes the capacity class of the relay |
| One onion layer of each recorded cell of a live circuit, when an adversary seizes the hop 1 or hop 2 key set | A6 at a middle relay | Part 3 §3.4.4. That layer gives the ciphertext of the next layer, and `CIRCUIT_MAX_AGE` of 4 hours ends the key set. The hop 3 key set updates at each cell under rule NET-204. An earlier draft ended it at 10 minutes, and Part 3 §3.4.3 gives the cause of the change. UMBRA accepts this residual |
| The wakes of one client at one ingress across 4 hours, and across a network change, which one session links | The ingress relay | Part 6 §6.2.3. `SESSION_RESUME_WINDOW` of 4 hours lets a push wake resume its session, and Part 3 §3.12 gives the builds that the resume saves. The ingress already links the wakes of one live circuit, thus the resume adds the link across a network change only. UMBRA accepts this residual |
| The bloc of hop 2 equals the bloc of hop 1 or of hop 3, under the relaxation of `NET-200` | The two relays that share the bloc, and the order that reaches both | Part 3 §3.4.6. Hop 1 and hop 3 stay in different blocs, thus no one order joins the client address to the queue. The client shows the relaxation under `NET-201`, and `NET-033` fails closed below it. Part 10 §10.6.3 sets the floor that ends the relaxation, and §16.6.1 sets the recruitment target that reaches the floor |
| The client clock follows a stale but valid `DirectoryRoot` at the first launch | An ingress relay that serves the stale root, and each relay that the retired set names | Part 10 §10.5.2. `REL-046` bounds the staleness to the age of the build, and `REL-034` keeps the epochs monotone under it. `REL-044` takes a new correction at the first fresh root. A holder of the only path of a client can replay a sequence of roots at the true cadence for the age of the build. `REL-008` detects the divergence on the first other channel. UMBRA accepts this residual |
| A relay outside the measured sample of a large cluster lends capacity to a relay inside it | The directory authority, as an inflated class of the sampled relay | Part 10 §10.3. `REL-102` shows the VRF selection after the epoch closes, thus the cluster feeds the lender blind. `REL-101` measures each relay inside `ceil(n / CLUSTER_SAMPLE)` slots, and `REL-001` limits the payoff to one class step in each epoch. UMBRA accepts this residual |
| The typed text of each message, and the passphrase, at the input method | A7, as the input method | Part 15 §15.6.6. `IMP-057` sets the no-learning flag on Android, and iOS gives no flag. The input method is a process that the user selected, and UMBRA cannot replace it. UMBRA accepts this residual |
| Each rendered message, at an enabled accessibility service | A7, as an accessibility service | Part 15 §15.6.6. `IMP-060` keeps the accessibility tree whole, because a hidden message is a hidden conversation for a user that cannot see the screen. The user enables each such service. UMBRA accepts this residual |
| A saved file and a screenshot, at each platform service | A7, as the platform cloud service | Part 15 §15.6.6. `IMP-045` makes the save an explicit action on one file, and `IMP-046` warns before the first one. `IMP-058` offers a screenshot block for one conversation on Android. UMBRA accepts this residual |
| A page image below the file system, at the flash layer | A6, with the flash chips | Part 15 §15.6.4. `IMP-042` and `IMP-043` overwrite a freed page and truncate the log. The flash translation layer keeps an old page that no file system call reaches. The record key of that page is a value that `IMP-041` overwrote, thus the page opens under no key. UMBRA accepts this residual |
| The notification keys of the current and the next epoch, and the alias map, in the after-first-unlock state | A6, with code execution on a locked device | Part 15 §15.6.6 and Part 8 rule `NTF-042`. The extension runs on a locked device, thus the two objects sit at the tier that the database refuses. The two keys open a wake payload of Part 8 §8.2.3 and no message. UMBRA accepts this residual |
| The rebuild timing of a circuit, from a drop of each cell of that circuit | An active A2 or A3 | Part 3 §3.11.1. `CIRCUIT_MAX_AGE` of 4 hours makes a rebuild normal, and the loop cover of Part 3 §3.6.1 measures the drop. UMBRA accepts this residual |
| The hello count and the hello times of a published handle or address | The queue relay of the rendezvous queue | Part 9 §9.6. The queue address is public by the choice of the holder. `RENDEZVOUS_ROTATE` of Part 9 §9.10 moves the queue on a schedule, thus one relay holds that count for one period. UMBRA accepts this residual |
| The blinded element and the time of each lookup, at a compelled directory | The handle directory, under a prospective order | Part 9 §9.4. The directory never sees the plaintext handle, and the token of Part 14 §14.3.2 names no client. The log gives a lookup count and the lookup times, and no handle. UMBRA accepts this residual |
| The payment record of a token purchase | The token issuer, and the payment processor | Part 14 §14.9. The signature is blind, thus the record links to no token and to no relay. A purchase is one of three paths, and path 3 costs time and makes no record. UMBRA accepts this residual |
| The count of tokens that one party holds in an epoch, which no rule bounds | The issuer, which cannot count for one party | Part 14 §14.9. A payer is anonymous, thus no cap for one payer exists. The epoch of `ABU-004` bounds the life of a token, and the price bounds the count. UMBRA accepts this residual |
| A report, which names a post, a reason, and a note, at one role holder | That role holder, and A6 against its device | Part 12 §12.5.3. The report names no reporter, and `COM-268` selects the role holder at random. UMBRA accepts this residual |
| A signed statement by a relay operator that it removed a post under a legal order, beside the stub | Each reader of that community | Part 12 §12.4.4 rule 10. The `OperatorRemoval` names the relay and the index, and it names no reader and no reporter. Each other relay of the community still serves the body. UMBRA accepts this residual |
| The metadata fields of an original that the user selected for one send | The recipient, and each party that the recipient gives the file to | Part 13 rule `ATT-155` removes each field by default, and `ATT-157` keeps them for the original that a user selects. The sender sees that statement at the selection. UMBRA accepts this residual |
| The download count of a chunk of a community attachment, which follows the pull volume of the community | The chunk relay that holds the chunk | Part 13 §13.9 and Part 12 §12.4.7. The chunk relay does not learn the community, because the descriptor travels in the community record. UMBRA accepts this residual |
| The phase of the fixed clock of Private mode, which is one value for each install between two draws | The ingress relay, and a local observer | Part 8 §8.3. The wakes fall at one offset inside each interval, thus two networks that see one phase see one client. `NTF-052` and `NTF-053` draw a new phase at each network change and at each ingress change. UMBRA accepts this residual |
| A match of two six-digit codes under an active adversary at the first contact, with a probability of one in 10⁶ for each ceremony | An active A3 at the first contact | Part 4 §4.5.2. The commit binds each nonce before the reveal, thus the adversary cannot select a nonce. The 60-digit safety number stays available for a comparison that needs more. UMBRA accepts this residual |
| The count of the registered notification queues of a community, which is close to its Instant-mode subscriber count, and the queue relay of each one | The community relay | Part 12 §12.6.4. A registration carries no pseudonym and no pull identifier, thus the relay links a queue to nothing. `COM-369` holds a registration in memory for 7 days. UMBRA accepts this residual |
| The invitation landing document, at a hostile invitation host | The invitation host, against a party without the client | Part 4 §4.3.1. `IDN-120` and `IDN-121` fix a static document with no script, and a host that serves a different document breaks that rule. The fragment never reaches the host. A fetch that the host makes from a link locks the queue under `IDN-023`, and the two parties detect it. UMBRA accepts this residual |

**[SEC-018]** A revision that adds a residual leak MUST add a row to this table.
**[SEC-019]** A revision that removes a leak MUST remove its row in the same
commit. §16.8 makes this table a published promise.

## 16.4 Attacks that this design anticipates

| Attack | Where this specification addresses it |
| --- | --- |
| Relay seizure and log correlation | Part 3 §3.2 — two unrelated queue IDs, and a key set for each queue |
| A join of the sender and the recipient across two relays | Part 3 §3.4.6 — operator, jurisdiction, and ASN disjointness, enforced in code |
| Latency-injection correlation (ToB #7, not corrected upstream) | Part 3 §3.5.3 — a randomized delivery delay, with named distributions |
| A message-existence oracle from the packet counts (ToB #2) | Part 8 §8.4.2 — a fetch response with a constant size and a constant count |
| Compulsion of a TLS key (Lavabit) | An inner transport encryption layer below TLS, shipped in v1, with short-lived relay identity keys |
| Deanonymization of a sealed sender through delivery receipts | Part 3 §3.5.4 — a receipt is an ordinary padded message, and it is off by default. A receipt rides a cover slot, and it replaces the cover cell of that slot |
| Bandwidth inflation (177×, 420×, 28×) | Part 10 §10.2 — discrete classes limit it to 4× in one 7-day epoch and to 64× over the ladder |
| Sybil flooding (KAX17) | Part 10 §10.7 — staging with an automated sybilhunter |
| Directory equivocation (IEEE S&P 2024) | Part 10 §10.5 — a 5-of-7 Byzantine broadcast with in-band gossip |
| Performance-adaptive selection as an oracle (PETS 2011) | Part 10 §10.6.2 — **[SEC-004]** local performance MUST NOT replace a relay |
| A group-membership beacon (the "flurry" attack) | Part 11 §11.3.0 |
| KEM re-encapsulation and key confusion (PQXDH) | Part 5 §5.3 and §5.11 — full transcript binding and domain separation |
| A tagging attack on the onion layer | Part 3 §3.4.4 — rugged-PRP per-hop encryption, with the tag of the layer below in the left block |
| A delivery beacon from a link preview fetch | Part 3 §3.3.2 — the receiver MUST NOT fetch a URL |
| A queue teardown that names the moment of a block | Part 14 §14.12 — the queue stays live and the acknowledgments continue |
| A reflector or a relay-detection probe from `MEAS_ECHO` | Part 10 §10.3.1 — a measurement session needs a `MeasurerCert` |
| A prekey-trial amplification against a responder | Part 5 §5.4.8 — flight 1 names one prekey with `pid` |
| A cross-command replay of a queue authenticator | Part 3 §3.2.3 — the authorized bytes and the `corr_id` rule |
| A break of deniability from a prekey signature | Part 5 §5.4.1 — no party signs a prekey |
| A DoS from skipped keys | Part 5 §5.5.4 — hard limits, and one of them is device-global |
| Invisible salamanders in franking | Part 13 §13.3.1 — key-committing AEAD with a negative test vector |
| An attestation relay (Quarkslab 2026) | Part 15 §15.6.5 — no hardware attestation for anti-abuse |

## 16.5 The update channel

This channel is the largest compromise vector that each system in this list does
not address, and the problem becomes more difficult.

**Requirements, all for v1:**

- **Reproducible builds** with a pinned toolchain. **[SEC-005]** The rebuild of the Rust core,
  the Android application, and the relay MUST be byte-identical.
- **Release metadata in the TUF format**, with a root threshold of **3-of-5 or
  more**. Individuals in **three or more jurisdictions** hold those keys
  offline.
- An **append-only transparency log** records the hash of each release. **[SEC-006]** The
  client MUST verify an inclusion proof before it applies an update. **[SEC-007]** The client
  MUST also **gossip the log heads with peers**, thus a split view becomes
  detectable.
- **Two or more independent rebuilders** publish attestations.
- Use Sigstore and Rekor for the log, but **pin the TUF root of UMBRA**. Do
  **not** use keyless OIDC signing. That method ties the release authority to a
  Google account or to a GitHub account, and a court can compel such an account.
- **Divide the release-signing authority across jurisdictions.** Thus one order
  against one signer does not give a release that a client accepts.

**Distribution:**

- Keep **three or more independent distribution channels**. **[SEC-008]** **On
  Android, one or more of those channels MUST be outside the control of
  Google.** **[SEC-020]** That channel MUST serve a non-certified Android
  device, which is a device without the Google services. On iOS each channel
  sits under the notarization of Apple, and §16.2.10 states that limit.
  **[SEC-009]** One or
  more channels MUST rebuild the release independently and verify it
  byte-for-byte against the published artifact. A second channel that rebuilds
  the release makes a modified build on one channel detectable. This control
  answers item 2 of §16.0 and trust assumption 4 of Part 2 §2.6.

  In 2026 the set below meets this requirement:

  - a platform store
  - an alternative marketplace under the EU DMA, or web distribution under Apple
    Notarization
  - a free-software catalog that verifies reproducible builds, or a direct
    download

  **No named vendor is normative.** **[SEC-010]** An implementation MUST NOT treat one catalog
  as a dependency. This requirement exists for three causes.

  First, a court can compel a channel to replace the application in a
  jurisdiction. Second, a channel can stop. Third, a channel that rebuilds the
  release detects a replaced artifact. Refer to A5 in Part 2 §2.2 and to the App
  stores row of §16.1.

  Weigh the channels, and do not only collect them. A catalog that rebuilds
  independently is worth more than a catalog that only mirrors. But the review
  of a catalog and its build queue add days or weeks to the update latency. That
  latency is a real cost for a security-critical application. That cost is the
  cause that some projects decline that route fully. **[SEC-011]** **One or more channels MUST
  be able to ship a security update in 24 hours.**
- Where the law permits, use **a different registered legal entity for each
  channel**. Thus one order against one entity does not reach each channel. A
  court that compels one entity cannot replace the application on the other
  channels (A5). In 2025 alone, Apple removed 1 213 applications in Russia. That
  number shows that an order against a store is a routine event. Continued
  availability in a country is a side-effect of this measure, and it is not a
  goal.
- The developer-verification regime of Google starts enforcement on **30
  September 2026**. That regime needs the legal identity of the nonprofit and
  its signing key, registered with Google. **This registration is a named entry
  in the threat model**, and it is not a formality.

## 16.6 Legal and governance requirements

These items are protocol requirements, because they decide if the protocol
survives.

- **Closed-world routing.** A relay speaks UMBRA only, to a client and to
  another relay. A relay does not speak to an arbitrary internet destination.
  This rule removes the accomplice-liability problem of a Tor exit node fully,
  and it is a real advantage of the architecture. State this advantage in the
  documentation for a relay operator.
- **An EU legal representative** under Directive (EU) 2023/1544. Regulation
  2023/1543 (e-Evidence) became applicable on 18 August 2026. It has response
  deadlines of 10 days and of 8 hours. Its penalties reach 2 % of the global
  turnover, and the representative carries them jointly. Publish a standing
  response procedure. That procedure confirms receipt in the emergency window,
  and it **states truthfully which data the nonprofit does not hold**.
- **Rest the CRA position on Recitals 15 and 16, and charter the nonprofit as
  an open-source software steward** (CRA Article 24). The client and the
  reference relay stay free software permanently, and no party supplies them
  in the course of a commercial activity. The sale of a token batch of Part 14
  §14.9 is a payment for relay capacity and not for the software. `ABU-091` of
  that section caps the price at cost recovery. There is no
  donation gate, no telemetry, and no collection of personal data outside of a
  security function. This structure keeps the software outside the CE marking
  and the conformity assessment. Note that the independent operation of build
  infrastructure triggers the severe-incident reporting of Article 14(3).
- **Enforcement friction, and not a shield.** A secret software-modification
  power exists in the United Kingdom under a technical capability notice, and
  in Australia under TOLA. **[SEC-012]** The entity that controls the release
  signing MUST hold no seat, no staff, and no asset in such a jurisdiction.
  That rule raises the cost of an order, because such a
  jurisdiction then holds nothing to seize and no person to compel. It is not
  a shield. A notice can name a party outside the jurisdiction, and a court of
  that jurisdiction can order a store to remove the application there. The
  controls that answer a secret modification order are the reproducible build
  of `SEC-005`, the second channel of `SEC-009`, and the transparency log of
  `SEC-006`. Those three make a modified release detectable by a party outside
  the order, and no rule of this part makes it impossible.
- **Publish a technical infeasibility statement** as a numbered annex to this
  specification. That statement covers client-side scanning, access to message
  content, and originator traceability. It cross-references the clauses that
  make each one impossible.

  That statement is the substantive submission in four proceedings. Those
  proceedings are a UK OSA s.121 proportionality assessment, an EU CSAR
  risk-mitigation discussion, an Indian Rule 4(2) proceeding, and a TOLA
  systemic-weakness objection. It is worth more than a policy document.
- **Obey App Store Guideline 1.2 without the nonprofit seeing the content.** The
  method has five parts:

  - client-side blocking and muting
  - an in-application report flow that makes a locally-signed bundle for the
    moderators of that community
  - a published moderation policy
  - published contact information
  - a documented expectation that a moderator responds in 24 hours

  The guidelines of Apple now extend 1.2 to anonymous chat applications
  explicitly.
- **[SEC-013]** **The project MAY publish a warrant canary.** **[SEC-014]** **The
  project MUST NOT present a warrant canary as a control.** The canary of Riseup
  stopped in November 2016, after two sealed warrants with gag orders. Riseup
  concluded that the canary was too coarse to inform a user, and that the real
  remedy was architectural. State in the same document that a canary is legally
  untested. Point the users to the transparency log and to the reproducible
  builds.

### 16.6.1 Funding

Budget the relay cost before v1, and publish the model. Part 10 §10.9.1 sizes
the outbound budget of a relay from the held sessions and the cover rate. Rule
`REL-022` forbids a budget against the real message count. Thus the
published model is a cost for each held session, and not a cost for each
message.

Signal spends about **$12.5 M each year on hosting**, for a *central single-hop*
architecture. In 2024 Signal had $29.4 M of revenue against $38.0 M of expenses.
Onion-chained relays multiply that cost.

- Target a reserve that covers **24 months or more** of core-relay operation
  before the launch.
- Limit one funder to a hard percentage of the annual revenue, **in the
  bylaws**.
- Fund the two auditors of the handle directory log (Part 9 §9.5.2) from the
  same reserve, for the same 24 months or more. Each auditor sits in a
  jurisdiction other than the seat of the nonprofit, and other than the seat of
  the second auditor. Signal pays two auditors, and both sit in one
  jurisdiction. A third jurisdiction costs more than a second auditor.
- Fund the measurement fleet of Part 10 §10.3 from the same reserve. Part 10
  §10.3 sizes one class-C2 test at 36 Mbit/s for 30 seconds. Rule `REL-097`
  measures each relay above C0 one time in each 7 days. About 3 000
  relays give about 430 tests each day, and a sampled cluster adds
  `ceil(n / CLUSTER_SAMPLE)` slots for each large cluster.
- Recruit relay operators in a third jurisdiction bloc before the launch. Part
  10 §10.6.3 sets a floor of three blocs. Each bloc holds 10 % of the ingress
  population and of the chain population. Part 10 §10.12 names two blocs. The third
  bloc is one state under `REL-093`, thus the target is one state that holds 10
  % of each population.
- Seat the seven directory authorities under seven legal persons before the
  launch, under Part 10 §10.5.1. A launch below `AUTHORITY_FLOOR` shows a
  `provisional directory` state on each client under `REL-126`.
- Note that the EU NGI and NLnet funding stream paid for much of this ecosystem.
  The Horizon Europe 2025 work programme cut that stream, and the stream stopped
  fully in June 2026. Do not plan for it.

## 16.7 Open problems

This section names the open problems honestly. A specification that claims to
have no open problem is not finished. Such a specification is unexamined.

1. **Post-quantum online deniability.** No QROM-secure construction exists at a
   practical size. UMBRA gives offline deniability only (Part 5 §5.7).
2. **A post-quantum VRF for key transparency** (§16.2.6).
3. **Transcript consistency in a group**, at a cost that UMBRA can pay (Part 11
   §11.7).
4. **Verifiable relay session multiplexing.** The unlinkability in Part 3 rests
   in part on a *behavioral* rule. A relay can disobey that rule silently, and a
   client cannot detect that. UMBRA inherits this problem from SimpleX, and the
   problem has no solution today.
5. **iOS notification delivery without one operator** (§16.2.8).
6. **Ban evasion in a community**, without a return to identity (Part 12 §12.5).
7. **Signature monoculture.** ML-DSA-65 alone signs the long-lived objects that
   a third party verifies. Those objects are the directory roots, the
   transparency tree heads, and the community roster roots. A lattice break
   permits a retroactive rewrite of the archived state.

   The hedge is partly in place. The release manifests and the TUF root are in a
   separate trust domain, with offline keys that are not lattice keys (§16.5).
   The `sig_id` field is also negotiable, thus a deployment can add a hybrid.
   But in the message core this is one point of cryptanalytic failure. UMBRA
   accepts that risk to keep the set of signed-object primitives minimal (Part 5
   §5.1).
8. **Formal analysis.** No peer-reviewed analysis of SimpleX exists. Thus UMBRA
   inherits no assurance from its closest reference system. **[SEC-015]** UMBRA SHOULD
   commission a formal analysis of the handshake, the ratchet, and the group key
   schedule before v1.0.

## 16.8 A standing instruction

The table in Part 3 §3.11 and the Compellable Set in §16.1 are **published
promises**. A change to this protocol can make a row of one of those tables
false. **[SEC-016]** Such a change MUST come with a specification change and a version
increment. **[SEC-017]** A revision MUST NOT make a silent amendment.

A drift in those tables, one convenience at a time, is the failure mode that
ends this project.
