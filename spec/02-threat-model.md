# UMBRA Protocol Specification — Part 2: Threat Model and Security Goals

**Status:** Draft
**Version:** 0.25.1
**Date:** 2026-10-13

---

## 2.1 Why this part comes first

This part gives the cause for each design decision in this specification. A
privacy protocol without an explicit adversary model is a marketing document.
This part states plainly where UMBRA cannot protect a user, and it does not hide
such a limit in a footnote.

The failures that deanonymized the users of "secure" messengers were almost
always **metadata failures and endpoint failures**. Broken ciphers were not the
cause. UMBRA gives its design weight accordingly.

## 2.2 Adversary classes

UMBRA models seven adversaries. One adversary can be more than one class at the
same time. A real investigation combines the classes.

**Each network class below is on-path and active. A4 observes and does not act.
A5, A6, and A7 act from other positions, and the subsection of each one states
that position.** An adversary that carries traffic can drop a cell, delay a cell,
reorder a cell, and replay a cell. That adversary can also put new bytes on a
link that it holds. This capability comes from the position of the adversary,
and it needs no separate class.

No class below can decrypt a record in transit. No class below can forge a
record that a key of a party authenticates. **A6 is outside this sentence,
because A6 holds the device and its keys.** UMBRA does not give guaranteed
availability against an active adversary, and §2.5 states that limit.

### A1 — On-path network adversary (local)

**What A1 can do:** A1 holds one or more network links. A1 can be an ISP, a
mobile carrier, a national IXP, or a Wi-Fi operator. A1 records volumes, times,
packet sizes, and endpoints. A1 also drops, delays, replays, and injects bytes
on a link that A1 holds. A1 cannot decrypt a record in transit, and A1 cannot
forge a record that an UMBRA key authenticates.

**In scope.** **[THR-001]** UMBRA MUST prevent A1 from learning the content or the recipient.
**[THR-002]** UMBRA MUST also prevent A1 from learning the number of different conversations
or the identity of a correspondent.

A1 learns that the device of the user connected to an UMBRA relay. A1 also
learns how much data moved and at what time. The traffic-shaping policy in Part
3 controls these two facts. A1 can also stop delivery on a link that A1 holds.
UMBRA does not give guaranteed availability, and §2.5 states that limit.

### A2 — Malicious or compromised relay operator

**What A2 can do:** A2 operates one or more relays. A2 sees all the data that
those relays see. A2 keeps logs, and the policy does not prevent this. A2 gives
false statements about its own behavior and its own measurements. A2 can be the
project itself, or a state that seized a relay. A2 also changes a cell, drops
a cell, delays a cell, and injects a cell at each relay that A2 holds.

**In scope, and the primary design driver.** **[THR-003]** UMBRA MUST give a relay
no data at rest that identifies a user, and that rule covers a relay under full
adversarial control. The rule binds the *protocol*, and it does not bind the
operator. A hostile operator writes each byte that its position gives it, and no
normative sentence stops that act. Thus the design removes the data from the
position, and it does not ask the position for a promise.

One position keeps such a datum. An ingress relay carries the connection, thus
it reads the client IP address. Part 15 §15.1 holds that row and Part 15 §15.3
records the residual. Each other position holds a random identifier and a
ciphertext only.

**[THR-004]** UMBRA MUST make sure that the logs of a relay cannot
link a sender to a recipient. **[THR-005]** If an adversary compromises *one relay*, that
adversary MUST NOT get the content of a conversation. **[THR-006]** If an adversary
compromises *one relay*, that adversary MUST NOT get the identities of the
participants.

### A3 — Colluding relay operators

**What A3 can do:** Two or more relays in the same chain share their logs and
correlate times. A3 also changes a cell, drops a cell, delays a cell, and
injects a cell at each relay that A3 holds. The rugged-PRP construction of Part
3 §3.4.4 defeats the tagging attack that this capability permits.

**Partially in scope.** An adversary can control **all** the relays in a chain.
That adversary then learns that a client at IP address X delivered to queue Q.
UMBRA decreases the probability of this condition with the path-selection
constraints in Part 10. **[THR-007]** A client MUST select the relays of one chain from
different organizations in different jurisdictions. The selection algorithm
applies weights, thus no operator can increase its share of the paths at a low
cost.

**The bootstrap exception.** `THR-007` has two exceptions, and Part 3 §3.4.6
holds both. Rule `NET-200` lets hop 2 share a jurisdiction bloc with one
end of the chain when the relay set holds fewer than three blocs. Rules
`NET-340`, `NET-350` and `NET-351` let a client build a chain of one
operator, in one bloc, and at one provider, while the signed directory is
provisional. That is the state of a network that one operator starts. In
that state A2 and A3 are one party. The operator of the network runs each
hop, and it joins the address of a client to the queues of that client.
The client shows the state and each such circuit to the user. The exception
ends at the first key set at the authority floor. The trade table of
§2.4 and Part 15 §15.3 each hold its row.

UMBRA does **not** claim security against an adversary that controls the
majority of the relay capacity. Part 15 quantifies that residual risk.

### A4 — Global passive adversary

**What A4 can do:** A4 monitors all the links in the network at the same time.
A4 does end-to-end time correlation. A4 observes and does not act. An active
global adversary is a stronger class, and this specification does not model it.

**Out of scope for Fast mode and Balanced mode.** No low-latency system resists
end-to-end confirmation by a global observer. This is a theoretical result, and
not an engineering gap. The *Private* mode of UMBRA increases the cost with a
longer per-hop delay (Part 3 §3.9). Private mode does not claim to defeat A4. An
implementation or a marketing document that makes a different claim does not
conform to this specification.

### A5 — Legal-process adversary

**What A5 can do:** A5 compels a relay operator, the project, a push provider,
an app store, or a hosting provider. A5 can compel such a party to give records,
to keep records in the future, or to change software.

**In scope, and a design constraint and not a policy problem.** The defense is
to make the compelled set empty by construction. A relay that does not hold a
user identifier cannot receive an order to give one. This specification
identifies each location where a party can accumulate compellable data. This
specification then removes that data, or it records the data as a residual risk
in Part 15.

### A6 — Endpoint adversary

**What A6 can do:** A6 has physical possession of an unlocked device. A6 can
also have forensic extraction tools or malware on the device. A6 can also apply
force to the user.

**Out of scope for the protocol, and partially mitigated.** UMBRA cannot protect
a compromised endpoint. UMBRA does limit the damage. Forward secrecy prevents
the recovery of past messages from the current key state. Post-compromise
security lets the channel heal when the attacker loses access. At-rest
encryption with hardware-backed key wrapping (Part 14) makes forensic extraction
from a powered-off device more difficult.

> **Note on multi-device operation.** UMBRA gives multi-device operation
> *with* history sync. This is a deliberate design decision. If a party
> seizes one device in a Device Set, that party gets the synced history of that
> device. Part 7 gives the mitigations, which are per-device sync scoping,
> retention limits, and revocation. Part 15 states the residual exposure again.

### A7 — Platform adversary

**What A7 can do:** A7 is the operating system of an honest device, together
with the software that shares that device. A7 holds no seized device, and A7
runs no malware. A7 is the platform cloud service that copies an application
container, the input method, an enabled accessibility service, the clipboard,
and the task snapshot service. A7 reads each byte that the client gives to a
platform interface. A7 cannot open the encrypted store of Part 14 §14.6.4, and
A7 cannot decrypt a record in transit.

Android is the v1 platform, and Part 1 §1.1 defers the web client. On
the web client of Part 14 §14.7, when it ships, A7 is the browser, the browser profile and its sync to the
account of the user at the browser vendor, each other extension that the user
installed, and the download location. This section keeps the abstract term
*the platform*, because the rule below binds each platform, and each platform
that a later version adds.

**[THR-015]** A web client MUST NOT run as a page that a host serves, because
trust assumption 4 of §2.6 fails for such a page at each load. Part 14 §14.7
gives the form that holds that assumption. The rule binds each version: it
forbids a hosted page now, and it binds the web client when one ships.

**In scope, and partially mitigated.** **[THR-013]** A client MUST NOT write a
plaintext record, a key, or a decrypted attachment to a platform store. Part 14
§14.6.6 defines a platform store, and it gives the rule for each platform
interface. An explicit user action is the one exception, and that section
names each such action. Part 15 §15.1 gives the platform cloud services a row,
and Part 15 §15.3 records each accepted residual.

UMBRA cannot remove A7, because a client runs on an operating system that UMBRA
does not control. A6 holds the device against the user, and A7 serves the user.
That difference is the cause that A7 gets a rule about where data goes, and A6
gets a mitigation only.

> *Cause.* A model with no class A7 gives the platform of an honest device no
> owner. A client that decrypts a video into the platform media store is then
> conformant. That file reaches a platform cloud service at the next sync. The
> at-rest protection of Part 14 §14.6.4 then ends at the disk write. The
> platform backup of the application container then reaches a party outside
> the list of Part 15 §15.1, against G13.

## 2.3 Security goals

The table below gives each security goal. For each goal, the table gives the
property, the adversary classes that the goal holds against, and the part that
realizes the goal.

| # | Goal | Holds against | Realized in |
| --- | --- | --- | --- |
| G1 | **Confidentiality** — only the intended recipients read the content | A1–A5 | Part 5 |
| G2 | **Post-quantum confidentiality** — G1 holds against an adversary that records data today and decrypts it later with a quantum computer | A1–A5 | Part 5 |
| G3 | **Integrity and authenticity** — no party can forge or change a message without detection | A1–A5 | Part 5 |
| G4 | **Forward secrecy** — a compromise of the current keys does not show past messages | A6 (after the event) | Part 5 |
| G5 | **Post-compromise security** — the channel heals after an attacker loses access | A6 (transient) | Part 5 |
| G6 | **Sender anonymity to the relay** — no relay learns which user sent a message | A2, A5 | Part 3 |
| G7 | **Recipient unlinkability** — no relay can link a queue to a person, and no relay can link two queues to the same person | A2, A5 † | Parts 3, 4 |
| G8 | **Contact-graph secrecy** — no third party learns that the two endpoints are in contact | A1, A2, A5 | Parts 3, 4 |
| G9 | **Cross-contact unlinkability** — two contacts of the same user cannot prove that they share a correspondent | A2, and colluding contacts | Part 4 |
| G10 | **Deniability** — a transcript does not prove authorship cryptographically to a third party | A5, A6 | Part 5 |
| G11 | **Membership privacy** — no relay learns the membership of a private group | A2, A5 † | Part 11 |
| G13 | **No compellable identity data** — infrastructure operators hold no data that identifies a user | A5 † | Parts 3, 10, 15 |

> † This goal holds only to the limit that Part 15 states. For G7 and G11 the
> limit is an active A2 or an active A3, and Part 15 §15.3 gives it. For G11 the
> group-queue relay also holds a bounded view. It learns the member count of a
> group at each rotation, the count of reader sessions and writer sessions, and
> the time and the bucket of each record. It learns no identity and no
> membership list. Part 3 §3.11 states that view, and Part 15 §15.3 records it.
> For G13 the
> limit is the ingress relay, which sees a client IP address because it carries
> the connection. Part 15 §15.1 holds that row, and Part 15 §15.3 records the
> residual. No protocol removes that address from the party that carries the
> packet.

> **Note on the goal numbers.** This table has no G12. The number G12 is
> reserved, and no goal uses it. Censorship resistance is not a goal, and §2.5
> gives the cause. The numbers of the other goals stay, because Parts 3, 13,
> and 15 refer to G13.

## 2.4 Usability goals

These goals are **normative**. **[THR-008]** A conformant implementation MUST meet each
goal of the table below. A protocol that users abandon protects no person. This
specification states the goals as measurable targets, thus a test can show
conformance. §2.4.2 gives the sociality goals, and rule `THR-014` binds an
implementation to them in the same manner.

| # | Goal | Target |
| --- | --- | --- |
| U1 | **Time to first message** — from the first launch to the first message that a relay accepts, on a mid-tier Android device on 4G. The channel comes from an invitation that the same session scanned | p50 ≤ 90 s, p95 ≤ 180 s, ≤ 6 taps, and **no security decision before the inbox is reachable**. No account screen, no phone number, no email address, and no server picker. |
| U2 | Message delivery latency, Balanced mode, the two parties online, and the sender holds the ratchet ownership of Part 7 §7.5.4 | **p50 ≤ 2.0 s, p95 ≤ 4.5 s.** Part 3 §3.12 models 1.6 s and 3.9 s against a measured propagation budget, thus the margin is 0.4 s and 0.6 s. **A send from a device that does not own the ratchet** adds the wake latency of the owner device (Part 8 §8.3). The target for that path is p50 ≤ 6 s and p95 ≤ 20 s in Instant mode, **while the owner device is unlocked**. A locked owner sends nothing, and the note below gives that case, which has no target |
| U3 | **Notification latency, Instant notifications and Balanced mode** — from the moment the sender taps send to the moment a locked and idle device shows the notification | p50 ≤ 3 s, p95 ≤ 15 s, p99 ≤ 60 s. **Hard invariant:** no message stays invisible for more than 15 min while the device has network. The device of this row is locked by the platform, and the client on it is unlocked or holds the wake table of Part 8 rule `NTF-135`. **Private notifications:** the fixed cadence of Part 8 §8.3 gives the latency while the client is unlocked. That latency is 20 min at the 20 min cadence and 30 min at the 30 min cadence, and more when the platform defers the timer. A locked client in Private mode shows nothing until the unlock |
| U4 | Idle background data consumption, Balanced mode with Instant notifications, on the model day of Part 3 §3.12 | ≤ 100 MB/month. Part 3 §3.12 models 77.99 MB with the session resume of Part 6 §6.2.3, and the note below gives the condition |
| U4b | Idle background data consumption, Balanced mode with Private notifications | **No target in v1.** Part 3 §3.12 models 149.22 MB at the 30 min cadence and 196.68 MB at the 20 min cadence of Part 8 §8.3. That section states the cause |
| U5 | Idle battery, Instant notifications on, application in the background | **Two terms.** With no background arrival, ≤ 2 % of a 4000 mAh battery in 24 h (≈ 80 mAh/day). The measured 1 % of Signal over 18 h 59 min is about 1.3 % in 24 h. Thus this target is about 1.6 times that figure. For each background arrival, ≤ 10 mWh. Part 3 §3.12 models 0 % and 9.1 mWh, which is 10.9 % on its model day of 184 arrivals. **Conformance test: a 24 h idle run with no arrival, and a run with a scripted arrival count, each on stock Android *and* on GrapheneOS.** |
| U6 | Delivery reliability, the recipient returns in the retention window | ≥ 99.9 % delivered in 60 s after the recipient comes online. **No message is permanently undeliverable** in the window. The window of a message is `MSG_TTL`. The file of an attachment has a shorter window, `CHUNK_TTL` of Part 12 §12.7.1, and the trade table gives that row |
| U7 | Addition of a second device | ≤ 60 s, one QR scan, and **no contact does the verification again** |
| U8 | Cold start to a rendered inbox, the store unlocked | ≤ 1.5 s on a 2021-class mid-range Android device |
| U8b | Unlock to a rendered inbox, after the auto-lock of Part 14 §14.6.4 | ≤ 4.5 s from the passphrase confirmation, on the same device. The Argon2id step of about 3 s is inside that figure |
| U9 | **Undecryptable-message rate** | < 1 in 10⁵ delivered, as the ratio at one device over 30 days. The numerator is the count of the records that `THR-009` lets the receiver classify as undecryptable. The denominator is the count of the delivered records |
| U10 | Account recovery, for a user that completed the recovery setup of Part 4 §4.7.6 | ≥ 99 % recover the identity, the contacts, and the queue state. ≥ 95 % also recover 45 days or more of text history. Median ≤ 10 min |
| U10b | Recovery setup | ≤ 4 taps from the settings screen to a confirmed recovery code. The prompts of Part 4 §4.7.6 offer that path two times, and no prompt blocks the message list |

> **The test for U5 is more important than the number.** SimpleX measured a 35 %
> battery drain over 10h24m. Signal measured 1 % over 18h59m. The SimpleX result
> occurred on GrapheneOS only, and stock Samsung devices and iPhone devices did
> not show it. A test on the two platform types is necessary. If the test does
> not occur, the regression reaches the users.
>
> **U9 has a design consequence.** UMBRA cannot collect two-sided debug logs,
> because such logs destroy metadata resistance. This limit is the cause of the
> unable-to-decrypt class of failures in Matrix, which has continued since 2017.
> **[THR-009]** Thus the wire format MUST carry sufficient in-band context for a receiver to
> **classify a failure alone**. This context is the session identifier, the
> ratchet epoch, and the message index. The receiver then sends the key
> request of Part 6 §6.6.11 to the sender on the existing pairwise queue, with
> no user action. Part 6 §6.5
> carries the three values in the `ctx` field and the braid frame of a ratchet
> record, outside the header ciphertext.
>
> **U3 has two scopes, and Part 8 §8.3 is the cause.** Private mode wakes the
> device on a fixed clock, and a message arrival does not change that clock.
> Part 8 §8.3 derives the floor of the fixed clock from Doze and from U5, thus
> the cadence does not go below 20 min. A 15 min invariant and a 20 min
> floor do not hold together. Thus U3 scopes its targets to Instant
> notifications and Balanced mode, and U5 uses the same method. Private mode
> keeps a stated latency, and the U3 row gives it.
>
> **U4 counts each push wake, and a wake is a transport handshake.** Part 3
> §3.12 derives the wake count from the 184 background arrivals of its model
> day. It prices a wake as a TLS handshake, a session resubscription, and a
> drain. Part 3 §3.4.3 sets `CIRCUIT_MAX_AGE` to 4 hours, thus most wakes pay
> no build. The handshake row is the largest row, because rule NET-023 of
> Part 3 §3.2.5 gives each queue relay its own session. The idle background
> is 77.99 MB each month, and the U4 target is 100 MB.
>
> **U4 rests on the session resume.** A client pauses its session at the end
> of each wake, and it resumes that session at the next wake (Part 6
> §6.2.3). A circuit thus lives from one wake to the next. A resume sends no
> frame again. Thus a connection that drops with a frame in flight loses its
> session, and so does a client process that ends and a relay that starts
> again. The next wake then pays a circuit build for each session, which
> Part 3 §3.12 prices at 12 576 bytes. A client that paid a build at each
> session of each wake would use about 183 MB each month. The test of
> §2.4.1 measures the figure that a build reaches.
>
> **U2 and U3 with a locked client.** Part 14 rule `IMP-119` locks the client
> after 15 minutes with no action of the user, and a locked client holds no
> key (Part 14 rule `IMP-127`). The owner device of Part 7 §7.5.4 then sends
> no record for a linked device, reads no pairwise queue, and carries no
> sync record to another device of the set. A linked device that composes
> waits for the unlock of the owner. The ownership claim of Part 7 §7.3.1
> is the designed bound: a device claims after `OWNER_TIMEOUT` of 90 s, at
> most `OWNER_CLAIM_RATE` times each day. v1 builds no claim of that scope
> (Part 7 rule `DEV-287`), thus in v1 the wait has no bound but the
> unlock. An owner that is gone for `OWNER_ABSENCE` of 24 h is absent, and
> a linked device then takes the set over under Part 7 §7.7. The second
> clause of U2 thus covers an unlocked
> owner alone. In Instant mode a locked client still shows which
> conversation waits, under Part 8 rule `NTF-136`, and U3 measures that
> alert. Part 15 §15.3 holds the row.
>
> **U4b names no target in v1.** A Private wake of Part 8 §8.3 opens
> each queue-relay session of the model day, because the client cannot know
> which queue holds a message. Part 3 §3.12 derives 149.22 MB and 196.68 MB
> each month from that. A target above those figures binds nothing, and a
> target below them fails under rule THR-008 with no rule that lets a client
> meet it. The cause is the session model of rule NET-023, and a change of
> that rule sets the target. Part 3 §3.12 states the figures, thus a reader
> sees the cost.
>
> **U8 covers an unlocked store, and U8b covers the unlock.** Part 14 §14.6.4
> pays about 3 s of Argon2id at each unlock. Thus a start after the auto-lock
> cannot render an inbox in 1.5 s. Thus each of the two paths has its own
> figure.
>
> **U9 is a device-local ratio.** A target for the population of the users
> needs a report from each user, and Part 15 §15.6 permits no telemetry. A
> client shows the ratio in its diagnostics screen, and it sends the ratio to
> no party.
>
> **U10 covers a user that completed the setup.** Part 4 §4.7.6 lets a user
> dismiss the recovery prompt two times. A user with no recovery code, no
> backup, and no guardians recovers nothing. Thus the 99 % target does not
> measure that user. U10b measures the setup path instead, because a
> published completion rate needs the telemetry that Part 15 §15.6 forbids.

If a usability goal conflicts with a security goal, this specification states
the conflict explicitly and names the resolution. A silent trade of a U-goal for
a G-goal is prohibited, and the reverse trade is also prohibited. Each trade
appears in the text of this specification.

The table below names each trade that this specification states. **[THR-010]** A revision that
adds a trade MUST add a row to this table.

| Trade | Where the text states it |
| --- | --- |
| Mandatory inbound pacing raises the Balanced p50 from 0.6 s to about 1.6 s, and U2 moves to match | Part 3 §3.9 |
| A backgrounded client makes no cover cell, thus an ingress relay reads the send times of that user | Part 3 §3.6.2 |
| A selected profile picture concedes G9 inside one Profile, in exchange for a recognizable identity | Part 4 §4.2.5 |
| The table MAC does not detect a full-file rollback, and it does not detect a change after the first unlock | Part 4 §4.6 |
| A short `SYNC_MAX_AGE` makes a device reject each older sibling record, thus that device converges on a short window only | Part 7 §7.5.2 |
| The sending device carries the convergence, thus a lost source device with no peer copy loses that range | Part 7 §7.5.3 |
| An edit window of 24 hours lets a sender change a delivered message, and the recipient keeps no earlier text | Part 7 §7.5.6 |
| A member keeps `K_e` for the life of the current group epoch, thus a seized device opens the retained records of that epoch from its start, at most `GROUP_EPOCH_MAX_AGE` | Part 11 §11.3.2 |
| A granting epoch is a signed and transferable statement, thus G10 does not cover the group administration | Part 11 §11.9.5 |
| A moderator removal in a private group destroys a record on the device of each member | Part 11 §11.9.6 |
| Each queue relay holds its own session, thus each push wake pays one transport handshake for each queue relay. That row is 42 % of the idle background, and the U4 target is 100 MB each month | Part 3 §3.12 |
| A circuit and its session live 4 hours and not 10 minutes. A seized hop 1 or hop 2 key set then opens 4 hours of recorded cells, and one session links the wakes of 4 hours | Part 3 §3.4.3, Part 6 §6.2.3 |
| Each background arrival wakes the device one time, thus the battery cost of Instant mode grows with the arrival count. U5 states that cost as a term for each arrival | Part 3 §3.12 |
| Private mode holds a message for its fixed cadence, thus U3 covers Instant notifications and Balanced mode only | Part 8 §8.3 |
| A hop 1 or hop 2 key set runs no per-cell update, thus a seized middle relay opens its layer of a recorded cell | Part 3 §3.4.4 |
| The braid header carries the public seed and not the private seed, thus the default heal window rises from 18 records to 36 records | Part 5 §5.5.2 |
| A group-queue relay reads the member count of a group at each rotation, from the slot count of the epoch-key record | Part 11 §11.4.2 |
| A skipped-message key lives 45 days, thus a seized device gives a wider key set | Part 5 §5.5.4 |
| A group-queue relay holds `GROUP_RETENTION` of the ciphertext of a group and the time and the bucket of each record, thus two replica operators see the activity of a group | Part 11 §11.5 |
| An accepted key-change notice ends the post-compromise healing for that contact | Part 4 §4.5.1 |
| A backup write costs about 492 KB each day on the chunk path, and U4 counts that cost | Part 3 §3.12 |
| A send from a device that does not own the ratchet waits for the next wake of the owner device | Part 7 §7.5.4 |
| The client locks after 15 minutes and a locked client holds no key. Thus a locked owner device sends nothing for a linked device, reads no queue, and carries no sync record, until the unlock. v1 builds no ownership claim after `OWNER_TIMEOUT`, thus the unlock is the one bound below `OWNER_ABSENCE` | Part 7 §7.5.4, Part 8 §8.4.1, Part 14 §14.6.4 |
| A provisional network runs on the relays of one operator. A client then builds a chain of one operator, and that operator joins the address of the client to its queues. Thus G6, G7 and G8 do not hold against that operator until the directory reaches the authority floor | Part 3 §3.4.6 |
| The file of an attachment lives `CHUNK_TTL` of 14 days at a relay, and a message lives `MSG_TTL` of 45 days. Thus a recipient that returns after 14 days gets the message and not its file, and the uploader pays less storage | Part 12 §12.7.1 |
| A resume sends no frame again, thus a connection that drops with a frame in flight costs each circuit of its session again. v1 ships TLS over TCP alone, thus a network with no TCP/443 carries no client | Part 3 §3.8, Part 3 §3.12, Part 6 §6.2.3 |
| The U2 p50 target is 2.0 s, because Part 3 §3.12 models 1.6 s against a measured propagation budget and `PACING_MEAN` holds at 1 s | Part 3 §3.12 |
| A link preview is a statement by the sender, because the receiver MUST NOT fetch the URL | Part 3 §3.3.2 |
| A disappearing message does not enter a backup, thus a restore does not recover it | Part 4 §4.7.2 |
| A blocked contact gets an ordinary delivery acknowledgment, thus the block costs the queue and the bytes of a live contact | Part 13 §13.12 |
| A 250 MiB attachment costs about 259 MiB of uplink, and about 7 minutes at 5 Mbit/s | Part 12 §12.7.2 |
| The relay that takes a chunk learns the other two relays that hold that chunk | Part 12 §12.4.1 |
| A poll count can differ between two members, because a group has no total order | Part 11 §11.11 |
| A shared contact needs the consent of that contact, thus a share is three records and not one | Part 6 §6.6.7 |
| A moderation epoch names no author, and a member folds each superseded epoch, thus the chain is not an audit log | Part 11 §11.9.6 |
| A group carries no delivery receipt, no read receipt, and no typing indicator, thus a sender in a group does not learn that a record arrived | Part 11 §11.6 |
| A member that leaves a group reads the group until any other member rotates the epoch, one backoff after the first member comes online | Part 11 §11.4.1 |
| An absence claim moves each ratchet of an absent device in one roster epoch, thus a device that owns the channels and that is offline for `OWNER_ABSENCE` can lose its ownership, and it learns of it when it returns | Part 7 §7.3.1 |
| A take-over of a device set removes each other linked device, and it renews each channel from what the lost device synced last. Thus the user links each other device again, and a contact that the lost device made in its last moments needs a new invitation | Part 7 §7.7 |
| Each linked device holds the pairwise key of each contact, the credentials that write to the queue of each contact, and the secret of the renewal guard of each contact. Thus a take-over reaches each contact, and it asks no contact a question | Part 7 §7.5.3 |
| A restore from a backup that is older than the newest renewal guard of a contact waits for the user of that contact, who accepts the new connection or refuses it | Part 3 §3.2.6, Part 4 §4.7.2 |
| A catch-up object puts the backlog of an absence on the chunk path at once, thus a relay reads that backlog as one attachment | Part 7 §7.5.1 |
| A save to the media store and a screenshot stay as user actions, thus one tap moves a plaintext out of the encrypted store | Part 14 §14.6.6 |
| The accessibility tree stays whole, thus an enabled accessibility service reads each rendered message | Part 14 §14.6.6 |
| The ClientHello is the ClientHello of the rustls stack and not of a browser, thus a classifier tells an UMBRA client from a browser on the first flight | Part 3 §3.8.1 |
| When the deferred web client ships: a web client sends the ClientHello of its browser, thus a classifier tells a web client from a native client on the first flight | Part 3 §3.8.1 |
| When the deferred web client ships: a web client receives a message while its browser runs, and the phone of the user carries each notification at another time | Part 8 §8.6 |
| When the deferred web client ships: the web client is a browser extension, thus each browser vendor is a gatekeeper of that client, and a user without the extension has no web client | Part 14 §14.7 |
| A published rendezvous queue rotates each 30 days, thus one relay holds the hello count of one period and the holder pays one queue and one write in each period | Part 9 §9.9 |
| A record that no relay accepts in `SEND_GIVE_UP` fails, and the user resends it, thus no retransmission runs for the life of a session | Part 3 §3.7 |
| A 1:1 conversation and a group at or below `GROUP_ALL_NOTIFY_MAX` default to a notification for each record. Thus a small conversation alerts on each record, and a large one alerts on a mention only | Part 7 §7.5.9 |
| The manual verification is a six-digit code, thus an active adversary at the first contact passes one ceremony in 10⁶ | Part 4 §4.5.2 |
| A delivery receipt and a read receipt are off by default. Thus a sender does not learn that a record arrived unless the peer opts in | Part 3 §3.5.4 |
| A typing indicator is off by default, thus a peer does not learn that a user composes unless that user opts in | Part 6 §6.6.9 |
| Each push lives 24 hours at the provider, a digest push too. Thus a seizure there exposes one day of 69-byte blobs in place of one hour. Thus the provider cannot tell a group wake from a pairwise wake by the expiry | Part 8 §8.4.2 |
| A device that fails three consecutive blob opens shows a clock state. Thus a wrong clock is visible, and a preview stops until the root is fresh | Part 8 §8.2.3, Part 14 §14.9.2 |
| A client takes its time from the signed directory root. Thus a device clock that is wrong by more than one hour stops nothing, and the client shows one line for it | Part 10 §10.5.2, Part 14 §14.9.2 |
| A sender re-encodes each media object and removes its metadata fields. Thus a recipient gets a smaller file with no location, and the original needs one selection for each send | Part 12 §12.3 |
| A forward is a new upload under a fresh key. Thus a relay joins no two conversations at one chunk, and the sender pays the upload again | Part 12 §12.3 |
| A receiver renders the verified segments of a media object before the digest check. Thus a player starts early, and a truncated object shows its end late | Part 12 §12.3.1 |
| A relay serves at most four times its store in a day and one chunk at most 60 times an hour. Thus a popular object moves to six replicas that its author pays for | Part 12 §12.11 |
| A bulk circuit runs in the mode of its conversation, thus a Private-mode upload of 250 MiB takes about 7.5 minutes at a 5 Mbit/s uplink | Part 12 §12.7.2 |
| A holder reads its own label at each tree head, thus a compelled insertion under that label raises the takeover warning at the holder, and each published label costs one metered lookup for each head | Part 9 §9.5.2 |
| The invitation link names one invitation host, thus that host learns each browser open of a link by a party without the client | Part 4 §4.3.1 |
| Private notifications wake the device on a fixed clock and open each queue-relay session. The idle background then rises to 149.22 MB or 196.68 MB each month. U4b names no target in v1. A locked client in Private mode receives nothing until the unlock | Part 3 §3.12, Part 8 §8.3 |
| A published Public Address sits in a second directory index, thus a party that holds its 20-byte hash reaches its rendezvous queue | Part 9 §9.3.3 |
| The addressee verifies the token or the proof of work of a hello, thus no relay limits a contact request. No limit for each sender exists at a Public Address, because the token is unlinkable. Any party can thus fill a published rendezvous queue to its quota with records that pass no check. The relay then refuses an honest hello until the addressee drains that queue | Part 13 §13.4, Part 9 §9.6 |
| A rendezvous queue in Instant mode registers with the Notification Delivery Relay. That relay then learns that a push token belongs to a published handle or address | Part 8 §8.2.6 |

### 2.4.1 Where each usability goal is realized

THR-008 makes a conformant implementation meet each goal of §2.4, and THR-014
makes it meet each goal of §2.4.2. A goal is not the property of one part. U2
and U4 each depend on rules in three parts, and a revision that changes one of
those rules has to check the goal again.

| Goal | The rules that carry it | The test |
| --- | --- | --- |
| U1 | Part 3 §3.10 carriers, Part 4 §4.2.5 `IDN-015`, Part 4 §4.7.6 `IDN-054`, Part 13 §13.2.1 | A scripted first launch on a mid-tier Android device on 4G |
| U2 | Part 3 §3.9 modes, Part 3 §3.5.2 pacing, Part 7 §7.5.1 `DEV-193`, Part 7 §7.5.4 | A two-party send, from the ratchet owner and from a peer device |
| U3 | Part 8 §8.3 modes, Part 8 §8.4.1, Part 8 §8.4.2 | A locked and idle device, in Instant mode and in Private mode |
| U4 | Part 3 §3.12 idle table, Part 3 §3.6.2 tier C, Part 3 §3.12 `NET-096` and `NET-097` and `NET-099` and `NET-100`, Part 4 §4.7.2 `IDN-080`, Part 6 §6.2.3 `WIR-361`, Part 8 §8.5 `WAKE_COALESCE_WINDOW` | A 24 h idle capture of the background bytes, in Instant mode, with the arrival count of the model day |
| U4b | Part 3 §3.12 idle table and its Private notifications paragraph, Part 8 §8.3 modes | No target in v1. A 24 h idle capture of the background bytes at each cadence of Private mode reports the figure |
| U5 | Part 3 §3.12 battery, Part 8 §8.4.1, Part 8 §8.8 | A 24 h idle run with no arrival, and a run with a scripted arrival count, on stock Android **and** GrapheneOS, with a power monitor |
| U6 | Part 3 §3.2.4 `MSG_TTL`, Part 3 §3.7 ARQ and `SEND_GIVE_UP`, Part 12 §12.4 replicas, Part 12 §12.7.1, Part 14 §14.9 | A recipient that returns inside the retention window |
| U7 | Part 7 §7.4, Part 7 §7.6 `DEV-131` | A second device link, timed, with a contact that verified before it |
| U8 | Part 14 §14.6.2 | A cold start on a 2021-class mid-range Android device, with the store unlocked |
| U8b | Part 14 §14.6.4 | A start after the auto-lock on the same device, timed from the passphrase confirmation |
| U9 | Part 2 §2.4 `THR-009`, Part 5 §5.5.2 braid, Part 5 §5.5.4 `CRY-098`, Part 6 §6.6.11 `WIR-456`, Part 11 §11.4.3 key supply | A count of the undecryptable records against the delivered records, at one device over 30 days |
| U10 | Part 4 §4.7.1, Part 4 §4.7.2, Part 4 §4.7.3, Part 4 §4.8 | A restore from a fresh install, timed, at each of the three recovery paths, after a completed setup |
| U10b | Part 4 §4.7.6 `IDN-051` to `IDN-054` | A scripted setup from the settings screen, with a tap count |
| S1 | Part 4 §4.3.2 `IDN-129` to `IDN-132`, Part 9 §9.3.3, Part 9 §9.6, Part 8 §8.2.6, Part 13 §13.4 | A pasted address string at a fresh install, timed to the shown request at the addressee, in Instant mode and in Private mode |
| S2 | Part 9 §9.4, Part 9 §9.6, Part 8 §8.2.6 | A typed handle at a fresh install, timed in the same manner as S1 |
| S3 | Part 6 §6.6.7 `WIR-358`, Part 4 §4.3.1 | A three-party introduction, timed from the request to the shown offer |

**[THR-011]** A revision that adds a usability goal or a sociality goal MUST add
a row to this table.
**[THR-012]** A revision that changes a rule of a row MUST measure that goal
again.

> *Cause.* Part 14 gives the assurance program of the cryptography and it gives
> no test plan for a usability goal. Without this table, a rule in one part
> can break a goal and no test shows it. A backup with no bandwidth row
> breaks U4, and a peer-device send with a pacing wait of 20 seconds breaks
> U2.

### 2.4.2 Sociality goals

The goals of §2.4 cover the private tier of Part 4 §4.1. A user with no
published address meets a contact through a QR code or through a link. The
table below covers the social tier, which a user turns on. S1 and S2 need a
published address or a published handle at the addressee. S3 needs the
consent of the contact that the introduction names.

| # | Goal | Target |
| --- | --- | --- |
| S1 | **Reach from a Public Address** — a stranger that holds a pasted address or a reusable link (Part 4 §4.3.2) sends a contact request | ≤ 3 taps from the paste to a sent request. The addressee sees the request in ≤ 60 s in Instant mode, and in ≤ 24 h in Private mode. Both devices have network |
| S2 | **Reach from a handle** — a stranger that types a handle sends a contact request | The taps and the latency of S1, plus one lookup of Part 9 §9.4 |
| S3 | **Introduction** — a user connects one contact with another contact through the contact share of Part 6 §6.6.7 | ≤ 2 taps at each of the three parties. The offer reaches the third party inside the U2 latency after the grant |

**[THR-014]** A conformant implementation MUST meet each goal of the table
above. §2.4.1 names the rules that carry each goal and the test of each goal.

> *Cause.* A goal with no mechanism is not measurable, thus each goal above
> has a mechanism. A handle lookup alone does not let a stranger reach a
> Public Address from the string of Part 4 §4.2.3. Part 9 §9.3.3 gives the
> address index for that string. The offer record of Part 6 §6.6.7 alone does
> not make a client show the offer. Part 6 rule `WIR-358` gives the offer its
> interface rule.

## 2.5 Non-goals

UMBRA does not give the properties below.

- **Anonymity from your contacts.** The persons that you speak to know that they
  speak to you. UMBRA hides *the graph* from the infrastructure. UMBRA does not
  hide the conversation from its participants.
- **Protection against a compromised endpoint.** Refer to A6.
- **Protection against traffic confirmation by a global observer.** Refer to A4.
- **Undetectable use.** A network observer can usually find that an UMBRA client
  operates. To hide the *fact* of use is a transport-layer function with its own
  trade-offs. This specification does not give that function. Part 3 §3.8.1
  states the trade.
- **Guaranteed availability.** A party can block or seize relays. The design of
  UMBRA lets it degrade and then recover. UMBRA is not unblockable.
- **Censorship resistance.** UMBRA does not have a goal to operate in a network
  that blocks it. Some mechanisms in Part 3 make a block more expensive. Those
  mechanisms exist for the metadata goals, and a failed block is a side-effect.
  Part 3 §3.8.1 and Part 15 §15.2.7 give the limits.
- **Legal protection.** To use UMBRA is not a defense in a jurisdiction. In some
  jurisdictions, to use UMBRA is itself a risk. Refer to Part 15.

**Two omissions of v1.** The two items below are not non-goals. v1 makes no
decision on them. This section states each one as an omission, thus a reader
does not read silence as a position.

- **Real-time media.** v1 gives no call profile and no media session. A
  later version that adds one states its latency target in §2.4, its
  metadata cost in the trade table of §2.4, and its residual in Part 15
  §15.3.
- **The ecosystem position.** v1 states no position on federation, on a
  bridge to another network, or on a local automation surface. A later
  version that takes a position states the metadata cause in this section.

## 2.6 Trust assumptions

The protocol is sound only if the assumptions below hold. This specification
lists them, thus a reader can check them and does not have to find them.

1. **The cryptographic primitives in Part 5 are secure** against classical
   adversaries and quantum adversaries, at the parameter levels that Part 5
   gives.
2. **The random number generator of the device is sound.** UMBRA derives all the
   long-term secrets from it. Part 5 §5.9 gives the hardening against a
   generator that fails partially, and Part 14 §14.10 names the platform
   source.
3. **A minimum of one relay in each chain is honest** and keeps no logs. The
   path selection in Part 10 makes this condition probable, but not certain.
   In a provisional network of Part 3 rule `NET-340` one operator runs each
   relay of a chain. This assumption then reads: that one operator is
   honest and keeps no logs.
4. **The client binary that the user runs is the binary that the auditor
   examined.** v1 gives no method to check this assumption (Part 14 §14.8,
   Part 15 §15.5). If the assumption fails, all the other guarantees become
   void. A web page that a host serves fails this
   assumption at each load, and Part 14 §14.7 gives the deferred web client
   a form that holds it.
5. **The user verifies a contact out-of-band a minimum of one time** for a
   conversation with serious consequences after a compromise. Part 4 §4.5.2
   makes the ceremony one QR scan or one six-digit code, and UMBRA cannot make
   it automatic.
6. **An adversary does not hold five or more of the seven directory signing
   keys.** Part 10 gives 5-of-7 multi-signing, the in-band digest gossip of
   `REL-008`, and the independence rules of Part 10 §10.5.1. These controls
   limit the damage if an adversary holds fewer keys than five. A
   provisional directory of Part 10 rule `REL-126` stands under fewer than
   `AUTHORITY_FLOOR` independent controls, and one party can hold each of
   its keys. This assumption then reads: that party is honest. The client
   shows the state under Part 14 §14.9.2.
7. **An adversary does not hold two or more of the three log signing keys**
   of Part 9 §9.5.2. The signers of the handle log are the anchor of each
   handle key and each address key of Part 9, and of each issuer key of
   Part 13 rule `ABU-002`. The self-monitoring of Part 9 §9.5.2 and the
   gossip of Part 9 §9.5.3 limit the damage of a forged head, and they do
   not prevent it.
8. **The pins of the client build are sound.** A build pins the directory
   key set of Part 10, the log key set of Part 9 §9.5.2, the route and the
   key configuration of the Notification Delivery Relay (Part 8 rule
   `NTF-127`), and the OHTTP key configuration of the directory service
   (Part 9 rule `DIS-163`). No signature from outside the build covers the
   last two, thus assumption 4 carries them: a party that changes a pin
   changes the binary.

## 2.7 What each party learns — summary

This table is the compact form of the analysis in Parts 3, 8, 10, and 15. This
document repeats the analysis here, because a reader needs it first.

**Part 3 §3.11 is the normative table, and this one is a summary.** The two
tables use the role names of Part 3 §3.1. A change to what a party learns goes
in Part 3 §3.11 first, and then in this table in the same commit. A summary that
drops a leak is the failure mode that this note prevents.

| Party | Learns | Does not learn |
| --- | --- | --- |
| **Ingress Relay** | The client IP address, the connection time, the cell counts, the cell sizes, that this client is an UMBRA client, and the count of the circuits of the client, which bounds the count of the groups that the user reads from above (Part 3 §3.11). When the deferred web client ships, it also learns whether a client is a web client or a native client (Part 3 §3.8.1). In tier C it also reads the send times, because a backgrounded client makes no cover cell (Part 3 §3.6.2). In a provisional network the operator of the ingress relay is also the operator of the queue relay. The row of the two colluding relays below is its row | The destination queue, the recipient, the content, which queues the client holds, and how many pairwise conversations the client has |
| **Chain Relay** | Two adjacent relay addresses, the time, and the cell size | The client IP address, the destination queue, the recipient, and the content |
| **Queue Relay** | The queue identifiers, the delivery time, the cell size, and the ciphertext at rest. For a maximum of 8 queues at a time, that those queues share one transport session (Part 3 §3.2.5) | The client IP address, the sender identity, the recipient identity, the content, and which person owns the queue |
| **Group-queue relay** | That a group queue exists, the count of its reader sessions and its writer sessions, the arrival time and the bucket of each record, the exact member count at each rotation from the slot count of the epoch-key record, the count of notify registrations, and the `relay_id` of each registered notify queue. It holds `GROUP_RETENTION` of ciphertext (Part 3 §3.2.7, Part 3 §3.11) | The identity of any member, the pairwise queue of any member, the sender of a record, the content, and the membership list |
| **Two colluding relays (ingress and queue)** | That a client at IP address X delivered to queue Q at time T | The recipient identity and the content. But this condition is a real deanonymization risk. Refer to the path constraints in Part 10 |
| **Notification Relay (NDR)** | An opaque and rotating push registration. That *some* queue that it monitors had activity. The platform push token | Which queue, which user, the content, and the contact graph |
| **Google (FCM), in Instant mode on a device with FCM. No platform party in Private mode, in Off mode, and on a device with no FCM** | The device push token, the application identity, and the wakeup time and count. Each push has one form and one expiry, thus not which wake is a group message | The content, the queue, the contact, and the sender |
| **The project** | The data that its own relays learn (above), and aggregate directory statistics | No more data than another operator gets. It holds no user database, because no user database exists |
| **Directory Authority** | Relay descriptors and measurements | Nothing about users. Clients get the full directory, or they use a privacy-preserving mechanism (Part 10) |
| **A contact** | All the data that you send to that contact, and that you are you | Your other contacts, your Pairwise Addresses with them, and your Public Address if you do not share it |
| **Legal process against one party** | Only the column of that party above | All other data. This limit is the objective of G13 |
