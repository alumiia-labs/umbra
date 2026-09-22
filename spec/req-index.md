# UMBRA Requirement Index

**Status:** Maintained with the specification
**Writing standard:** ASD-STE100 Simplified Technical English

---

## How to read this index

Each normative requirement in the specification carries an ID. The ID has a
three-letter part prefix, a hyphen, and a three-digit number. An example is
`NET-001`.

A marker in the specification reads `**[NET-001]**`. If the marker falls inside
an emphasized span, it reads `[NET-001]` without the emphasis, because Markdown
does not nest an emphasis inside an emphasis.

**This repository holds no generator for this file.** An author updates this
file in the same commit that changes a requirement in `spec/`.

### The rules for a number

- A new requirement takes the next free number in its part.
- A retired number does not return. A later requirement does not reuse it.
- The numbers in each part rise in document order. A revision that adds a
  requirement to an earlier section takes the next free number, thus a number
  can be out of document order after a revision.
- A requirement that moves to a different part keeps no number. It takes a new
  number in the part that receives it.

### The three checks that this file has to pass

1. Each `**[ID]**` marker in `spec/` has one row here, and each row here names a
   marker in `spec/`.
2. The Section column of a row names the section that holds the marker.
3. The Summary counts agree with the rows below.

### The Module column and the Test column

Both columns are empty. This repository holds no code today. An author fills
each column when a crate implements the requirement and a test covers it.

### The part prefixes

| Prefix | Part | File |
| --- | --- | --- |
| `SCP` | Scope and Conventions | `spec/01-scope-and-conventions.md` |
| `THR` | Threat Model and Security Goals | `spec/02-threat-model.md` |
| `NET` | Network Architecture | `spec/03-network-architecture.md` |
| `IDN` | Identity | `spec/04-identity.md` |
| `CRY` | Cryptographic Core | `spec/05-cryptographic-core.md` |
| `WIR` | Wire Format | `spec/06-wire-format.md` |
| `DEV` | Device Sets | `spec/07-device-sets.md` |
| `NTF` | Notifications | `spec/08-notifications.md` |
| `DIS` | Discovery, Handles, and Key Transparency | `spec/09-discovery.md` |
| `REL` | Relay Directory | `spec/10-relay-directory.md` |
| `GRP` | Private Groups | `spec/11-private-groups.md` |
| `COM` | Public Communities | `spec/12-communities.md` |
| `ATT` | Attachments and Large Objects | `spec/13-attachments.md` |
| `ABU` | Anti-Abuse Without Identifiers | `spec/14-anti-abuse.md` |
| `IMP` | Implementation | `spec/15-implementation.md` |
| `SEC` | Security Considerations | `spec/16-security-considerations.md` |

## Summary

| Prefix | MUST | MUST NOT | SHOULD | SHOULD NOT | MAY | Total |
| --- | --- | --- | --- | --- | --- | --- |
| `SCP` | 12 | 5 | 0 | 0 | 4 | **21** |
| `THR` | 11 | 4 | 0 | 0 | 0 | **15** |
| `NET` | 225 | 84 | 1 | 0 | 8 | **318** |
| `IDN` | 120 | 43 | 1 | 0 | 5 | **169** |
| `CRY` | 119 | 27 | 0 | 0 | 1 | **147** |
| `WIR` | 389 | 87 | 0 | 0 | 6 | **482** |
| `DEV` | 179 | 87 | 2 | 0 | 7 | **275** |
| `NTF` | 67 | 30 | 0 | 0 | 2 | **99** |
| `DIS` | 123 | 37 | 0 | 0 | 1 | **161** |
| `REL` | 124 | 32 | 1 | 0 | 2 | **159** |
| `GRP` | 212 | 58 | 0 | 0 | 6 | **276** |
| `COM` | 299 | 96 | 0 | 0 | 5 | **400** |
| `ATT` | 139 | 46 | 1 | 0 | 2 | **188** |
| `ABU` | 64 | 31 | 0 | 0 | 0 | **95** |
| `IMP` | 112 | 41 | 0 | 0 | 2 | **155** |
| `SEC` | 13 | 5 | 1 | 0 | 2 | **21** |
| **All** | 2208 | 713 | 7 | 0 | 53 | **2981** |

## SCP — Scope and Conventions

Source: `spec/01-scope-and-conventions.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `SCP-001` | §1.3 | MUST | (unstated) | An implementation that disobeys a **SHOULD** MUST give the cause in its documentation. |  |  |
| `SCP-002` | §1.5.1 | MAY | A user | A user MAY have more than one device. |  |  |
| `SCP-003` | §1.5.2 | MAY | A user | A user MAY publish a Public Address. |  |  |
| `SCP-004` | §1.5.2 | MUST NOT | (unstated) | A party that holds one of the two addresses MUST NOT be able to correlate it with the other address. |  |  |
| `SCP-005` | §1.5.2 | MAY | A user | A user MAY bind a handle to a Public Address. |  |  |
| `SCP-006` | §1.5.2 | MUST | The client | The client MUST tell the user to verify a handle out-of-band before a security-relevant decision. |  |  |
| `SCP-007` | §1.5.3 | MAY | A deployment | A deployment MAY operate a Notification Relay. |  |  |
| `SCP-008` | §1.7 | MUST | A revision that changes a constant of this table | A revision that changes a constant of this table MUST change each part of the third column in the same commit. |  |  |
| `SCP-009` | §1.7 | MUST | A revision that makes a second part quote a constant | A revision that makes a second part quote a constant MUST add a row to this table. |  |  |
| `SCP-010` | §1.7 | MUST NOT | A revision | A revision MUST NOT define one constant in two parts. |  |  |
| `SCP-011` | §1.8 | MUST NOT | A revision | A revision MUST NOT add a requirement that names an artifact with no row in this table. |  |  |
| `SCP-012` | §1.8 | MUST | A revision that adds an artifact | A revision that adds an artifact MUST define its layout, its carrier, and its maker in the same commit. |  |  |
| `SCP-013` | §1.8 | MUST | A revision that adds an artifact | A revision that adds an artifact MUST add a row to this table. |  |  |
| `SCP-014` | §1.8 | MUST | A revision that supplies a missing layout, carrier, or maker | A revision that supplies a missing layout, carrier, or maker MUST change the applicable cell in the same commit. |  |  |
| `SCP-015` | §1.8 | MUST NOT | A revision | A revision MUST NOT define one artifact in two parts. |  |  |
| `SCP-016` | §1.9 | MUST | A revision that adds a duration | A revision that adds a duration MUST name the party that measures it. |  |  |
| `SCP-017` | §1.9 | MUST | A revision that adds a duration | A revision that adds a duration MUST name the event that starts it. |  |  |
| `SCP-018` | §1.9 | MUST | A party | A party MUST measure a duration from a monotonic source between two restarts. |  |  |
| `SCP-019` | §1.9 | MUST | (unstated) | If a clock movement occurs while a duration runs, the party MUST start that duration again. |  |  |
| `SCP-020` | §1.9 | MUST | A revision that adds a comparison between the clocks of two parties | A revision that adds a comparison between the clocks of two parties MUST state a skew tolerance. |  |  |
| `SCP-021` | §1.9 | MUST NOT | A client | A client MUST NOT delete a message, a key, a chunk, or a token on an interrupted duration. |  |  |

## THR — Threat Model and Security Goals

Source: `spec/02-threat-model.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `THR-001` | §2.2 | MUST | UMBRA | UMBRA MUST prevent A1 from learning the content or the recipient. |  |  |
| `THR-002` | §2.2 | MUST | UMBRA | UMBRA MUST also prevent A1 from learning the number of different conversations or the identity of a correspondent. |  |  |
| `THR-003` | §2.2 | MUST | UMBRA | UMBRA MUST give a relay no data at rest that identifies a user, and that rule covers a relay under full adversarial control. |  |  |
| `THR-004` | §2.2 | MUST | UMBRA | UMBRA MUST make sure that the logs of a relay cannot link a sender to a recipient. |  |  |
| `THR-005` | §2.2 | MUST NOT | (unstated) | If an adversary compromises *one relay*, that adversary MUST NOT get the content of a conversation. |  |  |
| `THR-006` | §2.2 | MUST NOT | (unstated) | If an adversary compromises *one relay*, that adversary MUST NOT get the identities of the participants. |  |  |
| `THR-007` | §2.2 | MUST | A client | A client MUST select the relays of one chain from different organizations in different jurisdictions. |  |  |
| `THR-008` | §2.4 | MUST | A conformant implementation | A conformant implementation MUST meet each goal of the table below. |  |  |
| `THR-009` | §2.4 | MUST | (unstated) | Thus the wire format MUST carry sufficient in-band context for a receiver to **classify a failure alone**. |  |  |
| `THR-010` | §2.4 | MUST | A revision that adds a trade | A revision that adds a trade MUST add a row to this table. |  |  |
| `THR-011` | §2.4.1 | MUST | A revision that adds a usability goal or a sociality goal | A revision that adds a usability goal or a sociality goal MUST add a row to this table. |  |  |
| `THR-012` | §2.4.1 | MUST | A revision that changes a rule of a row | A revision that changes a rule of a row MUST measure that goal again. |  |  |
| `THR-013` | §2.2 | MUST NOT | A client | A client MUST NOT write a plaintext record, a key, or a decrypted attachment to a platform store. |  |  |
| `THR-014` | §2.4.2 | MUST | A conformant implementation | A conformant implementation MUST meet each goal of the table above. |  |  |
| `THR-015` | §2.2 | MUST NOT | A web client | A web client MUST NOT run as a page that a host serves, because trust assumption 4 of §2.6 fails for such a page at each load. |  |  |

## NET — Network Architecture

Source: `spec/03-network-architecture.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `NET-001` | §3.1 | MAY | One physical server | One physical server MAY implement more than one role. |  |  |
| `NET-002` | §3.1 | MUST NOT | But a relay | But a relay MUST NOT operate as a Chain Relay and as a Directory Authority at the same time. |  |  |
| `NET-003` | §3.1 | MUST NOT | A relay | A relay MUST NOT operate as a Chain Relay and as the Notification Relay for the same client. |  |  |
| `NET-004` | §3.2.1 | MUST | `RecipientId` and `SenderId` | `RecipientId` and `SenderId` MUST be independent CSPRNG outputs. |  |  |
| `NET-005` | §3.2.1 | MUST NOT | A party | A party MUST NOT be able to derive one identifier from the other. |  |  |
| `NET-006` | §3.2.1 | MUST NOT | A party | A party MUST NOT be able to derive an identifier from a key or from an earlier queue. |  |  |
| `NET-007` | §3.2.1 | MUST NOT | A relay | A relay MUST NOT store a value that links the two identifiers outside of the one queue record. |  |  |
| `NET-008` | §3.2.2 | MUST NOT | A recipient | A recipient MUST NOT give `QE` to a relay. |  |  |
| `NET-009` | §3.2.2 | MUST NOT | A queue key | A queue key MUST NOT come from the Root Identity or from a device key. |  |  |
| `NET-010` | §3.2.2 | MUST NOT | A queue key | A queue key MUST NOT come from the key of a different queue. |  |  |
| `NET-011` | §3.2.2 | MUST NOT | A queue key | A queue key MUST NOT be equal to one of these keys. |  |  |
| `NET-012` | §3.2.2 | MUST NOT | A queue key | A queue key MUST NOT be linkable to one of these keys. |  |  |
| `NET-013` | §3.2.2 | MUST | Implementations | Implementations MUST make queue keys from the device CSPRNG. |  |  |
| `NET-014` | §3.2.2 | MUST NOT | Implementations | Implementations MUST NOT derive queue keys from a per-user seed. |  |  |
| `NET-015` | §3.2.3 | MUST NOT | Implementations | Implementations MUST NOT use a digital signature for a queue command. |  |  |
| `NET-016` | §3.2.4 | MUST | The relay | The relay MUST reject more than this number. |  |  |
| `NET-017` | §3.2.4 | MUST | The relay | The relay MUST signal the quota. |  |  |
| `NET-018` | §3.2.4 | MUST NOT | A client | A client MUST NOT synchronize the rotation across queues. |  |  |
| `NET-019` | §3.2.4 | MUST | A client | A client MUST use independent jitter for each queue rotation. |  |  |
| `NET-020` | §3.2.4 | MUST | (unstated) | At the end of a rotation, a client MUST send `DEL` to the old relay. |  |  |
| `NET-021` | §3.2.4 | MUST NOT | A client | A client MUST NOT send `DEL` at a device revocation. |  |  |
| `NET-022` | §3.2.5 | MUST NOT | A client | A client MUST NOT multiplex more than `MAX_QUEUES_PER_SESSION = 8` queues onto one transport session to one relay. |  |  |
| `NET-023` | §3.2.5 | MUST | A client | A client MUST divide its queues across independent sessions over independent relay chains. |  |  |
| `NET-024` | §3.2.5 | MUST | A client | A client MUST do this division again at each rotation. |  |  |
| `NET-025` | §3.3 | MUST | Implementations | Implementations MUST also pad at the transport-record layer (§3.8). |  |  |
| `NET-026` | §3.3.1 | MUST | An attachment | An attachment MUST use chunks of `CHUNK_SIZE` (Part 13 §13.7). |  |  |
| `NET-027` | §3.4.1 | MUST NOT | The operator | The operator MUST NOT select the layer (§10.5). |  |  |
| `NET-028` | §3.4.3 | MUST NOT | A client | A client MUST NOT use one circuit for more than one privacy mode. |  |  |
| `NET-029` | §3.4.3 | MUST NOT | A client | A client MUST NOT carry interactive traffic and bulk traffic on the same circuit (§3.8). |  |  |
| `NET-030` | §3.4.4 | MUST | Per-hop encryption | Per-hop encryption MUST use a **rugged-PRP or wide-block construction**. |  |  |
| `NET-031` | §3.4.4 | MUST NOT | Per-hop encryption | Per-hop encryption MUST NOT use a stream cipher with a separate MAC. |  |  |
| `NET-032` | §3.4.6 | MUST | A client | A client MUST refuse to build a chain that disobeys an invariant of §3.4.6. |  |  |
| `NET-033` | §3.4.6 | MUST | (unstated) | If no conformant chain is available under `NET-200`, the client MUST **fail closed** and show the cause. |  |  |
| `NET-034` | §3.4.6 | MUST NOT | The client | The client MUST NOT degrade silently to a single-operator path. |  |  |
| `NET-035` | §3.5.2 | MUST | A relay | A relay MUST deliver to a client on a schedule. |  |  |
| `NET-036` | §3.5.2 | MUST NOT | That schedule | That schedule MUST NOT depend on the arrival times of the messages. |  |  |
| `NET-037` | §3.5.2 | MUST | (unstated) | If that batched peek finds more than `DRAIN_THRESHOLD` messages, the relay MUST answer it in one unpaced response. |  |  |
| `NET-038` | §3.5.2 | MUST NOT | UMBRA | UMBRA MUST NOT copy that default. |  |  |
| `NET-039` | §3.5.3 | MUST | The destination relay | The destination relay MUST take a delay for each message from an exponential distribution before it emits the message. |  |  |
| `NET-040` | §3.5.4 | MUST | A revision | A revision MUST derive this value again if the bucket ladder or the default chunk width changes. |  |  |
| `NET-041` | §3.5.4 | MUST | A client | A client MUST emit a delivery receipt when that client holds the message. |  |  |
| `NET-042` | §3.5.4 | MUST | A client | A client MUST emit a read receipt only after the user opens the conversation. |  |  |
| `NET-043` | §3.5.4 | MUST NOT | A client | A client MUST NOT emit a read receipt because it rendered a notification. |  |  |
| `NET-044` | §3.5.4 | MUST | The client | The client MUST batch acknowledgments for each queue. |  |  |
| `NET-045` | §3.5.4 | MUST | The client | The client MUST batch receipts for each peer up to `RECEIPT_BATCH_MAX`. |  |  |
| `NET-046` | §3.5.4 | MUST | The client | The client MUST emit a queued acknowledgment or a queued receipt in one of two places. |  |  |
| `NET-047` | §3.5.4 | MUST NOT | The client | The client MUST NOT open a transport session for the only purpose of an acknowledgment or a receipt. |  |  |
| `NET-048` | §3.5.4 | MUST NOT | A client | A client MUST NOT flush a held receipt because the application moved to the background. |  |  |
| `NET-049` | §3.5.4 | MUST NOT | The emission time | The emission time MUST NOT follow the attention of the user. |  |  |
| `NET-050` | §3.5.4 | MUST NOT | The client | The client MUST NOT emit an acknowledgment or a receipt sooner than `RECEIPT_MIN_DELAY` after the arrival that it reports. |  |  |
| `NET-051` | §3.5.4 | MUST | The client | The client MUST use the first opportunity that occurs after that floor. |  |  |
| `NET-052` | §3.5.4 | MUST | (unstated) | If the client holds an acknowledgment or a receipt for longer than `RECEIPT_MAX_HOLD`, the client MUST discard it. |  |  |
| `NET-053` | §3.5.4 | MUST | The client | The client MUST hold a receipt in the encrypted store only. |  |  |
| `NET-054` | §3.5.4 | MUST | The client | The client MUST erase a receipt when it emits or discards it. |  |  |
| `NET-055` | §3.5.4 | MUST | The client | The client MUST pad a receipt cell to `B0` at each receipt count. |  |  |
| `NET-056` | §3.5.4 | MUST | (unstated) | If the queued receipts do not fit the current bucket, the client MUST split them across two opportunities. |  |  |
| `NET-057` | §3.5.4 | MUST NOT | A client | A client MUST NOT select a larger bucket to carry more receipts, because the bucket then names the count. |  |  |
| `NET-059` | §3.5.4 | MUST | (unstated) | Delivery receipts and read receipts MUST be off by default for a new contact. |  |  |
| `NET-060` | §3.6.1 | MUST | Cover cells | Cover cells MUST be **loops**. |  |  |
| `NET-061` | §3.6.2 | MUST | A client | A client MUST use one cover rate in each privacy mode. |  |  |
| `NET-062` | §3.6.2 | MUST NOT | A client | A client MUST NOT change the cover rate because of the mode. |  |  |
| `NET-063` | §3.6.2 | MUST | (unstated) | About 20 % of the cover cells in tier A MUST be loops. |  |  |
| `NET-064` | §3.6.2 | MUST | A client | A client MUST carry a queued acknowledgment, a queued receipt, or a queued backup write in a scheduled cover slot. |  |  |
| `NET-065` | §3.6.2 | MUST | (unstated) | If two such items are due in one slot, the client MUST use the order below. |  |  |
| `NET-066` | §3.6.2 | MUST | A client | A client MUST fetch the directory diff only when the radio is on for another cause. |  |  |
| `NET-067` | §3.6.2 | MUST NOT | A client | A client MUST NOT open a session for the only purpose of a directory diff. |  |  |
| `NET-068` | §3.6.2 | MUST | Implementations | Implementations MUST test these constants against a real handset with a power monitor before a release. |  |  |
| `NET-069` | §3.6.3 | MUST | These relays | These relays MUST make loop cover at or above `RELAY_LOOP_RATE`. |  |  |
| `NET-070` | §3.6.3 | MUST | These relays | These relays MUST also make the inbound pacing cover of §3.5.2. |  |  |
| `NET-071` | §3.7 | MUST NOT | A client | A client MUST NOT send a retransmission at a timeout, because a retransmission burst at the timeout is a signature. |  |  |
| `NET-072` | §3.7 | MUST | A client | A client MUST then carry a retransmission in the next session that it opens for another cause. |  |  |
| `NET-073` | §3.8 | MUST | Implementations | **Implementations MUST disable 0-RTT** in TLS and in QUIC. |  |  |
| `NET-074` | §3.8 | MUST | (unstated) | Interactive traffic and bulk traffic MUST use separate connections, or separate QUIC streams. |  |  |
| `NET-075` | §3.8 | MUST | UMBRA | UMBRA MUST open userspace sockets in the application process. |  |  |
| `NET-076` | §3.8 | MUST NOT | UMBRA | UMBRA MUST NOT capture the device traffic with the Android `VpnService` or with the iOS `NetworkExtension`. |  |  |
| `NET-077` | §3.9 | MUST | A relay | A relay MUST use this one mean in each privacy mode. |  |  |
| `NET-078` | §3.9 | MUST NOT | A relay | A relay MUST NOT change the mean because of the mode. |  |  |
| `NET-079` | §3.9 | MUST NOT | Thus a revision | Thus a revision MUST NOT set `PACING_MEAN` above 1.9 s. |  |  |
| `NET-080` | §3.9.1 | MUST NOT | The mode | The mode MUST NOT be visible in the cell size, the cell count, or the chain length. |  |  |
| `NET-081` | §3.9.1 | MUST NOT | The UI | The UI MUST NOT label Private mode in a manner that implies that the user hides something. |  |  |
| `NET-082` | §3.10 | MUST NOT | An implementation | An implementation MUST NOT hardcode a relay list in the binary. |  |  |
| `NET-083` | §3.10 | MAY | A deployment | A deployment MAY use a function URL at a large cloud provider. |  |  |
| `NET-084` | §3.10.1 | MUST NOT | An operator | An operator MUST NOT operate an UMBRA relay that the directory does not list. |  |  |
| `NET-085` | §3.10.1 | MUST NOT | A client | A client MUST NOT build a chain through a relay that the signed manifest of §3.10 does not carry. |  |  |
| `NET-086` | §3.10.1 | MUST | A client | A client MUST select an ingress relay under the rules of Part 10 §10.6.1. |  |  |
| `NET-087` | §3.10.1 | MUST | A client | A client MUST keep an ingress relay for the minimum lifetime that Part 10 §10.6.1 gives. |  |  |
| `NET-088` | §3.10.1 | MUST NOT | A client | A client MUST NOT replace an ingress relay because of local performance (Part 10 §10.6.2). |  |  |
| `NET-089` | §3.10.1 | MAY | An operator | An operator MAY retire a relay. |  |  |
| `NET-090` | §3.10.1 | MUST | (unstated) | If an operator retires more than one relay, that operator MUST separate the retirements in time. |  |  |
| `NET-091` | §3.10.1 | MUST NOT | An operator | An operator MUST NOT derive a relay identity from the IP address of the relay. |  |  |
| `NET-092` | §3.12 | MUST | An implementation | An implementation MUST measure the text length distribution of a real deployment before a revision re-tunes the bucket ladder. |  |  |
| `NET-093` | §3.12 | MUST | A revision | A revision MUST count those records. |  |  |
| `NET-094` | §3.12 | MUST | An implementation | An implementation MUST measure the queue spread of the drains in a real deployment before a revision re-tunes this row. |  |  |
| `NET-095` | §3.12 | MUST | Thus a revision | Thus a revision MUST change the pacing rule, the foreground time of the model, or the sync topology before it raises the device count. |  |  |
| `NET-096` | §3.12 | MUST | A revision that changes one of the inputs below | A revision that changes one of the inputs below MUST derive this table again. |  |  |
| `NET-097` | §3.12 | MUST NOT | A client | A client MUST NOT carry a conversation record on a sync channel in a push-wake session. |  |  |
| `NET-098` | §3.12 | MAY | A client | A client MAY carry a control record of that section in such a session. |  |  |
| `NET-099` | §3.12 | MUST NOT | A client | A client MUST NOT build a spare circuit in a push-wake session. |  |  |
| `NET-100` | §3.12 | MUST NOT | A client | A client MUST NOT hold a push-wake session longer than 6 s, because U4 then fails. |  |  |
| `NET-101` | §3.12 | MUST | Implementations | Implementations MUST measure this cost on real handsets with a power monitor before a release. |  |  |
| `NET-102` | §3.2.4 | MAY | After that period a recipient | After that period a recipient MAY acknowledge above the hole. |  |  |
| `NET-103` | §3.2.4 | MUST | That recipient | That recipient MUST show a delivery gap. |  |  |
| `NET-104` | §3.12 | MUST | (unstated) | A revision that changes `REPLICAS`, the verify sample, or the `CREP` batching MUST derive this row again. |  |  |
| `NET-105` | §3.12 | MUST | A revision that changes the signature count, the validity, or the diff width | A revision that changes the signature count, the validity, or the diff width MUST derive this row again. |  |  |
| `NET-106` | §3.4.4 | MUST | A client and a relay | A client and a relay MUST derive the hop key material from that secret with one HKDF-SHA3-256 invocation. |  |  |
| `NET-107` | §3.4.4 | MUST | An implementation | An implementation MUST use a different key for each direction, and it MUST NOT use one key for the two directions. |  |  |
| `NET-108` | §3.4.4 | MUST | A sender | A sender MUST encipher a cell with the three steps of §3.4.4, where `T` is `circ_id` and `C` is the chaining value of that direction. |  |  |
| `NET-109` | §3.4.4 | MUST | A relay | A relay MUST rewrite `circ_id` at each hop, and §3.4.3 makes that value unlinkable across hops. |  |  |
| `NET-110` | §3.4.4 | MUST | A maintainer | A maintainer MUST get a `/crypto-review` of this construction against the Counter Galois Onion paper (eprint 2025/583) before a release tag. |  |  |
| `NET-111` | §3.4.4 | MUST | An implementation | Before a release tag, an implementation MUST add a known-answer test for four cells. |  |  |
| `NET-112` | §3.4.4 | MUST | Two implementations | Two implementations MUST produce byte-identical cells for one key and one tweak. |  |  |
| `NET-113` | §3.4.4 | MUST | A receiver | A receiver MUST decipher a cell with the inverse of the three steps of §3.4.4. |  |  |
| `NET-114` | §3.4.4 | MUST | The party that removes the innermost layer | The party that removes the innermost layer MUST compare `X_L` against the 16 zero bytes in constant time. |  |  |
| `NET-115` | §3.4.4 | MUST | A receiver | A receiver MUST drop the cell and tear the circuit down when the two values differ. |  |  |
| `NET-116` | §3.4.4 | MUST | A sender and a receiver | A sender and a receiver MUST set `C` to the `tag` of the cell that they just processed. |  |  |
| `NET-117` | §3.2.1 | MUST NOT | A recipient | A recipient MUST NOT give `RecipientId` to a sender. |  |  |
| `NET-118` | §3.2.3 | MUST | A party | A party MUST compute `authorized_bytes` as the concatenation that §3.2.3 gives. |  |  |
| `NET-119` | §3.2.3 | MUST | A party | A party MUST set `bind` to the empty byte string for each command of Part 6 §6.4. |  |  |
| `NET-120` | §3.2.3 | MUST | (unstated) | For a `CPUT` of Part 13 §13.3.3, a party MUST set `bind` to the 32-byte `storage_token` of that section. |  |  |
| `NET-121` | §3.2.3 | MUST | A relay | A relay MUST reject a command whose `auth` does not verify. |  |  |
| `NET-122` | §3.2.3 | MUST | A relay | A relay MUST reject a command whose `corr_id` that relay accepted before in the same transport session. |  |  |
| `NET-123` | §3.2.3 | MUST NOT | A relay | A relay MUST NOT retain a `corr_id` after that session ends. |  |  |
| `NET-124` | §3.4.4 | MUST | (unstated) | For a cell to the queue relay, a client MUST set `X_L` of the innermost layer to 16 zero bytes. |  |  |
| `NET-125` | §3.4.4 | MUST | A client | A client MUST then apply the steps of NET-108 for hop 3, for hop 2, and for hop 1, in that order. |  |  |
| `NET-126` | §3.4.4 | MUST | A client | A client MUST write the `Y_L` of hop 1 into the `tag` field and the `Y_R` of hop 1 into the `body` field. |  |  |
| `NET-127` | §3.4.4 | MUST | A relay | A relay MUST take `Y_L` from the `tag` field and `Y_R` from the `body` field. |  |  |
| `NET-128` | §3.4.4 | MUST | A relay | A relay MUST write the recovered `X_L` into the `tag` field and the recovered `X_R` into the `body` field. |  |  |
| `NET-129` | §3.4.4 | MUST NOT | A relay in the middle position | A relay in the middle position MUST NOT check `X_L`. |  |  |
| `NET-130` | §3.4.4 | MUST NOT | A party | A party MUST NOT act on a recovered payload before the comparison of NET-114 succeeds. |  |  |
| `NET-131` | §3.4.4 | MUST | A party | A party MUST process the cells of one circuit in the order that it receives them. |  |  |
| `NET-132` | §3.4.4 | MUST | A party | A party MUST tear the circuit down when a cell of that circuit does not arrive. |  |  |
| `NET-133` | §3.6.2 | MUST NOT | A client | A client MUST NOT carry a backup write in a cover slot. |  |  |
| `NET-134` | §3.11.1 | MUST | (unstated) | A revision that gives A2 or A3 a new active capability MUST add a row to this table. |  |  |
| `NET-135` | §3.12 | MUST | (unstated) | A revision that changes `OWNER_CLAIM_RATE` or the `OwnerClaimRecord` width MUST derive this row again. |  |  |
| `NET-136` | §3.12 | MUST | (unstated) | A revision that changes one of the four backup constants MUST derive this row again. |  |  |
| `NET-137` | §3.12 | MUST | An implementation | An implementation MUST measure the propagation of a real relay population before a release, and it MUST derive the two tables of §3.9 again. |  |  |
| `NET-138` | §3.12 | MUST | A revision | A revision MUST take a quantile of the sum, and it MUST NOT add the quantile of each term. |  |  |
| `NET-139` | §3.12 | MUST | A revision that changes `PACING_MEAN` | A revision that changes `PACING_MEAN` MUST derive the U2 target of Part 2 §2.4 again. |  |  |
| `NET-140` | §3.12 | MUST | That revision | That revision MUST also derive the U4 budget of §3.12 again. |  |  |
| `NET-141` | §3.12 | MUST | That revision | That revision MUST state the change against goal G6 and goal G7 of Part 2 §2.3. |  |  |
| `NET-142` | §3.3.2 | MUST NOT | A receiver | A receiver MUST NOT fetch a URL that a record carries. |  |  |
| `NET-143` | §3.3.2 | MUST NOT | A client | A client MUST NOT fetch a URL to render a preview. |  |  |
| `NET-144` | §3.3.2 | MAY | A sender | A sender MAY attach a preview that the sender made. |  |  |
| `NET-145` | §3.3.2 | MUST | A sender | A sender MUST re-encode a preview image under the rules of Part 9 §9.3.1, thus the image carries no metadata field. |  |  |
| `NET-146` | §3.3.2 | MUST | A client | A client MUST show the URL to the user before the user opens it. |  |  |
| `NET-147` | §3.3.2 | MUST | A client | A client MUST open a URL of a scheme other than `umbra` in the browser of the platform. |  |  |
| `NET-148` | §3.3.2 | MUST | (unstated) | Thus a client MUST render the host of the URL beside the preview. |  |  |
| `NET-149` | §3.2.3 | MUST | A party | For a community command of Part 12 §12.3.3, a party MUST use `pull_sk` in the place of `Q*_auth_sk`. |  |  |
| `NET-150` | §3.4.3 | MUST | A client | A client MUST send each `EXTEND` cell in bucket `B1`. |  |  |
| `NET-151` | §3.4.3 | MUST | A relay | A relay MUST send each `EXTENDED` cell in bucket `B1`. |  |  |
| `NET-152` | §3.4.3 | MUST | A client | A client MUST set `relay_id` to the `relay_id` of the descriptor that gave `s` for that hop. |  |  |
| `NET-153` | §3.4.3 | MUST | A relay | A relay MUST drop an `EXTEND` cell whose `relay_id` differs from its own `relay_id`. |  |  |
| `NET-154` | §3.4.3 | MUST | A party that opens a circuit on a link | A party that opens a circuit on a link MUST draw `circ_id` from its CSPRNG. |  |  |
| `NET-155` | §3.4.3 | MUST NOT | That party | That party MUST NOT use a value that a live circuit of that link holds. |  |  |
| `NET-156` | §3.4.3 | MUST | A relay | A relay MUST treat a cell that arrives on a `circ_id` that it does not hold as a build cell. |  |  |
| `NET-157` | §3.4.3 | MUST | A relay | A relay MUST drop a build cell whose command byte is not `EXTEND`. |  |  |
| `NET-158` | §3.4.3 | MUST | A relay | A relay MUST drop a build cell whose `tag` is not 16 zero bytes. |  |  |
| `NET-159` | §3.4.3 | MUST | A relay that accepts an `EXTEND` cell on a new `circ_id` | A relay that accepts an `EXTEND` cell on a new `circ_id` MUST run the responder side of Part 5 §5.4.9. |  |  |
| `NET-160` | §3.4.3 | MUST | That relay | That relay MUST answer with an `EXTENDED` cell on that `circ_id`, with a `tag` of 16 zero bytes. |  |  |
| `NET-161` | §3.4.3 | MUST | That relay | That relay MUST hold the circuit from that answer on. |  |  |
| `NET-162` | §3.4.3 | MUST | A relay that recovers an `EXTEND` cell on a held circuit | A relay that recovers an `EXTEND` cell on a held circuit MUST send the body to the relay of `relay_id`. |  |  |
| `NET-163` | §3.4.3 | MUST | That relay | That relay MUST send the body on a new circuit of its link to that relay. |  |  |
| `NET-164` | §3.4.3 | MUST | A relay that receives an `EXTENDED` cell on a circuit of `NET-198` | A relay that receives an `EXTENDED` cell on a circuit of `NET-198` MUST send that body on the held circuit. |  |  |
| `NET-165` | §3.4.3 | MUST | A relay | A relay MUST drop an `EXTEND` cell at the endpoint of a circuit that holds a next hop already. |  |  |
| `NET-166` | §3.4.3 | MUST | A relay in layer 3 | A relay in layer 3 MUST drop an `EXTEND` cell at the endpoint of a circuit. |  |  |
| `NET-167` | §3.4.3 | MUST | A relay | A relay MUST drop an `EXTEND` cell whose `relay_id` names a relay outside the layer after its own. |  |  |
| `NET-168` | §3.4.3 | MUST NOT | (unstated) | Before the `EXTENDED` cell of hop 3 arrives, a client MUST NOT send a cell other than `EXTEND` or `DESTROY`. |  |  |
| `NET-169` | §3.4.3 | MUST | (unstated) | If no `EXTENDED` cell arrives in `CIRCUIT_BUILD_TIMEOUT`, the client MUST send a `DESTROY` cell and discard the circuit. |  |  |
| `NET-170` | §3.2.6 | MUST | A client | A client MUST send a `NEW` for a queue before it gives the `QueueAddress` of that queue to a party. |  |  |
| `NET-171` | §3.2.6 | MUST | A client | A client MUST fill `relay_id` and `sender_id` from the relay that answered the `IDS`. |  |  |
| `NET-172` | §3.2.6 | MUST | A responder | A responder MUST put the `QueueAddress` of its first queue in the invitation bundle of Part 5 §5.4.1. |  |  |
| `NET-173` | §3.2.6 | MUST | An initiator | An initiator MUST put the `QueueAddress` of its first queue in `app_1` of flight 1. |  |  |
| `NET-174` | §3.2.6 | MUST | A responder | A responder MUST send flight 2 to the queue that `app_1` names. |  |  |
| `NET-175` | §3.2.6 | MUST NOT | A responder | A responder MUST NOT store that queue as the outbound queue of the contact before flight 3 verifies. |  |  |
| `NET-176` | §3.2.6 | MUST | (unstated) | At a rotation, the queue owner MUST send the new `QueueAddress` to the contact as a record of kind `0x33`. |  |  |
| `NET-177` | §3.2.6 | MUST | The owner | The owner MUST hold the old queue until a record arrives on the new queue, or until `ROTATE_GRACE` ends. |  |  |
| `NET-178` | §3.2.6 | MUST | The owner | The owner MUST then send the `DEL` of `NET-020`. |  |  |
| `NET-179` | §3.2.6 | MUST | A sender | A sender MUST use the newest `QueueAddress` that it accepted for a contact for each later `SEND` to that contact. |  |  |
| `NET-180` | §3.2.6 | MUST | (unstated) | If one operation rotates queues of more than one contact, the client MUST draw an independent delay for each. |  |  |
| `NET-181` | §3.2.6 | MUST | A client | A client MUST draw that delay from an exponential distribution with a mean of `SWEEP_SPREAD`. |  |  |
| `NET-182` | §3.2.6 | MUST | A client whose channel to a contact is dead | A client whose channel to a contact is dead MUST make a new queue for that contact. |  |  |
| `NET-183` | §3.2.6 | MUST | That client | That client MUST write a `DeadChannelBlob` with the `QueueAddress` of that queue under `handle(own, week)` and `read_sk(own, week)`. |  |  |
| `NET-184` | §3.2.6 | MUST | That client | That client MUST write the blob again under the handle of each new week while the channel stays dead. |  |  |
| `NET-185` | §3.2.6 | MUST | That client | That client MUST send a `CDEL` for the blob of the earlier week when it writes the new one. |  |  |
| `NET-186` | §3.2.6 | MUST | (unstated) | If a channel is dead or silent, the client MUST fetch `handle(peer, week)` and `handle(peer, week - 1)`. |  |  |
| `NET-187` | §3.2.6 | MUST | A client | A client MUST repeat that fetch one time in each week while the condition holds. |  |  |
| `NET-188` | §3.2.6 | MUST | A client | A client MUST draw the time of each fetch from a uniform distribution over 24 hours. |  |  |
| `NET-189` | §3.2.6 | MUST NOT | A client | A client MUST NOT fetch a dead-channel handle of a contact whose channel is neither dead nor silent. |  |  |
| `NET-190` | §3.2.6 | MUST | A client that opens a `DeadChannelBlob` of a peer | A client that opens a `DeadChannelBlob` of a peer MUST take its `QueueAddress` as the newest address of that peer. |  |  |
| `NET-191` | §3.2.6 | MUST | That client | That client MUST then send its own current `QueueAddress` as a record of kind `0x33` on that channel. |  |  |
| `NET-192` | §3.2.6 | MUST | A client | A client MUST treat a `DeadChannelBlob` whose `sealed` field does not open under `blob_key` as an empty handle. |  |  |
| `NET-193` | §3.2.6 | MUST | (unstated) | After a client accepts a `QueueAddress` of a contact, it MUST send again each record that holds no delivery receipt. |  |  |
| `NET-194` | §3.2.6 | MUST NOT | A client | A client MUST NOT write a `DeadChannelBlob` for a contact that the user blocked under Part 14 §14.12. |  |  |
| `NET-195` | §3.2.4 | MUST | A relay | A relay MUST count an accepted `SEND` and a `SUB` on a queue as activity. |  |  |
| `NET-196` | §3.2.4 | MUST NOT | A relay | A relay MUST NOT count a `COVER` as activity. |  |  |
| `NET-197` | §3.2.6 | MUST NOT | A client | A client MUST NOT fetch the dead-channel handle of a blocked contact. |  |  |
| `NET-198` | §3.4.3 | MUST | That relay | Before it sends the body, that relay MUST bind the new circuit to the held circuit as its next hop. |  |  |
| `NET-199` | §3.4.3 | MUST | That relay | That relay MUST send that body under its backward layer, with `X_L` of 16 zero bytes. |  |  |
| `NET-200` | §3.4.6 | MAY | (unstated) | If no chain satisfies every invariant, a client MAY relax invariant 2 at hop 2 alone. |  |  |
| `NET-201` | §3.4.6 | MUST | A client that relaxes invariant 2 | A client that relaxes invariant 2 MUST show the user that relaxation. |  |  |
| `NET-202` | §3.4.6 | MUST NOT | A client | A client MUST NOT relax invariant 1, invariant 3, invariant 4, or invariant 2 between hop 1 and hop 3. |  |  |
| `NET-203` | §3.2.6 | MUST | A client | A client MUST compute `week` from the most recent `DirectoryRoot` that it accepted. |  |  |
| `NET-204` | §3.4.4 | MUST | A client | A client MUST run the update on the forward key set of hop 3 after the hop 3 step of NET-125. |  |  |
| `NET-205` | §3.4.4 | MUST | A queue relay | A queue relay MUST run the update on its forward key set after the comparison of NET-114 succeeds. |  |  |
| `NET-206` | §3.4.4 | MUST | A queue relay | A queue relay MUST run the update on its backward key set after it enciphers a cell. |  |  |
| `NET-207` | §3.4.4 | MUST | A client | A client MUST run the update on the backward key set of hop 3 after the comparison of NET-114 succeeds. |  |  |
| `NET-208` | §3.4.4 | MUST | A party | A party MUST erase the key set that the update replaces. |  |  |
| `NET-209` | §3.4.4 | MUST NOT | A relay in the middle position | A relay in the middle position MUST NOT run the update. |  |  |
| `NET-210` | §3.4.4 | MUST | Two implementations | Two implementations MUST hold one hop 3 key set after `CIRCUIT_MAX_CELLS` cells in one direction. |  |  |
| `NET-211` | §3.4.4 | MUST NOT | A client | A client MUST NOT run the update on the key set of hop 1 or of hop 2. |  |  |
| `NET-212` | §3.12 | MUST | An implementation | An implementation MUST measure the queue-relay spread of a real deployment before a revision re-tunes this table. |  |  |
| `NET-213` | §3.12 | MUST | An implementation | An implementation MUST measure the handshake cost of the L1 stack of §3.8 before a revision re-tunes this table. |  |  |
| `NET-214` | §3.8 | MUST | A client | A client MUST offer `X25519MLKEM768` as the first key share of the ClientHello. |  |  |
| `NET-215` | §3.8 | MUST NOT | A client | A client MUST NOT offer a group other than `X25519MLKEM768` and `X25519`. |  |  |
| `NET-216` | §3.8 | MUST | A relay operator | A relay operator MUST terminate TLS with a stack that accepts `X25519MLKEM768`. |  |  |
| `NET-217` | §3.7 | MUST | A client | A client MUST stop the ARQ of a record at a `NACK` with reason `REJECTED` or `VERSION`. |  |  |
| `NET-218` | §3.7 | MUST | A client | A client MUST continue the ARQ after a `LIMIT`, a `BUSY`, or an `ADMISSION`, under the rules of that section. |  |  |
| `NET-219` | §3.7 | MUST NOT | A client | A client MUST NOT send one record more than `SEND_MAX_ATTEMPTS` times. |  |  |
| `NET-220` | §3.7 | MUST | (unstated) | If a record holds no relay acknowledgment `SEND_GIVE_UP` after its first send, the client MUST stop the ARQ of that record. |  |  |
| `NET-221` | §3.7 | MUST | (unstated) | When the ARQ of a record stops, the client MUST put the record in the `failed` state of Part 15 §15.9. |  |  |
| `NET-222` | §3.7 | MUST NOT | A client | A client MUST NOT send a `failed` record again without a user action. |  |  |
| `NET-223` | §3.2.7 | MUST | A relay that serves queues | A relay that serves queues MUST serve group queues. |  |  |
| `NET-224` | §3.2.7 | MUST | A relay | A relay MUST make `GroupQueueId` from its CSPRNG at a `GNEW`. |  |  |
| `NET-225` | §3.2.7 | MUST NOT | A party | A party MUST NOT be able to derive `GroupQueueId` from a key or from an earlier queue. |  |  |
| `NET-226` | §3.2.7 | MUST | A relay | A relay MUST hold, for a group queue, `GroupQueueId`, the three public keys, the previous `read_pk` and `write_pk` under the grace below, the records, and the notifier set of Part 8 §8.5.2. |  |  |
| `NET-227` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT hold per-reader state of a group queue other than the live sessions and the notifiers. |  |  |
| `NET-228` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT hold a list of the members of a group queue, and no command of Part 6 §6.4.5 carries a member identifier. |  |  |
| `NET-229` | §3.2.7 | MUST | A party | A party MUST authorize a group-queue command with the authenticator of §3.2.3, with `read_sk`, `write_sk`, or `own_sk` in the place of `Q*_auth_sk` and with `GroupQueueId` in `queue_id`. |  |  |
| `NET-230` | §3.2.7 | MUST | A member | A member MUST derive `read_sk` and `write_sk` of a group queue from the group epoch secret `K_e` under Part 11 §11.3.1. |  |  |
| `NET-231` | §3.2.7 | MUST NOT | (unstated) | A creator MUST make `own_sk` from the device CSPRNG, and a party MUST NOT derive it. |  |  |
| `NET-232` | §3.2.7 | MUST | A relay | A relay MUST assign `seq` for each group queue as a `u32` that starts at 1, that increases strictly, and that it never reissues. |  |  |
| `NET-233` | §3.2.7 | MUST NOT | A client | A client MUST NOT use `seq` as a message identifier or as an order across replicas. |  |  |
| `NET-234` | §3.2.7 | MUST | A relay | A relay MUST retain a record of a group queue by time and by quota only, under the table below. |  |  |
| `NET-235` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT erase a record because a reader read it. |  |  |
| `NET-236` | §3.2.7 | MUST | A reader | A reader MUST hold its own cursor for each replica, as mutable state of Part 7 §7.5.3, for each device. |  |  |
| `NET-237` | §3.2.7 | MUST | (unstated) | If a `GSUB` names a backlog above `DRAIN_THRESHOLD` of §3.5.2, the relay MUST answer it in one unpaced response, as `NET-037` gives for a pairwise queue. |  |  |
| `NET-238` | §3.2.7 | MUST | A relay | A relay MUST answer an accepted `GPOST` with a `GSEQ`. |  |  |
| `NET-239` | §3.2.7 | MUST | (unstated) | If a `GPOST` carries record bytes that the relay already holds, the relay MUST answer with the `seq` that it holds for those bytes. |  |  |
| `NET-240` | §3.2.7 | MUST | A relay | A relay MUST apply `GROUP_POST_RATE` for each group queue. |  |  |
| `NET-241` | §3.2.7 | MUST | A relay | A relay MUST answer a `GPOST` above that rate with a `NACK` of reason `LIMIT` (Part 6 §6.4.4). |  |  |
| `NET-242` | §3.2.7 | MUST | After a `GKEY`, a relay | After a `GKEY`, a relay MUST keep the previous `read_pk` for `GROUP_READ_GRACE` and the previous `write_pk` for `GROUP_WRITE_GRACE`. |  |  |
| `NET-243` | §3.2.7 | MUST | Inside that grace, a relay | Inside that grace, a relay MUST accept a `GSUB`, a `GUNSUB`, a `GNREG`, or a `GNUNREG` under either read key, and a `GPOST` under either write key. |  |  |
| `NET-244` | §3.2.7 | MUST | At a `GDEL`, a relay | At a `GDEL`, a relay MUST erase the group queue, each record, and each notifier. |  |  |
| `NET-245` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT retain an identifier of a deleted group queue. |  |  |
| `NET-246` | §3.2.7 | MUST | A relay | A relay MUST erase a record `GROUP_RETENTION` after its acceptance. |  |  |
| `NET-247` | §3.2.7 | MUST | If the records of a group queue exceed this quota, the relay | If the records of a group queue exceed this quota, the relay MUST erase the oldest record first. |  |  |
| `NET-248` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT erase a record below `GROUP_RETENTION` for a cause other than this quota or a `GDEL` | `GROUP_POST_RATE` | 60 records in each 60 s for each group queue, relay-local | `NET-240` and `NET-241` apply it | `GROUP_READ_GRACE` | 30 days | `NET-242` keeps the previous `read_pk` for this period | `GROUP_WRITE_GRACE` | 24 h | `NET-242` keeps the previous `write_pk` for this period | `GROUP_IDLE_TTL` | 60 days without an accepted `GPOST` or a `GSUB` | |  |  |
| `NET-249` | §3.2.7 | MUST | A relay | A relay MUST delete a group queue with no activity for this period. |  |  |
| `NET-250` | §3.2.7 | MUST | A relay | A relay MUST count an accepted `GPOST` and a `GSUB` as activity. |  |  |
| `NET-251` | §3.2.7 | MUST NOT | A relay | A relay MUST NOT count a `COVER` as activity | `GROUP_NOTIFIER_MAX` | 4 096 notifiers for each group queue | |  |  |
| `NET-252` | §3.2.7 | MUST | A relay | A relay MUST reject a `GNREG` that would exceed this count. |  |  |
| `NET-253` | §3.2.7 | MUST | A creator | A creator MUST make one group queue on each of `GROUP_REPLICAS` relays. |  |  |
| `NET-254` | §3.2.7 | MUST | The entries of those relays | The entries of those relays MUST carry different `operator_id` values and different jurisdiction blocs, under invariant 1 and invariant 2 of §3.4.6. |  |  |
| `NET-255` | §3.2.7 | MUST NOT | A creator | A creator MUST NOT apply the relaxation of `NET-200` to the two replicas. |  |  |
| `NET-256` | §3.2.7 | MUST | A sender | A sender MUST send the same record bytes to each replica, each under the ARQ of §3.7. |  |  |
| `NET-257` | §3.2.7 | MUST | A client | A client MUST put a record in the `accepted` state of Part 15 §15.9.1 when the first replica returns a `GSEQ`. |  |  |
| `NET-258` | §3.2.7 | MUST | The client | The client MUST continue the ARQ to the other replica in the background. |  |  |
| `NET-259` | §3.2.7 | MUST | (unstated) | If the ARQ to one replica ends under `NET-220` after the other replica accepted, the client MUST report that replica as a link fault under Part 10 §10.4.2. |  |  |
| `NET-260` | §3.2.7 | MUST | A reader | A reader MUST subscribe to one replica in each session, and it MUST select that replica at random. |  |  |
| `NET-261` | §3.2.7 | MUST | A reader | A reader MUST alternate replicas across sessions. |  |  |
| `NET-262` | §3.2.7 | MUST | (unstated) | If a reader observes a gap in the `counter` of one sender for longer than `GROUP_GAP_TIMEOUT` of Part 11 §11.10, it MUST open a session to the other replica and fetch from its cursor there. |  |  |
| `NET-263` | §3.2.7 | MUST NOT | A client | A client MUST NOT carry more than one group queue on one transport session. |  |  |
| `NET-264` | §3.2.7 | MUST NOT | A client | A client MUST NOT carry a command of a range other than Part 6 §6.4.5 on a session that carries a group-queue command. |  |  |
| `NET-265` | §3.2.7 | MAY | A client | A client MAY send a `COVER` of Part 6 §6.3 on a group-queue session. |  |  |
| `NET-266` | §3.2.7 | MUST | A client | A client MUST put each group-queue session on its own relay chain, under the invariants of §3.4.6. |  |  |
| `NET-267` | §3.2.7 | MUST | For each cell of a group-queue session, a client | For each cell of a group-queue session, a client MUST treat the group-queue relay as the queue relay of `NET-124`. |  |  |
| `NET-268` | §3.5.2 | MUST | A relay | A relay MUST run the clock of `NET-035` and `NET-036` on a group-queue session of §3.2.7 as on a pairwise session. |  |  |
| `NET-269` | §3.5.2 | MUST | The cover cell of a group-queue session | The cover cell of a group-queue session MUST have the shape of a `GMSG`, thus it is bit-indistinguishable from a real `B0` delivery on that session. |  |  |
| `NET-270` | §3.7 | MUST | A client | A client MUST take a `GSEQ` as the relay acknowledgment of a `GPOST` under this section. |  |  |
| `NET-271` | §3.7 | MUST | A client | A client MUST count `SEND_MAX_ATTEMPTS` and `SEND_GIVE_UP` for each replica of a `GPOST` separately. |  |  |
| `NET-272` | §3.7 | MUST | A client | A client MUST put a `GPOST` in the `failed` state only when no replica returned a `GSEQ` before `SEND_GIVE_UP`. |  |  |
| `NET-273` | §3.12 | MUST | An implementation | An implementation MUST measure the group-queue relay spread of a real deployment before a revision re-tunes this table. |  |  |
| `NET-274` | §3.12 | MUST | (unstated) | A revision that changes `GROUP_MAX`, `GROUP_REPLICAS`, `PRESENCE_INTERVAL`, or the group-record layout of Part 11 §11.3 MUST derive these rows again. |  |  |
| `NET-275` | §3.8 | MUST NOT | (unstated) | A web client MUST send the L1 stream through the WebSocket API of its browser, over TLS to port 443, and it MUST NOT use WebTransport in v1. |  |  |
| `NET-276` | §3.8 | MUST NOT | A relay | A relay MUST NOT accept TLS early data on its L1 listener. |  |  |
| `NET-277` | §3.8 | MUST NOT | A web client | A web client MUST NOT race QUIC, because the browser gives it no QUIC stream in v1. |  |  |
| `NET-278` | §3.2.3 | MUST | A party | A party MUST derive `k` as `HKDF-SHA3-256(salt = "", ikm = X25519(Q*_auth_sk, RelaySession_pk), info = "umbra/v1/cmd-auth", L = 32)`, and it MUST abort on a non-contributory Diffie-Hellman output, as Part 5 rule `CRY-040` does. |  |  |
| `NET-279` | §3.4.4 | MUST NOT | (unstated) | A party MUST take `T` from the derivation of `NET-106`, and it MUST NOT take `T` from `circ_id`. |  |  |
| `NET-280` | §3.8 | MUST | A client | A client MUST open the WebSocket-shaped stream with `GET /umbra HTTP/1.1`, a `Host` header that carries the `host` of the descriptor of Part 10 §10.5.3, `Upgrade: websocket`, `Connection: Upgrade`, a `Sec-WebSocket-Key` of 16 bytes from the CSPRNG in base64, `Sec-WebSocket-Version: 13`, and `Sec-WebSocket-Protocol: umbra.v1`, and no extension header. |  |  |
| `NET-281` | §3.8 | MUST NOT | (unstated) | A relay MUST answer an upgrade it accepts with status `101`, the `Sec-WebSocket-Accept` of RFC 6455 §4.2.2, and the same subprotocol, and it MUST NOT accept an extension. |  |  |
| `NET-282` | §3.8 | MUST NOT | (unstated) | A client MUST verify the TLS certificate of a relay against the `host` of its descriptor under the public CA roots, and it MUST NOT accept a connection without that check. |  |  |
| `NET-283` | §3.8 | MUST | A QUIC connection | A QUIC connection MUST negotiate the ALPN `umbra.v1`, and the TCP connection negotiates none. |  |  |
| `NET-284` | §3.2.3 | MUST | `RelaySession_pk` of a circuit | `RelaySession_pk` of a circuit MUST be the `er` field of the `HopReply` of its last hop. |  |  |
| `NET-285` | §3.2.3 | MUST | That hop | That hop MUST keep the private half of `er` as `RelaySession_sk` until the circuit ends, and it MUST erase it then. |  |  |
| `NET-286` | §3.2.3 | MUST | Each other hop | Each other hop MUST erase the private half of its `er` at the end of the handshake, under `CRY-059`. |  |  |
| `NET-287` | §3.2.3 | MUST | (unstated) | For the rules `NET-122` and `NET-123`, and for each rule of Part 6 that names the transport session of a command, the session of a command that arrives over a circuit is that circuit. |  |  |
| `NET-288` | §3.2.3 | MUST | A client | A client MUST reject an `IDS` whose `relay_session_pk` differs from the `er` of the circuit that carried it. |  |  |
| `NET-289` | §3.4.3 | MUST | (unstated) | A relay of layer 1 or 2 whose circuit holds no next hop is the endpoint of a forward cell, and it makes the check of `NET-114`. |  |  |
| `NET-290` | §3.4.3 | MUST | (unstated) | A relay reaches a relay of the next layer as a client of the session of Part 6 §6.2.3. |  |  |
| `NET-291` | §3.5.2 | MUST | A relay | A relay MUST send each cell that it starts on a circuit that ends at it on a tick of that clock. |  |  |
| `NET-292` | §3.2.6 | MUST | After flight 3, an initiator | After flight 3, an initiator MUST send a record of kind `0x33` as its first ratchet record, with the `QueueAddress` that `app_1` carried. |  |  |
| `NET-293` | §3.2.6 | MUST | A responder | A responder MUST hold a record of its user that comes before that first record, and it MUST send it when the chain opens. |  |  |
| `NET-294` | §3.2.6 | MUST NOT | A client | A client MUST NOT show a record of kind `0x33` in a conversation. |  |  |
| `NET-295` | §3.2.5 | MUST | A client | A client MUST count a queue toward that bound from its `NEW` or its `SUB`, because a relay binds the queue to the session at those two commands. |  |  |
| `NET-296` | §3.2.5 | MUST | A client that holds no session with room | A client that holds no session with room MUST build one more circuit, and the `NEW` MUST wait for that circuit. |  |  |
| `NET-297` | §3.2.5 | SHOULD | A client | A client SHOULD put the `SEND` to a contact on a circuit that does not serve the inbound queue of that contact. |  |  |
| `NET-298` | §3.2.4 | MUST | A queue relay | A queue relay MUST commit a change to durable storage before it sends the answer of the command that made the change. |  |  |
| `NET-299` | §3.2.4 | MUST | A relay | A relay MUST commit the changes of one command as a whole or not at all. |  |  |
| `NET-300` | §3.2.4 | MUST | The store | The store MUST hold, for each queue: the two identifiers, the two authorization keys with a lock key of Part 4 §4.3.1 in the place of `QS_auth`, the next sequence number, the last `ACK`, the notifier credential, the time of the last activity, and each record that no `ACK` covers. |  |  |
| `NET-301` | §3.2.4 | MUST | A relay | A relay MUST write each time to its store as a multiple of `STORE_TIME_GRAIN`, which is 3 600 s. |  |  |
| `NET-302` | §3.2.4 | MUST | A relay | A relay MUST erase from its storage a record that an `ACK` covers, a record past `MSG_TTL`, a queue after its `DEL` or its idle lifetime, and an invitation after its first fetch or its lifetime. |  |  |
| `NET-303` | §3.2.4 | MUST | At its start a relay | At its start a relay MUST drop a stored queue whose form does not parse, whose record sits at or below its last `ACK`, or whose record sits at or above its next sequence number. |  |  |
| `NET-304` | §3.6.2 | MUST | Each other cover cell of a client | Each other cover cell of a client MUST carry one `COVER` command of Part 6 §6.3 to the queue relay of the circuit, in the shape of a `B0` `SEND`. |  |  |
| `NET-305` | §3.6.2 | MUST | A client | A client MUST draw the time to the next slot from an exponential distribution with the mean of the tier, and it MUST draw it again at each slot, whether or not the slot carried an item. |  |  |
| `NET-306` | §3.6.2 | MUST | A client in the background that holds an open session | A client in the background that holds an open session MUST keep the slot clock for the items 1 to 6 of `NET-065`, and it MUST make no cover cell. |  |  |
| `NET-307` | §3.5.4 | MUST | A client | A client MUST hold at most one read receipt for each peer. |  |  |
| `NET-308` | §3.2.5 | MUST | A client | A client MUST put each command for a queue on a circuit whose last relay holds that queue: the `NEW`, the `SUB`, and the `ACK` of its own queue, and the `SEND` to the queue of a peer. |  |  |
| `NET-309` | §3.2.5 | MUST | A client that holds no such circuit | A client that holds no such circuit MUST build one, and the command MUST wait for it. |  |  |
| `NET-310` | §3.2.5 | MUST | A client | A client MUST give the candidates of §3.4.6 to the selection in a random order, and a relay that no other circuit of that client uses MUST come before a relay that one uses. |  |  |
| `NET-311` | §3.2.5 | MUST NOT | (unstated) | A client MUST build each chain again at the start of a run, and it MUST NOT store a chain: the store names the relay of a queue, and no relay of a path to it. |  |  |
| `NET-312` | §3.2.5 | MUST | A client | A client MUST reject a descriptor that has a relay line with no `layer`, no `operator`, no `country` or no `asn`, with one fact two times, or with a word that is no fact. |  |  |
| `NET-313` | §3.2.5 | MUST | A client | A client MUST take the first relay of layer 1 as its pinned ingress of `NET-022`. |  |  |
| `NET-314` | §3.2.5 | MUST | A client | A client MUST read a descriptor with the first line `umbra-network 1`. |  |  |
| `NET-315` | §3.2.5 | MUST | (unstated) | A stored queue can name a relay that the relay set holds no more, or a relay that no conformant chain reaches. |  |  |
| `NET-316` | §3.10 | MUST | An HTTPS carrier | An HTTPS carrier MUST give the `RelayManifest` at the path `/.well-known/umbra/manifest`, as the body of a `200` response with a `Content-Length`. |  |  |
| `NET-317` | §3.10 | MUST | A client | A client MUST make that request under the TLS configuration of §3.8, with no cookie and no header that names the device or the user. |  |  |
| `NET-318` | §3.10 | MUST | A client | A client MUST verify the bytes under Part 10 §10.5.5 before it uses one relay of them, and it MUST keep the last manifest that verified. |  |  |
| `NET-319` | §3.4.3 | MUST | A relay that holds no session to the relay of `relay_id` | A relay that holds no session to the relay of `relay_id` MUST open one and hold the body until it opens, and one dial MUST serve each body that waits for that relay. |  |  |

## IDN — Identity

Source: `spec/04-identity.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `IDN-001` | §4.2.1 | MUST NOT | A device | A device MUST NOT send the Root Identity to a relay. |  |  |
| `IDN-002` | §4.2.1 | MUST | A device | A device MUST transfer the Root Identity to a different device of the same user only on the device-link channel. |  |  |
| `IDN-003` | §4.2.1 | MUST | The client | The client MUST let the user recover the Root Identity as a **24-word recovery phrase**. |  |  |
| `IDN-004` | §4.2.3 | MAY | A user | A user MAY hold more than one Public Address at the index `j`. |  |  |
| `IDN-005` | §4.2.3 | MAY | A user | A user MAY hold a professional address and a personal address. |  |  |
| `IDN-006` | §4.2.3 | MAY | A user | A user MAY retire an address and move to the index `j+1`. |  |  |
| `IDN-007` | §4.2.3 | MUST | A client | A client MUST put the inbound request queues of a Public Address on different relays from a pairwise queue. |  |  |
| `IDN-008` | §4.2.3 | MUST | A client | A client MUST also put them in different transport sessions from a pairwise queue. |  |  |
| `IDN-009` | §4.2.3 | MUST NOT | The public address of a user | The public address of a user MUST NOT decide which relays hold the pairwise inboxes of that user. |  |  |
| `IDN-010` | §4.2.3 | MUST | (unstated) | At the moment of publication, the interface MUST state that a published address is a persistent identifier. |  |  |
| `IDN-011` | §4.2.3 | MUST | The interface | The interface MUST also state that a party can monitor such an address over time. |  |  |
| `IDN-012` | §4.2.3 | MUST | The interface | The interface MUST also state that pairwise invitations do not have this property. |  |  |
| `IDN-013` | §4.2.3 | MUST NOT | Implementations | Implementations MUST NOT show the two paths as equal in privacy. |  |  |
| `IDN-014` | §4.2.4 | MUST | The client | The client MUST tell the user to verify a handle out of band before a security-relevant decision. |  |  |
| `IDN-015` | §4.2.5 | MUST NOT | Thus the client | Thus the client MUST NOT show a setup screen for a Profile. |  |  |
| `IDN-016` | §4.2.5 | MUST | The palette | The palette MUST give a sufficient contrast ratio in a light theme and in a dark theme. |  |  |
| `IDN-017` | §4.2.5 | MAY | A user | A user MAY select a picture in place of the generated picture. |  |  |
| `IDN-018` | §4.2.5 | MUST | The client | The client MUST warn. |  |  |
| `IDN-019` | §4.2.5 | MUST | The client | The client MUST get an explicit confirmation. |  |  |
| `IDN-020` | §4.2.5 | SHOULD | The client | The client SHOULD warn. |  |  |
| `IDN-021` | §4.2.5 | MUST NOT | A client | A client MUST NOT dispatch a Profile as a fan-out to its contacts. |  |  |
| `IDN-022` | §4.2.5 | MUST NOT | A client | A client MUST NOT emit a cell whose only content is a Profile. |  |  |
| `IDN-023` | §4.3.1 | MUST | Implementations | Implementations MUST implement this lock for one-time invitations. |  |  |
| `IDN-024` | §4.3.2 | MUST | The UI | The UI MUST state this limit. |  |  |
| `IDN-025` | §4.5 | MUST | A key change | A key change MUST cause a **blocking notice in the conversation**. |  |  |
| `IDN-026` | §4.5 | MUST | The verification state | The verification state MUST apply to each pairwise identity. |  |  |
| `IDN-027` | §4.5 | MUST | The state | The state MUST continue through a queue rotation, a relay change, and a device link. |  |  |
| `IDN-028` | §4.5 | MUST NOT | The UI | The UI MUST NOT imply that unverified conversations are insecure. |  |  |
| `IDN-029` | §4.6 | MUST | (unstated) | The associated data of each record MUST hold the table identifier and the surrogate row identifier. |  |  |
| `IDN-030` | §4.6 | MUST | A `row_id` | A `row_id` MUST be unique inside its table. |  |  |
| `IDN-031` | §4.6 | MUST | A client | A client MUST reject a table that holds two live rows with one `row_id`. |  |  |
| `IDN-032` | §4.6 | MUST | A client | A client MUST report that condition in the same manner as a MAC mismatch. |  |  |
| `IDN-033` | §4.6 | MUST | Each table | Each table MUST carry a **table MAC**. |  |  |
| `IDN-034` | §4.6 | MUST | A client | A client MUST derive `K_tab` from `K_store` under the label `"umbra/v1/table-mac"`. |  |  |
| `IDN-035` | §4.6 | MUST NOT | A client | A client MUST NOT write `K_tab` to storage. |  |  |
| `IDN-036` | §4.6 | MUST | A client | A client MUST update the table MAC at each commit batch. |  |  |
| `IDN-037` | §4.6 | MUST NOT | A client | A client MUST NOT compute a table MAC by a scan of a table at the unlock. |  |  |
| `IDN-038` | §4.6 | MUST | A client | A client MUST verify each table MAC at the unlock. |  |  |
| `IDN-039` | §4.6 | MUST | (unstated) | If a table MAC does not match at the unlock, the client MUST tell the user. |  |  |
| `IDN-040` | §4.6 | MUST NOT | The client | The client MUST NOT continue silently. |  |  |
| `IDN-041` | §4.7.1 | MUST NOT | The client | The client MUST NOT export the code as 64 hexadecimal characters. |  |  |
| `IDN-042` | §4.7.1 | MAY | Mainstream builds | Mainstream builds MAY give platform-cloud backup of the Recovery Code through Android Block Store or iCloud Keychain. |  |  |
| `IDN-043` | §4.7.1 | MUST | Such backup | Such backup MUST be an explicit opt-in with a plain warning. |  |  |
| `IDN-044` | §4.7.1 | MUST | The warning | The warning MUST state that the backup makes a recovery dependency. |  |  |
| `IDN-045` | §4.7.1 | MUST | The warning | The warning MUST also name the legal process of that platform. |  |  |
| `IDN-046` | §4.7.1 | MUST | (unstated) | De-Googled builds, F-Droid builds, direct-download builds, and high-risk profiles MUST default to local self-custody recovery only. |  |  |
| `IDN-047` | §4.7.2 | MUST NOT | A retention limit | A retention limit MUST NOT remove an entry from that table. |  |  |
| `IDN-048` | §4.7.2 | MUST NOT | A client | A client MUST NOT write on a change. |  |  |
| `IDN-049` | §4.7.4 | MUST | An implementation | An implementation MUST measure these targets. |  |  |
| `IDN-050` | §4.7.4 | MUST | An implementation | An implementation MUST publish the results. |  |  |
| `IDN-051` | §4.7.6 | MUST NOT | A security-setup screen | A security-setup screen MUST NOT block the message list. |  |  |
| `IDN-052` | §4.7.6 | MUST | The client | The client MUST let a user dismiss a recovery prompt. |  |  |
| `IDN-053` | §4.7.6 | MUST NOT | (unstated) | After **two** dismissals the client MUST NOT prompt again, and only the settings screen offers the operation. |  |  |
| `IDN-054` | §4.7.6 | MUST NOT | Onboarding | Onboarding MUST NOT block on the confirmation of the recovery code if that block moves the time-to-first-message past the U1 target. |  |  |
| `IDN-055` | §4.5.1 | MUST | A client | A client MUST send a key-change notice inside the established pairwise ratchet session with that contact. |  |  |
| `IDN-056` | §4.5.1 | MUST NOT | A client | A client MUST NOT send it on a new session, on a group channel, or on a community channel. |  |  |
| `IDN-057` | §4.5.1 | MUST NOT | A client | A client MUST NOT sign a key-change notice. |  |  |
| `IDN-058` | §4.5.1 | MUST NOT | A client | A client MUST NOT carry a signature over the new keys inside the notice. |  |  |
| `IDN-059` | §4.5.1 | MUST | A receiver | A receiver MUST accept a key-change notice only from the receiving chain of that session. |  |  |
| `IDN-060` | §4.5.1 | MUST | A receiver | A receiver MUST bind the two new public keys into the next handshake transcript with that contact. |  |  |
| `IDN-061` | §4.5.1 | MUST | A receiver | A receiver MUST show the blocking notice of §4.5, and IDN-025 states that rule. |  |  |
| `IDN-062` | §4.5.1 | MUST NOT | A receiver | A receiver MUST NOT apply the new keys before the user answers that prompt. |  |  |
| `IDN-063` | §4.5.1 | MUST | A client | A client MUST send one key-change notice to each contact with an independent randomized delay for each contact. |  |  |
| `IDN-064` | §4.5.1 | MUST | A client | A client MUST draw that delay from an exponential distribution with a mean of `SWEEP_SPREAD`. |  |  |
| `IDN-065` | §4.5.1 | MUST NOT | A client | A client MUST NOT broadcast one statement about a new key to more than one contact. |  |  |
| `IDN-066` | §4.6 | MUST | A client | A client MUST compute `row_tag_i` over the record tag of the live row. |  |  |
| `IDN-067` | §4.6 | MUST NOT | A client | A client MUST NOT compute it over the plaintext of the row. |  |  |
| `IDN-068` | §4.6 | MUST | A client | A client MUST update `accum` incrementally. |  |  |
| `IDN-069` | §4.6 | MUST | A client | A client MUST use the two prefix bytes `0x01` and `0x02` above. |  |  |
| `IDN-070` | §4.7.1 | MUST | A client | A client MUST make `C_user` and `C_social` as two independent CSPRNG outputs. |  |  |
| `IDN-071` | §4.7.1 | MUST | A client | A client MUST derive `BackupRootKey` from the two halves together. |  |  |
| `IDN-072` | §4.7.1 | MUST NOT | A party | A party MUST NOT derive `BackupRootKey` from one half. |  |  |
| `IDN-073` | §4.7.2 | MUST | A relay | A relay MUST hold a backup object for `BACKUP_TTL`. |  |  |
| `IDN-074` | §4.7.2 | MUST | A revision | A revision MUST hold `BACKUP_LOOKBACK` weeks at or above `BACKUP_TTL`. |  |  |
| `IDN-075` | §4.7.2 | MUST | A client | A client MUST divide a backup object into chunks of `CHUNK_SIZE`. |  |  |
| `IDN-076` | §4.7.2 | MUST | A client | A client MUST write each chunk to `BACKUP_REPLICAS` relays under different operators. |  |  |
| `IDN-077` | §4.7.2 | MUST | A client | A client MUST send a backup chunk on the separate connection of Part 13 §13.8. |  |  |
| `IDN-078` | §4.7.2 | MUST | A client | A client MUST write a full backup object at each `BACKUP_FULL_INTERVAL`. |  |  |
| `IDN-079` | §4.7.2 | MUST | A client | A client MUST write a delta object at each `BACKUP_INTERVAL`. |  |  |
| `IDN-080` | §4.7.2 | MUST | A client | A client MUST write a backup in the foreground only. |  |  |
| `IDN-081` | §4.7.2 | MUST | A client | A client MUST draw an independent delay for each backup write, from a uniform distribution over the write interval. |  |  |
| `IDN-082` | §4.7.2 | MUST | A client | A client MUST hold a full backup object no longer than `BACKUP_HISTORY_DAYS` of history. |  |  |
| `IDN-083` | §4.7.3 | MUST | A client | A client MUST put `C_social` in the shares. |  |  |
| `IDN-084` | §4.7.3 | MUST NOT | A client | A client MUST NOT put `C_user` in a share. |  |  |
| `IDN-085` | §4.7.3 | MUST NOT | A client | A client MUST NOT put a value from which a party derives `C_user` in a share. |  |  |
| `IDN-086` | §4.7.3 | MUST NOT | (unstated) | If a client puts `C_user` in a platform-cloud item, that client MUST NOT put a share of `C_social` in that same item. |  |  |
| `IDN-087` | §4.7.3 | MUST | The interface | The interface MUST state that the shares alone do not recover the account. |  |  |
| `IDN-088` | §4.7.3 | MUST | The interface | The interface MUST state which half each share holder receives. |  |  |
| `IDN-089` | §4.5.1 | MUST | The blocking notice of §4.5 | The blocking notice of §4.5 MUST state that acceptance ends the post-compromise healing of Part 5 §5.5 for that contact. |  |  |
| `IDN-090` | §4.5.1 | MUST | That notice | That notice MUST offer an out-of-band verification before the acceptance. |  |  |
| `IDN-091` | §4.5.1 | MUST NOT | The interface | The interface MUST NOT make the acceptance the default action. |  |  |
| `IDN-092` | §4.5.1 | MUST NOT | The interface | The interface MUST NOT let a user accept the notice for more than one contact in one action. |  |  |
| `IDN-093` | §4.7.2 | MUST | A client | A client MUST write the backup root with `chunk_id` of `backup_handle_epoch`, `cred_sk` of `backup_write_cred`, and `read_sk` of `backup_read_cred`. |  |  |
| `IDN-094` | §4.7.2 | MUST | A client | A client MUST seal the root under `backup_key_epoch` as the `sealed` field below. |  |  |
| `IDN-095` | §4.7.2 | MUST | A client | A client MUST write each backup object as a file of Part 13 §13.3 in the backup class. |  |  |
| `IDN-096` | §4.7.2 | MUST | A client | A client MUST use level `0x01` for a backup object above `BACKUP_DESC_REFS` data chunks. |  |  |
| `IDN-097` | §4.7.2 | MUST | A client | A client MUST put the latest full object at entry 0, and then each later delta in write order. |  |  |
| `IDN-098` | §4.7.2 | MUST | A client | A client MUST write the root again after each object write, under Part 13 rule `ATT-138`. |  |  |
| `IDN-099` | §4.7.2 | MUST | (unstated) | After a full write succeeds, a client MUST send `CDEL` for each object that the new root does not name. |  |  |
| `IDN-100` | §4.7.2 | MUST NOT | A client | A client MUST NOT send `CDEL` for the root of an earlier epoch. |  |  |
| `IDN-101` | §4.7.2 | MUST | (unstated) | At a restore, the client MUST fetch the root of the current epoch, and then of each earlier epoch. |  |  |
| `IDN-102` | §4.7.2 | MUST | A client | A client MUST apply the full object of entry 0 and then each delta in entry order. |  |  |
| `IDN-103` | §4.7.2 | MUST | A client | A client MUST reject a root whose `sealed` field does not open, and it MUST treat that epoch as empty. |  |  |
| `IDN-104` | §4.2.4 | MUST | A client | A client MUST publish the public half of `HandleKey_{j,r}` as the `HK_pub` of the handle of `PublicAddressKey_j`. |  |  |
| `IDN-105` | §4.2.4 | MUST NOT | A client | A client MUST NOT publish a public half of `PublicAddressKey_j` as an `HK_pub`. |  |  |
| `IDN-106` | §4.2.4 | MUST | A client | A client MUST increase `r` by one at each rotation of the handle key. |  |  |
| `IDN-107` | §4.2.4 | MUST NOT | A client | A client MUST NOT publish two handle keys with one pair `(j, r)`. |  |  |
| `IDN-108` | §4.2.4 | MUST | A client | A client MUST hold the current `r` of each `j` in the local identity table. |  |  |
| `IDN-109` | §4.2.4 | MUST | (unstated) | After a restore of §4.7.2, a client MUST look up each handle that the restored local identity table names. |  |  |
| `IDN-110` | §4.2.4 | MUST | The client | The client MUST compare the newest `HK_pub` of that entry against the public half of `HandleKey_{j,r}`. |  |  |
| `IDN-111` | §4.2.4 | MUST | The client | The client MUST set `r` to the first value that matches. |  |  |
| `IDN-112` | §4.2.4 | MUST | (unstated) | If no value matches, the client MUST show the handle as lost. |  |  |
| `IDN-113` | §4.2.4 | MUST NOT | (unstated) | If no value matches, the client MUST NOT register the handle again without an explicit confirmation from the user. |  |  |
| `IDN-114` | §4.7.2 | MUST | A client | A client MUST pad the result under Part 13 §13.2.3. |  |  |
| `IDN-115` | §4.7.2 | MUST | A client | A client MUST record the `FileDescriptor` of that file as one `BackupEntry`. |  |  |
| `IDN-116` | §4.7.2 | MUST | The client | The client MUST stop when a root opens under its `backup_key_epoch`, or after `BACKUP_LOOKBACK` epochs. |  |  |
| `IDN-117` | §4.7.2 | MUST | A client | A client MUST write those chunks under the attachment commands of that section, with `BNEW` as the registration. |  |  |
| `IDN-118` | §4.2.4 | MUST | The client | The client MUST try each `r` from the restored counter to that counter plus `HANDLE_KEY_LOOKAHEAD`. |  |  |
| `IDN-119` | §4.7.2 | MUST | A client | A client MUST compute the weekly epoch from the most recent `DirectoryRoot` that it accepted. |  |  |
| `IDN-120` | §4.3.1 | MUST | The landing document | The landing document MUST hold no script. |  |  |
| `IDN-121` | §4.3.1 | MUST NOT | The landing document | The landing document MUST NOT reference a resource on a second host. |  |  |
| `IDN-122` | §4.3.1 | MUST | The invitation host | The invitation host MUST serve `/.well-known/assetlinks.json` and `/.well-known/apple-app-site-association`. |  |  |
| `IDN-123` | §4.3.1 | MUST | A client | A client MUST register the link as an Android App Link and as an iOS Universal Link. |  |  |
| `IDN-124` | §4.3.1 | MUST NOT | A client | A client MUST NOT open the landing document. |  |  |
| `IDN-125` | §4.3.1 | MUST NOT | A client | A client MUST NOT put the fragment in a request to any host. |  |  |
| `IDN-126` | §4.3.1 | MUST | A relay | A relay MUST delete a blob that no party fetched within `INVITE_TTL`. |  |  |
| `IDN-127` | §4.3.1 | MUST | A client | A client MUST treat an invitation as deleted at `INVITE_TTL` after the issue. |  |  |
| `IDN-128` | §4.3.1 | MUST | A client | A client MUST show the remaining lifetime beside an invitation that no party consumed. |  |  |
| `IDN-129` | §4.3.2 | MUST | A reusable link | A reusable link MUST carry the address of §4.2.3 and no other value. |  |  |
| `IDN-130` | §4.3.3 | MUST | A client | A client MUST accept a pasted `umbra:pub:` string and a link of §4.3.2 as the start of a contact request. |  |  |
| `IDN-131` | §4.3.3 | MUST | (unstated) | Before the client sends the hello of Part 9 §9.6, it MUST check that `SHA3-256(address_pk)[0..20]` equals the address. |  |  |
| `IDN-132` | §4.3.3 | MUST | The client | The client MUST look that address up under Part 9 §9.3.3. |  |  |
| `IDN-140` | §4.5.2 | MUST | The verification screen | The verification screen MUST offer the QR scan of the safety number first. |  |  |
| `IDN-141` | §4.5.2 | MUST | The manual ceremony | The manual ceremony MUST be the short code below. |  |  |
| `IDN-142` | §4.5.2 | MUST | A client | A client MUST send `VerifyCommit` before it holds the nonce of the peer. |  |  |
| `IDN-143` | §4.5.2 | MUST NOT | A client | A client MUST NOT send `VerifyReveal` before it holds the `VerifyCommit` of the peer. |  |  |
| `IDN-144` | §4.5.2 | MUST | A client | A client MUST reject a `VerifyReveal` whose hash under the label differs from the commit that it holds. |  |  |
| `IDN-145` | §4.5.2 | MUST | A client | A client MUST draw a fresh nonce for each ceremony. |  |  |
| `IDN-146` | §4.5.2 | MUST NOT | A client | A client MUST NOT show a code from an earlier ceremony. |  |  |
| `IDN-147` | §4.5.2 | MUST | A client | A client MUST set the verification state of §4.5 at a user confirmation that the two codes match. |  |  |
| `IDN-148` | §4.5.2 | MUST NOT | A client | A client MUST NOT set that state from the exchange alone. |  |  |
| `IDN-149` | §4.7.7 | MUST | A client | A client MUST export each of the three secrets as `RecoveryDigits` in decimal, in groups of five digits. |  |  |
| `IDN-150` | §4.7.7 | MUST NOT | A client | A client MUST NOT export any of the three as a word list. |  |  |
| `IDN-151` | §4.7.7 | MUST | A client | A client MUST verify `check` before it uses an entered secret. |  |  |
| `IDN-152` | §4.7.7 | MUST | (unstated) | If `check` fails, the client MUST say so and MUST NOT run the KDF. |  |  |
| `IDN-153` | §4.7.7 | MUST | (unstated) | If `type` differs from the type that the screen asks for, the client MUST name the type that the user entered and the type that the screen asks for. |  |  |
| `IDN-154` | §4.7.7 | MUST NOT | A client | A client MUST NOT use a payload of a type other than the one that the screen asks for. |  |  |
| `IDN-155` | §4.7.7 | MUST | (unstated) | If a restore yields an empty local identity table, the client MUST show a blocking screen that states that the restore recovered no identity. |  |  |
| `IDN-156` | §4.7.7 | MUST | That screen | That screen MUST offer the three recovery paths of §4.7 and no message list. |  |  |
| `IDN-157` | §4.2.3 | MUST | A client | A client MUST encode the 20 bytes in the Crockford base32 alphabet `0123456789abcdefghjkmnpqrstvwxyz`, in lower case, with no padding, and with the spare low bits of the last character at zero. |  |  |
| `IDN-158` | §4.2.3 | MUST | A client that reads an address | A client that reads an address MUST fold upper case to lower case, and it MUST read `o` as `0` and `i` and `l` as `1`, as that alphabet permits. |  |  |
| `IDN-159` | §4.3.1 | MUST | A client | A client MUST write the fragment after `#` as the 68 bytes above in base64url with no padding. |  |  |
| `IDN-160` | §4.3.1 | MUST | A client | A client MUST seal the bundle in the layout above, with the 192-bit link ID as the associated data, thus a blob moved under a second link ID fails to open. |  |  |
| `IDN-161` | §4.3.1 | MUST | A client | A client MUST reject a blob whose `version` is not `0x01` or whose `sealed` field does not open under the key of the fragment. |  |  |
| `IDN-162` | §4.6 | MUST | After the unlock, a client | After the unlock, a client MUST compute `accum` and `row_count` of each table from a scan of its rows, outside the unlock path, one time or more in each 24 hours that the store is open. |  |  |
| `IDN-163` | §4.6 | MUST | A client | A client MUST report a difference in the manner of `IDN-039`. |  |  |
| `IDN-164` | §4.3.1 | MUST NOT | (unstated) | A client MUST draw the 256 bits of key material of the fragment from the device CSPRNG, and it MUST NOT give them to a relay. |  |  |
| `IDN-165` | §4.3.1 | MUST | A client | A client MUST give the link to the user after the relay answered the `IPUT`, and not before. |  |  |
| `IDN-166` | §4.3.1 | MUST | A client that accepts a link | A client that accepts a link MUST write to the queue of the bundle under its lock key, and not under the `QS_auth` of the bundle. |  |  |
| `IDN-167` | §4.3.1 | MUST | (unstated) | A client whose `IGET` gets a `NACK`, or whose blob does not open under the fragment, MUST tell the user that the link gives no invitation. |  |  |
| `IDN-168` | §4.3.1 | MUST | A client | A client MUST resolve the `RelayRef` of the fragment before the `IGET`, and it MUST send the `IGET` on a circuit whose last hop is that relay. |  |  |
| `IDN-169` | §4.3.1 | MUST | The store of an inviter | The store of an inviter MUST hold the fragment of an invitation that waits, thus the client shows the link again after a restart. |  |  |
| `IDN-170` | §4.5.2 | MUST | A client that gets a start | A client that gets a start MUST end the ceremony that it holds, draw a fresh nonce, and send an answer that names that start. |  |  |
| `IDN-171` | §4.5.2 | MUST | A client | A client MUST take an answer only while it holds a start of its own with no commit of the peer, and only when `answers` is equal to the commit of that start. |  |  |
| `IDN-172` | §4.5.2 | MUST | A client that gets a start while its own start has no answer | A client that gets a start while its own start has no answer MUST compare the two commits as byte strings. |  |  |
| `IDN-173` | §4.5.2 | MUST NOT | A `VerifyReveal` that `IDN-144` rejects | A `VerifyReveal` that `IDN-144` rejects MUST NOT end the ceremony. |  |  |
| `IDN-174` | §4.5.2 | MUST NOT | A ceremony | A ceremony MUST NOT continue after the run of the client that holds it. |  |  |
| `IDN-175` | §4.5 | MUST | A client | A client MUST keep the verification state as the pairwise identity public key of the contact that the user verified. |  |  |
| `IDN-176` | §4.5 | MUST | (unstated) | A scan or an entry of a safety number that is equal to the number of the device, by its digits alone, MUST set the same state as a confirmed short code. |  |  |

## CRY — Cryptographic Core

Source: `spec/05-cryptographic-core.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `CRY-001` | §5.1 | MUST | (unstated) | A proposal to add a seventh primitive to the message core MUST give its cause against this list. |  |  |
| `CRY-002` | §5.1 | MUST | Those primitives | Those primitives MUST be in isolated crates or in platform adapters. |  |  |
| `CRY-003` | §5.1 | MUST NOT | Those primitives | Those primitives MUST NOT protect ordinary message content. |  |  |
| `CRY-004` | §5.1 | MUST NOT | Those primitives | Those primitives MUST NOT be on the path of a send on a pairwise channel that exists. |  |  |
| `CRY-005` | §5.1 | MUST NOT | An implementation | An implementation MUST NOT use a cryptographic primitive that this section does not list. |  |  |
| `CRY-006` | §5.1.1 | MUST | A future KEM substitution | A future KEM substitution MUST verify the anonymity and the robustness again, and not only IND-CCA. |  |  |
| `CRY-007` | §5.2 | MUST NOT | A device | A device MUST NOT derive a queue key from a long-term secret. |  |  |
| `CRY-008` | §5.3.2 | MUST NOT | Implementations | Implementations MUST NOT concatenate shared secrets and give them to an AEAD or to a raw hash without domain separation. |  |  |
| `CRY-009` | §5.4.2 | MUST | Implementations | Implementations MUST bind each transmitted field and the two AEAD flight tags into the transcript KDF. |  |  |
| `CRY-010` | §5.4.5 | MUST NOT | A client | A client MUST NOT use one one-time prekey in a second invitation. |  |  |
| `CRY-011` | §5.4.5 | MUST | That resolution | That resolution MUST be constant-time with respect to the position of the prekey in the set of outstanding prekeys. |  |  |
| `CRY-012` | §5.4.6 | MUST NOT | Implementations | Implementations MUST NOT use a timestamp for replay protection. |  |  |
| `CRY-013` | §5.4.6 | MUST NOT | (unstated) | Before that step, a 0-RTT payload MUST NOT make the final session state. |  |  |
| `CRY-014` | §5.4.7 | MUST | Implementations | Implementations MUST reject an all-zero X25519 output. |  |  |
| `CRY-015` | §5.4.7 | MUST NOT | UMBRA | UMBRA MUST NOT derive an AEAD key from static-static material alone. |  |  |
| `CRY-016` | §5.4.7 | MUST | A client | A client MUST put an ephemeral contribution from the two parties in each key derivation. |  |  |
| `CRY-017` | §5.5.1 | MUST | A client | A client MUST use the header-encrypted variant of the Double Ratchet. |  |  |
| `CRY-018` | §5.5.2 | MUST | A client | A client MUST select the chunk width so that the record fits the smallest bucket that holds the message. |  |  |
| `CRY-019` | §5.5.2 | MUST | (unstated) | If no permitted width gives a fit, the client MUST send the record with `pq_frame_len = 0`. |  |  |
| `CRY-020` | §5.5.2 | MUST | The client | The client MUST then send the chunk on a later record. |  |  |
| `CRY-021` | §5.5.2 | MUST NOT | UMBRA | UMBRA MUST NOT use the retransmit-until-acknowledged strategy of Apple PQ3. |  |  |
| `CRY-022` | §5.5.2 | MUST NOT | UMBRA | UMBRA MUST NOT make future KEM keypairs in advance. |  |  |
| `CRY-023` | §5.5.4 | MUST | An implementation | An implementation MUST store the skipped keys encrypted at rest under `K_store`. |  |  |
| `CRY-024` | §5.8 | MUST | Group content and community content | Group content and community content MUST have post-quantum protection in transit. At rest, `K_store` of §5.2 covers each record, and a community post is public at publication. |  |  |
| `CRY-025` | §5.9 | MUST | Implementations | Implementations MUST implement RFC 8937 randomness hardening unconditionally, with the construction of §5.9. |  |  |
| `CRY-026` | §5.9 | MUST | Implementations | Implementations MUST enforce one encapsulation for each ephemeral key **at the type level**. |  |  |
| `CRY-027` | §5.11 | MUST | (unstated) | Each KDF invocation and each signature MUST carry a label prefix. |  |  |
| `CRY-028` | §5.11 | MUST NOT | An implementation | An implementation MUST NOT use a label that this list does not hold. |  |  |
| `CRY-029` | §5.11 | MUST | (unstated) | A revision that needs a new label MUST add that label to this list. |  |  |
| `CRY-030` | §5.11 | MUST | That revision | That revision MUST give the cause. |  |  |
| `CRY-031` | §5.11 | MUST NOT | Two object types | Two object types MUST NOT share one label. |  |  |
| `CRY-032` | §5.11 | MUST NOT | (unstated) | The labels `"umbra/v1/community-pseudonym"` and `"umbra/v1/group-roster"` are not used, and an implementation MUST NOT add them. |  |  |
| `CRY-033` | §5.11 | MUST | Implementations | Implementations MUST bind the **full handshake transcript** into the KDF. |  |  |
| `CRY-034` | §5.3 | MUST | An implementation | An implementation MUST encode `pk_X` and `pub_X` as the 32-byte little-endian u-coordinate of RFC 7748. |  |  |
| `CRY-035` | §5.3 | MUST | An implementation | An implementation MUST encode `pk_M`, `sk_M`, and `ct_M` in the byte encoding of FIPS 203. |  |  |
| `CRY-036` | §5.3 | MUST | An implementation | An implementation MUST concatenate in the order that the two algorithms above give. |  |  |
| `CRY-037` | §5.3 | MUST NOT | An implementation | An implementation MUST NOT change either order. |  |  |
| `CRY-038` | §5.3 | MUST NOT | An implementation | An implementation MUST NOT rebuild `pk_M` from `sk_M` at each decapsulation, because that step is not constant-time in each ML-KEM implementation. |  |  |
| `CRY-039` | §5.3 | MUST | An implementation | An implementation MUST store `pk` beside `sk`. |  |  |
| `CRY-040` | §5.3 | MUST | `Decap` | `Decap` MUST abort on an all-zero `ss_X`, and §5.4.7 gives the cause. |  |  |
| `CRY-041` | §5.3 | MUST | `MLKEM768.Decap` | `MLKEM768.Decap` MUST use the implicit rejection of FIPS 203, thus a malformed `ct_M` gives a pseudorandom `ss_M` and it does not give an error. |  |  |
| `CRY-042` | §5.3 | MUST | An implementation | An implementation MUST give one error value for each failure of `Decap`. |  |  |
| `CRY-043` | §5.3 | MUST | An implementation | An implementation MUST perform the re-encapsulation check of §5.12. |  |  |
| `CRY-044` | §5.3 | MUST | `Encap` and `Decap` | `Encap` and `Decap` MUST give the same `ss` for one `(pk, sk)` pair and one `ct`. |  |  |
| `CRY-045` | §5.3 | MUST | (unstated) | The test vectors of Part 6 §6.8 MUST hold that equality. |  |  |
| `CRY-046` | §5.3 | MUST | Those test vectors | Those test vectors MUST hold a negative vector for an all-zero `pub_X`. |  |  |
| `CRY-047` | §5.4.2 | MUST | A revision | A revision MUST make the three flight rows and the sum agree. |  |  |
| `CRY-048` | §5.4.8 | MUST | An implementation | An implementation MUST follow this section step by step. |  |  |
| `CRY-049` | §5.4.8 | MUST | An implementation | An implementation MUST encode the ChaCha20-Poly1305 nonce as four zero bytes and then `n` in big-endian order, which gives 12 bytes. |  |  |
| `CRY-050` | §5.4.8 | MUST | An implementation | An implementation MUST set `n` to 0 at each `MixKey`. |  |  |
| `CRY-051` | §5.4.8 | MUST | An implementation | An implementation MUST abort if `n` reaches 2⁶⁴ −. |  |  |
| `CRY-052` | §5.4.8 | MUST | An implementation | An implementation MUST `MixHash` a ciphertext after the tag check and not before it. |  |  |
| `CRY-053` | §5.4.8 | MUST | An implementation | An implementation MUST use `h` as the associated data of each `Seal` and each `Open`. |  |  |
| `CRY-054` | §5.4.8 | MUST NOT | A responder | A responder MUST NOT make the final session state from `payload1`. |  |  |
| `CRY-055` | §5.4.8 | MUST | A responder | A responder MUST resolve `pid` against its outstanding prekeys before it runs `MixHash(s1)`. |  |  |
| `CRY-056` | §5.4.8 | MUST | That resolution | That resolution MUST be constant-time with respect to the prekey position, and CRY-011 states that rule. |  |  |
| `CRY-057` | §5.4.8 | MUST | An initiator | An initiator MUST check that the `n_hs` of flight 2 equals the `n_hs` that it sent. |  |  |
| `CRY-058` | §5.4.8 | MUST | An initiator | An initiator MUST abort if the two values differ. |  |  |
| `CRY-059` | §5.4.8 | MUST | An implementation | An implementation MUST erase `ck`, `h`, `k`, and each ephemeral private key after the split. |  |  |
| `CRY-060` | §5.4.8 | MUST | (unstated) | The test vectors of Part 6 §6.8 MUST hold one complete handshake transcript. |  |  |
| `CRY-061` | §5.4.8 | MUST | That vector | That vector MUST give `ck`, `h`, and `n` after each numbered step. |  |  |
| `CRY-062` | §5.4.8 | MUST | That vector | That vector MUST give `RK`, `HK_i2r`, and `HK_r2i`. |  |  |
| `CRY-063` | §5.5.1 | MUST | An implementation | An implementation MUST use the labels above. |  |  |
| `CRY-064` | §5.5.2 | MUST | An implementation | An implementation MUST use the label `"umbra/v1/pq-epoch"` for that step. |  |  |
| `CRY-065` | §5.5.2 | MUST NOT | An implementation | An implementation MUST NOT apply that step before it rebuilt the full ML-KEM material from the chunks. |  |  |
| `CRY-066` | §5.11 | MUST NOT | (unstated) | A group signature MUST use `"umbra/v1/group-grant"` or `"umbra/v1/group-moderation"`, and it MUST NOT use a label that names a seed. |  |  |
| `CRY-067` | §5.5.2 | MUST | An implementation | An implementation MUST use GF(2¹⁶) with the primitive polynomial `p(x) = x¹⁶ + x¹² + x³ + x + 1`, which is `0x1100B`. |  |  |
| `CRY-068` | §5.5.2 | MUST | An implementation | An implementation MUST use `0x0002` as the generator element. |  |  |
| `CRY-069` | §5.5.2 | MUST | An implementation | An implementation MUST read a field symbol as two bytes in big-endian order. |  |  |
| `CRY-070` | §5.5.2 | MUST | An implementation | An implementation MUST use a chunk width that is a whole number of symbols. |  |  |
| `CRY-071` | §5.5.2 | MUST | An implementation | An implementation MUST place the *k* data chunks first and in order, because the code is systematic. |  |  |
| `CRY-072` | §5.5.2 | MUST | An implementation | An implementation MUST encode each symbol position across the chunks, and it MUST NOT encode along one chunk. |  |  |
| `CRY-073` | §5.5.2 | MUST | An implementation | An implementation MUST use a Vandermonde generator matrix in systematic form. |  |  |
| `CRY-074` | §5.5.2 | MUST | An implementation | An implementation MUST build one codeword over the concatenation `header \|\| ek_vector \|\| ct1 \|\| ct2`, in that order. |  |  |
| `CRY-075` | §5.5.2 | MUST | Two implementations | Two implementations MUST produce byte-identical chunks for one material and one schedule. |  |  |
| `CRY-076` | §5.5.2 | MUST NOT | An implementation | An implementation MUST NOT code a part alone. |  |  |
| `CRY-077` | §5.5.2 | MUST | An implementation | An implementation MUST set the data chunk count *k* to 2 304 divided by the width *w*. |  |  |
| `CRY-078` | §5.5.2 | MUST | An implementation | An implementation MUST set the parity chunk count *r* to *k* divided by 8, rounded up. |  |  |
| `CRY-079` | §5.5.2 | MUST | A receiver | A receiver MUST rebuild the material when any *k* chunks of the *n* arrive. |  |  |
| `CRY-080` | §5.5.2 | MUST NOT | A receiver | A receiver MUST NOT wait for a chunk of a specific index. |  |  |
| `CRY-081` | §5.5.2 | MUST | A sender | A sender MUST set the `index` field of Part 6 §6.5 to the position of the chunk in the codeword, and that position counts from zero. |  |  |
| `CRY-082` | §5.5.2 | MUST | A sender | A sender MUST set `kind` of a data chunk to the part that holds the first byte of that chunk. |  |  |
| `CRY-083` | §5.5.2 | MUST | The test suite | The test suite MUST hold a vector for each of the three widths, and each vector MUST hold a loss pattern that drops *r* chunks. |  |  |
| `CRY-084` | §5.4.8 | MUST | An initiator | An initiator MUST set `pid` to the first 16 bytes of `SHA3-256( "umbra/v1/prekey-id" \|\| s1 )`, where `s1` is the 1 184-byte one-time prekey of §5.4.1. |  |  |
| `CRY-085` | §5.4.8 | MUST | A responder | A responder MUST select the one-time prekey that `pid` names. |  |  |
| `CRY-086` | §5.4.8 | MUST | A responder | A responder MUST abort when `pid` names no prekey that it holds. |  |  |
| `CRY-087` | §5.4.8 | MUST | A responder | A responder MUST abort when `pid` names a prekey that it consumed. |  |  |
| `CRY-088` | §5.4.8 | MUST NOT | A responder | A responder MUST NOT run more than one `MLKEM768.Decap` for one flight 1. |  |  |
| `CRY-089` | §5.4.5 | MUST | A responder | A responder MUST erase the private half of a one-time prekey when it consumes that prekey. |  |  |
| `CRY-091` | §5.5.2 | MUST | A receiver that rebuilt the material | A receiver that rebuilt the material MUST compare `SHA3-256(ek_vector \|\| rho)` against the hash in `header`. |  |  |
| `CRY-092` | §5.5.2 | MUST | That receiver | That receiver MUST reject the braid epoch when the two values differ. |  |  |
| `CRY-093` | §5.5.2 | MUST | A sender | A sender MUST make the seed `d` of its encapsulation key with the randomness function of §5.9. |  |  |
| `CRY-097` | §5.5.2 | MAY | A receiver | A receiver MAY discard a later chunk of a position that it holds. |  |  |
| `CRY-098` | §5.5.4 | MUST NOT | `SKIP_TTL` | `SKIP_TTL` MUST NOT be below the `MSG_TTL` of Part 3 §3.2.4. |  |  |
| `CRY-099` | §5.5.4 | MUST | A revision | A revision MUST hold the two values equal, and a revision MUST NOT raise `MSG_TTL` alone. |  |  |
| `CRY-100` | §5.4.8 | MUST | A responder | A responder MUST fill `range_i` of the prologue from the first two bytes of flight 1. |  |  |
| `CRY-101` | §5.4.8 | MUST | A responder | A responder MUST read those two bytes before it runs `MixHash(prologue)`. |  |  |
| `CRY-102` | §5.4.8 | MUST | A responder | A responder MUST apply Part 6 §6.7 rule `WIR-092` to `range_i` and `range_r` before it runs `MixHash(prologue)`. |  |  |
| `CRY-103` | §5.4.8 | MUST | Those vectors | Those vectors MUST hold a second transcript in which `range_i` is (1, 1) and `range_r` is (1, 2). |  |  |
| `CRY-104` | §5.4.8 | MUST | That vector | That vector MUST assert one `h` at the two parties after flight 1. |  |  |
| `CRY-105` | §5.4.9 | MUST | A revision | A revision MUST make the two flight rows and the sum agree. |  |  |
| `CRY-106` | §5.4.9 | MUST | An implementation | An implementation MUST apply rules `CRY-049` to `CRY-053` to this handshake. |  |  |
| `CRY-107` | §5.4.9 | MUST | A revision that adds a second suite | A revision that adds a second suite MUST add a range field to flight 1 and to the prologue. |  |  |
| `CRY-108` | §5.4.9 | MUST | A client | A client MUST take `s` and `relay_id` from one `RelayDescriptor` that passed Part 10 rules `REL-051` and `REL-057`. |  |  |
| `CRY-109` | §5.4.9 | MUST | A relay | A relay MUST abort when `tag1` does not verify. |  |  |
| `CRY-110` | §5.4.9 | MUST | A client | A client MUST abort when `tag2` does not verify. |  |  |
| `CRY-111` | §5.4.9 | MUST NOT | A party that aborts | A party that aborts MUST NOT send a later flight of that handshake. |  |  |
| `CRY-112` | §5.4.9 | MUST NOT | A flight of this handshake | A flight of this handshake MUST NOT carry a payload. |  |  |
| `CRY-113` | §5.4.9 | MUST | A party | A party MUST derive the hop key material from `ss_hop` of the split and from no other value. |  |  |
| `CRY-114` | §5.4.9 | MUST | An implementation | An implementation MUST erase `ck`, `h`, `k`, `e_sk`, `e1_sk`, and `er_sk` after the split. |  |  |
| `CRY-115` | §5.4.9 | MUST | A relay | A relay MUST accept flight 1 under each `ntor_pk` that a valid consensus lists for that relay. |  |  |
| `CRY-116` | §5.4.9 | MUST | The test vectors of Part 6 §6.8 | The test vectors of Part 6 §6.8 MUST hold one complete `UMBRA-NKhfs` transcript. |  |  |
| `CRY-117` | §5.4.9 | MUST | That vector | That vector MUST give `ck`, `h`, and `n` after each numbered step, and it MUST give `ss_hop`. |  |  |
| `CRY-118` | §5.2 | MUST | An implementation | An implementation MUST derive each key of the diagram with the `Expand` function and the `Hybrid` function above. |  |  |
| `CRY-119` | §5.2 | MUST | An implementation | An implementation MUST take the X25519 scalar from `t[0..32]`, `d` from `t[32..64]`, and `z` from `t[64..96]`. |  |  |
| `CRY-120` | §5.2 | MUST | An implementation | An implementation MUST clamp the X25519 scalar as RFC 7748 §5 states, before the first use. |  |  |
| `CRY-121` | §5.2 | MUST | The test vectors of Part 6 §6.8 | The test vectors of Part 6 §6.8 MUST hold one key-hierarchy vector from one fixed `RootIdentity`. |  |  |
| `CRY-122` | §5.4.5 | MUST | A client | A client MUST make a fresh one-time prekey for each invitation that it issues. |  |  |
| `CRY-123` | §5.4.5 | MUST | The responder | If the user deletes an invitation that no party consumed, the responder MUST erase the private half of its prekey. |  |  |
| `CRY-124` | §5.4.8 | MUST | An initiator | An initiator MUST write `0x01` in the `mode` byte of flight 1. |  |  |
| `CRY-125` | §5.4.8 | MUST | A responder | A responder MUST fill `handshake_mode` of the prologue from the third byte of flight 1. |  |  |
| `CRY-126` | §5.4.8 | MUST | A responder | A responder MUST abort when that byte holds a value that this section does not define. |  |  |
| `CRY-127` | §5.4.8 | MUST | Those vectors | Those vectors MUST hold a flight 1 whose `mode` byte is `0x02`, and the responder aborts before `MixHash(prologue)`. |  |  |
| `CRY-128` | §5.5.2 | MUST NOT | A sender | A sender MUST NOT put `d`, `z`, or the decapsulation key in a field of the codeword. |  |  |
| `CRY-129` | §5.5.2 | MUST | A sender | A sender MUST set `kind` of a chunk at index *k* or above to the parity value. |  |  |
| `CRY-130` | §5.5.3 | MUST | A sender | A sender MUST carry one chunk of its incomplete epoch on each `RatchetRecord`, except where CRY-019 applies. |  |  |
| `CRY-131` | §5.5.3 | MUST | A sender | After the chunk at index *n* − 1, a sender MUST continue with the chunk at index 0. |  |  |
| `CRY-132` | §5.5.3 | MUST NOT | A client | A client MUST NOT start a new epoch while an epoch of its own is incomplete. |  |  |
| `CRY-134` | §5.5.3 | MUST | The test vectors of Part 6 §6.8 | The test vectors of Part 6 §6.8 MUST hold a schedule in which `T` occurs during an incomplete epoch. |  |  |
| `CRY-135` | §5.4.8 | MUST | A party | A party MUST put that byte in the prologue, and it MUST abort a handshake whose peer holds the other value, because the two prologues then differ and each flight tag fails. |  |  |
| `CRY-136` | §5.4.8 | MUST | The responder | The responder MUST keep `er_sk` as its first DH ratchet private key until the first DH ratchet step of §5.5.1 replaces it, and it MUST erase it at that step. |  |  |
| `CRY-137` | §5.4.8 | MUST | The initiator | The initiator MUST use `er` as the ratchet public key of the responder at the start of the session. |  |  |
| `CRY-138` | §5.5.2 | MUST | A sender | A sender MUST make the ciphertext of an epoch against the encapsulation key that §5.5.5 names for that epoch, and against no other key. |  |  |
| `CRY-139` | §5.5.2 | MUST | An implementation | An implementation MUST take the evaluation points `x_i = g^i` for `i` in `0..n`, where `g` is the generator element of `CRY-068`, build `V[i][j] = x_i^j`, and use `G = V · (V[0..k])⁻¹`. |  |  |
| `CRY-140` | §5.5.3 | MUST | If a limit occurs during an incomplete epoch, the client | If a limit occurs during an incomplete epoch, the client MUST start the next epoch at the first DH chain start of §5.5.1 after the epoch is complete. |  |  |
| `CRY-141` | §5.5.5 | MUST | The initiator's epoch `e` | The initiator's epoch `e` MUST encapsulate to the responder's key of epoch `e − 1`. |  |  |
| `CRY-142` | §5.5.5 | MUST | The responder's epoch `e` | The responder's epoch `e` MUST encapsulate to the initiator's key of epoch `e`. |  |  |
| `CRY-143` | §5.5.5 | MUST | The initiator's epoch 1 | The initiator's epoch 1 MUST carry 1 088 zero bytes in the place of `ct1 || ct2`, because no responder key exists yet. |  |  |
| `CRY-144` | §5.5.5 | MUST | The responder | The responder MUST start its epoch 1 at the first chain start after it rebuilt the initiator's epoch 1, and it MUST carry no braid frame before that. |  |  |
| `CRY-145` | §5.5.5 | MUST | A party | A party MUST start an epoch at the first record of a DH sending chain and at no other record. |  |  |
| `CRY-146` | §5.5.5 | MUST | The first record of a chain | The first record of a chain MUST carry a braid frame; rule `CRY-019` does not apply to that record, and a client selects a bucket that holds the frame. |  |  |
| `CRY-147` | §5.5.5 | MUST | P | P MUST apply the mix of `CRY-064` for epoch `e` immediately before it derives the sending chain of its first DH ratchet step whose chain carries an epoch above `e`. |  |  |
| `CRY-148` | §5.5.5 | MUST | The peer | The peer MUST apply the same mix immediately before it derives the receiving chain of the step that the same chain starts, which it recognizes by the epoch number in the frame of any record of that chain. |  |  |
| `CRY-149` | §5.5.5 | MUST | A party | A party MUST retain `ss_e` from the moment it computes it, by encapsulation or by decapsulation, until the mix consumes it. |  |  |
| `CRY-150` | §5.4.1 | MUST | A client | A client MUST write the five fields in the order above, with `bundle_len` before `relay_bundle`, and a reader MUST reject a bundle with bytes after `relay_bundle`. |  |  |
| `CRY-151` | §5.4.1 | MUST | An HPKE of AUX-6 | An HPKE of AUX-6 MUST build its `suite_id` as `"HPKE" || kem_id || kdf_id || aead_id` from the identifiers of §5.4, which are `0x0001` each, and it MUST use `UMBRA-KEM` as the KEM with `Nsecret` of 32, `Nenc` of 1 120, and `Npk` of 1 216, HKDF-SHA3-256 as the KDF, and ChaCha20-Poly1305 as the AEAD, with the labeled extract and expand of RFC 9180 §4 unchanged. |  |  |
| `CRY-152` | §5.4.8 | MUST | (unstated) | The relay handshake of §5.4.9 has one exception of the same kind: the last hop of a circuit MUST keep its `er_sk` as `RelaySession_sk` under Part 3 rule `NET-285`, and it MUST erase it when the circuit ends. |  |  |

## WIR — Wire Format

Source: `spec/06-wire-format.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `WIR-001` | §6.1.1 | MUST | A parser | A parser MUST reject an encoding that is not the unique canonical form. |  |  |
| `WIR-002` | §6.1.1 | MUST | A parser | A parser MUST reject a non-minimal length, trailing bytes, and a set reserved bit. |  |  |
| `WIR-003` | §6.1.1 | MUST | A parser | A parser MUST reject padding that does not match the specified pattern. |  |  |
| `WIR-004` | §6.1.1 | MUST NOT | A party | A party MUST NOT use ciphertext bytes or signature bytes for one of three functions. |  |  |
| `WIR-005` | §6.1.1 | MUST NOT | A party | A party MUST NOT use a value that comes from those bytes for one of those three functions. |  |  |
| `WIR-006` | §6.1.1 | MUST | A parser | A parser MUST be total. |  |  |
| `WIR-007` | §6.1.1 | MAY | A part outside Part 6 | A part outside Part 6 MAY declare a namespace of its own. |  |  |
| `WIR-008` | §6.1.1 | MUST | A parser | A parser MUST read a byte value in the namespace of its own layer only. |  |  |
| `WIR-009` | §6.1.1 | MUST | An implementation | An implementation MUST give each namespace a separate type. |  |  |
| `WIR-010` | §6.1.1 | MUST NOT | An implementation | An implementation MUST NOT convert one type into another. |  |  |
| `WIR-011` | §6.3 | MUST | The padding in `body` | The padding in `body` MUST be zero bytes after one marker byte of `0x80`. |  |  |
| `WIR-012` | §6.3 | MUST | A receiver | A receiver MUST verify the padding pattern. |  |  |
| `WIR-013` | §6.3 | MUST | A receiver | A receiver MUST reject malformed padding. |  |  |
| `WIR-014` | §6.4 | MUST NOT | A party | A party MUST NOT compute `auth` as an AEAD ciphertext. |  |  |
| `WIR-015` | §6.4 | MUST | `COVER` | `COVER` MUST be bit-indistinguishable from a real command after the L4 encryption. |  |  |
| `WIR-016` | §6.4.1 | MUST | A client | A client MUST pack each command that is ready together into one cell, up to the command area of the bucket. |  |  |
| `WIR-017` | §6.4.2 | MUST | A party | A party MUST key the record with `K_QE`. |  |  |
| `WIR-018` | §6.4.2 | MUST | A party | A party MUST use ChaCha20-Poly1305 with a 12-byte nonce and a 16-byte tag. |  |  |
| `WIR-019` | §6.4.2 | MUST | A sender | A sender MUST draw `nonce` from the device CSPRNG for each record. |  |  |
| `WIR-020` | §6.4.2 | MUST NOT | A sender | A sender MUST NOT use a counter. |  |  |
| `WIR-021` | §6.4.2 | MUST NOT | A sender | A sender MUST NOT repeat a nonce under one `K_QE`. |  |  |
| `WIR-022` | §6.4.2 | MUST | A party | A party MUST bind `version \|\| SenderId` as the associated data. |  |  |
| `WIR-023` | §6.4.2 | MUST | A receiver | A receiver MUST reject an unknown kind. |  |  |
| `WIR-024` | §6.4.2 | MUST | A sender | A sender MUST fill the L6 record to a fixed length for the bucket. |  |  |
| `WIR-025` | §6.4.2 | MUST | (unstated) | Thus the `payload_len` of a `SEND` MUST equal that row. |  |  |
| `WIR-026` | §6.4.2 | MUST | The `payload_len` of a `MSG` | The `payload_len` of a `MSG` MUST equal the L5 payload row of §6.9. |  |  |
| `WIR-027` | §6.4.2 | MUST | A receiver | A receiver MUST take the true length from the `u16` inside the ciphertext. |  |  |
| `WIR-028` | §6.4.2 | MUST | A sender | A sender MUST fill the remainder with zero bytes inside the ciphertext. |  |  |
| `WIR-029` | §6.4.2 | MUST NOT | A relay | A relay MUST NOT move the message to a different bucket at that step. |  |  |
| `WIR-030` | §6.4.2 | MUST | A receiver | A receiver MUST reject a record with an unknown version. |  |  |
| `WIR-031` | §6.4.2 | MUST | A receiver | A receiver MUST reject a record whose tag does not verify. |  |  |
| `WIR-032` | §6.4.2 | MUST NOT | A receiver | A receiver MUST NOT report which check failed. |  |  |
| `WIR-033` | §6.4.2 | MUST | A sender | A sender MUST make a new queue before the message count of that queue reaches `ROTATE_AFTER` (Part 3 §3.2.4). |  |  |
| `WIR-039` | §6.4.3 | MUST | On a `DEL`, a relay | On a `DEL`, a relay MUST erase the queue record and each stored ciphertext. |  |  |
| `WIR-040` | §6.4.3 | MUST | A relay | A relay MUST also erase the sequence counter and the link between the `RecipientId` and the `SenderId`. |  |  |
| `WIR-041` | §6.4.3 | MUST NOT | A relay | A relay MUST NOT retain an identifier of a deleted queue. |  |  |
| `WIR-042` | §6.4.3 | MUST NOT | A relay | A relay MUST NOT keep a record that a queue existed. |  |  |
| `WIR-043` | §6.4.3 | MUST | (unstated) | At the end of a queue rotation, a client MUST send `DEL` to the old relay (Part 3 §3.2.4). |  |  |
| `WIR-044` | §6.4.3 | MUST | A client | A client MUST send each `DEL` at an independent delay with the rotation jitter of Part 3 §3.2.4. |  |  |
| `WIR-045` | §6.4.3 | MUST NOT | A client | A client MUST NOT send more than one `DEL` in one transport session. |  |  |
| `WIR-046` | §6.4.3 | MUST NOT | A client | A client MUST NOT send `DEL` at a device revocation. |  |  |
| `WIR-047` | §6.4.3 | MUST NOT | A relay | A relay MUST NOT derive the sequence number from the ciphertext, because §6.1.1 rule 5 forbids that derivation. |  |  |
| `WIR-048` | §6.4.3 | MUST | A relay | A relay MUST then delete each message on that queue with a sequence number at or below `s`. |  |  |
| `WIR-049` | §6.4.3 | MUST NOT | A relay | A relay MUST NOT forward an `ACK` to the sender. |  |  |
| `WIR-050` | §6.4.3 | MUST | A recipient | A recipient MUST store a record that it cannot decrypt before it acknowledges a later record. |  |  |
| `WIR-051` | §6.4.3 | MAY | A recipient | A recipient MAY use a hole in the sequence to find that a relay did not deliver a message. |  |  |
| `WIR-052` | §6.4.3 | MUST NOT | A recipient | A recipient MUST NOT treat the sequence as proof of a loss, because the relay assigns the sequence. |  |  |
| `WIR-053` | §6.4.3 | MUST NOT | A client | A client MUST NOT use the sequence number as a message identifier. |  |  |
| `WIR-054` | §6.4.3 | MUST | A relay | A relay MUST reject a delete command that `QS_auth` authorizes. |  |  |
| `WIR-055` | §6.4.3 | MUST NOT | A client | A client MUST NOT show a deletion as an enforcement. |  |  |
| `WIR-056` | §6.6 | MUST | A sender | A sender MUST draw `msg_id` from the device CSPRNG. |  |  |
| `WIR-057` | §6.6 | MUST NOT | A sender | A sender MUST NOT derive `msg_id` from the content or from a counter. |  |  |
| `WIR-058` | §6.6 | MUST NOT | A sender | A sender MUST NOT use a value that a different conversation also holds. |  |  |
| `WIR-059` | §6.6 | MUST | A sender | A sender MUST draw a new `msg_id` for each message and for each conversation. |  |  |
| `WIR-060` | §6.6 | MUST | A group send | A group send MUST carry one `msg_id` to each member. |  |  |
| `WIR-061` | §6.6 | MUST | An edit or a tombstone | An edit or a tombstone MUST name the `msg_id` of the target. |  |  |
| `WIR-062` | §6.6 | MUST NOT | A client | A client MUST NOT copy a `msg_id` that it received from a peer. |  |  |
| `WIR-063` | §6.6 | MUST | A sender | A sender MUST draw a new `msg_id` for each one. |  |  |
| `WIR-064` | §6.6 | MUST NOT | A sender | A sender MUST NOT use one `msg_id` two times on one chain. |  |  |
| `WIR-065` | §6.6 | MUST | A receiver | A receiver MUST reject the second use. |  |  |
| `WIR-066` | §6.6 | MUST NOT | A receiver | A receiver MUST NOT change a record that the first use named. |  |  |
| `WIR-067` | §6.6 | MUST | A client | A client MUST derive `msg_ref = SHA3-256(K_set \|\| msg_id)` truncated to 16 bytes. |  |  |
| `WIR-068` | §6.6 | MUST | A client | A client MUST use `msg_ref` for each stored reference to a message. |  |  |
| `WIR-069` | §6.6 | MUST NOT | A client | A client MUST NOT store a raw `msg_id` as a key, as an index, or as a join column. |  |  |
| `WIR-070` | §6.6 | MAY | Thus a client | Thus a client MAY hold a raw `msg_id` inside the stored body of an undelivered record. |  |  |
| `WIR-071` | §6.6 | MUST | A client | A client MUST erase that raw value when the retention ends. |  |  |
| `WIR-072` | §6.6 | MUST NOT | A client | A client MUST NOT index such a body by the raw value. |  |  |
| `WIR-073` | §6.6 | MUST NOT | A client | A client MUST NOT copy that raw value into a different row. |  |  |
| `WIR-074` | §6.6 | MUST | A new kind | A new kind MUST declare its class in this table. |  |  |
| `WIR-075` | §6.6 | MUST NOT | A client | A client MUST NOT process a kind that declares no class. |  |  |
| `WIR-076` | §6.6 | MUST NOT | An implementation | An implementation MUST NOT use it for a security decision, for an ordering guarantee, or for a replay check. |  |  |
| `WIR-077` | §6.6 | MUST | Typing indicators (`0x08`) | Typing indicators (`0x08`) MUST be off by default. |  |  |
| `WIR-078` | §6.6.1 | MUST | A parser | A parser MUST reject a `body_len` below 18. |  |  |
| `WIR-079` | §6.6.1 | MUST | A parser | A parser MUST reject a `new_body` that is not valid UTF-8. |  |  |
| `WIR-081` | §6.6.1 | MUST | A receiver | A receiver MUST reject an edit that names an attachment descriptor, a reaction, or a control kind. |  |  |
| `WIR-082` | §6.6.1 | MUST | A receiver | A receiver MUST accept an edit only from the sender of the target. |  |  |
| `WIR-083` | §6.6.1 | MUST NOT | (unstated) | The ratchet direction gives that authorization, and a client MUST NOT sign an edit. |  |  |
| `WIR-084` | §6.6.1 | MUST | A receiver | A receiver MUST reject a record whose scope byte does not match the channel that carried it. |  |  |
| `WIR-085` | §6.6.1 | MUST | A parser | A parser MUST reject a record when (`body_len` − 2) mod 16 is not. |  |  |
| `WIR-086` | §6.6.1 | MUST | A parser | A parser MUST reject a `k` of 0. |  |  |
| `WIR-087` | §6.6.1 | MUST | A parser | A parser MUST reject a `k` above `DELETE_BATCH_MAX`. |  |  |
| `WIR-088` | §6.6.1 | MUST | A parser | A parser MUST reject a target list that is not in strictly increasing byte order. |  |  |
| `WIR-089` | §6.6.1 | MUST | A parser | A parser MUST reject a repeated target. |  |  |
| `WIR-090` | §6.6.1 | MUST | A revision | A revision MUST derive this value again if the bucket ladder or the default chunk width changes. |  |  |
| `WIR-091` | §6.6.1 | MUST | (unstated) | If more targets wait, the client MUST split them across two records. |  |  |
| `WIR-092` | §6.7 | MUST | The two parties | The two parties MUST abort if that value is below the `min` value of one of them. |  |  |
| `WIR-093` | §6.7 | MUST | (unstated) | **Downgrade protection:** an implementation MUST bind the negotiated version and the two advertised ranges into the handshake transcript hash. |  |  |
| `WIR-094` | §6.8 | MUST | Each structure in this part | Each structure in this part MUST have canonical test vectors. |  |  |
| `WIR-095` | §6.8 | MUST | The vectors | The vectors MUST cover the cases of §6.8. |  |  |
| `WIR-096` | §6.8 | MUST | A vector | A vector MUST cover a cell body that carries an application kind value at the command offset. |  |  |
| `WIR-097` | §6.8 | MUST | The parser | The parser MUST reject that cell. |  |  |
| `WIR-098` | §6.8 | MUST | A vector | A vector MUST hold a `SEND` and the `MSG` that a relay makes from that `SEND`. |  |  |
| `WIR-099` | §6.8 | MUST | The vector | The vector MUST assert both `payload_len` values. |  |  |
| `WIR-100` | §6.8 | MUST | The vector | The vector MUST assert one bucket for the two commands. |  |  |
| `WIR-101` | §6.8 | MUST | The vectors | The vectors MUST cover the four cases below. |  |  |
| `WIR-102` | §6.8 | MUST | The parser | The parser MUST reject each case below. |  |  |
| `WIR-103` | §6.9 | MUST | A client | A client MUST compute the bucket from this table. |  |  |
| `WIR-104` | §6.9 | MUST NOT | A client | A client MUST NOT put a message in a bucket that does not hold it. |  |  |
| `WIR-105` | §6.9 | MUST NOT | A relay | A relay MUST NOT read a capacity from a served cell. |  |  |
| `WIR-106` | §6.4.2 | MUST | A revision | A revision MUST count that true length in each capacity row of §6.9. |  |  |
| `WIR-107` | §6.4 | MUST | An attachment command | An attachment command MUST travel on the separate connection of Part 13 §13.8. |  |  |
| `WIR-108` | §6.4 | MUST NOT | A client | A client MUST NOT batch an attachment command with a queue command. |  |  |
| `WIR-109` | §6.4.1 | MUST NOT | A client | A client MUST NOT send a cell that carries one command when a second ready command fits the command area of that cell. |  |  |
| `WIR-110` | §6.4.3 | MUST | A relay | A relay MUST emit each `MSG` of a queue that it holds and that no `ACK` covers. |  |  |
| `WIR-111` | §6.4.3 | MUST NOT | A relay | A relay MUST NOT erase a message before `MSG_TTL` and before an `ACK` covers it. |  |  |
| `WIR-112` | §6.4.3 | MUST NOT | A recipient | A recipient MUST NOT send an `ACK` that names `s` before it received each message of that queue at or below `s`. |  |  |
| `WIR-113` | §6.4.3 | MUST | (unstated) | If the lowest sequence number that a recipient did not receive is `h`, that recipient MUST set `s` below `h`. |  |  |
| `WIR-114` | §6.4.3 | MUST | A recipient | A recipient MUST count a record that it stored under rule 8 as received. |  |  |
| `WIR-115` | §6.4.3 | MUST NOT | A recipient | A recipient MUST NOT acknowledge a `MSG` before it commits that record to the local database. |  |  |
| `WIR-116` | §6.4.3 | MAY | (unstated) | If a hole at `h` stays open for `ACK_HOLE_TIMEOUT`, a recipient MAY send an `ACK` above `h`. |  |  |
| `WIR-117` | §6.4.3 | MUST | (unstated) | A recipient that acknowledges above a hole MUST show a delivery gap for that conversation. |  |  |
| `WIR-118` | §6.4.3 | MUST NOT | That recipient | That recipient MUST NOT show the conversation as complete. |  |  |
| `WIR-129` | §6.8 | MUST | The vectors | The vectors MUST cover the three cases below. |  |  |
| `WIR-130` | §6.8 | MUST | The parser | The parser MUST reject the second case and the third case. |  |  |
| `WIR-131` | §6.8 | MUST | The vectors | The vectors MUST cover the four cases below. |  |  |
| `WIR-132` | §6.8 | MUST | The parser | The parser MUST reject the last three cases. |  |  |
| `WIR-133` | §6.8 | MUST | The vectors | The vectors MUST cover a correct `commit` value and an incorrect `commit` value. |  |  |
| `WIR-134` | §6.8 | MUST | The vectors | The vectors MUST cover the 13-chunk boundary at bucket `B1`. |  |  |
| `WIR-135` | §6.3 | MUST | A relay | A relay MUST reject a cell whose command byte is above `0x07`. |  |  |
| `WIR-136` | §6.2.2 | MUST | A client | A client MUST make `session_id` from the device CSPRNG at the open of a session (§6.2.3). |  |  |
| `WIR-137` | §6.2.2 | MUST NOT | A client | A client MUST NOT reuse a `session_id` across two sessions to one relay. |  |  |
| `WIR-138` | §6.2.2 | MUST | A sender | A sender MUST increase `seq` by one for each frame, and it MUST start at zero. |  |  |
| `WIR-139` | §6.2.2 | MUST | A sender | A sender MUST close the session before `seq` wraps. |  |  |
| `WIR-140` | §6.2.2 | MUST | A sender | A sender MUST set bit 0 of `flags` on a resend, and it MUST keep `seq` at the value of the first transmission. |  |  |
| `WIR-141` | §6.2.2 | MUST | A receiver | A receiver MUST ignore a frame whose `seq` it already accepted. |  |  |
| `WIR-142` | §6.2.2 | MUST | A receiver | A receiver MUST reject a frame whose `flags` holds a non-zero value above bit 0. |  |  |
| `WIR-143` | §6.3 | MUST | A measurer | A measurer MUST send a `MEAS_OPEN` cell in bucket `B3`. |  |  |
| `WIR-144` | §6.6 | MUST | A parser | A parser MUST reject a body of kind `0x11` whose `type` is not `0x07`. |  |  |
| `WIR-146` | §6.6.3 | MUST | A sender | A sender MUST wrap each group control object in a `GroupControl`. |  |  |
| `WIR-147` | §6.6.3 | MUST | A parser | A parser MUST reject a `control_type` that the table above does not hold. |  |  |
| `WIR-148` | §6.6.3 | MUST | An implementation | An implementation MUST give the group control type its own type. |  |  |
| `WIR-149` | §6.6.3 | MUST NOT | An implementation | An implementation MUST NOT convert that type into another type. |  |  |
| `WIR-150` | §6.6.4 | MUST | A sender | A sender MUST set `source` to a value that the table above holds. |  |  |
| `WIR-151` | §6.6.4 | MUST | A parser | A parser MUST reject a `body_len` that is not 42. |  |  |
| `WIR-152` | §6.6.4 | MUST | A parser | A parser MUST reject a `source` that the table above does not hold. |  |  |
| `WIR-153` | §6.6.4 | MUST NOT | A client | A client MUST NOT emit a cell whose only content is a transparency digest. |  |  |
| `WIR-156` | §6.8 | MUST | The vectors | The vectors MUST cover one record of each of the three sources. |  |  |
| `WIR-157` | §6.8 | MUST | The parser | The parser MUST reject a `body_len` that is not 42 and a `source` of `0x04`. |  |  |
| `WIR-158` | §6.8 | MUST | The vectors | The vectors MUST cover one forward cell and one backward cell across three hops, at each of the four buckets. |  |  |
| `WIR-159` | §6.8 | MUST | The vectors | The vectors MUST assert that the cell length does not change at a hop. |  |  |
| `WIR-160` | §6.8 | MUST | The vectors | The vectors MUST hold a negative case where one bit of `body` changes at hop 2, and the endpoint rejects the cell. |  |  |
| `WIR-161` | §6.6.5 | MUST | A parser | A parser MUST reject a `body_len` below 41. |  |  |
| `WIR-162` | §6.6.5 | MUST | A parser | A parser MUST reject a record where `body_len` does not equal 40 plus `mention_count` times 16 plus `inner_len`. |  |  |
| `WIR-163` | §6.6.5 | MUST | A parser | A parser MUST reject an `inner_kind` of `0x09`, of `0x10`, or of `0x12`. |  |  |
| `WIR-164` | §6.6.5 | MUST | A parser | A parser MUST reject a `mention_count` above `MENTION_MAX`. |  |  |
| `WIR-165` | §6.6.5 | MUST | A parser | A parser MUST reject a repeated mention value. |  |  |
| `WIR-166` | §6.6.5 | MUST | A parser | A parser MUST reject a mention list that is not in strictly increasing byte order. |  |  |
| `WIR-167` | §6.6.5 | MUST | A client | A client MUST take the class of a rich record from `inner_kind`. |  |  |
| `WIR-168` | §6.6.5 | MUST NOT | A client | A client MUST NOT give a rich record a class of its own. |  |  |
| `WIR-169` | §6.6.5 | MUST | A sender | A sender MUST set `reply_target` to 16 zero bytes when the record answers no message. |  |  |
| `WIR-170` | §6.6.5 | MUST | A client | A client MUST store a non-zero `reply_target` as the `msg_ref` of §6.6. |  |  |
| `WIR-171` | §6.6.5 | MUST | A receiver | A receiver MUST resolve `reply_target` inside the conversation that carried the record. |  |  |
| `WIR-172` | §6.6.5 | MUST NOT | A receiver | A receiver MUST NOT search a different conversation. |  |  |
| `WIR-173` | §6.6.5 | MUST | A receiver | A receiver MUST render a reply whose target it does not hold as a reply to an absent message, and it MUST NOT drop the record. |  |  |
| `WIR-174` | §6.6.5 | MUST | A sender | A sender MUST compute a mention identifier with the derivation above. |  |  |
| `WIR-175` | §6.6.5 | MUST | A sender | A sender MUST set `mention_count` to zero on a pairwise channel. |  |  |
| `WIR-176` | §6.6.5 | MUST | A receiver | A receiver MUST reject a non-zero `mention_count` on a pairwise channel. |  |  |
| `WIR-177` | §6.6.5 | MUST | A client | A client MUST increase `forward_depth` by one when a user forwards a record. |  |  |
| `WIR-178` | §6.6.5 | MUST NOT | A client | A client MUST NOT decrease that value. |  |  |
| `WIR-179` | §6.6.5 | MUST | A client | A client MUST set the value to zero on an original record. |  |  |
| `WIR-180` | §6.6.6 | MUST | A parser | A parser MUST reject an `option_count` below 2 or above `POLL_OPTION_MAX`. |  |  |
| `WIR-181` | §6.6.6 | MUST | A parser | A parser MUST reject a `question` or an option `text` that is not valid UTF-8. |  |  |
| `WIR-182` | §6.6.6 | MUST | A parser | A parser MUST reject a `body_len` that does not equal the sum of the fields above. |  |  |
| `WIR-183` | §6.6.6 | MUST | A parser | A parser MUST reject a `choices` list that is not in strictly increasing order. |  |  |
| `WIR-184` | §6.6.6 | MUST | A parser | A parser MUST reject a repeated choice. |  |  |
| `WIR-185` | §6.6.6 | MUST | A parser | A parser MUST reject a choice at or above the `option_count` of the target. |  |  |
| `WIR-186` | §6.6.6 | MUST | A parser | A parser MUST reject a `choice_count` above 1 when bit 0 of `flags` is zero. |  |  |
| `WIR-187` | §6.6.6 | MUST | A receiver | A receiver MUST measure `open_seconds` from its own local receive time of the poll. |  |  |
| `WIR-188` | §6.6.6 | MUST NOT | A receiver | A receiver MUST NOT use `sent_at` for that measurement, and `WIR-076` states the same rule. |  |  |
| `WIR-189` | §6.6.6 | MUST | A receiver | A receiver MUST discard a vote that arrives after the period closed. |  |  |
| `WIR-190` | §6.6.6 | MUST | A receiver | A receiver MUST count one vote for each sender, and it MUST take the last vote of that sender by the sender-chain position of Part 11 §11.7. |  |  |
| `WIR-191` | §6.6.6 | MUST NOT | A client | A client MUST NOT render a poll count as an agreed count, and Part 11 §11.11 states the same limit. |  |  |
| `WIR-192` | §6.6.7 | MUST NOT | A client | A client MUST NOT put a pairwise address of a third party in a contact share. |  |  |
| `WIR-193` | §6.6.7 | MUST NOT | A client | A client MUST NOT put a Public Address of a third party in a contact share. |  |  |
| `WIR-194` | §6.6.7 | MUST | A client | A client MUST send a `request` before it sends an `offer`. |  |  |
| `WIR-195` | §6.6.7 | MUST NOT | A client | A client MUST NOT send an `offer` that carries an invitation which no `grant` gave it. |  |  |
| `WIR-196` | §6.6.7 | MUST | A client | A client MUST show a `request` of type `0x01`, and it MUST NOT answer it without a user action. |  |  |
| `WIR-197` | §6.6.7 | MUST | A parser | A parser MUST reject a `body_len` above zero on a record of type `0x01`. |  |  |
| `WIR-198` | §6.6.7 | MUST | A parser | A parser MUST reject a `body_len` of zero on a record of type `0x02` or of type `0x03`. |  |  |
| `WIR-199` | §6.6.7 | MUST | A client | A client MUST make a fresh invitation for each `grant`. |  |  |
| `WIR-200` | §6.6.7 | MUST NOT | A client | A client MUST NOT reuse one invitation across two grants. |  |  |
| `WIR-201` | §6.6.8 | MUST | A sender | A sender MUST set `seconds` to one value of the set that Part 7 §7.8 gives. |  |  |
| `WIR-202` | §6.6.8 | MUST | A receiver | A receiver MUST reject a value that the set does not hold. |  |  |
| `WIR-203` | §6.8 | MUST | The vectors | The vectors MUST cover the five cases below. |  |  |
| `WIR-204` | §6.8 | MUST | The parser | The parser MUST reject the eight cases that follow them. |  |  |
| `WIR-205` | §6.8 | MUST | The vectors | The vectors MUST cover the three cases below. |  |  |
| `WIR-206` | §6.8 | MUST | The parser | The parser MUST reject the six cases that follow them. |  |  |
| `WIR-207` | §6.8 | MUST | The vectors | The vectors MUST cover one record of each of the three types. |  |  |
| `WIR-208` | §6.8 | MUST | The parser | The parser MUST reject a non-empty body on a request and an empty body on a grant. |  |  |
| `WIR-209` | §6.8 | MUST | The vectors | The vectors MUST cover each value of the Part 7 §7.8 set. |  |  |
| `WIR-210` | §6.8 | MUST | The parser | The parser MUST reject a value that the set does not hold. |  |  |
| `WIR-211` | §6.4 | MUST | A relay | A relay MUST send a `CRPUT` on a direct transport session to the target relay. |  |  |
| `WIR-212` | §6.4 | MUST NOT | A relay | A relay MUST NOT send a `CRPUT` over a client circuit. |  |  |
| `WIR-213` | §6.4 | MUST | A `CRPUT` | A `CRPUT` MUST carry a `payload_len` of 32 682, which is the 32-byte `storage_token` and `CHUNK_SIZE`. |  |  |
| `WIR-214` | §6.4 | MUST NOT | A client | A client MUST NOT send a `CRPUT`. |  |  |
| `WIR-215` | §6.4 | MUST | A relay | A relay MUST reject a `CRPUT` that arrives over a circuit. |  |  |
| `WIR-216` | §6.2.1 | MUST | A sender | A sender MUST encode `type` in the 2-byte form. |  |  |
| `WIR-217` | §6.2.1 | MUST | A sender | A sender MUST encode `length` in the 4-byte form. |  |  |
| `WIR-218` | §6.2.1 | MUST | A receiver | A receiver MUST reject a capsule whose `type` is not `0x0B52` or `0x0B53`. |  |  |
| `WIR-219` | §6.2.1 | MUST | A receiver | A receiver MUST take the cell length from `length`, and that length is `length` minus 12. |  |  |
| `WIR-220` | §6.2.1 | MUST | A receiver | A receiver MUST reject an `UMBRA_CELL` capsule whose `length` is not 524, 2 060, 8 204, or 32 780. |  |  |
| `WIR-221` | §6.2.1 | MUST | A receiver | A receiver MUST reject an `UMBRA_SESSION` capsule whose `length` does not equal the length that §6.2.3 gives for its `op`. |  |  |
| `WIR-222` | §6.2.1 | MUST | A sender on the TCP transport | A sender on the TCP transport MUST put one capsule in one WebSocket binary frame with the FIN bit set. |  |  |
| `WIR-223` | §6.2.1 | MUST NOT | A sender | A sender MUST NOT put two capsules in one frame. |  |  |
| `WIR-224` | §6.2.1 | MUST NOT | A sender | A sender MUST NOT split a capsule across two frames. |  |  |
| `WIR-225` | §6.2.1 | MUST | (unstated) | If a WebSocket frame fits one TLS record, the sender MUST put that frame in one record. |  |  |
| `WIR-226` | §6.2.1 | MUST | (unstated) | If the frame does not fit one record, the sender MUST split it across the smallest count of records. |  |  |
| `WIR-227` | §6.2.1 | MUST NOT | A sender | A sender MUST NOT put two frames in one record. |  |  |
| `WIR-228` | §6.2.1 | MUST NOT | A sender | A sender MUST NOT add record padding under RFC 8446 §5.4. |  |  |
| `WIR-229` | §6.2.3 | MUST | A client | A client MUST send a `SessionOpen` or a `SessionResume` as the first capsule of each transport connection. |  |  |
| `WIR-230` | §6.2.3 | MUST | A relay | A relay MUST close a connection whose first capsule is not one of those two records. |  |  |
| `WIR-231` | §6.2.3 | MUST | A client | A client MUST draw `session_secret` from the device CSPRNG at each open. |  |  |
| `WIR-232` | §6.2.3 | MUST | A relay | A relay MUST hold `session_id`, `session_secret`, the next `seq`, and the accepted `seq` values for the life of the session. |  |  |
| `WIR-233` | §6.2.3 | MUST | A relay | A relay MUST close a connection whose `SessionOpen` names a `session_id` that a live session of that relay holds. |  |  |
| `WIR-234` | §6.2.3 | MUST | A client | A client MUST set `resume_count` to 1 at the first resume of a session. |  |  |
| `WIR-235` | §6.2.3 | MUST | A client | A client MUST increase `resume_count` by one at each later resume of that session. |  |  |
| `WIR-236` | §6.2.3 | MUST | A client | A client MUST compute `auth` with the derivation above. |  |  |
| `WIR-237` | §6.2.3 | MUST | A relay | A relay MUST verify `auth` before it binds the connection to the session. |  |  |
| `WIR-238` | §6.2.3 | MUST | A relay | A relay MUST reject a `SessionResume` whose `resume_count` is not above the last value that it accepted. |  |  |
| `WIR-239` | §6.2.3 | MUST | (unstated) | If the verification fails, the relay MUST close the connection. |  |  |
| `WIR-240` | §6.2.3 | MUST NOT | A relay | A relay MUST NOT report the cause of that close. |  |  |
| `WIR-241` | §6.2.3 | MUST | (unstated) | When a relay accepts a `SessionResume`, it MUST bind the session to the new connection. |  |  |
| `WIR-242` | §6.2.3 | MUST | (unstated) | If the previous connection of that session is open, the relay MUST close it. |  |  |
| `WIR-243` | §6.2.3 | MUST | A relay | A relay MUST hold the state of a session for `SESSION_RESUME_WINDOW` after it observes the close of the connection. |  |  |
| `WIR-244` | §6.2.3 | MUST | (unstated) | If the window ends with no accepted resume, the relay MUST discard that state. |  |  |
| `WIR-245` | §6.2.3 | MUST | (unstated) | If a client observed the close more than `SESSION_RESUME_WINDOW` before, it MUST open a new session. |  |  |
| `WIR-246` | §6.2.3 | MUST | (unstated) | If a client ends a session by its own choice, it MUST send a `SessionClose` before it closes the connection. |  |  |
| `WIR-247` | §6.2.3 | MUST | A relay | A relay MUST discard the session state when it receives a `SessionClose`. |  |  |
| `WIR-248` | §6.2.3 | MUST | Each party | Each party MUST erase `session_secret` when the session ends. |  |  |
| `WIR-249` | §6.5 | MUST | A sender | A sender MUST compute `session_tag` with the derivation above. |  |  |
| `WIR-250` | §6.5 | MUST | A sender | A sender MUST set `send_index` to zero on the first record of a session. |  |  |
| `WIR-251` | §6.5 | MUST | A sender | A sender MUST increase `send_index` by one for each later record of that session, modulo 65 536. |  |  |
| `WIR-252` | §6.5 | MUST | A receiver | A receiver MUST read `ctx` before it decrypts `hdr_ct`. |  |  |
| `WIR-253` | §6.5 | MUST | (unstated) | If a receiver cannot decrypt `hdr_ct`, it MUST classify the failure from `session_tag`, from `send_index`, and from the `epoch` of the braid frame. |  |  |
| `WIR-254` | §6.5 | MUST | A receiver | A receiver MUST use `send_index` to find the hole that Part 7 §7.5.6 rule `DEV-097` names. |  |  |
| `WIR-255` | §6.5 | MUST | A receiver | A receiver MUST reject a `version` that is not `0x02`. |  |  |
| `WIR-256` | §6.5 | MUST | A sender | A sender MUST set `epoch` to the epoch of Part 5 §5.5.2, which rule `CRY-064` binds as `BE32(epoch)`. |  |  |
| `WIR-257` | §6.5 | MUST | A receiver | A receiver MUST reject a `pq_frame_len` that is not 0, 39, 71, or 135. |  |  |
| `WIR-258` | §6.5 | MUST | A receiver | A receiver MUST reject an `index` at or above the chunk total *n* that Part 5 §5.5.2 gives for the width. |  |  |
| `WIR-259` | §6.6 | MUST | A parser | A parser MUST reject a body of kind `0x01` that is not valid UTF-8. |  |  |
| `WIR-260` | §6.6.1 | MUST | A receiver | A receiver MUST apply an edit only when the innermost kind of the target is `0x01`. |  |  |
| `WIR-261` | §6.6.1 | MUST | A receiver | A receiver MUST replace the innermost text of the target only. |  |  |
| `WIR-262` | §6.6.1 | MUST NOT | A receiver | A receiver MUST NOT change the `reply_target`, the `thread_root`, or the mention list of the target. |  |  |
| `WIR-263` | §6.6.5 | MUST | A sender in a community | A sender in a community MUST compute each reference value with the derivation above. |  |  |
| `WIR-264` | §6.6.5 | MUST | A client | A client MUST compute the `community_reply_id` of each community post that it holds. |  |  |
| `WIR-265` | §6.6.5 | MUST | A parser | A parser MUST reject a `version` that is not `0x02`. |  |  |
| `WIR-266` | §6.6.5 | MUST | A sender | A sender MUST set `thread_root` to 16 zero bytes when the record is in no thread. |  |  |
| `WIR-267` | §6.6.5 | MUST | A sender | A sender MUST set `thread_root` to a record whose own `reply_target` is zero. |  |  |
| `WIR-268` | §6.6.5 | MUST NOT | A sender | A sender MUST NOT set a non-zero `thread_root` on a record whose `reply_target` is zero. |  |  |
| `WIR-269` | §6.6.5 | MUST | A sender | A sender MUST set `thread_root` to zero on a pairwise channel. |  |  |
| `WIR-270` | §6.6.5 | MUST | A receiver | A receiver MUST reject a non-zero `thread_root` on a pairwise channel. |  |  |
| `WIR-271` | §6.6.5 | MUST | A receiver | A receiver MUST resolve `thread_root` under the rules of `WIR-171` to `WIR-173`. |  |  |
| `WIR-272` | §6.6.5 | MUST | A client | A client MUST store a non-zero `thread_root` as the `msg_ref` of §6.6 in a group. |  |  |
| `WIR-273` | §6.6.5 | MUST | A client | A client MUST group the records that share one `thread_root` in its interface. |  |  |
| `WIR-274` | §6.6.6 | MUST | A parser | A parser MUST reject a `q_len` above `POLL_QUESTION_MAX`. |  |  |
| `WIR-275` | §6.6.6 | MUST | A parser | A parser MUST reject an option `len` of zero or above `POLL_OPTION_TEXT_MAX`. |  |  |
| `WIR-276` | §6.6.9 | MUST | A parser | A parser MUST reject an `emoji_len` of zero or above `REACTION_MAX_BYTES`. |  |  |
| `WIR-277` | §6.6.9 | MUST | A parser | A parser MUST reject an `emoji` that is not valid UTF-8. |  |  |
| `WIR-278` | §6.6.9 | MUST | A parser | A parser MUST reject an `action` that is not `0x01` or `0x02`. |  |  |
| `WIR-279` | §6.6.9 | MUST | A parser | A parser MUST reject a `body_len` that does not equal 19 plus `emoji_len`. |  |  |
| `WIR-280` | §6.6.9 | MUST | A client | A client MUST store `target` as the `msg_ref` of §6.6. |  |  |
| `WIR-281` | §6.6.9 | MUST | A receiver | A receiver MUST apply a remove action only to a reaction with the same sender, `emoji`, and target. |  |  |
| `WIR-282` | §6.6.9 | MUST | A receiver | A receiver MUST resolve `target` under the rules of `WIR-171` and `WIR-172`. |  |  |
| `WIR-283` | §6.6.9 | MUST | A parser | A parser MUST reject a `state` that is not `0x01` or `0x02`. |  |  |
| `WIR-284` | §6.6.9 | MUST | A parser | A parser MUST reject a `body_len` that is not 2. |  |  |
| `WIR-285` | §6.6.9 | MUST NOT | A sender | A sender MUST NOT send two typing records to one peer inside `TYPING_INTERVAL`. |  |  |
| `WIR-286` | §6.6.9 | MUST | A receiver | A receiver MUST clear a typing state `TYPING_TTL` after it received the record that set it. |  |  |
| `WIR-287` | §6.6.9 | MUST NOT | A client | A client MUST NOT store a typing record after it processed it. |  |  |
| `WIR-288` | §6.6.9 | MUST | A parser | A parser MUST reject a `count` of zero or above `RECEIPT_BATCH_MAX`. |  |  |
| `WIR-289` | §6.6.9 | MUST | A parser | A parser MUST reject a `body_len` that does not equal 2 plus `count` times 16. |  |  |
| `WIR-290` | §6.6.9 | MUST | A parser | A parser MUST reject a target list that is not in strictly increasing byte order. |  |  |
| `WIR-291` | §6.6.9 | MUST | A parser | A parser MUST reject a repeated target. |  |  |
| `WIR-292` | §6.6.9 | MUST | A client | A client MUST store each target as the `msg_ref` of §6.6. |  |  |
| `WIR-293` | §6.6.9 | MUST | A receiver | A receiver MUST resolve each target under the rules of `WIR-171` and `WIR-172`. |  |  |
| `WIR-294` | §6.8 | MUST | The vectors | The vectors MUST cover one `UMBRA_CELL` capsule at each bucket and one `UMBRA_SESSION` capsule at each op. |  |  |
| `WIR-295` | §6.8 | MUST | The parser | The parser MUST reject each case below. |  |  |
| `WIR-296` | §6.8 | MUST | The vectors | The vectors MUST cover an open, a resume with a correct `auth`, and a close. |  |  |
| `WIR-297` | §6.8 | MUST | The relay | The relay MUST reject the two cases below. |  |  |
| `WIR-298` | §6.8 | MUST | The vectors | The vectors MUST cover the three cases below. |  |  |
| `WIR-299` | §6.8 | MUST | The parser | The parser MUST reject the three cases that follow them. |  |  |
| `WIR-302` | §6.8 | MUST | The vectors | The vectors MUST cover the three cases below. |  |  |
| `WIR-303` | §6.8 | MUST | The parser | The parser MUST reject the six cases that follow them. |  |  |
| `WIR-304` | §6.8 | MUST | The parser | The parser MUST reject a body of kind `0x01` that is not valid UTF-8. |  |  |
| `WIR-308` | §6.6.5 | MUST | A client | A client MUST match a reference value against those values. |  |  |
| `WIR-309` | §6.4 | MUST | A community command | A community command MUST travel on a transport session that carries no queue command. |  |  |
| `WIR-310` | §6.4 | MUST NOT | A client | A client MUST NOT batch a community command with a command of another range. |  |  |
| `WIR-311` | §6.8 | MUST | The vectors | The vectors MUST cover one `EXTEND` cell and one `EXTENDED` cell in bucket `B1`. |  |  |
| `WIR-312` | §6.8 | MUST | The relay | The relay MUST drop the three cases below. |  |  |
| `WIR-313` | §6.4.4 | MUST | A relay | A relay MUST answer a command that it rejects with one `NACK`. |  |  |
| `WIR-314` | §6.4.4 | MUST | That `NACK` | That `NACK` MUST carry the `corr_id` of the rejected command. |  |  |
| `WIR-315` | §6.4.4 | MUST | A relay | A relay MUST select `reason` from the table above. |  |  |
| `WIR-316` | §6.4.4 | MUST NOT | A relay | A relay MUST NOT send a `reason` outside the table. |  |  |
| `WIR-317` | §6.4.4 | MUST | A relay | A relay MUST send `REJECTED` for an unknown `queue_id` and for a failed `auth` alike. |  |  |
| `WIR-318` | §6.4.4 | MUST | (unstated) | If the command header of §6.4 does not parse, the relay MUST drop the cell without a `NACK`. |  |  |
| `WIR-319` | §6.4.4 | MUST | A relay | A relay MUST send a `NACK` on the circuit that carried the command, in bucket `B0`. |  |  |
| `WIR-320` | §6.4.4 | MUST | A relay | A relay MUST send a `NACK` in the place of the cover cell of an inbound pacing tick. |  |  |
| `WIR-321` | §6.4.4 | MUST NOT | A relay | A relay MUST NOT send a `NACK` outside a tick. |  |  |
| `WIR-322` | §6.4.4 | MUST | A relay | A relay MUST send a pending `NACK` before a pending `MSG` of the same session. |  |  |
| `WIR-323` | §6.4.4 | MUST | A client | A client MUST discard a `NACK` whose `corr_id` names no command of the same transport session. |  |  |
| `WIR-324` | §6.4.4 | MUST NOT | A client | A client MUST NOT send the same command bytes again after a `REJECTED` or a `VERSION`. |  |  |
| `WIR-325` | §6.4.4 | MUST | (unstated) | After an `ADMISSION`, a client MUST obtain the credential of the Part 14 §14.2 row before it sends again. |  |  |
| `WIR-326` | §6.4.4 | MUST NOT | A client | A client MUST NOT report a `reason` to a party other than the user. |  |  |
| `WIR-327` | §6.6.10 | MUST | A parser | A parser MUST reject a `QueueAddress` whose `version` is not `0x01`. |  |  |
| `WIR-328` | §6.6.10 | MUST | A parser | A parser MUST reject a body of kind `0x33` whose `body_len` is not 129. |  |  |
| `WIR-329` | §6.6.10 | MUST NOT | A client | A client MUST NOT send a record of kind `0x33` on a group channel or on a community channel. |  |  |
| `WIR-330` | §6.6.10 | MUST | A receiver | A receiver MUST accept a record of kind `0x33` only from the receiving chain of the session. |  |  |
| `WIR-331` | §6.6.10 | MUST | (unstated) | After the grace period of Part 3 §3.2.6 ends, a client MUST erase the `QueueAddress` that a newer address replaced. |  |  |
| `WIR-332` | §6.6.11 | MUST | A parser | A parser MUST reject a `scope` value or a `status` value that this section does not name. |  |  |
| `WIR-337` | §6.6.11 | MUST NOT | A client | A client MUST NOT send more than `KEY_REQUEST_RATE` key requests to one peer in each 24 hours. |  |  |
| `WIR-338` | §6.6.11 | MUST | A receiver | A receiver MUST discard a key request above that rate. |  |  |
| `WIR-339` | §6.6.11 | MUST | (unstated) | If a sender holds the logical message that `index` names, it MUST send that message again. |  |  |
| `WIR-340` | §6.6.11 | MUST | A sender that does not hold it | A sender that does not hold it MUST answer with status `not held`. |  |  |
| `WIR-341` | §6.6.11 | MUST | A client that takes status `not held` | A client that takes status `not held` MUST show the record as a delivery failure under Part 2 §2.4 U9. |  |  |
| `WIR-342` | §6.8 | MUST | The vectors | The vectors MUST cover one request and one supply in each scope, and one supply of each status. |  |  |
| `WIR-347` | §6.6.11 | MUST | A receiver | A receiver MUST discard a key supply that matches no outstanding request of its own. |  |  |
| `WIR-348` | §6.6.11 | MUST | That re-send | That re-send MUST carry the original `msg_id` under the current ratchet state. |  |  |
| `WIR-349` | §6.5 | MUST | A receiver | A receiver MUST reject a `kind` of `0x00`, of `0x05`, or of `0x07` or above. |  |  |
| `WIR-350` | §6.8 | MUST | That vector | That vector MUST give each key of the diagram, with `RootIdentity`, `salt_c`, `j`, and `r` stated. |  |  |
| `WIR-351` | §6.8 | MUST | The vectors | The vectors MUST hold the flight 1 of Part 5 rule `CRY-127`, whose `mode` byte is `0x02`. |  |  |
| `WIR-352` | §6.8 | MUST | The vectors | The vectors MUST give the full codeword, the `header`, and the seeds `d` and `z` of the sender. |  |  |
| `WIR-353` | §6.8 | MUST | The vectors | The vectors MUST assert that no 32-byte window of the codeword equals `d` or `z`. |  |  |
| `WIR-354` | §6.8 | MUST | The vectors | The vectors MUST give a forward cell and a backward cell after one update. |  |  |
| `WIR-355` | §6.8 | MUST | The vectors | The vectors MUST give the key set after `CIRCUIT_MAX_CELLS` updates. |  |  |
| `WIR-356` | §6.8 | MUST | The test | The test MUST run three steps on one stated plaintext record. |  |  |
| `WIR-357` | §6.8 | MUST | The test | After each step, the test MUST assert that the three files hold no 16-byte window of that plaintext. |  |  |
| `WIR-358` | §6.6.7 | MUST | A client | A client MUST show an `offer` of type `0x03`, and it MUST NOT accept it without a user action. |  |  |
| `WIR-360` | §6.2.3 | MUST | (unstated) | At the end of a push wake, a client MUST close the connection without a `SessionClose`. |  |  |
| `WIR-361` | §6.2.3 | MUST | (unstated) | If the next wake to that ingress starts inside `SESSION_RESUME_WINDOW`, the client MUST send a `SessionResume`. |  |  |
| `WIR-362` | §6.6 | MUST | A parser | A parser MUST reject a body of kind `0x36` or `0x37` whose length is not 32. |  |  |
| `WIR-363` | §6.4 | MUST | A group-queue command | A group-queue command MUST travel on a transport session that carries no command of another range. |  |  |
| `WIR-364` | §6.4 | MUST NOT | A client | A client MUST NOT batch a group-queue command with a command of another range. |  |  |
| `WIR-365` | §6.4 | MUST | One transport session | One transport session MUST carry the commands of one group queue only. |  |  |
| `WIR-366` | §6.4 | MAY | A party | A party MAY send a `COVER` in a group-queue session. |  |  |
| `WIR-367` | §6.4 | MUST | A `COVER` in a group-queue session | A `COVER` in a group-queue session MUST have the shape of a `GMSG`. |  |  |
| `WIR-368` | §6.4.5 | MUST | A party | A party MUST reject a command whose `cmd` is between `0x9B` and `0x9F`. |  |  |
| `WIR-369` | §6.4.5 | MUST | A party | A party MUST reject a group-queue command whose `payload_len` differs from the length that the table above gives for its `cmd`. |  |  |
| `WIR-370` | §6.4.5 | MUST | A `GPOST` | A `GPOST` MUST carry a `payload_len` equal to the "record on a `GMSG`" row of the group-queue capacity table of §6.9. |  |  |
| `WIR-371` | §6.4.5 | MUST | A `GMSG` | A `GMSG` MUST carry a `payload_len` equal to the L5 payload row of §6.9. |  |  |
| `WIR-372` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT move a record to a different bucket between the `GPOST` and the `GMSG`. |  |  |
| `WIR-373` | §6.4.5 | MUST | A relay | A relay MUST apply the admission control of Part 14 §14.2 to a `GNEW`. |  |  |
| `WIR-374` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT apply an admission gate to a `GPOST`. |  |  |
| `WIR-375` | §6.4.5 | MUST | A relay | A relay MUST answer a `GPOST` above `GROUP_POST_RATE` with a `NACK` of reason `LIMIT`. |  |  |
| `WIR-376` | §6.4.5 | MUST | A relay | A relay MUST make `GroupQueueId` from its CSPRNG at each accepted `GNEW`. |  |  |
| `WIR-377` | §6.4.5 | MUST | A relay | A relay MUST answer an accepted `GNEW` with one `GIDS` in the same session. |  |  |
| `WIR-378` | §6.4.5 | MUST | A relay | A relay MUST start `seq` at 1 on a new group queue. |  |  |
| `WIR-379` | §6.4.5 | MUST | A relay | A relay MUST give each accepted record a `seq` above each earlier `seq` of that group queue. |  |  |
| `WIR-380` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT give the `seq` of an erased record to a second record. |  |  |
| `WIR-381` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT derive `seq` from the record bytes, because §6.1.1 rule 5 forbids that derivation. |  |  |
| `WIR-382` | §6.4.5 | MUST NOT | A client | A client MUST NOT use `seq` as a message identifier. |  |  |
| `WIR-383` | §6.4.5 | MUST NOT | A client | A client MUST NOT use `seq` as an order across replicas. |  |  |
| `WIR-384` | §6.4.5 | MUST | A relay | A relay MUST answer an accepted `GPOST` with one `GSEQ` that carries the `corr_id` of that `GPOST`. |  |  |
| `WIR-385` | §6.4.5 | MUST | (unstated) | If a relay holds a record whose bytes equal the `GroupQueueRecord` of a `GPOST`, it MUST answer with the `seq` that it holds. |  |  |
| `WIR-386` | §6.4.5 | MUST NOT | That relay | That relay MUST NOT store a second copy. |  |  |
| `WIR-387` | §6.4.5 | MUST | On a `GSUB`, a relay | On a `GSUB`, a relay MUST emit each retained record of the group queue with a `seq` above `from_seq`, in `seq` order. |  |  |
| `WIR-388` | §6.4.5 | MUST | While the session lives, a relay | While the session lives, a relay MUST emit each record that it accepts after the `GSUB` to that session. |  |  |
| `WIR-389` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT erase a record on an action of a reader. |  |  |
| `WIR-390` | §6.4.5 | MUST | On a `GKEY`, a relay | On a `GKEY`, a relay MUST replace `read_pk` and `write_pk` with the two values of the payload. |  |  |
| `WIR-391` | §6.4.5 | MUST | A relay | A relay MUST keep the previous `read_pk` for `GROUP_READ_GRACE` after the `GKEY`. |  |  |
| `WIR-392` | §6.4.5 | MUST | A relay | A relay MUST keep the previous `write_pk` for `GROUP_WRITE_GRACE` after the `GKEY`. |  |  |
| `WIR-393` | §6.4.5 | MUST | Inside `GROUP_READ_GRACE`, a relay | Inside `GROUP_READ_GRACE`, a relay MUST accept a `GSUB`, a `GUNSUB`, a `GNREG`, or a `GNUNREG` under either read key. |  |  |
| `WIR-394` | §6.4.5 | MUST | Inside `GROUP_WRITE_GRACE`, a relay | Inside `GROUP_WRITE_GRACE`, a relay MUST accept a `GPOST` under either write key. |  |  |
| `WIR-395` | §6.4.5 | MUST | When a grace ends, a relay | When a grace ends, a relay MUST erase the previous key. |  |  |
| `WIR-396` | §6.4.5 | MUST | A relay | A relay MUST reject a command under an erased key with a `NACK` of reason `REJECTED`. |  |  |
| `WIR-397` | §6.4.5 | MUST | A relay | A relay MUST hold one previous read key and one previous write key only, thus a second `GKEY` inside a grace replaces the previous key. |  |  |
| `WIR-398` | §6.4.5 | MUST | On a `GDEL`, a relay | On a `GDEL`, a relay MUST erase the group queue, each record, each notify registration, and each key that it holds for the queue. |  |  |
| `WIR-399` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT retain an identifier of a deleted group queue. |  |  |
| `WIR-400` | §6.4.5 | MUST NOT | A relay | A relay MUST NOT keep a record that a group queue existed. |  |  |
| `WIR-401` | §6.4.5 | MUST | A parser | A parser MUST reject a `GroupNotifyRegistration` whose `version` is not `0x01`. |  |  |
| `WIR-402` | §6.4.5 | MUST | A relay | A relay MUST answer a `GNREG` above `GROUP_NOTIFIER_MAX` registrations with a `NACK` of reason `LIMIT`. |  |  |
| `WIR-403` | §6.4.6 | MUST | A sender | A sender MUST fill a `GroupQueueRecord` to the "record on a `GMSG`" row of the group-queue capacity table of §6.9 for its bucket. |  |  |
| `WIR-404` | §6.4.6 | MUST | For kind `0x01`, a sender | For kind `0x01`, a sender MUST put the fill inside `ContentPlain` after `app`, thus the AEAD covers it. |  |  |
| `WIR-405` | §6.4.6 | MUST | For kind `0x02`, a sender | For kind `0x02`, a sender MUST put the fill inside `body` after the `EpochKeyBody`. |  |  |
| `WIR-406` | §6.4.6 | MUST | `body_len` | `body_len` MUST equal that row minus 24. |  |  |
| `WIR-407` | §6.4.6 | MUST | A receiver | A receiver MUST verify that each fill byte is zero. |  |  |
| `WIR-408` | §6.4.6 | MUST | A relay | A relay MUST read `version`, `kind`, `epoch`, `slot`, and the bucket of a `GroupQueueRecord`, and no other field. |  |  |
| `WIR-409` | §6.4.6 | MUST | A relay | A relay MUST reject a `GPOST` whose `version` or `kind` the table above does not hold. |  |  |
| `WIR-410` | §6.4.6 | MUST | A receiver | A receiver MUST reject a record whose `version` is not `0x01`. |  |  |
| `WIR-411` | §6.4.6 | MUST | A receiver | A receiver MUST reject a record whose `kind` is not `0x01` or `0x02`. |  |  |
| `WIR-412` | §6.4.6 | MUST | A receiver | A receiver MUST reject a content record whose tag does not verify, and `WIR-032` applies to that rejection. |  |  |
| `WIR-413` | §6.4.6 | MUST | A parser | A parser MUST reject a `tag_mode` that is not `0x01` or `0x02`. |  |  |
| `WIR-414` | §6.4.6 | MUST | In dense mode, a parser | In dense mode, a parser MUST reject a `tag_count` that does not equal the active member count of the receiver's roster at `roster_epoch`. |  |  |
| `WIR-415` | §6.4.6 | MUST | In sparse mode, a parser | In sparse mode, a parser MUST reject a list that is not in strictly increasing `index` order. |  |  |
| `WIR-416` | §6.4.6 | MUST | A parser | A parser MUST reject a repeated `index` in a sparse list. |  |  |
| `WIR-417` | §6.4.6 | MUST | A parser | A parser MUST reject a `ContentPlain` whose fields end after the plaintext ends. |  |  |
| `WIR-418` | §6.4.6 | MUST | A sender | A sender MUST use dense mode for each `AppMessage` but a `GroupControl` of type `0x06`. |  |  |
| `WIR-419` | §6.4.6 | MUST | A sender | A sender MUST use sparse mode for a `GroupControl` of type `0x06`, with one entry for each member of role `admin` or above. |  |  |
| `WIR-420` | §6.4.6 | MUST | (unstated) | A receiver that finds no entry for its own index in a sparse record MUST discard that record. |  |  |
| `WIR-421` | §6.4.6 | MUST | A sender | A sender MUST draw `nonce` from the device CSPRNG for each content record. |  |  |
| `WIR-422` | §6.4.6 | MUST | A sender | A sender MUST set `nonce` to 12 zero bytes on an epoch-key record. |  |  |
| `WIR-423` | §6.4.6 | MUST | A rotator | A rotator MUST use the inline carrier when 7 plus the sum of the slot sizes fits the record `body` row of §6.9 at bucket `B3`. |  |  |
| `WIR-424` | §6.4.6 | MUST | Otherwise a rotator | Otherwise a rotator MUST use the chunked carrier. |  |  |
| `WIR-425` | §6.4.6 | MUST | A rotator | A rotator MUST set `slots_per_chunk` to the greatest value at which the slots of each segment fit `SEGMENT_SIZE`. |  |  |
| `WIR-426` | §6.4.6 | MUST | A parser | A parser MUST reject a `slots_per_chunk` of 0. |  |  |
| `WIR-427` | §6.4.6 | MUST | A parser | A parser MUST reject a `carrier` that is not `0x01` or `0x02`. |  |  |
| `WIR-428` | §6.4.6 | MUST | A parser | A parser MUST reject an inline body whose length before the fill does not equal 7 plus the sum of the slot sizes. |  |  |
| `WIR-429` | §6.4.6 | MUST | A parser | A parser MUST reject a slot list that is not in strictly increasing `index` order. |  |  |
| `WIR-430` | §6.4.6 | MUST | A parser | A parser MUST reject a repeated `index` in a slot list. |  |  |
| `WIR-431` | §6.4.6 | MUST | A parser | A parser MUST reject an `own_count` that is not 0 or `GROUP_REPLICAS`. |  |  |
| `WIR-432` | §6.6 | MUST | A parser | A parser MUST reject an `AppMessage` of kind `0x11` that arrives in a ratchet record or in a group queue record. |  |  |
| `WIR-433` | §6.6 | MUST | A parser | A parser MUST reject an `inner_kind` of `0x0D` or of `0x0E` in a ratchet record or in a group queue record. |  |  |
| `WIR-434` | §6.6.1 | MUST | A receiver | A receiver MUST resolve the target of an edit through each `RichRecord` wrapper. |  |  |
| `WIR-435` | §6.6.3 | MUST | A parser | A parser MUST reject a `JoinRecord` whose length is not 1 313. |  |  |
| `WIR-436` | §6.6.3 | MUST | A parser | A parser MUST reject a `stage` that is not `0x01` or `0x02`. |  |  |
| `WIR-437` | §6.6.3 | MUST | A parser | A parser MUST reject an offer whose `body_len` does not equal 3 905 plus `name_len`. |  |  |
| `WIR-438` | §6.6.3 | MUST | A parser | A parser MUST reject a `name` that is not valid UTF-8. |  |  |
| `WIR-439` | §6.6.3 | MUST | A parser | A parser MUST reject a `replica_count` that is not `GROUP_REPLICAS`. |  |  |
| `WIR-440` | §6.6.3 | MUST | A parser | A parser MUST reject an admit whose `body_len` does not equal 187 plus `desc_len` plus `path_len`. |  |  |
| `WIR-443` | §6.6.3 | MUST | A client | A client MUST send a `JoinRecord` and a `GroupInvitation` on the pairwise channel between the inviting admin and the joiner, and on no other channel. |  |  |
| `WIR-444` | §6.6.3 | MUST | A receiver | A receiver MUST discard a `JoinRecord` or a `GroupInvitation` that arrives as a group record. |  |  |
| `WIR-445` | §6.6.3 | MUST | A client | A client MUST send a group control record of type `0x03`, `0x04`, `0x05`, `0x06`, or `0x08` as the `app` of a `GroupQueueRecord`, and on no pairwise channel. |  |  |
| `WIR-446` | §6.6.3 | MUST | A receiver | A receiver MUST discard a group control record of one of those types that arrives on a pairwise channel. |  |  |
| `WIR-447` | §6.6.3 | MUST | A parser | A parser MUST reject a `SnapshotNotice` whose length does not equal 39 plus `desc_len`. |  |  |
| `WIR-448` | §6.6.3 | MUST | A parser | A parser MUST reject a `role` that the table above does not hold. |  |  |
| `WIR-449` | §6.6.3 | MUST | A parser | A parser MUST reject an `entries` list that is not in strictly increasing `index` order. |  |  |
| `WIR-450` | §6.6.3 | MUST | A parser | A parser MUST reject a `keys` list that is not in strictly increasing `index` order. |  |  |
| `WIR-451` | §6.6.3 | MUST | A parser | A parser MUST reject a `keys` entry whose `index` names no entry of `entries`. |  |  |
| `WIR-452` | §6.6.3 | MUST | A parser | A parser MUST reject a `kem_pk` whose SHA3-256 differs from the `kem_pk_hash` of its entry. |  |  |
| `WIR-453` | §6.6.3 | MUST | A parser | A parser MUST reject a `RosterSnapshot` whose length does not equal the sum of its fields. |  |  |
| `WIR-454` | §6.6.7 | MUST | A parser | A parser MUST reject a `type` that is not `0x01`, `0x02`, or `0x03`. |  |  |
| `WIR-455` | §6.6.11 | MUST | A client | A client MUST send a key request of scope `0x01` on the pairwise channel with the party that sent the record. |  |  |
| `WIR-456` | §6.6.11 | MUST | A client | A client MUST send a key request of scope `0x02` or `0x03` as a group record on the group queue when it holds a write credential inside `GROUP_WRITE_GRACE` and an epoch inside `GROUP_EPOCH_GRACE`. |  |  |
| `WIR-457` | §6.6.11 | MUST | Otherwise a client | Otherwise a client MUST send that request on a pairwise channel with a member of the group. |  |  |
| `WIR-458` | §6.6.11 | MUST NOT | A client | A client MUST NOT send a key request on a community channel. |  |  |
| `WIR-459` | §6.6.11 | MUST | A receiver | A receiver MUST accept a key supply of scope `0x01` only on the channel on which it sent the request. |  |  |
| `WIR-460` | §6.6.11 | MUST | A receiver | A receiver MUST accept the answer to a request of scope `0x02` or `0x03` under the rules of Part 11 §11.4.2 and §11.9.8, and not by the channel that carried the request. |  |  |
| `WIR-461` | §6.6.11 | MAY | A member that answers a request of scope `0x02` or `0x03` | A member that answers a request of scope `0x02` or `0x03` MAY send a `KeySupply` of status `0x01` on the channel that carried the request, and the requester takes nothing from it but the report. |  |  |
| `WIR-462` | §6.6.11 | MUST | A client | A client MUST mark each record that it opens under an epoch secret from a one-slot epoch-key record as recovered. |  |  |
| `WIR-463` | §6.6.11 | MUST NOT | The interface | The interface MUST NOT show a recovered record as a record whose `counter` the client tracked without a gap. |  |  |
| `WIR-464` | §6.6.11 | MUST NOT | A client | A client MUST NOT post more than `KEY_REQUEST_RATE` key requests to one group queue in each 24 hours. |  |  |
| `WIR-465` | §6.8 | MUST | The vectors | The vectors MUST assert that the `reply_target`, the `thread_root`, and the mention list do not change. |  |  |
| `WIR-466` | §6.8 | MUST | The vectors | The vectors MUST cover the six cases below. |  |  |
| `WIR-467` | §6.8 | MUST | The named receiver | The named receiver MUST reject the two cases that follow them. |  |  |
| `WIR-468` | §6.8 | MUST | The vectors | The vectors MUST cover one `GKEY`, one `GSUB` under the previous read key inside `GROUP_READ_GRACE`, and one `GPOST` under the previous write key inside `GROUP_WRITE_GRACE`. |  |  |
| `WIR-469` | §6.8 | MUST | The relay | The relay MUST reject a `GSUB` under the previous read key after `GROUP_READ_GRACE`, and a `GPOST` under the previous write key after `GROUP_WRITE_GRACE`. |  |  |
| `WIR-471` | §6.8 | MUST | The vectors | The vectors MUST cover a snapshot at 3 members in one segment, and the segment count of a snapshot at `GROUP_MAX`, which is 21. |  |  |
| `WIR-472` | §6.9 | MUST | A sender | A sender MUST compute the bucket of a group record from the group-queue capacity table. |  |  |
| `WIR-473` | §6.9 | MUST | (unstated) | A revision that changes the fixed part of `GroupQueueRecord`, the fixed fields of `ContentPlain`, or `GROUP_TAG_LEN` MUST derive this table again. |  |  |
| `WIR-474` | §6.6.3 | MUST | A parser | A parser MUST reject an admit that carries a granting epoch. |  |  |
| `WIR-478` | §6.6.3 | MUST | A receiver | A receiver MUST verify `sig` against `old_roster_pk`, and `SHA3-256(old_roster_pk)` against the `roster_pk_hash` of `old_index` in its roster, before it acts on the record. |  |  |
| `WIR-479` | §6.8 | MUST | The vectors | The vectors MUST cover one record of each of the eight control types. |  |  |
| `WIR-480` | §6.8 | MUST | The parser | The parser MUST reject a `control_type` of `0x00`, of `0x01`, and of `0x0A`. |  |  |
| `WIR-481` | §6.8 | MUST | The vectors | The vectors MUST hold one `RekeyRecord` with a correct signature and one with a changed `old_index`, and the parser MUST reject the second. |  |  |
| `WIR-482` | §6.6.3 | MUST | A parser | A parser MUST reject a `RekeyRecord` whose length is not 6 614. |  |  |
| `WIR-483` | §6.6.3 | MUST | A client | A client MUST send a `RekeyRecord` as a group record, or on a pairwise channel to a member of role `admin` or above with `epoch_index` and `previous_epoch_hash` zero, and on no other channel. |  |  |
| `WIR-484` | §6.6.3 | MUST | A receiver | A receiver MUST discard a `RekeyRecord` on a pairwise channel whose chain fields are not zero, and a `RekeyRecord` in a group record whose chain fields are zero. |  |  |
| `WIR-485` | §6.2.1 | MUST NOT | A relay | A relay MUST NOT negotiate the `permessage-deflate` extension of RFC 7692, or any other WebSocket extension, on an L1 connection. |  |  |
| `WIR-486` | §6.2.1 | MUST | (unstated) | A web client sends each capsule through the WebSocket API of its browser, thus rules `WIR-225` to `WIR-228` bind the native client and the relay, and the browser decides the record layout of the client. |  |  |
| `WIR-487` | §6.4 | MUST | A party | A party MUST reject a command of `ACK`, `NKEY`, `NID`, `QUOTA`, `NACK`, `SUB`, `UNSUB`, or `DEL` whose `payload_len` differs from the length that the table above gives. |  |  |
| `WIR-488` | §6.4 | MUST | A party | A party MUST reject a `NEW` whose `payload_len` differs from 64 plus the length of its `Admission`, and an `IDS` whose `payload_len` is not 96. |  |  |
| `WIR-489` | §6.6.3 | MUST | A parser | A parser MUST reject an `op` of a `PlainEpoch` that the layout above does not hold, and a `PlainEpoch` whose length does not equal the sum of the fields of its `op`. |  |  |
| `WIR-490` | §6.6.3 | MUST | A parser | A parser MUST reject a `GrantingEpoch` that carries `grantee_roster_pk` at a `role` below `0x03`, or that omits it at a `role` of `0x03` or above. |  |  |
| `WIR-491` | §6.6.3 | MUST | A parser | A parser MUST reject an `action_count` of 0 or above `MOD_ACTION_MAX`, and an `action` that the layout above does not hold. |  |  |
| `WIR-492` | §6.6.3 | MUST | A parser | A parser MUST reject a `GroupPresence` whose length is not 1. |  |  |
| `WIR-493` | §6.6.3 | MUST | The `path` | The `path` MUST be a sequence of `BE16(len) || GroupControl` entries, each a granting epoch of Part 11 §11.9.2 under its wrapper, in chain order; a parser MUST reject a `path` that ends inside an entry or that holds a `control_type` other than `0x04`. |  |  |
| `WIR-494` | §6.4 | MUST | A relay | A relay MUST put the `corr_id` of a command in the `corr_id` field of its answer. |  |  |
| `WIR-495` | §6.4 | MUST | A relay | A relay MUST draw the `corr_id` of a command that it starts from its CSPRNG. |  |  |
| `WIR-496` | §6.4 | MUST | A relay | A relay MUST answer an accepted `SEND` with one `QUOTA` under `WIR-494`. |  |  |
| `WIR-497` | §6.4 | MUST | A client | A client MUST take a `QUOTA` or a `NACK` as an answer only when its `corr_id` names a command of the same circuit that holds no answer yet, and it MUST discard each other one. |  |  |
| `WIR-498` | §6.4 | MUST NOT | A client | A client MUST NOT use a `corr_id` two times on one circuit. |  |  |
| `WIR-499` | §6.2.1 | MUST | A sender | A sender MUST put an `UMBRA_SESSION` capsule in a frame with the 7-bit length form of RFC 6455 §5.2, because that capsule is 47, 35, or 15 bytes. |  |  |
| `WIR-500` | §6.2.1 | MUST | A receiver | A receiver MUST reject a frame in the 16-bit length form whose length is below 126, and a frame in the 64-bit length form. |  |  |
| `WIR-501` | §6.2.2 | MUST | (unstated) | Each direction of a session holds a `seq` of its own. |  |  |
| `WIR-502` | §6.4.2 | MUST | A party | A party MUST send each flight of `UMBRA-XKhfs` as a `HandshakeRecord`, and in the smallest bucket whose L7 row of §6.9 holds the record. |  |  |
| `WIR-503` | §6.4.2 | MUST | A receiver | A receiver MUST drop a `HandshakeRecord` whose `flight` is not the flight that the queue waits for, and it MUST keep the state of the handshake. |  |  |
| `WIR-504` | §6.4.2 | MUST | A receiver | A receiver MUST drop a record of kind `0x01` on a queue whose handshake is not complete, because no ratchet state can open it. |  |  |
| `WIR-505` | §6.4 | MUST | The `payload_len` of an `IPUT` and of an `IBLOB` | The `payload_len` of an `IPUT` and of an `IBLOB` MUST equal the "L6 record on a `MSG`" row of §6.9 at the bucket of the cell. |  |  |
| `WIR-506` | §6.4 | MUST | A sender | A sender MUST fill with zero bytes, and a receiver MUST reject a payload whose fill holds another byte or whose `blob_len` is zero. |  |  |
| `WIR-507` | §6.4 | MUST | (unstated) | The queue owner signs an `IRES` and an `IPUT` under `QR_auth`, with the `RecipientId` in `queue_id`. |  |  |
| `WIR-508` | §6.4 | MUST | A relay | A relay MUST accept an `IPUT` one time for a link identifier, from the queue of its `IRES` alone, and it MUST answer with an `ILINK` of that identifier. |  |  |
| `WIR-509` | §6.4 | MUST | (unstated) | The party that fetches signs an `IGET` under the private half of `lock_pk`, with a `queue_id` of zero, as a `NEW` signs under its new `QR_auth`. |  |  |
| `WIR-510` | §6.4 | MUST | At the first `IGET` that verifies, a relay | At the first `IGET` that verifies, a relay MUST answer with the blob, delete the blob and the link identifier, and put `lock_pk` in the place of the `QS_auth` of the queue. |  |  |
| `WIR-511` | §6.4 | MUST | A relay | A relay MUST answer an `IGET` for an identifier that it does not hold with the `NACK` reason `REJECTED`, and `WIR-317` gives that one reason to an unknown link, to a link with no blob, and to an `auth` that does not verify. |  |  |
| `WIR-512` | §6.4 | MUST NOT | A relay | A relay MUST NOT answer a `COVER` of a client. |  |  |
| `WIR-513` | §6.4 | MUST NOT | A client | A client MUST NOT hold a `COVER`, an `ACK`, a `SUB`, an `UNSUB`, or a `DEL` in the table of the commands that wait for an answer. |  |  |
| `WIR-514` | §6.6.9 | MUST | (unstated) | A read receipt, kind `0x07`, is a marker that moves forward. |  |  |
| `WIR-515` | §6.4 | MUST | A relay | A relay MUST send a `CRPUT` as the value of one `UMBRA_REPLICA` capsule, on a connection of §6.2.1 that it opens for that copy. |  |  |
| `WIR-516` | §6.4 | MUST NOT | (unstated) | The sender MUST set `corr_id` and `auth` of that command to zero bytes, and the receiver MUST NOT read them. |  |  |
| `WIR-517` | §6.4.5 | MUST | A creator | A creator MUST key the authenticator of a `GNEW` with the `own_sk` whose public half sits in `own_pk` of that same payload. |  |  |
| `WIR-518` | §6.4.5 | MUST NOT | (unstated) | A relay MUST verify a `GNEW` under the `own_pk` of its payload, and it MUST NOT accept a `GNEW` under `read_pk` or under `write_pk`. |  |  |
| `WIR-519` | §6.4.5 | MUST NOT | (unstated) | A relay MUST emit a `GMSG` of an accepted `GPOST` to each session that subscribed, and the relay MUST NOT emit a second `GMSG` for a record whose bytes `WIR-385` matched. |  |  |
| `WIR-520` | §6.6.3 | MUST | An admit | An admit MUST carry `read_sk_e` and `write_sk_e` of the epoch that it names. |  |  |
| `WIR-521` | §6.6.3 | MUST | A parser | A parser MUST reject an admit whose `body_len` is not 249 plus `desc_len`. |  |  |

## DEV — Device Sets

Source: `spec/07-device-sets.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `DEV-001` | §7.3.1 | MUST NOT | A device | A device MUST NOT give the roster to a relay in plaintext. |  |  |
| `DEV-002` | §7.4 | MUST | The device | The device MUST send the provisioning payload over a fresh ephemeral queue. |  |  |
| `DEV-003` | §7.4 | MUST | The device | The device MUST delete that queue directly after the use. |  |  |
| `DEV-004` | §7.4 | MUST | The provisioning payload | The provisioning payload MUST carry the **local identity table** of Part 4 §4.7.2. |  |  |
| `DEV-005` | §7.4 | MUST | The link QR code | The link QR code MUST expire after 120 seconds. |  |  |
| `DEV-006` | §7.4 | MUST | The link QR code | The link QR code MUST operate one time only. |  |  |
| `DEV-007` | §7.4 | MUST | A device that has a provision | A device that has a provision MUST refuse a link into a second device set. |  |  |
| `DEV-008` | §7.4 | MUST | The client | The client MUST make the user do an explicit local wipe before a second link. |  |  |
| `DEV-009` | §7.5.1 | MUST NOT | A client | A client MUST NOT add a device to a device set that already holds `MAX_DEVICES` devices. |  |  |
| `DEV-010` | §7.5.1 | MUST | A client | A client MUST reject a roster that names more than `MAX_DEVICES` devices. |  |  |
| `DEV-011` | §7.5.1 | MUST | Each device of one user | Each device of one user MUST hold the same table. |  |  |
| `DEV-012` | §7.5.1 | MUST NOT | (unstated) | The retention limits of §7.5.2 MUST NOT remove an entry from that table. |  |  |
| `DEV-013` | §7.5.1 | MUST NOT | Thus a device | Thus a device MUST NOT depend on relay retention for convergence. |  |  |
| `DEV-014` | §7.5.2 | MUST | A device | A device MUST retain a tombstone at least as long as that device retains a message that predates that tombstone. |  |  |
| `DEV-015` | §7.5.2 | MUST | That device | That device MUST then set the watermark of `D` to `c`. |  |  |
| `DEV-016` | §7.5.2 | MUST NOT | A device | A device MUST NOT advance a watermark past a counter for which it still holds a record. |  |  |
| `DEV-017` | §7.5.2 | MUST | A device with the `live` scope | A device with the `live` scope MUST set the watermark of each source device. |  |  |
| `DEV-018` | §7.5.2 | MUST | That device | That device MUST set each watermark to the current counter of that source at the link. |  |  |
| `DEV-019` | §7.5.2 | MUST | A restore | A restore MUST carry the watermark of each source device. |  |  |
| `DEV-020` | §7.5.2 | MUST | The interface | The interface MUST state that trade at the point where the user sets the value. |  |  |
| `DEV-021` | §7.5.3 | MUST | A new kind | A new kind MUST declare its class in Part 6 §6.6. |  |  |
| `DEV-022` | §7.5.3 | MUST NOT | A client | A client MUST NOT process a kind that declares no class. |  |  |
| `DEV-023` | §7.5.3 | MUST NOT | A client | A client MUST NOT put a peer signal on a sync channel. |  |  |
| `DEV-024` | §7.5.3 | MUST | A client | A client MUST identify each message by the triple (conversation, sender, `msg_ref`) of Part 6 §6.6. |  |  |
| `DEV-025` | §7.5.3 | MUST | A client | A client MUST remove a duplicate by that triple. |  |  |
| `DEV-026` | §7.5.3 | MUST NOT | A client | A client MUST NOT use a hash of ciphertext bytes for one of three functions. |  |  |
| `DEV-027` | §7.5.3 | MUST | A receiver | A receiver MUST resolve a target only inside the conversation that carried the naming record. |  |  |
| `DEV-028` | §7.5.3 | MUST | A receiver | A receiver MUST resolve a target only against the messages of the sender that the L6 QueueE2E key names. |  |  |
| `DEV-029` | §7.5.3 | MUST NOT | A receiver | A receiver MUST NOT search a different conversation. |  |  |
| `DEV-030` | §7.5.3 | MUST NOT | A receiver | A receiver MUST NOT change a record before it completes this check. |  |  |
| `DEV-031` | §7.5.3 | MUST NOT | A client | A client MUST NOT use a wall clock for the order. |  |  |
| `DEV-032` | §7.5.3 | MUST NOT | A client | A client MUST NOT use `sent_at` for the order. |  |  |
| `DEV-033` | §7.5.3 | MUST | A client | A client MUST order a revision by the sender-chain position of the author. |  |  |
| `DEV-034` | §7.5.3 | MUST | A client | A client MUST keep a high-water mark of the applied position for each target. |  |  |
| `DEV-035` | §7.5.3 | MUST | A client | A client MUST discard a revision at or below that mark. |  |  |
| `DEV-036` | §7.5.3 | MUST NOT | (unstated) | A message body is not mutable state, thus last-writer-wins MUST NOT apply to a message body. |  |  |
| `DEV-037` | §7.5.3 | MUST | A device | A device MUST reject an insertion from `D` whose causal counter is at or below that watermark. |  |  |
| `DEV-038` | §7.5.3 | MAY | A device | A device MAY remove a tombstone after the watermark passes the counter of the target. |  |  |
| `DEV-039` | §7.5.3 | MUST NOT | In that case the client | In that case the client MUST NOT show the rejection. |  |  |
| `DEV-040` | §7.5.3 | MUST | The client | The client MUST then show that gap under §7.5.5 rule. |  |  |
| `DEV-041` | §7.5.3 | MUST NOT | A client | A client MUST NOT store it. |  |  |
| `DEV-042` | §7.5.3 | MUST NOT | A client | A client MUST NOT put it on a sync channel. |  |  |
| `DEV-043` | §7.5.3 | MUST NOT | A client | A client MUST NOT put a control record in one of the other classes. |  |  |
| `DEV-044` | §7.5.3 | MUST NOT | A client | A client MUST NOT put a deletion inside kind `0x20`. |  |  |
| `DEV-045` | §7.5.3 | MUST | A receiver | A receiver MUST reject a kind `0x05` record whose scope byte does not match the channel that carried it. |  |  |
| `DEV-046` | §7.5.3 | MUST | (unstated) | If no peer holds a range, the device MUST show a history gap for that range. |  |  |
| `DEV-047` | §7.5.4 | MUST | The composing device | The composing device MUST draw `msg_id` before it gives the plaintext to the owner. |  |  |
| `DEV-048` | §7.5.4 | MUST NOT | The ratchet owner | The ratchet owner MUST NOT draw a new `msg_id`. |  |  |
| `DEV-049` | §7.5.4 | MAY | A device | A device MAY then claim the ownership with a broadcast of an `OwnerClaimRecord` of §7.3.1. |  |  |
| `DEV-050` | §7.5.5 | MUST | A client | A client MUST put that record on a sync channel of §7.5.1 only. |  |  |
| `DEV-051` | §7.5.5 | MUST NOT | A client | A client MUST NOT put it on a pairwise channel, on a group channel, or on a community channel. |  |  |
| `DEV-052` | §7.5.5 | MUST | A client | A client MUST reject a sync acknowledgment that arrives on a different channel. |  |  |
| `DEV-053` | §7.5.5 | MUST | (unstated) | A revision that adds a device-set control record MUST give that record a new `control_type` value. |  |  |
| `DEV-054` | §7.5.5 | MUST NOT | A device | A device MUST NOT use the relay sequence number of Part 6 §6.4.3 as that counter. |  |  |
| `DEV-055` | §7.5.5 | MUST | A device | A device MUST set `counter` to the highest causal counter of the peer with the property below. |  |  |
| `DEV-056` | §7.5.5 | MUST | A device | A device MUST send a sync acknowledgment after it takes `SYNC_ACK_BATCH` records from one peer. |  |  |
| `DEV-057` | §7.5.5 | MUST | A device | A device MUST also send one when `SYNC_ACK_MAX_DELAY` passes. |  |  |
| `DEV-058` | §7.5.5 | MUST | (unstated) | At each acknowledgment a device MUST set that pending count to zero. |  |  |
| `DEV-059` | §7.5.5 | MUST | That device | That device MUST also start the `SYNC_ACK_MAX_DELAY` period again. |  |  |
| `DEV-060` | §7.5.5 | MUST | (unstated) | If the batch condition and the period come due together, a device MUST send one sync acknowledgment only. |  |  |
| `DEV-061` | §7.5.5 | MUST NOT | (unstated) | If no new record arrived, a device MUST NOT send a sync acknowledgment. |  |  |
| `DEV-062` | §7.5.5 | MUST NOT | A device | A device MUST NOT retain a sync acknowledgment for a resend. |  |  |
| `DEV-063` | §7.5.5 | MUST NOT | A device | A device MUST NOT count a sync acknowledgment toward `SYNC_ACK_BATCH`. |  |  |
| `DEV-064` | §7.5.5 | MUST | A device | A device MUST send a sync acknowledgment at the ordinary send rate of that sync channel. |  |  |
| `DEV-065` | §7.5.5 | MUST | A device | A device MUST retain each sync record that it sent and that the peer did not acknowledge. |  |  |
| `DEV-066` | §7.5.5 | MUST | A device | A device MUST key that retained record by the `msg_ref` of Part 6 §6.6 and by the causal counter. |  |  |
| `DEV-067` | §7.5.5 | MUST | (unstated) | If a relay signals `QUOTA` on a sync queue, the sending device MUST keep the record in its local database. |  |  |
| `DEV-068` | §7.5.5 | MUST NOT | That device | That device MUST NOT show a delivery failure to the user. |  |  |
| `DEV-069` | §7.5.5 | MUST | A device | A device MUST resend each retained record above the acknowledged counter of the peer. |  |  |
| `DEV-070` | §7.5.5 | MUST | (unstated) | If no sync acknowledgment arrived from that peer, a device MUST resend each retained record. |  |  |
| `DEV-071` | §7.5.5 | MUST | A device | A device MUST do that resend when a sync acknowledgment arrives. |  |  |
| `DEV-072` | §7.5.5 | MUST | A device | A device MUST also do that resend at a new sync queue. |  |  |
| `DEV-073` | §7.5.5 | MUST | A device | A device MUST pace a resend at the ordinary send rate of that sync channel. |  |  |
| `DEV-074` | §7.5.5 | MUST NOT | A device | A device MUST NOT resend in one burst. |  |  |
| `DEV-075` | §7.5.5 | MUST NOT | A device | A device MUST NOT retain a record for the resend after `SYNC_MAX_AGE`. |  |  |
| `DEV-076` | §7.5.5 | MUST | (unstated) | While a resend is in progress, the client MUST show that the history is still arriving. |  |  |
| `DEV-077` | §7.5.5 | MUST | (unstated) | If no device of the set holds a range, the device MUST show a **history gap** for that range. |  |  |
| `DEV-078` | §7.5.5 | MUST NOT | The device | The device MUST NOT hide the gap. |  |  |
| `DEV-079` | §7.5.5 | MUST NOT | The device | The device MUST NOT show the history as complete. |  |  |
| `DEV-080` | §7.5.6 | MUST | A receiver | A receiver MUST accept an edit only from the sender of the target. |  |  |
| `DEV-081` | §7.5.6 | MUST | A receiver | A receiver MUST accept a deletion of scope `0x02` only for a target that the same sender sent. |  |  |
| `DEV-082` | §7.5.6 | MUST NOT | A sender | A sender MUST NOT use one `msg_id` two times on one chain. |  |  |
| `DEV-083` | §7.5.6 | MUST | A receiver | A receiver MUST reject the second use. |  |  |
| `DEV-084` | §7.5.6 | MUST NOT | A receiver | A receiver MUST NOT change a record that the first use named. |  |  |
| `DEV-085` | §7.5.6 | MUST | A receiver | A receiver MUST discard a deletion that names a target which that receiver received in the other direction. |  |  |
| `DEV-086` | §7.5.6 | MUST NOT | A receiver | A receiver MUST NOT put such a target in the pending reference table below. |  |  |
| `DEV-087` | §7.5.6 | MUST | The ratchet owner of the recipient | The ratchet owner of the recipient MUST reject an edit that arrives more than `EDIT_WINDOW` after it received the target. |  |  |
| `DEV-088` | §7.5.6 | MUST | A receiver | A receiver MUST reject the revision that follows the limit. |  |  |
| `DEV-089` | §7.5.6 | MUST | A receiver | A receiver MUST discard an edit at or below that mark. |  |  |
| `DEV-090` | §7.5.6 | MUST | A client | A client MUST mark an edited message as edited, at each recipient. |  |  |
| `DEV-091` | §7.5.6 | MUST | A client | A client MUST apply that mark before the first render of the new text. |  |  |
| `DEV-092` | §7.5.6 | MUST NOT | The interface | The interface MUST NOT change a delivered message without a mark. |  |  |
| `DEV-093` | §7.5.6 | MUST | A client | A client MUST hold an edit or a deletion whose target has not arrived in a **pending reference table**. |  |  |
| `DEV-094` | §7.5.6 | MUST | A client | A client MUST store the `msg_ref` of Part 6 §6.6 as that target. |  |  |
| `DEV-095` | §7.5.6 | MUST | A client | A client MUST discard a pending entry above either limit. |  |  |
| `DEV-096` | §7.5.6 | MUST NOT | A pending reference entry | A pending reference entry MUST NOT suppress or delay the missing-index recovery of Part 2 §2.4. |  |  |
| `DEV-097` | §7.5.6 | MUST | A client | A client MUST treat a hole in the ratchet index as a delivery failure. |  |  |
| `DEV-098` | §7.5.6 | MUST | That client | That client MUST then send the key request of Part 6 §6.6.11. |  |  |
| `DEV-099` | §7.5.6 | MUST | (unstated) | A device that applies a tombstone MUST discard the record key of the named record. |  |  |
| `DEV-100` | §7.5.6 | MUST | That device | That device MUST overwrite the named record. |  |  |
| `DEV-101` | §7.5.6 | MUST NOT | A client | A client MUST NOT only hide a row. |  |  |
| `DEV-102` | §7.5.6 | MUST NOT | A client | A client MUST NOT render an absence as the act of a named party. |  |  |
| `DEV-103` | §7.5.6 | MAY | (unstated) | If the client holds that evidence, the client MAY render the absence as the act of a named party. |  |  |
| `DEV-104` | §7.5.6 | MUST NOT | The placeholder | The placeholder MUST NOT vanish without a trace. |  |  |
| `DEV-105` | §7.5.6 | MAY | The user | The user MAY clear it. |  |  |
| `DEV-106` | §7.5.6 | MUST NOT | (unstated) | The local deletion happens at once, and the client MUST NOT delay it. |  |  |
| `DEV-107` | §7.5.6 | MUST | In that case the client | In that case the client MUST draw an independent delay for each destination. |  |  |
| `DEV-108` | §7.5.6 | MUST | The client | The client MUST draw that delay from an exponential distribution with a mean of `SWEEP_SPREAD`. |  |  |
| `DEV-109` | §7.5.6 | MUST NOT | The client | The client MUST NOT dispatch the set as a burst. |  |  |
| `DEV-112` | §7.5.6 | MUST | A client | A client MUST send an edit and a deletion under the ordinary ARQ of Part 3 §3.7. |  |  |
| `DEV-113` | §7.5.6 | MUST NOT | A client | A client MUST NOT run a retry loop that a relay quota signal paces. |  |  |
| `DEV-114` | §7.5.6 | MUST | (unstated) | If a relay signals the quota, the client MUST show a delivery failure to the user. |  |  |
| `DEV-115` | §7.5.6 | MUST | A history transfer | A history transfer MUST carry the tombstone set for the same window. |  |  |
| `DEV-116` | §7.5.6 | MUST | A restore | A restore MUST apply the tombstone set that the backup or the archive carries. |  |  |
| `DEV-117` | §7.5.6 | MUST | In that case the client | In that case the client MUST show the count to the user. |  |  |
| `DEV-118` | §7.5.6 | MUST | The client | The client MUST get a confirmation before it applies those tombstones. |  |  |
| `DEV-119` | §7.5.6 | MUST | At a revocation, a client | At a revocation, a client MUST show the number of deletions from the revoked device. |  |  |
| `DEV-120` | §7.5.6 | MUST | The client | The client MUST tell the user that a restore from a backup that predates the revocation recovers those messages. |  |  |
| `DEV-121` | §7.5.6 | MUST | A device with the `live` scope | A device with the `live` scope MUST store a tombstone for a message that it never held. |  |  |
| `DEV-122` | §7.5.6 | MUST NOT | That device | That device MUST NOT request the named message from a peer device. |  |  |
| `DEV-123` | §7.5.6 | MUST NOT | A client | A client MUST NOT emit a reconciliation record whose size follows the conversation count. |  |  |
| `DEV-124` | §7.5.6 | MUST NOT | A client | A client MUST NOT emit a reconciliation record whose size follows the tombstone count. |  |  |
| `DEV-125` | §7.5.6 | MUST NOT | A client | A client MUST NOT emit reconciliation traffic on a schedule that a reconnect determines. |  |  |
| `DEV-126` | §7.5.7 | MUST | Thus the interface | Thus the interface MUST state each limit below. |  |  |
| `DEV-127` | §7.5.7 | MUST | The two operations | The two operations MUST carry two different labels and two different confirmations. |  |  |
| `DEV-128` | §7.5.7 | MUST NOT | The interface | The interface MUST NOT make that operation the visually safer choice. |  |  |
| `DEV-129` | §7.5.7 | MUST | After the act the interface | After the act the interface MUST show which of the two operations it performed. |  |  |
| `DEV-130` | §7.5.7 | MUST NOT | (unstated) | A community and a private conversation MUST NOT share one deletion affordance or one wording. |  |  |
| `DEV-131` | §7.6 | MUST NOT | That operation | That operation MUST NOT cause a safety-number change or a prompt for a new verification (usability goal U7). |  |  |
| `DEV-132` | §7.6 | MUST NOT | A device | A device MUST NOT share the roster with a contact. |  |  |
| `DEV-133` | §7.6.1 | MAY | A user | A user MAY export an encrypted archive. |  |  |
| `DEV-134` | §7.6.1 | MUST NOT | That restore | That restore MUST NOT break the affected conversations permanently. |  |  |
| `DEV-135` | §7.6.1 | MUST | That client | That client MUST then start the re-establishment of the queue over the pairwise identity. |  |  |
| `DEV-136` | §7.6.1 | MUST NOT | A client | A client MUST NOT upload the archive to UMBRA infrastructure. |  |  |
| `DEV-137` | §7.7 | MUST | The UI | The UI MUST state this limit in those words. |  |  |
| `DEV-138` | §7.7 | MUST | The UI | The UI MUST also recommend the identity reset from the recovery phrase for a device in hostile hands. |  |  |
| `DEV-139` | §7.7.1 | SHOULD | In that case the user | In that case the user SHOULD also make a new community identity. |  |  |
| `DEV-140` | §7.7.1 | SHOULD | The user | The user SHOULD do that in each community that matters. |  |  |
| `DEV-141` | §7.7.1 | MUST | The interface | The interface MUST offer that operation in the reset flow. |  |  |
| `DEV-142` | §7.7.1 | MUST | The interface | The interface MUST state that a new community identity loses the post history. |  |  |
| `DEV-143` | §7.3 | MUST | A device | A device MUST make `DeviceRosterKey_i` from its own CSPRNG. |  |  |
| `DEV-144` | §7.3 | MUST NOT | A device | A device MUST NOT derive that keypair from the `RootIdentity`, from `K_devset`, or from `SyncChannelSeed`. |  |  |
| `DEV-145` | §7.3 | MUST NOT | A device | A device MUST NOT transmit the private half of `DeviceRosterKey_i`. |  |  |
| `DEV-146` | §7.3 | MUST NOT | (unstated) | The provisioning payload of §7.4 MUST NOT carry that private half. |  |  |
| `DEV-147` | §7.3 | MUST | A device | A device MUST publish the public half of `DeviceRosterKey_i` in its `DeviceEntry` of §7.3.1. |  |  |
| `DEV-148` | §7.3.1 | MUST | A device | A device MUST sign a roster epoch with its own `DeviceRosterKey_i`. |  |  |
| `DEV-149` | §7.3.1 | MUST | A device | A device MUST put its own `DeviceId` in `signer_id`. |  |  |
| `DEV-150` | §7.3.1 | MUST | A verifier | A verifier MUST check `prev_hash` against the SHA3-256 of the roster epoch that it holds at `epoch − 1`. |  |  |
| `DEV-151` | §7.3.1 | MUST | A verifier | A verifier MUST reject an epoch that does not chain. |  |  |
| `DEV-152` | §7.3.1 | MUST | (unstated) | For an epoch above 0, a verifier MUST find `signer_id` in the `devices` list of the **previous** epoch. |  |  |
| `DEV-153` | §7.3.1 | MUST | A verifier | A verifier MUST reject the epoch if the previous epoch names `signer_id` in its `revoked` list. |  |  |
| `DEV-154` | §7.3.1 | MUST | A verifier | A verifier MUST verify `sig` against the `mldsa_pk` of that entry. |  |  |
| `DEV-155` | §7.3.1 | MUST | For epoch 0, a verifier | For epoch 0, a verifier MUST find `signer_id` in the `devices` list of that same epoch. |  |  |
| `DEV-156` | §7.3.1 | MUST | That verifier | That verifier MUST verify `sig` against the `mldsa_pk` of that entry. |  |  |
| `DEV-157` | §7.3.1 | MUST | A verifier | A verifier MUST reject an epoch whose `revoked` list does not hold each `DeviceId` that an earlier epoch revoked. |  |  |
| `DEV-158` | §7.3.1 | MUST | A device | A device MUST take the current owner of a subject from the claim of the **highest** epoch that names that subject. |  |  |
| `DEV-159` | §7.3.1 | MUST | A device | A device MUST treat a subject that no epoch names as owned by the device that established that subject. |  |  |
| `DEV-160` | §7.3.1 | MUST | A device that changes the owner of a subject | A device that changes the owner of a subject MUST publish that change in an `OwnerClaimRecord`. |  |  |
| `DEV-161` | §7.3.1 | MUST NOT | A roster epoch | A roster epoch MUST NOT carry more than `OWNER_CLAIM_MAX` claims. |  |  |
| `DEV-162` | §7.3.1 | MUST NOT | A device | A device MUST NOT name a subject two times in one epoch. |  |  |
| `DEV-163` | §7.3.1 | MUST | (unstated) | The provisioning payload of §7.4 MUST carry the current ownership table. |  |  |
| `DEV-164` | §7.3.1 | MUST | A revision | A revision MUST derive this total again if it adds a field to `DeviceEntry` or raises `MAX_DEVICES`. |  |  |
| `DEV-165` | §7.4 | MUST | The new device | The new device MUST make its own `DeviceKey` and its own `DeviceRosterKey` before step 5. |  |  |
| `DEV-166` | §7.4 | MUST | The existing device | The existing device MUST put those public halves in the `DeviceEntry` of epoch *n+1. |  |  |
| `DEV-167` | §7.4 | MUST NOT | The provisioning payload | The provisioning payload MUST NOT carry a `DeviceRosterKey` private half. |  |  |
| `DEV-168` | §7.4 | MUST | The new device | The new device MUST send the public half of the two keypairs to the existing device over the channel of step 2. |  |  |
| `DEV-169` | §7.5.4 | MUST NOT | A device | A device MUST NOT claim the ownership of a subject before `OWNER_TIMEOUT` passes. |  |  |
| `DEV-170` | §7.7 | MUST | (unstated) | A device that sees two verified epochs at one index from **one** `signer_id` MUST show the fork and MUST name that device. |  |  |
| `DEV-171` | §7.7 | MUST NOT | That device | That device MUST NOT select one of the two silently. |  |  |
| `DEV-172` | §7.7.1 | MUST | A full identity reset | A full identity reset MUST also make a new `DeviceRosterKey` on each remaining device. |  |  |
| `DEV-173` | §7.7.1 | MUST | The client | The client MUST then publish a roster epoch 0 for the new device set. |  |  |
| `DEV-174` | §7.5.3 | MUST | A client | A client MUST take the class from `inner_kind`. |  |  |
| `DEV-175` | §7.5.3 | MUST NOT | A client | A client MUST NOT give a group record a class of its own. |  |  |
| `DEV-176` | §7.3.1 | MUST | A device | A device MUST set `epoch` to the `epoch` of the previous roster plus. |  |  |
| `DEV-177` | §7.3.1 | MUST | (unstated) | If two verified successors name one `prev_hash` and two different values of `signer_id` sign them, a device MUST select one by the order below. |  |  |
| `DEV-178` | §7.3.1 | MUST NOT | A device | A device MUST NOT show a fork for that case when the two `revoked` lists hold the same entries. |  |  |
| `DEV-179` | §7.3.1 | MUST | (unstated) | A device whose epoch the order did not select MUST publish its claims again against the selected epoch. |  |  |
| `DEV-180` | §7.3.1 | MUST NOT | A device | A device MUST NOT apply a roster epoch that names its own `DeviceId` in `revoked`. |  |  |
| `DEV-181` | §7.3.1 | MUST | That device | That device MUST show that event to the user. |  |  |
| `DEV-182` | §7.7 | MUST | (unstated) | A device that finds that a peer applied a different epoch at one index MUST show the fork. |  |  |
| `DEV-183` | §7.3.1 | MUST | A device | A device MUST publish an ownership change in an `OwnerClaimRecord`. |  |  |
| `DEV-184` | §7.3.1 | MUST NOT | A device | A device MUST NOT publish a roster epoch whose only change is an ownership claim. |  |  |
| `DEV-185` | §7.3.1 | MUST | A verifier | A verifier MUST find `signer_id` in the `devices` list of the roster epoch that `roster_epoch` names. |  |  |
| `DEV-186` | §7.3.1 | MUST | A verifier | A verifier MUST verify `sig` against the `mldsa_pk` of that entry. |  |  |
| `DEV-187` | §7.3.1 | MUST | A verifier | A verifier MUST reject a record whose `roster_hash` does not match that epoch. |  |  |
| `DEV-188` | §7.3.1 | MUST | A verifier | A verifier MUST reject a claim record whose `roster_epoch` is below the highest roster epoch that the verifier applied. |  |  |
| `DEV-189` | §7.3.1 | MUST | A device | A device MUST take the current owner of a subject from the record with the highest pair (`roster_epoch`, `claim_seq`) that names that subject. |  |  |
| `DEV-190` | §7.3.1 | MUST | (unstated) | If two records hold that same pair, a device MUST select the lower `signer_id` in byte order. |  |  |
| `DEV-191` | §7.3.1 | MUST NOT | A device | A device MUST NOT send more than `OWNER_CLAIM_RATE` claim records of scope `0x01` or scope `0x02` each day. |  |  |
| `DEV-192` | §7.3.1 | MUST NOT | A device | A device MUST NOT put a claim of scope `0x01` and a claim of scope `0x02` for one subject in one record. |  |  |
| `DEV-193` | §7.5.1 | MUST | A client | A client MUST send an interactive sync record at the first opportunity. |  |  |
| `DEV-194` | §7.5.1 | MUST NOT | A client | A client MUST NOT hold an interactive sync record for a cover slot. |  |  |
| `DEV-195` | §7.5.1 | MUST | A client | A client MUST bound the interactive sync records on one channel by a token bucket. |  |  |
| `DEV-196` | §7.5.1 | MUST NOT | A client | A client MUST NOT mark a record interactive when no user action waits on it. |  |  |
| `DEV-197` | §7.5.3 | MUST | A client | A client MUST converge each item of that table across the device set. |  |  |
| `DEV-198` | §7.5.3 | MUST | A revision that adds a chat-list item | A revision that adds a chat-list item MUST add a row. |  |  |
| `DEV-199` | §7.5.3 | MUST | A client | A client MUST hold a draft under the record encryption of Part 15 §15.6.4. |  |  |
| `DEV-200` | §7.5.3 | MUST NOT | A client | A client MUST NOT put a draft in the backup of Part 4 §4.7.2. |  |  |
| `DEV-201` | §7.5.3 | MUST | A client | A client MUST erase a draft from the device set when the user sends it or clears it. |  |  |
| `DEV-202` | §7.5.3 | MUST | A client | A client MUST let the user turn the draft sync off, and Part 16 §16.3 records the residual. |  |  |
| `DEV-203` | §7.5.8 | MUST | A party | A party MUST apply the timer to each record that it takes after it applied the timer record. |  |  |
| `DEV-204` | §7.5.8 | MUST NOT | A party | A party MUST NOT apply a timer to a record that predates it. |  |  |
| `DEV-205` | §7.5.8 | MAY | Each party of a conversation | Each party of a conversation MAY set the timer. |  |  |
| `DEV-206` | §7.5.8 | MUST | A client | A client MUST show the party that set the current value and the time of that change. |  |  |
| `DEV-207` | §7.5.8 | MUST | A client | A client MUST show a timer change as a record in the conversation. |  |  |
| `DEV-208` | §7.5.8 | MUST | For a record from the other party, a client | For a record from the other party, a client MUST measure the period from its own local receive time. |  |  |
| `DEV-209` | §7.5.8 | MUST NOT | A client | A client MUST NOT use `sent_at` for that measurement, and Part 6 rule `WIR-076` states the same rule. |  |  |
| `DEV-210` | §7.5.8 | MUST | (unstated) | At the end of the period a client MUST discard the record key of Part 15 §15.6.4 for that record. |  |  |
| `DEV-211` | §7.5.8 | MUST | That client | That client MUST overwrite the record. |  |  |
| `DEV-212` | §7.5.8 | MUST | A client | A client MUST apply the timer on each device of the set. |  |  |
| `DEV-213` | §7.5.8 | MUST NOT | A client | A client MUST NOT depend on a peer device to erase a record. |  |  |
| `DEV-214` | §7.5.8 | MUST | A client | A client MUST carry a timed record to a device of the set on the sync channel only. |  |  |
| `DEV-215` | §7.5.8 | MUST NOT | A client | A client MUST NOT put such a record in a durable store other than the local database of the device. |  |  |
| `DEV-216` | §7.5.8 | MUST NOT | A client | A client MUST NOT put such a record in a history transfer of §7.5.6 rule 2. |  |  |
| `DEV-217` | §7.5.8 | MUST NOT | A client | A client MUST NOT show a timer as an enforcement. |  |  |
| `DEV-218` | §7.5.8 | MUST | The interface | The interface MUST state that a party can copy, photograph, or export a message before the period ends. |  |  |
| `DEV-219` | §7.5.9 | MUST | A client | A client MUST hold the notification setting as mutable state of §7.5.3. |  |  |
| `DEV-220` | §7.5.9 | MUST | A client | A client MUST converge that setting across the device set. |  |  |
| `DEV-221` | §7.5.9 | MUST | A client | A client MUST default a new group above `T1_MAX` members to `mentions`. |  |  |
| `DEV-222` | §7.5.9 | MUST | A client | A client MUST default a community to `none`, and Part 12 §12.6 states the same default. |  |  |
| `DEV-223` | §7.5.9 | MUST NOT | A client | A client MUST NOT let the setting change the wake behavior of Part 8 §8.3. |  |  |
| `DEV-224` | §7.3 | MUST | A device | A device MUST make its own `device_id` from its own CSPRNG at the link. |  |  |
| `DEV-225` | §7.3 | MUST NOT | A device | A device MUST NOT derive `device_id` from a key, from a hardware identifier, or from an earlier `device_id`. |  |  |
| `DEV-226` | §7.3.1 | MUST | A device | A device MUST compute `subject` as the SHA3-256 hash of `K_set`, the scope, and the value. |  |  |
| `DEV-227` | §7.3.1 | MUST | A device | A device MUST fold each claim that it applies into its ownership table. |  |  |
| `DEV-228` | §7.3.1 | MUST | A device | A device MUST retain the SHA3-256 hash of each roster epoch that it applied. |  |  |
| `DEV-229` | §7.3.1 | MUST NOT | A device | A device MUST NOT retain a signed claim record or a superseded roster epoch after the fold. |  |  |
| `DEV-230` | §7.3.1 | MUST | A claimant | A claimant MUST measure an absence from its own receive time of the last record from that device. |  |  |
| `DEV-231` | §7.3.1 | MUST NOT | A claimant | A claimant MUST NOT publish a claim of scope `0x03` before that absence reaches `OWNER_ABSENCE`. |  |  |
| `DEV-232` | §7.3.1 | MUST NOT | A device | A device MUST NOT send more than `OWNER_ABSENCE_RATE` claim records that hold a claim of scope `0x03`. |  |  |
| `DEV-233` | §7.3.1 | MUST | A device | A device MUST apply a claim of scope `0x03` to each subject that the absent device owns. |  |  |
| `DEV-234` | §7.3.1 | MUST NOT | A device | A device MUST NOT put a claim of scope `0x03` together with a claim of a different scope in one record. |  |  |
| `DEV-235` | §7.3.1 | MUST | (unstated) | Before a claimant publishes a claim of scope `0x03`, it MUST show how many subjects the absent device owns. |  |  |
| `DEV-236` | §7.5.1 | MUST | (unstated) | If the acknowledged counter of a peer lags by more than `SYNC_CATCHUP_LAG`, the device MUST make a catch-up object. |  |  |
| `DEV-237` | §7.5.1 | MUST | A device | A device MUST write the object on the chunk path of Part 13 §13.3.3 over the connection of Part 13 §13.8. |  |  |
| `DEV-238` | §7.5.1 | MUST | A device | A device MUST send the `FileDescriptor` of that object in a `DeviceSetControl` of `control_type` `0x04`. |  |  |
| `DEV-239` | §7.5.1 | MUST | A peer | A peer MUST apply each record of the object in causal order, and then acknowledge under §7.5.5. |  |  |
| `DEV-240` | §7.5.1 | MUST | A device | A device MUST continue the resend of §7.5.5 rule 3 for each record that the peer did not acknowledge. |  |  |
| `DEV-241` | §7.5.1 | MUST | (unstated) | While the bucket is empty, a client MUST show the message as waiting for the pacing clock. |  |  |
| `DEV-242` | §7.5.8 | MUST | A device that sends a timed record on a sync channel | A device that sends a timed record on a sync channel MUST put the remaining period in `expires_in`. |  |  |
| `DEV-243` | §7.5.8 | MUST | A device | A device MUST compute `expires_in` again at each send and at each resend of that record. |  |  |
| `DEV-244` | §7.5.8 | MUST | A device that takes a sync copy | A device that takes a sync copy MUST measure `expires_in` seconds from its own receive time of that copy. |  |  |
| `DEV-245` | §7.5.8 | MUST | A composing device | A composing device MUST measure the period from the moment it sent or gave the record. |  |  |
| `DEV-246` | §7.5.6 | MUST NOT | A device of the recipient that does not own the ratchet | A device of the recipient that does not own the ratchet MUST NOT measure the window. |  |  |
| `DEV-247` | §7.5.6 | MUST NOT | A ratchet owner | A ratchet owner MUST NOT forward a revision that it rejected to the device set. |  |  |
| `DEV-248` | §7.5.8 | MUST NOT | A member below the `admin` role of Part 11 §11.9 | A member below the `admin` role of Part 11 §11.9 MUST NOT set the timer of a private group. |  |  |
| `DEV-249` | §7.5.8 | MUST | A member | A member MUST reject a timer record from a member below that role. |  |  |
| `DEV-250` | §7.7 | MUST | The signer of an epoch with a new `revoked` entry | The signer of an epoch with a new `revoked` entry MUST make `seed_input` from its own CSPRNG. |  |  |
| `DEV-251` | §7.7 | MUST | That signer | That signer MUST send a `SyncSeedUpdate` to each device in `devices` on the sync channel of that pair. |  |  |
| `DEV-252` | §7.7 | MUST | A device | A device MUST derive `SyncChannelSeed_n+1` with the construction above, and Part 5 §5.11 holds the label. |  |  |
| `DEV-253` | §7.7 | MUST | A device | A device MUST discard a `SyncSeedUpdate` that the `signer_id` of the named epoch did not send. |  |  |
| `DEV-254` | §7.7 | MUST NOT | A device | A device MUST NOT change the seed at an epoch with no new `revoked` entry. |  |  |
| `DEV-255` | §7.7 | MUST NOT | A device | A device MUST NOT open a sync channel to a revoked device. |  |  |
| `DEV-256` | §7.7 | MUST | A device | A device MUST reject a sync channel from a revoked device. |  |  |
| `DEV-257` | §7.7 | MUST NOT | A device | After a device applies the epoch that revokes a device, it MUST NOT accept a sync record from that device. |  |  |
| `DEV-258` | §7.5.9 | MUST | A client | A client MUST default a 1:1 conversation to `all`. |  |  |
| `DEV-259` | §7.5.9 | MUST | A client | A client MUST default a new group at or below `T1_MAX` members to `all`. |  |  |
| `DEV-260` | §7.3.1 | MUST | A device | A device MUST count a claim record that holds a claim of scope `0x04` under `OWNER_CLAIM_RATE` in the same manner as a record of scope `0x01`. |  |  |
| `DEV-261` | §7.5.3 | MUST NOT | (unstated) | A client MUST hold the group-queue cursor of each replica as per-device state, and it MUST NOT put that cursor on a sync channel. |  |  |
| `DEV-262` | §7.7 | MUST | A device that applies an epoch with a new `revoked` entry | A device that applies an epoch with a new `revoked` entry MUST start the group re-key of Part 11 §11.12 for each group of the user. |  |  |
| `DEV-263` | §7.7.1 | MUST | A full identity reset | A full identity reset MUST also start the group re-key of Part 11 §11.12 in each group of the user. |  |  |
| `DEV-264` | §7.4 | MUST NOT | (unstated) | A web client of Part 15 §15.7 MUST link as a device of this section, and it MUST NOT make a `RootIdentity`. |  |  |
| `DEV-265` | §7.4 | MUST | (unstated) | When a web client returns to this flow after it lost its store, the existing device MUST revoke the old entry under §7.7 before step |  |  |
| `DEV-266` | §7.4 | MAY | The new device | The new device MAY show the QR code of step 1 in the place of the existing device. |  |  |
| `DEV-267` | §7.4 | MUST | In that direction the existing device | In that direction the existing device MUST show the label of the new device, and it MUST get an explicit confirmation from the user, before step 4. |  |  |
| `DEV-268` | §7.5.3 | MUST | A device | A device MUST carry a conversation record on a sync channel as a `SyncedRecord`, and it MUST take the class of that record from the kind of `inner`. |  |  |
| `DEV-269` | §7.5.3 | MUST | A parser | A parser MUST reject a `vector` that is not in strictly increasing `device_id` order, or that holds more than `MAX_DEVICES` entries. |  |  |
| `DEV-270` | §7.5.3 | MUST | A device | A device MUST apply a `MutableItem` when its `lamport` is above the value held, or equal with a lower `device_id` of the writer, and it MUST discard it otherwise. |  |  |
| `DEV-271` | §7.5.3 | MUST | A device | A device MUST give each `SyncedRecord` and each `MutableItem` that it sends the next value of its causal counter, which starts at 1. |  |  |
| `DEV-272` | §7.5.3 | MUST | The `vector` | The `vector` MUST hold the entry of the sender, and the `counter` of that entry is the causal counter of the record. |  |  |
| `DEV-273` | §7.5.3 | MUST | A receiver | A receiver MUST reject a record whose `vector` holds no entry of the device that the sync channel names. |  |  |
| `DEV-274` | §7.5.3 | MUST | The entry of each other device | The entry of each other device MUST carry the acknowledgment point of `DEV-055` that the sender holds for that device. |  |  |
| `DEV-275` | §7.5.3 | MUST | A device | A device MUST add one to its `lamport` before each send of a counted record. |  |  |
| `DEV-276` | §7.5.3 | MUST | A device | A device MUST reject a `SyncAck` whose `counter` is above its own causal counter, because no record holds that counter. |  |  |
| `DEV-277` | §7.5.3 | MUST | A device | A device MUST retain a `MutableItem` for the resend of §7.5.5 under a reference to its row and its key, and not under its bytes. |  |  |

## NTF — Notifications

Source: `spec/08-notifications.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `NTF-001` | §8.1 | MUST NOT | One infrastructure party | One infrastructure party MUST NOT hold a passive database of push-token bindings. |  |  |
| `NTF-002` | §8.2 | MUST | (unstated) | The hop from the queue relay to the NDR MUST use Oblivious HTTP (RFC 9458) or a second mix hop. |  |  |
| `NTF-003` | §8.2.2 | MUST NOT | Implementations | Implementations MUST NOT emit a variable-length payload. |  |  |
| `NTF-004` | §8.2.2 | MUST NOT | Implementations | Implementations MUST NOT put a field outside the AEAD envelope. |  |  |
| `NTF-005` | §8.2.4 | MUST NOT | A party | A party MUST NOT be able to derive the notifier ID from the `RecipientId` of the queue. |  |  |
| `NTF-006` | §8.2.4 | MUST NOT | A party | A party MUST NOT be able to derive the notifier ID from the `SenderId` of the queue. |  |  |
| `NTF-007` | §8.2.5 | MUST | (unstated) | The triple `(handle, k_tok, notifier_id)` MUST rotate each **7 days**. |  |  |
| `NTF-008` | §8.2.5 | MUST | The triple | The triple MUST also rotate at each change of the contact set. |  |  |
| `NTF-009` | §8.3 | MUST | The UI | The UI MUST show the trade in one honest line. |  |  |
| `NTF-010` | §8.3 | MUST NOT | (unstated) | the UI MUST NOT hide Private mode. |  |  |
| `NTF-011` | §8.3 | MUST | Onboarding | Onboarding MUST include a high-risk profile. |  |  |
| `NTF-012` | §8.4.1 | MUST NOT | A client | A client MUST NOT hold the push-wake session longer than 6 s. |  |  |
| `NTF-013` | §8.4.1 | MUST NOT | A client | A client MUST NOT build a spare circuit in a push-wake session. |  |  |
| `NTF-014` | §8.4.1 | MUST | A high-priority FCM message | A high-priority FCM message MUST always cause a notification that the user can see. |  |  |
| `NTF-017` | §8.4.3 | MUST | (unstated) | The response path for a message fetch MUST carry padding to a constant number of fixed cells. |  |  |
| `NTF-018` | §8.5 | MUST NOT | (unstated) | A busy community of 1000 members or more MUST NOT make one push for each message. |  |  |
| `NTF-019` | §8.5 | MUST | A queue relay | A queue relay MUST apply the window to each handle, whatever the class of the conversation behind it. |  |  |
| `NTF-027` | §8.7 | MUST | This text is normative, and it | The text of §8.7 is normative, and it MUST appear in the security documentation that the user reads. |  |  |
| `NTF-028` | §8.7 | MUST | (unstated) | The NDR of the nonprofit and its core queue relays MUST be in different legal jurisdictions. |  |  |
| `NTF-029` | §8.7 | MUST | The client | The client MUST let the user pin an NDR independently of the relays of that user. |  |  |
| `NTF-030` | §8.7 | MUST | The NDR | The NDR MUST publish a no-logging policy, a warrant canary, and a transparency log of its software builds. |  |  |
| `NTF-031` | §8.2.1 | MUST | A device | A device MUST make one `k_tok` and one `handle` for each group of at most `MAX_QUEUES_PER_HANDLE` queues. |  |  |
| `NTF-032` | §8.2.1 | MUST NOT | A device | A device MUST NOT put more than `MAX_QUEUES_PER_HANDLE` queues under one handle. |  |  |
| `NTF-033` | §8.2.1 | MUST | A device | A device MUST set `MAX_QUEUES_PER_HANDLE` equal to the `MAX_QUEUES_PER_SESSION` of Part 3 §3.2.5, which is 8. |  |  |
| `NTF-034` | §8.2.1 | MUST | A device | A device MUST divide its queues across handles again at each rotation of NTF-007. |  |  |
| `NTF-035` | §8.2.2 | MUST | An implementation | An implementation MUST bind `ver` and `epoch` as the associated data of the AEAD. |  |  |
| `NTF-036` | §8.2.2 | MUST | An implementation | An implementation MUST set each reserved bit of `flags` to zero. |  |  |
| `NTF-037` | §8.2.2 | MUST | A receiver | A receiver MUST reject a blob whose reserved bits are not zero. |  |  |
| `NTF-038` | §8.4.1 | MUST | A client | A client MUST carry a Private-mode wake over UnifiedPush or over a persistent socket. |  |  |
| `NTF-039` | §8.4.1 | MUST NOT | A client | A client MUST NOT carry a fixed-cadence wake over a high-priority FCM message. |  |  |
| `NTF-040` | §8.4.1 | MUST | A client that holds neither carrier | A client that holds neither carrier MUST show that Private mode is not available on that build. |  |  |
| `NTF-041` | §8.4.1 | MUST NOT | That client | That client MUST NOT show Private mode as active. |  |  |
| `NTF-043` | §8.2.6 | MUST | (unstated) | In Instant mode, a client MUST register a rendezvous queue under a notification handle of its own. |  |  |
| `NTF-044` | §8.2.6 | MUST NOT | A client | A client MUST NOT put a rendezvous queue and a pairwise queue under one `(handle, k_tok)` of §8.2.1. |  |  |
| `NTF-045` | §8.2.6 | MUST NOT | (unstated) | In Private mode, a client MUST NOT register a rendezvous queue with the Notification Delivery Relay. |  |  |
| `NTF-046` | §8.2.6 | MUST | (unstated) | In Private mode, a client MUST drain each rendezvous queue at least one time in each 24 h. |  |  |
| `NTF-047` | §8.2.6 | MUST | (unstated) | In Off mode, a client MUST drain each rendezvous queue at each foreground session. |  |  |
| `NTF-048` | §8.5 | MUST NOT | A queue relay | A queue relay MUST NOT hand a second push for one handle to the Notification Delivery Relay inside `WAKE_COALESCE_WINDOW`. |  |  |
| `NTF-049` | §8.5 | MUST | (unstated) | If an event arrives inside the window, the queue relay MUST hand one push at the end of the window. |  |  |
| `NTF-050` | §8.5 | MUST | A revision that changes `WAKE_COALESCE_WINDOW` | A revision that changes `WAKE_COALESCE_WINDOW` MUST derive the U3 target and the idle table of Part 3 §3.12 again. |  |  |
| `NTF-051` | §8.5 | MUST | An implementation | An implementation MUST measure the coalesced share in a real deployment before a revision re-tunes the window. |  |  |
| `NTF-052` | §8.3 | MUST | A client in Private mode | A client in Private mode MUST draw the phase of its fixed clock from the CSPRNG at each network change. |  |  |
| `NTF-053` | §8.3 | MUST | The client | The client MUST draw it again at each change of its ingress relay pair. |  |  |
| `NTF-065` | §8.4.3 | MUST | A queue relay | A queue relay MUST set the push expiry to `PUSH_TTL_MESSAGE` for a message push. |  |  |
| `NTF-066` | §8.4.3 | MUST | (unstated) | If no drain of a handle follows a message push inside `REPUSH_INTERVAL`, the queue relay MUST hand one more push. |  |  |
| `NTF-067` | §8.4.3 | MUST NOT | A queue relay | A queue relay MUST NOT hand more than `REPUSH_MAX` re-pushes for one message. |  |  |
| `NTF-068` | §8.4.3 | MUST | (unstated) | At each session open and at each session resume, a client MUST run the peek of Part 3 §3.7 item 4 on each queue of that session. |  |  |
| `NTF-069` | §8.5.1 | MUST | A client in Instant mode | A client in Instant mode MUST register one notification queue for each community at `mentions` or `all`. |  |  |
| `NTF-070` | §8.5.1 | MUST | A client | A client MUST put that queue under a notification handle of its own. |  |  |
| `NTF-071` | §8.5.1 | MUST | A client | A client MUST rotate that queue with the triple of `NTF-007`, and it MUST register the new queue before it drops the old one. |  |  |
| `NTF-072` | §8.5.1 | MUST NOT | A community relay | A community relay MUST NOT write more than `COMMUNITY_DIGEST_BUDGET` digests into one queue in one day. |  |  |
| `NTF-073` | §8.5.1 | MUST NOT | A community relay | A community relay MUST NOT write a digest into a queue when no post arrived since the previous digest to that queue. |  |  |
| `NTF-074` | §8.5.1 | MUST NOT | A client in Private mode or in Off mode | A client in Private mode or in Off mode MUST NOT register a community notification queue. |  |  |
| `NTF-075` | §8.2.3 | MUST | A receiver | A receiver MUST accept a blob whose `epoch` is inside the window. |  |  |
| `NTF-076` | §8.2.3 | MUST | A receiver | A receiver MUST reject a blob outside that window without an AEAD open. |  |  |
| `NTF-077` | §8.2.3 | MUST | A receiver | A receiver MUST count the consecutive failed opens of blobs inside the window. |  |  |
| `NTF-078` | §8.2.3 | MUST | (unstated) | At `NTF_FAIL_MAX` consecutive failures, the client MUST show the `clock` state of Part 15 §15.9.2. |  |  |
| `NTF-079` | §8.2.3 | MUST | One open that succeeds | One open that succeeds MUST reset the count. |  |  |
| `NTF-080` | §8.2.5 | MUST | A device | A device MUST rotate one handle group of §8.2.1 at a time. |  |  |
| `NTF-081` | §8.2.5 | MUST NOT | A device | A device MUST NOT rotate two handle groups inside one session. |  |  |
| `NTF-082` | §8.3 | MUST | The settings | The settings MUST offer the high-risk configuration, which selects Private notifications and disables the content preview. |  |  |
| `NTF-083` | §8.3 | MUST | A build | A build MUST ship Instant mode with the content preview off as the default of each Profile. |  |  |
| `NTF-084` | §8.2.3 | MUST | The client | The client MUST then establish `k_ntf_root` again at the next foreground session. |  |  |
| `NTF-086` | §8.4.3 | MUST | A queue relay | A queue relay MUST set it to `PUSH_TTL_DIGEST` for a digest push. |  |  |
| `NTF-087` | §8.3 | MUST | An implementation | An implementation MUST measure the wake cost of the fixed clock on a mid-range Android device, with a power monitor, before a revision re-tunes the cadence of Private mode. |  |  |
| `NTF-088` | §8.4.1 | MUST NOT | A party that dispatches a push | A party that dispatches a push MUST NOT set a collapse key on a message push. |  |  |
| `NTF-089` | §8.4.1 | MUST | An Android client | An Android client MUST group the tray by the conversation of `queue_alias` after the AEAD open, with a notification group of the platform. |  |  |
| `NTF-090` | §8.5.2 | MUST | A client in Instant mode | A client in Instant mode MUST make one notify queue for each group at `mentions` or `all`, on each device. |  |  |
| `NTF-091` | §8.5.2 | MUST | A client | A client MUST put a group notify queue under a notification handle that holds no pairwise queue and no rendezvous queue. |  |  |
| `NTF-092` | §8.5.2 | MAY | A client | A client MAY put a group notify queue and a community notify queue under one handle. |  |  |
| `NTF-093` | §8.5.2 | MUST | A client | A client MUST register the `QueueAddress` of the notify queue with each replica of the group queue by `GNREG`. |  |  |
| `NTF-094` | §8.5.2 | MUST NOT | A registration | A registration MUST NOT carry a member index, a pseudonym, or a device identifier. |  |  |
| `NTF-095` | §8.5.2 | MUST NOT | A group-queue relay | A group-queue relay MUST NOT link a registration to a reader session or to a writer session. |  |  |
| `NTF-096` | §8.5.2 | MUST | A group-queue relay | A group-queue relay MUST write one `NotifyDigest` as a `SEND` into each registered notify queue when it accepts a `GPOST`. |  |  |
| `NTF-097` | §8.5.2 | MUST NOT | A group-queue relay | A group-queue relay MUST NOT write a second digest to one registration inside `GROUP_DIGEST_MIN_GAP`. |  |  |
| `NTF-098` | §8.5.2 | MUST | If a record arrives inside the gap, the group-queue relay | If a record arrives inside the gap, the group-queue relay MUST write one digest at the end of the gap. |  |  |
| `NTF-099` | §8.5.2 | MUST NOT | A group-queue relay | A group-queue relay MUST NOT write a digest that names a record, a member index, or a sequence number. |  |  |
| `NTF-100` | §8.5.2 | MUST | A group-queue relay | A group-queue relay MUST hold a registration in memory only. |  |  |
| `NTF-101` | §8.5.2 | MUST NOT | A group-queue relay | A group-queue relay MUST NOT hold more than `GROUP_NOTIFIER_MAX` registrations for one group queue. |  |  |
| `NTF-102` | §8.5.2 | MUST | A group-queue relay | A group-queue relay MUST discard a registration 7 days plus `CLOCK_SKEW` after the `GNREG` that made it. |  |  |
| `NTF-103` | §8.5.2 | MUST | A group-queue relay | A group-queue relay MUST discard a registration at a `GNUNREG` that names its queue. |  |  |
| `NTF-104` | §8.5.2 | MUST | A client | A client MUST rotate a group notify queue with the triple of `NTF-007`. |  |  |
| `NTF-105` | §8.5.2 | MUST | A client | A client MUST register the new queue before it drops the old one. |  |  |
| `NTF-106` | §8.5.2 | MUST NOT | A client in Private mode or in Off mode | A client in Private mode or in Off mode MUST NOT register a group notify queue. |  |  |
| `NTF-107` | §8.5.2 | MUST | On a wake, a client | On a wake, a client MUST drain the notify queue under Part 6 §6.4.3. |  |  |
| `NTF-108` | §8.5.2 | MUST | The client | The client MUST then open a session to one replica of the group queue with `GSUB` from its cursor. |  |  |
| `NTF-109` | §8.7 | MAY | A deployment | A deployment MAY operate its own Notification Delivery Relay. |  |  |
| `NTF-110` | §8.6 | MUST NOT | A web client | A web client MUST NOT register a push token with the NDR, and it MUST NOT hold a registration of §8.5.1 or §8.5.2 of its own. |  |  |
| `NTF-111` | §8.6 | MUST | A web client | A web client MUST take each arrival from its live session, and it MUST show an alert through the notification API of the browser while the browser runs. |  |  |
| `NTF-112` | §8.2.3 | MUST | A queue relay | A queue relay MUST hold an `UMBRA-KEM` notification key pair, and it MUST answer the `NKEY` of a queue with an `NPK` that carries the public half, before the `NID`. |  |  |
| `NTF-113` | §8.2.3 | MUST | A device | A device MUST seal a `NotifyBinding` to that key with HPKE of AUX-6 in the base mode, with `"umbra/v1/ntf"` as the HPKE info and the `RecipientId` of the queue as the associated data, and MUST send it as the `NBIND` of that queue. |  |  |
| `NTF-114` | §8.2.3 | MUST NOT | (unstated) | A queue relay MUST seal the blobs of that queue under the fields of the binding, and it MUST NOT hold a binding after the queue is deleted or after the rotation of `NTF-007` replaces it. |  |  |
| `NTF-115` | §8.2 | MUST | The OHTTP of that hop | The OHTTP of that hop MUST use the HPKE of AUX-6, and its key configuration and its request header MUST carry the suite identifiers of Part 5 §5.4 in place of the registry values of RFC 9180. |  |  |
| `NTF-116` | §8.4.1 | MUST | A client that carries its wakes over a persistent socket | A client that carries its wakes over a persistent socket MUST hold that socket in a `specialUse` foreground service, with a notice that the user can see for the whole time. |  |  |
| `NTF-117` | §8.4.1 | MUST | That service | That service MUST hold no key and no socket of its own. |  |  |
| `NTF-118` | §8.4.1 | MUST | A client | A client MUST start a new run after a run ends with a fault, while a view is on the screen or the service runs. |  |  |
| `NTF-119` | §8.4.1 | MUST | A message alert | A message alert MUST show no text of the message and no name of a contact while the content preview is off (`NTF-083`). |  |  |
| `NTF-120` | §8.4.1 | MUST | A client | A client MUST end the service at a lock, because a locked client holds no key that reads a queue (Part 15 rule `IMP-127`). |  |  |
| `NTF-121` | §8.4.1 | MUST NOT | A record that arrives | A record that arrives MUST NOT start the idle time of the auto-lock again. |  |  |

## DIS — Discovery, Handles, and Key Transparency

Source: `spec/09-discovery.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `DIS-001` | §9.3.1 | MUST | A client | A client MUST re-encode a selected picture before it stores that picture in the blob. |  |  |
| `DIS-002` | §9.3.1 | MUST | The re-encode | The re-encode MUST remove each metadata field. |  |  |
| `DIS-003` | §9.3.1 | MUST | The re-encode | The re-encode MUST hold the result inside the `B2` bucket of 8 KiB. |  |  |
| `DIS-004` | §9.3.1 | MUST | (unstated) | If the user selects one picture for two Profiles, the client MUST warn. |  |  |
| `DIS-005` | §9.3.1 | MUST | The client | The client MUST get an explicit confirmation. |  |  |
| `DIS-006` | §9.3.1 | MUST NOT | A client | A client MUST NOT put a pet-avatar (§9.8) in the blob. |  |  |
| `DIS-007` | §9.5.1 | MUST | The VRF inputs | The VRF inputs MUST be `(label \|\| version)`, and not `label` alone. |  |  |
| `DIS-008` | §9.5.1 | MUST | The tree | The tree MUST use a **fresh tree-wide nonce at each epoch** (CONIKS §3.1). |  |  |
| `DIS-009` | §9.5.1 | MUST | The leaf | The leaf MUST commit to the **handle string** and not to the index. |  |  |
| `DIS-010` | §9.5.1 | MUST | There | There MUST be a maximum of **one update for each label in each epoch**. |  |  |
| `DIS-011` | §9.5.2 | MUST | A client | A client MUST reject a `SignedTreeHead` whose `timestamp` is more than `TREE_HEAD_FRESHNESS` plus `CLOCK_SKEW` before the device clock. |  |  |
| `DIS-012` | §9.5.4 | MUST | An implementation | An implementation MUST state this limit in its user-facing documentation. |  |  |
| `DIS-013` | §9.6 | MUST | (unstated) | After the upgrade, a contact from a handle MUST be bit-for-bit indistinguishable from a contact from a QR code. |  |  |
| `DIS-014` | §9.6 | MUST | The client | The client MUST poll the rendezvous queue through a **different relay chain** from the pairwise queues. |  |  |
| `DIS-015` | §9.6 | MUST | The client | The client MUST also poll that queue on a **different schedule**. |  |  |
| `DIS-016` | §9.8 | MUST NOT | A handle | A handle MUST NOT render as a verified identity. |  |  |
| `DIS-017` | §9.8 | MAY | The viewer | The viewer MAY also assign a picture to a contact. |  |  |
| `DIS-018` | §9.8 | MUST NOT | A client | A client MUST NOT send a pet-avatar to any party. |  |  |
| `DIS-019` | §9.8 | MUST | The client | The client MUST show the two values apart. |  |  |
| `DIS-020` | §9.8.1 | MUST NOT | A warning | A warning MUST NOT fire at each rotation of a handle key. |  |  |
| `DIS-021` | §9.8.1 | MUST | A warning | A warning MUST state the concrete next action. |  |  |
| `DIS-022` | §9.8.1 | MUST NOT | A warning | A warning MUST NOT show a fingerprint. |  |  |
| `DIS-023` | §9.7 | MUST | A client | A client MUST send one notice for each contact. |  |  |
| `DIS-024` | §9.7 | MUST NOT | A client | A client MUST NOT reuse one authenticated object across two contacts. |  |  |
| `DIS-025` | §9.8.1 | MUST | A client | A client MUST apply Part 4 §4.5.1 to a pairwise identity key, and IDN-025 makes that notice blocking. |  |  |
| `DIS-026` | §9.5.3 | MUST | A client | A client MUST carry a tree head as a `DigestBody` of Part 6 §6.6.4. |  |  |
| `DIS-027` | §9.5.3 | MUST NOT | A client | A client MUST NOT put a tree head in a field that this specification does not define. |  |  |
| `DIS-028` | §9.5.3 | MUST | A client | A client MUST emit at most one digest for each `source` in each `GOSSIP_INTERVAL`. |  |  |
| `DIS-029` | §9.5.3 | MUST | A client | A client MUST emit a digest in a scheduled cover slot of Part 3 §3.6.2 only. |  |  |
| `DIS-030` | §9.5.3 | MUST NOT | A client | A client MUST NOT open a session for the only purpose of a digest. |  |  |
| `DIS-031` | §9.5.3 | MUST | A client | A client MUST select the contact of a digest at random from the contacts that hold a live session. |  |  |
| `DIS-032` | §9.5.3 | MUST NOT | A client | A client MUST NOT send one digest to more than one contact in one cover slot. |  |  |
| `DIS-033` | §9.5.3 | MUST | A receiver | A receiver MUST compare a digest against the tree head that it holds at that `epoch`. |  |  |
| `DIS-034` | §9.5.3 | MUST | (unstated) | If the two values differ, a receiver MUST show a split-view warning. |  |  |
| `DIS-035` | §9.9.1 | MUST | A directory | A directory MUST encapsulate to the `HK_pub` that its current entry holds. |  |  |
| `DIS-036` | §9.9.1 | MUST | A directory | A directory MUST make `nonce` from its own CSPRNG for each renewal. |  |  |
| `DIS-037` | §9.9.1 | MUST | A holder | A holder MUST derive `k` with the label above, and Part 5 §5.11 holds that label. |  |  |
| `DIS-038` | §9.9.1 | MUST | A holder | A holder MUST answer with the HMAC-SHA3-256 over `nonce` under `k`. |  |  |
| `DIS-039` | §9.9.1 | MUST | A directory | A directory MUST compare `ans` in constant time. |  |  |
| `DIS-040` | §9.9.1 | MUST NOT | A directory | A directory MUST NOT renew a lease without a correct `ans`. |  |  |
| `DIS-041` | §9.9.1 | MUST NOT | A directory | A directory MUST NOT accept an `ans` for a `lease_epoch` that it did not issue. |  |  |
| `DIS-042` | §9.9.1 | MUST NOT | A directory | A directory MUST NOT retain `ss`, `k`, or `ans` after the renewal. |  |  |
| `DIS-043` | §9.5.2 | MUST | A signer | A signer MUST sign a `SignedTreeHead` with ML-DSA-65. |  |  |
| `DIS-044` | §9.5.2 | MUST NOT | An implementation | An implementation MUST NOT use a threshold signature construction for a tree head. |  |  |
| `DIS-045` | §9.5.2 | MUST | A signer | A signer MUST distribute a key set as a `SignedLogKeySet`. |  |  |
| `DIS-046` | §9.5.2 | MUST | A client | A client MUST compute `keyset_hash` over the `keyset` field alone. |  |  |
| `DIS-047` | §9.5.2 | MUST | The log operator | The log operator MUST make one `SignedTreeHead` for each epoch of the log. |  |  |
| `DIS-048` | §9.5.2 | MUST | The log operator | The log operator MUST sign each head under signer index `0`. |  |  |
| `DIS-049` | §9.5.2 | MUST | An auditor | An auditor MUST verify the consistency proof from the last head that it signed before it signs a head. |  |  |
| `DIS-050` | §9.5.2 | MUST | (unstated) | Before an auditor signs the head of an epoch, it MUST verify the rules of §9.5.1 over its update set. |  |  |
| `DIS-051` | §9.5.2 | MUST NOT | A signer | A signer MUST NOT sign two heads that hold one `tree_size`. |  |  |
| `DIS-052` | §9.5.2 | MUST | The directory | The directory MUST return the newest `SignedTreeHead` with each proof of §9.4 step 4. |  |  |
| `DIS-053` | §9.5.2 | MUST | A client | A client MUST verify an inclusion proof or an absence proof against the `root` of a head that it accepted. |  |  |
| `DIS-054` | §9.5.2 | MUST | A client | A client MUST reject a `sig_count` that is not 2 or 3. |  |  |
| `DIS-055` | §9.5.2 | MUST | A client | A client MUST reject a repeated `signer_index`. |  |  |
| `DIS-056` | §9.5.2 | MUST | A client | A client MUST reject a `signer_index` at or above `signer_count`. |  |  |
| `DIS-057` | §9.5.2 | MUST | A client | A client MUST reject a `sigs` list that is not in ascending order of `signer_index`. |  |  |
| `DIS-058` | §9.5.2 | MUST | A client | A client MUST verify each signature against the key at its `signer_index` in the `LogKeySet` that the client holds. |  |  |
| `DIS-059` | §9.5.2 | MUST | A client | A client MUST count 2 or more valid signatures before it accepts the head. |  |  |
| `DIS-060` | §9.5.2 | MUST | A client | A client MUST reject a `SignedTreeHead` whose `keyset_hash` differs from the hash of the `LogKeySet` that the client holds. |  |  |
| `DIS-061` | §9.5.2 | MUST | A client | A client MUST reject a `SignedTreeHead` whose `tree_size` is below the highest `tree_size` that the client accepted. |  |  |
| `DIS-062` | §9.5.2 | MUST | A client | A client MUST reject a `SignedTreeHead` whose `timestamp` is more than `CLOCK_SKEW` after the device clock. |  |  |
| `DIS-063` | §9.5.2 | MUST | A client | A client MUST retain each head that it accepted for `TREE_HEAD_RETAIN` after the acceptance. |  |  |
| `DIS-064` | §9.5.2 | MUST | A client | A client MUST accept a `LogKeySet` only with 2 or more valid ML-DSA-65 signatures from the previous key set. |  |  |
| `DIS-065` | §9.5.2 | MUST | A client | A client MUST reject a `LogKeySet` whose `keyset_epoch` is at or below the `keyset_epoch` that the client holds. |  |  |
| `DIS-066` | §9.5.2 | MUST | A client build | A client build MUST ship the genesis `LogKeySet`. |  |  |
| `DIS-067` | §9.5.2 | MUST | (unstated) | In the degraded read, a client MUST complete a lookup of §9.4. |  |  |
| `DIS-068` | §9.5.2 | MUST | (unstated) | In the degraded read, a client MUST show the result of a lookup as unverified. |  |  |
| `DIS-069` | §9.5.2 | MUST NOT | (unstated) | In the degraded read, a client MUST NOT send the hello of §9.6 step 2 without an explicit user confirmation. |  |  |
| `DIS-070` | §9.5.2 | MUST NOT | (unstated) | In the degraded read, a client MUST NOT replace a held `HK_pub` with a resolved value that differs. |  |  |
| `DIS-071` | §9.5.2 | MUST NOT | (unstated) | In the degraded read, a client MUST NOT show a split-view warning under `DIS-034`. |  |  |
| `DIS-072` | §9.5.3 | MUST | A client | A client MUST set `epoch` to the `tree_size` and `digest` to the `root` of the newest head that it accepted. |  |  |
| `DIS-073` | §9.9.2 | MUST | A directory | A directory MUST publish a tombstone as a version of the label whose `HK_pub` and `rendezvous` fields hold zero bytes. |  |  |
| `DIS-074` | §9.9.2 | MUST | A directory | A directory MUST hold the last `HK_pub` of a tombstoned label for `HANDLE_RESERVE` after the tombstone. |  |  |
| `DIS-075` | §9.9.2 | MUST NOT | (unstated) | During `HANDLE_RESERVE`, a directory MUST NOT register a tombstoned label to a party that fails the challenge of §9.9.1. |  |  |
| `DIS-076` | §9.9.2 | MUST | (unstated) | If the answer is correct, the directory MUST publish a new version of the label with the same `HK_pub`. |  |  |
| `DIS-077` | §9.9.2 | MUST | (unstated) | After `HANDLE_RESERVE`, a directory MUST publish a registration of the label as the next version after the tombstone version. |  |  |
| `DIS-078` | §9.9.2 | MUST | A client | A client MUST hold the `version` of the entry with each `HK_pub` that it holds for a handle. |  |  |
| `DIS-079` | §9.9.2 | MUST | (unstated) | Before a client replaces a held `HK_pub`, it MUST fetch each label version between the held and the resolved `version`. |  |  |
| `DIS-080` | §9.9.2 | MUST | (unstated) | If that count is above `HANDLE_HISTORY_MAX`, the client MUST show the takeover warning. |  |  |
| `DIS-081` | §9.9.2 | MUST | (unstated) | If a tombstone version lies between the two, the client MUST compare the `HK_pub` before it with the `HK_pub` after it. |  |  |
| `DIS-082` | §9.9.2 | MUST | (unstated) | If the two differ, the client MUST show the takeover warning. |  |  |
| `DIS-083` | §9.9.2 | MUST NOT | A client | A client MUST NOT apply `DIS-020` to the takeover warning. |  |  |
| `DIS-084` | §9.9.2 | MUST | The takeover warning | The takeover warning MUST state that a different party now holds the handle. |  |  |
| `DIS-085` | §9.9.2 | MUST NOT | (unstated) | Under the takeover warning, a client MUST NOT send the hello of §9.6 step 2 without an explicit user confirmation. |  |  |
| `DIS-086` | §9.6 | MUST | A client | A client MUST put a fresh set of the fields of Part 5 §5.4.1 in each hello. |  |  |
| `DIS-087` | §9.6 | MUST | A client that accepts a request | A client that accepts a request MUST send flight 1 of Part 5 §5.4.2 to the `queue_address` of those fields. |  |  |
| `DIS-088` | §9.3.2 | MUST | A client | A client MUST apply the `UsernameCaseMapped` profile of RFC 8265 to the `name` part before each use of a handle. |  |  |
| `DIS-089` | §9.3.2 | MUST | A client | A client MUST reject a `name` part that the profile rejects. |  |  |
| `DIS-090` | §9.3.2 | MUST | A client | A client MUST measure the 32-byte limit of §9.3 on the output of the profile. |  |  |
| `DIS-091` | §9.3.2 | MUST | A directory | A directory MUST reject a registration whose `name` part changes under the profile. |  |  |
| `DIS-092` | §9.3.2 | MUST | A client | A client MUST use the canonical handle at each use of `<handle>` in this part. |  |  |
| `DIS-093` | §9.9.3 | MUST | A directory | Before a directory publishes a new version of an existing label, it MUST run the challenge above. |  |  |
| `DIS-094` | §9.9.3 | MUST | A directory | A directory MUST encapsulate to the `HK_pub` of the current version. |  |  |
| `DIS-095` | §9.9.3 | MUST | A holder | A holder MUST derive `k` with the label above, and Part 5 §5.11 holds that label. |  |  |
| `DIS-096` | §9.9.3 | MUST | A holder | A holder MUST compute `ans` over `nonce` and `SHA3-256(entry_new)`. |  |  |
| `DIS-097` | §9.9.3 | MUST | A directory | A directory MUST compare `ans` in constant time. |  |  |
| `DIS-098` | §9.9.3 | MUST NOT | A directory | A directory MUST NOT publish `entry_new` without a correct `ans`. |  |  |
| `DIS-099` | §9.9.3 | MUST NOT | A directory | A directory MUST NOT publish an `entry_new` whose `version` is not the current version plus one. |  |  |
| `DIS-100` | §9.9.3 | MUST NOT | A directory | A directory MUST NOT retain `ss`, `k`, or `ans` after the write. |  |  |
| `DIS-101` | §9.9.3 | MUST | A registration of a label that no version holds | A registration of a label that no version holds MUST carry the token of §9.9, and it needs no challenge. |  |  |
| `DIS-102` | §9.9.3 | MUST NOT | A directory | A directory MUST NOT run the challenge for the tombstone of a lapsed lease. |  |  |
| `DIS-103` | §9.3.3 | MUST NOT | A client | A client MUST NOT publish an `AddressEntry` without an explicit act of the user for that Public Address. |  |  |
| `DIS-104` | §9.3.3 | MUST | A client | A client MUST set `address_pk` to the public half of the `PublicAddressKey_j` whose hash is `address`. |  |  |
| `DIS-105` | §9.3.3 | MUST | A client that reads an `AddressEntry` | A client that reads an `AddressEntry` MUST compute `SHA3-256(address_pk)[0..20]`. |  |  |
| `DIS-106` | §9.3.3 | MUST NOT | A client | A client MUST NOT name one rendezvous queue in an `AddressEntry` and in a `DirectoryEntry`. |  |  |
| `DIS-107` | §9.3.3 | MUST | A client | A client MUST poll the rendezvous queue of an `AddressEntry` under `DIS-014` and `DIS-015`. |  |  |
| `DIS-108` | §9.3.3 | MUST | An `AddressEntry` | An `AddressEntry` MUST use the registration, the lease, the tombstone, the renewal, and the write authorization of §9.9. |  |  |
| `DIS-109` | §9.3.3 | MUST NOT | A directory | A directory MUST NOT serve a list of the address labels. |  |  |
| `DIS-110` | §9.6 | MUST | A client | A client MUST encapsulate that hello to `address_pk`. |  |  |
| `DIS-111` | §9.12 | MUST | A directory | A directory MUST verify that `SHA3-256("umbra/v1/community-id" \|\| admission \|\| actor_pk)` equals `community_id`, and that `SHA3-256(actor_pk)` equals `actor`. |  |  |
| `DIS-112` | §9.12 | MUST | A directory | A directory MUST verify the signature under `actor_pk`. |  |  |
| `DIS-113` | §9.12 | MUST NOT | A directory | A directory MUST NOT publish a listing that fails either check. |  |  |
| `DIS-114` | §9.12 | MUST NOT | A directory | A directory MUST NOT publish a listing whose `listing_index` is not the current index plus one. |  |  |
| `DIS-115` | §9.12 | MUST | A listing | A listing MUST carry the token of §9.9 at each publication. |  |  |
| `DIS-116` | §9.12 | MUST | A directory | A directory MUST remove a listing at `LISTING_LEASE` after its acceptance, unless a later listing replaced it. |  |  |
| `DIS-117` | §9.12 | MUST | An owner client | An owner client MUST set `activity` from the chains that the client pulled under Part 12 §12.3.3. |  |  |
| `DIS-118` | §9.12 | MUST | An owner client | An owner client MUST set `category`, `language`, and `name` to the values of the current `CommunityMeta`. |  |  |
| `DIS-119` | §9.12 | MUST | A directory | A directory MUST rank the listings of an answer by `activity` from high to low. |  |  |
| `DIS-120` | §9.12 | MUST NOT | A directory | A directory MUST NOT put more than `LISTING_PAGE` listings in one page. |  |  |
| `DIS-121` | §9.12 | MUST | A directory | A directory MUST match `prefix` against the `name` after the `UsernameCaseMapped` profile of §9.3.2 on both strings. |  |  |
| `DIS-122` | §9.12 | MUST | A browse | A browse MUST carry one first-party token of §9.4.1. |  |  |
| `DIS-123` | §9.12 | MUST | A client | A client MUST verify `DIS-111` and `DIS-112` on each listing that it shows. |  |  |
| `DIS-124` | §9.12 | MUST | A client | A client MUST show a listing as unverified until the `CommunityMeta` of the link verifies under Part 12 §12.7.1. |  |  |
| `DIS-125` | §9.12 | MUST | A client | A client MUST compare `activity` with the chains that it pulls after the join. |  |  |
| `DIS-126` | §9.12 | MUST | (unstated) | If the pulled chains show a lower bucket, the client MUST show that difference beside the listing. |  |  |
| `DIS-127` | §9.12 | MUST NOT | A directory | A directory MUST NOT put a listing with `link_len` 0 in a page. |  |  |
| `DIS-128` | §9.3.3 | MUST NOT | The client | The client MUST NOT use an entry whose result differs from `address`. |  |  |
| `DIS-129` | §9.3.3 | MUST NOT | A directory | A directory MUST NOT answer a query that names a prefix of an address. |  |  |
| `DIS-130` | §9.12 | MUST | A directory | Inside one bucket, a directory MUST rank by the acceptance time from new to old. |  |  |
| `DIS-131` | §9.6 | MUST | A client | A client MUST end a hello with one `Admission` of Part 14 §14.2, inside the AEAD of the hello. |  |  |
| `DIS-132` | §9.6 | MUST | That `Admission` | That `Admission` MUST hold a cross-relay token of Part 14 §14.3.1 or a `PowSolution` of Part 14 §14.4. |  |  |
| `DIS-133` | §9.9 | MUST | A client | A client MUST publish a new rendezvous queue for each published entry at each `RENDEZVOUS_ROTATE`. |  |  |
| `DIS-134` | §9.9 | MUST | The client | The client MUST keep the previous queue for `ROTATE_GRACE` of Part 3 §3.2.6 after the write. |  |  |
| `DIS-135` | §9.9 | MUST | The client | The client MUST drain both queues under Part 8 §8.2.6 during that period. |  |  |
| `DIS-136` | §9.5.3 | MUST | (unstated) | If the receiver holds no head at that `epoch`, it MUST fetch the co-signed head of that `epoch` before the comparison. |  |  |
| `DIS-137` | §9.5.2 | MUST | A client that holds a published label | A client that holds a published label MUST fetch the inclusion proof of its newest version at each head that it accepts. |  |  |
| `DIS-138` | §9.5.2 | MUST | (unstated) | If that version differs from the version that the client published, the client MUST show the takeover warning of §9.9.2. |  |  |
| `DIS-139` | §9.5.2 | MUST NOT | The client | The client MUST NOT publish a new version over a version that it did not publish, without a user action. |  |  |
| `DIS-140` | §9.3 | MUST | A `DirectoryEntry` on the wire | A `DirectoryEntry` on the wire MUST be `handle_len u8 || handle || HK_pub [1216]u8 || rendezvous [129]u8 || version u32`, with the canonical handle of §9.3.2 in `handle` and the `QueueAddress` of Part 6 §6.6.10 in `rendezvous`. |  |  |
| `DIS-141` | §9.3.1 | MUST | A client | A client MUST seal the profile blob as `0x01 || nonce [24]u8 || XChaCha20-Poly1305(blob key, nonce, profile, ad = <handle>)`, with the canonical handle as the associated data and the nonce from the device CSPRNG. |  |  |
| `DIS-142` | §9.5.2 | MUST | Each `sig` | Each `sig` MUST cover `"umbra/v1/tree-head" || version || tree_size || timestamp || root keyset_hash`, which is the label and then each field before `sig_count`. |  |  |
| `DIS-143` | §9.6 | MUST | A client | A client MUST seal a hello as `0x01 || ct || nonce [24]u8 || XChaCha20-Poly1305(K_hello, nonce, body, ad = ct)`, where `(ct, ss) = UMBRA-KEM.Encap(entry_pk)`, `K_hello = HKDF-SHA3-256(salt = "", ikm = ss, info = "umbra/v1/hello" || entry_pk, L = 32)`, and `entry_pk` is the key of the entry that the initiator resolved. |  |  |
| `DIS-144` | §9.9.1 | MUST NOT | A directory | A directory MUST NOT accept an `ans` for a `lease_epoch` that it issued before the current version of the label was published. |  |  |
| `DIS-145` | §9.5.1 | MUST | The VRF input of a version | The VRF input of a version MUST be `search_key || BE32(version)`, where `search_key` is the VOPRF output over the label input. |  |  |
| `DIS-146` | §9.5.1 | MUST | The first version of a label | The first version of a label MUST be 0, and each next version MUST be one above the version before it. |  |  |
| `DIS-147` | §9.5.1 | MUST NOT | (unstated) | The log operator MUST compute each hash of the prefix tree under the nonce of the epoch, and it MUST NOT use one nonce in two epochs. |  |  |
| `DIS-148` | §9.5.1 | MUST NOT | The log operator | The log operator MUST NOT change a leaf and MUST NOT remove a leaf. |  |  |
| `DIS-149` | §9.5.1 | MUST | A client | A client MUST reject a `LookupProof` whose `tree_size` differs from the `tree_size` of the accepted head. |  |  |
| `DIS-150` | §9.5.1 | MUST | A client | A client MUST recompute `log_leaf_e` from `nonce` and `prefix_root`, and it MUST verify it under the `root` of that head with `log_path`. |  |  |
| `DIS-151` | §9.5.1 | MUST | A client | A client MUST reject a `log_path` with a `side` of 0x01. |  |  |
| `DIS-152` | §9.5.1 | MUST | A client | A client MUST compute the ladder from `found` and `newest`, and it MUST reject a proof whose `steps` differ from that ladder in count. |  |  |
| `DIS-153` | §9.5.1 | MUST | For each step, a client | For each step, a client MUST verify `vrf_proof` under the VRF key of the directory, and it MUST verify the prefix proof at the index that the VRF gives. |  |  |
| `DIS-154` | §9.5.1 | MUST | A client | A client MUST reject a proof where a present version shows no leaf, or an absent version shows one. |  |  |
| `DIS-155` | §9.5.1 | MUST | Under terminal 0x02, a client | Under terminal 0x02, a client MUST reject an `other_index` that equals the index of the step, or that differs from it in the first `sibling_count` bits. |  |  |
| `DIS-156` | §9.5.1 | MUST | A client | A client MUST recompute `commitment` from `opening` and `entry`, and it MUST reject a proof whose step at `newest` holds another value. |  |  |
| `DIS-157` | §9.5.1 | MUST | A client | A client MUST reject a `DirectoryEntry` whose `handle` differs from the canonical handle of the query, or whose `version` differs from `newest`. |  |  |
| `DIS-158` | §9.5.1 | MUST | A client build | A client build MUST ship the ECVRF public key of the directory beside the genesis `LogKeySet` of `DIS-066`. |  |  |
| `DIS-159` | §9.5.1 | MUST | A client that retains an accepted head | A client that retains an accepted head MUST verify a consistency proof from that head before it accepts a head with a higher `tree_size`. |  |  |
| `DIS-160` | §9.5.1 | MUST | A client | A client MUST reject a head whose `tree_size` equals the `tree_size` of a retained head and whose `root` differs. |  |  |
| `DIS-161` | §9.5.1 | MUST | Before an auditor signs the head of an epoch, it | Before an auditor signs the head of an epoch, it MUST verify that the nonce of the epoch is new, that each new leaf sits at an index that held no leaf, and that the log tree is the tree it signed last with one leaf more. |  |  |

## REL — Relay Directory

Source: `spec/10-relay-directory.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `REL-001` | §10.2 | MAY | A class | A class **MAY increase by a maximum of one step in each 7-day epoch**. |  |  |
| `REL-002` | §10.3 | MUST | A relay | A relay MUST decrypt each `MEAS_ECHO` cell that a measurer sends to it. |  |  |
| `REL-003` | §10.3 | MUST | That relay | That relay MUST then re-emit that cell to the measurer. |  |  |
| `REL-004` | §10.4 | MUST | The directory | The directory MUST size the detection window for that rate. |  |  |
| `REL-005` | §10.4.1 | MUST | In that case a probe | In that case a probe MUST be **VRF-selected and cryptographically committed**. |  |  |
| `REL-006` | §10.4.1 | MUST | The directory | The directory MUST show the probe only after the epoch closes. |  |  |
| `REL-007` | §10.5 | MUST | A client | A client MUST verify the 5-of-7 multi-signature of §10.5.2. |  |  |
| `REL-008` | §10.5 | MUST | A client | A client MUST also gossip the consensus digest in band, over the existing queue traffic and loop traffic. |  |  |
| `REL-009` | §10.5 | MUST | A client | A client MUST fetch the `RelaySetDiff` of §10.5.3 only when the radio is on for another cause (Part 3 §3.6.2). |  |  |
| `REL-010` | §10.5 | MUST NOT | A client | A client MUST NOT open a session for the only purpose of a directory diff. |  |  |
| `REL-011` | §10.6 | MUST | A client | A client MUST reject a chain when two of its relays share an item of the §10.6 list. |  |  |
| `REL-012` | §10.6 | MUST | Directory authorities | Directory authorities MUST verify the dossier before the first listing. |  |  |
| `REL-013` | §10.6 | MUST | They | They MUST verify it again at a material change. |  |  |
| `REL-014` | §10.6.2 | MUST NOT | A client | A client MUST NOT replace a relay because of a local performance measurement. |  |  |
| `REL-015` | §10.6.2 | MUST NOT | The client | The client MUST NOT select "the fastest peer that I have seen". |  |  |
| `REL-016` | §10.6.2 | MUST | A client | A client MUST report **repeated forced replacement to the directory as a link fault**. |  |  |
| `REL-017` | §10.6.2 | MUST NOT | A client | A client MUST NOT absorb such an event silently. |  |  |
| `REL-018` | §10.8 | MUST | That statistic | That statistic MUST pass through **two-aggregator additive secret sharing and Laplace noise**. |  |  |
| `REL-019` | §10.8 | MUST NOT | A directory authority | A directory authority MUST NOT publish a raw per-relay counter. |  |  |
| `REL-020` | §10.8 | MUST | A directory authority | A directory authority MUST publish the noised value only. |  |  |
| `REL-021` | §10.9.1 | MUST | An operator | An operator MUST size the outbound budget of a queue relay against 7 200 cells. |  |  |
| `REL-022` | §10.9.1 | MUST NOT | An operator | An operator MUST NOT size that budget against the real message count. |  |  |
| `REL-023` | §10.9.1 | MUST | An operator | An operator MUST size the byte budget of that session against 4 071 936 bytes. |  |  |
| `REL-024` | §10.9.1 | MUST NOT | An operator | An operator MUST NOT size that budget at the `B0` cost of all 7 200 cells. |  |  |
| `REL-025` | §10.5.2 | MUST | A directory authority | A directory authority MUST sign a `DirectoryRoot` with ML-DSA-65. |  |  |
| `REL-026` | §10.5.2 | MUST NOT | An implementation | An implementation MUST NOT use a threshold signature construction. |  |  |
| `REL-027` | §10.5.2 | MUST | A client | A client MUST reject a `sig_count` below 5 or above 7. |  |  |
| `REL-028` | §10.5.2 | MUST | A client | A client MUST reject a repeated `authority_index`. |  |  |
| `REL-029` | §10.5.2 | MUST | A client | A client MUST reject an `authority_index` at or above `authority_count`. |  |  |
| `REL-030` | §10.5.2 | MUST | A client | A client MUST reject a `sigs` list that is not in ascending order of `authority_index`. |  |  |
| `REL-031` | §10.5.2 | MUST | A client | A client MUST verify each signature against the key at its `authority_index` in the key set that the client holds. |  |  |
| `REL-032` | §10.5.2 | MUST | A client | A client MUST count 5 or more **valid** signatures before it accepts the object. |  |  |
| `REL-033` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryRoot` whose `keyset_hash` differs from the hash of the key set that the client holds. |  |  |
| `REL-034` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryRoot` whose `epoch` is below the highest epoch that the client verified. |  |  |
| `REL-035` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryRoot` whose `epoch_start_unix` is more than `CONSENSUS_VALIDITY` plus `CLOCK_SKEW` before the client clock. |  |  |
| `REL-036` | §10.5.2 | MUST | A client | A client MUST accept a `DirectoryKeySet` only with 5 or more valid ML-DSA-65 signatures from the **previous** key set. |  |  |
| `REL-037` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryKeySet` whose `keyset_epoch` is at or below the `keyset_epoch` that the client holds. |  |  |
| `REL-038` | §10.5.2 | MUST | (unstated) | The offline recovery arrangement MUST hold one key of the 7. |  |  |
| `REL-039` | §10.5.2 | MUST | A client build | A client build MUST ship the genesis `DirectoryKeySet`. |  |  |
| `REL-040` | §10.3 | MUST | A measurer | A measurer MUST send a `MEAS_ECHO` cell in bucket `B0`. |  |  |
| `REL-041` | §10.3 | MUST | A relay | A relay MUST reject a `MEAS_ECHO` cell in a different bucket, because a larger bucket turns the echo into an amplifier. |  |  |
| `REL-042` | §10.5.2 | MUST | A directory authority | A directory authority MUST distribute a key set as a `SignedKeySet`. |  |  |
| `REL-043` | §10.5.2 | MUST | A client | A client MUST compute `keyset_hash` over the `keyset` field alone, and it MUST NOT include `sig_count` or `sigs` in that hash. |  |  |
| `REL-044` | §10.5.2 | MUST | (unstated) | If an accepted `DirectoryRoot` starts more than `CLOCK_SKEW` after the client clock, a client MUST record a new correction. |  |  |
| `REL-045` | §10.5.2 | MUST | A client build | A client build MUST ship the epoch number that held at the build time. |  |  |
| `REL-046` | §10.5.2 | MUST | A client with no verified epoch | A client with no verified epoch MUST reject a `DirectoryRoot` whose `epoch` is below that shipped number. |  |  |
| `REL-047` | §10.5.3 | MUST | A relay | A relay MUST publish its descriptor in the encoding above. |  |  |
| `REL-048` | §10.5.3 | MUST | A relay | A relay MUST sign the descriptor with `identity_pk` over this preimage, and Part 5 §5.11 holds the label. |  |  |
| `REL-049` | §10.5.3 | MUST | A relay | A relay MUST set `relay_id` to `SHA3-256(identity_pk)`. |  |  |
| `REL-050` | §10.5.3 | MUST | A client | A client MUST reject a descriptor whose `relay_id` differs from that hash. |  |  |
| `REL-051` | §10.5.3 | MUST | A client | A client MUST verify `sig` against `identity_pk` before it uses any field of a descriptor. |  |  |
| `REL-052` | §10.5.3 | MUST | A directory authority | A directory authority MUST prefix a leaf hash with `0x00` and a node hash with `0x01`. |  |  |
| `REL-053` | §10.5.3 | MUST NOT | An implementation | An implementation MUST NOT compute a leaf hash and a node hash under one construction. |  |  |
| `REL-054` | §10.5.3 | MUST | A directory authority | A directory authority MUST order the leaves by `relay_id`, from the lowest value to the highest value. |  |  |
| `REL-055` | §10.5.3 | MUST NOT | That authority | That authority MUST NOT put two leaves with one `relay_id` in one tree. |  |  |
| `REL-056` | §10.5.3 | MUST | A directory authority | A directory authority MUST carry the last node of a level with an odd node count to the next level without a change. |  |  |
| `REL-057` | §10.5.3 | MUST | A client | A client MUST verify the inclusion proof of an entry before it selects the relay of that entry. |  |  |
| `REL-058` | §10.5.3 | MUST | A client | A client MUST reject an entry with no inclusion proof. |  |  |
| `REL-059` | §10.5.3 | MUST | (unstated) | If the entry width, the relay count, or the fetch schedule changes, a revision MUST derive both rows again. |  |  |
| `REL-060` | §10.5.4 | MUST | A client | A client MUST compute the layer of each candidate for hop 2 and hop 3 with the function above. |  |  |
| `REL-061` | §10.5.4 | MUST | A client | A client MUST compute the layer again each time it accepts a `DirectoryRoot`. |  |  |
| `REL-062` | §10.5.4 | MUST NOT | A relay | A relay MUST NOT declare its own layer, and a descriptor carries no layer field. |  |  |
| `REL-063` | §10.5.3 | MUST NOT | That authority | That authority MUST NOT duplicate that node. |  |  |
| `REL-064` | §10.3.1 | MUST | A measurer | A measurer MUST open a measurement session with a `MEAS_OPEN` cell. |  |  |
| `REL-065` | §10.3.1 | MUST | A measurer | A measurer MUST carry a `MeasurerCert` and a signature over the circuit identifier in that cell. |  |  |
| `REL-066` | §10.3.1 | MUST | A relay | A relay MUST verify each signature of the certificate against the key set of the current `DirectoryRoot`. |  |  |
| `REL-067` | §10.3.1 | MUST | A relay | A relay MUST reject a certificate whose `not_after` is below the current consensus epoch. |  |  |
| `REL-068` | §10.3.1 | MUST | A relay | A relay MUST reject a `MEAS_ECHO` cell that arrives outside an open measurement session. |  |  |
| `REL-069` | §10.3.1 | MUST | A relay | A relay MUST rate-limit a rejected measurement attempt, and it MUST NOT answer above that rate. |  |  |
| `REL-070` | §10.3.1 | MUST | A directory authority | A directory authority MUST issue a `MeasurerCert` with a lifetime of `MEASURER_CERT_TTL` or less. |  |  |
| `REL-071` | §10.4.2 | MUST | A relay | A relay MUST issue a `LinkReceipt` for each batch of `RECEIPT_WINDOW` cells that it takes from an adjacent relay. |  |  |
| `REL-072` | §10.4.2 | MUST | A relay | A relay MUST sign that receipt with the `identity_pk` of its descriptor. |  |  |
| `REL-073` | §10.4.2 | MUST | A relay | A relay MUST retain each receipt that it issued and each receipt that it took, for `RECEIPT_RETENTION`. |  |  |
| `REL-074` | §10.4.2 | MUST | A relay | A relay MUST erase a receipt after that period. |  |  |
| `REL-075` | §10.4.2 | MUST NOT | A relay | A relay MUST NOT put a client address, a queue identifier, or a payload byte in a receipt. |  |  |
| `REL-076` | §10.4.2 | MUST | A client | A client MUST send a `LinkFaultReport` when its loop-failure rate on one chain reaches `LOOP_FAULT_RATE` in one epoch. |  |  |
| `REL-077` | §10.4.2 | MUST NOT | A client | A client MUST NOT sign a `LinkFaultReport`. |  |  |
| `REL-078` | §10.4.2 | MUST | A client | A client MUST carry a `LinkFaultReport` in a scheduled cover slot or in a push-wake session. |  |  |
| `REL-079` | §10.4.2 | MUST NOT | A client | A client MUST NOT open a session for the only purpose of a `LinkFaultReport`. |  |  |
| `REL-080` | §10.4.2 | MUST | A directory authority | A directory authority MUST run an isolation query on a relay whose fault rate reaches `RELAY_FAULT_RATE` in one epoch. |  |  |
| `REL-081` | §10.4.2 | MUST | That authority | That authority MUST then request the receipt that covers the probe cell from each relay of the circuit. |  |  |
| `REL-082` | §10.4.2 | MUST | A relay | A relay MUST give its receipts to a directory authority at an isolation query. |  |  |
| `REL-083` | §10.4.2 | MUST | A directory authority | A directory authority MUST expel a relay that makes a contradiction at an isolation query. |  |  |
| `REL-084` | §10.4.2 | MUST | (unstated) | If the query does not name one relay, a directory authority MUST remove the link and it MUST NOT remove either relay. |  |  |
| `REL-085` | §10.6.3 | MUST | A relay | A relay MUST sign the family certificate of each family that it declares, with the `identity_pk` of its own descriptor. |  |  |
| `REL-086` | §10.6.3 | MUST | A relay | A relay MUST set `family_id` of its descriptor to the SHA3-256 of that certificate. |  |  |
| `REL-087` | §10.6.3 | MUST | A directory authority | A directory authority MUST verify each signature of a family certificate before it lists a member. |  |  |
| `REL-088` | §10.6.3 | MUST | A directory authority | A directory authority MUST reject a certificate whose `sig_count` differs from `member_count`. |  |  |
| `REL-089` | §10.6.3 | MUST | A directory authority | A directory authority MUST reject a certificate that does not name the relay whose descriptor carries its hash. |  |  |
| `REL-090` | §10.6.3 | MUST | A directory authority | A directory authority MUST retain the family certificate of each `family_id` that a listed descriptor names. |  |  |
| `REL-091` | §10.6.3 | MUST | A directory authority | A directory authority MUST publish the bloc list as a `BlocList` beside each `DirectoryRoot`. |  |  |
| `REL-092` | §10.6.3 | MUST | A client | A client MUST take the bloc of a relay from that list and from the `jurisdiction` field of the descriptor. |  |  |
| `REL-093` | §10.6.3 | MUST | A client | A client MUST treat a code that no bloc names as a bloc of its own. |  |  |
| `REL-094` | §10.6.3 | MUST NOT | A directory authority | A directory authority MUST NOT change the bloc list without the 5-of-7 signature of §10.5.2. |  |  |
| `REL-095` | §10.2 | MUST | (unstated) | If a class test verifies below the `class` of the entry, the directory MUST set `class` to the verified class. |  |  |
| `REL-096` | §10.2 | MUST NOT | A directory authority | A directory authority MUST NOT apply a staging delay or a step limit to a demotion. |  |  |
| `REL-097` | §10.2 | SHOULD | A directory authority | A directory authority SHOULD measure each relay above C0 one time in each `MEASURE_INTERVAL`. |  |  |
| `REL-098` | §10.2 | MUST | (unstated) | If a relay has no verifying report inside `MEASURE_STALE`, a directory authority MUST set its `class` to C0. |  |  |
| `REL-099` | §10.3 | MUST | (unstated) | If a cluster holds `CLUSTER_FULL` relays or fewer, the directory MUST measure the full cluster in one slot. |  |  |
| `REL-100` | §10.3 | MUST | (unstated) | If a cluster holds more than `CLUSTER_FULL` relays, the directory MUST select `CLUSTER_SAMPLE` relays of it for each slot. |  |  |
| `REL-101` | §10.3 | MUST | The directory | The directory MUST measure each relay of such a cluster inside `ceil(n / CLUSTER_SAMPLE)` slots. |  |  |
| `REL-102` | §10.3 | MUST | The directory | The directory MUST show the selection of a slot only after the epoch closes. |  |  |
| `REL-103` | §10.3.1 | MUST | A relay | A relay MUST count 2 or more valid signatures under different `authority_index` values before it accepts a `MeasurerCert`. |  |  |
| `REL-104` | §10.3.1 | MUST | A relay | A relay MUST reject a `MeasurerCert` whose `measurer_id` the `revoked` list of the current `DirectoryRoot` names. |  |  |
| `REL-105` | §10.3.1 | MUST | (unstated) | If a measurer key is lost or compromised, a directory authority MUST put its `measurer_id` in `revoked`. |  |  |
| `REL-106` | §10.3.1 | MUST | A directory authority | A directory authority MUST keep that entry in `revoked` until the `not_after` of the certificate passes. |  |  |
| `REL-107` | §10.4.2 | MUST NOT | A client | A client MUST NOT send more than one `LinkFaultReport` in one push-wake session. |  |  |
| `REL-108` | §10.4.2 | MAY | A directory authority | A directory authority MAY run an isolation query on one link on its own evidence. |  |  |
| `REL-109` | §10.4.2 | MUST | (unstated) | At an isolation query, a directory authority MUST build a circuit through the relay under query and its reported neighbor. |  |  |
| `REL-110` | §10.4.2 | MUST | That authority | That authority MUST send a loop cell on that circuit. |  |  |
| `REL-111` | §10.4.2 | MUST | That authority | That authority MUST record the `circ_id` and the `tag` of the probe cell at each hop. |  |  |
| `REL-112` | §10.4.2 | MUST NOT | A directory authority | A directory authority MUST NOT run that query from fewer than `FAULT_MIN_REPORTS` reports. |  |  |
| `REL-113` | §10.5.2 | MUST NOT | A client with no correction | A client with no correction MUST NOT apply `REL-035`. |  |  |
| `REL-114` | §10.5.2 | MUST | A client with no correction | A client with no correction MUST record the correction from the first `DirectoryRoot` that it accepts. |  |  |
| `REL-115` | §10.5.2 | MUST | (unstated) | After a clock movement of Part 1 §1.9, a client MUST discard the correction. |  |  |
| `REL-116` | §10.5.2 | MUST | A client | A client MUST show the user the `corrected` state. |  |  |
| `REL-117` | §10.5.2 | MUST | A directory authority | A directory authority MUST set `epoch_start_unix` to `epoch × 3 600`. |  |  |
| `REL-118` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryRoot` whose `epoch_start_unix` differs from `epoch × 3 600`. |  |  |
| `REL-119` | §10.5.2 | MUST | A directory authority | A directory authority MUST set `bloc_hash` to the SHA3-256 over the canonical `BlocList` of §10.6.3. |  |  |
| `REL-120` | §10.5.2 | MUST | A client | A client MUST reject a `DirectoryRoot` whose `revoked_count` is above `MEASURER_REVOKE_MAX`. |  |  |
| `REL-121` | §10.5.1 | MUST | The nonprofit | The nonprofit MUST admit a directory authority only when a legal person operates it. |  |  |
| `REL-122` | §10.5.1 | MUST NOT | The nonprofit | The nonprofit MUST NOT admit two directory authorities under one beneficial control. |  |  |
| `REL-123` | §10.5.1 | MUST | The nonprofit | The nonprofit MUST place the seven authorities in three or more jurisdiction blocs of §10.6.3. |  |  |
| `REL-124` | §10.5.1 | MUST | The nonprofit | The nonprofit MUST publish the legal person, the jurisdiction, and the bloc of each authority. |  |  |
| `REL-125` | §10.5.1 | MUST | The directory authorities | The directory authorities MUST set `independent_count` of the `DirectoryKeySet` to the count of authorities under different beneficial control. |  |  |
| `REL-126` | §10.5.1 | MUST | A client | A client MUST show the user a `provisional directory` state while `independent_count` is below `AUTHORITY_FLOOR`. |  |  |
| `REL-127` | §10.5.3 | MUST | A relay | A relay MUST set `chunk_store_gib` to the store that it declares under Part 13 §13.7, in GiB. |  |  |
| `REL-128` | §10.5.3 | MUST | A directory authority | A directory authority MUST set `operator_id` from the beneficial-control declaration of the dossier of §10.6. |  |  |
| `REL-129` | §10.5.3 | MUST | A directory authority | A directory authority MUST set `class` at or below `capacity_class` of the descriptor. |  |  |
| `REL-130` | §10.5.3 | MUST | A directory authority | A directory authority MUST set `flags` bit 0 only for an ingress eligible relay. |  |  |
| `REL-131` | §10.5.3 | MUST NOT | A directory authority | A directory authority MUST NOT take `operator_id`, `class`, or `flags` from a relay. |  |  |
| `REL-132` | §10.5.3 | MUST | A client | A client MUST take the class, the operator, and the ingress eligibility of a relay from the entry. |  |  |
| `REL-133` | §10.5.3 | MUST | A client | A client MUST use a relay at hop 1 only when `flags` bit 0 of its entry is set. |  |  |
| `REL-134` | §10.5.3 | MUST NOT | A client | A client MUST NOT use a relay whose `flags` bit 0 is set at hop 2 or at hop 3. |  |  |
| `REL-135` | §10.5.3 | MUST | A directory authority | A directory authority MUST publish one `RelaySetDiff` beside each `DirectoryRoot`. |  |  |
| `REL-136` | §10.5.3 | MUST | A directory authority | A directory authority MUST set each store level from the free store that the relay reported in that epoch. |  |  |
| `REL-137` | §10.6.3 | MUST | A client | A client MUST take the family of a relay from `family_id` of its entry. |  |  |
| `REL-138` | §10.6.3 | MUST NOT | A client | A client MUST NOT fetch a family certificate to apply `REL-011`. |  |  |
| `REL-139` | §10.6 | MUST NOT | A directory authority | A directory authority MUST NOT list relays of one family above the family ceiling in one population of one bloc. |  |  |
| `REL-140` | §10.6 | MUST NOT | A directory authority | A directory authority MUST NOT list an ASN above 10 % of one population of one bloc. |  |  |
| `REL-141` | §10.6.3 | MUST | A client | A client MUST verify that the SHA3-256 of the `BlocList` equals `bloc_hash` of the accepted `DirectoryRoot` before it applies `REL-092`. |  |  |
| `REL-142` | §10.6.3 | MUST NOT | A directory authority | A directory authority MUST NOT publish a `BlocList` under which the current relay set does not reach the floor. |  |  |
| `REL-143` | §10.5.3 | MUST | A relay | A relay MUST set `host` to the DNS name that the TLS certificate of its co-tenant site names, in ASCII, with zero bytes after the name. |  |  |
| `REL-144` | §10.5.3 | MUST | A client | A client MUST reject a descriptor whose `host` is empty, holds a byte outside the DNS name characters, or holds a non-zero byte after a zero byte. |  |  |
| `REL-145` | §10.5.5 | MUST | A carrier | A carrier MUST give the manifest in the encoding above, with the entries in ascending order of `relay_id`. |  |  |
| `REL-146` | §10.5.5 | MUST | A client | A client MUST verify the root under §10.5.2 before it verifies one entry. |  |  |
| `REL-147` | §10.5.5 | MUST | A client | A client MUST reject the whole manifest when one entry fails `REL-050`, `REL-051`, `REL-057` or `REL-144`, when two entries are not in ascending order of `relay_id`, when a `step_count` is above 16, or when a `side` is not `0x00` or `0x01`. |  |  |
| `REL-148` | §10.5.5 | MUST | A client | A client MUST reject an entry whose `valid_after` is above the `epoch` of the root. |  |  |
| `REL-149` | §10.5.5 | MUST | A client | A client MUST reject a manifest whose root names a `bloc_hash` that differs from the hash of the `BlocList` that the client holds. |  |  |
| `REL-150` | §10.5.4 | MUST NOT | A client | A client MUST NOT use a relay at hop 3 when `roles` bit 0 of its descriptor is not set. |  |  |
| `REL-151` | §10.5.4 | MUST | A client | A client MUST reject an entry that sets bit 1 with bit 0, that sets bit 1 with no queue role or no chain role in `roles`, or that sets a bit above bit 1. |  |  |
| `REL-152` | §10.5.4 | MUST NOT | A directory authority | A directory authority MUST NOT sign a root over an entry whose bit 1 differs from the function. |  |  |
| `REL-153` | §10.6.1 | MUST | A client | A client MUST keep its pins in the store of Part 15 §15.6.4. |  |  |
| `REL-154` | §10.6.1 | MUST | A client | A client MUST fill an open place with a random draw from the ingress eligible relays of the accepted set. |  |  |
| `REL-155` | §10.6.1 | MUST NOT | A client | A client MUST NOT dial an ingress relay that is no pin. |  |  |
| `REL-156` | §10.5.4 | MUST | A directory authority | A directory authority MUST list a relay of the chain population in one root with `flags` bit 2 set and bit 1 clear before it places the relay. |  |  |
| `REL-157` | §10.5.4 | MUST NOT | An authority | An authority MUST NOT set bit 1 in the same root as bit 2. |  |  |
| `REL-158` | §10.5.4 | MUST NOT | A client | A client MUST NOT select a relay whose entry sets bit 2 for any hop, and a relay MUST NOT open a circuit to one. |  |  |
| `REL-159` | §10.5.4 | MUST | The relays of the first root of a directory | The relays of the first root of a directory MUST take their layer under `GENESIS_ROOT` at epoch 0, with no pending root. |  |  |

## GRP — Private Groups

Source: `spec/11-private-groups.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `GRP-025` | §11.6 | MUST NOT | A client | A client MUST NOT use a peer-to-peer mesh fan-out above about 20 members. |  |  |
| `GRP-035` | §11.7 | MUST | A client | A client MUST identify each record by the triple (group, sender, `msg_id`) (Part 6 §6.6). |  |  |
| `GRP-036` | §11.7 | MUST | A client | A client MUST remove a duplicate by that triple. |  |  |
| `GRP-037` | §11.7 | MUST NOT | A client | A client MUST NOT use a ciphertext hash as an identifier, because Part 6 §6.1.1 rule 5 prohibits that use. |  |  |
| `GRP-038` | §11.7 | MUST | A receiver | A receiver MUST resolve a target only inside the group that carried the naming record. |  |  |
| `GRP-039` | §11.7 | MUST | A receiver | A receiver MUST resolve that target only against the messages of the member that the L6 QueueE2E key names. |  |  |
| `GRP-042` | §11.7 | MUST NOT | A client | A client MUST NOT use a wall clock for the order. |  |  |
| `GRP-043` | §11.7 | MUST NOT | A client | A client MUST NOT use `sent_at` for the order. |  |  |
| `GRP-044` | §11.7 | MUST NOT | The interface | The interface MUST NOT show the order as an agreed order. |  |  |
| `GRP-045` | §11.7 | MAY | A member | A member MAY compare a rolling transcript digest out of band. |  |  |
| `GRP-049` | §11.3.2 | MAY | An admin | An admin MAY turn on a limited history window by an explicit action. |  |  |
| `GRP-050` | §11.8 | MUST | The UI | The UI MUST show this eviction. |  |  |
| `GRP-051` | §11.9 | MUST | A group | A group MUST have two or more members with the `owner` role. |  |  |
| `GRP-052` | §11.9.1 | MUST | A member | A member MUST make `GroupRosterSeed_g` from the device CSPRNG at the join. |  |  |
| `GRP-053` | §11.9.1 | MUST NOT | A member | A member MUST NOT derive that seed from the `RootIdentity`. |  |  |
| `GRP-054` | §11.9.1 | MUST NOT | A member | A member MUST NOT derive that seed from `group_id`. |  |  |
| `GRP-055` | §11.9.1 | MUST | A member | A member MUST store `GroupRosterSeed_g` in the **local identity table** of Part 4 §4.7.2. |  |  |
| `GRP-056` | §11.9.1 | MUST | A member | A member MUST make a different roster key for each group. |  |  |
| `GRP-057` | §11.9.1 | MUST NOT | A member | A member MUST NOT use a roster key outside the group that its table row names. |  |  |
| `GRP-058` | §11.9.1 | MUST | Each device of one member | Each device of one member MUST use the same seed. |  |  |
| `GRP-060` | §11.9.2 | MUST | A granting epoch | A granting epoch MUST carry an ML-DSA-65 signature from the roster key of the member that gives the role. |  |  |
| `GRP-061` | §11.9.2 | MUST | The signature | The signature MUST cover the group-grant preimage of §11.9.2. |  |  |
| `GRP-062` | §11.9.2 | MUST | A verifier | A verifier MUST check that signature against a roster key. |  |  |
| `GRP-063` | §11.9.2 | MUST | A verifier | A verifier MUST reject a granting epoch from a granter that holds a role below `admin`. |  |  |
| `GRP-064` | §11.9.2 | MUST NOT | A plain epoch | A plain epoch MUST NOT carry a signature. |  |  |
| `GRP-066` | §11.9.2 | MUST | A verifier | A verifier MUST discard a plain epoch if the local roster gives that member no role that permits the operation. |  |  |
| `GRP-067` | §11.9.2 | MUST | A member client | A member client MUST offer a self-removal. |  |  |
| `GRP-068` | §11.9.3 | MUST | A member | A member MUST retain each granting epoch on the authority path to a current role. |  |  |
| `GRP-069` | §11.9.3 | MUST | A member | A member MUST discard a granting epoch that a later granting epoch supersedes, after that member verified the successor. |  |  |
| `GRP-070` | §11.9.4 | MUST | (unstated) | If a member sees two different successors to one epoch **from one member**, that member MUST show the fork. |  |  |
| `GRP-071` | §11.9.4 | MUST NOT | That member | That member MUST NOT select one successor silently. |  |  |
| `GRP-072` | §11.9.4 | MUST | The client | The client MUST name that party. |  |  |
| `GRP-073` | §11.9.4 | MUST | (unstated) | If the two successors are plain epochs, the client MUST show that the members disagree. |  |  |
| `GRP-074` | §11.9.4 | MUST NOT | The client | The client MUST NOT name a party. |  |  |
| `GRP-076` | §11.9.4 | MUST | A member | A member MUST discard an epoch above one of these limits. |  |  |
| `GRP-077` | §11.9.6 | MUST | A moderation epoch | A moderation epoch MUST carry an ML-DSA-65 signature from the `GroupRosterKey_g` of the acting member. |  |  |
| `GRP-078` | §11.9.6 | MUST | The signature | The signature MUST cover the group-moderation preimage of §11.9.6. |  |  |
| `GRP-079` | §11.9.6 | MUST | A verifier | A verifier MUST check that signature against a roster key. |  |  |
| `GRP-080` | §11.9.6 | MUST NOT | A client | A client MUST NOT apply an action before that check succeeds. |  |  |
| `GRP-081` | §11.9.6 | MUST | A verifier | A verifier MUST reject a moderation epoch from a member that holds a role below `moderator`. |  |  |
| `GRP-082` | §11.9.6 | MUST | A client | A client MUST show a placeholder that names the action and the acting role. |  |  |
| `GRP-083` | §11.9.6 | MUST NOT | The placeholder | The placeholder MUST NOT vanish without a trace. |  |  |
| `GRP-084` | §11.9.6 | MUST NOT | A moderator | A moderator MUST NOT act on a message that an earlier epoch already removed. |  |  |
| `GRP-085` | §11.9.6 | MUST | The interface | The interface MUST make **hide** the default. |  |  |
| `GRP-086` | §11.9.6 | MUST | A remove | A **remove** MUST need a second confirmation. |  |  |
| `GRP-087` | §11.9.6 | MUST | (unstated) | the interface MUST state that a remove is not reversible. |  |  |
| `GRP-089` | §11.9.6 | MUST | At each epoch, a client | At each epoch, a client MUST show the number of removals since the previous epoch. |  |  |
| `GRP-090` | §11.9.6 | MUST | The client | The client MUST state that fact at the moment it applies a removal epoch. |  |  |
| `GRP-106` | §11.9.2 | MUST | A signer | A signer MUST put that label first in the preimage. |  |  |
| `GRP-107` | §11.9.2 | MUST | A verifier | A verifier MUST reject a signature over a preimage that carries a different label. |  |  |
| `GRP-108` | §11.9.6 | MUST | A signer | A signer MUST put that label first in the preimage. |  |  |
| `GRP-109` | §11.9.6 | MUST | A verifier | A verifier MUST reject a signature over a preimage that carries a different label. |  |  |
| `GRP-117` | §11.9.4 | MUST | A client | A client MUST apply that order. |  |  |
| `GRP-118` | §11.9.4 | MUST NOT | A client | A client MUST NOT show a fork for that case. |  |  |
| `GRP-119` | §11.9.4 | MUST | (unstated) | A member whose epoch the order above did not select MUST publish that epoch again against the selected epoch. |  |  |
| `GRP-125` | §11.9.0 | MUST | A sender | A sender MUST wrap each object of that table in a `GroupControl`. |  |  |
| `GRP-126` | §11.9.0 | MUST | A receiver | A receiver MUST take the object type from `control_type` alone. |  |  |
| `GRP-127` | §11.9.0 | MUST NOT | A receiver | A receiver MUST NOT infer an object type from the length of a record. |  |  |
| `GRP-128` | §11.9.7 | MUST | A member | A member MUST emit a `GroupPresence` record in each `PRESENCE_INTERVAL` in which it sent no other record to that group. |  |  |
| `GRP-132` | §11.9.7 | MUST | An admin | An admin MUST count a member as silent when it took no record and no presence record from that member for `GROUP_SILENT_EVICT`. |  |  |
| `GRP-133` | §11.9.7 | MUST | An admin | An admin MUST then remove that member with a plain epoch of §11.9.2. |  |  |
| `GRP-134` | §11.9.7 | MUST NOT | An admin | An admin MUST NOT remove a member that it counts as silent for a shorter period. |  |  |
| `GRP-135` | §11.9.7 | MUST NOT | A client | A client MUST NOT treat a delivery receipt or a read receipt as a presence signal. |  |  |
| `GRP-140` | §11.11 | MUST | A receiver | A receiver MUST discard a mention that names no member of the local roster. |  |  |
| `GRP-141` | §11.11 | MUST NOT | A client | A client MUST NOT show the mention list of a record to a member that the list does not name. |  |  |
| `GRP-142` | §11.11 | MUST | A receiver | A receiver MUST resolve a reply target inside the group that carried the record. |  |  |
| `GRP-143` | §11.11 | MUST NOT | A receiver | A receiver MUST NOT resolve a reply target against a pairwise conversation. |  |  |
| `GRP-146` | §11.11 | MUST | A client | A client MUST count the votes that it holds. |  |  |
| `GRP-147` | §11.11 | MUST NOT | A client | A client MUST NOT render a poll count as an agreed count. |  |  |
| `GRP-148` | §11.11 | MUST | A client | A client MUST show that a count is the local view. |  |  |
| `GRP-149` | §11.11 | MUST NOT | (unstated) | Thus a client MUST NOT offer a poll in a group above `POLL_GROUP_MAX` members. |  |  |
| `GRP-151` | §11.2.1 | MUST | The creator | The creator MUST make `group_id` from the device CSPRNG at the creation of the group. |  |  |
| `GRP-152` | §11.2.1 | MUST NOT | The creator | The creator MUST NOT derive `group_id` from a member identity, from `GroupRosterSeed_g`, or from an earlier `group_id`. |  |  |
| `GRP-153` | §11.2.1 | MUST | A member | A member MUST reject an invitation to a `group_id` that it already holds. |  |  |
| `GRP-166` | §11.9.7 | MUST | (unstated) | If the silent member holds `moderator` or above, the admin MUST first remove that role with a granting epoch. |  |  |
| `GRP-167` | §11.9.7 | MUST NOT | A member | A member MUST NOT count a silence demotion against `GRANT_RATE`. |  |  |
| `GRP-168` | §11.9.7 | MUST | (unstated) | If the removal leaves fewer than two owners, the admin MUST hold the removal. |  |  |
| `GRP-169` | §11.8 | MUST NOT | A member of a group of two members | A member of a group of two members MUST NOT evict the other member for silence. |  |  |
| `GRP-170` | §11.9.1 | MUST | A client | A client MUST show an offer to the user, and it MUST NOT accept an offer without a user action. |  |  |
| `GRP-179` | §11.9.6 | MUST NOT | A signer | A signer MUST NOT put the author of a target in the preimage. |  |  |
| `GRP-180` | §11.9.6 | MUST | A client | A client MUST resolve the author through `msg_ref`, and it MUST NOT take the author from the hint. |  |  |
| `GRP-181` | §11.9.6 | MUST | A member | A member MUST retain a moderation epoch only while it is the current statement about a target it holds. |  |  |
| `GRP-182` | §11.9.6 | MUST | A member | A member MUST fold an older moderation epoch into local unsigned state and keep its hash for the chain check. |  |  |
| `GRP-184` | §11.9.7 | MUST | The admin | The admin MUST then prompt each surviving owner to grant `owner` to another member. |  |  |
| `GRP-185` | §11.2 | MUST | A member | A member MUST authorize a group-queue command with the deniable authenticator of Part 3 §3.2.3, with `read_sk`, `write_sk`, or `own_sk` in the place of `Q*_auth_sk` and `GroupQueueId` in `queue_id`. |  |  |
| `GRP-186` | §11.2 | MUST | A member | A member MUST carry a group-queue command on a transport session that carries no other command range. |  |  |
| `GRP-187` | §11.2 | MUST | One such session | One such session MUST carry one group queue. |  |  |
| `GRP-188` | §11.2.1 | MUST | The creator | The creator MUST make `own_sk` for each replica from the device CSPRNG. |  |  |
| `GRP-189` | §11.2.1 | MUST NOT | The creator | The creator MUST NOT derive `own_sk` from `group_id`, from `GroupRosterSeed_g`, or from the epoch secret of §11.3.1. |  |  |
| `GRP-190` | §11.2.1 | MUST | The creator | The creator MUST make a different `own_sk` for each replica. |  |  |
| `GRP-191` | §11.2.1 | MUST | The creator | The creator MUST send `GNEW` to two relays whose entries carry different `operator_id` values and different jurisdiction blocs, under invariant 1 and invariant 2 of Part 3 §3.4.6. |  |  |
| `GRP-192` | §11.2.1 | MAY | A creator that finds no such pair | A creator that finds no such pair MAY relax the bloc invariant in the manner of Part 3 rule `NET-200`, and Part 3 rule `NET-201` makes it show that relaxation. |  |  |
| `GRP-193` | §11.2.1 | MUST | A `GNEW` | A `GNEW` MUST end with an `Admission` of Part 14 §14.2. |  |  |
| `GRP-194` | §11.2.1 | MUST | A sender | A sender MUST send the same record bytes to each replica, each under the ARQ of Part 3 §3.7. |  |  |
| `GRP-195` | §11.2.1 | MUST | A client | A client MUST put a record in the `accepted` state of Part 15 §15.9.1 when one replica returned `GSEQ`. |  |  |
| `GRP-196` | §11.2.1 | MUST | A client | A client MUST continue the ARQ to the other replica in the background after that acceptance. |  |  |
| `GRP-197` | §11.2.1 | MUST | A client | A client MUST report a replica that never accepts as a link fault under Part 10 §10.4.2. |  |  |
| `GRP-198` | §11.2.1 | MUST NOT | A `GPOST` | A `GPOST` MUST NOT carry an `Admission`. |  |  |
| `GRP-199` | §11.2.1 | MUST | If a client reaches no replica of a group, it | If a client reaches no replica of a group, it MUST show one line at the top of the message list of that group and keep each outbound record of that group `queued`. |  |  |
| `GRP-200` | §11.2.1 | MUST | That line | That line MUST end without a user action when one replica accepts a session. |  |  |
| `GRP-201` | §11.2.2 | MUST NOT | A client | A client MUST NOT use `seq` as a message identifier or as an order across replicas. |  |  |
| `GRP-202` | §11.2.2 | MUST | A reader device | A reader device MUST hold one cursor for each replica, as mutable state of Part 7 §7.5.3. |  |  |
| `GRP-203` | §11.2.2 | MUST | A reader | A reader MUST subscribe to one replica in each session, chosen at random. |  |  |
| `GRP-204` | §11.2.2 | MUST | A reader | A reader MUST alternate the replicas across its sessions. |  |  |
| `GRP-205` | §11.2.2 | MUST | (unstated) | A reader that observes a gap in the `counter` of one sender (§11.3.5) for longer than `GROUP_GAP_TIMEOUT` MUST open a session to the other replica and fetch from its cursor there. |  |  |
| `GRP-206` | §11.2.2 | MUST | A reader | A reader MUST discard a record that it already holds by the triple of `GRP-035`, whichever replica carried it. |  |  |
| `GRP-207` | §11.2.2 | MUST | A device | A device MUST hold a cursor at or above the newest epoch-key record of the group (§11.4.2) on one replica before it sends a `GPOST`. |  |  |
| `GRP-208` | §11.2.3 | MUST | A client that was offline longer than `GROUP_RETENTION` | A client that was offline longer than `GROUP_RETENTION` MUST show a gap in the group, in the manner of Part 6 rule `WIR-117`. |  |  |
| `GRP-209` | §11.2.3 | MUST NOT | A client | A client MUST NOT ask any member for a record that the retention erased. |  |  |
| `GRP-210` | §11.2.3 | MUST | A client that finds the group queue gone at each replica | A client that finds the group queue gone at each replica MUST show the group as closed. |  |  |
| `GRP-211` | §11.3 | MUST | A sender | A sender MUST fill a record to the fixed length of its bucket, in the manner of Part 6 rule `WIR-024`, with zero bytes inside `body` after the true content. |  |  |
| `GRP-212` | §11.3 | MUST | A sender | A sender MUST draw `nonce` from the device CSPRNG for each content record. |  |  |
| `GRP-213` | §11.3 | MUST | A sender | A sender MUST set `nonce` to zero on an epoch-key record. |  |  |
| `GRP-214` | §11.3 | MUST | A sender | A sender MUST bind `ad` as the associated data of that AEAD. |  |  |
| `GRP-215` | §11.3 | MUST | A sender | A sender MUST use dense mode for every `AppMessage` kind except a `GroupControl` of type `0x06` (`GroupPresence`). |  |  |
| `GRP-216` | §11.3 | MUST | A sender | A sender MUST use sparse mode for a `GroupPresence`, with one entry for each member of role `admin` or above. |  |  |
| `GRP-217` | §11.3 | MUST | A receiver that finds no entry for itself in a sparse record | A receiver that finds no entry for itself in a sparse record MUST discard that record as unattributed, unless the receiver holds role `admin` or above and the record is a `GroupPresence`. |  |  |
| `GRP-218` | §11.3 | MUST | A sender | A sender MUST set `roster_epoch` to the newest roster epoch that its device holds. |  |  |
| `GRP-219` | §11.3 | MUST NOT | A group content record | A group content record MUST NOT carry a wrapper that names the group. |  |  |
| `GRP-220` | §11.3.1 | MUST | The party that starts an epoch | The party that starts an epoch MUST draw `K_e` from the device CSPRNG. |  |  |
| `GRP-221` | §11.3.1 | MUST NOT | That party | That party MUST NOT derive `K_e` from `group_id`, from `GroupRosterSeed_g`, or from an earlier epoch secret. |  |  |
| `GRP-222` | §11.3.1 | MUST | A member | A member MUST derive each slot key, the record key, and the two queue credentials with the calls above. |  |  |
| `GRP-223` | §11.3.1 | MUST | A member | A member MUST compute `t` from the device clock, and Part 1 §1.9 applies to that clock. |  |  |
| `GRP-224` | §11.3.1 | MUST | A member | A member MUST take `t_e` from the epoch-key record. |  |  |
| `GRP-225` | §11.3.1 | MUST NOT | A member | A member MUST NOT compute `t_e` from the arrival time of that record. |  |  |
| `GRP-226` | §11.3.2 | MUST | A device | A device MUST store, for each group, the triple `(e, t_old, K_{e,t_old})` with `t_old = t_now − GROUP_SLOT_WINDOW`, and no earlier slot key of that epoch. |  |  |
| `GRP-227` | §11.3.2 | MUST | A device | A device MUST advance `t_old` by one slot each hour: derive `K_{e,t_old+1}` forward, overwrite, and zeroize the previous key. |  |  |
| `GRP-228` | §11.3.2 | MUST | A receiver | A receiver MUST accept a content record only when its `slot` is in `[t_now − GROUP_SLOT_WINDOW, t_now + GROUP_SLOT_SKEW]`. |  |  |
| `GRP-229` | §11.3.2 | MUST | A receiver | A receiver MUST store a record outside that window in the manner of Part 6 rule `WIR-050`, treat it as evidence of a clock movement of Part 1 §1.9, and retry it after the next clock check. |  |  |
| `GRP-230` | §11.3.2 | MUST | After a rotation to `e + 1`, a receiver | After a rotation to `e + 1`, a receiver MUST keep the state of epoch `e` for `GROUP_EPOCH_GRACE`. |  |  |
| `GRP-231` | §11.3.2 | MUST | A receiver | A receiver MUST zeroize that state at the end of the grace. |  |  |
| `GRP-232` | §11.3.2 | MUST | Inside that grace a receiver | Inside that grace a receiver MUST accept a record of epoch `e` only from a member that its current roster holds. |  |  |
| `GRP-233` | §11.3.2 | MUST | An admin that turned on `HISTORY_WINDOW` = W | An admin that turned on `HISTORY_WINDOW` = W MUST hand the joiner `K_{e,t_join − W}` in the admit stage of §11.9.1 in the place of `K_{e,t_join}`. |  |  |
| `GRP-234` | §11.3.2 | MUST | If that window crosses an epoch boundary, the admin | If that window crosses an epoch boundary, the admin MUST hand the slot key at the start of the current epoch and no key of an earlier epoch. |  |  |
| `GRP-235` | §11.3.3 | MUST | A member | A member MUST derive `GroupPairKey_g` and `GroupKemKey_g` with the calls above. |  |  |
| `GRP-236` | §11.3.3 | MUST | A member | A member MUST take `pair_pk` and `kem_pk` of another member from that member's roster entry (§11.9.1). |  |  |
| `GRP-237` | §11.3.3 | MUST | A member | A member MUST abort the pair-key derivation on an all-zero `ss_ij`, as Part 5 rule `CRY-040` does for a decapsulation. |  |  |
| `GRP-238` | §11.3.3 | MUST | A sender | A sender MUST compute one tag for each active member of `roster_epoch` other than itself, with the derivation above. |  |  |
| `GRP-239` | §11.3.3 | MUST | A sender | A sender MUST put 12 zero bytes at its own position of a dense vector. |  |  |
| `GRP-240` | §11.3.3 | MUST | A receiver | A receiver MUST verify the tag at its own position under `K_{sender,self}`, where `sender_index` names the sender. |  |  |
| `GRP-241` | §11.3.3 | MUST | A receiver | A receiver MUST reject a record whose tag fails. |  |  |
| `GRP-242` | §11.3.3 | MUST NOT | A receiver | A receiver MUST NOT report a tag failure to any party. |  |  |
| `GRP-243` | §11.3.3 | MUST | A receiver | A receiver MUST attribute a record to the member that its verified tag names. |  |  |
| `GRP-244` | §11.3.3 | MUST NOT | A receiver | A receiver MUST NOT attribute a record to a member on `sender_index` alone. |  |  |
| `GRP-245` | §11.3.3 | MUST | A member | A member MUST zeroize the cached `K_ij` of a member at that member's removal. |  |  |
| `GRP-246` | §11.3.4 | MUST | The sender | The sender MUST set `t` to `floor(now / 3600)`, derive `K_{e,t}` from its stored state, and set `counter` to the last value it sent in epoch `e` plus 1. |  |  |
| `GRP-247` | §11.3.4 | MUST NOT | A sender | A sender MUST NOT add a dispatch delay, a per-recipient dispatch, or a rate cap of its own to a group send. |  |  |
| `GRP-248` | §11.3.4 | MUST | A sender | A sender MUST draw one `msg_id` for one group send, and Part 6 rule `WIR-060` states the same rule. |  |  |
| `GRP-249` | §11.3.5 | MUST | A receiver | A receiver MUST reject a record with an unknown `version` or `kind`. |  |  |
| `GRP-250` | §11.3.5 | MUST | A receiver | A receiver MUST reject a record whose `epoch` is neither the current epoch nor the previous epoch inside `GROUP_EPOCH_GRACE`. |  |  |
| `GRP-251` | §11.3.5 | MUST | A receiver | A receiver MUST treat an AEAD failure, a tag failure, and a parse failure as one error value, in the manner of Part 6 rule `WIR-032`. |  |  |
| `GRP-252` | §11.3.5 | MUST | A receiver | A receiver MUST hold a record whose `roster_epoch` is above its newest roster epoch, without a tag check and without a change to the `counter` state of the sender, until it applies a roster record that brings its roster to that epoch. |  |  |
| `GRP-253` | §11.3.5 | MUST | A receiver | A receiver MUST discard a held record when `GROUP_ROSTER_WAIT` passes after its arrival. |  |  |
| `GRP-254` | §11.3.5 | MUST | A receiver | A receiver MUST show a gap for a discarded held record, in the manner of §11.2.3. |  |  |
| `GRP-255` | §11.3.5 | MUST | A receiver that holds such a record | A receiver that holds such a record MUST fetch from the other replica under §11.2.2, because the missing roster record is a gap. |  |  |
| `GRP-256` | §11.3.5 | MUST | A receiver | A receiver MUST discard a record whose `roster_epoch` is below the roster epoch of its own admission. |  |  |
| `GRP-257` | §11.3.5 | MUST | A receiver | A receiver MUST reject a record whose `sender_index` names no member of the receiver's **current** roster. |  |  |
| `GRP-258` | §11.3.5 | MUST | A receiver | A receiver MUST identify the record by the triple of `GRP-035`. |  |  |
| `GRP-259` | §11.3.5 | MUST | A receiver | A receiver MUST track `counter` for each (sender, epoch) pair, for the gap detection of §11.2.2 and the order of §11.7. |  |  |
| `GRP-260` | §11.3.5 | MUST | A receiver | A receiver MUST apply a verified roster record before it evaluates any record with a higher `seq` on the same replica. |  |  |
| `GRP-261` | §11.3.5 | MUST | A receiver | A receiver MUST evaluate a content record against the active-member set of the `roster_epoch` that the record names, and against the current roster for step 6. |  |  |
| `GRP-262` | §11.3.5 | MUST | A receiver | A receiver MUST hold a roster record whose predecessor it does not hold, under the same wait as a held content record, together with each content record that names an epoch at or above it. |  |  |
| `GRP-263` | §11.3.5 | MUST | A receiver | A receiver MUST keep the active-member set of each roster epoch from its own admission epoch onward, for `GROUP_RETENTION` after that epoch. |  |  |
| `GRP-264` | §11.4.1 | MUST | An admin that removes a member | An admin that removes a member MUST rotate in the same action, directly after the roster record that removes it. |  |  |
| `GRP-267` | §11.4.1 | MUST NOT | A member | A member MUST NOT rotate at a join. |  |  |
| `GRP-268` | §11.4.1 | MUST NOT | A member | A member MUST NOT rotate at a promotion. |  |  |
| `GRP-273` | §11.4.1 | MUST | A member that verifies two epoch-key records for one epoch | A member that verifies two epoch-key records for one epoch MUST install the secret of the record whose rotator has the lower member index, and it MUST keep the other secret as an alternate for `GROUP_EPOCH_GRACE`. |  |  |
| `GRP-274` | §11.4.1 | MUST | A receiver | A receiver MUST try the alternate secret of an epoch when the record key of that epoch fails to open a record. |  |  |
| `GRP-276` | §11.4.2 | MUST | A rotator | A rotator MUST build one slot for each member the new roster holds, in index order, and no slot for a member it removes. |  |  |
| `GRP-277` | §11.4.2 | MUST | A rotator | A rotator MUST set `own_count` to `GROUP_REPLICAS` for a member of role `admin` or above and to 0 for each other member. |  |  |
| `GRP-278` | §11.4.2 | MUST | A rotator | A rotator MUST put `own_sk` of replica 1 and then of replica 2 in `own_sks`, in the replica order of the roster snapshot (§11.9.8). |  |  |
| `GRP-279` | §11.4.2 | MUST | A rotator | A rotator MUST use a fresh `Encap` for each slot. |  |  |
| `GRP-280` | §11.4.2 | MUST | A rotator | A rotator MUST carry the slots inline when the record fits the "record on a `GMSG`" row of `B3`, and chunked otherwise. |  |  |
| `GRP-281` | §11.4.2 | MUST | In the chunked carrier, a rotator | In the chunked carrier, a rotator MUST write the object as blocks of `SEGMENT_SIZE` bytes (Part 13 §13.2.3), each block holding `slots_per_chunk` slots in index order and then zero bytes, so that no slot crosses a chunk boundary. |  |  |
| `GRP-282` | §11.4.2 | MUST | A rotator | A rotator MUST set `slots_per_chunk` to the largest value at which every block fits `SEGMENT_SIZE`. |  |  |
| `GRP-283` | §11.4.2 | MUST | A rotator | A rotator MUST write that object on the chunk path of Part 13 §13.3.3 under `CNEW`, and Part 13 §13.4 makes the replicas. |  |  |
| `GRP-284` | §11.4.2 | MUST | A member | A member MUST fetch the one chunk that holds its slot, which is chunk `floor(p / slots_per_chunk)` for its rank `p` among the included members. |  |  |
| `GRP-285` | §11.4.2 | MUST NOT | A member | A member MUST NOT fetch another chunk of that object. |  |  |
| `GRP-286` | §11.4.2 | MUST | A member that reads an epoch-key record | A member that reads an epoch-key record MUST decapsulate its slot, verify `tag` under `K_{rotator,self}`, verify the rotator's role, install `(e + 1, t_{e+1}, K_{e+1,t_{e+1}})`, derive the queue credentials of `e + 1`, and keep the state of epoch `e` for `GROUP_EPOCH_GRACE`. |  |  |
| `GRP-287` | §11.4.2 | MUST NOT | A member | A member MUST NOT install an epoch secret whose `tag` fails. |  |  |
| `GRP-288` | §11.4.2 | MUST NOT | A member | A member MUST NOT install an epoch secret from an epoch-key record whose `epoch` is below its current epoch, or equal to it other than under the two-rotator rule of §11.4.1 and the one-slot record of §11.4.3. |  |  |
| `GRP-289` | §11.4.3 | MUST | A member that lacks the current epoch secret | A member that lacks the current epoch secret MUST send a `KeyRequest` of scope `0x02` as a group record under the previous epoch, while `GROUP_WRITE_GRACE` and `GROUP_EPOCH_GRACE` hold. |  |  |
| `GRP-290` | §11.4.3 | MUST | Outside those graces, the member | Outside those graces, the member MUST send that `KeyRequest` on a pairwise channel to any member of the group that it holds a channel with. |  |  |
| `GRP-295` | §11.4.3 | MUST NOT | A member | A member MUST NOT send more than `KEY_REQUEST_RATE` epoch requests for one group in each 24 h. |  |  |
| `GRP-297` | §11.4.3 | MUST | If no path exists, the member | If no path exists, the member MUST show the group as "membership lapsed", and it needs a new invitation. |  |  |
| `GRP-298` | §11.4.3 | MUST | An admin that promotes a member to `admin` or above | An admin that promotes a member to `admin` or above MUST post a one-slot epoch-key record of the current epoch for that member with `own_count` = `GROUP_REPLICAS`, directly after the granting epoch. |  |  |
| `GRP-299` | §11.6 | MUST NOT | A member | A member MUST NOT send a receipt of Part 6 §6.6.9 kind `0x06` or kind `0x07` in a group. |  |  |
| `GRP-300` | §11.6 | MUST NOT | A member | A member MUST NOT send a typing indicator of kind `0x08` in a group. |  |  |
| `GRP-301` | §11.6 | MUST NOT | A client | A client MUST NOT show a `delivered` or a `read` state for a group record; the states of Part 15 §15.9.1 that a group record reaches are `queued`, `accepted`, and `failed`. |  |  |
| `GRP-302` | §11.7 | MUST | A receiver | A receiver MUST take that pair from the record that its verified tag attributes. |  |  |
| `GRP-303` | §11.7 | MUST NOT | A receiver | A receiver MUST NOT take an order from a count of the arrivals or from `seq`. |  |  |
| `GRP-304` | §11.9 | MUST NOT | A granter | A granter MUST NOT give a role at `moderator` or above when the roster already holds `ROLE_HOLDER_MAX` such members. |  |  |
| `GRP-305` | §11.9.1 | MUST | An admin | An admin MUST assign a new member the lowest index above every index that the roster ever used. |  |  |
| `GRP-306` | §11.9.1 | MUST NOT | A group | A group MUST NOT reuse an index. |  |  |
| `GRP-307` | §11.9.1 | MUST | A member | A member MUST store the full `kem_pk` of every active member, because any member may become an admin and a rotator needs each one. |  |  |
| `GRP-308` | §11.9.1 | MUST | A member | A member MUST verify a `kem_pk` and a `roster_pk` against the hash in the roster entry before it uses either one. |  |  |
| `GRP-309` | §11.9.1 | MUST | A joiner that accepts | A joiner that accepts MUST make `GroupRosterSeed_g` under `GRP-052`, derive the three keys, and send a `JoinRecord` on the same channel. |  |  |
| `GRP-310` | §11.9.1 | MUST | The inviting admin | The inviting admin MUST post a plain epoch of §11.9.2 that adds the joiner, with the `JoinRecord` fields and the new `index`, as a group record to each replica. |  |  |
| `GRP-311` | §11.9.1 | MUST | The admin | The admin MUST take `GSEQ` from each replica before step 4. |  |  |
| `GRP-312` | §11.9.1 | MUST | The admin | The admin MUST then send a `GroupInvitation` of stage `0x02` (an admit) on the pairwise channel. |  |  |
| `GRP-313` | §11.9.1 | MUST | The joiner | The joiner MUST fetch the snapshot, verify it under §11.9.8, subscribe to one replica from the `seq` of the add, install the epoch state, and apply each roster record after `roster_epoch` from the queue. |  |  |
| `GRP-314` | §11.9.2 | MUST | A member | A member MUST compute the hash of a roster epoch as the SHA3-256 of the `GroupControl` payload bytes of that epoch. |  |  |
| `GRP-315` | §11.9.2 | MUST | A member | A member MUST put that value in `previous_epoch_hash` of the successor. |  |  |
| `GRP-316` | §11.9.2 | MUST | A granting epoch that gives a role at `moderator` or above | A granting epoch that gives a role at `moderator` or above MUST carry the full `roster_pk` of the grantee. |  |  |
| `GRP-317` | §11.9.2 | MUST | A verifier | A verifier MUST check that `roster_pk` against `grantee_roster_pk_hash` and against the roster entry. |  |  |
| `GRP-318` | §11.9.2 | MUST | A verifier | A verifier MUST take the authority of a plain epoch from the tag vector of the record that carried it. |  |  |
| `GRP-319` | §11.9.2 | MUST | A plain epoch that adds a member | A plain epoch that adds a member MUST carry the `JoinRecord` fields of that member and its new `index`. |  |  |
| `GRP-320` | §11.9.2 | MUST | A verifier | A verifier MUST reject an add whose `index` is not the lowest index above every index the roster ever used. |  |  |
| `GRP-321` | §11.9.7 | MUST | A member | A member MUST tag that record for each member that the local roster gives the role `admin` or above, and for no other member. |  |  |
| `GRP-322` | §11.9.7 | MUST | A member below `admin` that reads a `GroupPresence` | A member below `admin` that reads a `GroupPresence` MUST discard it without a report. |  |  |
| `GRP-323` | §11.9.8 | MUST | The inviting admin | The inviting admin MUST write a snapshot at the `roster_epoch` of the add, or reuse one it wrote at that same `roster_epoch`. |  |  |
| `GRP-324` | §11.9.8 | MUST | The admin | The admin MUST put the authority path in the snapshot object and not in the admit. |  |  |
| `GRP-325` | §11.9.8 | MUST | An admit | An admit MUST carry no granting epoch. |  |  |
| `GRP-326` | §11.9.8 | MUST | A joiner | A joiner MUST verify `chain_hash` against the hash of the roster epoch that the add record names, verify each granting epoch of the path under §11.9.2, and verify each `kem_pk` against the `kem_pk_hash` of its entry. |  |  |
| `GRP-327` | §11.9.8 | MUST | A joiner | A joiner MUST reject a snapshot that fails one of those checks. |  |  |
| `GRP-328` | §11.9.8 | MUST | A joiner | A joiner MUST show a rejected snapshot as a failed admission. |  |  |
| `GRP-329` | §11.9.8 | MUST | A member that restores from a backup and lacks a `kem_pk` | A member that restores from a backup and lacks a `kem_pk` MUST fetch the newest snapshot named by any admit it holds, or ask an admin with a `KeyRequest` of scope `0x03`. |  |  |
| `GRP-330` | §11.9.8 | MUST | An admin that reads a `KeyRequest` of scope `0x03` | An admin that reads a `KeyRequest` of scope `0x03` MUST answer with a `SnapshotNotice` (type `0x08`) as a group record that carries a fresh descriptor at the current `roster_epoch`. |  |  |
| `GRP-331` | §11.10 | MUST | A revision | A revision MUST keep `GROUP_EPOCH_GRACE` equal to `GROUP_WRITE_GRACE`, `GROUP_EPOCH_MAX_AGE` at or below `GROUP_SILENT_EVICT`, `GROUP_SILENT_EVICT` equal to `GROUP_RETENTION`, and `GROUP_RETENTION` at or below `MSG_TTL`. |  |  |
| `GRP-332` | §11.10 | MUST | (unstated) | A revision that changes `GROUP_MAX`, `GROUP_TAG_LEN`, or the bucket ladder MUST derive the cost table of §11.2, the `B1` member bound of §11.3.3, and `POLL_GROUP_MAX` again. |  |  |
| `GRP-333` | §11.11 | MUST NOT | A sender | A sender MUST NOT put a wrapper that names the group inside a `RichRecord`, and Part 6 rule `WIR-163` rejects such an `inner_kind`. |  |  |
| `GRP-334` | §11.11 | MUST | A sender | A sender MUST compute a mention identifier under Part 6 §6.6.5, with `group_id` as the scope and the 32-byte `pair_pk` of the member's roster entry as the member key. |  |  |
| `GRP-335` | §11.11 | MUST | A receiver | A receiver MUST take that `pair_pk` from the roster entry of §11.9.1. |  |  |
| `GRP-336` | §11.11 | MUST | A member | A member MUST send a `PollVote` of Part 6 §6.6.6 as one group record. |  |  |
| `GRP-337` | §11.11 | MUST NOT | A member | A member MUST NOT send a vote to the poll author on a pairwise channel. |  |  |
| `GRP-338` | §11.12 | MUST | Exactly one device of a member, the group sender owner, | Exactly one device of a member, the **group sender owner**, MUST post the group records of that member, for every group of the user. |  |  |
| `GRP-339` | §11.12 | MUST | That device | That device MUST hold `counter` for each group as mutable state of Part 7 §7.5.3, and the sync channel converges it. |  |  |
| `GRP-340` | §11.12 | MUST | A device that does not own the group sender | A device that does not own the group sender MUST compose the record and hand the plaintext to the owner as an interactive sync record, exactly as a pairwise send under Part 7 §7.5.4. |  |  |
| `GRP-341` | §11.12 | MUST | Ownership | Ownership MUST change by an `OwnerClaim` of scope `0x04`, whose `subject` is `SHA3-256( K_set || 0x04 || 32 zero bytes )` under Part 7 rule `DEV-226`. |  |  |
| `GRP-342` | §11.12 | MUST | At a change, the new owner | At a change, the new owner MUST continue `counter` from the synced value. |  |  |
| `GRP-343` | §11.12 | MUST | Every device of a member | Every device of a member MUST subscribe to a replica on its own circuit with its own cursor, under §11.2.2. |  |  |
| `GRP-344` | §11.12 | MUST | Every device of a member | Every device of a member MUST open its own slot of each epoch-key record. |  |  |
| `GRP-345` | §11.12 | MUST | (unstated) | At a device revocation of Part 7 §7.7 and at a full identity reset of Part 7 §7.7.1, a remaining device MUST make a new `GroupRosterSeed_g` for each group that the user holds, and it MUST derive the three keys of §11.9.1 from it. |  |  |
| `GRP-348` | §11.12 | MUST | An admin that receives a `RekeyRecord` | An admin that receives a `RekeyRecord` MUST verify it under Part 6 rule `WIR-478`. |  |  |
| `GRP-349` | §11.12 | MUST NOT | (unstated) | The admin MUST discard a record that fails that check, and it MUST NOT act on it. |  |  |
| `GRP-351` | §11.12 | MUST NOT | The admin | The admin MUST NOT reuse `old_index`. |  |  |
| `GRP-355` | §11.4.1 | MAY | Any active member | Any active member MAY rotate at a trigger. |  |  |
| `GRP-356` | §11.4.1 | MUST | A receiver | A receiver MUST reject an epoch-key record whose rotator is the index that the trigger excludes, or whose rotator is not active at the `roster_epoch` of that record. |  |  |
| `GRP-357` | §11.4.1 | MUST | A receiver | A receiver MUST reject an epoch-key record for which the roster chain holds no trigger since the epoch-key record of the epoch before it. |  |  |
| `GRP-358` | §11.4.1 | MUST | A member that reads a trigger it did not cause | A member that reads a trigger it did not cause MUST draw a delay from an exponential distribution with mean `ROTATE_BACKOFF_ROLE` if it holds a role at `moderator` or above, and with mean `ROTATE_BACKOFF_MEMBER` otherwise. |  |  |
| `GRP-359` | §11.4.1 | MUST NOT | (unstated) | That member MUST rotate at the end of the delay if no epoch-key record that answers the trigger arrived before it, and it MUST NOT rotate if one did. |  |  |
| `GRP-360` | §11.4.1 | MUST | Any member | Any member MUST rotate, under the same backoff, when `GROUP_EPOCH_MAX_AGE` passes after `t_e` and no epoch-key record of a later epoch has arrived. |  |  |
| `GRP-361` | §11.4.1 | MUST | A rotator that holds `own_sk` | A rotator that holds `own_sk` MUST send `GKEY` with `read_pk_{e+1}` and `write_pk_{e+1}` to each replica after that replica returned `GSEQ` for the epoch-key record. |  |  |
| `GRP-362` | §11.4.1 | MUST NOT | A rotator | A rotator MUST NOT send `GKEY` to a replica before that replica accepted the epoch-key record. |  |  |
| `GRP-363` | §11.4.1 | MUST | (unstated) | A member of role `admin` or above that installs an epoch it did not credential MUST send `GKEY` for that epoch to each replica at once. |  |  |
| `GRP-364` | §11.4.1 | MUST | (unstated) | A rotator that reads an epoch-key record for the epoch it posted, from a lower member index, MUST switch to that secret, and if it holds `own_sk` it MUST send `GKEY` with the credentials of that secret to each replica. |  |  |
| `GRP-365` | §11.12 | MUST | For each such group, that device | For each such group, that device MUST post a `RekeyRecord` of Part 6 §6.6.3 as a group record. |  |  |
| `GRP-366` | §11.12 | MUST | A receiver | A receiver MUST verify a `RekeyRecord` under Part 6 rule `WIR-478`, and it MUST reject a `new_index` that breaks `GRP-320`. |  |  |
| `GRP-367` | §11.12 | MUST | A receiver | A receiver MUST then apply the record as a roster record: `old_index` leaves the active set, and `new_index` enters it with the new keys and the role of `old_index`. |  |  |
| `GRP-368` | §11.12 | MUST | (unstated) | A `RekeyRecord` is a rotation trigger of §11.4.1, and the index it excludes is `old_index`. |  |  |
| `GRP-369` | §11.12 | MUST | (unstated) | A member that verifies two `RekeyRecord`s for one `old_index` with one `previous_epoch_hash` MUST apply the record whose SHA3-256 is lower, and it MUST show the fork under `GRP-070`, because one member made two successors. |  |  |
| `GRP-370` | §11.12 | MUST NOT | (unstated) | The device whose record lost MUST send its `RekeyRecord` on a pairwise channel to a member of role `admin` or above that it holds a channel with, with `epoch_index` and `previous_epoch_hash` set to zero, and it MUST NOT post a second `RekeyRecord` as a group record. |  |  |
| `GRP-371` | §11.12 | MUST | The admin | The admin MUST then post a plain epoch that removes the index that the record names as its current index, post a plain epoch that adds the new keys under a new index, and send the admit of §11.9.1 step 4 on the same pairwise channel. |  |  |
| `GRP-372` | §11.12 | MUST | The member | The member MUST zeroize the old seed and the old three keys when an epoch-key record with a slot for its new index arrives. |  |  |
| `GRP-373` | §11.12 | MUST | The interface | The interface MUST show each group whose re-key waits for a rotation or for an admit. |  |  |
| `GRP-374` | §11.12 | MUST | (unstated) | If the record of the user lost under `GRP-369` and the user holds no pairwise channel with an admin of that group, the interface MUST state that the group needs a new invitation, and the client MUST send a self-removal of its current index under `GRP-067`, which is a rotation trigger. |  |  |
| `GRP-375` | §11.4.3 | MUST | (unstated) | Any active member that reads a `KeyRequest` of scope `0x02` from an index that the current roster holds MUST answer, after the backoff of §11.4.1 and only if no one-slot epoch-key record for that index arrived first, with a one-slot epoch-key record of the current epoch for that member, inline with `slot_count` 1 and `own_count` 0, and then with a `KeySupply` of status `0x01` on the path that carried the request. |  |  |
| `GRP-376` | §11.4.3 | MUST | (unstated) | A member that receives a `KeyRequest` of scope `0x02` on a pairwise channel MUST post it again as a group record, thus every member reads it and the backoff applies. |  |  |
| `GRP-377` | §11.4.3 | MUST NOT | A member | A member MUST NOT answer a `KeyRequest` from an index that the current roster does not hold. |  |  |
| `GRP-378` | §11.4.3 | MUST | A member | A member MUST discard an epoch request above that rate. |  |  |
| `GRP-379` | §11.4.3 | MUST | A receiver | A receiver MUST reject a slot whose `own_count` is above 0 when the rotator held a role below `admin` at the `roster_epoch` of the record, because only an admin holds `own_sk`. |  |  |
| `GRP-380` | §11.4.1 | MAY | An implementation | An implementation MAY draw that delay as `mean × ln(2^32 / (u + 1))` from one uniform 32-bit `u`, with a logarithm from the bit length and a sixteen-entry table of the fraction; the shape of the distribution is what the backoff needs, and not its precision. |  |  |
| `GRP-381` | §11.9.2 | MUST | A verifier | A verifier MUST run every check of an epoch before it records that epoch as a successor of its predecessor, thus a rejected epoch never counts as one of the two successors of `GRP-070`. |  |  |
| `GRP-382` | §11.9.2 | MUST | A plain epoch that adds or removes a member | A plain epoch that adds or removes a member MUST come from a member at `admin` or above, and a self-removal from the member that leaves; a verifier MUST discard each other plain epoch under `GRP-066`. |  |  |
| `GRP-383` | §11.4.2 | MUST | The `slot` field of the epoch-key record header | The `slot` field of the epoch-key record header MUST carry `t_{e+1}`, and a member MUST take `t_e` of `GRP-224` from that field. |  |  |
| `GRP-384` | §11.3.1 | MUST | An admit | An admit MUST carry `read_sk_e` and `write_sk_e`, and a joiner MUST take the two credentials from it. |  |  |
| `GRP-385` | §11.3.1 | MUST NOT | A joiner | A joiner MUST NOT derive a queue credential, because it holds no `K_e`. |  |  |
| `GRP-386` | §11.3.1 | MUST NOT | (unstated) | A member that takes `K_e` from an epoch-key record (§11.4.2) MUST derive the two credentials from it and MUST NOT keep the pair of an earlier epoch after `GROUP_EPOCH_GRACE`. |  |  |
| `GRP-387` | §11.4.2 | MUST | A rotator below `admin` | A rotator below `admin` MUST set `own_count` to 0 in every slot, because it holds no `own_sk`. |  |  |
| `GRP-388` | §11.4.2 | MUST | A member | A member MUST read the inline slots of an epoch-key record under the slot lengths that the roles of its own roster give, and, when that read fails or its own slot does not open under it, under the lengths of a record whose every `own_count` is 0. |  |  |
| `GRP-389` | §11.9.2 | MUST | A member that posts a roster object | A member that posts a roster object MUST build the record that carries it under the roster epoch that stands before that object, and MUST apply the object to its own roster after it built that record. |  |  |
| `GRP-390` | §11.2.2 | MUST | A client whose circuit to one replica ends under `NET-169` | A client whose circuit to one replica ends under `NET-169` MUST keep each other circuit of its group-queue session. |  |  |
| `GRP-391` | §11.2.2 | MUST | A reader whose `GSUB` found no circuit under `NET-169` | A reader whose `GSUB` found no circuit under `NET-169` MUST subscribe at the other replica in the same session. |  |  |
| `GRP-392` | §11.2.2 | MUST | (unstated) | A client whose group-queue session ends before an answer to a `GPOST` MUST send the same bytes in its next session, under Part 3 rule `NET-072`, and the relay answers with the `seq` that it holds (`NET-239`). |  |  |
| `GRP-393` | §11.2.2 | MAY | A client that sends a `GNEW` again in the same way | A client that sends a `GNEW` again in the same way MAY leave one empty group queue at a relay that answered the first one, and `GROUP_RETENTION` ends it. |  |  |
| `GRP-394` | §11.2.2 | MUST | A client whose group-queue link ends | A client whose group-queue link ends MUST wait `GROUP_RELINK_FIRST` before a new link. |  |  |

## COM — Public Communities

Source: `spec/12-communities.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `COM-001` | §12.1.1 | MUST | The UI | The UI MUST make this difference impossible to miss. |  |  |
| `COM-002` | §12.1.1 | MUST | A community | A community MUST look different from a private group. |  |  |
| `COM-003` | §12.1.1 | MUST | A community | A community MUST also read differently. |  |  |
| `COM-004` | §12.1.1 | MUST | At a join, the UI | At a join, the UI MUST show what becomes visible. |  |  |
| `COM-005` | §12.2 | MUST | The creator | The creator MUST make that role pseudonym the §12.3.2 way, from a second and independent seed. |  |  |
| `COM-006` | §12.2.1 | MUST | A client | A client MUST identify each post by the triple (`community_id`, `pseudonym`, `index`). |  |  |
| `COM-007` | §12.2.1 | MUST | A relay | A relay MUST serve each post under the pseudonym of its author. |  |  |
| `COM-008` | §12.2.1 | MUST | A client | A client MUST treat two records with the same triple as one post. |  |  |
| `COM-009` | §12.2.1 | MUST NOT | A client | A client MUST NOT merge two records with different triples. |  |  |
| `COM-010` | §12.2.1 | MUST NOT | A client | A client MUST NOT compare the bodies of two posts from two different pseudonyms. |  |  |
| `COM-011` | §12.2.1 | MUST | (unstated) | If two relays serve two different bodies at one triple, the client MUST show a relay integrity warning. |  |  |
| `COM-012` | §12.2.1 | MUST | That warning | That warning MUST name the two relays. |  |  |
| `COM-013` | §12.2.1 | MUST NOT | A client | A client MUST NOT select one of the two bodies silently. |  |  |
| `COM-014` | §12.2.1 | MUST | (unstated) | If the client holds `link_{n-1}` for that author, the client MUST compute `link_n` again. |  |  |
| `COM-015` | §12.2.1 | MUST | The client | The client MUST reject a record that does not match. |  |  |
| `COM-016` | §12.2.1 | MUST NOT | (unstated) | A relay does not serve `link_n`, and a client MUST NOT accept `link_n` from a relay. |  |  |
| `COM-017` | §12.2.1 | MUST | A client | A client MUST treat a `PostStub` and a body at one triple as one post. |  |  |
| `COM-018` | §12.2.1 | MUST | A client | A client MUST identify each checkpoint by the triple (`community_id`, `pseudonym`, `end_index`). |  |  |
| `COM-019` | §12.2.1 | MUST | In that case the client | In that case the client MUST show a fork of that pseudonym. |  |  |
| `COM-020` | §12.2.1 | MUST NOT | A client | A client MUST NOT select one checkpoint silently. |  |  |
| `COM-021` | §12.2.1 | MUST | A client | A client MUST identify each moderation epoch and each community roster by the pair (`community_id`, `epoch_index`). |  |  |
| `COM-022` | §12.2.1 | MUST NOT | A client | A client MUST NOT use the checkpoint signature bytes as an identifier or as a deduplication key. |  |  |
| `COM-023` | §12.2.1 | MUST NOT | A client | A client MUST NOT use a value that comes from those bytes for either function. |  |  |
| `COM-024` | §12.3.1 | MUST NOT | A community | A community MUST NOT carry kind `0x06` or kind `0x07`. |  |  |
| `COM-025` | §12.3.1 | MUST NOT | A client | A client MUST NOT emit a delivery receipt or a read receipt for a community post. |  |  |
| `COM-026` | §12.3.1 | MUST | A relay | A relay MUST reject such a record. |  |  |
| `COM-027` | §12.3.2 | MUST | At the join, a client | At the join, a client MUST make `CommunityIdentitySeed_g` from the device CSPRNG. |  |  |
| `COM-028` | §12.3.2 | MUST NOT | A client | A client MUST NOT derive that seed from the `RootIdentity`, from `community_id`, or from other key material. |  |  |
| `COM-029` | §12.3.2 | MUST | (unstated) | A member that holds a role in the community MUST make a second and independent seed for that role. |  |  |
| `COM-030` | §12.3.2 | MUST | That member | That member MUST use the resulting **role pseudonym** in a community roster and in a moderation epoch (§12.5.2). |  |  |
| `COM-031` | §12.3.2 | MUST NOT | A member | A member MUST NOT sign a moderation epoch with the authoring pseudonym. |  |  |
| `COM-032` | §12.3.2 | MUST | A client | A client MUST store each seed in the **local identity table**. |  |  |
| `COM-033` | §12.3.2 | MUST | The client | The client MUST hold the local identity table under the per-record encryption of Part 15 §15.6.4. |  |  |
| `COM-034` | §12.3.2 | MUST | The client | The client MUST cover that table with the table MAC of Part 4 §4.6. |  |  |
| `COM-035` | §12.3.2 | MUST NOT | A post | A post MUST NOT carry a public key. |  |  |
| `COM-036` | §12.3.2 | MUST | A checkpoint | A checkpoint MUST carry `CommunityIdentityKey_g.pk`. |  |  |
| `COM-037` | §12.3.2 | MUST | (unstated) | A community roster and a moderation epoch MUST carry the public key of the role pseudonym that signs it. |  |  |
| `COM-038` | §12.3.2 | MUST | (unstated) | Before a client verifies a checkpoint signature, that client MUST hash the carried public key. |  |  |
| `COM-039` | §12.3.2 | MUST | (unstated) | If that hash differs from `pseudonym_g`, the client MUST reject the checkpoint. |  |  |
| `COM-040` | §12.3.2 | MUST | A client | A client MUST put the local identity table in each of the three places below. |  |  |
| `COM-041` | §12.3.2 | MUST NOT | (unstated) | `SYNC_MAX_AGE` and `SYNC_MAX_BYTES` MUST NOT remove an entry from that table. |  |  |
| `COM-042` | §12.3.2 | MUST NOT | (unstated) | If a client does not hold `CommunityIdentitySeed_g`, that client MUST NOT post in that community. |  |  |
| `COM-043` | §12.3.2 | MUST | The client | The client MUST tell the user that the community identity and its post history are lost. |  |  |
| `COM-044` | §12.3.2 | MUST | (unstated) | A device that is not the chain owner MUST give the post text to the chain owner. |  |  |
| `COM-045` | §12.4.1 | MUST | An author | An author MUST publish a checkpoint when `SIG_INTERVAL` posts have no checkpoint. |  |  |
| `COM-046` | §12.4.1 | MUST | An author | An author MUST also publish a checkpoint when the oldest post with no checkpoint reaches `SIG_MAX_AGE`. |  |  |
| `COM-047` | §12.4.1 | MUST NOT | An author | An author MUST NOT publish more than one checkpoint in each `SIG_MIN_INTERVAL`. |  |  |
| `COM-048` | §12.4.1 | MUST NOT | An author | An author MUST NOT publish a checkpoint that covers zero new posts. |  |  |
| `COM-049` | §12.4.1 | MUST | If it fits, the client | If it fits, the client MUST send the post and the checkpoint in one cell. |  |  |
| `COM-050` | §12.4.1 | MUST | If it does not fit, the client | If it does not fit, the client MUST send the checkpoint in a separate cell. |  |  |
| `COM-051` | §12.4.1 | MUST | The parameters of §12.9 | The parameters of §12.9 MUST satisfy `SIG_MAX_AGE` at or above `SIG_INTERVAL × 3600 / POST_RATE_LIMIT` seconds. |  |  |
| `COM-052` | §12.4.1 | MUST | The parameters of §12.9 | The parameters of §12.9 MUST satisfy `PENDING_DEMOTE` above `SIG_MAX_AGE` plus the maximum `PULL_INTERVAL`. |  |  |
| `COM-053` | §12.4.1 | MUST NOT | A client | A client MUST NOT display a pending post that only one relay serves. |  |  |
| `COM-054` | §12.4.1 | MUST | A client | A client MUST hold that post until one of two events. |  |  |
| `COM-055` | §12.4.1 | MUST | A client | A client MUST render a pending post in a visually different state that does not attribute final authorship. |  |  |
| `COM-056` | §12.4.1 | MUST NOT | A client | A client MUST NOT use a pending post as moderation evidence. |  |  |
| `COM-057` | §12.4.1 | MUST NOT | A client | A client MUST NOT delete a pending post on a short timer. |  |  |
| `COM-058` | §12.4.1 | MUST | A client | A client MUST show that pattern as a relay integrity warning that names the relay. |  |  |
| `COM-059` | §12.4.1 | MUST NOT | A client | A client MUST NOT absorb it silently as a post expiry. |  |  |
| `COM-060` | §12.4.1 | MAY | A withdrawal | A withdrawal MAY name any index in the history of that pseudonym. |  |  |
| `COM-061` | §12.4.1 | MUST | A client | A client MUST reject an entry that names an index outside the history of that pseudonym. |  |  |
| `COM-062` | §12.4.1 | MUST | A client | A client MUST reject a repeated index. |  |  |
| `COM-063` | §12.4.1 | MUST | A client | A client MUST reject a list that is not in strictly increasing order before the run of the sentinel. |  |  |
| `COM-064` | §12.4.1 | MUST NOT | A future revision | A future revision MUST NOT fold a community checkpoint signature into a post identifier. |  |  |
| `COM-065` | §12.4.3 | MUST | A client | A client MUST verify that the posts from different relays are consistent. |  |  |
| `COM-066` | §12.4.3 | MUST | The community | The community MUST be the same. |  |  |
| `COM-067` | §12.4.3 | MUST | (unstated) | the sequence MUST be the same. |  |  |
| `COM-068` | §12.4.3 | MUST | A client | A client MUST show a divergence to the user as a **relay integrity warning** that names the relays. |  |  |
| `COM-069` | §12.4.3.1 | MUST | A client | A client MUST show a gap as a relay integrity warning that names the relay. |  |  |
| `COM-070` | §12.4.3.1 | MUST | In that case the client | In that case the client MUST treat a body and a stub at that index as equivalent. |  |  |
| `COM-071` | §12.4.3.1 | MUST NOT | That client | That client MUST NOT report a divergence. |  |  |
| `COM-072` | §12.4.3.1 | MUST NOT | (unstated) | If a client holds part of a window, that client MUST NOT report a gap inside that window. |  |  |
| `COM-073` | §12.4.3.1 | MUST NOT | (unstated) | Before that time passes, a client MUST NOT report a checkpoint divergence. |  |  |
| `COM-074` | §12.4.3.1 | MUST | A client | A client MUST report a divergence that stays past that time. |  |  |
| `COM-075` | §12.4.3.1 | MUST NOT | A client | A client MUST NOT show a checkpoint divergence as a post expiry. |  |  |
| `COM-076` | §12.4.3.1 | MUST | A client | A client MUST apply the settle window of rule 4 to a body divergence at one triple. |  |  |
| `COM-077` | §12.4.3.1 | MUST | A client | A client MUST apply that same window to a stub divergence. |  |  |
| `COM-078` | §12.4.3.1 | MUST NOT | A client | A client MUST NOT render an indicator on a settled post that comes from unsettled data. |  |  |
| `COM-079` | §12.4.3.1 | MUST | The interface | The interface MUST keep a moderator removal, an author withdrawal, and a gap apart. |  |  |
| `COM-080` | §12.4.4 | MUST | An implementation | An implementation MUST give the community record type its own type. |  |  |
| `COM-081` | §12.4.4 | MUST NOT | An implementation | An implementation MUST NOT convert that type into another type. |  |  |
| `COM-082` | §12.4.4 | MUST | A relay | A relay MUST serve `PostStub` in place of a body that an artifact of §12.5.2 names. |  |  |
| `COM-083` | §12.4.4 | MUST NOT | A relay | A relay MUST NOT serve a stub for a body that no such artifact names. |  |  |
| `COM-084` | §12.4.4 | MUST | (unstated) | If a relay serves a checkpoint, that relay MUST serve a record for each index in the window. |  |  |
| `COM-085` | §12.4.4 | MUST | At that index a relay | At that index a relay MUST serve a `PostStub`. |  |  |
| `COM-086` | §12.4.4 | MUST NOT | (unstated) | If a client holds part of a window, that client MUST NOT verify that window. |  |  |
| `COM-087` | §12.4.4 | MUST NOT | That client | That client MUST NOT report a gap inside that window. |  |  |
| `COM-088` | §12.4.4 | MUST | The client | The client MUST request the missing indexes from each of `COMMUNITY_MIN_RELAYS` relays under different operators. |  |  |
| `COM-089` | §12.4.4 | MUST | (unstated) | If an asked relay did not prune a missing index, the client MUST show a relay integrity warning. |  |  |
| `COM-090` | §12.4.4 | MUST | That warning | That warning MUST name each asked relay that did not prune that index. |  |  |
| `COM-091` | §12.4.4 | MUST | A client | A client MUST spread a first-window backfill across two or more `PULL_INTERVAL` periods. |  |  |
| `COM-092` | §12.4.4 | MUST NOT | A client | A client MUST NOT issue a pull whose size separates a first subscription from a steady-state pull. |  |  |
| `COM-093` | §12.4.4 | MUST NOT | A private-group tombstone | A private-group tombstone MUST NOT carry a hash of the deleted plaintext. |  |  |
| `COM-094` | §12.4.5 | MUST NOT | A client | A client MUST NOT publish a checkpoint whose cause is a withdrawal. |  |  |
| `COM-095` | §12.4.5 | MUST | The interface | The interface MUST state this plainly. |  |  |
| `COM-096` | §12.4.5 | MUST NOT | The interface | The interface MUST NOT show a withdrawal as complete before the checkpoint publishes. |  |  |
| `COM-097` | §12.4.5 | MUST | A relay | A relay MUST serve `PostStub` in place of a body that a verified checkpoint withdraws. |  |  |
| `COM-098` | §12.4.5 | MUST | A client | A client MUST render an amended post beside its amendment. |  |  |
| `COM-099` | §12.4.5 | MUST | A client | A client MUST mark the earlier post as amended. |  |  |
| `COM-100` | §12.4.5 | MUST | (unstated) | If the earlier body is withdrawn, the client MUST show the `PostStub` placeholder of §12.4.4 in its place. |  |  |
| `COM-101` | §12.4.5 | MUST | A client | A client MUST reject an `amends` value that names an index outside the history of that pseudonym. |  |  |
| `COM-102` | §12.4.5 | MUST | The interface | The interface MUST state that the withdrawal is permanent and public: "Readers see that you withdrew a post here. |  |  |
| `COM-103` | §12.4.5 | MUST | A removed post: the interface | A removed post: the interface MUST show a placeholder that names the index and reads "a moderator removed this post". |  |  |
| `COM-104` | §12.4.5 | MUST NOT | The entry | The entry MUST NOT vanish without a trace. |  |  |
| `COM-105` | §12.4.5 | MUST | (unstated) | A withdrawn post: the interface MUST show a placeholder that reads "the author withdrew this post". |  |  |
| `COM-106` | §12.4.5 | MUST NOT | The interface | The interface MUST NOT use the moderator wording. |  |  |
| `COM-107` | §12.4.5 | MUST | (unstated) | An unexplained absence: the interface MUST show a relay integrity warning that names the relay. |  |  |
| `COM-108` | §12.4.5 | MUST NOT | The interface | The interface MUST NOT show it as a removal or as a withdrawal. |  |  |
| `COM-109` | §12.5 | MUST | A community | A community MUST have two or more independent owners, and §12.5.2 rule 10 gives the cause. |  |  |
| `COM-110` | §12.5 | MUST | A community roster | A community roster MUST carry a signature from the role pseudonym of an owner. |  |  |
| `COM-111` | §12.5 | MUST | A moderation epoch | A moderation epoch MUST carry a signature from the role pseudonym of an owner, an admin, or a moderator. |  |  |
| `COM-112` | §12.5.1 | MUST | The community roster | The community roster MUST name the role pseudonym of that key in the admin role or above. |  |  |
| `COM-113` | §12.5.1 | MUST | An implementation | An implementation MUST use that definition in Part 14 §14.10. |  |  |
| `COM-114` | §12.5.2 | MUST | (unstated) | Before a client verifies the signature, that client MUST hash `actor_pk`. |  |  |
| `COM-115` | §12.5.2 | MUST | (unstated) | If that hash differs from `actor`, the client MUST reject the object. |  |  |
| `COM-116` | §12.5.2 | MUST | An action of kind 1 | An action of kind 1 MUST name the pair (`target`, `index`). |  |  |
| `COM-117` | §12.5.2 | MUST NOT | A client | A client MUST NOT resolve a removal by the index alone. |  |  |
| `COM-118` | §12.5.2 | MUST | A relay | A relay MUST serve the artifact that justifies a stub, beside that stub. |  |  |
| `COM-119` | §12.5.2 | MUST | A client | A client MUST verify the artifact before that client accepts the absence. |  |  |
| `COM-120` | §12.5.2 | MUST | (unstated) | If `epoch_index` is 0, the client MUST check that `SHA3-256("umbra/v1/community-id" \|\| admission \|\| actor_pk)` equals `community_id`. |  |  |
| `COM-121` | §12.5.2 | MUST | A client | A client MUST reject a moderation epoch that neither the current `CommunityRoster` nor the current `ModeratorSet` authorizes. |  |  |
| `COM-122` | §12.5.2 | MUST | That `CommunityRoster` or that `ModeratorSet` | That `CommunityRoster` or that `ModeratorSet` MUST name the `actor` in a role that permits the action. |  |  |
| `COM-123` | §12.5.2 | MUST | A client | A client MUST reject a `CommunityRoster` that an owner role pseudonym did not sign. |  |  |
| `COM-124` | §12.5.2 | MUST | A client | A client MUST reject an epoch whose `previous_epoch` names an object that the client cannot obtain. |  |  |
| `COM-125` | §12.5.2 | MUST | (unstated) | If two verified successors name one `previous_epoch` and **one** value of `actor` signs them, the client MUST show the fork and MUST name that actor. |  |  |
| `COM-126` | §12.5.2 | MUST NOT | That client | That client MUST NOT select one successor silently. |  |  |
| `COM-127` | §12.5.2 | MUST NOT | (unstated) | If a verification of rule 4 fails, a client MUST NOT have changed any record. |  |  |
| `COM-128` | §12.5.2 | MUST | A client | A client MUST render a moderator removal and an author withdrawal differently. |  |  |
| `COM-129` | §12.5.2 | MUST NOT | A client | A client MUST NOT render a cause that a stub states. |  |  |
| `COM-130` | §12.5.2 | MUST | A community | A community MUST have two or more owners. |  |  |
| `COM-131` | §12.7.2 | MAY | A community | A community MAY opt in to a listing in the public directory of Part 9 §9.12. |  |  |
| `COM-132` | §12.9 | MUST NOT | The client | The client MUST NOT rotate automatically. |  |  |
| `COM-133` | §12.9 | MUST | This value | This value MUST satisfy rule 5 of §12.4.1. |  |  |
| `COM-134` | §12.9 | MUST | This value | This value MUST satisfy rule 6 of §12.4.1. |  |  |
| `COM-135` | §12.5.2 | MUST | (unstated) | Before that rejection, the client MUST request the named object from the relay that served the epoch. |  |  |
| `COM-136` | §12.5.2 | MUST | (unstated) | If two verified successors name one `previous_epoch` and two different values of `actor` sign them, the client MUST select one successor by the order of §12.5.2. |  |  |
| `COM-137` | §12.5.2 | MUST NOT | The client | The client MUST NOT show a fork for that case. |  |  |
| `COM-138` | §12.5.2 | MUST NOT | A client | A client MUST NOT apply an entry of a `CommunityRoster` or of a `ModeratorSet` that it did not select. |  |  |
| `COM-139` | §12.5.2 | MUST | An actor whose `CommunityRoster` or `ModeratorSet` the network did not select | An actor whose `CommunityRoster` or `ModeratorSet` the network did not select MUST publish that object again against the selected epoch. |  |  |
| `COM-140` | §12.5.2 | MUST | That actor | That actor MUST use a new `epoch_index` and a new `previous_epoch` for that publication. |  |  |
| `COM-141` | §12.5.2 | MUST NOT | A client | A client MUST NOT show an action as applied before that action lands on the selected chain. |  |  |
| `COM-142` | §12.3.2 | MUST | A member that holds a role | A member that holds a role MUST derive `RoleReportKey_r` from the seed of that role. |  |  |
| `COM-143` | §12.3.2 | MUST | That member | That member MUST publish the encapsulation key of `RoleReportKey_r` in its `RosterEntry` of §12.5.2. |  |  |
| `COM-144` | §12.3.2 | MUST NOT | A member | A member MUST NOT use `RoleSigningKey_r` for a key agreement. |  |  |
| `COM-145` | §12.3.2 | MUST NOT | A member | A member MUST NOT use `RoleReportKey_r` for a signature. |  |  |
| `COM-146` | §12.5.2 | MUST | A client | A client MUST reject a `CommunityRoster` with more than `ROSTER_ENTRY_MAX` entries. |  |  |
| `COM-147` | §12.5.2 | MUST | A revision | A revision MUST derive this total again if it adds a field to `RosterEntry` or raises `ROSTER_ENTRY_MAX`. |  |  |
| `COM-148` | §12.3.2 | MUST | A relay | A relay MUST apply `POST_RATE_LIMIT` for each `pseudonym` of each community that it serves. |  |  |
| `COM-149` | §12.3.2 | MUST NOT | A relay | A relay MUST NOT need an anonymous credential to apply that limit. |  |  |
| `COM-150` | §12.3.2 | MUST | A relay | A relay MUST apply the proof of work of Part 14 §14.8 as the surge valve above that limit. |  |  |
| `COM-151` | §12.3.2 | MUST NOT | A relay | A relay MUST NOT hold a rate-limit counter after `POST_RATE_WINDOW`. |  |  |
| `COM-152` | §12.5.1 | MUST | A reporter | A reporter MUST take the encapsulation key from the `report_ek` field of the `RosterEntry` of §12.5.2. |  |  |
| `COM-153` | §12.5.1 | MUST NOT | A reporter | A reporter MUST NOT use an ML-DSA-65 key as the designated verifier key. |  |  |
| `COM-154` | §12.1.1 | MUST | (unstated) | At a join, the interface MUST state that the pseudonym of the user is durable in that community. |  |  |
| `COM-155` | §12.1.1 | MUST | The interface | The interface MUST state that a party can monitor that pseudonym over time, and that a court can name it in an order against a relay. |  |  |
| `COM-156` | §12.1.1 | MUST | The interface | The interface MUST state that a rotation loses the post history. |  |  |
| `COM-157` | §12.1.1 | MUST NOT | The interface | The interface MUST NOT show a community pseudonym and a pairwise identity as equal in privacy. |  |  |
| `COM-158` | §12.6.1 | MUST | A `CommunityPost` | A `CommunityPost` MUST carry a mention list and a reply target in the first bytes of its `body`, under the `RichRecord` encoding of Part 6 §6.6.5. |  |  |
| `COM-159` | §12.6.1 | MUST | A client | A client MUST set `inner_kind` to `0x01` for a text post. |  |  |
| `COM-160` | §12.6.1 | MUST | A sender | A sender MUST compute a mention identifier under Part 6 §6.6.5, with the `community_id` as the scope and the pseudonym of the named member as the member key. |  |  |
| `COM-161` | §12.6.1 | MUST | A client | A client MUST resolve a reply target and a thread root through the `community_reply_id` of Part 6 §6.6.5, and it MUST NOT resolve either one as a `msg_id`. |  |  |
| `COM-162` | §12.6.1 | MUST NOT | A client | A client MUST NOT set a `forward_depth` above zero in a community. |  |  |
| `COM-163` | §12.6.1 | MUST NOT | A relay | A relay MUST NOT index a post by its mention list. |  |  |
| `COM-164` | §12.6.1 | MUST NOT | A relay | A relay MUST NOT notify a party because a mention names that party. |  |  |
| `COM-165` | §12.6.1 | MUST | A client | A client MUST find a mention of the user at the pull of §12.9, and it MUST NOT ask a relay for the posts that name it. |  |  |
| `COM-166` | §12.6.1 | MUST | A client | A client MUST default the notification setting of Part 7 §7.5.9 to `none` for a community. |  |  |
| `COM-167` | §12.6.1 | MUST | A client | A client MUST let the user raise that setting to `mentions` or to `all`. |  |  |
| `COM-168` | §12.2.2 | MUST | A creator | A creator MUST set the admission byte at the creation. |  |  |
| `COM-169` | §12.2.2 | MUST | A client | A client MUST derive `community_id` with the construction of §12.2. |  |  |
| `COM-170` | §12.2.2 | MUST | A client | A client MUST reject a community whose admission byte this specification does not define. |  |  |
| `COM-171` | §12.2.2 | MUST NOT | A revision | A revision MUST NOT define a mechanism that moves a community from one mode to the other. |  |  |
| `COM-172` | §12.3.1 | MUST NOT | A `PullRequest` | A `PullRequest` MUST NOT carry a value that binds it to a client, a device, or an earlier session. |  |  |
| `COM-173` | §12.3.1 | MUST NOT | A client | A client MUST NOT pull two communities in one transport session. |  |  |
| `COM-174` | §12.3.1 | MUST | A client | A client MUST select the `PULL_INTERVAL` of each community and of each relay separately. |  |  |
| `COM-175` | §12.3.3 | MUST | A party | A party MUST key the authenticator of a community command with `pull_sk` in the place of `Q*_auth_sk`. |  |  |
| `COM-176` | §12.3.3 | MUST | A community command | A community command MUST put `community_id` in the `queue_id` field. |  |  |
| `COM-177` | §12.3.3 | MUST | A relay | A relay MUST give each accepted record of a community a `seq` above each earlier `seq` of that community. |  |  |
| `COM-178` | §12.3.3 | MUST NOT | A relay | A relay MUST NOT change the `seq` of a record. |  |  |
| `COM-179` | §12.3.3 | MUST NOT | A relay | A relay MUST NOT give a pruned `seq` to a second record. |  |  |
| `COM-180` | §12.3.3 | MUST NOT | A client | A client MUST NOT compare a `seq` of one relay with a `seq` of another relay. |  |  |
| `COM-181` | §12.3.3 | MUST | A relay | A relay MUST fill a `PAGE` in the order of the selector table. |  |  |
| `COM-182` | §12.3.3 | MUST | A relay | A relay MUST stop a page at `count` entries, or at the `B3` L5 payload of Part 6 §6.9. |  |  |
| `COM-183` | §12.3.3 | MUST | (unstated) | Under selector `0x01`, a relay MUST set `floor` to the seq floor. |  |  |
| `COM-184` | §12.3.3 | MUST | (unstated) | Under selector `0x02`, a relay MUST set `floor` to the chain floor of §12.4.6. |  |  |
| `COM-185` | §12.3.3 | MUST | (unstated) | Under selector `0x03` and selector `0x04`, a relay MUST set `floor` to 0. |  |  |
| `COM-186` | §12.3.3 | MUST | A relay | A relay MUST set `next` to the value that follows the last entry. |  |  |
| `COM-187` | §12.3.3 | MUST | (unstated) | If the page holds no entry, the relay MUST set `next` to `from`, and to 0 under the sentinel. |  |  |
| `COM-188` | §12.3.3 | MUST | A relay | A relay MUST reject a `PULL` whose `selector` is not `0x01` and whose `from` is the sentinel. |  |  |
| `COM-189` | §12.3.3 | MUST | A relay | A relay MUST reject a `PULL` whose `count` is 0 or above `PULL_BATCH`. |  |  |
| `COM-190` | §12.3.3 | MUST | A client | A client MUST hold `next` of the last `PAGE` under selector `0x01` for each relay and each community. |  |  |
| `COM-191` | §12.3.3 | MUST | A client | A client MUST use that value as `from` in its next pull under selector `0x01` from that relay. |  |  |
| `COM-192` | §12.3.3 | MUST | A client | A client MUST set `count` to `PULL_BATCH` in each pull under selector `0x01`. |  |  |
| `COM-193` | §12.3.3 | MUST | (unstated) | If `floor` is above the cursor, the client MUST treat each `seq` between the two as pruned at that relay. |  |  |
| `COM-194` | §12.3.3 | MUST | (unstated) | If a page under selector `0x01` holds `PULL_BATCH` entries, the client MUST pull again in the same session. |  |  |
| `COM-195` | §12.3.3 | MUST | (unstated) | At a join, a client MUST make its first pull under selector `0x01` with the sentinel. |  |  |
| `COM-196` | §12.3.3 | MUST | (unstated) | At a join, a client MUST pull the control chain from `epoch_index` 0, and the metadata from `meta_index` 0. |  |  |
| `COM-197` | §12.3.3 | MUST | A `PUB` | A `PUB` MUST carry one record of type `0x01`, `0x03`, `0x04`, `0x05`, `0x06`, or `0x08`. |  |  |
| `COM-198` | §12.3.3 | MUST | A relay | A relay MUST reject a `PUB` that carries a `PostStub`. |  |  |
| `COM-199` | §12.3.3 | MUST | A relay | A relay MUST reject a record whose `community_id` field differs from the `queue_id` of the command. |  |  |
| `COM-200` | §12.3.3 | MUST | A publisher | A publisher MUST send a `PUB` of each record to each relay that the selected `CommunityMeta` (§12.7) names. |  |  |
| `COM-201` | §12.3.3 | MUST | A publisher | A publisher MUST send a `PUB` again at each session until the relay answers with a `PUBACK` or a `NACK`. |  |  |
| `COM-202` | §12.3.3 | MUST | A relay | A relay MUST answer an accepted `PUB` with a `PUBACK` that carries the `seq` of the record. |  |  |
| `COM-203` | §12.3.3 | MUST | (unstated) | If the relay holds that record already, the relay MUST answer with the `seq` that it holds. |  |  |
| `COM-204` | §12.3.3 | MUST | A relay | A relay MUST answer a rejected `PUB` with a `NACK` of Part 6 §6.4.4, and not with a `PUBACK`. |  |  |
| `COM-205` | §12.3.3 | MUST | A relay | A relay MUST apply the admission control of Part 14 to a `PUB` of a `CommunityRoster` with `epoch_index` 0. |  |  |
| `COM-206` | §12.3.3 | MUST NOT | A relay | A relay MUST NOT accept a record of a community before it holds the `CommunityRoster` with `epoch_index` 0. |  |  |
| `COM-207` | §12.3.3 | MUST | A relay | A relay MUST apply the identity check of §12.5.2 rule 5 to that roster. |  |  |
| `COM-208` | §12.3.3 | MUST | A relay | A relay MUST verify the signature of a `Checkpoint`, a `CommunityRoster`, a `ModeratorSet`, a `ModerationEpoch`, or a `CommunityMeta` before acceptance. |  |  |
| `COM-209` | §12.3.3 | MUST | A relay | A relay MUST apply §12.5.2 rule 1 and rule 5 to a `CommunityRoster`, to a `ModeratorSet`, and to a `ModerationEpoch`. |  |  |
| `COM-210` | §12.3.3 | MUST | A relay | A relay MUST apply the hash check of `COM-038` to a `Checkpoint`. |  |  |
| `COM-211` | §12.3.3 | MUST | A relay | A relay MUST count a `PUB` under `POST_RATE_LIMIT` against the `pseudonym` of a `CommunityPost`, or the `actor` of another record. |  |  |
| `COM-212` | §12.3.3 | MUST | A party | A party MUST reject a `Checkpoint` whose window holds more than `SIG_INTERVAL` indexes. |  |  |
| `COM-213` | §12.3.3 | MUST | A relay | A relay MUST accept a second `CommunityPost` with a different body at a triple that no held checkpoint covers. |  |  |
| `COM-214` | §12.3.3 | MUST | A relay | A relay MUST reject a third body at one triple. |  |  |
| `COM-215` | §12.3.3 | MUST | A relay | A relay MUST serve each body that it holds at a pending triple. |  |  |
| `COM-216` | §12.3.3 | MUST | (unstated) | At that time, the relay MUST keep at each index the body that the recomputation of §12.4.4 rule 6 admits. |  |  |
| `COM-217` | §12.3.3 | MUST | The relay | The relay MUST drop each other body at that index. |  |  |
| `COM-218` | §12.3.3 | MUST | (unstated) | If a relay holds an admitted body at a triple, the relay MUST reject a different body at that triple. |  |  |
| `COM-219` | §12.3.3 | MUST | (unstated) | If a relay serves two bodies at one triple, a client MUST hold both pending until a checkpoint covers it. |  |  |
| `COM-220` | §12.3.3 | MUST | A client | A client MUST apply the selection of `COM-216` at that checkpoint. |  |  |
| `COM-221` | §12.4.4 | MUST NOT | (unstated) | If each asked relay pruned a missing index, the client MUST NOT show a warning for that index. |  |  |
| `COM-222` | §12.4.6 | MUST | A relay | A relay MUST keep a `CommunityPost`, a `PostStub`, and a `Checkpoint` for `COMMUNITY_RETENTION` after the relay accepts the record. |  |  |
| `COM-223` | §12.4.6 | MUST NOT | A relay | A relay MUST NOT prune such a record before that time to make space. |  |  |
| `COM-224` | §12.4.6 | MUST | A relay | A relay MUST keep each record of the control chain and each `CommunityMeta` while it serves that community. |  |  |
| `COM-225` | §12.4.6 | MAY | (unstated) | After `COMMUNITY_RETENTION`, a relay MAY prune a record. |  |  |
| `COM-226` | §12.4.6 | MUST | A relay | A relay MUST prune a window as one unit, which is the `Checkpoint` and each record that it covers. |  |  |
| `COM-227` | §12.4.6 | MUST NOT | A relay | A relay MUST NOT prune an index of a chain while it holds a lower index of that chain. |  |  |
| `COM-228` | §12.4.6 | MUST | A relay | A relay MUST reject a `PUB` of a `CommunityPost` whose `index` is below the chain floor of its pseudonym. |  |  |
| `COM-229` | §12.4.6 | MUST | A relay | A relay MUST reject a `PUB` of a `Checkpoint` whose `start_index` is below that chain floor. |  |  |
| `COM-230` | §12.4.6 | MUST | A client | A client MUST treat an index below the chain floor of a relay as pruned at that relay. |  |  |
| `COM-231` | §12.4.6 | MUST NOT | A client | A client MUST NOT show a relay integrity warning for a pruned index. |  |  |
| `COM-232` | §12.4.6 | MUST NOT | A client | A client MUST NOT count a pruned index as a gap under §12.4.3.1. |  |  |
| `COM-233` | §12.4.6 | MUST NOT | A client | A client MUST NOT report a divergence between a relay that serves an index and a relay that pruned it. |  |  |
| `COM-234` | §12.4.6 | MAY | A client | A client MAY keep a post that a relay pruned. |  |  |
| `COM-235` | §12.4.6 | MUST | A relay whose store is full | A relay whose store is full MUST reject a `PUB` of a `CommunityPost`. |  |  |
| `COM-236` | §12.4.6 | MUST | That relay | That relay MUST signal a capacity fault to the directory, in the manner of Part 13 rule `ATT-091`. |  |  |
| `COM-237` | §12.4.6 | MUST | A revision that changes `POST_RATE_LIMIT`, `MAX_POST_SIZE`, `SIG_INTERVAL`, or `COMMUNITY_RETENTION` | A revision that changes `POST_RATE_LIMIT`, `MAX_POST_SIZE`, `SIG_INTERVAL`, or `COMMUNITY_RETENTION` MUST derive this section again. |  |  |
| `COM-238` | §12.4.6 | MUST | A client that fetches a chunk from a community record | A client that fetches a chunk from a community record MUST send a `CRNW` for it in that session. |  |  |
| `COM-239` | §12.4.6 | MUST | An owner client that adds a relay | An owner client that adds a relay MUST publish the control chain and each `CommunityMeta` to that relay. |  |  |
| `COM-240` | §12.4.6 | MUST | That client | That client MUST then publish to the new relay each record inside `COMMUNITY_RETENTION` that it holds, newest window first. |  |  |
| `COM-241` | §12.4.6 | MUST | A re-seed | A re-seed MUST publish a window in full, with its `Checkpoint`. |  |  |
| `COM-242` | §12.7 | MUST | A client | A client MUST make the fragment from the device CSPRNG at the creation. |  |  |
| `COM-243` | §12.7 | MUST | A client | A client MUST derive `meta_key` from `community_id` and the fragment. |  |  |
| `COM-244` | §12.7 | MUST NOT | A client | A client MUST NOT send the fragment, or a value that comes from it, to a relay. |  |  |
| `COM-245` | §12.7 | MUST | A client that shares a link | A client that shares a link MUST fill the hints from the `relays` list of the current `CommunityMeta`. |  |  |
| `COM-246` | §12.7 | MUST | A joiner | A joiner MUST pull the metadata under `COM-196` from a hinted relay. |  |  |
| `COM-247` | §12.7 | MUST | (unstated) | After a `CommunityMeta` verifies, a client MUST use its `relays` list in the place of the hints. |  |  |
| `COM-248` | §12.7.1 | MUST | An owner | An owner MUST publish a `CommunityMeta` with `meta_index` 0 at the creation, after the `CommunityRoster` with `epoch_index` 0. |  |  |
| `COM-249` | §12.7.1 | MUST | A party | A party MUST reject a `CommunityMeta` that an owner role pseudonym of the current `CommunityRoster` did not sign. |  |  |
| `COM-250` | §12.7.1 | MUST | A party | A party MUST apply the hash check of §12.5.2 rule 1 to `actor_pk`. |  |  |
| `COM-251` | §12.7.1 | MUST | A party | A party MUST reject a `CommunityMeta` whose `previous_meta` differs from the hash of the `CommunityMeta` at `meta_index` − 1. |  |  |
| `COM-252` | §12.7.1 | MUST | A client | A client MUST apply the successor order of §12.5.2 rule 6 to two verified `CommunityMeta` records at one `meta_index`. |  |  |
| `COM-253` | §12.7.1 | MUST | A client | A client MUST select the verified `CommunityMeta` with the highest `meta_index` as the current metadata. |  |  |
| `COM-254` | §12.7.1 | MUST | A `CommunityMeta` | A `CommunityMeta` MUST name at least `COMMUNITY_MIN_RELAYS` relays under different operators. |  |  |
| `COM-255` | §12.7.1 | MUST | A party | A party MUST reject a `CommunityMeta` with more than `COMMUNITY_RELAY_MAX` relays. |  |  |
| `COM-256` | §12.7.1 | MUST | A revision that changes `CommunityMeta`, `CommunityMetaBody`, or a `META_*` value | A revision that changes `CommunityMeta`, `CommunityMetaBody`, or a `META_*` value MUST derive the total above again. |  |  |
| `COM-257` | §12.7.1 | MUST | A client | A client MUST reject a `CommunityMetaBody` whose `name_len`, `text_len`, or `rules_len` is above its maximum of §12.9. |  |  |
| `COM-258` | §12.7.1 | MUST | A client | A client MUST reject a body whose `name`, `text`, or `rules` is not valid UTF-8. |  |  |
| `COM-259` | §12.7.1 | MUST | A client | A client MUST show a `category` that the table above does not define as `0x00`. |  |  |
| `COM-260` | §12.7.1 | MUST | An icon | An icon MUST be one attachment of one chunk under Part 13. |  |  |
| `COM-261` | §12.7.1 | MUST | A client | A client MUST re-encode an icon under Part 9 rules `DIS-001` and `DIS-002` before the upload. |  |  |
| `COM-262` | §12.7.1 | MUST | An owner client | An owner client MUST upload the icon again, and publish a new `CommunityMeta`, before `CHUNK_LIFE_MAX` passes from the upload. |  |  |
| `COM-263` | §12.7.1 | MUST | (unstated) | Before a user joins, the client MUST show the five items of the current `CommunityMeta`. |  |  |
| `COM-264` | §12.7.1 | MUST | The client | The client MUST show the rules again before the first post of the user. |  |  |
| `COM-265` | §12.7.1 | MUST NOT | A client | A client MUST NOT show a name, a description, or an icon from a `CommunityMeta` that did not verify. |  |  |
| `COM-266` | §12.5.3 | MUST | A reporter | A reporter MUST send a report record in bucket `B1`. |  |  |
| `COM-267` | §12.5.3 | MUST | A revision | A revision MUST derive this total again if it changes `REPORT_NOTE_MAX` or adds a field. |  |  |
| `COM-268` | §12.5.3 | MUST | A reporter | A reporter MUST select one entry of the current `CommunityRoster` with the device CSPRNG. |  |  |
| `COM-269` | §12.5.3 | MUST NOT | A reporter | A reporter MUST NOT select an entry by its role, by its position, or by an earlier selection. |  |  |
| `COM-270` | §12.5.3 | MUST | A reporter | A reporter MUST encapsulate to `report_ek` of that entry with `UMBRA-KEM`, and it MUST derive `K_rep` with the label above. |  |  |
| `COM-271` | §12.5.3 | MUST | A reporter | A reporter MUST send the report record as a `SEND` to the queue of `report_queue` of that entry. |  |  |
| `COM-272` | §12.5.3 | MUST NOT | A reporter | A reporter MUST NOT put its own pseudonym, its own handle, or another identifier of itself in a report. |  |  |
| `COM-273` | §12.5.3 | MUST | A client | A client MUST offer a report action on each community post that it renders. |  |  |
| `COM-274` | §12.5.3 | MUST | A role holder | A role holder MUST make one report queue under Part 3 rule `NET-170` before the roster names its role. |  |  |
| `COM-275` | §12.5.3 | MUST | A roster signer | A roster signer MUST take `report_ek` and `report_queue` of an entry from the role holder over their pairwise channel. |  |  |
| `COM-276` | §12.5.3 | MUST | A role holder | A role holder MUST subscribe to its report queue in each session that it opens under Part 3 §3.5.1. |  |  |
| `COM-277` | §12.5.3 | MUST | A role holder | A role holder MUST open such a session at least one time in each `REPORT_POLL_MAX`. |  |  |
| `COM-278` | §12.5.3 | MUST NOT | A role holder | A role holder MUST NOT rotate a report queue under `ROTATE_AFTER` of Part 3 §3.2.4. |  |  |
| `COM-279` | §12.5.3 | MUST | A role holder | A role holder MUST hold a report queue until `ROTATE_GRACE` after a roster without its entry succeeds. |  |  |
| `COM-280` | §12.5.3 | MUST | A role holder | A role holder MUST then send the `DEL` of Part 3 rule `NET-020`. |  |  |
| `COM-281` | §12.5.3 | MUST | A role holder | A role holder MUST decapsulate `kem_ct` with `RoleReportKey_r`, derive `K_rep`, and open `ct`. |  |  |
| `COM-282` | §12.5.3 | MUST | A role holder | A role holder MUST discard a report record that fails one of those steps without a signal. |  |  |
| `COM-283` | §12.5.3 | MUST | (unstated) | Before it shows a report, a role holder MUST fetch the post that `pseudonym` and `index` name under §12.3.3. |  |  |
| `COM-284` | §12.5.3 | MUST | (unstated) | If the two hashes differ, the role holder MUST discard the report. |  |  |
| `COM-285` | §12.5.3 | MUST | (unstated) | If the chain holds no post at that pair, the role holder MUST try again at each pull. |  |  |
| `COM-286` | §12.5.3 | MUST NOT | A role holder | A role holder MUST NOT forward a report to a party outside the roster of that community. |  |  |
| `COM-287` | §12.5.3 | MUST | Each entry | Each entry MUST have the same probability. |  |  |
| `COM-288` | §12.5.3 | MUST NOT | A roster signer | A roster signer MUST NOT make either value itself. |  |  |
| `COM-289` | §12.5.3 | MUST | A role holder | A role holder MUST parse the plaintext as an `AppMessage` of kind `0x11` with a `CommunityReport` body. |  |  |
| `COM-290` | §12.5.3 | MUST | The role holder | The role holder MUST compare the hash of that post with `post_hash` before it shows the report. |  |  |
| `COM-291` | §12.5.3 | MUST | The role holder | The role holder MUST discard such a report `REPORT_HOLD` after its arrival. |  |  |
| `COM-292` | §12.5 | MUST | A moderator set | A moderator set MUST carry a signature from the role pseudonym of an owner or of an admin. |  |  |
| `COM-293` | §12.5.2 | MUST | A client | A client MUST reject a `ModeratorSet` with more than `MODERATOR_MAX` entries. |  |  |
| `COM-294` | §12.5.2 | MUST | A revision | A revision MUST derive this total again if it adds a field to `ModeratorSet` or raises `MODERATOR_MAX`. |  |  |
| `COM-295` | §12.5.2 | MUST | A client | A client MUST reject a `ModerationEpoch` that carries a `kind` outside the table. |  |  |
| `COM-296` | §12.5.2 | MUST | A client | A client MUST apply the actions on one (`target`, `index`) pair in chain order. |  |  |
| `COM-297` | §12.5.2 | MUST | (unstated) | If a kind 2 action carries an `index`, a relay MUST serve a `PostStub` at each index of `target` up to it. |  |  |
| `COM-298` | §12.5.2 | MUST | A relay | A relay MUST reject a `PUB` from a banned pseudonym until an action of kind 5 names that pseudonym. |  |  |
| `COM-299` | §12.5.2 | MUST | A relay | A relay MUST keep a removed body for the retention of §12.4.6. |  |  |
| `COM-300` | §12.5.2 | MUST | (unstated) | If a kind 8 action names an index whose body the relay holds, the relay MUST serve that body again. |  |  |
| `COM-301` | §12.5.2 | MUST | (unstated) | If a restore stands and a relay still serves a stub, the client MUST show the restore as pending. |  |  |
| `COM-302` | §12.5.2 | MUST NOT | The client | The client MUST NOT show a relay integrity warning for that stub. |  |  |
| `COM-303` | §12.5.2 | MUST | A client | A client MUST show a pinned post at the top of the timeline until an action of kind 6 names it. |  |  |
| `COM-304` | §12.5.2 | MUST | (unstated) | While a lock stands, a relay MUST reject a `PUB` of a `CommunityPost`. |  |  |
| `COM-305` | §12.5.2 | MUST | A relay | A relay MUST measure a lock duration from its acceptance of the epoch. |  |  |
| `COM-306` | §12.5.2 | MUST | A client | A client MUST show a lock and its end. |  |  |
| `COM-307` | §12.5.2 | MUST | A client | A client MUST apply each action of a verified `ModerationEpoch` that names the selected `previous_epoch`. |  |  |
| `COM-308` | §12.5.2 | MUST | (unstated) | If two such epochs reverse each other on one `target` and `index`, the client MUST apply the selected epoch. |  |  |
| `COM-309` | §12.5.2 | MUST | A client | A client MUST reject a `ModeratorSet` that no owner or admin role pseudonym of the current `CommunityRoster` signed. |  |  |
| `COM-310` | §12.5.2 | MUST | A relay | A relay MUST reject a `ModerationEpoch` above `MOD_EPOCH_RATE` for one `actor`. |  |  |
| `COM-311` | §12.5.2 | MUST | A relay | A relay MUST reject a `ModerationEpoch` above `MOD_EPOCH_COMMUNITY_RATE` for one community. |  |  |
| `COM-312` | §12.5.2 | MUST | A relay | A relay MUST reject a `CommunityRoster` or a `ModeratorSet` above `ROSTER_RATE` for one community. |  |  |
| `COM-313` | §12.5.2 | MUST NOT | A client | A client MUST NOT walk more than `MOD_CHAIN_FETCH_MAX` predecessors under `COM-135` for one epoch. |  |  |
| `COM-314` | §12.5.4 | MUST | A client | A client MUST let the user mute a pseudonym in one community. |  |  |
| `COM-315` | §12.5.4 | MUST NOT | A client | A client MUST NOT render a post, a reaction, or a repost of a muted pseudonym in that community. |  |  |
| `COM-316` | §12.5.4 | MUST | The client | The client MUST show the count of the hidden records, in the manner of Part 14 rule `ABU-038`. |  |  |
| `COM-317` | §12.5.4 | MUST NOT | A client | A client MUST NOT show a mention from a muted pseudonym as a mention. |  |  |
| `COM-318` | §12.5.4 | MUST | A client | A client MUST verify the chain of a muted pseudonym under §12.4.1. |  |  |
| `COM-319` | §12.5.4 | MUST NOT | A client | A client MUST NOT send a record for a mute, and it MUST NOT tell a relay. |  |  |
| `COM-320` | §12.5.4 | MUST | A client | A client MUST hold the mute list of a community as the mutable state of Part 7 §7.5.3. |  |  |
| `COM-321` | §12.5.4 | MUST NOT | A client | A client MUST NOT hold more than `MUTE_LIST_MAX` pseudonyms in the mute list of one community. |  |  |
| `COM-322` | §12.6.2 | MUST | A reaction | A reaction MUST be a `CommunityPost` whose `RichRecord` `inner_kind` is `0x03`, with a `ReactionBody` of Part 6 §6.6.9. |  |  |
| `COM-323` | §12.6.2 | MUST | The `target` of that body | The `target` of that body MUST be the `community_reply_id` of the target post. |  |  |
| `COM-324` | §12.6.2 | MUST NOT | A client | A client MUST NOT set a reply target or a mention in a reaction. |  |  |
| `COM-325` | §12.6.2 | MUST | A repost | A repost MUST be a `CommunityPost` whose `RichRecord` `inner_kind` is `0x0D`, with a `RepostBody`. |  |  |
| `COM-326` | §12.6.2 | MUST | (unstated) | If the client subscribes to the origin community, it MUST render a repost with the target post. |  |  |
| `COM-327` | §12.6.2 | MUST NOT | A client | A client MUST NOT join the origin community for a repost without a user action. |  |  |
| `COM-328` | §12.6.2 | MUST | A relay | A relay MUST count a reaction under `REACT_RATE_LIMIT` and a repost under `REPOST_RATE_LIMIT`. |  |  |
| `COM-329` | §12.6.2 | MUST NOT | A relay | A relay MUST NOT count a reaction or a repost under `POST_RATE_LIMIT`. |  |  |
| `COM-330` | §12.6.2 | MUST | (unstated) | If the `flags` field of the current `CommunityMetaBody` sets bit 0, a relay MUST reject a reaction. |  |  |
| `COM-331` | §12.6.2 | MUST | (unstated) | If that field sets bit 1, a relay MUST reject a repost. |  |  |
| `COM-332` | §12.6.2 | MUST NOT | A client | A client MUST NOT send a record that a set bit forbids. |  |  |
| `COM-333` | §12.6.2 | MUST | A client | A client MUST tally a reaction count from the records that it pulled. |  |  |
| `COM-334` | §12.6.2 | MUST | A client | A client MUST count a maximum of one reaction for each pseudonym and emoji. |  |  |
| `COM-335` | §12.6.2 | MUST NOT | A relay | A relay MUST NOT serve an aggregate count. |  |  |
| `COM-336` | §12.6.3 | MUST NOT | A client | A client MUST NOT publish a `CommunityContact` without an explicit act of the user for that pseudonym. |  |  |
| `COM-337` | §12.6.3 | MUST | A `CommunityContact` | A `CommunityContact` MUST travel as a `CommunityPost` whose `RichRecord` `inner_kind` is `0x0E`. |  |  |
| `COM-338` | §12.6.3 | MUST | A client | A client MUST take the newest verified `CommunityContact` of a pseudonym as its current one. |  |  |
| `COM-339` | §12.6.3 | MUST NOT | The `rendezvous` queue | The `rendezvous` queue MUST NOT be a queue that a `DirectoryEntry`, an `AddressEntry`, or a pairwise contact names. |  |  |
| `COM-340` | §12.4.7 | MAY | A `CommunityPost` | A `CommunityPost` MAY carry a `RichRecord` whose `inner_kind` is `0x02`, which is a `FileDescriptor` of Part 13 §13.3. |  |  |
| `COM-341` | §12.4.7 | MUST | (unstated) | Before the upload, the client MUST state that each party with the link reads the file. |  |  |
| `COM-342` | §12.4.7 | MUST | A reader that renews a chunk of a community attachment | A reader that renews a chunk of a community attachment MUST send the `CRNW` of Part 13 §13.3.3. |  |  |
| `COM-343` | §12.4.7 | MUST NOT | A client | A client MUST NOT download a community attachment without a user action, unless the user set an automatic download for that community. |  |  |
| `COM-344` | §12.6.3 | MUST | The author client | The author client MUST drain that queue under Part 8 §8.2.6. |  |  |
| `COM-345` | §12.6.3 | MUST | A reader | A reader MUST send the hello of Part 9 §9.6 to that queue, and it MUST encapsulate the hello to `contact_pk`. |  |  |
| `COM-346` | §12.6.3 | MUST | A client | A client MUST show a hello under a pseudonym as a contact request that names the community and the pseudonym. |  |  |
| `COM-347` | §12.6.3 | MUST NOT | The client | The client MUST NOT accept that request without a user action. |  |  |
| `COM-348` | §12.7.1 | MUST | A client | A client MUST treat a `flags` bit that §12.6.2 does not define as zero. |  |  |
| `COM-349` | §12.7.2 | MUST | (unstated) | Before an owner lists a community, the client MUST show the five items of the statement above. |  |  |
| `COM-350` | §12.7.2 | MUST | An owner client | An owner client MUST publish a new `CommunityListing` at each `CommunityMeta` change, and before `LISTING_LEASE` ends. |  |  |
| `COM-351` | §12.7.2 | MUST | An owner client | An owner client MUST let the owner withdraw the listing, and a withdrawal is a `CommunityListing` with `link_len` 0. |  |  |
| `COM-352` | §12.5.2 | MUST NOT | A relay | A relay MUST NOT serve a removed body while the removal stands. |  |  |
| `COM-353` | §12.5.2 | MUST | A client | A client MUST measure a lock duration from its verification of the epoch. |  |  |
| `COM-354` | §12.5.2 | MUST NOT | A client | A client MUST NOT let the user compose a post while a lock stands. |  |  |
| `COM-355` | §12.5.2 | MUST | (unstated) | At that bound, the client MUST reject the epoch. |  |  |
| `COM-356` | §12.6.2 | MUST | (unstated) | If it does not, the client MUST render the repost with the link. |  |  |
| `COM-357` | §12.4.4 | MUST | A relay that removes a body under a legal order | A relay that removes a body under a legal order MUST serve an `OperatorRemoval` beside the stub. |  |  |
| `COM-358` | §12.4.4 | MUST | A relay | A relay MUST sign it under the identity key of its own descriptor. |  |  |
| `COM-359` | §12.4.4 | MUST | A client | A client MUST verify the signature against the descriptor of `relay_id`. |  |  |
| `COM-360` | §12.4.4 | MUST | A client | A client MUST treat a stub with a verified `OperatorRemoval` as an authorized absence at that relay only. |  |  |
| `COM-361` | §12.4.4 | MUST NOT | A client | A client MUST NOT apply an `OperatorRemoval` at a different relay. |  |  |
| `COM-362` | §12.4.4 | MUST | A client that holds another relay of the community | A client that holds another relay of the community MUST fetch the body from that relay. |  |  |
| `COM-363` | §12.4.4 | MUST | A client | A client MUST render an operator removal differently from a moderator removal and from an author withdrawal. |  |  |
| `COM-364` | §12.5.2 | MUST | A `CommunityRoster` that drops an owner entry | A `CommunityRoster` that drops an owner entry MUST carry cosignatures from more than half of the current owners. |  |  |
| `COM-365` | §12.5.2 | MUST | A client | A client MUST reject such a roster with fewer cosignatures. |  |  |
| `COM-366` | §12.5.2 | MUST | A cosignature | A cosignature MUST cover the preimage of `signature`, under the key of the named owner. |  |  |
| `COM-367` | §12.5.2 | MUST | A client | A client MUST reject a roster whose `cosign_count` is not 0 and whose entries drop no owner. |  |  |
| `COM-368` | §12.6.4 | MUST | A subscriber | A subscriber MUST send `NREG` on the session of that community under `COM-173`. |  |  |
| `COM-369` | §12.6.4 | MUST | A community relay | A community relay MUST hold a registration in memory only. |  |  |
| `COM-370` | §12.6.4 | MUST | A community relay | A community relay MUST discard a registration at an `NUNREG` that names its queue. |  |  |
| `COM-371` | §12.6.4 | MUST | A community relay | A community relay MUST write a `NotifyDigest` as a `SEND` to each registered queue when a post arrives, under the budget of Part 8 rule `NTF-072` and the silence of `NTF-073`. |  |  |
| `COM-372` | §12.6.4 | MUST NOT | A community relay | A community relay MUST NOT write a `NotifyDigest` that names a post, a pseudonym, or an index. |  |  |
| `COM-373` | §12.6.4 | MUST NOT | A community relay | A community relay MUST NOT link a registration to a pull. |  |  |
| `COM-374` | §12.6.4 | MUST NOT | A subscriber | A subscriber MUST NOT put a pseudonym in a `NotifyRegistration`. |  |  |
| `COM-375` | §12.6.4 | MUST | A community relay | A community relay MUST discard a registration 7 days plus `CLOCK_SKEW` after its `NREG`. |  |  |
| `COM-376` | §12.3.2 | MUST | A member | A member MUST derive `RoleReportKey_r`, and `CommunityContactKey_g` of §12.6.3, as 96 bytes of HKDF-SHA3-256 output under the label as the `info`, split by `Hybrid` of Part 5 §5.2. |  |  |
| `COM-377` | §12.5.2 | MUST | `previous_epoch` | `previous_epoch` MUST be the SHA3-256 of the predecessor bytes that its signature covers, without the label. |  |  |
| `COM-378` | §12.5.2 | MUST | A verifier | A verifier MUST reject an object whose `epoch_index` is not one above the `epoch_index` of the object that `previous_epoch` names. |  |  |
| `COM-379` | §12.5.2 | MUST | A verifier | A verifier MUST apply rule 1 to the `actor_pk` of each cosignature, and it MUST reject a roster with a cosignature of its signer, of one owner two times, or of a party that the roster before it does not name as an owner. |  |  |
| `COM-380` | §12.5.2 | MUST | A `CommunityRoster` with its cosignatures | A `CommunityRoster` with its cosignatures MUST fit the 32 589 bytes of one `PAGE` record. |  |  |
| `COM-381` | §12.5.2 | MUST | The `actor_role` byte | The `actor_role` byte MUST be 1 for an owner, 2 for an admin, and 3 for a moderator, and a verifier MUST reject an epoch whose `actor_role` differs from the role that rule 5 gives the `actor`. |  |  |
| `COM-382` | §12.5.2 | MUST | An action of kind 4 or kind 7 | An action of kind 4 or kind 7 MUST come from an admin or an owner, because a lock stops each author of the community. |  |  |
| `COM-383` | §12.5.2 | MUST | The `entries` of a `ModeratorSet` | The `entries` of a `ModeratorSet` MUST be in strictly increasing byte order. |  |  |
| `COM-384` | §12.5.2 | MUST NOT | A `CommunityRoster` | A `CommunityRoster` MUST NOT name one `pseudonym` in two entries. |  |  |
| `COM-385` | §12.5.2 | MUST | The `CommunityRoster` at `epoch_index` 0 | The `CommunityRoster` at `epoch_index` 0 MUST name its `actor` in an owner entry, and it MUST carry no cosignature. |  |  |
| `COM-386` | §12.7.1 | MUST | The `flags` field | The `flags` field MUST sit in the signed record and not in the sealed body. |  |  |
| `COM-387` | §12.7.1 | MUST | (unstated) | That hash is the SHA3-256 of the bytes that the signature covers, without the label, in the manner of `COM-377`. |  |  |
| `COM-388` | §12.7.1 | MUST | (unstated) | The check of `COM-251` binds a party that holds the record at `meta_index` − 1. |  |  |
| `COM-389` | §12.7.1 | MUST | (unstated) | When a `CommunityRoster` drops the owner that signed the current `CommunityMeta`, a remaining owner MUST publish a new `CommunityMeta`. |  |  |
| `COM-390` | §12.7 | MUST | (unstated) | The derivation is HKDF-SHA3-256 with the fragment as the `ikm`, no salt, the label and then `community_id` as the `info`, and 32 bytes of output. |  |  |
| `COM-391` | §12.3.3 | MUST | A relay | A relay MUST reject a `CommunityPost` whose `body` does not parse as the `RichRecord` of `COM-158`, or whose `forward_depth` is not zero. |  |  |
| `COM-392` | §12.3.3 | MUST | A relay | A relay MUST count a `Checkpoint` against its `pseudonym` in a count of its own, at `POST_RATE_LIMIT` in each `POST_RATE_WINDOW`. |  |  |
| `COM-393` | §12.3.3 | MUST | A relay | A relay MUST reject a `Checkpoint` whose window holds an index that a held `Checkpoint` of that pseudonym covers, unless the two are one checkpoint under `COM-203`. |  |  |
| `COM-394` | §12.3.3 | MUST | A relay that holds two bodies at a pending triple | A relay that holds two bodies at a pending triple MUST accept a third body when a held `Checkpoint` covers the triple and the recomputation of §12.4.4 rule 6 admits that body. |  |  |
| `COM-395` | §12.3.3 | MUST | An author whose `PUB` of a post got a `NACK` | An author whose `PUB` of a post got a `NACK` MUST send that `PUB` again after the `PUBACK` of the `Checkpoint` that covers the post. |  |  |
| `COM-396` | §12.5.2 | MUST | (unstated) | For a moderation epoch that means selector `0x03`, and for a checkpoint it means selector `0x02`, at the relay that serves the stub. |  |  |
| `COM-397` | §12.6.2 | MUST | The `link` of a `RepostBody` | The `link` of a `RepostBody` MUST name `origin_community`, and `link_len` MUST be 0 exactly when `origin_community` is this community. |  |  |
| `COM-398` | §12.4.5 | MUST | (unstated) | The history of a post ends below its own `index`, thus a party MUST reject a `CommunityPost` whose `amends` is not the sentinel and is at or above its `index`. |  |  |
| `COM-399` | §12.3.3 | MUST | (unstated) | Under selector `0x02`, the records of one `index` are one unit: each body or stub at that index, the `OperatorRemoval` of a stub, and the `Checkpoint` whose `end_index` is that index. |  |  |
| `COM-400` | §12.3.3 | MUST | (unstated) | A `PUB` payload holds one record and then the `Admission`. |  |  |

## ATT — Attachments and Large Objects

Source: `spec/13-attachments.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `ATT-001` | §13.1 | MUST | An attachment mechanism | An attachment mechanism MUST meet the three requirements below. |  |  |
| `ATT-002` | §13.1 | MUST NOT | The mechanism | **The mechanism MUST NOT make the sender stay online** until each recipient fetches the file. |  |  |
| `ATT-003` | §13.1 | MUST NOT | The mechanism | The mechanism MUST NOT make the sender upload the file again for each group member. |  |  |
| `ATT-004` | §13.1 | MUST NOT | A relay | A relay MUST NOT be able to tell that two chunks belong to one file. |  |  |
| `ATT-005` | §13.1 | MUST NOT | A relay | A relay MUST NOT be able to tell that two chunks belong to one user. |  |  |
| `ATT-006` | §13.3.1 | MUST | The attachment AEAD | The attachment AEAD MUST be key-committing. |  |  |
| `ATT-007` | §13.3.1 | MUST | (unstated) | The test suite of this specification MUST include a negative vector that fails on the construction that does not commit. |  |  |
| `ATT-008` | §13.3.2 | MUST | A client | A client MUST resolve `relay_hint` against the current consensus. |  |  |
| `ATT-009` | §13.3.2 | MUST NOT | A client | A client MUST NOT fetch an older consensus to resolve a reference, because Part 10 §10.5 forbids a session for the only purpose of a directory diff. |  |  |
| `ATT-010` | §13.3.2 | MUST | (unstated) | If `relay_hint` matches no relay in the current consensus, the client MUST treat that replica as unreachable. |  |  |
| `ATT-011` | §13.3.2 | MUST | The client | The client MUST then try another replica under §13.4. |  |  |
| `ATT-012` | §13.3.2 | MUST | (unstated) | If `relay_hint` matches two or more relays in the current consensus, the client MUST treat that replica as unresolvable. |  |  |
| `ATT-013` | §13.3.2 | MUST | The client | The client MUST then try another replica under §13.4. |  |  |
| `ATT-014` | §13.3.2 | MUST | The client | The client MUST report that failure to the user. |  |  |
| `ATT-015` | §13.3.2 | MUST NOT | (unstated) | the client MUST NOT show a partial file. |  |  |
| `ATT-016` | §13.3.2 | MUST | A revision | A revision MUST measure the relay churn rate over 45 days before it lowers `REPLICAS`. |  |  |
| `ATT-017` | §13.4 | MUST | A client | A client MUST register each chunk at three or more relays under different `operator_id` values of Part 10 §10.5.3. |  |  |
| `ATT-018` | §13.4 | MUST | The descriptor | The descriptor MUST carry the three references. |  |  |
| `ATT-019` | §13.4 | MUST NOT | The client | The client MUST NOT use a fixed order. |  |  |
| `ATT-020` | §13.7 | MUST | (unstated) | If the bucket ladder or the command header changes, a revision MUST derive this value again. |  |  |
| `ATT-021` | §13.7 | MUST | A client | A client MUST select the bucket of a descriptor from those four values. |  |  |
| `ATT-022` | §13.7 | MUST NOT | Thus a v1 client | Thus a v1 client MUST NOT send an attachment above `MAX_DESCRIPTOR_CHUNKS`, which is 269 chunks and about 8.78 MB. |  |  |
| `ATT-023` | §13.7 | MUST | A revision | A revision MUST derive §13.7.2 again before it raises that value. |  |  |
| `ATT-024` | §13.8 | MUST | An attachment transfer | An attachment transfer MUST use a **separate connection**, or separate QUIC streams, from the interactive messaging. |  |  |
| `ATT-025` | §13.3.1 | MUST | A sender | A sender MUST put `commit` in the `FileDescriptor` of §13.3. |  |  |
| `ATT-026` | §13.3.1 | MUST | A receiver | A receiver MUST compute `commit` again from `file_key` and `file_nonce`. |  |  |
| `ATT-027` | §13.3.1 | MUST | A receiver | A receiver MUST compare the two values in constant time. |  |  |
| `ATT-028` | §13.3.1 | MUST | (unstated) | If the two values differ, a receiver MUST reject the descriptor. |  |  |
| `ATT-029` | §13.3.1 | MUST NOT | A receiver | A receiver MUST NOT fetch a chunk of a descriptor that it rejected. |  |  |
| `ATT-030` | §13.3.1 | MUST | A receiver | A receiver MUST make that comparison before it decrypts a chunk. |  |  |
| `ATT-031` | §13.3.1 | MUST | A receiver | A receiver MUST verify `digest` against the full plaintext after the decryption. |  |  |
| `ATT-032` | §13.3.1 | MUST NOT | A receiver | A receiver MUST NOT present a file as complete, save it, or forward it before that check succeeds. |  |  |
| `ATT-033` | §13.3.3 | MUST NOT | An attachment command | An attachment command MUST NOT carry a signature. |  |  |
| `ATT-034` | §13.3.3 | MUST | An uploader | An uploader MUST make `cred_sk` from the device CSPRNG for each chunk. |  |  |
| `ATT-035` | §13.3.3 | MUST NOT | An uploader | An uploader MUST NOT derive `cred_sk` from `file_key`. |  |  |
| `ATT-036` | §13.3.3 | MUST NOT | An uploader | An uploader MUST NOT use one `cred_sk` for two chunks. |  |  |
| `ATT-037` | §13.3.3 | MUST | A client | A client MUST derive `read_sk` of a file chunk from `file_key` and the index of the chunk. |  |  |
| `ATT-038` | §13.3.3 | MUST | A relay | A relay MUST select `storage_token` from its own CSPRNG. |  |  |
| `ATT-039` | §13.3.3 | MUST NOT | A relay | A relay MUST NOT derive `storage_token` from `cred_pk`, from `read_pk`, or from the chunk bytes. |  |  |
| `ATT-040` | §13.3.3 | MUST | A relay | A relay MUST authorize `CPUT` and `CDEL` against `cred_pk` only. |  |  |
| `ATT-041` | §13.3.3 | MUST | A relay | A relay MUST authorize `CGET` and `CRNW` against `read_pk` only. |  |  |
| `ATT-042` | §13.3.3 | MUST | (unstated) | The authorized bytes of a `CPUT` MUST hold `storage_token`. |  |  |
| `ATT-043` | §13.3.3 | MUST | A `CPUT` and a `CDAT` | A `CPUT` and a `CDAT` MUST carry exactly `CHUNK_SIZE` bytes. |  |  |
| `ATT-044` | §13.3.3 | MUST | A relay | A relay MUST reject a `CPUT` of a different length. |  |  |
| `ATT-045` | §13.3.3 | MUST | A relay | A relay MUST apply the admission control of Part 14 to a `CNEW`. |  |  |
| `ATT-046` | §13.3.3 | MUST | A relay | A relay MUST erase a chunk at `CDEL`, and at `CHUNK_TTL` after the `CPUT` or after the last accepted `CRNW`. |  |  |
| `ATT-047` | §13.3.3 | MUST NOT | A relay | A relay MUST NOT retain the identifier of an erased chunk. |  |  |
| `ATT-048` | §13.3.3 | MUST | A client | A client MUST send an attachment command on the separate connection of §13.8. |  |  |
| `ATT-049` | §13.3.2 | MUST | (unstated) | A revision that adds a field to `FileDescriptor` or to `ChunkRef` MUST derive `R` again from Part 6 §6.9. |  |  |
| `ATT-050` | §13.7.1 | MUST NOT | `CHUNK_TTL` | `CHUNK_TTL` MUST NOT be below the `MSG_TTL` of Part 3 §3.2.4. |  |  |
| `ATT-051` | §13.7.1 | MUST NOT | (unstated) | A revision MUST hold the two values equal, and a revision MUST NOT raise `MSG_TTL` alone. |  |  |
| `ATT-052` | §13.7.1 | MUST | (unstated) | If each replica of a chunk is gone, the client MUST report the failure to the user and MUST name the file. |  |  |
| `ATT-053` | §13.7.1 | MUST NOT | The client | The client MUST NOT show a partial file. |  |  |
| `ATT-054` | §13.7.1 | MUST | The client | The client MUST offer the sender a re-send of the file. |  |  |
| `ATT-055` | §13.3.3 | MUST | An uploader | An uploader MUST select `chunk_id` from the device CSPRNG, and it MUST select one value for each chunk. |  |  |
| `ATT-056` | §13.3.3 | MUST NOT | An uploader | An uploader MUST NOT derive `chunk_id` from `file_key`, from `cred_pk`, from `read_pk`, or from the chunk bytes. |  |  |
| `ATT-057` | §13.3.3 | MUST | An uploader | An uploader MUST use the same `chunk_id` at each of the `REPLICAS` relays that hold one chunk. |  |  |
| `ATT-058` | §13.3.3 | MUST | A relay | A relay MUST reject a `CNEW` whose `chunk_id` names a chunk that the relay holds. |  |  |
| `ATT-059` | §13.2.3 | MUST | A sender | A sender MUST pad `plaintext` with one marker byte of `0x80` and then zero bytes. |  |  |
| `ATT-060` | §13.2.3 | MUST | A sender | A sender MUST select the smallest *k* that makes the length of `padded` a whole multiple of `SEGMENT_SIZE`. |  |  |
| `ATT-061` | §13.2.3 | MUST | A sender | A sender MUST append the marker byte even when the length of `plaintext` is already a whole multiple of `SEGMENT_SIZE`. |  |  |
| `ATT-062` | §13.2.3 | MUST | A receiver | A receiver MUST read the last segment from its last byte toward its first byte. |  |  |
| `ATT-063` | §13.2.3 | MUST | The first byte that is not `0x00` | The first byte that is not `0x00` MUST be `0x80`, and a receiver MUST reject the file when that byte holds a different value. |  |  |
| `ATT-064` | §13.2.3 | MUST | A receiver | A receiver MUST remove that marker byte and each zero byte after it. |  |  |
| `ATT-065` | §13.2.3 | MUST NOT | A receiver | A receiver MUST NOT read the padding of a segment whose tag failed under §13.3.1. |  |  |
| `ATT-066` | §13.9 | MUST | A revision that adds a client of the chunk path | A revision that adds a client of the chunk path MUST add a row to this table. |  |  |
| `ATT-067` | §13.3 | MUST | A receiver | A receiver MUST take the data chunk count from that division. |  |  |
| `ATT-068` | §13.3 | MUST | A parser | A parser MUST reject a `padded_size` that `CHUNK_SIZE` does not divide. |  |  |
| `ATT-069` | §13.3 | MUST | A sender | A sender MUST set `media_seconds` for a `mime_class` of audio, of voice, or of video. |  |  |
| `ATT-070` | §13.3 | MUST | A sender | A sender MUST set `media_seconds` to zero for each other class. |  |  |
| `ATT-071` | §13.3 | MUST NOT | A sender | A sender MUST NOT send a voice object above `VOICE_MAX_SECONDS`. |  |  |
| `ATT-072` | §13.3.4 | MUST | A client | A client MUST use level `0x00` when the data chunk count is at or below the ref count that the descriptor bucket holds. |  |  |
| `ATT-073` | §13.3.4 | MUST | A client | A client MUST use level `0x01` above that count. |  |  |
| `ATT-074` | §13.3.4 | MUST | A parser | A parser MUST reject a `level` above `0x01`. |  |  |
| `ATT-075` | §13.3.4 | MUST | A client | A client MUST derive `K_manifest` with the label above, and Part 5 §5.11 holds that label. |  |  |
| `ATT-076` | §13.3.4 | MUST NOT | A client | A client MUST NOT encrypt a manifest under `file_key` itself. |  |  |
| `ATT-077` | §13.3.4 | MUST | A client | A client MUST order the `ChunkRef` values of a manifest by the chunk index, from the lowest index to the highest index. |  |  |
| `ATT-078` | §13.3.4 | MUST | A receiver | A receiver MUST reject a manifest whose length is not a whole multiple of 120 bytes after the padding is removed. |  |  |
| `ATT-079` | §13.3.4 | MUST | A receiver | A receiver MUST rebuild the full manifest before it fetches a data chunk. |  |  |
| `ATT-080` | §13.3.4 | MUST NOT | A receiver | A receiver MUST NOT present a file as complete before it verifies `digest` under `ATT-031`. |  |  |
| `ATT-081` | §13.3.4 | MUST NOT | A relay | A relay MUST NOT tell a manifest chunk from a data chunk. |  |  |
| `ATT-082` | §13.3.4 | MUST | A revision | A revision MUST define a second manifest level before it raises `MAX_FILE_SIZE` above 2.22 GiB. |  |  |
| `ATT-083` | §13.7.2 | MUST | A client | A client MUST show the uplink cost of an attachment above `LARGE_FILE_WARN` before it starts the upload. |  |  |
| `ATT-084` | §13.7.2 | MUST | A client | A client MUST let the user cancel at that point. |  |  |
| `ATT-085` | §13.7.2 | MUST NOT | A client | A client MUST NOT start an upload above that size on a metered network without a user action. |  |  |
| `ATT-086` | §13.10 | MUST | A relay that declares the attachment role | A relay that declares the attachment role MUST hold `CHUNK_STORE_MIN` of free storage. |  |  |
| `ATT-087` | §13.10 | MUST | A relay | A relay MUST publish the declared store in `chunk_store_gib` of its descriptor of Part 10 §10.5.3. |  |  |
| `ATT-088` | §13.10 | MUST | A directory authority | A directory authority MUST reject an attachment role from a relay whose `chunk_store_gib` is below `CHUNK_STORE_MIN`. |  |  |
| `ATT-089` | §13.10 | MUST | A relay | A relay MUST reject a `CNEW` when its store holds less free space than `CHUNK_SIZE`. |  |  |
| `ATT-090` | §13.10 | MUST NOT | A relay below `CHUNK_STORE_TARGET` of stored bytes | A relay below `CHUNK_STORE_TARGET` of stored bytes MUST NOT erase a chunk before `CHUNK_TTL` to make space. |  |  |
| `ATT-091` | §13.10 | MUST | A relay | A relay MUST signal that condition to the directory as a capacity fault. |  |  |
| `ATT-092` | §13.10 | MUST | A relay | A relay MUST apply `UPLOAD_QUOTA_DAY` for each credential that presents a token. |  |  |
| `ATT-093` | §13.10 | MUST | A relay | A relay MUST reject a `CNEW` above that quota. |  |  |
| `ATT-094` | §13.10 | MUST NOT | A relay | A relay MUST NOT hold a quota counter after 24 hours. |  |  |
| `ATT-095` | §13.10 | MUST | A revision that raises `MAX_FILE_SIZE`, `UPLOAD_QUOTA_DAY`, `REPLICAS`, `CHUNK_TTL`, or `CHUNK_LIFE_MAX` | A revision that raises `MAX_FILE_SIZE`, `UPLOAD_QUOTA_DAY`, `REPLICAS`, `CHUNK_TTL`, or `CHUNK_LIFE_MAX` MUST derive this section again. |  |  |
| `ATT-096` | §13.4.1 | MUST | A client | A client MUST send `CNEW` to each of the `REPLICAS` relays of a chunk before it sends `CPUT`. |  |  |
| `ATT-097` | §13.4.1 | MUST | A client | A client MUST send `CPUT` to one of those relays only. |  |  |
| `ATT-098` | §13.4.1 | MUST | A client | A client MUST send `CREP` to the relay that took the `CPUT`. |  |  |
| `ATT-099` | §13.4.1 | MUST | A client | A client MUST send `CREP` after that `CPUT` succeeds. |  |  |
| `ATT-100` | §13.4.1 | MUST | A client | A client MUST put the `storage_token` that each target issued in the target of that relay. |  |  |
| `ATT-101` | §13.4.1 | MUST NOT | A client | A client MUST NOT put a token of one relay in the target of another relay. |  |  |
| `ATT-102` | §13.4.1 | MUST | A relay | A relay MUST send one `CRPUT` to each target of a `CREP`. |  |  |
| `ATT-103` | §13.4.1 | MUST | A relay | A relay MUST put the `storage_token` of that target in the `CRPUT` payload. |  |  |
| `ATT-104` | §13.4.1 | MUST | A relay | A relay MUST send the bytes that the `CPUT` gave it, without a change. |  |  |
| `ATT-105` | §13.4.1 | MUST NOT | A relay | A relay MUST NOT send a `CRPUT` to a relay that a `CREP` did not name. |  |  |
| `ATT-106` | §13.4.1 | MUST NOT | A relay | A relay MUST NOT keep a `storage_token` of another relay after it sends the `CRPUT` that uses it. |  |  |
| `ATT-107` | §13.4.1 | MUST | A relay | A relay MUST authorize a `CRPUT` against the `storage_token` that its own `CID` issued for that `chunk_id`. |  |  |
| `ATT-108` | §13.4.1 | MUST NOT | A relay | A relay MUST NOT authorize a `CRPUT` against `cred_pk`. |  |  |
| `ATT-109` | §13.4.1 | MUST | A relay | A relay MUST accept one `CRPUT` for each registration. |  |  |
| `ATT-110` | §13.4.1 | MUST | A relay | A relay MUST reject a second `CRPUT` for a `chunk_id` that it holds. |  |  |
| `ATT-111` | §13.4.1 | MUST | A relay | A relay MUST reject a `CRPUT` whose payload is not 32 682 bytes. |  |  |
| `ATT-112` | §13.4.1 | MUST | A relay | A relay MUST erase the `storage_token` of a registration when it accepts the chunk. |  |  |
| `ATT-113` | §13.4.1 | MUST | A client | A client MUST send a `CVFY` to each replica relay for a sample of the chunks that the relay holds. |  |  |
| `ATT-114` | §13.4.1 | MUST | A client | A client MUST draw `nonce` from the device CSPRNG for each `CVFY`. |  |  |
| `ATT-115` | §13.4.1 | MUST | A relay | A relay MUST answer a `CVFY` with a `CPRF` that carries the value above. |  |  |
| `ATT-116` | §13.4.1 | MUST | A relay | A relay MUST answer with an unknown-chunk response when it holds no chunk at that `chunk_id`. |  |  |
| `ATT-117` | §13.4.1 | MUST | A client | A client MUST compare `proof` against the value that it computes from its own copy. |  |  |
| `ATT-118` | §13.4.1 | MUST | (unstated) | If the two values differ, or if the relay answers unknown-chunk, the client MUST send `CNEW` and `CPUT` to a fresh relay for that chunk. |  |  |
| `ATT-119` | §13.4.1 | MUST | The client | The client MUST report the relay that failed as a link fault under Part 10 §10.4.2. |  |  |
| `ATT-120` | §13.4.1 | MUST | A client | A client MUST select the sampled chunks at random. |  |  |
| `ATT-121` | §13.4.1 | MUST NOT | A client | A client MUST NOT use a fixed sample position, because a relay that predicts the sample replicates that chunk and drops the others. |  |  |
| `ATT-122` | §13.4.1 | MUST | A client | A client MUST select the `REPLICAS` relays of one chunk independently of the relays of each other chunk. |  |  |
| `ATT-123` | §13.4 | MUST NOT | A client | A client MUST NOT upload more than one copy of a chunk, and §13.4.1 makes the relay push the others. |  |  |
| `ATT-124` | §13.7.2 | MUST | A revision that takes the code above | A revision that takes the code above MUST make that measurement first, and it MUST state the §13.2.2 concession or the device cost in the Part 2 §2.4 table. |  |  |
| `ATT-125` | §13.3.3 | MUST NOT | A relay | A relay MUST NOT set the erase time of a chunk later than `CHUNK_LIFE_MAX` after the `CNEW`. |  |  |
| `ATT-126` | §13.3.3 | MUST NOT | A relay | A relay MUST NOT answer a `CRNW`. |  |  |
| `ATT-127` | §13.3.3 | MUST | A relay | A relay MUST hold a backup-class chunk for `BACKUP_TTL` after the `CPUT` or the `CRPUT` that gave the bytes. |  |  |
| `ATT-128` | §13.3.3 | MUST | A relay | A relay MUST reject a `CRNW` on a backup-class chunk. |  |  |
| `ATT-129` | §13.3.3 | MUST | A relay | A relay MUST apply each other rule of this section to a backup-class chunk as to an attachment chunk. |  |  |
| `ATT-130` | §13.3.3 | MUST | A relay | A relay MUST apply the admission control of Part 14 to a `BNEW` as to a `CNEW`. |  |  |
| `ATT-131` | §13.3.3 | MUST NOT | A client | A client MUST NOT register a backup object under `CNEW`, and it MUST NOT register an attachment under `BNEW`. |  |  |
| `ATT-132` | §13.3.3 | MUST | A client | A client MUST register a backup-class chunk at `BACKUP_REPLICAS` relays under different operators. |  |  |
| `ATT-133` | §13.4.2 | MUST | A writer | A writer MUST select the first `BACKUP_REPLICAS` relays of the placement list of `h`. |  |  |
| `ATT-134` | §13.4.2 | MUST | (unstated) | If a `BNEW` at a selected relay fails, the writer MUST replace that relay with the next of the list. |  |  |
| `ATT-135` | §13.4.2 | MUST | A writer | A writer MUST send `CPUT` to the selected relay of the lowest rank and `CREP` for the others, under §13.4.1. |  |  |
| `ATT-136` | §13.4.2 | MUST | A reader | A reader MUST send `CGET` to the relays of the placement list in list order, until it holds the chunk. |  |  |
| `ATT-137` | §13.4.2 | MUST NOT | A reader | A reader MUST NOT ask more than `PLACE_PROBE` relays for one `h`. |  |  |
| `ATT-138` | §13.4.2 | MUST | (unstated) | Before a writer replaces the chunk under one `h`, it MUST send `CDEL` to each relay that holds it. |  |  |
| `ATT-139` | §13.4.2 | MUST | A party | A party MUST compute the placement list from the consensus that it holds. |  |  |
| `ATT-140` | §13.4.2 | MUST | (unstated) | If a handle-addressed chunk has no named write credential, the writer MUST use a random `cred_sk` of `ATT-034`. |  |  |
| `ATT-141` | §13.3.2 | MUST | A client | A client MUST set a `RelayRef` that names no relay to 12 zero bytes. |  |  |
| `ATT-142` | §13.3.2 | MUST | A receiver | A receiver MUST reject a `FileDescriptor` with a null `RelayRef` on a pairwise, group, or community channel. |  |  |
| `ATT-143` | §13.4.2 | MUST NOT | A party | A party MUST NOT fetch a consensus for that computation. |  |  |
| `ATT-144` | §13.10 | SHOULD | A writer | A writer SHOULD prefer a relay at store level 2 or 3 for a `CNEW` or a `BNEW`. |  |  |
| `ATT-147` | §13.2.3 | MUST | The writer of a handle-addressed chunk | The writer of a handle-addressed chunk MUST pad its sealed object under the scheme above. |  |  |
| `ATT-148` | §13.2.3 | MUST | A reader of such a chunk | A reader of such a chunk MUST reject a sealed object shorter than 16 bytes. |  |  |
| `ATT-149` | §13.3.1 | MUST | A sender | A sender MUST seal each segment under `nonce_i` and the associated data above. |  |  |
| `ATT-150` | §13.3.1 | MUST | A receiver | A receiver MUST reject a chunk whose tag fails. |  |  |
| `ATT-151` | §13.3.1 | MUST | A receiver | A receiver MUST reject a file whose last chunk under `padded_size` carries `last_i` of `0x00`. |  |  |
| `ATT-152` | §13.3.1 | MAY | A receiver | A receiver MAY render the verified segments of a media object in chunk order before that check completes. |  |  |
| `ATT-153` | §13.3 | MUST | A sender | A sender MUST set `pixel_w` and `pixel_h` for an image and for a video, after the re-encode of `ATT-155`. |  |  |
| `ATT-154` | §13.3 | MUST | A receiver | A receiver MUST size the placeholder of an image or a video from those two fields. |  |  |
| `ATT-155` | §13.3 | MUST | A sender | A sender MUST re-encode an image, an audio, a voice, or a video object before the encryption. |  |  |
| `ATT-156` | §13.3 | MUST | A sender | A sender MUST re-encode an image above `IMAGE_REENCODE_BYTES` to at most that size. |  |  |
| `ATT-157` | §13.3 | MUST | (unstated) | If the user selects the original for one send, the sender MUST skip both re-encodes for that send and MUST state that the original carries its metadata fields. |  |  |
| `ATT-158` | §13.3 | MUST NOT | A client | A client MUST NOT reuse a `file_key`, a `file_nonce`, or a `ChunkRef` across two conversations. |  |  |
| `ATT-159` | §13.3.1 | MUST | A receiver | A receiver MUST reject a file in which a chunk before the last one carries `last_i` of `0x01`. |  |  |
| `ATT-160` | §13.3.3 | MUST | An uploader | An uploader MUST retain the `cred_sk` of each chunk until the chunk is erased. |  |  |
| `ATT-161` | §13.3.3 | MUST | (unstated) | When a client applies a deletion to a record with a descriptor it uploaded, it MUST send `CDEL` for each `ChunkRef`. |  |  |
| `ATT-162` | §13.7.1 | MUST | A revision | A revision MUST hold `BACKUP_TTL` of Part 4 §4.8 at or above `BACKUP_LOOKBACK` weekly epochs less one epoch. |  |  |
| `ATT-163` | §13.7.1 | MUST | A revision | A revision MUST hold `BACKUP_TTL` above `BACKUP_FULL_INTERVAL` plus `BACKUP_HISTORY_DAYS`. |  |  |
| `ATT-164` | §13.7.2 | MUST NOT | A client | A client MUST NOT hold more than 8 `CPUT` in flight. |  |  |
| `ATT-165` | §13.7.2 | MUST NOT | A client | A client MUST NOT hold more than 32 `CGET` in flight. |  |  |
| `ATT-166` | §13.7.2 | MUST | A client | A client MUST send the `CREP` of a chunk while the `CPUT` of the next chunk is in flight. |  |  |
| `ATT-167` | §13.7.2 | MUST | A client | A client MUST build the attachment circuit of §13.8 in the privacy mode of the conversation that carries the descriptor. |  |  |
| `ATT-168` | §13.10 | MAY | A relay above `CHUNK_STORE_TARGET` | A relay above `CHUNK_STORE_TARGET` MAY erase attachment chunks before `CHUNK_TTL`, oldest renewal first. |  |  |
| `ATT-169` | §13.11 | MUST NOT | A relay | A relay MUST NOT serve more than `CHUNK_EGRESS_BUDGET_DAY` of chunk bytes in one day. |  |  |
| `ATT-170` | §13.11 | MUST | Above that budget, a relay | Above that budget, a relay MUST answer a `CGET` with a `NACK` of reason `BUSY`, and Part 6 §6.4.4 gives the reason. |  |  |
| `ATT-171` | §13.11 | MUST NOT | A relay | A relay MUST NOT serve one chunk more than `CHUNK_FETCH_RATE` times in one hour. |  |  |
| `ATT-172` | §13.11 | MUST | Above that rate, a relay | Above that rate, a relay MUST answer a `CGET` of that chunk with a `NACK` of reason `LIMIT`. |  |  |
| `ATT-173` | §13.11 | MUST | A client that receives `BUSY` or `LIMIT` for a chunk | A client that receives `BUSY` or `LIMIT` for a chunk MUST fetch the next replica of the `ChunkRef`. |  |  |
| `ATT-174` | §13.11 | MUST NOT | A client | A client MUST NOT send the same `CGET` to the same relay again inside one hour. |  |  |
| `ATT-175` | §13.11 | MUST | An author of a community attachment | An author of a community attachment MUST register `HOT_REPLICAS` copies of each chunk when the activity bucket of the community is at its top level, under Part 9 §9.12. |  |  |
| `ATT-176` | §13.11 | MUST | A receiver | A receiver MUST treat two refs with one `chunk_id` as replicas of one chunk. |  |  |
| `ATT-177` | §13.2.3 | MUST | A receiver | A receiver MUST pass over each `0x00` byte of that read. |  |  |
| `ATT-178` | §13.7.2 | MUST NOT | A client | A client MUST NOT wait for the `CRPUT` of a replica before the next `CPUT`. |  |  |
| `ATT-179` | §13.10 | MUST NOT | Such a relay | Such a relay MUST NOT erase a backup-class chunk. |  |  |
| `ATT-180` | §13.3.3 | MUST | A relay | A relay MUST authorize `CREP` and `CVFY` against `cred_pk` only, and it MUST authorize a `CNEW` and a `BNEW` against the `cred_pk` that the payload carries, in the same manner as Part 6 §6.4 authorizes a `NEW` against the key in its payload. |  |  |
| `ATT-181` | §13.3.3 | MUST | A pending registration whose bytes never arrive | A pending registration whose bytes never arrive MUST leave the relay at `CHUNK_TTL` after the `CNEW` or the `BNEW`, and the relay MUST count it as `CHUNK_SIZE` of used store until then. |  |  |
| `ATT-182` | §13.3.3 | MUST | A client | A client MUST derive `read_sk` as `HKDF-SHA3-256(salt = "", ikm = file_key, info = "umbra/v1/chunk-read" || BE32(chunk_index), L = 32)`, and it MUST clamp the result as an X25519 scalar. |  |  |
| `ATT-183` | §13.3.4 | MUST | A client | A client MUST derive `K_manifest` as `HKDF-SHA3-256(salt = "", ikm = file_key, info = "umbra/v1/file-manifest" || file_nonce, L = 32)`. |  |  |
| `ATT-184` | §13.3.4 | MUST | (unstated) | A manifest carries no digest of its own: the tag of each manifest chunk under `K_manifest` authenticates it, and a receiver MUST accept a manifest whose chunks each verify under §13.3.1 and whose ref count equals the data chunk count of `padded_size`. |  |  |
| `ATT-185` | §13.4.1 | MUST | A relay | A relay MUST reject a `CREP` whose `target_count` is 0 or above `HOT_REPLICAS` − 1. |  |  |
| `ATT-186` | §13.3.3 | MUST | A relay | A relay MUST answer an accepted `CPUT` and an accepted `CREP` with a `CPRF` whose `proof` is `SHA3-256(corr_id || chunk)`, where `corr_id` is the 16 bytes of that command and `chunk` is what the relay holds. |  |  |
| `ATT-187` | §13.3.3 | MUST | A relay | A relay MUST answer an accepted `CDEL` with a `CPRF` of 32 zero bytes. |  |  |
| `ATT-188` | §13.3.3 | MUST | A client | A client MUST compare the `proof` of `ATT-186` against the value from its own copy, and it MUST take a difference as a failed `CPUT` under `ATT-118`. |  |  |
| `ATT-189` | §13.4.1 | MUST | (unstated) | A registration, a `CPUT` or a `CREP` that a relay refuses, or that gets no answer, fails the chunk before its copies exist. |  |  |
| `ATT-190` | §13.4.1 | MUST | (unstated) | A `CVFY` can arrive before the copy that it asks for, because the copy travels on a connection of its own. |  |  |

## ABU — Anti-Abuse Without Identifiers

Source: `spec/14-anti-abuse.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `ABU-001` | §14.4 | MUST NOT | UMBRA | UMBRA MUST NOT build a three-party Attester. |  |  |
| `ABU-002` | §14.5 | MUST | A client | A client MUST refuse a token from a key that is not in the log. |  |  |
| `ABU-003` | §14.5 | MUST | A client | A client MUST also refuse to redeem against a relay that advertises a key that is not in the log. |  |  |
| `ABU-004` | §14.6 | MUST | An issuer | An issuer MUST rotate each issuer key at one global 7-day epoch boundary. |  |  |
| `ABU-005` | §14.6 | MUST NOT | An issuer | An issuer MUST NOT give one key or one relay a rotation of its own. |  |  |
| `ABU-006` | §14.7 | MUST NOT | UMBRA | UMBRA MUST NOT build a global double-spend database. |  |  |
| `ABU-007` | §14.8 | MUST NOT | An implementation | An implementation MUST NOT let an attacker influence the effort parameter. |  |  |
| `ABU-008` | §14.8 | MUST | The client | The client MUST give the user visible feedback during the computation. |  |  |
| `ABU-009` | §14.10 | MUST | An implementation | An implementation MUST use that definition for the designated verifier of this part. |  |  |
| `ABU-010` | §14.10 | MUST NOT | UMBRA | **UMBRA MUST NOT build a global moderator key**. |  |  |
| `ABU-011` | §14.10 | MUST NOT | UMBRA | UMBRA MUST NOT frank a 1:1 message. |  |  |
| `ABU-012` | §14.4 | MUST | An addressee client | An addressee client MUST verify the `Admission` at the end of a hello before it shows the request. |  |  |
| `ABU-013` | §14.4 | MUST NOT | A deployment | A deployment MUST NOT put a privately verifiable credential on a path whose verifier is not its issuer. |  |  |
| `ABU-014` | §14.2.1 | MUST | That verifier | That verifier MUST accept a correct proof of work of §14.8 in place of the credential of the row. |  |  |
| `ABU-015` | §14.2.1 | MUST NOT | A relay | A relay MUST NOT need a token for a queue creation. |  |  |
| `ABU-016` | §14.2.1 | MUST NOT | An issuer | An issuer MUST NOT need an identifier from a client to issue a token batch. |  |  |
| `ABU-017` | §14.2.1 | MUST | A deployment | A deployment MUST publish the attestation that it uses for an issuance. |  |  |
| `ABU-018` | §14.2.1 | MUST NOT | A deployment | A deployment MUST NOT use a hardware attestation for that purpose, and §14.11 gives the cause. |  |  |
| `ABU-019` | §14.10 | MUST | A reporter | A reporter MUST encapsulate to that key with `UMBRA-KEM`. |  |  |
| `ABU-020` | §14.10 | MUST NOT | An implementation | An implementation MUST NOT name an ML-DSA-65 key as a designated verifier key. |  |  |
| `ABU-021` | §14.12 | MUST | A client | A client MUST hold the block state as mutable state of Part 7 §7.5.3. |  |  |
| `ABU-022` | §14.12 | MUST | A client | A client MUST converge that state across the device set. |  |  |
| `ABU-023` | §14.12 | MUST NOT | A client | A client MUST NOT send a record to the blocked party that names the block. |  |  |
| `ABU-024` | §14.12 | MUST NOT | A client | A client MUST NOT change the queue set of that contact at the block. |  |  |
| `ABU-025` | §14.12 | MUST NOT | A client | A client MUST NOT send `DEL` on the queue of a blocked contact. |  |  |
| `ABU-026` | §14.12 | MUST | A client | A client MUST continue to send `ACK` for the records of a blocked contact. |  |  |
| `ABU-027` | §14.12 | MUST | A client | A client MUST discard a record of a blocked contact after it acknowledges that record. |  |  |
| `ABU-028` | §14.12 | MUST NOT | A client | A client MUST NOT render such a record. |  |  |
| `ABU-029` | §14.12 | MUST NOT | A client | A client MUST NOT raise a notification for such a record. |  |  |
| `ABU-030` | §14.12 | MUST | A client | A client MUST continue to emit a delivery receipt of Part 6 §6.6 kind `0x06` at the rate that held before the block. |  |  |
| `ABU-031` | §14.12 | MUST NOT | A client | A client MUST NOT emit a read receipt of kind `0x07` for a blocked contact. |  |  |
| `ABU-032` | §14.12 | MUST | A client | A client MUST continue to advance the ratchet of a blocked contact. |  |  |
| `ABU-033` | §14.12 | MUST NOT | A client | A client MUST NOT let the skipped-key store of Part 5 §5.5.4 grow past `MAX_STORED` for that session. |  |  |
| `ABU-034` | §14.12 | MUST | A client | A client MUST restore the ordinary behavior at an unblock. |  |  |
| `ABU-035` | §14.12 | MUST NOT | A client | A client MUST NOT deliver a record that it discarded under ABU-027 to the user at an unblock. |  |  |
| `ABU-036` | §14.12 | MUST | A client | A client MUST discard a record of a blocked member of a group. |  |  |
| `ABU-037` | §14.12 | MUST NOT | A client | A client MUST NOT emit a group record that names the block. |  |  |
| `ABU-038` | §14.12 | MUST | A client | A client MUST show the count of the records that it discarded, thus a user knows that the conversation has a gap. |  |  |
| `ABU-039` | §14.12 | MUST | A client | A client MUST offer the removal of Part 11 §11.9.2 to a member that holds a role of `admin` or above, beside the block. |  |  |
| `ABU-040` | §14.12 | MUST | The interface | The interface MUST state that a blocked party can still send. |  |  |
| `ABU-041` | §14.12 | MUST | The interface | The interface MUST state that a block does not tell the blocked party. |  |  |
| `ABU-042` | §14.12 | MUST NOT | The interface | The interface MUST NOT claim that a block stops a message. |  |  |
| `ABU-043` | §14.10 | MUST | A reporter | A reporter MUST send a report under Part 12 §12.5.3 and under no other carrier. |  |  |
| `ABU-044` | §14.2 | MUST | A client | A client MUST end the payload of a `NEW`, a `CNEW`, a `BNEW`, and a `PUB` with one `Admission`. |  |  |
| `ABU-045` | §14.2 | MUST | A parser | A parser MUST reject a `kind` that the table above does not hold. |  |  |
| `ABU-046` | §14.2 | MUST | A parser | A parser MUST reject a `len` that differs from the body length of its `kind`. |  |  |
| `ABU-047` | §14.2 | MUST | A relay whose newest `PowChallenge` holds `effort` 0 | A relay whose newest `PowChallenge` holds `effort` 0 MUST accept an `Admission` of kind `0x00` on `NEW`, `CNEW`, and `BNEW`. |  |  |
| `ABU-048` | §14.2 | MUST | (unstated) | If that `effort` is above 0, the relay MUST answer such a command with a `NACK` of reason `ADMISSION`. |  |  |
| `ABU-049` | §14.2 | MUST | A relay | A relay MUST accept an `Admission` of kind `0x00` on a `PUB` under `POST_RATE_LIMIT` that is not a community creation. |  |  |
| `ABU-056` | §14.4 | MUST | An addressee client | An addressee client MUST hold the spent-nonce set of an epoch until the end of the next epoch. |  |  |
| `ABU-057` | §14.8 | MUST | A verifier | A verifier MUST make a new `PowChallenge` with a fresh `seed` at each `POW_CHALLENGE_PERIOD`. |  |  |
| `ABU-058` | §14.8 | MUST | A verifier | A verifier MUST accept a solution to its newest challenge and to the one before it. |  |  |
| `ABU-059` | §14.8 | MUST NOT | A verifier | A verifier MUST NOT accept a solution to an older challenge. |  |  |
| `ABU-060` | §14.8 | MUST | A relay | A relay MUST derive `effort` from the backlog of its own admission queue over the last `POW_CHALLENGE_PERIOD`. |  |  |
| `ABU-061` | §14.8 | MUST NOT | A verifier | A verifier MUST NOT take an `effort` value from a client or from another party. |  |  |
| `ABU-062` | §14.8 | MUST NOT | A verifier | A verifier MUST NOT set `effort` above `POW_EFFORT_MAX`. |  |  |
| `ABU-063` | §14.8 | MUST | A relay | A relay MUST publish its newest challenge to the directory authorities at each `POW_CHALLENGE_PERIOD`. |  |  |
| `ABU-064` | §14.8 | MUST | A directory authority | A directory authority MUST serve the newest challenge of a relay beside the descriptor of that relay. |  |  |
| `ABU-065` | §14.8 | MUST | A client | A client MUST fetch the challenge of a relay on the path of a descriptor fetch. |  |  |
| `ABU-066` | §14.8 | MUST NOT | A client | A client MUST NOT open a session for the only purpose of a challenge fetch. |  |  |
| `ABU-067` | §14.8 | MUST | A verifier other than a relay or an addressee client | A verifier other than a relay or an addressee client MUST return its newest challenge with each admission rejection. |  |  |
| `ABU-068` | §14.8 | MUST | A client | A client MUST verify `sig` against the identity key of the verifier before it computes a solution. |  |  |
| `ABU-069` | §14.8 | MUST NOT | A client | A client MUST NOT compute a solution to a challenge that it fetched more than `POW_CHALLENGE_PERIOD` before. |  |  |
| `ABU-070` | §14.8 | MUST NOT | The handle directory | The handle directory MUST NOT set `effort` below `POW_LOOKUP_FLOOR`. |  |  |
| `ABU-071` | §14.8 | MUST | A verifier | A verifier MUST reject a `PowSolution` whose `seed` is not the seed of a challenge that `ABU-058` accepts. |  |  |
| `ABU-072` | §14.8 | MUST | A verifier | A verifier MUST reject a `PowSolution` whose `effort` is below the `effort` of that challenge. |  |  |
| `ABU-073` | §14.8 | MUST | A verifier | A verifier MUST reject a `PowSolution` that fails the Equi-X verification or the `pass` test. |  |  |
| `ABU-074` | §14.8 | MUST | A verifier | A verifier MUST reject a `PowSolution` whose `nonce` it accepted before under the same `seed`. |  |  |
| `ABU-075` | §14.8 | MUST | A client | A client MUST set `effort` in a `PowSolution` at or above the `effort` of the challenge that it holds. |  |  |
| `ABU-076` | §14.9 | MUST | (unstated) | On path 3 the issuer MUST demand one `PowSolution` at `POW_EFFORT_MAX` for each token of the batch. |  |  |
| `ABU-077` | §14.9 | MUST NOT | The issuer | The issuer MUST NOT issue a token on path 3 for a solution at a lower effort. |  |  |
| `ABU-078` | §14.4 | MUST | An addressee client | An addressee client MUST verify a token of a hello against an issuer key of the log of §14.5. |  |  |
| `ABU-079` | §14.4 | MUST NOT | An addressee client | An addressee client MUST NOT accept a token of a type other than `0x0002` in a hello. |  |  |
| `ABU-080` | §14.4 | MUST | An addressee client | An addressee client MUST accept a token of the current epoch and a token of the epoch before it. |  |  |
| `ABU-081` | §14.4 | MUST | An addressee client | An addressee client MUST reject a token whose nonce it accepted before at the same Profile. |  |  |
| `ABU-082` | §14.4 | MUST | A client that holds no token | A client that holds no token MUST compute the solution of a hello under the three values above. |  |  |
| `ABU-083` | §14.4 | MUST | An addressee client | An addressee client MUST verify a `PowSolution` of a hello against the seed of the current epoch and against the seed of the epoch before it. |  |  |
| `ABU-084` | §14.4 | MUST | An addressee client | An addressee client MUST apply `ABU-072` to `ABU-074` to that solution, with `HELLO_POW_EFFORT` as the effort of the challenge. |  |  |
| `ABU-085` | §14.4 | MUST | An addressee client | An addressee client MUST reject a hello whose `Admission` is of kind `0x00`. |  |  |
| `ABU-086` | §14.4 | MUST NOT | An addressee client | An addressee client MUST NOT show more than `HELLO_INBOUND_LIMIT` hellos for one published entry in one epoch. |  |  |
| `ABU-087` | §14.4 | MUST | (unstated) | If the client reaches that limit, it MUST offer the rotation of Part 9 §9.9.3 to the user. |  |  |
| `ABU-088` | §14.4 | MUST | The client | The client MUST discard a hello above the limit after it acknowledges the record. |  |  |
| `ABU-089` | §14.2 | MUST | A parser | A parser MUST reject kind `0x02`, which an earlier draft gave to an ARC presentation. |  |  |
| `ABU-090` | §14.9 | MUST | The nonprofit | The nonprofit MUST publish the price of a token batch with the cost model of Part 16 §16.6.1. |  |  |
| `ABU-091` | §14.9 | MUST NOT | The nonprofit | The nonprofit MUST NOT set that price above the recovery of the relay cost. |  |  |
| `ABU-092` | §14.8 | MUST | That derivation | That derivation MUST be `effort = min(POW_EFFORT_MAX, backlog / POW_BACKLOG_UNIT)`, raised to the floor of the verifier where one applies, with `backlog` the count of admissions pending in that period. |  |  |
| `ABU-093` | §14.3.2 | MUST | A party | A party MUST compute `token_key_id` as `SHA3-256` over the issuer public key bytes: the 256-byte modulus of a `0x0002` key, or the 32-byte ristretto255 element of a `0x0005` key. |  |  |
| `ABU-094` | §14.3.2 | MUST | A party | A party MUST compute `challenge_digest` as `SHA3-256` over `TokenChallenge = token_type u16 || epoch u32 || redemption_context [32]u8`, where `epoch` is the epoch number of §14.6 and `redemption_context` is the `relay_id` of one relay under §14.7, or 32 zero bytes for any relay of the type. |  |  |
| `ABU-095` | §14.3.2 | MUST | A verifier | A verifier MUST accept a token whose `challenge_digest` names the current epoch or the one before it, with its own `relay_id` or the zero context, and MUST reject each other digest. |  |  |
| `ABU-096` | §14.3.2 | MUST | (unstated) | The `0x0002` authenticator is the RFC 9474 signature over `token_input` with a 48-byte salt that the client draws at the blind, and the `0x0005` authenticator is the RFC 9497 output over `token_input` at the VOPRF mode. |  |  |
| `ABU-097` | §14.3.2 | MUST | An issuer | An issuer MUST answer a batch of `0x0005` requests with one DLEQ proof over the batch, and a client MUST verify that proof before it finalizes a token of the batch. |  |  |
| `ABU-098` | §14.5 | MUST | An issuer | An issuer MUST publish the key of each token type for each epoch as version 0 of the label above, before the epoch starts. |  |  |
| `ABU-099` | §14.5 | MUST | A client | A client MUST look up that label under Part 9 §9.4, and it MUST verify the `LookupProof` of Part 9 §9.5.1 before it accepts the key. |  |  |
| `ABU-100` | §14.5 | MUST | A client | A client MUST reject the label when its newest version is not A second version is a second key for one epoch, and the binary ladder of Part 9 §9.5.1 shows it to each client. |  |  |
| `ABU-101` | §14.5 | MUST | A client | A client MUST reject an entry whose `token_type` or `epoch` differs from the label that it looked up. |  |  |

## IMP — Implementation

Source: `spec/15-implementation.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `IMP-002` | §15.2 | MUST | A change | A change MUST name the register that it charges. |  |  |
| `IMP-003` | §15.2 | MUST | (unstated) | A claim that a change costs no crate MUST name that register too. |  |  |
| `IMP-004` | §15.2.1 | MUST | An implementation | An implementation **MUST** turn the `pkcs8` default off. |  |  |
| `IMP-005` | §15.2.2 | MUST NOT | (unstated) | If the measured R2 count is more than 30, the maintainers MUST NOT tag a release. |  |  |
| `IMP-006` | §15.2.2 | MUST | Those maintainers | Those maintainers MUST first remove a primitive, or MUST first revise this section with a written cause. |  |  |
| `IMP-007` | §15.2.3 | MUST NOT | One subsystem in R3 | One subsystem in R3 MUST NOT add more transitive crates than its row in the table below. No single platform part costs more than the whole message core. |  |  |
| `IMP-008` | §15.2.3 | MUST | (unstated) | At the first measurement, the maintainers MUST publish the R3 count. |  |  |
| `IMP-009` | §15.2.3 | MUST | Those maintainers | Those maintainers MUST set the R3 cap in the same change. |  |  |
| `IMP-010` | §15.2.4 | MUST | That commit | That commit MUST also add a `DEPENDENCIES.md` file at the root of the repository. |  |  |
| `IMP-011` | §15.2.4 | MUST | `DEPENDENCIES.md` | `DEPENDENCIES.md` MUST hold the five items of §15.2.4. |  |  |
| `IMP-012` | §15.2.4 | MUST | The maintainers | The maintainers MUST publish `DEPENDENCIES.md` before the first tagged release. |  |  |
| `IMP-013` | §15.2.4 | MUST NOT | The maintainers | The maintainers MUST NOT tag a release without that file. |  |  |
| `IMP-014` | §15.2.4 | MUST | A CI job | A CI job MUST generate that file again at each commit. |  |  |
| `IMP-015` | §15.2.4 | MUST | That job | That job MUST fail the build on a difference against the committed file. |  |  |
| `IMP-016` | §15.3 | MUST | That crate | That crate MUST give byte-identical output to the portable path. |  |  |
| `IMP-017` | §15.4 | MUST NOT | (unstated) | Key material, a passphrase, and message plaintext MUST NOT be a Kotlin `String` or `ByteArray`. |  |  |
| `IMP-019` | §15.5.2 | MUST | (unstated) | The portable build, the AVX2 build, and the NEON build MUST serialize each cryptographic object identically, at each commit. |  |  |
| `IMP-020` | §15.5.4 | MUST | An implementation | An implementation MUST hold a `SOUNDNESS.md` file. |  |  |
| `IMP-021` | §15.6.2 | MUST | (unstated) | `llvm-objdump -p libumbra.so \| grep LOAD` MUST show `align 2**14` or higher. |  |  |
| `IMP-022` | §15.6.2 | MUST | `zipalign -v -c -P 16 4` | `zipalign -v -c -P 16 4` MUST pass. |  |  |
| `IMP-023` | §15.6.4 | MUST | A client | A client MUST derive the record key with the input set of the block above, and with no other input. |  |  |
| `IMP-024` | §15.6.4 | MUST | A client | A client MUST store the keyed form of `msg_id` that Part 6 §6.6 gives. |  |  |
| `IMP-025` | §15.6.4 | MUST NOT | A client | A client MUST NOT store the raw value. |  |  |
| `IMP-026` | §15.6.4 | MUST | That item | That item MUST use a different label and a different access-control policy. |  |  |
| `IMP-027` | §15.6.4 | MUST | An implementation | An implementation MUST let the user export it and delete it from the UMBRA settings. |  |  |
| `IMP-028` | §15.6.4 | MUST NOT | That operation | That operation MUST NOT change a local storage key. |  |  |
| `IMP-029` | §15.6.5 | MUST | Relay reputation | Relay reputation MUST come from measured behavior only. |  |  |
| `IMP-030` | §15.6.5 | MUST NOT | Relay reputation | Relay reputation MUST NOT come from device attestation. |  |  |
| `IMP-031` | §15.6.5 | MUST NOT | Relay reputation | Relay reputation MUST NOT come from a "genuine device" proof. |  |  |
| `IMP-032` | §15.8 | MUST | Two independent builds | Two independent builds MUST give the same hash. |  |  |
| `IMP-033` | §15.8 | MUST | A minimum of one rebuilder | A minimum of one rebuilder MUST be outside the control of the nonprofit. |  |  |
| `IMP-034` | §15.5.2 | MUST | The repository | The repository MUST vendor the NIST ACVP and CAVP corpora and the C2SP `testvectors_v1` corpus at `tests/vectors/`. |  |  |
| `IMP-035` | §15.5.2 | MUST | The repository | The repository MUST hold a `tests/vectors/PROVENANCE.md` file that records the upstream commit of each corpus. |  |  |
| `IMP-036` | §15.5.2 | MUST NOT | A test | A test MUST NOT fetch a vector at test time. |  |  |
| `IMP-037` | §15.6.1 | MUST NOT | The FFI surface | The FFI surface MUST NOT carry message plaintext, key material, or a passphrase as a Kotlin `ByteArray`, a Kotlin `String`, a Swift `Data`, or a Swift `String`. |  |  |
| `IMP-038` | §15.6.1 | MUST | `Draft` and `MsgRef` | `Draft` and `MsgRef` MUST be opaque UniFFI object handles. |  |  |
| `IMP-039` | §15.6.1 | MUST | An implementation | An implementation MUST zeroize the buffer behind a `Draft` when that draft is dropped, and it MUST do that whether the send succeeded or failed. |  |  |
| `IMP-040` | §15.6.4 | MUST | A client | A client MUST make a fresh `record_salt` and a fresh `nonce` from the CSPRNG at each write of a record. |  |  |
| `IMP-041` | §15.6.4 | MUST | A client that discards a record key under Part 7 | A client that discards a record key under Part 7 MUST overwrite `record_salt` with zero bytes. |  |  |
| `IMP-042` | §15.6.4 | MUST | A client | A client MUST open the database with `PRAGMA secure_delete=ON`. |  |  |
| `IMP-043` | §15.6.4 | MUST | A client | After a client applies a deletion batch, it MUST run `PRAGMA wal_checkpoint(TRUNCATE)`. |  |  |
| `IMP-044` | §15.6.6 | MUST | A client | A client MUST write a decrypted attachment inside the encrypted store of §15.6.4. |  |  |
| `IMP-045` | §15.6.6 | MUST NOT | A client | A client MUST NOT write a decrypted attachment to the platform media store without an explicit user action. |  |  |
| `IMP-046` | §15.6.6 | MUST | A client | Before the first such action, a client MUST show a one-time warning. |  |  |
| `IMP-047` | §15.6.6 | MUST | That warning | That warning MUST state that the file leaves the encrypted store, and that each platform service then reads it. |  |  |
| `IMP-048` | §15.6.6 | MUST | An Android client | An Android client MUST set `android:allowBackup="false"` on the `<application>` element, with `tools:replace="android:allowBackup"`. |  |  |
| `IMP-050` | §15.6.6 | MUST | The settings of a client | The settings of a client MUST state that the platform backup carries no UMBRA data. |  |  |
| `IMP-055` | §15.6.6 | MUST | A client | A client MUST draw a cover view over each conversation surface before the application leaves the foreground. |  |  |
| `IMP-056` | §15.6.6 | MUST | A client | A client MUST mark a copied message as sensitive. |  |  |
| `IMP-057` | §15.6.6 | MUST | An Android client | An Android client MUST set `IME_FLAG_NO_PERSONALIZED_LEARNING` on each composer and on the passphrase field. |  |  |
| `IMP-058` | §15.6.6 | MUST | A client | A client MUST offer a screenshot block as a setting of one conversation, and not as a global setting. |  |  |
| `IMP-059` | §15.6.6 | MUST NOT | A client | A client MUST NOT block a screenshot in a conversation by default. |  |  |
| `IMP-060` | §15.6.6 | MUST NOT | A client | A client MUST NOT hide a message from the accessibility tree. |  |  |
| `IMP-061` | §15.6.4 | MUST | A client | A client MUST derive `K_wrap` with the block above, and with no other input. |  |  |
| `IMP-062` | §15.6.4 | MUST | A client | A client MUST make the secure-element key with no export path. |  |  |
| `IMP-065` | §15.6.4 | MUST NOT | A client | A client MUST NOT demand a user authentication for each use of the secure-element key. |  |  |
| `IMP-066` | §15.2.8 | MUST | The L1 stack | The L1 stack MUST use `rustls` with the `aws-lc-rs` provider. |  |  |
| `IMP-067` | §15.2.8 | MUST NOT | An implementation | An implementation MUST NOT use the `ring` provider for L1. |  |  |
| `IMP-068` | §15.2.8 | MUST | The `rustls` build | The `rustls` build MUST turn the `tls12` feature off. |  |  |
| `IMP-069` | §15.2.8 | MUST | A build | A build MUST pin an `aws-lc-rs` version that ships the bindings for `aarch64-linux-android` and for `aarch64-apple-ios`. |  |  |
| `IMP-072` | §15.9.1 | MUST | A client | A client MUST hold each outbound record in one state of the table above. |  |  |
| `IMP-073` | §15.9.1 | MUST NOT | A client | A client MUST NOT add a state to the table. |  |  |
| `IMP-074` | §15.9.1 | MUST | A client | A client MUST show a `failed` record with its cause and with a resend affordance. |  |  |
| `IMP-075` | §15.9.1 | MUST NOT | A client | A client MUST NOT resend a `failed` record without a user action. |  |  |
| `IMP-076` | §15.9.1 | MUST NOT | A client | A client MUST NOT show a `queued` record as a failure. |  |  |
| `IMP-077` | §15.9.2 | MUST | A client | A client MUST show each current degraded state in one line at the top of the message list. |  |  |
| `IMP-078` | §15.9.2 | MUST NOT | A client | A client MUST NOT show a degraded state as a security failure. |  |  |
| `IMP-079` | §15.9.2 | MUST NOT | A client | A client MUST NOT block the message list, the composer, or a send in a degraded state. |  |  |
| `IMP-080` | §15.9.2 | MUST | A client | A client MUST leave a degraded state without a user action when its condition ends. |  |  |
| `IMP-081` | §15.9.2 | MUST NOT | A client | A client MUST NOT add a degraded state to the table without a row in Part 2 §2.4. |  |  |
| `IMP-082` | §15.9.2 | MUST | (unstated) | In the `recipient queue full` state, a client MUST keep the record `queued`. |  |  |
| `IMP-083` | §15.9.3 | MUST | Each string that a rule of this specification requires the interface to show | Each string that a rule of this specification requires the interface to show MUST carry a stable message identifier. |  |  |
| `IMP-084` | §15.9.3 | MUST | That identifier | That identifier MUST be `umbra.ui.` followed by the rule identifier in lower case. |  |  |
| `IMP-085` | §15.9.3 | MUST NOT | A revision | A revision MUST NOT change an identifier. |  |  |
| `IMP-086` | §15.9.3 | MUST | A test | A test MUST check that each identifier resolves to a non-empty string in each shipped locale. |  |  |
| `IMP-087` | §15.9.3 | MUST NOT | A release | A release MUST NOT ship a locale that fails that test. |  |  |
| `IMP-088` | §15.9.4 | MUST | The interface | The interface MUST meet WCAG 2.2 at level AA. |  |  |
| `IMP-089` | §15.9.4 | MUST | Text | Text MUST hold a contrast ratio of 4.5:1 or more against its background. |  |  |
| `IMP-090` | §15.10 | MUST | A client | A client MUST take each CSPRNG output from the platform source, which is `getrandom` on Android and `SecRandomCopyBytes` on iOS. |  |  |
| `IMP-091` | §15.10 | MUST NOT | A client | A client MUST NOT hold a userspace generator that it seeds one time. |  |  |
| `IMP-092` | §15.10 | MUST | A relay | A relay MUST take each CSPRNG output from `getrandom` of its kernel. |  |  |
| `IMP-093` | §15.10 | MUST | A client | A client MUST apply the hardening of Part 5 §5.9 to each value that the platform source gives. |  |  |
| `IMP-094` | §15.7.1 | MUST | The web client | The web client MUST ship as a browser extension bundle. |  |  |
| `IMP-095` | §15.7.1 | MUST NOT | A deployment | A deployment MUST NOT serve the web client as a hosted page, as a progressive web application, or as a script that a page loads. |  |  |
| `IMP-096` | §15.7.1 | MUST NOT | (unstated) | The bundle MUST hold each byte of code that the web client runs, and the web client MUST NOT load a script, a module, or a WebAssembly binary from a network location. |  |  |
| `IMP-097` | §15.7.2 | MUST NOT | (unstated) | A web client MUST be a linked device of a device set under Part 7, and it MUST NOT make a `RootIdentity`. |  |  |
| `IMP-098` | §15.7.2 | MUST NOT | A web client | A web client MUST NOT hold a Recovery Code of Part 4 §4.7.1, a `C_social` share, or a backup key of Part 4 §4.7.2. |  |  |
| `IMP-099` | §15.7.2 | MUST | (unstated) | A web client that finds its store absent or unreadable at start MUST return to the link flow of Part 7 §7.4, and it MUST show the line "This browser is no longer linked. |  |  |
| `IMP-100` | §15.7.2 | MUST | The existing device | The existing device MUST revoke the old entry under Part 7 §7.7 before it links the same browser again, and Part 7 rule `DEV-265` gives that step. |  |  |
| `IMP-101` | §15.7.3 | MUST NOT | (unstated) | A web client MUST use the WebSocket API of the browser over TLS to port 443, and it MUST NOT use WebTransport or `fetch` for the L1 stream in v1. |  |  |
| `IMP-102` | §15.7.3 | MUST NOT | A web client | A web client MUST NOT open a connection to a host other than its two pinned ingress relays of Part 10 §10.6.1 and the bootstrap carriers of Part 3 §3.10. |  |  |
| `IMP-103` | §15.7.3 | MUST | The extension manifest | The extension manifest MUST request no host permission on any site, no content script, and no access to the browsing data of the user. |  |  |
| `IMP-104` | §15.7.4 | MUST | A web client | A web client MUST encrypt each record with the record key of §15.6.4, and it MUST keep each metadata-sensitive column inside the encrypted blob. |  |  |
| `IMP-105` | §15.7.4 | MUST NOT | (unstated) | A web client MUST store in the IndexedDB of the extension origin only, and it MUST NOT use the sync storage area of the browser, the local storage area, or a cookie. |  |  |
| `IMP-106` | §15.7.4 | MUST | A web client | A web client MUST make `k_se` of §15.6.4 as a non-extractable HMAC-SHA256 key of the Web Cryptography API, and it MUST compute `S` with that key. |  |  |
| `IMP-107` | §15.7.4 | MUST | A web client | A web client MUST calibrate Argon2id to about 3 s for each try in the browser, in the manner of §15.6.4. |  |  |
| `IMP-108` | §15.7.4 | MUST | A web client that applies a deletion batch of §15.6.4 | A web client that applies a deletion batch of §15.6.4 MUST overwrite `record_salt` and the ciphertext of each record with zero bytes, and then delete the record. |  |  |
| `IMP-109` | §15.7.4 | MUST | A web client | A web client MUST call `navigator.storage.persist()` at the first launch, and it MUST treat a refusal as no error. |  |  |
| `IMP-110` | §15.7.5 | MUST | The settings of a web client | The settings of a web client MUST state that the browser receives messages while it runs, and that the phone receives each notification. |  |  |
| `IMP-111` | §15.7.5 | MUST | A web client | A web client MUST apply `IMP-044` to `IMP-047` with the download location as the platform media store. |  |  |
| `IMP-112` | §15.7.5 | MUST | A web client | A web client MUST state that the screenshot block of `IMP-058` is not available in the browser, because a browser gives no equivalent of `FLAG_SECURE`. |  |  |
| `IMP-113` | §15.7.6 | MUST NOT | The `umbra-web` crate | The `umbra-web` crate MUST NOT add more transitive crates than its row in §15.2.3. |  |  |
| `IMP-114` | §15.7.6 | MUST | The extension bundle | The extension bundle MUST be reproducible under §15.8, and Part 16 rule `SEC-005` names it. |  |  |
| `IMP-115` | §15.7.6 | MUST | The web client | The web client MUST verify the inclusion proof of Part 16 rule `SEC-006` for its own bundle at each start, and it MUST refuse to unlock the store while that proof is absent. |  |  |
| `IMP-116` | §15.6.4 | MUST | A client | A client MUST run Argon2id with one lane, a memory of 64 MiB or more, and 3 passes or more. |  |  |
| `IMP-117` | §15.6.4 | MUST | At the creation of the store, a client | At the creation of the store, a client MUST measure one try at that floor on the device, and it MUST raise the passes until one try takes about 3 s. |  |  |
| `IMP-118` | §15.6.4 | MUST | A passphrase change | A passphrase change MUST wrap the same `K_store` under a new `salt_pw` and a new `nonce_w`. |  |  |
| `IMP-119` | §15.6.4 | MUST NOT | A client | A client MUST NOT let the user set an auto-lock above 30 minutes of idle time, and the default MUST be 15 minutes. |  |  |
| `IMP-120` | §15.6.4 | MUST | `table_id` | `table_id` MUST be one byte, and `row_id` MUST be the 16 bytes of the block above. |  |  |
| `IMP-121` | §15.6.4 | MAY | A row | A row MAY carry one more indexed column, which is the `row_id` of the row that owns it, such as the conversation of a message. |  |  |
| `IMP-122` | §15.6.4 | MUST NOT | A client | A client MUST NOT open a record whose `record_salt` is zero bytes. |  |  |
| `IMP-123` | §15.6.4 | MUST | A client | A client MUST write the rows of a commit batch and the table MAC of each table that the batch changed in one transaction of the database. |  |  |
| `IMP-124` | §15.6.1 | MUST | Text and the passphrase | Text and the passphrase MUST cross as UTF-16 code units, and the Rust side MUST overwrite its copy after the use. |  |  |
| `IMP-125` | §15.6.1 | MUST | The secure-element step of §15.6.4 | The secure-element step of §15.6.4 MUST cross as one callback that takes the input of the keyed function and returns its 32 bytes. |  |  |
| `IMP-126` | §15.6.1 | MUST | A record that waits for the send path | A record that waits for the send path MUST sit in the store under the record encryption of §15.6.4, in a table of its own. |  |  |
| `IMP-127` | §15.6.1 | MUST | A lock | A lock MUST stop the network runtime, and the runtime MUST drop its state at that stop. |  |  |
| `IMP-128` | §15.6.1 | MUST | A client | A client MUST order a conversation view by the time of its own store of each message. |  |  |
| `IMP-129` | §15.6.1 | MUST NOT | (unstated) | A conversation identifier on the surface MUST be the surrogate of §15.6.4 under the store key, and it MUST NOT be a queue identifier. |  |  |
| `IMP-130` | §15.6.4 | MUST | A stored object | A stored object MUST start with a version byte, and a client MUST reject a row whose version it does not read. |  |  |
| `IMP-131` | §15.6.4 | MUST | A client | A client MUST commit each change of a channel to the store before it writes a byte of that call to the link. |  |  |
| `IMP-132` | §15.6.4 | MUST | A client | A client MUST commit a received record and the channel state that opened it in one batch of `IMP-123`. |  |  |
| `IMP-133` | §15.6.4 | MUST NOT | (unstated) | A client MUST replace the row of a channel at each commit, and it MUST NOT keep an earlier state of a channel. |  |  |
| `IMP-134` | §15.6.4 | MUST | At the start of a run a client | At the start of a run a client MUST send a `SUB` for each stored queue. |  |  |
| `IMP-135` | §15.6.4 | MUST NOT | (unstated) | A record that arrives a second time at or below the stored cursor, or at a stored sequence number above it, MUST NOT reach the ratchet. |  |  |
| `IMP-136` | §15.6.4 | MUST | A client | A client MUST delete the row of an invitation in the batch that follows the flight 1 that consumed its prekey, before flight 2 leaves. |  |  |
| `IMP-137` | §15.6.4 | MUST | A record that waits in the send queue at the start of a run | A record that waits in the send queue at the start of a run MUST go again under its `msg_id`. |  |  |
| `IMP-138` | §15.6.1 | MUST NOT | (unstated) | The name that a user gives a contact MUST stay on the devices of that user, and a client MUST NOT send it to a peer or to a relay. |  |  |
| `IMP-139` | §15.6.1 | MUST | A client | A client MUST count a received message as not seen while its store time is above the read marker of its conversation, and it MUST move that marker when the user looks at the conversation and at no other time. |  |  |
| `IMP-140` | §15.6.4 | MUST | A client | A client MUST keep that setting in the store, under the record encryption of this section. |  |  |
| `IMP-141` | §15.6.4 | MUST | A client | A client MUST ask for the current passphrase before a passphrase change. |  |  |
| `IMP-142` | §15.6.1 | MUST | (unstated) | The short code and the safety number of Part 4 §4.5 are public values of the two devices, and they cross the surface as strings. |  |  |
| `IMP-143` | §15.6.4 | MUST | (unstated) | A record that the client uses itself gives no message: a queue address, a record of a ceremony. |  |  |
| `IMP-144` | §15.6.1 | MUST | A client | A client MUST ask for the camera of the platform at the moment the user opens a scanner, and at no other time. |  |  |
| `IMP-145` | §15.6.4 | MUST | The surface | The surface MUST take the state of the app, on the screen or not, from the platform layer, and the runtime MUST select the cover tier of Part 3 §3.6.2 from that state alone. |  |  |
| `IMP-146` | §15.6.1 | MUST | A client | A client MUST hold a receipt in table `0x0B` from the commit of the message that it reports, or from the move of the read marker of `IMP-139`, to the slot that carries it (`NET-053`). |  |  |
| `IMP-147` | §15.6.1 | MUST NOT | A receipt is no message of a conversation, and a client | A receipt is no message of a conversation, and a client MUST NOT store it as one. |  |  |
| `IMP-148` | §15.6.1 | MUST NOT | (unstated) | A conversation view MUST show the read state as one mark of the contact at the newest message that the contact saw, and it MUST NOT write a word for that state on each message. |  |  |
| `IMP-149` | §15.6.1 | MUST | A stored record | A stored record MUST hold its `reply_target` as the `msg_ref` of Part 6 §6.6 (`WIR-170`). |  |  |
| `IMP-150` | §15.6.1 | MUST NOT | (unstated) | The surface MUST give the target of a reply as a handle of a message of the same conversation, or as absent (`WIR-173`), and it MUST NOT give a `msg_id` or a `msg_ref`. |  |  |
| `IMP-151` | §15.6.1 | MUST | The placeholder of Part 7 §7.5.6 | The placeholder of Part 7 §7.5.6 MUST be the row of the deleted message itself: the client overwrites the content of that row with a record of kind `0x05` that names the `msg_id` of the row, under a new record key (`DEV-099`, `DEV-100`). |  |  |
| `IMP-152` | §15.6.1 | MUST | (unstated) | A deletion request of this device is a record that waits for the send path as each other record does (`DEV-112`). |  |  |
| `IMP-153` | §15.6.1 | MUST | The surface | The surface MUST give a deleted state of a message and no text for it, and the event of a deletion MUST carry the conversation and no content. |  |  |
| `IMP-154` | §15.6.1 | MUST | An edit | An edit MUST change the row of its target in place, under a new record key, and the client MUST keep no earlier text. |  |  |
| `IMP-155` | §15.6.1 | MUST | An edit that arrives before its target | An edit that arrives before its target MUST wait in table `0x0C` with its new text, and the target takes that text and the edited mark in the batch that stores it. |  |  |
| `IMP-156` | §15.6.1 | MUST | A client | A client MUST reject a reaction whose `emoji` holds a code point that no emoji sequence uses, from a contact and from its own surface. |  |  |
| `IMP-157` | §15.6.1 | MUST | A client | A client MUST take a reaction only for a message that it holds in the conversation of the sender (`WIR-282`), and it MUST drop each other one. |  |  |
| `IMP-158` | §15.6.4 | MUST | The stored form of a contact and of an invitation | The stored form of a contact and of an invitation MUST name the relay that holds its inbound queue, because a new run builds a circuit to that relay before it subscribes (`NET-308`). |  |  |
| `IMP-159` | §15.6.4 | MUST | A client | A client MUST keep the highest epoch of a `DirectoryRoot` that it verified in the settings table, and it MUST give the larger of that value and the shipped epoch of `REL-045` to the consensus at each start. |  |  |
| `IMP-160` | §15.6.4 | MUST | The plaintext of a file | The plaintext of a file MUST sit in the at-rest store and in no other place on the device: no cache file, no temporary file, and no platform media store. |  |  |
| `IMP-161` | §15.6.4 | MUST | A lock | A lock MUST take each file job out of the memory, because a job holds its file in the clear, and an unlock MUST make the jobs again from the store. |  |  |
| `IMP-162` | §15.6.4 | MUST | (unstated) | The record of a file holds its descriptor (Part 6 §6.6 kind `0x02`), and the descriptor exists when the relays hold each chunk. |  |  |
| `IMP-163` | §15.6.4 | MUST | A client | A client MUST start a download for each received record of kind `0x02` whose descriptor it can read. |  |  |
| `IMP-164` | §15.6.4 | MUST | A deletion of a message | A deletion of a message MUST erase its rows in the tables `0x0F`, `0x10` and `0x11` in the batch that takes the message, and for a file that this device uploaded it MUST then send the `CDEL` of `ATT-161` for each chunk to each relay of that chunk. |  |  |
| `IMP-165` | §15.6.1 | MUST | The file of a draft | The file of a draft MUST cross the surface as a path that the core reads, and not as its bytes. |  |  |
| `IMP-166` | §15.6.1 | MAY | The bytes of a file that the store holds | The bytes of a file that the store holds MAY cross the surface one time for each decode, into a sink of the platform. |  |  |

## SEC — Security Considerations

Source: `spec/16-security-considerations.md`

| ID | Section | Key word | Binds | Requirement | Module | Test |
| --- | --- | --- | --- | --- | --- | --- |
| `SEC-001` | §16.1.1 | MUST | An anonymous credential | An anonymous credential MUST authorize a queue rotation. |  |  |
| `SEC-002` | §16.1.1 | MUST NOT | A long-lived key | A long-lived key MUST NOT authorize it. |  |  |
| `SEC-003` | §16.3 | MAY | A client | A client MAY split the text, and this specification does not require that split. |  |  |
| `SEC-004` | §16.4 | MUST NOT | (unstated) | local performance MUST NOT replace a relay. |  |  |
| `SEC-005` | §16.5 | MUST | (unstated) | The rebuild of the Rust core, the Android application, and the relay MUST be byte-identical. |  |  |
| `SEC-006` | §16.5 | MUST | The client | The client MUST verify an inclusion proof before it applies an update. |  |  |
| `SEC-007` | §16.5 | MUST | The client | The client MUST also **gossip the log heads with peers**, thus a split view becomes detectable. |  |  |
| `SEC-008` | §16.5 | MUST | One or more of those channels | One or more of those channels MUST be outside the control of Apple and of Google. |  |  |
| `SEC-009` | §16.5 | MUST | One or more channels | One or more channels MUST rebuild the release independently and verify it byte-for-byte against the published artifact. |  |  |
| `SEC-010` | §16.5 | MUST NOT | An implementation | An implementation MUST NOT treat one catalog as a dependency. |  |  |
| `SEC-011` | §16.5 | MUST | One or more channels | One or more channels MUST be able to ship a security update in 24 hours. |  |  |
| `SEC-012` | §16.6 | MUST | The entity that controls the release signing | The entity that controls the release signing MUST hold no seat, no staff, and no asset in such a jurisdiction. |  |  |
| `SEC-013` | §16.6 | MAY | The project | The project MAY publish a warrant canary. |  |  |
| `SEC-014` | §16.6 | MUST NOT | The project | The project MUST NOT present a warrant canary as a control. |  |  |
| `SEC-015` | §16.7 | SHOULD | UMBRA | UMBRA SHOULD commission a formal analysis of the handshake, the ratchet, and the group key schedule before v1.0. |  |  |
| `SEC-016` | §16.8 | MUST | Such a change | Such a change MUST come with a specification change and a version increment. |  |  |
| `SEC-017` | §16.8 | MUST NOT | A revision | A revision MUST NOT make a silent amendment. |  |  |
| `SEC-018` | §16.3 | MUST | A revision that adds a residual leak | A revision that adds a residual leak MUST add a row to this table. |  |  |
| `SEC-019` | §16.3 | MUST | A revision that removes a leak | A revision that removes a leak MUST remove its row in the same commit. |  |  |
| `SEC-020` | §16.5 | MUST | That channel | That channel MUST serve a non-certified Android device, which is a device without the Google services. |  |  |
| `SEC-021` | §16.5 | MUST | A rebuilder of `SEC-009` | A rebuilder of `SEC-009` MUST fetch the extension bundle from each listed store and verify it against the published artifact, because the store and not the nonprofit serves that bundle. |  |  |

