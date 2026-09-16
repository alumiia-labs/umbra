# UMBRA Protocol Specification — Part 1: Scope, Conventions, and Terminology

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 1.1 Objective

UMBRA is a message transport and encryption protocol. It gives private,
post-quantum, metadata-resistant communication between persons. UMBRA has three
design objectives.

- **Content.** Only the intended recipients can read the content. This holds
  now. This also holds after a cryptographically relevant quantum computer
  becomes available.
- **Metadata.** The metadata shows who speaks to whom, at what time, how
  frequently, and from which location. No one party in the system can rebuild
  this metadata. This limit applies also to the parties that operate the
  infrastructure.
- **Usability.** Ordinary persons can use UMBRA. A protocol that persons cannot
  use is not a privacy protocol. It is only a privacy demonstration. Delivery
  is reliable, notifications arrive, and the battery cost is small. Onboarding
  does not make the user learn the two objectives above. Part 2 §2.4 states
  these objectives again as measurable targets.

This specification is normative. It contains all the information to build an
implementation. A developer does not have to read the reference implementation.

**Platform scope of v1.** Android and the web are the v1 client platforms.
The web client is the same core in a browser extension, and it is a linked
device of a device set; Part 15 §15.7 gives its form and its limits. An iOS
client and a native desktop shell are deferred to a later revision, and Part
15 §15.6.3 records what such a revision must revisit. The core stays
platform-neutral, thus the deferral changes the scope of this text and not
the design.

## 1.2 What this document is not

UMBRA does not try to be one of the items that follow.

- **Unlinkable to a global adversary.** Such an adversary monitors the full
  network and has an unlimited budget. This property needs a full mixnet with
  continuous cover traffic. Such a mixnet is not compatible with the usability
  objective in §1.1. Part 2 gives the adversary model of UMBRA in full. This
  specification does not overclaim.
- **A replacement for operational security.** UMBRA protects the protocol. UMBRA
  cannot protect a user if an adversary gets control of the endpoint. UMBRA
  cannot protect a user if an adversary applies force to that user. UMBRA cannot
  protect a user if an adversary identifies that user through a channel that is
  not part of the protocol.
- **A blockchain, a token, or a payment network.**

## 1.3 Requirements language

This document uses the key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD
NOT**, and **MAY**. BCP 14 (RFC 2119, RFC 8174) gives the meaning of these five
key words. The key words have this meaning only when they are in capital
letters.

BCP 14 also defines **SHALL**, **SHALL NOT**, **REQUIRED**, **RECOMMENDED**,
**NOT RECOMMENDED**, and **OPTIONAL**. BCP 14 makes each of these key words
equal to one of the five key words above. This document uses the five key words
only, because STE rule 1.11 does not permit two terms for one meaning. The table
below gives the mapping.

| BCP 14 key word | Key word in this document |
| --- | --- |
| SHALL, REQUIRED | MUST |
| SHALL NOT | MUST NOT |
| RECOMMENDED | SHOULD |
| NOT RECOMMENDED | SHOULD NOT |
| OPTIONAL | MAY |

An implementation that disobeys a **MUST** is not an UMBRA implementation. **[SCP-001]** An
implementation that disobeys a **SHOULD** MUST give the cause in its
documentation.

## 1.4 Notation

| Notation | Meaning |
| --- | --- |
| `a \|\| b` | Concatenation of the byte strings `a` and `b` |
| `len(a)` | Length of `a` in bytes |
| `x[i..j]` | Bytes `i` (inclusive) through `j` (exclusive) of `x`, zero-indexed |
| `0x…` | Literal bytes in hexadecimal |
| `{}` | The empty byte string |
| `KDF(salt, ikm, info, L)` | Key derivation that gives `L` bytes |
| `AEAD(k, n, ad, pt)` | Authenticated encryption with associated data |
| `KEM.Gen()`, `KEM.Encap(pk)`, `KEM.Decap(sk, ct)` | Key encapsulation mechanism |
| `SIG.Sign(sk, m)`, `SIG.Verify(pk, m, sig)` | Digital signature |
| `H(x)` | Cryptographic hash of `x` |

All integers on the wire are **unsigned and big-endian**, unless this document
says differently. All lengths are in bytes. Each byte string has a fixed width,
or it has a length prefix. There are no delimiters and no self-describing types.
Part 6 gives the wire encoding rules and the causes for them.

## 1.5 Terminology

This document uses the terms below with only the meaning that this section
gives. UMBRA sometimes uses a word that a different protocol uses with a
different meaning. This document records each such difference.

### 1.5.1 Parties

**User** — A person. UMBRA does not give a user one global identifier. Refer to
*Root Identity*.

**Device** — One installation of an UMBRA client that holds key material. **[SCP-002]** A user
MAY have more than one device. The devices of one user make a *Device Set*.

**Root Identity** — The long-term secret. All other key material of a user comes
from this secret. The first device makes the Root Identity. No device sends the
Root Identity on the network. The Root Identity is the only secret that can
rebuild the identity of a user, and it has no representation that the network
can see.

**Device Set** — The set of devices that share one Root Identity. The Device Set
also includes the membership protocol that adds and revokes devices. Refer to
Part 7.

**Contact** — A different user with an established *Pairwise Channel*.

**Peer** — One of the two parties of a Pairwise Channel, from the view of the
other party.

### 1.5.2 Identity artifacts

**Pairwise Address** — An address for one contact. Each contact of a user sees a
*different* Pairwise Address. Two contacts cannot compare their addresses and
find that they speak to the same user. This is the default condition, and it is
the condition that keeps privacy.

**Public Address** — A long-term address that lets strangers start contact.
**[SCP-003]** A user MAY publish a Public Address. To publish a Public Address is
an explicit, informed, and revocable act. A Public Address has no cryptographic
relation to a Pairwise Address of the same user. **[SCP-004]** A party that holds
one of the two addresses MUST NOT be able to correlate it with the other address.
Refer to Part 4.

**Handle** — A human-readable name for a Public Address. **[SCP-005]** A user MAY
bind a handle to a Public Address. The local identity table of Part 4 §4.2.4
holds that binding, and the directory of Part 9 does not show it.
Handles help usability, and they are not authoritative. **[SCP-006]** The client
MUST tell the user to verify a handle out-of-band before a security-relevant
decision.

### 1.5.3 Network entities

**Relay** — A server that accepts, stores, and serves messages from *Queues*. A
relay is not trusted. A relay learns only the data that Part 3 lists.

**Queue** — A one-direction, anonymous mailbox on a server. A queue has a
*sender credential* and a *recipient credential*. The relay cannot link the two
credentials to each other. Messages move in one direction only. A Pairwise
Channel uses a minimum of two queues, one for each direction. The two queues are
usually on relays that different organizations operate in different
jurisdictions.

**Group Queue** — A relay-held, retained, many-reader mailbox that serves one
group. A group queue has a *reader credential*, a *writer credential*, and an
*owner credential*. Each member holds the first two. The relay holds the
records, the live sessions, and the notify registrations, and it holds no
membership list. A group holds one group queue on each of two relays, and the
two are *replicas*. Refer to Part 3 §3.2.7.

**Ingress Relay** — The relay that a client connects to directly. It sees the
network address of the client. Part 3 §3.1 gives the full role table.

**Chain Relay** — A relay in the middle position of a chain. It sees two
adjacent hop addresses and a cell time, and it sees nothing else.

**Queue Relay** — The relay that holds the destination queue. It sees the
identifier of the destination queue.

**Relay Chain** — The sequence of relays that a message moves through. Each
relay in the chain can decrypt one layer only. No relay in the chain learns the
network address of the sending client together with the identifier of the
destination queue.

**Directory Authority** — An operator of the signed, auditable, replicated list
of the known relays and their measured quality. Refer to Part 10.

**Notification Relay (NDR)** — A service that changes a queue notification into a
platform push notification. **[SCP-007]** A deployment MAY operate a Notification
Relay. A Notification Relay is a different role from a Queue Relay, and it gets
less trust. Refer to Part 8.

> **One name for one role.** Part 3 §3.1 is the source of these five names, and
> this document uses no other name for a relay role. An earlier draft used
> "Entry Relay" for an Ingress Relay, "Exit Relay" for a Queue Relay, and "Push
> Relay" for a Notification Relay. Those three names are withdrawn. STE rule 1.5
> permits one word for one meaning only.

### 1.5.4 Protocol objects

**Pairwise Channel** — The two-direction, ratcheted, forward-secret
cryptographic association between two contacts.

**Session** — The cryptographic state of one direction of a Pairwise Channel.

**Envelope** — The outermost unit on the wire, which the relay can see. An
envelope has a fixed size from a set of buckets.

**Message** — The end-to-end encrypted payload in an envelope.

**Group** — A private conversation with hidden membership. A group has 2 to 500
members, and one mechanism serves each size.

**Group Record** — The end-to-end encrypted unit that a member posts to a group
queue. One group record carries one message to each member. Refer to Part 11
§11.3.

**Epoch-Key Record** — A group record that gives each member the key of a new
group epoch, in one slot for each member. Refer to Part 11 §11.4.2.

**Community** — A public conversation that a party joins with a link. A community
has no member limit, and Part 12 gives the design target of 1000 members or more.
A conversation above the 500-member limit of a group is a community. A community
has a weaker privacy model, and this document records that model in full. Refer
to Part 12.

### 1.5.5 Privacy modes

UMBRA gives three privacy modes for each conversation. The modes differ only in
the added delay (Part 3 §3.9). Each mode uses 3 hops, the same bucket ladder,
the same baseline cover, and the same inbound pacing.

| Mode | Hops | Shaping | Added delay |
| --- | --- | --- | --- |
| **Fast** | 3 | Size bucketing, baseline cover, and inbound pacing | none |
| **Balanced** (default) | 3 | Size bucketing, baseline cover, and inbound pacing | a per-hop delay |
| **Private** | 3 | Size bucketing, baseline cover, and inbound pacing | a longer per-hop delay |

Part 3 §3.9 gives the delay distribution and the mean of each mode. Part 3
§3.9.1 forbids a mode that is visible in the cell size, the cell count, or the
chain length. Part 3 §3.9.1 also gives the anonymity-set-fragmentation argument
that limits how a deployment can offer these modes. Part 2 §2.4 goal U2 gives
the only delivery-latency target, and that target applies to Balanced mode.

## 1.6 Language rules

This document obeys ASD-STE100 Simplified Technical English, Issue 9. STE is a
controlled language that makes technical text easier to read and to translate.
The writing rules in Part 1 of STE apply to all prose in this document. This
document is descriptive text, thus the rules in STE section 6 apply to sentence
length and to paragraph length.

Four categories of text are exempt from the STE dictionary rules.

- **Requirements key words.** The key words in §1.3 keep the spelling and the
  meaning that BCP 14 gives them. A change to these key words changes what an
  implementation has to do.
- **Technical nouns and technical verbs.** STE rules 1.5, 1.6, 1.8, and 1.12
  apply. A writer can use a technical noun or a technical verb that the STE
  dictionary does not contain. §1.6.1 gives the register of the approved terms
  for UMBRA.
- **Code, notation, and data.** Code blocks, the notation in §1.4, field names,
  algorithm names, byte values, and test vectors are not prose. This document
  quotes them without a change.
- **Quoted material and citations.** This document quotes the title of a source
  and the words of a source without a change.

### 1.6.1 Technical noun and technical verb register

STE rule 1.8 tells a writer to use the technical nouns that the subject field
approves. The table below gives the register of technical terms for UMBRA. A
term in this register is approved for this document.

| Category | Terms |
| --- | --- |
| Cryptographic primitives | ML-KEM, ML-DSA, X25519, ChaCha20-Poly1305, SHA-3, SHAKE, HKDF, AEAD, KEM, KDF, MAC, nonce, ciphertext, plaintext, key, keypair, seed, salt, entropy, codeword, parity, prologue |
| Cryptographic operations | encrypt, decrypt, sign, verify, hash, derive, encapsulate, decapsulate, ratchet, wrap, unwrap, pad, zeroize, commit |
| Protocol objects | envelope, message, queue, session, channel, cell, chunk, epoch, handshake, header, payload, prekey, token, tag, credential, subscription, receipt, revision, tombstone, checkpoint, stub, artifact, carrier, layout, listing, reaction, repost, hello, moderator set, mute list, activity bucket, tally, group queue, replica, slot, epoch-key record, tag vector, pair key, notify queue, roster snapshot |
| Network entities | relay, directory, client, server, node, hop, chain, transport, endpoint, bucket, invitation host, landing document, TLS provider, reverse proxy |
| Platform components | operating system, input method, accessibility service, accessibility tree, task snapshot, clipboard, media store, platform backup, platform store, cover view, keystore, high-risk configuration, background push, alert push |
| Identity objects | identity, address, handle, device, roster, membership, group, community, Profile, pseudonym, petname, avatar, pet-avatar, identicon, member index, group sender owner, joiner, claimant, catch-up object, canonical handle |
| Security concepts | adversary, threat, metadata, unlinkability, deniability, forward secrecy, replay, side channel, oracle |
| Data and storage | byte, buffer, index, record, log, database, file, attachment, backup, manifest, write-ahead log, deletion batch |
| Time | clock, duration, deadline, skew, monotonic source, clock movement |

STE rule 1.7 does not let a writer use a technical noun as a verb. STE rule 1.13
does not let a writer use a technical verb as a noun.

## 1.7 The constant register

A constant that one part defines and a second part quotes is a cross-part
dependency. Fifteen requirements of this specification order a revision to
derive a figure again when such a constant changes. `NET-092`, `NET-096`,
`NET-104`, `NET-105`, `ATT-020`, `ATT-049`, `DEV-164`, and `REL-059` are
examples. Without the table below a maintainer finds the dependents by hand.

| Constant | Owner | The parts that quote it |
| --- | --- | --- |
| `MSG_TTL` | Part 3 §3.2.4 | Part 5 §5.5.4, Part 7 §7.5.6, Part 13 §13.7.1, Part 16 §16.1 |
| `QUEUE_IDLE_TTL` | Part 3 §3.2.4 | Part 7 §7.5.1, Part 16 §16.1 |
| `MAX_QUEUES_PER_SESSION` | Part 3 §3.2.5 | Part 2 §2.7, Part 3 §3.11, Part 8 §8.2.1, Part 16 §16.3 |
| The bucket ladder | Part 3 §3.3 | Part 5 §5.6, Part 6 §6.9, Part 3 §3.12, Part 11 §11.3.3 |
| `CIRCUIT_MAX_AGE`, `CIRCUIT_MAX_CELLS` | Part 3 §3.4.3 | Part 2 §2.4, Part 3 §3.4.4, Part 3 §3.11.1, Part 3 §3.12, Part 6 §6.2.2, Part 6 §6.2.3, Part 6 §6.8, Part 16 §16.3 |
| `SESSION_RESUME_WINDOW` | Part 6 §6.2.3 | Part 3 §3.4.3, Part 3 §3.12, Part 16 §16.3 |
| `PACING_MEAN` | Part 3 §3.9 | Part 3 §3.12, Part 8 §8.8, Part 10 §10.9.1 |
| `RECEIPT_BATCH_MAX` | Part 3 §3.5.4 | Part 6 §6.6, Part 6 §6.6.9, Part 6 §6.8 |
| The tier A cover rate | Part 3 §3.6.2 | Part 3 §3.12, Part 4 §4.7.2, Part 7 §7.5.1, Part 9 §9.5.3, Part 10 §10.4.2 |
| The cell wire costs 560, 2 096, 8 240, 32 860 | Part 6 §6.9 | Part 3 §3.3.1, Part 3 §3.5.2, Part 3 §3.9, Part 3 §3.12, Part 7 §7.3.1, Part 7 §7.5.5, Part 10 §10.9.1, Part 11 §11.3.3, Part 11 §11.9.5, Part 11 §11.11, Part 12 §12.4.1, Part 13 §13.7.2, Part 16 §16.3 |
| `BACKUP_*` | Part 4 §4.8 | Part 3 §3.12, Part 7 §7.5.8, Part 9 §9.9.2, Part 13 §13.3.2, Part 13 §13.3.3, Part 13 §13.4.2, Part 13 §13.9, Part 16 §16.1 |
| `SKIP_TTL` | Part 5 §5.5.4 | Part 1 §1.9 |
| `MAX_DEVICES`, `OWNER_CLAIM_RATE`, `OWNER_ABSENCE_RATE` | Part 7 §7.8 | Part 3 §3.12 |
| `OWNER_ABSENCE` | Part 7 §7.8 | Part 2 §2.4 |
| `MAX_QUEUES_PER_HANDLE` | Part 8 §8.2.1 | Part 8 §8.7 |
| `WAKE_COALESCE_WINDOW` | Part 8 §8.5 | Part 2 §2.4, Part 3 §3.12 |
| The consensus epoch and `CONSENSUS_VALIDITY` | Part 10 §10.11 | Part 3 §3.2.6, Part 3 §3.12, Part 4 §4.7.2, Part 13 §13.3.2 |
| `RECEIPT_WINDOW` | Part 10 §10.11 | Part 10 §10.9.1 |
| `GROUP_MAX` | Part 11 §11.10 | Part 1 §1.5.4, Part 3 §3.12, Part 11 §11.3.3, Part 11 §11.9.1 |
| `MOD_ACTION_MAX`, `ROSTER_ENTRY_MAX` | Part 12 §12.9 | Part 12 §12.5.2, Part 11 §11.9.6 |
| `MODERATOR_MAX`, `MOD_EPOCH_RATE`, `MOD_EPOCH_COMMUNITY_RATE`, `ROSTER_RATE`, `MOD_CHAIN_FETCH_MAX` | Part 12 §12.9 | Part 12 §12.5.2 |
| `MUTE_LIST_MAX` | Part 12 §12.9 | Part 12 §12.5.4 |
| `REACT_RATE_LIMIT`, `REPOST_RATE_LIMIT` | Part 12 §12.9 | Part 12 §12.6.2 |
| `LISTING_LEASE`, `LISTING_PAGE` | Part 9 §9.10 | Part 9 §9.12, Part 12 §12.7.2 |
| `RENDEZVOUS_ROTATE` | Part 9 §9.10 | Part 16 §16.1, Part 16 §16.3 |
| `CHUNK_SIZE`, `REPLICAS`, `CHUNK_TTL`, `CHUNK_LIFE_MAX` | Part 13 §13.7 | Part 3 §3.12, Part 4 §4.7.2, Part 12 §12.4.6, Part 12 §12.7.1 |
| `MAX_FILE_SIZE`, `UPLOAD_QUOTA_DAY`, `CHUNK_STORE_MIN`, `CHUNK_STORE_TARGET` | Part 13 §13.7 | Part 13 §13.7.2, Part 13 §13.10, Part 2 §2.4, Part 10 §10.5.3 |
| `SEGMENT_SIZE`, `MAX_CONCURRENT_CHUNKS`, `IMAGE_REENCODE_BYTES` | Part 13 §13.7 | Part 13 §13.2.3, Part 13 §13.3, Part 13 §13.7.2 |
| `CHUNK_EGRESS_BUDGET_DAY`, `CHUNK_FETCH_RATE`, `HOT_REPLICAS` | Part 13 §13.7 | Part 13 §13.11, Part 2 §2.4 |
| `MENTION_MAX`, `POLL_OPTION_MAX`, `POLL_GROUP_MAX` | Part 11 §11.10 | Part 6 §6.6.5, Part 6 §6.6.6, Part 11 §11.11 |
| `TIMER_VALUES`, `FORWARD_MAX_DEPTH` | Part 7 §7.8 | Part 6 §6.6.5, Part 6 §6.6.8, Part 7 §7.5.8 |
| The propagation budget of 420 ms | Part 3 §3.12 | Part 2 §2.4 U2, Part 3 §3.9 |
| The circuit-hop flight widths 1 232 and 1 136, and the sum 2 368 | Part 5 §5.4.9 | Part 2 §2.4, Part 3 §3.4.3, Part 3 §3.12 |
| Each U-goal target | Part 2 §2.4 | Part 2 §2.4.1 names each rule that carries a goal |
| `QUEUE_QUOTA` | Part 3 §3.2.4 | Part 6 §6.4.3, Part 7 §7.5.1, Part 14 §14.12 |
| `ROTATE_AFTER` | Part 3 §3.2.4 | Part 6 §6.4.2, Part 7 §7.5.5 |
| `ACK_HOLE_TIMEOUT` | Part 3 §3.2.4 | Part 6 §6.4.3 |
| `DRAIN_THRESHOLD` | Part 3 §3.5.2 | Part 16 §16.3 |
| `RECEIPT_MAX_HOLD` | Part 3 §3.5.4 | Part 6 §6.6 |
| `MAX_SKIP` | Part 5 §5.5.4 | Part 16 §16.3 |
| `MAX_STORED` | Part 5 §5.5.4 | Part 14 §14.12, Part 16 §16.3 |
| `MAX_BYTES`, `MAX_STORED_DEVICE` | Part 5 §5.5.4 | Part 16 §16.3 |
| `DELETE_BATCH_MAX` | Part 7 §7.5.6 | Part 6 §6.6.1, Part 6 §6.8 |
| `SWEEP_SPREAD` | Part 7 §7.5.6 | Part 4 §4.5.1 |
| `SYNC_MAX_AGE` | Part 7 §7.8 | Part 2 §2.4, Part 6 §6.6, Part 12 §12.3.2 |
| `SYNC_MAX_BYTES` | Part 7 §7.8 | Part 12 §12.3.2 |
| `SYNC_ACK_BATCH`, `SYNC_ACK_MAX_DELAY`, `OWNER_CLAIM_MAX` | Part 7 §7.8 | Part 3 §3.12 |
| `ROSTER_RATE_LIMIT`, `GROUP_EPOCH_RATE`, `GRANT_RATE` | Part 11 §11.10 | none |
| `KEY_REQUEST_RATE` | Part 11 §11.10 | Part 6 §6.6.11 |
| `GROUP_REPLICAS` | Part 11 §11.10 | Part 1 §1.5.3, Part 3 §3.2.7, Part 3 §3.12, Part 6 §6.4.6 |
| `GROUP_SLOT`, `GROUP_SLOT_WINDOW`, `GROUP_SLOT_SKEW` | Part 11 §11.10 | Part 1 §1.9, Part 2 §2.4, Part 6 §6.4.6, Part 15 §15.9.2, Part 16 §16.3 |
| `GROUP_EPOCH_MAX_AGE`, `GROUP_EPOCH_GRACE`, `GROUP_ROSTER_WAIT` | Part 11 §11.10 | Part 6 §6.6.11, Part 16 §16.3 |
| `GROUP_GAP_TIMEOUT` | Part 11 §11.10 | Part 3 §3.2.7 |
| `ROTATE_BACKOFF_ROLE`, `ROTATE_BACKOFF_MEMBER` | Part 11 §11.10 | none |
| `GROUP_TAG_LEN` | Part 11 §11.10 | Part 6 §6.4.6, Part 6 §6.9 |
| `GROUP_INDEX_MAX`, `ROLE_HOLDER_MAX` | Part 11 §11.10 | Part 6 §6.6.3 |
| `GROUP_ALL_NOTIFY_MAX` | Part 11 §11.10 | Part 2 §2.4, Part 7 §7.5.9, Part 8 §8.5 |
| `GROUP_SILENT_EVICT`, `PRESENCE_INTERVAL` | Part 11 §11.10 | Part 3 §3.2.7, Part 3 §3.12 |
| `HISTORY_WINDOW` | Part 11 §11.10 | Part 6 §6.6.3 |
| `GROUP_RETENTION` | Part 3 §3.2.7 | Part 2 §2.4, Part 2 §2.7, Part 11 §11.2.3, Part 11 §11.8, Part 16 §16.1 |
| `GROUP_QUEUE_QUOTA`, `GROUP_IDLE_TTL` | Part 3 §3.2.7 | Part 11 §11.2.3, Part 16 §16.1 |
| `GROUP_POST_RATE` | Part 3 §3.2.7 | Part 6 §6.4.5, Part 11 §11.3.4, Part 14 §14.2 |
| `GROUP_READ_GRACE`, `GROUP_WRITE_GRACE` | Part 3 §3.2.7 | Part 6 §6.4.5, Part 11 §11.4.3, Part 16 §16.1, Part 16 §16.3 |
| `GROUP_NOTIFIER_MAX` | Part 3 §3.2.7 | Part 8 §8.5.2, Part 16 §16.1 |
| `GROUP_DIGEST_MIN_GAP` | Part 8 §8.5.2 | none |
| `COMMUNITY_MIN_RELAYS` | Part 12 §12.9 | Part 14 §14.4 |
| `PULL_BATCH`, `COMMUNITY_RETENTION`, `COMMUNITY_RELAY_MAX` | Part 12 §12.9 | Part 12 §12.3.3, Part 12 §12.4.6, Part 12 §12.7, Part 13 §13.7, Part 16 §16.1 |
| `CLOCK_SKEW` | Part 10 §10.11 | Part 1 §1.9, Part 9 §9.5.2, Part 10 §10.5.2 |
| `ROTATE_GRACE` | Part 3 §3.2.6 | Part 12 §12.5.3 |
| `SEND_MAX_ATTEMPTS`, `SEND_GIVE_UP` | Part 3 §3.7 | Part 15 §15.9 |
| `RELAY_LOOP_RATE` | Part 3 §3.6.3 | none |
| `NTF_FAIL_MAX` | Part 8 §8.2.3 | Part 15 §15.9.2 |
| `PUSH_TTL_MESSAGE`, `PUSH_TTL_DIGEST`, `REPUSH_INTERVAL`, `REPUSH_MAX` | Part 8 §8.4.3 | Part 2 §2.4 |
| `COMMUNITY_DIGEST_BUDGET` | Part 8 §8.5.1 | Part 12 §12.6.4, Part 2 §2.4 |
| `POST_RATE_LIMIT` | Part 12 §12.9 | Part 14 §14.2 |
| `POW_LOOKUP_FLOOR` | Part 14 §14.13 | Part 9 §9.4.1 |
| `HELLO_POW_EFFORT`, `HELLO_INBOUND_LIMIT` | Part 14 §14.13 | Part 9 §9.9, Part 2 §2.4 |
| `INVITE_TTL` | Part 4 §4.8 | Part 5 §5.4.5 |
| `CLUSTER_SAMPLE` | Part 10 §10.11 | Part 16 §16.3, Part 16 §16.6.1 |
| `AUTHORITY_FLOOR` | Part 10 §10.11 | Part 16 §16.6.1 |

- **[SCP-008]** A revision that changes a constant of this table MUST change
  each part of the third column in the same commit.
- **[SCP-009]** A revision that makes a second part quote a constant MUST add a
  row to this table.
- **[SCP-010]** A revision MUST NOT define one constant in two parts.

> *Cause.* Two defects that this revision corrects came from a missing row.
> The receipt section of an earlier draft of Part 11 quoted a U4 value of 15 MB
> after Part 2 §2.4 moved that goal to 25 MB. Part 3 §3.12 counted a group
> fan-out as 8 × 25 after Part 11 §11.2 stated that a fan-out is the recipient
> count. Each of those figures sat in a
> part that does not own the constant.

## 1.8 The artifact register

A requirement that names an object binds an implementer to build that object.
The implementer needs three facts. The first is the byte layout. The second is
the carrier that moves the object between two parties. The third is the party
that makes the object, by an issuance or by a derivation. This specification
gives each behavior a requirement ID, and it gives an artifact no such
discipline.

The table below lists each named artifact and the section that gives each fact.
A cell that reads `none` records a gap of this draft. A row with such a cell is
not a defect of the register. The register exists to show that cell. The
"Made by" column names the party in the sense of §1.5. "Out of band" names a
side channel that the user selects, such as a QR code scan.

| Artifact | Layout | Carrier | Made by |
| --- | --- | --- | --- |
| `Capsule` | Part 6 §6.2.1 | The WebSocket frame or the QUIC stream of Part 3 §3.8 | Client and relay |
| `SessionFrame` | Part 6 §6.2.2 | `Capsule` | Client |
| `SessionOpen`, `SessionResume`, `SessionClose` | Part 6 §6.2.3 | `Capsule` | Client |
| `Cell` | Part 6 §6.3 and Part 3 §3.4.3 | `SessionFrame` | Client |
| `HopHello`, `HopReply` | Part 3 §3.4.3 | `EXTEND` and `EXTENDED`, Part 6 §6.3 | Client and relay |
| Queue `Command` | Part 6 §6.4 | `Cell` | Client and relay |
| `QueueE2E` | Part 6 §6.4.2 | `Command` | Client |
| `NackPayload` | Part 6 §6.4.4 | `NACK`, Part 6 §6.4 | Relay |
| `RatchetRecord`, `RatchetCtx`, `PqFrame` | Part 6 §6.5 | `QueueE2E` | Client |
| `AppMessage` | Part 6 §6.6 | `RatchetRecord` | Client |
| Text body, kind `0x01` | Part 6 §6.6 | `AppMessage` | Client |
| `ReactionBody`, kind `0x03` | Part 6 §6.6.9 | `AppMessage` | Client |
| `ReceiptBody`, kinds `0x06` and `0x07` | Part 6 §6.6.9 | `AppMessage` | Client |
| `TypingBody`, kind `0x08` | Part 6 §6.6.9 | `AppMessage` | Client |
| `EditBody`, `DeleteBody` | Part 6 §6.6.1 | `AppMessage` | Client |
| `GroupControl` | Part 6 §6.6.3 | `AppMessage` | Client |
| `DigestBody` | Part 6 §6.6.4 | `AppMessage` | Client |
| `RichRecord` | Part 6 §6.6.5 | `AppMessage` | Client |
| `Poll`, `PollOption`, `PollVote` | Part 6 §6.6.6 | `AppMessage` | Client |
| `ContactShare` | Part 6 §6.6.7 | `AppMessage` | Client |
| `ConversationTimer` | Part 6 §6.6.8 | `AppMessage` | Client |
| `version_range` | Part 6 §6.7 | The invitation, Part 5 §5.4.1 | Client |
| `QueueAddress` | Part 6 §6.6.10 | The four carriers of Part 3 §3.2.6 | Client |
| `KeyRequest`, `KeySupply` | Part 6 §6.6.11 | `AppMessage`, kinds `0x34` and `0x35` | Client |
| `VerifyCommit`, `VerifyReveal` | Part 4 §4.5.2 | `AppMessage`, kinds `0x36` and `0x37` | Client |
| `RecoveryDigits` | Part 4 §4.7.7 | Out of band | Client |
| `DeadChannelBlob` | Part 3 §3.2.6 | A handle-addressed chunk, Part 13 §13.4.2 | Client |
| Public Address string | Part 4 §4.2.3 | Out of band | Client |
| `Profile_j` | Part 4 §4.2.5 | The invitation, Part 4 §4.3.1 | Client |
| One-time invitation link | Part 4 §4.3.1 | Out of band | Client |
| Invitation landing document | Part 4 §4.3.1 | HTTPS at the invitation host | The nonprofit |
| Invitation blob | Part 5 §5.4.1 | The relay, under the link of Part 4 §4.3.1 | Client |
| Reusable contact link (Part 4 §4.3.2) | none | Out of band | Client |
| `KeyChangeNotice` | Part 4 §4.5.1 | `AppMessage`, kind `0x30` | Client |
| Backup object, `BackupRootChunk`, `BackupRoot`, `BackupEntry` | Part 4 §4.7.2 | Backup-class chunks under `BNEW`, Part 13 §13.3.3, and the handle-addressed chunk of Part 13 §13.4.2 | Client |
| Recovery share (Part 4 §4.7.3) | none | none | Client |
| Handshake flights 1 to 3 | Part 5 §5.4.2 | none | Client |
| `Roster`, `DeviceEntry`, `OwnerClaim`, `OwnerClaimRecord` | Part 7 §7.3.1 | none | Client |
| Link QR code and provisioning payload (Part 7 §7.4) | none | none | Client |
| Mutable state body, kind `0x20` sub-kind `0x01` (Part 7 §7.5.3) | none | `AppMessage` | Client |
| `DeviceSetControl`, `SyncAck` | Part 7 §7.5.5 | `AppMessage`, kind `0x20` sub-kind `0x02` | Client |
| `SyncSeedUpdate` | Part 7 §7.7 | `DeviceSetControl`, type `0x05` | Client |
| Catch-up object (Part 7 §7.5.1) | none | The chunk path of Part 13 §13.3.3, and `DeviceSetControl` type `0x04` carries its `FileDescriptor` | Client |
| Push registration `(handle_i, ct_token_i)` (Part 8 §8.2.1) | none | none | Client |
| Notification blob | Part 8 §8.2.2 | The platform push, Part 8 §8.4 | Relay |
| `k_ntf_root` transfer (Part 8 §8.2.3) | none | none | Client |
| `DirectoryEntry` | Part 9 §9.3 | The directory, Part 9 §9.3 | Client |
| `AddressEntry` | Part 9 §9.3.3 | The directory, Part 9 §9.3.3 | Client |
| Reusable contact link | Part 4 §4.3.2 | Out of band | Client |
| `CommunityListing`, `ListingQuery`, `ListingPage` | Part 9 §9.12 | The directory, Part 9 §9.12 | Client and directory |
| Handle link | Part 9 §9.3.1 | Out of band | Client |
| Profile blob (Part 9 §9.3.1) | none | none | Client |
| Lookup request and response (Part 9 §9.4) | none | none | Client and directory |
| `SignedTreeHead`, `SignerSig` | Part 9 §9.5.2 | The lookup response of Part 9 §9.4 step 4 | The signers of Part 9 §9.5.2 |
| `LogKeySet`, `SignedLogKeySet` | Part 9 §9.5.2 | The client build, and the signers of Part 9 §9.5.2 | The signers of Part 9 §9.5.2 |
| Rendezvous hello (Part 9 §9.6), which carries the fields of Part 5 §5.4.1 and ends with an `Admission` | none | The rendezvous queue, Part 9 §9.6 | Client |
| Renewal challenge and answer | Part 9 §9.9.1 | none | Directory and client |
| Registration request (Part 9 §9.9) | none | none | Client |
| `MeasurerCert` | Part 10 §10.3.1 | `MEAS_OPEN`, Part 6 §6.3 | Two or more directory authorities |
| `LinkReceipt` | Part 10 §10.4.2 | none | Relay |
| `LinkFaultReport` | Part 10 §10.4.2 | A cover slot or a push-wake session, Part 10 §10.4.2 | Client |
| Isolation query (Part 10 §10.4.2) | none | none | Directory authority |
| `DirectoryRoot`, `AuthoritySig` | Part 10 §10.5.2 | The bootstrap carriers of Part 3 §3.10 | Directory authority |
| `DirectoryKeySet`, `SignedKeySet` | Part 10 §10.5.2 | The bootstrap carriers of Part 3 §3.10 | Directory authority |
| `RelaySetDiff` | Part 10 §10.5.3 | The bootstrap carriers of Part 3 §3.10 | Directory authority |
| `RelayDescriptor` | Part 10 §10.5.3 | `RelayEntry`, Part 10 §10.5.3 | Relay |
| `RelayEntry` | Part 10 §10.5.3 | The consensus, Part 10 §10.5.3 | Directory authority |
| Inclusion proof (Part 10 §10.5.3) | none | none | Directory authority |
| `FamilyCert` | Part 10 §10.6.3 | The dossier of Part 10 §10.6 | Relay |
| `BlocList`, `Bloc` | Part 10 §10.6.3 | The bootstrap carriers of Part 3 §3.10 | Directory authority |
| Group-queue commands `0x90` to `0x9A` | Part 6 §6.4.5 | `Cell` | Client and relay |
| `GroupQueueRecord` | Part 6 §6.4.6 | `GPOST` and `GMSG`, Part 6 §6.4.5 | Client |
| `ContentPlain` | Part 6 §6.4.6 | `GroupQueueRecord`, kind `0x01` | Client |
| `EpochKeyBody`, `KemSlot`, `SlotPayload` | Part 6 §6.4.6 | `GroupQueueRecord`, kind `0x02`, or the chunk path of Part 13 §13.3.3 | Client |
| `NotifyRegistration` for a group | Part 6 §6.4.5 | `GNREG` and `GNUNREG`, Part 6 §6.4.5 | Client |
| `JoinRecord` | Part 6 §6.6.3 | `GroupControl`, type `0x02`, on the pairwise channel of the invitee to the inviter | Client |
| `GroupInvitation` | Part 6 §6.6.3 | `GroupControl`, type `0x07`, on the pairwise channel of the inviter to the invitee | Client |
| `SnapshotNotice` | Part 6 §6.6.3 | `GroupQueueRecord`, as `GroupControl` type `0x08` | Client |
| `RekeyRecord` | Part 6 §6.6.3 | `GroupControl`, type `0x09`, on a pairwise channel to an admin | Client |
| `GroupMemberEntry`, `RosterSnapshot` | Part 6 §6.6.3 | The chunk path of Part 13 §13.3.3, under a `FileDescriptor` in a `GroupInvitation` stage `0x02` or in a `SnapshotNotice` | Client |
| Plain epoch (Part 11 §11.9.2) | none | `GroupControl`, type `0x03` | Client |
| Granting epoch (Part 11 §11.9.2) | none | `GroupControl`, type `0x04` | Client |
| Group moderation epoch (Part 11 §11.9.6) | none | `GroupControl`, type `0x05` | Client |
| `GroupPresence` | Part 11 §11.9.7 | `GroupQueueRecord`, as `GroupControl` type `0x06` | Client |
| `Checkpoint` | Part 12 §12.4.1 | `PUB` and `PAGE`, Part 12 §12.3.3 | Client |
| `CommunityPost`, `PostStub` | Part 12 §12.4.4 | `PUB` and `PAGE`, Part 12 §12.3.3 | Client, and relay for a stub |
| `OperatorRemoval` | Part 12 §12.4.4 | `PAGE`, Part 12 §12.3.3 | Relay |
| `NotifyRegistration` | Part 12 §12.6.4 | `NREG` and `NUNREG`, Part 12 §12.3.3 | Client |
| `NotifyDigest` | Part 12 §12.6.4 | `SEND`, as the L6 record of kind `0x04` | Community relay |
| `PullRequest`, `PullResponse`, `PullEntry` | Part 12 §12.3.3 | `PULL` and `PAGE`, Part 12 §12.3.3 | Client and relay |
| Community commands `0x80` to `0x83` | Part 12 §12.3.3 | `Cell` | Client and relay |
| `CommunityRoster`, `RosterEntry`, `RosterCosign`, `ModerationEpoch`, `ModerationAction`, `ModeratorSet` | Part 12 §12.5.2 | `PUB` and `PAGE`, Part 12 §12.3.3 | Client |
| `RepostBody` | Part 12 §12.6.2 | `RichRecord` inside a `CommunityPost`, Part 12 §12.6.2 | Client |
| `CommunityContact` | Part 12 §12.6.3 | `RichRecord` inside a `CommunityPost`, Part 12 §12.6.3 | Client |
| Community link | Part 12 §12.7 | Out of band | Client |
| `CommunityMeta`, `CommunityMetaBody` | Part 12 §12.7.1 | `PUB` and `PAGE`, Part 12 §12.3.3 | Client |
| `CommunityReport`, `ReportRecord` | Part 12 §12.5.3 | `QueueE2E` to the report queue, Part 12 §12.5.3 | Client |
| `FileDescriptor`, `ChunkRef` | Part 13 §13.3 | `AppMessage`, kind `0x02` | Client |
| `RelayRef` | Part 13 §13.3.2 | `ChunkRef` | Client |
| Chunk commands `0x70` to `0x7B` | Part 13 §13.3.3 | `Cell` | Client and relay |
| `CrepPayload`, `ReplicaTarget` | Part 13 §13.4.1 | `CREP`, Part 13 §13.3.3 | Client |
| `Admission` | Part 14 §14.2 | `NEW`, `CNEW`, `BNEW`, and `PUB` | Client |
| `PowChallenge` | Part 14 §14.8 | The descriptor path of Part 10 §10.5.3, or a rejection of the verifier | The verifier of Part 14 §14.2 |
| `PowSolution` | Part 14 §14.8 | `Admission` | Client |
| Cross-relay token, first-party token | The RFC of each type, Part 14 §14.3 | none | Issuer, Part 14 §14.9 |

The table has 105 rows, and 21 of them hold at least one `none` cell.
`Cell` has two definitions, and the two agree field for field.

- **[SCP-011]** A revision MUST NOT add a requirement that names an artifact
  with no row in this table.
- **[SCP-012]** A revision that adds an artifact MUST define its layout, its
  carrier, and its maker in the same commit.
- **[SCP-013]** A revision that adds an artifact MUST add a row to this table.
- **[SCP-014]** A revision that supplies a missing layout, carrier, or maker
  MUST change the applicable cell in the same commit.
- **[SCP-015]** A revision MUST NOT define one artifact in two parts.

> *Cause.* A review of draft 0.1.0 found eight named mechanisms with no wire
> object, no issuer, or no locator. The pull credential of an earlier draft of
> Part 12 §12.3.1 and the queue address of Part 3 §3.2.2 are two of them. The proof-of-work
> challenge of Part 14 §14.8 is a third. Each one sat behind a requirement that
> an implementer could not satisfy.
>
> The table above found more. The handshake flights of Part 5 §5.4.2 have a
> byte layout, and no command or kind carries them. Rule `SCP-015` follows rule
> `SCP-010`, and the duplicate pair above is the debt that it stops from
> growing.

## 1.9 Time and the clock

Twelve parts state a duration. `MSG_TTL`, `ACK_HOLE_TIMEOUT`, `SKIP_TTL`,
`EDIT_WINDOW`, the conversation timer, and `open_seconds` are examples. Three
rules name the party that measures the duration and the event that starts it.
Those rules are `DEV-087`, `DEV-208`, and `WIR-187`. No rule names a clock
source. A phone clock moves at a restart, at a time-zone change, after a flat
battery, and after a restore.

This section defines five terms. A **duration** is a period that a rule states.
The **device clock** is the clock that the platform sets from the network or
from the user. A **monotonic source** is a counter that the platform does not
move backward between two restarts. A **clock movement** is a change of the
device clock by more than `CLOCK_SKEW` in one step. A clock movement that
occurs while a duration runs **interrupts** that duration.

Part 10 §10.11 owns `CLOCK_SKEW` and sets it to 1 hour. A party detects a clock
movement when the device clock and the monotonic source advance by amounts that
differ by more than `CLOCK_SKEW`. Part 16 §16.3 records that no platform gives a
monotonic counter that survives a restore. A party cannot detect a clock
movement across a restart, thus a duration that spans a restart runs on the
device clock. This specification accepts that residual.

The group slot index of Part 11 §11.3.1 reads the device clock, thus a group
record carries a clock comparison between two members. `GROUP_SLOT_SKEW` of
Part 11 §11.10 is its skew tolerance under `SCP-020`, and a record outside the
slot window is a `clock` event of Part 15 §15.9.2.

- **[SCP-016]** A revision that adds a duration MUST name the party that
  measures it. **[SCP-017]** A revision that adds a duration MUST name the
  event that starts it.
- **[SCP-018]** A party MUST measure a duration from a monotonic source between
  two restarts.
- **[SCP-019]** If a clock movement occurs while a duration runs, the party
  MUST start that duration again.
- **[SCP-020]** A revision that adds a comparison between the clocks of two
  parties MUST state a skew tolerance. Part 10 §10.5.2 rule `REL-035` gives
  the form.
- **[SCP-021]** A client MUST NOT delete a message, a key, a chunk, or a token
  on an interrupted duration.

> *Cause.* Two rules destroy data on a forward clock movement. Rule `NET-102`
> lets a recipient acknowledge above a hole after `ACK_HOLE_TIMEOUT`. Rule
> `WIR-048` then makes the relay delete each message of that queue at or below
> the acknowledged sequence. One forward jump on the recipient destroys messages
> that no party delivered. Rule `CRY-098` holds a skipped key for `SKIP_TTL`,
> and an early deletion makes a delivered message permanently undecryptable.
> That is the U9 failure that the cause note of Part 5 §5.5.4 closed.
>
> Rule `SCP-019` delays each of those deletions, and rule `SCP-021` forbids them
> while the delay runs. Rule `SCP-021` binds the client, because a phone clock
> moves and a relay clock rarely does.

## 1.10 Document map

| Part | Title |
| --- | --- |
| 1 | Scope, Conventions, and Terminology *(this document)* |
| 2 | Threat Model and Security Goals |
| 3 | Network Architecture: Queues, Relays, and Relay Chaining |
| 4 | Identity: Root, Pairwise, and Public Addresses |
| 5 | Cryptographic Core: Primitives, Handshake, and Ratchet |
| 6 | Wire Format and Encoding |
| 7 | Device Sets, Multi-Device Sync, and Revocation |
| 8 | Notifications and Mobile Delivery |
| 9 | Discovery: Handles, the Directory, and Key Transparency |
| 10 | Relay Directory, Measurement, and Selection |
| 11 | Private Groups |
| 12 | Public Communities |
| 13 | Attachments and Large Objects |
| 14 | Anti-Abuse Without Identifiers |
| 15 | Implementation Requirements and Assurance |
| 16 | Security Considerations and Known Limitations |
