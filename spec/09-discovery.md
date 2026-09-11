# UMBRA Protocol Specification — Part 9: Discovery, Handles, and Key Transparency

**Status:** Draft
**Version:** 0.1.0-draft

---

## 9.1 The result that shapes this part

Key transparency has real deployments. WhatsApp shipped it in April 2023. Apple
shipped iMessage Contact Key Verification in iOS 17.2. Meta Messenger shipped it
in November 2025. Signal shipped Automatic Key Verification in August 2026. The
IETF KEYTRANS working group agreed on a combined tree design, and UMBRA adopts
that design.

But the most important finding is **negative**, and the design has to accept it:

> **Each deployed key-transparency system gets its enumeration resistance from
> server-side access control and from rate limiting. No such system gets that
> resistance from cryptography.**

The SoK of KT security goals (eprint 2024/1938) calls this property "Privacy via
Access Control". That paper shows that CONIKS, SEEMless, OPTIKS, and the
KEYTRANS architecture all depend on it. Parakeet states directly that anonymous
lookups operate "counter to our privacy requirement."

The consequences are measured, and they are not hypothetical:

- Gegenhuber and others (NDSS 2026) enumerated **3.5 billion WhatsApp accounts
  at 7 000 accounts each second, from one university IP address**. **No party
  blocked them.** They collected X25519 identity keys and 77 million profile
  photos. This document has not verified those figures against the published
  version of the paper.
- Hagen and others (NDSS 2021) showed that a hash of a phone number gives no
  protection. They used 24 GB of custom rainbow tables at 52 ms for each hash.
  The success rate was more than 99.99 % over 118 billion numbers.

A human-readable handle has low entropy by definition. **UMBRA cannot make its
handle directory unenumerable.** Thus UMBRA does the one honest thing that is
available:

> **Bound what a crawl gives.** The directory contains only ephemeral,
> single-purpose, and rotatable values. A full crawl gives the list of the
> handles and sufficient data to send a contact request to each one. It gives
> nothing that names a person, and Part 16 §16.2.5 states the residual.

## 9.2 Scope: opted-in entries only

**The transparency log covers opted-in handles, opted-in Public Addresses, and
listed communities only. It does not cover pairwise contacts.** §9.3.3 gives
the address entry, and §9.12 gives the community listing.

A contact from a QR code or from a shared link received the key on an
authenticated out-of-band channel. Thus key transparency adds nothing for such a
contact. The inclusion of such contacts also builds the global directory that
UMBRA exists to prevent.

This reduction of the scope is the largest one available, and it gives four
concrete benefits. The tree holds 10⁵ to 10⁷ entries and not 10⁹. A snapshot for
each epoch becomes affordable. Parakeet-style compaction is not necessary. The
dangerous liveness assumption disappears, which is the assumption that a user
comes online between two tombstone epochs.

## 9.3 What the directory contains

A directory entry holds **only** these fields:

```
DirectoryEntry {
    handle          UTF-8, ≤ 32 bytes + discriminator
    HK_pub          X25519 + ML-KEM-768 public keys      (the L2 handle key)
    rendezvous      queue address, rotatable at any time
    version         u32
}
```

An entry contains **no** profile name, **no** avatar, **no** status text, **no**
key-rotation timestamp, and **no** long-lived value.

`HK_pub` is the public half of `HandleKey_{j,r}` of Part 4 §4.2.4. That key is
separate from the Public Address key, thus a crawl does not link a handle to a
Public Address. The user rotates it with one tap, and the rotation counter `r`
makes the new key.

A full crawl of the directory gives the existing handle strings, the rotatable
handle public keys, and the rotatable rendezvous addresses. That data is
sufficient to spam a request queue. That data is not sufficient to deanonymize,
to locate, or to link a person. The user rotates each value with one tap.

**Part 2 states this residual leak, and this part does not hide it.** UMBRA does
not claim enumeration resistance for the handle directory.

### 9.3.1 Rich profile data lives in an encrypted blob

The profile name, the avatar, and the welcome message travel in a **blob that
the client encrypts**. The key for that blob is in the fragment of the shared
link, and the directory does not hold it:

```
umbra://h/<handle>#<128-bit fragment>

directory index = VOPRF over <handle> only
blob key        = HKDF("umbra/v1/profile-blob" || <handle> || fragment)
```

Part 5 §5.11 holds the label `"umbra/v1/profile-blob"`.

A person that types a bare handle gets the rendezvous queue only, and that
person has to ask for permission. A person that receives the full link gets the
profile directly.

This design prevents the outcome of 77 million scraped profile photos.

The blob holds the selected picture of a Profile (Part 4 §4.2.5). Three rules
apply to that picture.

1. **[DIS-001]** A client MUST re-encode a selected picture before it stores that picture in
   the blob. **[DIS-002]** The re-encode MUST remove each metadata field.
   **[DIS-003]** The re-encode MUST hold the result inside the `B2` bucket of
   8 KiB.
2. **[DIS-004]** If the user selects one picture for two Profiles, the client
   MUST warn. **[DIS-005]** The client MUST get an explicit confirmation. Part 4
   §4.2.5 gives the cross-Profile rules and the rule for a reused name.
3. **[DIS-006]** A client MUST NOT put a pet-avatar (§9.8) in the blob. A pet-avatar is local
   state, and no party receives it.

> *Cause.* Image metadata carries GPS coordinates. A picture above `B2` becomes
> a Part 13 attachment, and an attachment has a different metadata profile. A
> size fingerprint is not a cause here, because Part 3 §3.3 pads each cell to
> one of four sizes. Thus each picture inside `B2` looks the same on the wire.

### 9.3.2 The canonical form of a handle

Two strings that render as one string have to name one entry. The profile
below fixes one form of the `name` part, and each use of a handle in this part
starts from that form.

- **[DIS-088]** A client MUST apply the `UsernameCaseMapped` profile of RFC 8265
  to the `name` part before each use of a handle. That profile applies the
  `IdentifierClass` of RFC 8264, the width mapping, the case mapping, NFC, and
  the bidi rule. **[DIS-089]** A client MUST reject a `name` part that the
  profile rejects.
- **[DIS-090]** A client MUST measure the 32-byte limit of §9.3 on the output
  of the profile. The discriminator is ASCII digits, and the profile does not
  change it.
- **[DIS-091]** A directory MUST reject a registration whose `name` part
  changes under the profile.
- The **canonical handle** is `@`, the profile output, `#`, and the
  discriminator. **[DIS-092]** A client MUST use the canonical handle at each
  use of `<handle>` in this part. That use includes the VOPRF input of §9.3.1
  and the blob key of §9.3.1.

> *Cause.* An earlier draft gave the handle no normalization, and it ran the
> VOPRF over the bytes that the user typed. A `name` in NFD and the same
> `name` in NFC gave two directory indexes, and a lookup of the one missed the
> other. Signal avoids the problem with an ASCII grammar, and UMBRA keeps a
> Unicode `name`. The profile maps two renderings to one string, and it rejects
> a control character. A confusable pair stays, because no profile removes it.
> DIS-016 makes a handle no verified identity, and §9.8 gives the petname that
> the user trusts instead.

### 9.3.3 The address index

Part 4 §4.2.3 gives a Public Address a wire form, which is 20 bytes of the hash
of `PublicAddressKey_j.pk`. A person that holds that string, or the reusable
link of Part 4 §4.3.2, needs a rendezvous queue and an encapsulation key. The
address index gives both. It is a second label space in the tree of §9.5, and
the handle index is the first.

```
AddressEntry {
    address         [20]u8         // SHA3-256(PublicAddressKey_j.pk)[0..20], Part 4 §4.2.3
    address_pk      [1216]u8       // the public half of PublicAddressKey_j, X25519 then ML-KEM-768
    rendezvous      QueueAddress   // 129 bytes, Part 6 §6.6.10, rotatable at any time
    version         u32
}

label = VOPRF over ( "umbra/v1/address-index" || address )
```

An `AddressEntry` is 1 369 bytes. The label prefix keeps the address label
space apart from the handle label space of §9.3.1 under one VOPRF key. Part 5
§5.11 holds that label. A handle label is the VOPRF over the canonical handle alone,
thus no address label equals a handle label.

- **[DIS-103]** A client MUST NOT publish an `AddressEntry` without an explicit
  act of the user for that Public Address. Part 4 §4.2.3 makes a publication an
  explicit, informed, and revocable act, and this index does not change it.
- **[DIS-104]** A client MUST set `address_pk` to the public half of the
  `PublicAddressKey_j` whose hash is `address`. **[DIS-105]** A client that
  reads an `AddressEntry` MUST compute `SHA3-256(address_pk)[0..20]`.
  **[DIS-128]** The client MUST NOT use an entry whose result differs from
  `address`.
- **[DIS-106]** A client MUST NOT name one rendezvous queue in an
  `AddressEntry` and in a `DirectoryEntry`. **[DIS-107]** A client MUST poll the
  rendezvous queue of an `AddressEntry` under `DIS-014` and `DIS-015`. That is
  the poll of a handle queue.
- **[DIS-108]** An `AddressEntry` MUST use the registration, the lease, the
  tombstone, the renewal, and the write authorization of §9.9. In each of those
  constructions, `address_pk` takes the place of `HK_pub`, and the 20 bytes of
  `address` take the place of `handle`.
- **[DIS-109]** A directory MUST NOT serve a list of the address labels.
  **[DIS-129]** A directory MUST NOT answer a query that names a prefix of an
  address.

> *Cause.* An earlier draft let a stranger paste `umbra:pub:` in Part 4 §4.3.3,
> and no index resolved the string. The handle index of §9.3 holds `HK_pub`,
> which Part 4 rule `IDN-105` keeps apart from `PublicAddressKey_j`, thus that
> index cannot serve the address. The address is a 160-bit value, thus a crawl
> that enumerates the handle index finds no address entry. Part 16 §16.2.5
> states that difference. `DIS-106` keeps the two entries of one Profile apart
> at the rendezvous queue, because one shared queue address links the handle to
> the address under a crawl. Part 4 §4.2.4 gives the cause of that separation.
> Part 2 §2.4.2 goal S1 names this index.

## 9.4 Lookup: blind the query, meter the chokepoint

```
1. Client blinds the handle with a VOPRF (RFC 9497, ristretto255-SHA512).
2. Directory evaluates under its key, returning a DLEQ proof of correct evaluation.
3. Client unblinds to obtain the search key.
4. Client fetches the KEYTRANS inclusion or absence proof for that key.
```

An address lookup blinds `"umbra/v1/address-index" || address` in step 1, and
steps 2 to 4 do not change. A listing lookup of §9.12 blinds
`"umbra/v1/community-listing" || community_id` in the same manner.

The directory **does not see the plaintext handle**. An anonymous crawler has to
pass one chokepoint. That chokepoint is one operation that a party can meter,
and it shows nothing about the handle in the query.

### 9.4.1 Metering with anonymous tokens

The rate limit applies to the **OPRF evaluations** and not to the tree lookups.
The rate limit uses the first-party token of Part 14 §14.3.2 and not accounts.
There is one token for each evaluation. The issuer of Part 14 §14.9 issues the
tokens, and its key is separate from the key of the directory.

Obey the warning in RFC 9576. **Each bit of token metadata decreases the
anonymity set exponentially, and a key rotation divides the users.** Thus UMBRA
uses one token type, one issuer configuration, and one slow globally
synchronized rotation schedule (Part 14 §14.6).

A cheap proof-of-work on the client is the layer below. It is a fallback with no
dependency. Thus the directory degrades gracefully, and it does not fail closed,
if the issuer is unavailable. Part 14 §14.8 rule `ABU-070` gives the directory
an effort floor of `POW_LOOKUP_FLOOR`, thus a lookup with no token is not free.

## 9.5 The transparency log

### 9.5.1 Structure

UMBRA uses the KEYTRANS **combined tree**. That structure is a VRF-blinded
Merkle prefix tree. A snapshot of that tree goes into a left-balanced
append-only log tree, with HMAC commitments and a binary-ladder search.

**[DIS-007]** **The VRF inputs MUST be `(label || version)`, and not `label` alone.** This
rule is not negotiable. A fixed tree position for each user gives the CONIKS
tracing vulnerability. In that vulnerability, the sibling in your own inclusion
proof shows when your neighbor rotates a key. That leak continues forever, and
it continues after that neighbor removes you.

More requirements:

- **[DIS-008]** The tree MUST use a **fresh tree-wide nonce at each epoch** (CONIKS §3.1).
- **[DIS-009]** The leaf MUST commit to the **handle string** and not to the index. Thus a VRF
  key that an attacker chooses cannot collide two handles.
- **[DIS-010]** There MUST be a maximum of **one update for each label in each epoch**.

### 9.5.2 Third-party auditing, three jurisdictions

The log operates in `thirdPartyAuditing` mode, with **three independent signers
in three jurisdictions**. The signers are the nonprofit and two independent
auditors. Signer index `0` is the nonprofit, and signer indexes `1` and `2` are
the two auditors. A client accepts a tree head that two of the three signed.

Against adversary A5 this design means that **no one legal order can make a
split view**. A split view needs two signers, and no one jurisdiction holds two
of them. The freshness bound below limits an equivocation to one week.

The `contactMonitoring` mode is untenable in UMBRA. The contacts are mutually
pseudonymous, thus no party can depend on them to monitor the labels of each
other.

**The object.** The signed tree head follows the `DirectoryRoot` pattern of
Part 10 §10.5.2. Part 5 §5.1 gives ML-DSA-65 as primitive 3, and the primitive
register holds no threshold scheme. **[DIS-043]** A signer MUST sign a
`SignedTreeHead` with ML-DSA-65. **[DIS-044]** An implementation MUST NOT use a
threshold signature construction for a tree head.

```
SignedTreeHead {
    version        u8          // 0x01
    tree_size      u64         // the epoch of the log, which is its leaf count
    timestamp      u64         // Unix seconds, set by the log operator
    root           [32]u8      // the root hash of the log tree of §9.5.1
    keyset_hash    [32]u8      // SHA3-256 over the canonical LogKeySet
    sig_count      u8          // 2 or 3
    sigs           [sig_count]SignerSig
}

SignerSig {
    signer_index   u8
    sig            [3309]u8    // ML-DSA-65, label "umbra/v1/tree-head"
}

LogKeySet {
    version        u8          // 0x01
    keyset_epoch   u64         // strictly increasing
    signer_count   u8          // 3
    keys           [signer_count][1952]u8   // ML-DSA-65 public keys
}

SignedLogKeySet {
    keyset         LogKeySet
    sig_count      u8          // 2 or 3
    sigs           [sig_count]SignerSig     // under the PREVIOUS key set
}
```

Each signature covers this preimage:

```
"umbra/v1/tree-head" || version || tree_size || timestamp || root || keyset_hash
```

`keyset_hash` is the SHA3-256 over the canonical `LogKeySet` encoding.
`LogKeySet` carries no signature field, for the cause that Part 10 §10.5.2
states. **[DIS-045]** A signer MUST distribute a key set as a `SignedLogKeySet`.
**[DIS-046]** A client MUST compute `keyset_hash` over the `keyset` field
alone. A `SignedTreeHead` with 2 signatures is 6 702 bytes, and one with 3
signatures is 10 012 bytes. Part 6 §6.9 gives the `B3` `L5 payload` row 32 650
bytes, thus each form fits one `B3` cell.

**The issue of a head.**

1. **[DIS-047]** The log operator MUST make one `SignedTreeHead` for each
   epoch of the log. **[DIS-048]** The log operator MUST sign each head under
   signer index `0`.
2. **[DIS-049]** An auditor MUST verify the consistency proof from the last
   head that it signed before it signs a head. **[DIS-050]** Before an auditor
   signs the head of an epoch, it MUST verify the rules of §9.5.1 over its
   update set.
3. **[DIS-051]** A signer MUST NOT sign two heads that hold one `tree_size`.
   A named signer set makes an equivocation attributable, and this rule makes
   the second signature the evidence.
4. **[DIS-052]** The directory MUST return the newest `SignedTreeHead` with
   each proof of §9.4 step 4. **[DIS-053]** A client MUST verify an inclusion
   proof or an absence proof against the `root` of a head that it accepted.

**The verification rules.**

5. **[DIS-054]** A client MUST reject a `sig_count` that is not 2 or 3.
6. **[DIS-055]** A client MUST reject a repeated `signer_index`. **[DIS-056]**
   A client MUST reject a `signer_index` at or above `signer_count`.
7. **[DIS-057]** A client MUST reject a `sigs` list that is not in ascending
   order of `signer_index`.
8. **[DIS-058]** A client MUST verify each signature against the key at its
   `signer_index` in the `LogKeySet` that the client holds. **[DIS-059]** A
   client MUST count 2 or more valid signatures before it accepts the head.
9. **[DIS-060]** A client MUST reject a `SignedTreeHead` whose `keyset_hash`
   differs from the hash of the `LogKeySet` that the client holds.
10. **[DIS-061]** A client MUST reject a `SignedTreeHead` whose `tree_size` is
    below the highest `tree_size` that the client accepted.
11. **[DIS-011]** A client MUST reject a `SignedTreeHead` whose `timestamp` is
    more than `TREE_HEAD_FRESHNESS` plus `CLOCK_SKEW` before the device clock.
    **[DIS-062]** A client MUST reject a `SignedTreeHead` whose `timestamp` is
    more than `CLOCK_SKEW` after the device clock. §9.10 gives
    `TREE_HEAD_FRESHNESS` as 7 days, and Part 10 §10.11 gives `CLOCK_SKEW` as 1
    hour. The device clock bounds these two tests only. `DIS-061` holds when
    the clock is wrong, thus a client with a bad clock loses freshness and does
    not lose rollback protection.
12. **[DIS-063]** A client MUST retain each head that it accepted for
    `TREE_HEAD_RETAIN` after the acceptance. §9.5.3 compares a gossiped digest
    against a retained head.

**The self-check.** A compelled directory that inserts a version under a label
shows it in the tree. Only the holder can tell that the version is wrong. No
auditor holds the intent of the holder.

13. **[DIS-137]** A client that holds a published label MUST fetch the inclusion
    proof of its newest version at each head that it accepts. **[DIS-138]** If
    that version differs from the version that the client published, the client
    MUST show the takeover warning of §9.9.2. **[DIS-139]** The client MUST NOT
    publish a new version over a version that it did not publish, without a user
    action.

    The check is one lookup of §9.4 for each published label at each head.
    The token or the proof of work of §9.4.1 pays for it. Part 3 §3.12 does not
    count it, because a published label is an opt-in surface.

    > *Cause.* An earlier draft gave the holder no rule that reads its own
    > entry. A directory under an order inserted a key under a handle, each
    > stranger reached the new key, and no alarm fired at the holder. The
    > auditors of §9.5.2 verify the tree and not the intent of a holder, thus
    > the holder is the only monitor of its own label.

**The key-set rotation.**

13. **[DIS-064]** A client MUST accept a `LogKeySet` only with 2 or more valid
    ML-DSA-65 signatures from the **previous** key set. Each of those
    signatures covers `"umbra/v1/tree-head-keyset" || version ||`
    `keyset_epoch || SHA3-256(the new canonical key set)`. Part 5 §5.11 holds
    that label.
14. **[DIS-065]** A client MUST reject a `LogKeySet` whose `keyset_epoch` is at
    or below the `keyset_epoch` that the client holds.
15. **[DIS-066]** A client build MUST ship the genesis `LogKeySet`. Part 16
    §16.5 puts the build under binary transparency.

Two signers rotate the third out when an auditor stops, disputes, or receives
a legal order. Thus the loss of one signer costs one rotation and not the
directory.

**The degraded read.** A client is in the degraded read when it holds no
`SignedTreeHead` that passes rules 5 to 11. The loss of one signer does not put
a client in that state, because two signers suffice. The loss of two does.

16. **[DIS-067]** In the degraded read, a client MUST complete a lookup of
    §9.4. **[DIS-068]** In the degraded read, a client MUST show the result of
    a lookup as unverified.
17. **[DIS-069]** In the degraded read, a client MUST NOT send the hello of
    §9.6 step 2 without an explicit user confirmation.
18. **[DIS-070]** In the degraded read, a client MUST NOT replace a held
    `HK_pub` with a resolved value that differs.
19. **[DIS-071]** In the degraded read, a client MUST NOT show a split-view
    warning under `DIS-034`. The client holds no accepted head to compare
    against.

> *Cause.* An earlier draft made `DIS-011` a hard rejection of a tree head that
> the three signers did not co-sign in 7 days. That draft defined no object, no
> signer index, no preimage, no key set, and no rotation. Under that draft one
> auditor outage, one dispute, or one legal order stopped each handle lookup
> after seven days. §9.4.1 says that the directory degrades gracefully and does
> not fail closed. The deployment of Signal runs two auditors in one
> jurisdiction, which shows how hard three funded auditors in three
> jurisdictions are to keep. A 2-of-3 acceptance keeps the property that no
> one legal order makes a split view, and it survives the loss of one signer.
> The degraded read keeps a lookup available below that threshold, and it
> removes the two automatic actions that a forged entry would exploit.
> `DIS-011` now names the object, the field, the measuring party, and the skew
> tolerance, as §1.9 requires. Its bound of 7 days is unchanged.

### 9.5.3 Gossip the tree head in ordinary ciphertext

A client sends the 32-byte `root` of the newest tree head that it accepted to
a contact **inside the AEAD payload of an ordinary record**. That is the design
of Apple CKV.

Part 6 §6.6.4 gives the carrier, which is an `AppMessage` of kind `0x31` with a
`DigestBody`. The `source` byte holds `0x01` for this tree head.

- **[DIS-026]** A client MUST carry a tree head as a `DigestBody` of Part 6
  §6.6.4. **[DIS-027]** A client MUST NOT put a tree head in a field that this
  specification does not define. **[DIS-072]** A client MUST set `epoch` to the
  `tree_size` and `digest` to the `root` of the newest head that it accepted.
- **[DIS-028]** A client MUST emit at most one digest for each `source` in each
  `GOSSIP_INTERVAL`. §9.10 sets that value to 6 hours.
- **[DIS-029]** A client MUST emit a digest in a scheduled cover slot of Part 3
  §3.6.2 only. **[DIS-030]** A client MUST NOT open a session for the only
  purpose of a digest.
- **[DIS-031]** A client MUST select the contact of a digest at random from the
  contacts that hold a live session. **[DIS-032]** A client MUST NOT send one
  digest to more than one contact in one cover slot.
- **[DIS-033]** A receiver MUST compare a digest against the tree head that it
  holds at that `epoch`. **[DIS-136]** If the receiver holds no head at that
  `epoch`, it MUST fetch the co-signed head of that `epoch` before the
  comparison. **[DIS-034]** If the two values differ, a receiver MUST show a
  split-view warning. Rule `DIS-063` retains the fetched head.

This method costs almost nothing. A digest replaces the cover cell of its slot,
thus it adds no cell to the outbound process. It needs no more network contact,
thus it makes no new correlator. It is also the only split-view detector that
survives an adversary that controls the full view of the client of the
directory.

> *Cause.* An earlier draft said that a client attaches the hash to a fraction of
> the ordinary messages, and Part 6 gave no field, no application kind, and no
> capacity row. Part 6 §6.4.2 rule 6 also fills the L6 record to a fixed length,
> thus no spare byte holds a hash. Part 16 §16.4 names this gossip as the answer
> to directory equivocation, and Part 10 rule `REL-008` requires the same
> mechanism for the consensus root. The record of Part 6 §6.6.4 serves the two.

### 9.5.4 Ciphersuite, and the one place UMBRA is not post-quantum

| Component | Algorithm |
| --- | --- |
| Trees | SHA3-256 |
| Tree-head and update signatures | ML-DSA-65 |
| Commitments | HMAC-SHA3-256 with a random 32-byte opening |
| **Index blinding** | **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) — classically secure only** |

**[DIS-012]** **An implementation MUST state this limit in its user-facing documentation.**
Part 16 §16.2.6 records the same limit as a residual risk. A harvested log and a
future cryptographically relevant quantum computer together **de-blind the full
historical directory**.

There are two mitigations. First, rotate the VRF key at a multi-year era
boundary. Second, use the "enumeration is worthless" property of §9.3. The
de-blinded directory shows which handles existed, and that data is close to
public.

The only available post-quantum VRFs are impractical. LB-VRF gives an 84-byte
output with a proof of about 5 KB, and it is a few-time scheme. Examine this
decision again before v2.

## 9.6 Contact through a handle: upgrade immediately and abandon the path

```
1. Initiator looks up @alice → (HK_pub, rendezvous_queue).
2. Initiator sends a hello to the rendezvous queue, encapsulated to HK_pub,
   with the Admission of Part 14 §14.4 at its end.
3. Alice reviews the request and accepts.
4. BOTH sides mint fresh pairwise identities and fresh unidirectional queues on
   INDEPENDENTLY selected relays.
5. The rendezvous path is never used again for that conversation.
```

**What the hello carries.** The hello holds the invitation fields of Part 5
§5.4.1, which the initiator makes for this request, and the profile that the
initiator shows. Thus the initiator of the request is the responder of the
handshake, and its one-time prekey travels inside the hello. No relay and no
directory serves a prekey, and Part 5 §5.4.5 states that rule.

**[DIS-086]** A client MUST put a fresh set of the fields of Part 5 §5.4.1 in
each hello. **[DIS-087]** A client that accepts a request MUST
send flight 1 of Part 5 §5.4.2 to the `queue_address` of those fields.

**[DIS-131]** A client MUST end a hello with one `Admission` of Part 14 §14.2,
inside the AEAD of the hello. **[DIS-132]** That `Admission` MUST hold a
cross-relay token of Part 14 §14.3.1 or a `PowSolution` of Part 14 §14.4. Part
14 §14.4 gives the verification at the addressee, and the queue relay reads a
padded message and nothing more.

**Contact through a Public Address.** The initiator holds the 20-byte address
from a pasted string or from a reusable link of Part 4 §4.3.2. Step 1 then
looks up the `AddressEntry` of §9.3.3, and it gets `(address_pk, rendezvous)`.
**[DIS-110]** A client MUST encapsulate that hello to `address_pk`. Part 14
§14.4 derives the proof-of-work seed from `address_pk`. Steps 3 to 5 do not
change. Part 8
§8.2.6 gives the drain of the rendezvous queue at the addressee, and Part 2
§2.4.2 goal S1 sets the latency.

**[DIS-013]** **After the upgrade, a contact from a handle MUST be bit-for-bit
indistinguishable from a contact from a QR code.**

**[DIS-014]** The client MUST poll the rendezvous queue through a **different relay chain**
from the pairwise queues. **[DIS-015]** The client MUST also poll that queue on a **different
schedule**. Thus a relay that sees the
polling of a handle queue cannot correlate that polling with the conversation
traffic of the same user.

## 9.7 A key change propagates in each pairwise session, and no root signs it

This rule is the KISS answer and also the unlinkable answer, and it is easy to
make incorrectly.

**Do not** broadcast a root-signed statement about a new key. One root signature
that arrives at *n* contacts is a **perfect linker**. It proves to two colluding
contacts that they share a correspondent, and it destroys goal G9.

In place of that method, introduce the replacement pairwise key **in each
existing pairwise session**. Part 4 §4.5.1 gives the key-change notice that
carries it. **No party signs that notice.** A `PairwiseIdentity_c` holds an
X25519 keypair and an ML-KEM-768 keypair only, and neither keypair signs data.
The ratchet of the existing session authenticates the notice, in the same manner
as it authenticates an edit (Part 6 §6.6.1).

Each contact receives a different record on a different chain. **[DIS-023]** A client MUST
send one notice for each contact. **[DIS-024]** A client MUST NOT reuse one
authenticated object across two contacts. Part 4 §4.5.1 rule 6 gives the delay
that separates the sends.

A client uses the root identity **only** for recovery after a total loss. That
recovery falls back correctly to out-of-band verification.

## 9.8 UI: a petname system, not a handle display

Each contact has three names:

| Name | Global? | Memorable? | Secure? | Shown |
| --- | --- | --- | --- | --- |
| Key | yes | no | yes | on demand |
| **Handle** | yes | yes | **no** | secondary, always with its origin |
| **Petname** (the user assigns it) | no | yes | yes | **prominently** |

**[DIS-016]** **A handle MUST NOT render as a verified identity.** The documentation of Signal
states that key transparency "does not verify the identity of the user who
controls a particular phone number or username." A handle proves that *this key
is consistently published for this string*. A handle proves nothing about the
party that holds the key.

The user assigns the petname when the user accepts the contact. That moment also
gives the user a natural point to do the out-of-band confirmation.

**The pet-avatar.** **[DIS-017]** The viewer MAY also assign a picture to a contact. The
client shows that picture to the viewer only. **[DIS-018]** **A client MUST NOT send a
pet-avatar to any party.** A pet-avatar is mutable state under Part 7 §7.5.3,
thus the devices of one user converge on one value. §9.3.1 rule 3 keeps a
pet-avatar out of the encrypted profile blob.

The pet-avatar stands beside the petname. The viewer names the contact, and the
viewer pictures the contact. Part 4 §4.2.5 gives the Profile, which holds the
value that the contact selected. **[DIS-019]** The client MUST show the two values apart.

### 9.8.1 Verification UX

**This subsection covers a handle key in the §9.5 transparency log. It does not
cover a pairwise identity key.** **[DIS-025]** A client MUST apply Part 4 §4.5.1 to a
pairwise identity key, and IDN-025 makes that notice blocking.

- **Automatic verification is the default, and it is silent.**
- A **handle** key-change warning fires **only** when the transparency log cannot
  prove that the publication of the change was consistent. **[DIS-020]** A warning MUST NOT
  fire at each rotation of a handle key. **[DIS-021]** A warning MUST state the concrete next
  action. **[DIS-022]** A warning MUST NOT show a fingerprint.
- The manual fallback is a **short comparison code in the SAS style**. The
  manual fallback is not a long fingerprint.

> The evidence is clear. In Schröder and Huber (EuroUSEC 2016), 21 of the 28
> participants failed the comparison of a long number. **13 of those
> participants believed that they had succeeded.** A verification UI that
> persons fail while they feel successful is worse than no UI, because it makes
> false confidence.

## 9.9 Handle lifecycle and abuse controls

| Control | Rule |
| --- | --- |
| Registration cost | One first-party token of Part 14 §14.3.2, with no proof-of-work fallback (Part 14 §14.2). **A phone number or an email address is prohibited.** |
| Format | `@name#dddd`. A discriminator of 2 to 9 digits prevents nickname squatting |
| Lease | A handle has a lease of `HANDLE_LEASE`. The user renews the lease with the challenge of §9.9.1. The directory tombstones a handle with no renewal |
| Tombstone | A tombstoned label stays reserved for its last holder for `HANDLE_RESERVE`. A registration after that period is a takeover, and §9.9.2 gives the warning |
| Rendezvous rate limit | A cross-relay token or a proof of work for each request, and `HELLO_INBOUND_LIMIT` hellos in each epoch. Part 14 §14.4 gives both |
| Rotation | A rotation of the handle or of the rendezvous address is **instant and one tap**. §9.9.3 authorizes the write. The client also rotates the rendezvous address at each `RENDEZVOUS_ROTATE` |

A trivial rotation is the objective. It is the real defense of the user against
spam and against a completed crawl. It is also the cause that the directory
holds nothing worth a second crawl.

**The scheduled rendezvous rotation.**

- **[DIS-133]** A client MUST publish a new rendezvous queue for each published
  entry at each `RENDEZVOUS_ROTATE`. **[DIS-134]** The client MUST keep the
  previous queue for `ROTATE_GRACE` of Part 3 §3.2.6 after the write.
  **[DIS-135]** The client MUST drain both queues under Part 8 §8.2.6 during
  that period. Thus a stranger that resolved the entry before the write reaches
  the holder, and one queue relay holds the hello count of one period only.

> *Cause.* An earlier draft made each rotation a user action. A published queue
> address is a public value. The relay that holds it reads the hello count and
> the hello times of the entry for as long as the address stands. Part 16 §16.3
> states that residual, and the schedule bounds it to one period. The cost is
> one `NEW` and one directory write in each period.

### 9.9.1 The lease renewal challenge

The renewal proves that the party holds the private half of `HK_pub`. The
construction uses two primitives of Part 5 §5.1, which are `UMBRA-KEM` and
HMAC-SHA3-256. It adds no primitive to the register.

```
directory:   (ct, ss) <- UMBRA-KEM.Encap( HK_pub )
             nonce    <- 16 bytes from the CSPRNG of the directory
             sends ct || nonce

holder:      ss  <- UMBRA-KEM.Decap( HK_sk, HK_pub, ct )
             k   <- HKDF-SHA3-256( salt = "umbra/v1/handle-renew", ikm = ss,
                                   info = handle || BE64(lease_epoch), L = 32 )
             ans <- HMAC-SHA3-256( k, nonce )
             sends ans
```

- **[DIS-035]** A directory MUST encapsulate to the `HK_pub` that its current
  entry holds. **[DIS-036]** A directory MUST make `nonce` from its own CSPRNG
  for each renewal.
- **[DIS-037]** A holder MUST derive `k` with the label above, and Part 5 §5.11
  holds that label. **[DIS-038]** A holder MUST answer with the HMAC-SHA3-256
  over `nonce` under `k`.
- **[DIS-039]** A directory MUST compare `ans` in constant time. **[DIS-040]** A
  directory MUST NOT renew a lease without a correct `ans`. **[DIS-041]** A
  directory MUST NOT accept an `ans` for a `lease_epoch` that it did not issue.
- **[DIS-042]** A directory MUST NOT retain `ss`, `k`, or `ans` after the
  renewal.

> *Cause.* An earlier draft renewed a lease with "a ZK proof of knowledge of the
> handle key". Part 5 §5.1 closes the primitive register and rule `CRY-005`
> forbids a primitive that the register does not hold. `HK_pub` is X25519 with
> ML-KEM-768, and neither half signs data, thus no listed primitive gives that
> proof. A challenge under the KEM proves the same possession, and it is post-
> quantum on the ML-KEM half.
>
> The challenge is not a signature, thus it is not transferable. A directory
> that keeps `ans` proves nothing to a third party, because that directory could
> compute `ans` itself from `ss`. DIS-042 removes the value in any case.

### 9.9.2 The tombstone, the reservation, and the takeover

A tombstone ends the lease, and it does not end the record of the label. A user
that lost each device restores from a backup inside `BACKUP_TTL` of Part 4
§4.8. The restored client derives the handle key again under Part 4 §4.2.4,
and it answers the challenge of §9.9.1. The reservation below keeps the label
for that user.

**The tombstone.**

- **[DIS-073]** A directory MUST publish a tombstone as a version of the label
  whose `HK_pub` and `rendezvous` fields hold zero bytes. **[DIS-074]** A
  directory MUST hold the last `HK_pub` of a tombstoned label for
  `HANDLE_RESERVE` after the tombstone.
- **[DIS-075]** During `HANDLE_RESERVE`, a directory MUST NOT register a
  tombstoned label to a party that fails the challenge of §9.9.1. The
  challenge uses the last `HK_pub` of the label. **[DIS-076]** If the answer is correct, the
  directory MUST publish a new version of the label with the same `HK_pub`.
- **[DIS-077]** After `HANDLE_RESERVE`, a directory MUST publish a registration
  of the label as the next version after the tombstone version.

**The takeover warning.** A registration after the reservation is a consistent
publication, thus the log proves it. `DIS-020` keeps a rotation silent, and a
takeover is not a rotation.

- **[DIS-078]** A client MUST hold the `version` of the entry with each
  `HK_pub` that it holds for a handle.
- **[DIS-079]** Before a client replaces a held `HK_pub`, it MUST fetch each
  label version between the held and the resolved `version`.
  **[DIS-080]** If that count is above `HANDLE_HISTORY_MAX`, the client MUST
  show the takeover warning.
- **[DIS-081]** If a tombstone version lies between the two, the client MUST
  compare the `HK_pub` before it with the `HK_pub` after it.
  **[DIS-082]** If the two differ, the client MUST show the takeover warning.
- **[DIS-083]** A client MUST NOT apply `DIS-020` to the takeover warning.
  **[DIS-084]** The takeover warning MUST state that a different party now
  holds the handle.
- **[DIS-085]** Under the takeover warning, a client MUST NOT send the hello
  of §9.6 step 2 without an explicit user confirmation.

> *Cause.* An earlier draft tombstoned a handle with no renewal and stopped
> there. A second party then registered the label, and the log proved that
> publication consistent, thus `DIS-020` kept the client silent. A contact that
> held a pet name for the handle then sent a hello to the second party. The
> reservation equals `BACKUP_TTL`, because a backup that a relay still holds is
> a backup that a user can still restore. The zero-byte tombstone gives the
> client a version to find, and the version scan is bounded because a rotation
> is rare.

### 9.9.3 The write authorization

A new version of an existing label is a write, and the renewal of §9.9.1
authorizes no write. The construction below proves that the writer holds the
private half of the current `HK_pub`. It binds the answer to the entry that
the writer sends.

```
directory:   (ct, ss) <- UMBRA-KEM.Encap( HK_pub_current )
             nonce    <- 16 bytes from the CSPRNG of the directory
             sends ct || nonce

holder:      ss  <- UMBRA-KEM.Decap( HK_sk, HK_pub_current, ct )
             k   <- HKDF-SHA3-256( salt = "umbra/v1/handle-write", ikm = ss,
                                   info = handle || BE32(version_new), L = 32 )
             ans <- HMAC-SHA3-256( k, nonce || SHA3-256(entry_new) )
             sends ans || entry_new
```

- **[DIS-093]** Before a directory publishes a new version of an existing label,
  it MUST run the challenge above. **[DIS-094]** A directory MUST encapsulate to
  the `HK_pub` of the current version.
- **[DIS-095]** A holder MUST derive `k` with the label above, and Part 5 §5.11
  holds that label. **[DIS-096]** A holder MUST compute `ans` over `nonce` and
  `SHA3-256(entry_new)`.
- **[DIS-097]** A directory MUST compare `ans` in constant time. **[DIS-098]** A
  directory MUST NOT publish `entry_new` without a correct `ans`.
  **[DIS-099]** A directory MUST NOT publish an `entry_new` whose `version` is
  not the current version plus one.
- **[DIS-100]** A directory MUST NOT retain `ss`, `k`, or `ans` after the
  write.
- **[DIS-101]** A registration of a label that no version holds MUST carry the
  token of §9.9, and it needs no challenge. §9.9.2 covers a tombstoned label.
- **[DIS-102]** A directory MUST NOT run the challenge for the tombstone of a
  lapsed lease. The directory publishes that version itself.

> *Cause.* An earlier draft gave the directory no rule about who writes a new
> version. A party that held a registration token published a version of the
> label of another user. §9.9.2 then showed that user as a takeover. The
> challenge above is the challenge of §9.9.1 under a second label, with the
> entry hash in the answer. Thus a directory that relays a challenge to the
> holder cannot swap the entry after the answer. A lapsed lease needs no
> challenge, because the directory writes the tombstone and no other party
> does.

## 9.10 Parameters

| Parameter | Value |
| --- | --- |
| `GOSSIP_INTERVAL` | 6 h for each `source` (§9.5.3) |
| `HANDLE_LEASE` | 180 days, renewed under §9.9.1 |
| `TREE_HEAD_FRESHNESS` | 7 days, measured by the client from the `timestamp` of the head (§9.5.2) |
| `TREE_HEAD_RETAIN` | 14 days, measured by the client from the acceptance of the head (§9.5.2) |
| `HANDLE_RESERVE` | 180 days, measured by the directory from the tombstone, equal to `BACKUP_TTL` of Part 4 §4.8 (§9.9.2) |
| `HANDLE_HISTORY_MAX` | 64 versions, the version scan bound of §9.9.2 |
| `LISTING_LEASE` | 30 days, measured by the directory from the acceptance of a `CommunityListing` (§9.12) |
| `RENDEZVOUS_ROTATE` | 30 days, measured by the client from the write of the current rendezvous version (§9.9) |
| `LISTING_PAGE` | 20 listings in one `ListingPage` (§9.12) |
| Directory scale | 10⁵ to 10⁷ entries (§9.2) |

## 9.11 Implementation note

Vendor the ECVRF, and write the rest.

The `akd_core` ECVRF module of `facebook/akd` is the only RFC 9381
implementation in Rust with an NCC audit. Mirror that module, or write it again
against its test vectors. Do **not** take the full `akd` crate. That crate
carries the complexity of SEEMless and Parakeet, together with tombstoning,
compaction, and assumptions with a MySQL shape. An opt-in directory of 10⁶
entries does not need those parts.

Use NCC-E008327 as the test checklist of UMBRA:

- reject identity points from `encode_to_curve`
- reject low-order VRF public keys
- reject non-canonical encodings
- zeroize expanded private keys on drop
- enforce a maximum of one update for each label in each epoch

## 9.12 The community listing

Part 12 §12.7.2 lets a community opt in to a public listing. This section gives
the listing record, its index, and the browse query. A listed community is a
public statement, and Part 12 §12.7.2 states what that statement shows.

```
CommunityListing {
    version         u8            // 0x01
    community_id    [32]u8
    admission       u8            // the admission byte of Part 12 §12.2.2
    actor           [32]u8        // the genesis owner role pseudonym
    actor_pk        [1952]u8      // genesis_root_public_key of Part 12 §12.2
    listing_index   u32           // increases by one at each publication
    category        u8            // the category table of Part 12 §12.7.1
    language        [2]u8         // ISO 639-1, lower case
    activity        u8            // the activity bucket of the table below
    name_len        u8
    name            [name_len]u8  // UTF-8, ≤ META_NAME_MAX of Part 12 §12.9
    link_len        u8
    link            [link_len]u8  // the community link of Part 12 §12.7
    signature       [3309]u8      // ML-DSA-65, label "umbra/v1/community-listing"
}

label = VOPRF over ( "umbra/v1/community-listing" || community_id )
```

The signature covers each field before it, with the label in front. A link is
259 characters at `COMMUNITY_RELAY_MAX` hints. That count is 10 characters
of scheme and path, 52 of `community_id`, and 3 of `?r=`. It is then 167 of
eight 20-character hints with seven commas, and 27 of the fragment with its
`#`. Thus a listing
is a maximum of 5 659 bytes. Part 5 §5.11 holds the two labels.

| `activity` | The distinct pseudonyms that posted in the last 7 days |
| --- | --- |
| `0x00` | 0 |
| `0x01` | 1 to 9 |
| `0x02` | 10 to 99 |
| `0x03` | 100 to 999 |
| `0x04` | 1 000 or more |

**The publication.**

- **[DIS-111]** A directory MUST verify that
  `SHA3-256("umbra/v1/community-id" || admission || actor_pk)` equals
  `community_id`, and that `SHA3-256(actor_pk)` equals `actor`. **[DIS-112]** A
  directory MUST verify the signature under `actor_pk`. **[DIS-113]** A
  directory MUST NOT publish a listing that fails either check.
- **[DIS-114]** A directory MUST NOT publish a listing whose `listing_index` is
  not the current index plus one. A first listing has index 0.
- **[DIS-115]** A listing MUST carry the token of §9.9 at each publication.
- **[DIS-116]** A directory MUST remove a listing at `LISTING_LEASE` after its
  acceptance, unless a later listing replaced it.
- **[DIS-117]** An owner client MUST set `activity` from the chains that the
  client pulled under Part 12 §12.3.3. **[DIS-118]** An owner client MUST set
  `category`, `language`, and `name` to the values of the current
  `CommunityMeta`.

**The browse query.** A browse asks for the listings of one category, of one
language, or of a name prefix, and the directory answers with a page.

```
ListingQuery {
    version         u8            // 0x01
    category        u8            // 0xFF names each category
    language        [2]u8         // two zero bytes name each language
    prefix_len      u8            // 0 names each name
    prefix          [prefix_len]u8
    page            u16
}

ListingPage {
    version         u8
    count           u8            // 0 to LISTING_PAGE
    listings        [count]CommunityListing
}
```

- **[DIS-127]** A directory MUST NOT put a listing with `link_len` 0 in a
  page. Part 12 rule `COM-351` makes that listing the withdrawal.
- **[DIS-119]** A directory MUST rank the listings of an answer by `activity`
  from high to low. **[DIS-130]** Inside one bucket, a directory MUST rank by
  the acceptance time from new to old. **[DIS-120]** A directory MUST NOT put more than `LISTING_PAGE` listings
  in one page.
- **[DIS-121]** A directory MUST match `prefix` against the `name` after the
  `UsernameCaseMapped` profile of §9.3.2 on both strings.
- **[DIS-122]** A browse MUST carry one first-party token of §9.4.1. The
  proof-of-work floor of Part 14 rule `ABU-070` applies to a browse with no
  token.
- **[DIS-123]** A client MUST verify `DIS-111` and `DIS-112` on each listing
  that it shows. **[DIS-124]** A client MUST show a listing as unverified until
  the `CommunityMeta` of the link verifies under Part 12 §12.7.1.
- **[DIS-125]** A client MUST compare `activity` with the chains that it pulls
  after the join. **[DIS-126]** If the pulled chains show a lower bucket, the
  client MUST show that difference beside the listing.

> *Cause.* Part 12 §12.7.2 named a directory that no part defined, thus Part 2
> §2.4.2 goal S3 had no mechanism. The listing puts a signed record under a
> label in the tree of §9.5, thus an owner audits the record that the directory
> serves. The genesis owner is the one party that the directory can verify,
> because `community_id` commits to `actor_pk`. A community that lost the
> genesis key cannot list, and no other party can list it. The activity bucket
> comes from the chain and not from a subscriber count. No party holds a
> subscriber count, because Part 12 §12.8 states that no subscriber list
> exists. A relay could report a pull volume through the aggregate of Part 10
> §10.8, and this draft does not add that path. The owner already signs the
> listing, and a subscriber checks the bucket against the chain under
> `DIS-125`.
