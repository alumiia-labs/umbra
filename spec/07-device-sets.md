# UMBRA Protocol Specification — Part 7: Device Sets, History Sync, and Revocation

**Status:** Draft
**Version:** 0.13.0
**Date:** 2026-10-09

---

## 7.1 Why this is in v1 and not v2

Multi-device operation with history sync is a **key-schedule constraint and not
a feature**. A design that assumed one ratchet for each pairwise queue cannot
add it later. Such a design has to rebuild the key schedule, or it has to push
the ratchet state onto relays.

A double-ratchet state on a relay, in an encrypted form, gives a seized relay an encrypted blob for each user, and the
*update time of that blob alone* is a strong activity signal. That design
also has four problems: concurrent state updates, the prevention of two
subscriptions at the same time, skipped-message handling, and a ratchet
conflict when two devices process the same message.

Thus UMBRA specifies device sets in the initial key schedule.

## 7.2 The accepted trade

UMBRA v1 has multi-device operation **with** history sync. Part 2 §A6
states the consequence. This part states it again, because a user needs this
fact before the link and not after it:

> **The seizure of one device in a Device Set exposes the synced history of that
> device.** History sync gives a copy to each linked device. The mitigations
> below limit the exposure, and they do not remove it.

The exposure is larger than the synced history if the seized device is unlocked
or if malware compromises it. Such a device can hold or recover the
`RootIdentity`, the local identity table, and the current queue state. That
result is an identity compromise and not only a history compromise. Revocation
(§7.7) stops the future traffic only if the attacker did not keep the
`RootIdentity`. If the attacker kept it, the user has to do the full identity
reset of §7.7.1.

The mitigations below are all mandatory:

1. **Scoped sync** (§7.5) — a device declares how much history it accepts.
2. **Retention limits** (§7.5.2) — the age and the size of the synced history
   have limits.
3. **Fast revocation** (§7.7) — the system cuts off a lost device, and that
   device cannot decrypt future traffic. §7.3 makes the roster signing key local
   to one device, thus a revoked device also cannot sign a later roster epoch.
4. **Per-device at-rest encryption** (Part 14) — a seized device that is powered
   off is a ciphertext blob and not a transcript.

## 7.3 Structure

```
RootIdentity
     │ KDF("umbra/v1/device-set")
     ▼
 K_devset
     └── SyncChannelSeed   (derives sync queues, updated at each revocation, §7.7)

 Device_1 (phone)     Device_2 (laptop)     Device_3 (tablet)
   DeviceKey_1          DeviceKey_2           DeviceKey_3
   DeviceRosterKey_1    DeviceRosterKey_2     DeviceRosterKey_3
   generated ON that device; the private half never leaves it
```

Each device makes its own `DeviceKey` locally, which is X25519 with ML-KEM-768.
Each device also makes its own `DeviceRosterKey` locally, which is an ML-DSA-65
keypair. The device transfers the `RootIdentity` seed one time, at the link,
over the channel of §7.4.

**The roster signing authority is per device, and it does not come from the
`RootIdentity`.**

- **[DEV-224]** A device MUST make its own `device_id` from its own CSPRNG at
  the link. A `device_id` names one device. A roster epoch MUST NOT hold two
  entries with one `device_id`. A parser MUST reject an epoch that does.
  A device MUST refuse the link of a new device whose `device_id` its
  roster holds in `devices` or in `revoked`. Two entries with one identifier
  would share one sync channel, and one of the two devices would lose its
  sync with no notice. **[DEV-225]** A device MUST NOT derive `device_id` from a key, from
  a hardware identifier, or from an earlier `device_id`.
- **[DEV-143]** A device MUST make `DeviceRosterKey_i` from its own CSPRNG. **[DEV-144]** A device MUST
  NOT derive that keypair from the `RootIdentity`, from `K_devset`, or from
  `SyncChannelSeed`.
- **[DEV-145]** A device MUST NOT transmit the private half of `DeviceRosterKey_i`. **[DEV-146]** The
  provisioning payload of §7.4 MUST NOT carry that private half.
- **[DEV-147]** A device MUST publish the public half of `DeviceRosterKey_i` in its
  `DeviceEntry` of §7.3.1.

> *Cause.* `K_devset` comes from the `RootIdentity`, and §7.4 gives the
> `RootIdentity` to each linked device. If one `DeviceRosterKey` came from
> `K_devset`, each linked device could derive that one signing key. A revoked
> device could then sign roster epoch *n+2* and put itself back in the set.
> Revocation is mitigation 3 of §7.2, and under that derivation the mitigation
> reaches no device that was linked at any time. A per-device key that
> the device makes locally removes the signing authority of a revoked device,
> because §7.3.1 rule 4 takes the authority from the previous epoch and not from
> a secret that every device holds.
>
> The `RootIdentity` still reaches each device, and §7.2 states that cost. That
> cost is a cost against the pairwise identities and the recovery path
> only. §7.7.1 gives the full identity reset for that case.

### 7.3.1 The roster

A **roster** describes the device set. The roster is a signed record with a
version number that increases monotonically:

```
Roster {
    version        u8           // 0x01
    epoch          u64          // strictly increasing
    device_count   u8
    devices        [device_count]DeviceEntry
    revoked_count  u8
    revoked        [revoked_count][16]u8   // DeviceId tombstones, never removed
    claim_count    u8           // 0 to OWNER_CLAIM_MAX
    claims         [claim_count]OwnerClaim
    prev_hash      [32]u8       // SHA3-256 of the previous roster, hash-chained
    signer_id      [16]u8       // the DeviceId of the signing device
    sig            [3309]u8     // ML-DSA-65, label "umbra/v1/device-roster"
}

DeviceEntry {
    device_id      [16]u8       // random, not derived
    x25519_pk      [32]u8
    mlkem_pk       [1184]u8
    mldsa_pk       [1952]u8     // DeviceRosterKey_i, made on that device (§7.3)
    label          [32]u8       // user-visible, for example "Laptop"
    added_epoch    u64
    sync_scope     u8           // see 7.5
}

OwnerClaim {
    scope          u8           // 0x01 a pairwise identity, 0x02 retired,
                                // 0x03 each subject of an absent device,
                                // 0x04 the group sender owner
    subject        [32]u8       // a blinded subject, see below
    owner          [16]u8       // the DeviceId that takes the ownership
}
```

**The subject is blinded.** `K_set` is the `DeviceSetKey` of Part 4 §4.2, and
Part 6 §6.6 uses it in the same manner for `msg_ref`. **[DEV-226]** A device
MUST compute `subject` as `SHA3-256(K_set || scope || value)`. For scope `0x01`
the value is the pairwise identity public key, which is the 32-byte X25519
public key of Part 4 §4.5. The scope `0x02` is reserved. For scope
`0x03` the value is the
`device_id` of the absent device, and §7.5.4 gives that claim. For scope
`0x04` the value is 32 zero bytes, thus one claim names the group sender owner
of Part 11 §11.12 for every group of the user, and §7.5.4 gives that claim.

> *Cause.* A roster that names each subject in the clear is a list of each
> contact of the user. That list is signed, and each
> device and the archive of §7.6.1 hold it. `K_set` never leaves the device
> set, thus a party outside the set cannot test a candidate against the list.
> A seized device holds `K_set`. Thus the blinding protects the archive and a
> roster that left the set, and it does not protect a seized device. Part 15
> §15.3 records that residual.

A `DeviceEntry` is 3 225 bytes and an `OwnerClaim` is 49 bytes. A roster at
`MAX_DEVICES` with 4 tombstones and 8 claims is 29 625 bytes, thus it uses
bucket `B3`. That total is 60 bytes of fields, 8 entries at 3 225 bytes, 4
tombstones at 16 bytes, 8 claims at 49 bytes, and a 3 309-byte signature. Part 6
§6.9 gives the body of an `AppMessage` 32 448 bytes at `B3`, and the
`DeviceSetControl` header of §7.5.5 takes 3 more bytes. **[DEV-164]** A later version MUST derive
this total again if it adds a field to `DeviceEntry` or raises `MAX_DEVICES`.

A roster epoch travels as a device-set control record of §7.5.5, with the
`control_type` value `0x02`.

**[DEV-001]** A device MUST NOT give the roster to a relay in plaintext. A device distributes
the roster over the sync channel (§7.5). A device gives a redacted form to the
contacts (§7.6).

**The signature preimage.** The signature covers this preimage:

```
"umbra/v1/device-roster" || version || epoch || device_count || devices ||
revoked_count || revoked || claim_count || claims || prev_hash || signer_id
```

Part 5 §5.11 holds the label `"umbra/v1/device-roster"`.

**The six rules of a roster epoch.**

1. **[DEV-148]** A device MUST sign a roster epoch with its own `DeviceRosterKey_i`. **[DEV-149]** A device
   MUST put its own `DeviceId` in `signer_id`.
2. **[DEV-150]** A verifier MUST check `prev_hash` against the SHA3-256 of the roster epoch
   that it holds at `epoch − 1`. **[DEV-151]** A verifier MUST reject an epoch that does not
   chain.
3. **[DEV-152]** For an epoch above 0, a verifier MUST find `signer_id` in the `devices` list
   of the **previous** epoch. **[DEV-153]** A verifier MUST reject the epoch if the previous
   epoch names `signer_id` in its `revoked` list. **[DEV-154]** A verifier MUST verify `sig`
   against the `mldsa_pk` of that entry.
4. **[DEV-155]** For epoch 0, a verifier MUST find `signer_id` in the `devices` list of that
   same epoch. **[DEV-156]** That verifier MUST verify `sig` against the
   `mldsa_pk` of that entry.
   Epoch 0 is the trust anchor of the device set. §7.4 step 4 carries the
   current roster to a new device, and that transfer moves on the authenticated
   channel of §7.4.
5. **[DEV-157]** A verifier MUST reject an epoch whose `revoked` list does not hold each
   `DeviceId` that an earlier epoch revoked. A tombstone is permanent. Thus a
   parser MUST also reject an epoch that names a `DeviceId` of its own
   `revoked` list in its `devices` list.
6. **[DEV-176]** A device MUST set `epoch` to the `epoch` of the previous roster plus 1.
   **[DEV-180]** A device MUST NOT apply a roster epoch that names its own `DeviceId` in
   `revoked`. **[DEV-181]** That device MUST show that event to the user.

**Two devices that sign one epoch index.** §7.5.4 lets a device claim an
ownership at the next epoch, thus two devices can sign the same epoch index at
the same time. That event is normal use, and it is not evidence of an attack.

- **[DEV-177]** If two verified successors name one `prev_hash` and two different values of
  `signer_id` sign them, a device MUST select one by the order below.
  **[DEV-178]** A device MUST NOT show a fork for that case when the two
  `revoked` lists hold the same entries. A device shows the fork under §7.7 in
  each other case.
  1. The successor whose `revoked` list holds more entries.
  2. If the two lists hold the same count, the lower `signer_id` in byte order.
- **[DEV-179]** A device whose epoch the order did not select MUST publish its claims again
  against the selected epoch.

> *Cause of the first rule of that order.* A hostile device that the user
> revokes at epoch *n+1* can sign a competing epoch *n+1*. A revocation carries
> more tombstones than an ordinary epoch, thus a revocation wins the order.
> DEV-180 also makes each honest device reject a competing epoch that revokes
> that honest device. The residual is a hostile device that revokes one honest
> device and not the other. The two honest devices then disagree, and §7.7
> shows the fork at the next epoch. Part 15 §15.3 records that residual.
> DEV-178 suppresses the fork display only when the two `revoked` lists hold
> the same entries. A suppression for each pair of successors that rule 1 or
> rule 2 orders has a defect. In a set of three devices a hostile device can
> then revoke the two honest devices in two competing epochs. Rule 2 then
> selects one of them in silence at each honest device.

> *The effect on a revoked device.* A revoked device holds its own
> `DeviceRosterKey_i` and the roster chain up to the epoch that revoked it. It
> can sign an epoch that names the epoch before its revocation as the
> predecessor. Rule 2 makes that object a fork and not a successor, thus §7.7
> detects it and names the device. The revoked device cannot sign a successor to
> the revoking epoch, because rule 3 takes the signing authority from the
> `devices` list of that epoch and that list does not hold it.

**The owner claims.** A roster epoch carries the ownership changes that the
epoch makes, and it does not carry the full ownership table. §7.5.4 gives the
ratchet ownership and the group sender ownership.

- **[DEV-158]** A device MUST take the current owner of a subject from the claim of the
  **highest** epoch that names that subject. **[DEV-159]** A device MUST treat a subject that
  no epoch names as owned by the device that established that subject.
- **[DEV-160]** A device that changes the owner of a subject MUST publish
  that change in an `OwnerClaimRecord`. The record below is the one timely
  carrier. DEV-184 forbids a roster epoch for a claim alone, and the next
  device event has no bound.
- **[DEV-161]** A roster epoch MUST NOT carry more than `OWNER_CLAIM_MAX` claims. §7.8 gives
  that value.
- **[DEV-162]** A device MUST NOT name a subject two times in one epoch.
- **[DEV-163]** The provisioning payload of §7.4 MUST carry the current ownership table.
  Thus a new device does not replay the roster chain to build that table.

> *Cause.* §7.5.4 depends on the name of the owner of each subject, thus the
> roster carries a field for that name. A delta of claims keeps
> the roster small at 150 contacts, and a full ownership table in each epoch
> does not.

#### The ownership claim record

A roster epoch carries a claim at a device event, which is an addition or a
revocation. **An ownership change alone does not need a roster epoch.**

```
OwnerClaimRecord {
    version      u8        // 0x01
    roster_epoch u64       // the roster epoch that this record extends
    roster_hash  [32]u8    // SHA3-256 of that roster epoch
    claim_seq    u32       // strictly increasing for each signer, in that epoch
    claim_count  u8        // 1 to OWNER_CLAIM_MAX
    claims       [claim_count]OwnerClaim
    signer_id    [16]u8    // the DeviceId of the signing device
    sig          [3309]u8  // ML-DSA-65, label "umbra/v1/device-claim"
}
```

At `OWNER_CLAIM_MAX` the record is **3 763 bytes**. That total is 62 bytes of
fields, 8 claims at 49 bytes, and a 3 309-byte signature. Part 6 §6.9 gives the
`B2` `L5 payload` row 8 074 bytes, thus the record uses bucket `B2` at 8 240
bytes on the wire. Part 5 §5.11 holds the label.

The signature covers this preimage:

```
"umbra/v1/device-claim" || version || roster_epoch || roster_hash ||
claim_seq || claim_count || claims || signer_id
```

A claim record travels as a device-set control record of §7.5.5, with the
`control_type` value `0x03`.

- **[DEV-183]** A device MUST publish an ownership change in an
  `OwnerClaimRecord`. **[DEV-184]** A device MUST NOT publish a roster epoch
  whose only change is an ownership claim.
- **[DEV-185]** A verifier MUST find `signer_id` in the `devices` list of the
  roster epoch that `roster_epoch` names. **[DEV-186]** A verifier MUST verify
  `sig` against the `mldsa_pk` of that entry. **[DEV-187]** A verifier MUST
  reject a record whose `roster_hash` does not match that epoch.
- **[DEV-188]** A verifier MUST reject a claim record whose `roster_epoch` is
  below the highest roster epoch that the verifier applied.
- **[DEV-189]** A device MUST take the current owner of a subject from the
  record with the highest pair (`roster_epoch`, `claim_seq`) that names that
  subject. **[DEV-190]** If two records hold that same pair, a device MUST
  select the lower `signer_id` in byte order. DEV-158 gives the same fold over a
  roster epoch, and a roster epoch ranks above a claim record at one
  `roster_epoch`.
- **[DEV-191]** A device MUST NOT send more than `OWNER_CLAIM_RATE` claim
  records of scope `0x01` each day. §7.8 gives that value.
  **[DEV-260]** A device MUST count a claim record that holds a claim of scope
  `0x04` under `OWNER_CLAIM_RATE` in the same manner as a record of scope
  `0x01`.
- **[DEV-192]** A device MUST NOT put a claim of scope `0x02` in a record, and
  a verifier MUST reject a record that holds one. **[DEV-234]** A device MUST NOT
  put a claim of scope `0x03` together with a claim of a different scope in
  one record.

**The absence claim.** A claim of scope `0x03` takes each subject that one
absent device owns. The device that publishes it is the claimant.

- **[DEV-230]** A claimant MUST measure an absence from its own receive time
  of the last record from that device. That record arrived on their sync
  channel. **[DEV-231]** A claimant MUST NOT publish a claim of scope
  `0x03` before that absence reaches `OWNER_ABSENCE`. §7.8 gives that value,
  and it is far above `OWNER_TIMEOUT`.
- **[DEV-232]** A device MUST NOT send more than `OWNER_ABSENCE_RATE` claim
  records that hold a claim of scope `0x03`. DEV-191 does not count such a
  record.
- **[DEV-233]** A device MUST apply a claim of scope `0x03` to each subject
  that the absent device owns. The ownership at the point where the fold
  reaches that claim applies. A later claim of scope `0x01` names one subject
  again in the ordinary manner.
- **[DEV-235]** Before a claimant publishes a claim of scope `0x03`, it MUST
  show how many subjects the absent device owns.

> *Cause.* A phone that a user loses owns each ratchet that it established.
> `OWNER_CLAIM_RATE` gives a surviving device 4 records each day at 8 claims
> each. With claims of scope `0x01` alone, the user regains 32 contacts each
> day. At 150 contacts that recovery takes 5 days, and each contact in the
> meantime sees no message from
> the user. One absence claim moves each subject at once. Part 3 §3.12 gives
> the cost of that claim on the day of a loss, and Part 2 §2.4 states the
> trade.

**The retention of a claim.** A device applies a claim once, and it does not
audit the chain later.

- **[DEV-227]** A device MUST fold each claim that it applies into its
  ownership table. For each subject the table holds the owner and the pair
  (`roster_epoch`, `claim_seq`) that named it.
- **[DEV-228]** A device MUST retain the SHA3-256 hash of each roster epoch
  that it applied. §7.7 compares `prev_hash` against those hashes.
  **[DEV-229]** A device MUST NOT retain a signed claim record or a superseded
  roster epoch after the fold. The highest roster epoch stays, because DEV-152
  finds the signer of the next epoch in its `devices` list. The 8 roster
  epochs before the highest one are the one exception. A device MUST keep
  them. A device MUST NOT keep an earlier one. A roster epoch is a control record
  with no counter and no resend (`DEV-271`), and DEV-150 verifies an epoch
  against the epoch before it alone. Thus a device that missed one epoch
  verifies no later one, and the kept epochs are its way back.
  A device sends its highest epoch on each sync channel at the start of
  each run. A device that takes from a peer an epoch below its own
  highest one, equal to the epoch that it applied at that index, MUST send
  that peer each epoch that follows it, in order, when it keeps each of
  them. The peer applies each one under the six rules above. A device that
  is more than 9 epochs behind verifies no epoch again, and the user links
  it again under §7.4.

> *Cause.* §7.5.4 makes a device claim a ratchet ownership after
> `OWNER_TIMEOUT`, which is 90 seconds. A user that moves between a phone and a
> laptop makes that claim often. A `Roster` at `MAX_DEVICES` is 29 625 bytes and
> it uses bucket `B3` at 32 860 bytes on the wire, and a device sends it on each
> of its *d* − 1 sync channels. Thus an ownership change in a roster epoch
> costs a full rewrite of
> the device list. This record costs 8 240 bytes, which is 4.0 times less, and
> Part 3 §3.12 holds the row. A claim record carries no `DeviceEntry`, thus it
> also does not carry 3 225 bytes for each device that did not change.

## 7.4 Linking a device

The link is a one-shot flow, and it is in person or on an authenticated side
channel. The target is 60 seconds or less and one QR scan (usability goal U7).

The new device holds no `RootIdentity` until the link ends, thus it has no
queue and no pairwise channel. The two devices meet on three handle-addressed
chunks of Part 12 §12.4.2. Each one sits under a handle that both devices
derive, and the placement list of the relay set names its relays.

```
  Existing device                          New device
        │                                       │
        │  1. writes the offer (link_pk,        │
        │     an ephemeral UMBRA-KEM key) and   │
        │     displays the ticket as a QR:      │
        │     nonce (16 B), SHA3 of the offer   │──── scan ───▶
        │                                       │
        │                2. reads the offer, checks it against
        │                   the ticket, and writes the hello:
        │                   an encapsulation to link_pk, and
        │                   under a key of its secret the
        │                   device_id, DeviceKey_pk,
        │                   DeviceRosterKey_pk, and label
        │◀── reads the hello ───────────────────│
        │                                       │
        │  3. both devices show a 6-digit code  │
        │     from the shared secret and the    │
        │     transcript — the user confirms    │
        │     that the two codes match ─────────│
        │                                       │
        │  4. signs roster epoch n+1, makes a   │
        │     sync invitation, uploads a        │
        │     snapshot of the store with the    │
        │     roster and the invitation, and    │
        │     writes the sealed provision:      │
        │     the descriptor of the snapshot ──▶│
        │                                       │
        │◀── 5. the sync channel opens ─────────│
```

**The objects.** Part 5 §5.11 holds the five labels.

```
LinkTicket {                     // 49 B, the QR code as "UMBRA-LINK:" and base64url
    version     u8               // 0x01
    nonce       [16]u8           // fresh for each link
    commit      [32]u8           // SHA3-256("umbra/v1/link-offer" || LinkOffer)
}

LinkOffer {                      // 1 217 B, under the offer slot
    version     u8               // 0x01
    link_pk     [1216]u8         // UMBRA-KEM, for this link alone
}

LinkHello {                      // 4 377 B, under the hello slot
    version     u8               // 0x01
    ct          [1120]u8         // UMBRA-KEM.Encap(link_pk), which gives ss
    nonce       [24]u8
    tag         [16]u8
    body        [3216]u8         // sealed under the hello key, XChaCha20-Poly1305:
                                 //   device_id [16]u8
                                 //   device_pk [1216]u8   DeviceKey
                                 //   roster_pk [1952]u8   DeviceRosterKey
                                 //   label     [32]u8     UTF-8, padded with zeros
}

slot(label, secret)  = handle, cred_sk, read_sk
                     = SHA3-256(label || secret || "handle"), and "cred", and "read"
offer slot           = slot("umbra/v1/link-offer", nonce)
hello slot           = slot("umbra/v1/link-hello", nonce)
hello key            = SHA3-256("umbra/v1/link-hello" || ss || nonce || "seal")
transcript           = SHA3-256("umbra/v1/link-transcript" || nonce || LinkOffer || LinkHello)
code                 = BE32(SHA3-256("umbra/v1/link-code" || ss || transcript)[0..4]) mod 1 000 000
provision slot       = slot("umbra/v1/link-provision", ss || transcript)
seal key             = SHA3-256("umbra/v1/link-provision" || ss || transcript || "seal")

Provision {                      // sealed under the seal key, XChaCha20-Poly1305
    version     u8               // 0x01
    from_device [16]u8           // the device_id of the existing device
    snapshot    u32 length, bytes      // a FileDescriptor of Part 12 §12.3
}
```

**Requirements:**

- The confirmation code (step 3) is **mandatory**. Without that code, a QR
  code on an observed or relayed screen is a device-linking attack.
- **[DEV-280]** The existing device MUST write the offer under the offer
  slot before it shows the ticket, and the ticket MUST carry the hash of that
  offer. **[DEV-281]** The new device MUST reject an offer whose hash differs
  from the ticket, and it MUST write its hello under the hello slot.
- **[DEV-282]** Each device MUST derive the hello key, the transcript, the
  code, the provision slot, and the seal key as above. **[DEV-288]** The new
  device MUST seal the four fields of the body of its hello under the hello
  key, and the existing device MUST reject a hello whose body does not open.
  A relay that holds the hello thus reads no key and no label. **[DEV-283]** The two devices
  MUST show the code of step 3, and the existing device MUST NOT write the
  provision before the user confirms on it that the two codes match.
- **[DEV-002]** The existing device MUST write the provision under the
  provision slot and under no other handle. **[DEV-003]** The existing device
  MUST erase the offer when it reads the hello, or at `LINK_QR_TTL` after the
  offer, whichever comes first. It MUST erase the provision and the chunks of
  the snapshot when the sync channel opens, or at `LINK_PROVISION_TTL` after
  the provision, whichever comes first. The new device MUST erase its hello
  when it reads the provision.
- **[DEV-004]** The snapshot MUST be a full backup object of Part 4 §4.7.2
  under a fresh file key. Thus it carries the **local identity table** of
  Part 4 §4.7.2, and without that table the new device cannot sign a granting
  epoch (Part 11 §11.9.1). **[DEV-289]** The snapshot MUST also carry the
  roster of epoch *n+1*, the bundle of the sync invitation, and the
  `device_id` and the label of the existing device as the peer of that
  channel. It MUST NOT carry a record that waits to go, since the sender of
  that record is the existing device. **[DEV-311]** The snapshot MUST carry
  the causal counter of the existing device at the confirmation of
  `DEV-283`, and the new device MUST start the contiguous point of `DEV-055`
  for that peer at that counter. Each record after it waits for the new
  device under `DEV-297`, and a second link otherwise leaves a hole of each
  earlier record. **[DEV-295]** It MUST NOT carry the
  recovery code of Part 4 §4.7.1. That code opens each later backup, thus a
  device that the user removes under §7.7 would read the history that
  follows its removal. The device that owns the channels writes the backups
  and keeps the code. The provision thus stays one chunk at
  `MAX_DEVICES`.
- **[DEV-284]** The new device MUST make its store from the root seed of the
  snapshot and take each row of it, as a restore does, and it MUST keep its
  own `DeviceKey`, `DeviceRosterKey`, and `device_id`.
- **[DEV-285]** A device that holds no roster MUST sign epoch 0 with itself
  alone before it offers its first link. Epoch *n+1* then adds the new device.
- **[DEV-286]** The existing device MUST put the bundle of a new invitation
  in the snapshot, and the new device MUST accept it at its first run. The channel of
  that invitation is the sync channel of the two devices (§7.5). Neither
  device shows it as a contact.
- **[DEV-287]** The existing device keeps the ownership of each pairwise
  ratchet and of each group sender at the link. The new device owns nothing
  until a claim of §7.3.1 or §7.5.4. Until then it MUST NOT read the queue of
  a contact, send a group record, or write a backup of Part 4 §4.7.2: each
  queue has one reader, and the backup root of a week has one writer.
  The v1 client publishes no claim and applies none. Thus the
  device that owns the channels at the first link owns them for the life of
  the set. That device alone signs an epoch that adds or revokes a device. **A
  set whose owning device is lost or seized thus cannot revoke that device,
  cannot link a device, and sends and reads nothing more.** The other
  devices keep the history that they hold. The user recovers through the
  restore of Part 4 §4.7 on a new device, with the Recovery Code that the
  owning device held and that the user wrote down (`DEV-295`). That new
  device starts a new set. Part 4 §4.7 gives what a restore renews at the
  contacts of the user. A user with no Recovery Code recovers nothing of
  the set. Steps 1 and 3 of §7.7 and the absence claim of §7.3.1 describe
  the path that a later version builds. They are not a property of
  v1.
- **[DEV-290]** The existing device MUST keep the roster of epoch *n+1* only
  when the sync channel of the new device opens. A link that ends before
  that leaves epoch *n* in force. A link that the user cancels, or that
  expires, after the confirmation of `DEV-283` MUST retire the sync
  invitation of `DEV-286` at once. The existing device erases the one-time
  prekey and the handshake state of that invitation, and it sends the `DEL`
  of its queue. An invitation whose queue no relay made yet ends when the
  relay made it, and no party gets its bundle. The existing device also
  removes the pending device from its store. The existing device MUST
  refuse a contact whose handshake names it a device while the existing
  device holds no pending device. The channel of that contact ends as the
  channel of a revoked device ends. No
  view shows it, no record goes on it, and no later run reads its queue.
  **Limit of v1.** The existing device holds the list of its
  sync invitations in the memory of one run. The existing device does not
  retire an invitation of a link that ended with its run, or while the
  client was locked. That invitation
  stays until `INVITE_TTL` of Part 4 ends it (`IDN-127`). The refusal above
  covers that time, because the pending device leaves the store at the end
  of the link, or at the next unlock. **[DEV-297]** From the confirmation of
  `DEV-283`, the existing device MUST retain each record that it publishes
  for the new device, and it MUST send each one when that sync channel
  opens, under the pacing of §7.5.5. A record between the snapshot and the
  channel is otherwise lost to the new device.
- **[DEV-291]** A backup of Part 4 §4.7.2 MUST NOT carry a row of the device
  set or a row of a sync channel. A restored device is a new device, and it
  links again.
- **[DEV-165]** The new device MUST make its own `DeviceKey` and its own `DeviceRosterKey`
  before step 2. **[DEV-168]** The new device MUST send the public half of the two keypairs
  in its hello. **[DEV-166]** The existing device MUST
  put those public halves in the `DeviceEntry` of epoch *n+1*. **[DEV-167]** The
  provision MUST NOT carry a `DeviceRosterKey` private half. §7.3
  gives the cause.
- **[DEV-005]** The link QR code MUST expire after 120 seconds. **[DEV-006]** The
  link QR code MUST operate one time only.
- **[DEV-007]** A device that has a provision MUST refuse a link into a second device set. **[DEV-008]** The
  client MUST make the user do an explicit local wipe before a second link.
- **The web client.** Part 1 §1.1 defers the web client, and the four
  rules below bind it when it ships. **[DEV-264]** A web client of Part 14 §14.7 MUST link
  as a device of this section, and it MUST NOT make a `RootIdentity`.
  **[DEV-265]** When a web client returns to this flow after it lost its
  store, the existing device MUST revoke the old entry under §7.7 before step
  5. **[DEV-266]** The new device MAY show the QR code of step 1 in the place
  of the existing device. The two devices then swap the offer and the `ct`
  of the hello, and the new device writes the body of its hello, sealed as
  above, under a slot of the secret. The code of step 3 shows on both
  devices as before. **[DEV-267]** In that
  direction the existing device MUST show the label of the new device, and it
  MUST get an explicit confirmation from the user, before step 4.

> *Cause of the sealed hello and of the rows of the snapshot.* A hello with
> its fields in the clear lets a relay that holds it read the label of the
> device. A provision that holds the roster and the sync bundle does not fit
> one chunk: at eight devices the roster alone is near 29 KB.

> *Cause of the handle-addressed chunks.* The alternative is a
> handshake over an ephemeral queue. The new device holds no root identity
> before the provision, and each queue of the reference client hangs off one.
> A handle-addressed chunk needs no identity, the restore of Part 4 §4.7.2
> already reads one, and the code of `DEV-283` gives the same protection as
> the handshake transcript: a party that read the QR code and wrote the
> hello first shows a code that differs from the screen of the new device.

> *Cause.* A browser has no camera that a user trusts for a scan, and a phone
> has one. A QR code that the new device shows moves the scan to the phone.
> That direction is the one that a device-linking attack uses, because a page
> can show such a code to a victim. The code of step 3 and the confirmation of
> `DEV-267` name the device on the phone before any secret moves, thus the
> user sees what the scan links.

## 7.5 History sync

### 7.5.1 The sync channel

The devices in a set communicate over **dedicated sync queues**. Those queues
use the same relay fabric as the other traffic. A link of §7.4 opens one sync
channel, between the device that owns the channels and the new device, and
only the device that owns the channels starts a link. A set of *d* devices
thus has *d−1* sync channels, in a star around that device.
**[DEV-308]** The device that owns the channels MUST publish again, to each
of its peers, each `SyncedRecord` and each `MutableItem` that it takes from
one peer, the source included, since each peer takes each counter of the
publisher (`DEV-055`). A device MUST treat as a peer only a device with a
sync channel to it. A device that takes, from the device that owns the
channels, a `SyncedRecord` equal in `scope`, `subject`, `author`, and `inner`
to one that it published and still retains MUST drop it.

> *Cause.* A full mesh needs *d(d−1)/2* channels, and the link of §7.4
> opens one. Without the relay of `DEV-308`, a record that a linked device
> composes reaches the owner alone. Each other linked device does not read it,
> and the log of the
> composing device keeps it for each peer that it cannot reach. The owner
> reads each channel already, thus its relay costs one publish for each
> record, and a new link needs no channel of its own to each other device.

**[DEV-009]** A client MUST NOT add a device to a device set that already holds `MAX_DEVICES`
devices. **[DEV-010]** A client MUST reject a roster that names more than `MAX_DEVICES`
devices. §7.8 sets `MAX_DEVICES` to 8. That cap keeps *d* small, and it bounds
the fan-out of the relay. The owner of the channels relays, and a claim of
§7.3.1 moves that duty with the channels.

The sync traffic has these properties:

- A full UMBRA ratchet encrypts it, in the same manner as contact traffic. **The
  codebase holds one ratchet implementation.** Sync is not a special case.
- The client pads it to the same bucket ladder, and paces it from the same cover
  clock. Thus a relay cannot tell sync traffic from contact traffic.
- **An interactive record is the one exception to that pacing.** An interactive
  record is a record that a user action waits on. §7.5.4 gives the one such
  record, which is the plaintext that a composing device gives to the ratchet
  owner.

  **[DEV-193]** A client MUST send an interactive sync record at the first
  opportunity. **[DEV-194]** A client MUST NOT hold an interactive sync record
  for a cover slot. **[DEV-195]** A client MUST bound the interactive sync
  records on one channel by a token bucket. The bucket holds
  `SYNC_INTERACTIVE_BURST` tokens, and it refills at `SYNC_INTERACTIVE_RATE`.
  **[DEV-196]** A
  client MUST NOT mark a record interactive when no user action waits on it.
  **[DEV-241]** While the bucket is empty, a client MUST show the message as
  waiting for the pacing clock.

  > *Cause.* Part 3 §3.6.2 gives the cover clock a mean of 20 seconds in the
  > foreground. Under the pacing rule alone, a message that a user types on a
  > laptop waits a mean of 20 seconds before the phone can send it. U2 of
  > Part 2 §2.4 gives a p50 of 2.0 seconds. A flat limit of 4 records each
  > minute is the alternative to the bucket. A user that sends 5 short lines
  > in a row then sees the fifth line
  > wait, with no statement of the cause. The bucket lets
  > a burst of 12 through, and the mean rate stays at 4 each minute.
  >
  > *What the exception shows.* An interactive sync record is a `B1` cell that
  > follows a user action. An ordinary send from the ratchet owner is also a
  > `B1` cell that follows a user action, and Part 3 §3.9 gives no send batching
  > in any mode. Thus an ingress relay reads one shape for the two cases, and
  > the exception adds no signal that a send does not already carry.
- No sync traffic moves through a distinguished "sync relay". Sync queues obey
  the same operator-disjointness rules as the other traffic.
- The sync channel carries each new entry of the **local identity table** of
  Part 4 §4.7.2. **[DEV-011]** Each device of one user MUST hold the same table. **[DEV-012]** The retention
  limits of §7.5.2 MUST NOT remove an entry from that table.

> A sync queue is a transport, and it is not the durable log of the device set.
> The durable log is the local database of each device. Part 3 §3.2.4 bounds a
> queue at `QUEUE_QUOTA`, at `MSG_TTL`, and at `QUEUE_IDLE_TTL`. **[DEV-013]** Thus a device
> MUST NOT depend on relay retention for convergence.

**The ceiling of the sync channel, and the catch-up object.** Part 3 §3.12
gives a device 360 tier A cover slots in its 2-hour foreground day. That
section gives the model user 278 records each day. The pacing rule above puts
the sync copy of each record in a cover slot. Thus one channel drains a
backlog at about 82 records each day above the live traffic. A peer that was
absent for 7 days holds a backlog of 1 946 records, and the channel needs
about 24 days to drain it. The catch-up object removes that wait.

- **[DEV-236]** If the acknowledged counter of a peer lags by more than
  `SYNC_CATCHUP_LAG`, the device MUST make a catch-up object. The object holds
  each retained record above that counter, and §7.8 gives the value. The
  object is each retained body in the order of its counter, each as
  `BE32(len) || body`, where `body` is the sync record as the channel
  carries it.
- **[DEV-237]** A device MUST write the object on the chunk path of Part 12
  §12.3.3 over the connection of Part 12 §12.8. Part 4 §4.7.2 carries the
  backup on that path in the same manner.
- **[DEV-238]** A device MUST send the `FileDescriptor` of that object in a
  `DeviceSetControl` of `control_type` `0x04`. §7.5.5 gives that record, and
  it travels on the sync channel.
- **[DEV-239]** A peer MUST apply each record of the object in causal order,
  and then acknowledge under §7.5.5. Each record counts as if it arrived on
  the sync channel. **[DEV-240]** A device MUST continue the resend of §7.5.5
  rule 3 for each record that the peer did not acknowledge. Part 6 rule
  `WIR-065` discards a record that arrives two times.

> *Cause.* A relay reads the object as an attachment of the size that the
> backlog gives. Part 3 §3.12 gives that size for the 7-day case, which is 21
> chunks at `B3`. Part 2 §2.4 states the trade.

### 7.5.2 Sync scope and retention

Each device declares a scope at the link:

| Scope | Receives | Typical use |
| --- | --- | --- |
| `full` | All the history in the retention window | Primary phone |
| `recent` | The last 30 days | Laptop |
| `live` | Only the messages that arrive after the link | Shared or higher-risk device |

`live` is the default for a device that a user links more than 7 days after the
creation of the device set. The cause is that a device added later is more
probably a secondary device.

The retention on a device has two limits. `SYNC_MAX_AGE` has a default of 365
days, the user can configure it, and its minimum is 1 day. `SYNC_MAX_BYTES` has
a default of 2 GiB. Each device enforces the two limits independently.

**A tombstone is exempt from `SYNC_MAX_BYTES`.** **[DEV-014]** A device MUST retain a
tombstone at least as long as that device retains a message that predates that
tombstone.

> *Cause.* Each device enforces the two limits alone, and the user can set
> `SYNC_MAX_AGE` down to one day. Without this exemption a device drops a
> tombstone and keeps the target. The §7.5.3 statement that a device which syncs
> late cannot restore a deleted message then does not hold.

Each device holds a **source watermark** for each source device. The watermark
is one causal counter, it is local state, and it never travels on the wire.

- A device removes each record from source device `D` at or below causal counter
  `c`. **[DEV-015]** That device MUST then set the watermark of `D` to `c`. `SYNC_MAX_AGE` and
  `SYNC_MAX_BYTES` each cause such a removal.
- **[DEV-016]** A device MUST NOT advance a watermark past a counter for which it still holds
  a record.
- **[DEV-017]** A device with the `live` scope MUST set the watermark of each source device.
  **[DEV-018]** That device MUST set each watermark to the current counter of that source at
  the link. Thus a `live` device receives no history.
- **[DEV-019]** A restore MUST carry the watermark of each source device. That restore comes
  from a Part 4 §4.7.2 backup or from a §7.6.1 archive. Without those watermarks
  a restored device accepts an insertion that it has to reject.

`SYNC_MAX_AGE` has a minimum of 1 day. At a value near that minimum a device
advances its watermarks each day. That device then rejects each sibling record
that is older than that value, and it converges on a short window only. **[DEV-020]** The
interface MUST state that trade at the point where the user sets the value.

### 7.5.3 Ordering and conflict resolution

A sync message carries a **causal context**. That context is a compact version
vector over the device IDs, together with a Lamport counter. For a record
under a live conversation timer the context also carries `expires_in`, and
§7.5.8 gives that field. The three layouts below carry it.

```
CausalContext {
    version       u8          // 0x01
    lamport       u64         // the Lamport counter of the sender at the send
    device_count  u8          // 0 to MAX_DEVICES
    vector        [device_count]VectorEntry   // device_id ascending, no repeat
    expires_in    u32         // seconds, or 0 (§7.5.8)
}

VectorEntry {                 // 24 bytes
    device_id     [16]u8
    counter       u64         // the causal counter of that device the sender has seen
}

SyncedRecord {                // the body of kind 0x20 at sub-kind 0x03
    sub_kind      u8          // 0x03
    context       CausalContext
    scope         u8          // 0x01 a pairwise conversation
    subject       [32]u8      // the blinded subject of DEV-226 that names it
    author        u8          // 0x00 the user, 0x01 the other party
    inner_len     u32
    inner         [inner_len]u8   // one AppMessage of Part 6 §6.6
}

MutableItem {                 // the body of kind 0x20 at sub-kind 0x01
    sub_kind      u8          // 0x01
    context       CausalContext
    writer        [16]u8      // the device_id of the device that wrote the value
    item          u8          // the row of the mutable-state table below, from 1
    key_len       u16
    key           [key_len]u8     // the scope of the row: a conversation, a contact,
                                  // an identity, or a message
    value_len     u16
    value         [value_len]u8
}
```

- **[DEV-268]** A device MUST carry a conversation record on a sync channel
  as a `SyncedRecord`, and it MUST take the class of that record from the
  kind of `inner`. **[DEV-269]** A parser MUST reject a `vector` that is not
  in strictly increasing `device_id` order, or that holds more than
  `MAX_DEVICES` entries. **[DEV-292]** A device MUST name the conversation
  of a `SyncedRecord` by `scope` and `subject`. For scope `0x01` the subject
  is the one of `DEV-226` for the pairwise identity of that conversation,
  thus each device of the set derives it and no party outside the set can.
  A device MUST set `author` to `0x00` for a record that the user wrote on a
  device of the set, and to `0x01` for a record of the other party. A parser
  MUST reject a scope other than `0x01` and `0x02`, and another author. A receiver MUST apply the
  record in the conversation that the subject names, in the direction that
  `author` gives. **[DEV-293]** The device that owns a pairwise ratchet MUST
  publish each record that it takes from the contact, and each record of
  the user that it sends but one that a peer handed to it. A device that
  does not own the ratchet MUST publish each record that the user composes
  on it, and the owner then sends that record under `DEV-047` and
  `DEV-048`. **[DEV-296]** For scope `0x02` the conversation is a private
  group of Part 11, and `subject = SHA3-256(K_set || 0x02 || group_id)`. A
  group record carries no tag for the index of its sender, thus no other
  device of the member reads that record on the group queue. The device that
  posts a record of the member MUST publish it, a roster object included,
  and a device that takes it MUST apply a roster object to its roster and
  keep each other record as one of the user. Each device reads the records
  of the other members on its own subscription (Part 11 `GRP-343`).
  **[DEV-270]** A device MUST apply a `MutableItem`
  when its `lamport` is above the value held, or equal with a lower
  `writer`, and it MUST discard it otherwise. A device MUST set `writer` to
  its own `device_id` in each item that it writes, and a relay of `DEV-308`
  MUST keep the `lamport` and the `writer` of the item that it carries.
  **[DEV-310]** A device MAY forget the winner of a delivery item once it
  holds more than 65 536 of them, the oldest by `lamport` first, and it
  keeps the winner of each item of another table. The delivery state of
  each message is an item, thus the set grows with each message; an item
  that arrives after its winner went can then win again, and each item of
  that table converges forward in any case.

> *Cause.* Two implementations can exchange a sync record only when the
> context and each sub-kind have a layout. The three layouts above are the
> one carrier of each. Without a conversation and an author in the synced
> record, a receiver cannot tell where a record goes, or whether the user
> wrote it.

**The counters of a context.**

- **[DEV-271]** A device MUST give each `SyncedRecord` and each `MutableItem`
  that it sends the next value of its causal counter, which starts at 1. It
  MUST give a `DeviceSetControl` no counter. **[DEV-272]** The `vector` MUST
  hold the entry of the sender, and the `counter` of that entry is the causal
  counter of the record. **[DEV-273]** A receiver MUST reject a record whose
  `vector` holds no entry of the device that the sync channel names.
- **[DEV-274]** The entry of each other device MUST carry the acknowledgment
  point of `DEV-055` that the sender holds for that device.
- **[DEV-275]** A device MUST add one to its `lamport` before each send of a
  counted record. At the receipt of a counted record, it MUST set its
  `lamport` to the higher of its own value and the value of the record. A
  device MUST reject a counted record whose `lamport` is more than 2³² above
  its own value. It takes neither the counter nor the content of that
  record, and its own `lamport` stays. That bound is relative to the
  receiver. The device that owns the channels can take two records in turn
  that are each inside the bound. Its value is then more than 2³² above
  a device that saw neither. A device that it links later starts at zero,
  and a device that was behind stays behind. Thus the bound holds at the
  device that owns the channels, for each record of each other device.
  A device that owns no channel MUST take a counted record of the device
  that owns them at any `lamport`. Its own `lamport` starts again from that
  value. Each record of the set reaches such a device through the owner of
  the channels (`DEV-308`), which applied the bound to each write that it
  took. A new device takes its first `lamport` in this way, from the first
  record of the device that linked it. A device MUST NOT let its `lamport`
  stop at its last value, and it sends no counted record when the next
  value does not exist. A `lamport` counts the writes of a set, and no set
  writes 2³² records between two syncs of one device. Without the bound,
  one record of one device with the last value of the field gives that
  value to each device. Each later write of the set carries it, and
  `DEV-270` then orders by the writer alone for the life of the set.
- **[DEV-276]** A device MUST reject a `SyncAck` whose `counter` is above its
  own causal counter, because no record holds that counter.
- **[DEV-277]** A device MUST retain a `MutableItem` for the resend of §7.5.5
  under a reference to its row and its key, and not under its bytes. A resend
  MUST carry the value that the device holds at the resend. The last writer
  wins under `DEV-270`, thus an older value would lose at the peer in any
  case.

> *Cause.* §7.5.5 acknowledges a causal counter, thus a record has to carry
> its own counter, and a rule has to name the records that take one. The
> entry of the sender in the vector is that place, and it costs no field.

Each kind of Part 6 §6.6 is in exactly one class. **[DEV-021]** A new kind MUST declare its
class in Part 6 §6.6. **[DEV-022]** A client MUST NOT process a kind that declares no class.

| Class | Kinds | Rule |
| --- | --- | --- |
| Insertion | `0x01`, `0x02`, `0x03`, `0x0A`, `0x0B`, `0x0C` | Commutative |
| Revision | `0x04` | The sender-chain position gives the order |
| Tombstone | `0x05` | Terminal |
| Peer signal | `0x06`, `0x07` | Part 3 §3.5.4 gives the rules. **[DEV-023]** A client MUST NOT put a peer signal on a sync channel |
| Mutable state | `0x20` sub-kind `0x01` | The last writer wins, under `DEV-270` |
| Ephemeral | `0x08` | The client does not store it |
| Control | `0x0D`, `0x10`, `0x20` sub-kind `0x02`, `0x30`, `0x31`, `0x32`, `0x33`, `0x34`, `0x35` | Part 4 §4.7.3 gives `0x0D`. Part 11 gives `0x10`. §7.5.5 gives `0x20` sub-kind `0x02`, which is the sync acknowledgment. Part 4 §4.5.1 gives `0x30`. Part 9 §9.5.3 gives `0x31`. §7.5.8 gives `0x32`. Part 6 §6.6.10 gives `0x33`. Part 6 §6.6.11 gives `0x34` and `0x35` |
| Wrapper | `0x09`, and `0x20` sub-kind `0x03` | Part 6 §6.6.5 gives the rich record, and `DEV-268` gives the synced record. Kind `0x12` of Part 6 §6.6.2 is retired; a group content record is the `app` of a group record of Part 11 §11.3, and its own kind gives its class. **[DEV-174]** A client MUST take the class from `inner_kind`. **[DEV-175]** A client MUST NOT give a wrapper a class of its own |

- **Insertion** is commutative. **[DEV-024]** A client MUST identify each message by the
  triple (conversation, sender, `msg_ref`) of Part 6 §6.6. **[DEV-025]** A client MUST remove
  a duplicate by that triple. **[DEV-026]** A client MUST NOT use a hash of ciphertext
  bytes for one of three functions. Those three functions are an identifier, a
  deduplication key, and an order tiebreak. Part 6 §6.1.1 rule 5 gives that
  prohibition.
- **[DEV-027]** A receiver MUST resolve a target only inside the conversation that carried the
  naming record. **[DEV-028]** A receiver MUST resolve a target only against the messages of
  the sender that the L6 QueueE2E key names. **[DEV-029]** A receiver MUST NOT search a
  different conversation. **[DEV-030]** A receiver MUST NOT change a record before it
  completes this check.
- The order of two records from **one sender** comes from the sender-chain
  position. For a group that position is the lexicographic pair (`epoch`,
  `counter`) of Part 11 §11.7, and for a pairwise conversation it is the
  ratchet position of Part 6 §6.5. The order of two records from **two different senders**
  comes from the local insertion sequence. That sequence belongs to the device
  that first put the record in the synced history. If those two rules do not
  resolve two records, the byte order of `msg_ref` applies. **[DEV-031]** A client MUST NOT use
  a wall clock for the order. **[DEV-032]** A client MUST NOT use `sent_at` for
  the order.
- **A revision** is kind `0x04`. **[DEV-033]** A client MUST order a revision by the
  sender-chain position of the author. **[DEV-034]** A client MUST keep a high-water mark of
  the applied position for each target. **[DEV-035]** A client MUST discard a revision at or
  below that mark. **[DEV-036]** A message body is not mutable state, thus last-writer-wins
  MUST NOT apply to a message body.
- **A tombstone** is kind `0x05`, and no other kind makes a tombstone. A
  tombstone wins against an insertion and against a revision at each position.
  §7.5.2 gives the watermark of source device `D`. **[DEV-037]** A device MUST reject an
  insertion from `D` whose causal counter is at or below that watermark. Thus a
  device that syncs late cannot restore a deleted message, and it cannot restore
  a pruned message. **[DEV-038]** A device MAY remove a tombstone after the watermark passes
  the counter of the target.
  - The device can hold a record of having held or pruned that range. That
    rejection is then the normal case. **[DEV-039]** In that case the client MUST NOT show the
    rejection.
  - If the device never held that range, the rejection is a **history gap**. **[DEV-040]** The
    client MUST then show that gap under §7.5.5 rule 7.
- **Mutable state** uses last-writer-wins by causal context, with the device ID
  as the tiebreak. The mutable state holds the items below.

  | Item | Scope |
  | --- | --- |
  | The read marker | Each conversation |
  | The mute, and the notification setting of §7.5.9 | Each conversation |
  | The contact name, which is the petname of Part 9 §9.8 | Each contact |
  | The pet-avatar of Part 9 §9.8 | Each contact |
  | The verification state of Part 4 §4.5 | Each pairwise identity |
  | The delivery state and the read state | Each message |
  | The local insertion sequence of Part 11 §11.7 | Each conversation |
  | The group `counter` of the group sender owner, Part 11 §11.3.4 and §7.5.4 | Each group |
  | The block state of Part 13 §13.12 | Each contact, and each member of a group under its index |
  | The archive flag, the pin flag, and the folder label | Each conversation |
  | The unread marker that a user sets by hand | Each conversation |
  | The draft text | Each conversation |
  | An entry of the local identity table of Part 4 §4.7.2 | Each pairwise identity |
  | The state of a group that the device that owns the channels made or joined after a link | Each group |
  | The re-key of the member in a group after a removal | Each group |

  **[DEV-197]** A client MUST converge each item of that table across the device
  set. **[DEV-294]** The item of an entry of the local identity table takes
  the subject of `DEV-226` as its key. Its value for a pairwise identity is
  49 bytes: `0x01`, the salt of Part 4 §4.2.2, and the 32-byte key of the
  conversation in the stores of the set. A device MUST publish that item
  when it makes a contact. A receiver MUST reject an item whose subject the
  salt does not give, and it MUST otherwise hold the conversation from
  then on, whether or not it owns the channel. The device that owns the
  channels MUST publish, at the start of each run, the item of each contact
  that its engine does not hold, and a receiver MUST hold a synced record
  whose subject names no conversation until the item comes. **[DEV-198]** A later version that adds a chat-list item MUST add a row.

  **[DEV-304]** The device that owns the channels MUST publish the delivery
  state of each message that it sent when that state becomes delivered,
  read, or failed. The item takes the row of the message in the stores of
  the set as its key, and one byte of the state as its value. A receiver
  MUST move the state of its copy up only, and it MUST take a failure for a
  copy that no receipt reached. A message that another device handed to
  the owner thus shows its receipts on the device that composed it.

  **[DEV-298]** The device that owns the channels MUST publish the state of
  each group that it makes or joins while the set holds another device, when
  the group holds its two replicas. The item takes the group subject of
  `DEV-296` as its key, and its value is the descriptor of one backup object
  of Part 4 §4.7.2 on the chunk path. That object holds the row of the group,
  its seeds, its conversation row, and each row that the group owns, and no
  queue job of the creator. **[DEV-299]** A receiver MUST reject an object
  with a row of another group, or a group whose subject is not the key of
  the item. A receiver that holds the group MUST keep its own row, since its
  cursors are its own (`DEV-261`). A receiver that lacks the group MUST keep
  each synced record of it, and it MUST apply them in their order when the
  state arrives.
  **[DEV-300]** After the re-key of a removal (Part 11 `GRP-345`), the device
  that owns the channels MUST publish, for each group, the new seed and the
  re-key object under the group subject. **[DEV-301]** Each other device MUST
  apply that re-key to its own row of the group, and it MUST keep the seed
  before it for the grace of Part 11 `GRP-372`. **[DEV-309]** A device that
  does not hold the group yet, or whose roster does not reach the roster
  epoch before the re-key, MUST keep the item and apply it again after each
  group state and each roster object that it takes, for 7 days at the most.
  The group state comes on the chunk path and the roster object on the sync
  channel, and either one can come after the item.
  **[DEV-302]** An existing device MUST NOT start a second link while the
  sync channel of the last one has not opened, since the new device of that
  link takes its handshake then.
  **[DEV-303]** A device that does not own the channels MUST keep an
  epoch-key record of the next epoch that does not install, and it MUST try
  it again after each roster object of the member that it applies. That roster
  object comes on the sync channel, and the key comes on the group queue, and
  either one can come first (Part 11 `GRP-357`).

  **One item of group state does not converge.** Each device reads a group
  queue on its own circuit, and it holds its own cursor for each replica of
  that queue (Part 11 §11.2.2). **[DEV-261]** A client MUST hold the
  group-queue cursor of each replica as per-device state, and it MUST NOT put
  that cursor on a sync channel. A device that learns the cursor of a peer
  device gains nothing, because the `seq` of a replica is relay-local, and the
  `msg_id` rule of Part 6 §6.6 removes a duplicate that two cursors give.

  > **The draft is the one item that carries content.** A draft is unsent text,
  > thus a peer device holds a message that no party sent. **[DEV-199]** A
  > client MUST hold a draft under the record encryption of Part 14 §14.6.4.
  > **[DEV-200]** A client MUST NOT put a draft in the backup of Part 4 §4.7.2.
  > **[DEV-201]** A client MUST erase a draft from the device set when the user
  > sends it or clears it. **[DEV-202]** A client MUST let the user turn the
  > draft sync off, and Part 15 §15.3 records the residual.
- **An ephemeral record** is kind `0x08`. **[DEV-041]** A client MUST NOT store it.
  **[DEV-042]** A client MUST NOT put it on a sync channel.
- **A control record** is not a conversation record. **[DEV-043]** A client MUST NOT put a
  control record in one of the other classes.

**The routing of a deletion.** A deletion for the devices of one user travels as
kind `0x05` with the scope byte `0x01`, on a sync channel of §7.5.1. A deletion
for the other party travels as kind `0x05` with the scope byte `0x02`, on a
pairwise channel. Part 6 §6.6 gives the scope byte. **[DEV-044]** A client MUST NOT put a
deletion inside kind `0x20`. **[DEV-045]** A receiver MUST reject a kind `0x05` record whose
scope byte does not match the channel that carried it.

> *Cause.* GitHub Security Lab reported GHSL-2026-082 and GHSL-2026-095 in March
> 2026. A lookup by author and send time carried no conversation scope. An
> administrator of one group then deleted a message in a different group. In the
> second report the destructive step ran before the authorization check, and the
> failed check did not roll the transaction back.

This design has the shape of a CRDT, and it is deliberate. There is no consensus
and no leader. A device that returns after an absence converges through the
retransmission of §7.5.5. That convergence reaches each record that at least one
peer device still holds, and `SYNC_MAX_AGE` bounds that set. The default of
`SYNC_MAX_AGE` is 365 days. **[DEV-046]** If no peer holds a range, the device MUST show a
history gap for that range.

> **The trade, stated.** The relay queue does not carry the convergence. The
> sending device carries it. If a source device is lost and no peer holds a
> range, that range is gone. UMBRA states that limit, and UMBRA does not claim a
> recovery path that it does not build.

### 7.5.4 The ratchet-fork problem

Multi-device operation has one hard problem. Two devices can hold the pairwise
ratchet state for the contact *c*. If the two devices send, the ratchet forks.

**The UMBRA resolution: one device owns each pairwise ratchet at a time.**

- The roster chain names a **ratchet owner** device for each pairwise identity.
  §7.3.1 gives the `OwnerClaim` record and the fold that gives the current
  owner. A claim of scope `0x01` names a pairwise identity, and its `subject` is
  the SHA3-256 of the pairwise identity public key.
- Only the owner advances the ratchet with the contact. A different device
  gives the plaintext to the owner over the sync channel. The owner then
  encrypts the message and sends it.
- **[DEV-047]** The composing device MUST draw `msg_id` before it gives the plaintext to the
  owner. **[DEV-048]** The ratchet owner MUST NOT draw a new `msg_id`. Thus a device that does
  not own the ratchet names its own message, and it can edit or delete that
  message later.
- The owner can become unreachable for `OWNER_TIMEOUT`, which has a default of
  90 seconds. **[DEV-049]** A device MAY then claim the ownership with a
  broadcast of an `OwnerClaimRecord` of §7.3.1. The pair (`roster_epoch`,
  `claim_seq`) gives the order of the claims, and the device ID breaks a tie.
  **[DEV-169]** A device MUST NOT claim the ownership of a
  subject before `OWNER_TIMEOUT` passes. The v1 client builds
  no claim, and `DEV-287` states what follows from that.
- At a change of the ownership, the new owner takes the **next DH ratchet
  step of the channel**. That is the step of Part 5 §5.5 that follows the next record
  of the peer under a new ratchet key. A sender cannot step alone, because the
  peer derives each receiving chain from its own newest ratchet key, which the
  sender holds only after that record. Thus a stale former owner decrypts no
  traffic after that step. It decrypts the records of the peer before the
  step only when it also reads their queue, which the queue rotation of §7.7
  step 2c ends.

**The group sender owner.** A group has no ratchet, and a group record carries
a per-sender `counter` that Part 11 §11.3.4 keeps strictly increasing in each
epoch. Thus the same resolution applies: one device, the **group sender owner**
of Part 11 §11.12, posts each group record for every group of the user, and a
claim of scope `0x04` of §7.3.1 names it with one subject for all groups. A
device that is not the owner composes and hands the plaintext to the owner as an
interactive sync record, in the same manner as a pairwise send, and DEV-047,
DEV-048, and DEV-193 to DEV-196 apply. The `counter` of each group is mutable
state of §7.5.3, and the new owner continues it from the synced value; a
collision that a race causes is a reorder at each receiver and not a security
event (Part 11 §11.3.5). Every device of the set reads each group on its own
circuit with its own cursor, and DEV-261 gives that cursor.

**What this design costs a send from a device that is not the owner.** The
composing device sends an interactive sync record under DEV-193, thus it adds no
pacing wait. The owner device then takes that record and sends the message. If
the owner is in the background, the owner takes the record at its next push
wake, and Part 8 §8.3 gives that wake latency. Part 2 §2.4 U2 states the target
for this path, which is a p50 of 6 s and a p95 of 20 s in Instant mode.

**That target covers an unlocked owner.** Part 14 rule `IMP-119` locks a
client after 15 minutes with no action of the user. A locked client
holds no key and runs no network (Part 14 rule `IMP-127`). A push wake of a
locked owner shows which conversation waits (Part 8 rule `NTF-136`), and it
takes no record. Thus a locked owner sends nothing for another device, reads
no pairwise queue, and publishes no sync record again under `DEV-308`.
Each other device of the set waits for the unlock of that owner. The claim of `DEV-049`
is the designed bound of that wait, at `OWNER_TIMEOUT` and under
`OWNER_CLAIM_RATE`. The v1 client builds no claim (`DEV-287`),
thus in v1 the wait ends at the unlock of the owner and at no
other time. A linked device shows the composed record as `queued` for that
time. Part 2 §2.4 states the trade, and Part 15 §15.3 holds the row.

This design costs one round trip when a device that is not the owner sends
first. In exchange it removes the full class of ratchet-fork bugs. The
alternative is the Sesame-style per-device session mesh of Signal. That
alternative is also correct, but it multiplies the pairwise sessions by the
device count at the two ends. For two users with 8 devices each, the count
reaches 64 sessions, which is too expensive under the session budget of Part 3
§3.12.

### 7.5.5 Convergence after an absence

The sending device is the durable log of the device set. §7.5.1 states that a
sync queue is a transport and not a log. Thus a device retains what it sent
until the peer reports that it holds the record. This section gives that report
and the seven rules that use it.

**The sync acknowledgment record.** The report is an application record of Part
6 §6.6. Its kind is `0x20` and its sub-kind is `0x02`. **[DEV-050]** A client MUST put that
record on a sync channel of §7.5.1 only. **[DEV-051]** A client MUST NOT put it on a pairwise
channel or on a group channel.

**[DEV-052]** A client MUST reject a sync acknowledgment that arrives on a different channel.
A sync acknowledgment is a control record of §7.5.3, and it is not a peer
signal.

```
DeviceSetControl {
    version        u8        // 0x01
    control_type   u8        // 0x01 a sync acknowledgment, 0x02 a roster epoch,
                             // 0x03 an ownership claim record,
                             // 0x04 a catch-up descriptor,
                             // 0x05 a sync seed update
    payload        [n]u8     // the record that `control_type` names
}

SyncAck {
    counter        u64       // the causal counter of the peer, cumulative
}
```

> **These byte values are device-set control types.** Part 6 §6.1.1 rule 7 gives
> the namespace rule. The value `0x01` names a sync acknowledgment, the value
> `0x02` names a roster epoch of §7.3.1, and the value `0x03` names an ownership
> claim record of §7.3.1. The value `0x04` names the `FileDescriptor` of a
> catch-up object of §7.5.1, and Part 12 §12.3 gives that structure. The value
> `0x05` names a `SyncSeedUpdate` of §7.7.
> **[DEV-053]** A later version
> that adds a device-set control record MUST give that record a new
> `control_type` value.
>
> A cell command of Part 6 §6.3 uses the same byte values with different
> meanings. A queue command of Part 6 §6.4 and an L6 record kind of Part 6
> §6.4.2 do the same. A `PqFrame` kind of Part 6 §6.5 and an application kind of
> Part 6 §6.6 also do the same.

The body of that `AppMessage` is 11 bytes. That total is 1 byte of sub-kind, 1
byte of version, 1 byte of `control_type`, and 8 bytes of `counter`. Part 6 §6.9
gives 155 bytes to the body of an `AppMessage` at bucket `B0`. That figure is
the `Text, default chunk` row. Thus the record fits bucket `B0`, and it costs
one cell of 560 bytes on the wire.

The size of that record is fixed. Thus the record obeys the §7.5.6 rule that
forbids a reconciliation record whose size follows the conversation count or the
tombstone count.

**The counter is the acknowledgment point, and the relay sequence number is
not.** The field `counter` names the causal counter of the peer. §7.5.2 and
§7.5.3 give that counter. The counter belongs to a device and not to a queue.
Thus a queue rotation does not change it, and a `QUEUE_IDLE_TTL` deletion does
not change it.

**[DEV-054]** A device MUST NOT use the relay sequence number of Part 6 §6.4.3 as that
counter. That sequence has queue scope, a relay assigns it, and Part 6 §6.4.3
rule 10 states that a rotation resets it.

> *Cause.* Part 6 §6.4 sends `ACK` from the recipient to the relay under
> `QR_auth`. That command instructs the relay to delete a message, and it does
> not reach the sending device. The sending device holds `QS_auth` and not
> `QR_auth`. Thus the device set needs an acknowledgment of its own, and that
> acknowledgment travels on the reverse sync queue as an application record.

**The value of `counter`.** **[DEV-055]** A device MUST set `counter` to the highest causal
counter of the peer with the property below. For each record of the peer at or
below that counter, the device needs no resend.

- The device needs no resend of a record that it holds.
- The device needs no resend of a record that it pruned under §7.5.2.
- The device needs no resend of a record that a §7.5.2 watermark rejects.

Thus a device with the `live` scope acknowledges the history that it declines.
The peer then stops the retransmission of that history.

**When a device sends the record.** The batch condition governs.
`SYNC_ACK_MAX_DELAY` is a maximum delay, and it is not a rate cap.

- **[DEV-056]** A device MUST send a sync acknowledgment after it takes `SYNC_ACK_BATCH`
  records from one peer.
- **[DEV-057]** A device MUST also send one when `SYNC_ACK_MAX_DELAY` passes. That period
  starts at the first record that the last acknowledgment does not cover.
- A device holds a pending count of the records that the last acknowledgment
  does not cover. **[DEV-058]** At each acknowledgment a device MUST set that pending count to
  zero. **[DEV-059]** That device MUST also start the `SYNC_ACK_MAX_DELAY` period again.
- **[DEV-060]** If the batch condition and the period come due together, a device MUST send
  one sync acknowledgment only.
- **[DEV-061]** If no new record arrived, a device MUST NOT send a sync acknowledgment.
- **[DEV-062]** A device MUST NOT retain a sync acknowledgment for a resend. **[DEV-063]** A device MUST NOT
  count a sync acknowledgment toward `SYNC_ACK_BATCH`.
- **[DEV-064]** A device MUST send a sync acknowledgment at the ordinary send rate of that
  sync channel. That rate is the only limit on the acknowledgment rate.

> *Cause.* A device does not retain a sync acknowledgment, and it does not count
> one. Those two rules stop a regress. Without them an acknowledgment
> acknowledges an acknowledgment without end.

**The cost.** A set of *d* devices gives each device *d − 1* sync channels
(§7.5.1). The acknowledgment count on one channel each day is the idle term plus
the batch term. An acknowledgment is a `B0` cell at 560 bytes.

- The idle term comes from `SYNC_ACK_MAX_DELAY`, which is 6 hours. That period
  gives at most 4 acknowledgments on each channel each day.
- The batch term comes from `SYNC_ACK_BATCH`, which is 32 records. That
  condition gives one acknowledgment for each completed batch of 32 records that
  the device takes on that channel. A partial batch adds no acknowledgment to
  this term.

Thus one channel costs at most 4 + *n* / 32 cells each day. The value *n* is the
records that the device takes on that channel, and the batch term counts the
completed batches only. A device pays that cost on each of its *d − 1* channels.

**A silent set and a low-rate set are two different states.** The name *idle
term* names a term of the count above, and it does not name a state of a set. A
**silent set** takes no new record on a channel. The rule above forbids a sync
acknowledgment when no new record arrived. Thus a silent set pays 0 cells on
that channel.

A **low-rate set** takes at least one new record in each `SYNC_ACK_MAX_DELAY`
period. That set takes fewer than `SYNC_ACK_BATCH` records in that period. Thus
a low-rate set pays the idle term only. At `MAX_DEVICES` of 8 a low-rate set
pays 7 × 4 = 28 cells each day, which is 28 × 560 = 15 680 bytes. **The 28-cell
figure describes the low-rate set, and it is not a floor on the full cost.**

A busy channel adds the batch term, and the batch term is the larger of the two.
Part 3 §3.12 gives a mix of 278 records each day. A device that takes 278
records on one channel completes 8 batches, because 8 × 32 = 256 records. The
remaining 22 records do not complete a batch, thus they fall to the idle term.
At `MAX_DEVICES` of 8 the batch term alone is 7 × 8 = 56 cells each day, which
is 56 × 560 = 31 360 bytes. That term is two times the idle term. The two terms
together give 7 × 12 = 84 cells each day, which is 84 × 560 = 47 040 bytes.

Part 3 §3.12 carries the acknowledgment cost as one uplink row and one downlink
row. That section also carries the cost of the sync records themselves, which is
far larger. Part 3 §3.12 gives the device count of the model, the derivation of
each row, and the scaling rule for *d* devices.

**The send opportunity.** §7.5.1 paces a sync record from the cover clock. Part
3 §3.6.2 gives tier C no cover clock. Part 3 §3.12 forbids a conversation record
on a sync channel in a push-wake session, and the U4 budget is the cause. Thus a
device sends a conversation record on a sync channel in the foreground only.
Part 3 §3.12 permits a control record of §7.5.3 in that session, and the sync
acknowledgment is a control record.

While a peer takes the records, the batch condition holds the unacknowledged
backlog on one sync channel near `SYNC_ACK_BATCH` records. The backlog also
holds each record that the device sends while the acknowledgment travels. Thus a
new sync queue resends about 32 records. A record of about 350 bytes needs
bucket `B1`, thus 32 records cost 32 × 2 096 = 67 072 bytes. Part 3 §3.3 gives
the bucket ladder, and Part 6 §6.9 gives the wire cost of each bucket.
If a peer is absent, the backlog grows with that absence, and `SYNC_MAX_AGE`
bounds it. Part 3 §3.2.4 sets `ROTATE_AFTER` to 90 days or 10 000 messages, thus
a new sync queue is rare.

**The seven rules.**

1. **[DEV-065]** A device MUST retain each sync record that it sent and that the peer did not
   acknowledge. The sync acknowledgment above gives the acknowledgment point of
   each peer. **[DEV-066]** A device MUST key that retained record by the `msg_ref` of Part 6
   §6.6 and by the causal counter. The retained body still holds the raw
   `msg_id`, because the resend puts that value on the wire. Part 6 §6.6 permits
   that raw value inside an undelivered body only.
2. **[DEV-067]** If a relay signals `QUOTA` on a sync queue, the sending device MUST keep the
   record in its local database. Part 6 §6.4 gives `QUOTA` as the value `0x50`.
   **[DEV-068]** That device MUST NOT show a delivery failure to the user.
3. **[DEV-069]** A device MUST resend each retained record above the acknowledged counter of
   the peer. A retained counter whose body the device holds no more, as that
   of a timed record whose period ended (`DEV-211`), MUST go in that resend
   as a **void**. A void is a `MutableItem` with `item` 0, which is no row of the
   table of §7.5.3. It has an empty `key` and an empty `value`, the `writer`
   and the current `lamport` of the sender, and the counter of the lost
   record as the counter of the sender in its `vector`. A void takes no new
   counter. A device that takes a `MutableItem` with `item` 0 MUST take its
   counter under `DEV-055`. That device MUST apply nothing. That device MUST
   NOT publish it
   again under `DEV-308`. Without the void the acknowledgment point of the
   peer stays below that counter permanently. Each acknowledgment then starts the
   resend of each later record again, and no device drops the bodies of
   those records. A device that holds 65 536 counters of one source above
   its acknowledgment point MUST NOT take a further one above that point.
   The source sends that counter again. That bound keeps the stored state of a
   device finite when a source sends counters with holes. A counter that
   left the log under `DEV-075` goes in no resend and in no void, and
   `DEV-077` shows its range. **[DEV-070]** If no sync acknowledgment arrived from that peer, a device MUST
   resend each retained record. **[DEV-071]** A device MUST do that resend when a sync
   acknowledgment arrives. **[DEV-072]** A device MUST also do that resend at a new sync
   queue. A rotation or a `QUEUE_IDLE_TTL` deletion makes a new sync queue, and
   the counter survives that queue. **[DEV-312]** A device MUST also start
   that resend when a relay refused a sync record of that peer or no path
   took it, and when a record waited for a channel of the peer that the run
   did not hold yet. Thus a lost last record goes in the same run, and not at
   the next one. A device starts it so at most once for each peer in a run,
   and a record that a full queue holds waits for the acknowledgment of
   `DEV-071`.
4. **[DEV-073]** A device MUST pace a resend at the ordinary send rate of that sync channel. **[DEV-074]** A
   device MUST NOT resend in one burst. A burst at a reconnect is a device-set
   beacon. A resend
   carries ordinary sync records, and it is not the reconciliation traffic that
   §7.5.6 forbids.
5. **[DEV-075]** A device MUST NOT retain a record for the resend after `SYNC_MAX_AGE`.
6. **[DEV-076]** While a resend is in progress, the client MUST show that the history is still
   arriving.
7. **[DEV-077]** If no device of the set holds a range, the device MUST show a **history gap**
   for that range. **[DEV-078]** The device MUST NOT hide the gap. **[DEV-079]** The device MUST NOT show
   the history as complete.

### 7.5.6 The edit and the deletion

A deletion that reaches a descriptor of Part 12 erases the chunks at the
uploader only, under Part 12 rule `ATT-161`. A recipient holds no `cred_sk`. A
recipient that deletes a record with an attachment removes its own copy and
nothing at a relay.

Part 6 §6.6.1 gives the `EditBody` and the `DeleteBody`. §7.5.3 gives the class
of each kind, the order of a revision, and the routing of a deletion. This
section gives the authorization, the window, the placeholder, and the interface
rules. These rules apply to a pairwise conversation and to a private group.

**The authorization is the ratchet direction, and nothing else.** **[DEV-080]** A receiver
MUST accept an edit only from the sender of the target. **[DEV-081]** A receiver MUST accept a
deletion of scope `0x02` only for a target that the same sender sent. A record
on the receiving chain comes from the peer by construction, thus the peer names
the messages of the peer and no other message.

**[DEV-082]** A sender MUST NOT use one `msg_id` two times on one chain. **[DEV-083]** A receiver MUST
reject the second use. **[DEV-084]** A receiver MUST NOT change a record that the first use
named. Part 6 §6.6 gives `msg_id`.

**[DEV-085]** A receiver MUST discard a deletion that names a target which that receiver
received in the other direction. **[DEV-086]** A receiver MUST NOT put such a target in the
pending reference table below.

> *Cause.* Without that rule the peer plants a forward tombstone that erases a
> message the receiver has not yet sent. There is no signature in this
> construction, thus the deniability of Part 5 §5.7 is untouched.

**The edit window.** `EDIT_WINDOW` is 24 hours. **The ratchet owner of the
recipient measures that window against its own local receive time of the
target.** **[DEV-087]** The ratchet owner of the recipient MUST reject an edit
that arrives more than `EDIT_WINDOW` after it received the target.
**[DEV-246]** A device of the recipient that does not own the ratchet MUST
NOT measure the window. It applies the revision that the owner forwarded under
DEV-033 and DEV-034. **[DEV-247]** A ratchet owner MUST NOT forward a
revision that it rejected to the device set.

> *Cause.* The window cannot use `sent_at`, because Part 6 §6.6 forbids that
> use. The window cannot count sender-chain positions, because §7.5.4 resets the
> counter at a change of the ratchet ownership. The local receive time is local
> state, and no other party influences it. A relay that delays a message
> shortens the window that the sender gets. That failure is safe, because it
> does not extend the window. A device that does not own the ratchet takes the
> target on the sync channel, at the pace of §7.5.1 or in a catch-up object.
> Thus its own receive time is later than that of the owner by an unbounded
> amount. If each device measured the window, the devices of one
> recipient would disagree about one edit.

**The revision limit.** `EDIT_MAX` is 8 revisions of one message. **[DEV-088]** A receiver
MUST reject the revision that follows the limit. §7.5.3 gives the high-water
mark of the applied sender-chain position. **[DEV-089]** A receiver MUST discard an edit at or
below that mark.

**The edited mark.** **[DEV-090]** A client MUST mark an edited message as edited, at each
recipient. **[DEV-091]** A client MUST apply that mark before the first render of the new
text. **[DEV-092]** The interface MUST NOT change a delivered message without a mark.

The client does not keep the earlier text. The author discards the Part 14
§14.6.4 record key of the superseded revision, and the recipient does the same.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** Inside the
> 24-hour window a sender changes what a message says, and the recipient holds
> no view of the earlier text. The window bounds the exposure, and it does not
> remove it. A hostile peer with live ratchet state writes new text into a
> transcript. That transcript is on a device that the peer does not own. The
> peer can do that for 24 hours after the original.
>
> The alternative is a retained original at the recipient, with no window. That
> alternative is stronger against a hostile sender. This specification takes the
> bounded-window form.

**A record that arrives before its target.** Messages arrive out of order. **[DEV-093]** A
client MUST hold an edit or a deletion whose target has not arrived in a
**pending reference table**. The key of that table is the triple (conversation,
direction, target), or the triple (group, author, target). **[DEV-094]** A client MUST store
the `msg_ref` of Part 6 §6.6 as that target.

| Parameter | Value |
| --- | --- |
| `REF_ORPHAN_TTL` | 45 days, which equals `MSG_TTL` |
| `REF_ORPHAN_MAX` | 4 096 entries for each conversation |

**[DEV-095]** A client MUST discard a pending entry above either limit.

**[DEV-096]** **A pending reference entry MUST NOT suppress or delay the missing-index
recovery of Part 2 §2.4.** **[DEV-097]** A client MUST treat a hole in the ratchet index as a
delivery failure. **[DEV-098]** That client MUST then send the key request of
Part 6 §6.6.11. A pending entry
can name the missing target, and that condition does not change the two
instructions.

> *Cause.* Without this rule a relay withholds one message, sends the record
> that names it, and the client waits in place of the recovery. U9 sets the
> undecryptable-message rate below 1 in 10⁵.

**Two deletion operations, and they are not the same.**

| Operation | Scope byte | Travels on | Reaches |
| --- | --- | --- | --- |
| Delete for me | `0x01` | A sync channel of §7.5.1 only | The devices of one user |
| Delete for everyone | `0x02` | A pairwise channel only | The other party, and then the devices of that party |

A device sends a deletion for the devices of one user on each of the `d-1` sync
channels. §7.5.1 gives no broadcast primitive, thus that delivery is `d-1`
independent queue operations. A user with one device pays zero cells, because
the deletion is then a local database operation.

For a deletion for the other party, the client sends one record with the scope
byte `0x02` on the pairwise channel. The client also sends one record with the
scope byte `0x01` on each of its own `d-1` sync channels. §7.6 forbids a device
identifier on the wire, and it forbids sharing the roster with a contact. Thus
the request reaches the contact as one event for one peer. The device set of the
contact then carries the tombstone on its own sync channels. Neither party
addresses a device of the other party.

**[DEV-099]** A device that applies a tombstone MUST discard the record key of the named
record. Part 14 §14.6.4 gives that record key. **[DEV-100]** That device MUST overwrite the
named record. **[DEV-101]** A client MUST NOT only hide a row.

**The placeholder.** **[DEV-102]** **A client MUST NOT render an absence as the act of a named
party.** The client can hold local evidence that the target existed on this
device. **[DEV-103]** If the client holds that evidence, the client MAY render the absence as
the act of a named party.

| The client held the target | The client shows |
| --- | --- |
| Yes, and then the tombstone arrived | A placeholder. **[DEV-104]** The placeholder MUST NOT vanish without a trace. **[DEV-105]** The user MAY clear it |
| No, and the tombstone names an unknown target | Nothing at that position. The §2.4 recovery stays active |

> *Cause.* Without this rule a relay withholds a message and delivers a
> fabricated absence. The interface then blames a person for an act that the
> relay performed.

**Rate, spread, and delivery.** **[DEV-106]** The local deletion happens at once, and the
client MUST NOT delay it. The spread below applies to the outbound request and
to nothing else.

`DELETE_RATE_LIMIT` and `SWEEP_SPREAD` in the parameters of this section
bound the outbound request. `SWEEP_SPREAD` applies to that request only.

**One user action can produce records in more than one conversation or group.
**[DEV-107]** In that case the client MUST draw an independent delay for each
destination. **[DEV-108]** The client MUST draw that delay from an exponential distribution
with a mean of `SWEEP_SPREAD`. **[DEV-109]** The client MUST NOT dispatch the set as a
burst.**

> *Cause.* A sweep across each conversation is the normal use of a deletion for
> the other party, and it is not an edge case. `DELETE_RATE_LIMIT` counts for
> each conversation, thus it does not spread a sweep. Two colluding contacts
> that each see a deletion arrive inside a few seconds get a large likelihood
> ratio that they share a correspondent. G9 holds against colluding contacts.

An edit or a deletion in a group is one group record of Part 11 §11.3, and the
group sender owner of §7.5.4 posts it as any group send. The group is one
destination under DEV-107.

> *Cause.* A send of an edit or a deletion to each member on a
> pairwise channel needs an independent delay for each member, because a burst
> to the member set is a membership beacon. A group record reaches every
> member through one group queue, thus there is no set of sends to spread.

**[DEV-112]** A client MUST send an edit and a deletion under the ordinary ARQ of Part 3 §3.7.
**[DEV-113]** A client MUST NOT run a retry loop that a relay quota signal paces. **[DEV-114]** If a relay
signals the quota, the client MUST show a delivery failure to the user.

**Retention, restore, and revocation.**

1. §7.5.2 exempts a tombstone from `SYNC_MAX_BYTES`, and it gives the retention
   rule.
2. **[DEV-115]** A history transfer MUST carry the tombstone set for the same window. A
   history transfer happens at a device link, at a scope change, and at a backup
   restore. It also happens at the re-establishment of a sync channel that a
   relay deleted under `QUEUE_IDLE_TTL`. The history window of Part 11 §11.8
   that an admin turns on is also a history transfer.
3. **[DEV-116]** A restore MUST apply the tombstone set that the backup or the archive
   carries. Part 4 §4.7.2 gives the backup, and §7.6.1 gives the archive. The
   client can hold tombstones that postdate that epoch. **[DEV-117]** In that case the client
   MUST show the count to the user. **[DEV-118]** The client MUST get a confirmation before it
   applies those tombstones.
4. **[DEV-119]** At a revocation, a client MUST show the number of deletions from the revoked
   device. §7.7 gives the revocation, and that count starts at the previous
   roster epoch. **[DEV-120]** The client MUST tell the user that a restore from a backup that
   predates the revocation recovers those messages.
5. **[DEV-121]** A device with the `live` scope MUST store a tombstone for a message that it
   never held. **[DEV-122]** That device MUST NOT request the named message from a peer
   device.
6. Part 4 §4.6 puts the message table and the tombstone table under the table
   MAC.
7. **[DEV-123]** A client MUST NOT emit a reconciliation record whose size follows the
   conversation count. **[DEV-124]** A client MUST NOT emit a reconciliation record whose size
   follows the tombstone count. **[DEV-125]** A client MUST NOT emit reconciliation traffic on
   a schedule that a reconnect determines.

**Parameters.**

| Parameter | Value |
| --- | --- |
| `EDIT_WINDOW` | 24 h, and the ratchet owner of the recipient measures it from its own receive time |
| `EDIT_MAX` | 8 revisions of one message |
| `DELETE_BATCH_MAX` | 9 targets in one record. Part 6 §6.6.1 derives it from Part 6 §6.9 |
| `DELETE_RATE_LIMIT` | 1 record of kind `0x05` in each 10 s, for each sender in each conversation and in each group |
| `SWEEP_SPREAD` | Exponential, mean 30 min |
| `REF_ORPHAN_TTL` | 45 days |
| `REF_ORPHAN_MAX` | 4 096 entries for each conversation |

### 7.5.7 What the interface states about an edit and a deletion

Part 4 §4.2.3 sets the precedent for an honest-UI rule. A deletion for the other
party is a request, and it is not an enforcement. The device of the recipient
holds the plaintext. **[DEV-126]** Thus the interface MUST state each limit below.

**A deletion for the other party.**

- "This asks the app of the other person to delete the message. The other person
  can keep a copy. A person who is offline gets the request later. UMBRA cannot
  delete a message on a device that you do not control."
- "UMBRA does not tell you whether the request arrived. A relay can hold the
  request back, and you do not learn that it did."
- "A message that waits at a relay can reach the other person before your
  request does. The relay holds an undelivered message for up to 45 days."
- "The app of the other person keeps a note that you deleted a message here. The
  other person can remove that note. You cannot."
- "UMBRA sends your requests over the next hour and not at once. Requests that
  arrive at the same moment let two of your contacts learn that they both know
  you."

**A deletion for your own devices.**

- "This removes the message from your devices. The other person keeps their
  copy."
- **[DEV-127]** The two operations MUST carry two different labels and two different
  confirmations. The deletion for your own devices can read as the stronger
  operation. **[DEV-128]** The interface MUST NOT make that operation the visually safer
  choice. **[DEV-129]** After the act the interface MUST show which of the two operations it
  performed.

**A deletion in a group.**

- "This asks the app of each member to delete the message. A member who left the
  group never gets the request. A member who sends nothing for more than 30 days
  leaves the group and never gets the request. A member can keep a copy."

**The other paths.**

- A device that returns after a long absence: "This device was offline for more
  than 60 days. It can still hold messages that you deleted while it was away."
- A backup restore: "A restore brings back the messages that the backup holds. A
  backup can be up to 26 weeks old. A message that you deleted after that backup
  comes back."
- An exported archive: "An archive file is outside UMBRA. A delete does not
  reach it."
- An attachment: "UMBRA discards the key for the file. If you sent the file,
  UMBRA asks each relay to erase its parts. If another person sent it, its
  parts stay at the relay for up to 28 days. A person who already downloaded
  the file keeps the file."
- A revocation: "This device deleted N messages since the last change to your
  device list. If you did not delete them, restore from a backup that predates
  today."

**An edit.**

- "The other person already read the earlier text. An edit changes what their
  app shows. An edit cannot remove what a person read."
- "You can edit a message for 24 hours."
- In a group: "The members already read the earlier text. A member who left the
  group, and a member who is offline, keeps the earlier text. UMBRA cannot show
  that every member sees the same text."

### 7.5.8 The conversation timer

A conversation timer removes a message from each device after a period. Part 6
§6.6.8 gives the record, and §7.8 gives the value set.

**The timer is a shared setting, and it is not a property of one message.**

- **[DEV-203]** A party MUST apply the timer to each record that it takes after
  it applied the timer record. **[DEV-204]** A party MUST NOT apply a timer to a
  record that predates it.
- **[DEV-205]** Each party of a conversation MAY set the timer. **[DEV-206]** A
  client MUST show the party that set the current value and the time of that
  change. **[DEV-207]** A client MUST show a timer change as a record in the
  conversation.
- **[DEV-208]** For a record from the other party, a client MUST measure the
  period from its own local receive time.
  **[DEV-209]** A client MUST NOT use `sent_at` for that
  measurement, and Part 6 rule `WIR-076` states the same rule. §7.5.6 gives the
  same basis to `EDIT_WINDOW`.
- **[DEV-245]** A composing device MUST measure the period from the moment it
  sent or gave the record. §7.5.4 gives the plaintext to the ratchet owner,
  and that owner takes the deadline from the sync copy under the rule below.
- **The deadline travels in the sync copy.** **[DEV-242]** A device that sends
  a timed record on a sync channel MUST put the remaining period in
  `expires_in`. That field is in the causal context of §7.5.3, in seconds.
  **[DEV-243]** A device MUST compute `expires_in` again at each send and at
  each resend of that record. **[DEV-244]** A device that takes a sync copy
  MUST measure `expires_in` seconds from its own receive time of that copy.
  The field is a duration, thus no clock comparison of Part 1 §1.9 occurs.
- **[DEV-210]** At the end of the period a client MUST discard the record key of
  Part 14 §14.6.4 for that record. **[DEV-211]** That client MUST overwrite the
  record. §7.5.6 rules `DEV-099` through `DEV-101` give the same erasure for a
  tombstone.
- **[DEV-212]** A client MUST apply the timer on each device of the set.
  **[DEV-213]** A client MUST NOT depend on a peer device to erase a record.

**A timed record enters the local database and the sync channel only.**

- **[DEV-214]** A client MUST carry a timed record to a device of the set on
  the sync channel only. A catch-up object of §7.5.1 is part of that channel.
  **[DEV-215]** A client MUST NOT put such a record in a durable store
  other than the local database of the device. The backup of Part 4 §4.7.2, the
  archive of §7.6.1, and an export are such stores.
- **[DEV-216]** A client MUST NOT put such a record in a history transfer of
  §7.5.6 rule 2. The history window of Part 11 §11.8 is one such transfer.

> *Cause.* A backup that held a timed record would return that record at a
> restore, after the period ended. Part 4 §4.7.2 holds a full object for
> `BACKUP_FULL_INTERVAL` and a relay holds it for `BACKUP_TTL`, thus the record
> would outlive its timer by up to 180 days. A user that sets a timer states an
> intent, and a silent recovery path defeats it. A rule that lists the
> forbidden stores lets a new store fall outside the rule. The positive form above
> names the two permitted paths, and each other path is out.

**The timer in a group.** Each rule of this section binds a private group in
the same manner as a pairwise conversation. A group record of Part 11 §11.3
is the target. **[DEV-248]** A member below the `admin` role of Part 11
§11.9 MUST NOT set the timer of a private group. **[DEV-249]** A member MUST
reject a timer record from a member below that role.

**What the timer does not do.**

- **[DEV-217]** A client MUST NOT show a timer as an enforcement. Part 7 §7.5.7
  gives the same rule for a deletion, and the cause is the same. The device of
  the other party holds the plaintext, and UMBRA cannot reach a device that the
  user does not control.
- **[DEV-218]** The interface MUST state that a party can copy, photograph, or
  export a message before the period ends.
- A member that a group evicts under Part 11 §11.9.7 keeps what it holds. A
  party that never took the timer record applies no timer.

### 7.5.9 The notification setting is per conversation

Part 8 §8.3 gives three notification modes, and a user selects one for each
profile. That mode decides **how the device wakes**. This section gives the
setting that decides **what the device shows**, and it is per conversation.

| Value | The client shows a notification for |
| --- | --- |
| `all` | Each record of that conversation |
| `mentions` | A record that names the user under Part 6 §6.6.5 |
| `none` | No record, and the conversation stays in the list |

- **[DEV-219]** A client MUST hold the notification setting as mutable state of
  §7.5.3. **[DEV-220]** A client MUST converge that setting across the device
  set.
- **[DEV-258]** A client MUST default a 1:1 conversation to `all`.
  **[DEV-259]** A client MUST default a new group at or below
  `GROUP_ALL_NOTIFY_MAX` members to `all`. **[DEV-221]** A client MUST default
  a new group above `GROUP_ALL_NOTIFY_MAX` members to `mentions`. Part 11
  §11.10 gives that value.
- **[DEV-223]** A client MUST NOT let the setting change the wake behavior of
  Part 8 §8.3. The device wakes on the profile mode, and the setting decides
  what the client renders after the wake.

> *Cause.* Part 8 §8.3 sets the mode for each profile. With that mode alone, a
> user that joins one busy group has to choose between a silent device and a
> device that wakes for each of 500 members. The setting above separates the two decisions. It
> also costs no wake and no cell, because it acts after the drain.
>
> A `mentions` setting needs the mention list of Part 6 §6.6.5, and that list is
> inside the AEAD of the conversation. Thus the relay and the Notification
> Delivery Relay of Part 8 learn nothing from this setting.

## 7.6 What contacts see

A contact sees **one peer**, and not a device count.

- The pairwise identity applies to each *user* and not to each device (Part 4
  §4.2.2). The addition or the removal of a device does not change the pairwise
  identity. **[DEV-131]** That operation MUST NOT cause a safety-number change or a prompt for
  a new verification (usability goal U7).
- A message carries no device identifier. A contact cannot tell which of your
  devices sent a message, and cannot tell how many devices you have.
- **[DEV-132]** A device MUST NOT share the roster with a contact.

### 7.6.1 Rotation-safe backup

**[DEV-133]** A user MAY export an encrypted archive. The archive holds the `RootIdentity`,
the local identity table, and the current roster. The archive also holds the
source watermark of each source device (§7.5.2), and optionally the message
history. The encryption uses
a passphrase from the user, with Argon2id calibrated to about 3 s on a mid-range
device.

**Conformance requirement.** A user can restore an archive that is older than a
queue rotation. **[DEV-134]** That restore MUST NOT break the affected conversations
permanently. At a restore, a client can find a stale queue state. **[DEV-135]** That client
MUST then start the re-establishment of the queue over the pairwise identity.
The pairwise identity stays correct. Part 3 §3.2.6 gives the re-establishment.
It is a new queue, a `QueueAddress` on a live channel, and the dead-channel
blob when no live channel remains.

A connection that a stale backup and a rotated address break silently and
permanently is a conformance bug in UMBRA.

**[DEV-136]** A client MUST NOT upload the archive to UMBRA infrastructure. The archive is a
file, and the user puts it in a location of their choice.

## 7.7 Revocation

Revocation is the mitigation that makes history sync tolerable. Thus revocation
has to be fast and complete.

```
1. Any remaining device publishes roster epoch n+1 with the device in `revoked`.
   That device signs the epoch with its own DeviceRosterKey (§7.3.1 rule 3).
2. Every remaining device, on observing epoch n+1:
     a. deletes the sync channels to the revoked device;
     b. takes the next DH ratchet step on every pairwise channel it owns, which
        follows the next record of the peer (§7.5.4);
     c. rotates every queue the revoked device knew;
     d. derives the sync channel seed of epoch n+1 from the seed update;
     e. starts the group re-key of Part 11 §11.12 for each group of the user.
3. Ratchet ownership held by the revoked device is claimed per §7.5.4.
```

**The seed update (step 2d).** `SyncChannelSeed_0` is the seed of the diagram
of §7.3, and `K_devset` derives it. The seed of epoch *n+1* equals the seed of
epoch *n*, except at an epoch that revokes a device. At that epoch the signing
device makes a new seed, and it sends the input to each remaining device.

```
seed_input          <- 32 bytes from the CSPRNG of the signing device
SyncChannelSeed_n+1  = HKDF-SHA3-256( salt = SyncChannelSeed_n, ikm = seed_input,
                                      info = "umbra/v1/sync-seed" || BE64(n+1),
                                      L = 32 )

SyncSeedUpdate {
    epoch          u64       // n+1, the epoch that revokes the device
    seed_input     [32]u8
}
```

- **[DEV-250]** The signer of an epoch with a new `revoked` entry MUST make
  `seed_input` from its own CSPRNG. **[DEV-251]** That signer MUST send a
  `SyncSeedUpdate` to each device in `devices` on the sync channel of that
  pair. The record travels as a `DeviceSetControl` of §7.5.5 with
  `control_type` `0x05`.
- **[DEV-252]** A device MUST derive `SyncChannelSeed_n+1` with the construction
  above, and Part 5 §5.11 holds the label. **[DEV-253]** A device MUST discard
  a `SyncSeedUpdate` that the `signer_id` of the named epoch did not send.
- **[DEV-254]** A device MUST NOT change the seed at an epoch with no new
  `revoked` entry.
- **[DEV-255]** A device MUST NOT open a sync channel to a revoked device.
  **[DEV-256]** A device MUST reject a sync channel from a revoked device.
  **[DEV-257]** After a device applies the epoch that revokes a device, it MUST
  NOT accept a sync record from that device. That holds from the record
  after the epoch on, for the records that one read of a queue gives
  together too.
- **[DEV-313]** The signer of an epoch with a new `revoked` entry MUST send
  that epoch once on the sync channel of each device that it revokes, before
  it deletes that channel under step 2a. Thus an honest device learns of its
  removal and shows it under `DEV-181`. The epoch tells that device nothing
  that it does not hold. The signer MUST send the epochs that it keeps under
  `DEV-229` on that channel before that epoch. A device that missed
  one of them verifies the epoch of its removal through them alone. A device
  that takes a verified epoch which revokes it at the index of its own
  highest epoch, as a rival of that epoch, MUST show the event under
  `DEV-181` in the same manner. The signer keeps the notice in its store with the
  epoch. It deletes the channel when a relay accepted the notice, or
  `MSG_TTL` after the revocation, whichever comes first. Thus a removal on a
  device with no connection still reaches the removed device. Each time the
  signer sends the notice again, after a lock or at a new run, it MUST send
  the kept epochs that lead to the epoch of the notice before it again, and
  no epoch above that epoch. It is possible that the removed device missed an epoch,
  and the queue of the first send does not live through a lock. Until then the
  channel carries that one record. The signer sends no later epoch and no
  sync record on it, and it discards each record that arrives on it under
  `DEV-257`.
- **[DEV-262]** A device that applies an epoch with a new `revoked` entry MUST
  start the group re-key of Part 11 §11.12 for each group of the user. The
  ratchet step of step 2b heals a pairwise channel at the next record of the
  peer and no group key, and Part 11 §11.12 gives the cause. Until that step
  the rotation of step 2c is what keeps the revoked device from the records of
  the channel. The revoked device holds the chain keys and no queue to read
  them from.

A `SyncSeedUpdate` is 40 bytes. With the sub-kind, the version, and the
`control_type` the body is 43 bytes, and it fits bucket `B0` of Part 6 §6.9.

**The rotations of step 2c are a debt of the store.** The device that owns
the pairwise channels writes the list of its contacts to its store before it
writes the epoch. Each session then asks for the rotation of each contact on
that list, with the delay of Part 3 `NET-180`. A contact leaves the list
when its new queue exists. Thus a revocation with no connection, and a
session that ends before a rotation, lose no rotation.

> *Cause.* A derivation from `K_devset`
> alone gives the seed that the revoked device holds, because §7.3 says that
> device holds the `RootIdentity`. With no new input, step 2d changes
> nothing. The random
> input from the signer is a value that the revoked device does not see,
> because DEV-255 gives it no sync channel. The chain over the old seed binds
> each update to the seed before it.

**Properties:**

- **Revocation acts on the future only.** A revoked device keeps the data that
  it synced. Revocation cannot reach a device that the user does not control.
  **[DEV-137]** The UI MUST state this limit in those words. **[DEV-138]** The UI MUST also recommend the
  full identity reset of §7.7.1 for a device in hostile hands.
- **Revocation removes the roster signing authority.** §7.3.1 rule 3 takes that
  authority from the `devices` list of the previous epoch and from the `revoked`
  list of that epoch. §7.3 makes each `DeviceRosterKey` local to one device.
  Thus a revoked device cannot sign a successor to epoch *n+1*, and it cannot
  put itself back in the set.
- **A roster fork is detectable.** The roster is hash-chained. A stolen device
  that publishes a competing roster cannot do so silently. **[DEV-170]** A device that sees
  two verified epochs at one index from **one** `signer_id` MUST show the fork
  and MUST name that device. **[DEV-171]** That device MUST NOT select one of the two
  silently. §7.3.1 rule DEV-177 resolves two epochs from two different signers,
  and that case is normal use.
- **[DEV-182]** A device that finds that a peer applied a different epoch at one index MUST
  show the fork. Two honest devices reach that state only after a hostile device
  signed an epoch, and §7.3.1 states that residual. The device MUST name the
  `signer_id` of that epoch only when its signature verifies under the
  `DeviceRosterKey` of that device, which the kept epoch before it or the
  highest epoch gives. In each other case it MUST name the device whose sync
  channel carried the epoch. Thus a device of the set cannot put a fork on
  another device with an epoch that it forged.
- **The device set is the only audience of a roster.** §7.6 forbids a device to
  share the roster with a contact, and §7.3.1 forbids a plaintext roster at a
  relay. Thus a fork from a revoked device reaches the remaining devices only,
  and those devices hold the honest chain already.
- **The relays do not authenticate a revocation.** The relays learn nothing
  about device sets. The queue rotation is the operation that cuts off the
  device, and to a relay it looks like an ordinary rotation.
- **A revocation sends no `DEL`.** Step 2b and step 2c cut the revoked device. A
  `DEL` at that moment names a set of queues at one instant. Two colluding
  relays then link those queues to one person. Part 6 §6.4.3 rule 4 states this
  prohibition.

### 7.7.1 Full identity reset

Revocation is not sufficient if an attacker can hold the `RootIdentity` itself.
The user then makes a new `RootIdentity`. The client moves through the contact
list and issues a **key-change notice** over each existing pairwise channel.
Part 4 §4.5.1 gives that notice. The ratchet of the existing session
authenticates it, and no party signs it. Each contact sees a blocking
verification prompt (Part 4 §4.5). This flow is deliberately visible and
deliberately inconvenient.

**[DEV-172]** A full identity reset MUST also make a new `DeviceRosterKey` on each remaining
device. **[DEV-173]** The client MUST then publish a roster epoch 0 for the new device set.
The old roster chain has no authority over the new one, and §7.3.1 rule 4 makes
the new epoch 0 the trust anchor.

A full identity reset does not change a group roster key by derivation. Part
11 §11.9.1 does not derive that key from the `RootIdentity`. An attacker can
hold a device of the user. **[DEV-263]** A full identity reset MUST also start
the group re-key of Part 11 §11.12 in each group of the user.

**The storage seed stays.** The first `RootIdentity` of a device also gives
`K_store`, which the passphrase wraps, and `K_set`, which names each stored
message by `msg_ref`. **[DEV-305]** A full identity reset MUST keep that seed
as the storage seed, and it MUST keep `K_store` and `K_set`. **[DEV-306]** The
new `RootIdentity` MUST give each pairwise identity and each key of discovery
of Part 9 after the reset. An entry of Part 9 that the device published before
the reset is the one exception. The directory holds the key of the earlier
root for it. Thus the device keeps that root for that entry alone, to open a
hello, to renew the lease, and to rotate or retire the entry. A rotation of
the key moves the entry to the new root, and the device erases the earlier
root with the last entry that it serves. The key of the earlier root signs the
write of that rotation, and it signs the write again after a fault. Thus the
device MUST keep an earlier root while an entry that it publishes, or a
version of an entry that its store took and the log does not show yet, has a
key from that root or needs that key for its write. It MUST erase the root
only after the log showed the version that replaced the last such entry under
the new key, or after that entry went. A write that only the store took, and
a write that the directory refused, erase no root. **[DEV-307]** A device set of more than one device
MUST remove each other device under §7.7 before the reset.

> *Cause.* A reply holds its target as a `msg_ref` alone, and a new `K_set`
> would name each stored message by another value. No party could map a stored
> reference to the new one, thus a new `K_set` would strand each reply, edit,
> and deletion of the history. **The residual.** `K_set` blinds the subjects of
> §7.3.1, and an attacker that held the root holds `K_set`. §7.3.1 states that
> the blinding does not protect a seized device, and the reset gives no more.
> A set of one device takes the new roster of `DEV-173` with no transfer of
> the new root to a device that could be in hostile hands.

## 7.8 Limits

| Parameter | Value |
| --- | --- |
| `MAX_DEVICES` | 8 |
| `OWNER_TIMEOUT` | 90 s |
| `LINK_QR_TTL` | 120 s |
| `LINK_PROVISION_TTL` | 600 s |
| `SYNC_MAX_AGE` | 365 days (configurable, 1 day or more) |
| `SYNC_MAX_BYTES` | 2 GiB (configurable) |
| `SYNC_ACK_BATCH` | 32 records |
| `SYNC_ACK_MAX_DELAY` | 6 h |
| Roster epoch rate limit | 1 in 10 s for each device |
| `OWNER_CLAIM_MAX` | 8 claims in one roster epoch or in one claim record (§7.3.1) |
| `OWNER_CLAIM_RATE` | 4 claim records of scope `0x01` or `0x04` for each device each day (§7.3.1). Scope `0x02` is retired |
| `OWNER_ABSENCE` | 24 h, measured by the claimant from the last record it took from the absent device (§7.3.1) |
| `OWNER_ABSENCE_RATE` | 1 claim record of scope `0x03` for each device each hour (§7.3.1) |
| `SYNC_INTERACTIVE_RATE` | 4 interactive sync records each minute, as the refill rate of the bucket (§7.5.1) |
| `SYNC_INTERACTIVE_BURST` | 12 tokens in the bucket (§7.5.1) |
| `SYNC_CATCHUP_LAG` | 360 records behind the counter of the device (§7.5.1) |
| `TIMER_VALUES` | 0, 30 s, 5 min, 1 h, 8 h, 24 h, 7 d, 28 d, and 90 d (§7.5.8) |
| `FORWARD_MAX_DEPTH` | 5, and Part 6 §6.6.5 gives the field (§7.5.6) |
