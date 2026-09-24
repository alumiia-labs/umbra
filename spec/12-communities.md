# UMBRA Protocol Specification — Part 12: Public Communities (1000+)

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 12.1 The honest privacy model

This part starts with what UMBRA does **not** give. A community feature that
implies a stronger property is worse than no feature.

> **Content that a user posts to a link-joinable public community is public.**
> Relays deliver that content, and those relays can read it. In a community
> UMBRA protects **which party publishes** and **which party subscribes**.

End-to-end encryption of a public community gives no confidentiality. A party joins a public
community when that party follows the link of that community. The adversary can
do the same. Thus a key that goes to the members is a key that the adversary
holds. To encrypt content to a set that holds your attacker gives nothing. That
operation also costs the moderation, the search, and the abuse handling that a
community of 50 000 persons needs.

SimpleX reached the same conclusion in April 2026, after four years with the
alternative. UMBRA adopts the conclusion at the start. UMBRA then spends the
complexity that it saves on **participation privacy**, which is the property
that protects persons.

### 12.1.1 What that means concretely

| | Private group (Part 11) | Public community (this part) |
| --- | --- | --- |
| Content visible to relays | No | **Yes** |
| Membership visible to relays | No | The subscriber set is hidden. The authorship of a post is pseudonymous |
| Who can join | Invited parties only | Each party with the link |
| Maximum practical size | 500 | 100 000 or more |
| Moderation | In band, by the members | Server-assisted, by the moderators |

**[COM-001]** The UI MUST make this difference impossible to miss. **[COM-002]** A community MUST look
different from a private group. **[COM-003]** A community MUST also read differently. Those
two rules apply at each point where a user can confuse the two. **[COM-004]** At a join, the
UI MUST show what becomes visible.

**The pseudonym is durable, and the interface says so.** Part 16 §16.1.1 calls a
community pseudonym the one durable identifier in the system. §12.9 forbids an
automatic rotation, because a rotation loses the post history of the author.

- **[COM-154]** At a join, the interface MUST state that the pseudonym of the
  user is durable in that community.
- **[COM-155]** The interface MUST state that a party can monitor that pseudonym
  over time, and that a court can name it in an order against a relay.
- **[COM-156]** The interface MUST state that a rotation loses the post history.
- **[COM-157]** The interface MUST NOT show a community pseudonym and a pairwise
  identity as equal in privacy.

> *Cause.* Part 4 §4.2.3 sets the precedent with rules IDN-010 through IDN-013
> for a Public Address, which is the weaker case. A community pseudonym is the
> stronger case, because Part 16 §16.1 gives it the only row of the compellable
> set that names a durable identifier. An earlier draft made COM-004 the only
> rule at a join, and that rule names no property of the pseudonym.

## 12.2 Architecture: origin-cache

```
        Owner devices (authoritative state)
              │  signs roster + moderation epochs
              ▼
     ┌────────┴────────┬─────────────────┐
     ▼                 ▼                 ▼
  Relay A           Relay B           Relay C        ← replaceable caches,
  (operator 1)      (operator 2)      (operator 3)     different operators
     │                 │                 │
     └────────┬────────┴────────┬────────┘
              ▼                 ▼
        Subscribers pull; client-side dedup across relays
```

- **The authoritative state is on the owner devices.** The relays are transient
  distribution nodes with the shape of a CDN, and they hold a cache.
- The **community identity** is
  `SHA3-256("umbra/v1/community-id" \|\| admission \|\| genesis_root_public_key)`.
  It is fixed at the creation, it is in the community link, and it is a binding
  prefix in each signed message. The value `genesis_root_public_key` is the
  ML-DSA-65 public key of an **owner role pseudonym**. The value `admission` is
  one byte, and §12.2.2 gives it. **[COM-005]** The creator MUST make that role
  pseudonym the §12.3.2 way, from a second and independent seed. §12.5.2 rule 5
  checks the derivation above at epoch 0.
- **The owner publishes to more than one relay, and the client removes the
  duplicates.** The relays have different operators. Thus no one operator sees
  the full pull pattern of a subscriber (§12.3.1). More than one relay also
  makes the cross-relay consistency check possible (§12.4.3). One relay that
  stops does not stop the community (U6). The parameter `COMMUNITY_MIN_RELAYS`
  gives the minimum, and the cost is low.
- A subscriber does not connect to an owner and does not connect to another
  subscriber. A new subscriber costs nothing, and that property is the cause
  that a community scales where a private group does not.

### 12.2.1 Identification and deduplication

A community post is not an `AppMessage`, thus a community post carries no
`msg_id`.

- **[COM-006]** A client MUST identify each post by the triple (`community_id`, `pseudonym`,
  `index`). §12.4.4 gives the record and its `index`. **[COM-007]** A relay MUST serve each
  post under the pseudonym of its author.
- **[COM-008]** A client MUST treat two records with the same triple as one post. **[COM-009]** A client
  MUST NOT merge two records with different triples. **[COM-010]** A client MUST NOT compare
  the bodies of two posts from two different pseudonyms. Two authors can publish
  one text.
- **[COM-011]** If two relays serve two different bodies at one triple, the client MUST show a
  relay integrity warning. **[COM-012]** That warning MUST name the two relays. That warning
  comes after the settle window of §12.4.3.1 rule 5. **[COM-013]** A client MUST NOT select
  one of the two bodies silently.
- **[COM-014]** If the client holds `link_{n-1}` for that author, the client MUST compute
  `link_n` again. **[COM-015]** The client MUST reject a record that does not match. `link_n`
  is a value that the reader computes. **[COM-016]** A relay does not serve `link_n`, and a
  client MUST NOT accept `link_n` from a relay.
- **[COM-017]** A client MUST treat a `PostStub` and a body at one triple as one post. That
  rule applies after the client verifies the artifact of §12.5.2 that justifies
  the stub.
- **[COM-018]** A client MUST identify each checkpoint by the triple (`community_id`,
  `pseudonym`, `end_index`). Two relays can serve two checkpoints that each
  verify at one triple and that differ. **[COM-019]** In that case the client MUST show a fork
  of that pseudonym. **[COM-020]** A client MUST NOT select one checkpoint silently.
- **[COM-021]** A client MUST identify each moderation epoch and each community roster by the
  pair (`community_id`, `epoch_index`). The fork rule above applies without a
  change.
- **[COM-022]** A client MUST NOT use the checkpoint signature bytes as an identifier or as a
  deduplication key. **[COM-023]** A client MUST NOT use a value that comes from those bytes
  for either function. Part 6 §6.1.1 rule 5 gives that rule.

### 12.2.2 The admission mode, and why it cannot change

A community carries one **admission mode**. The mode is one byte. The community
identity of §12.2 binds that byte.

| Byte | Mode | This specification defines the mode |
| --- | --- | --- |
| `0x01` | Open. A party joins with the link | Yes. §12.1 gives the model |
| `0x02` | Closed. An owner admits each party | No. The byte is reserved |

- **[COM-168]** A creator MUST set the admission byte at the creation.
- **[COM-169]** A client MUST derive `community_id` with the construction of §12.2.
- **[COM-170]** A client MUST reject a community whose admission byte this specification does
  not define.

**The mode cannot change.** The identity binds the byte, thus a different byte
gives a different `community_id`. A different `community_id` gives a different
link, a different binding prefix, and a different post chain. An owner that
writes a different byte creates a second community, and the first community
continues without a change. No party moves a community between the two modes.

- **[COM-171]** A revision MUST NOT define a mechanism that moves a community from one mode
  to the other.

> *Cause.* §12.1 states that the content of an open community is public. A move
> to the closed mode cannot make that content private again, because each relay
> and each party that held the link already read it. A move to the open mode
> publishes the content that a member wrote under a different promise. Each
> direction breaks a promise that a user relied on when that user posted. Thus
> the identity binds the mode, and no rule changes it.

## 12.3 Participation privacy

This property is the property that UMBRA protects here, and the requirements are
strict.

### 12.3.1 Subscriber privacy

- A subscriber pulls through the **ordinary 3-hop relay chain** (Part 3). Thus a
  community relay does not see the IP address of a subscriber.
- A pull carries **no client identifier**. §12.3.3 gives the request record,
  and that record holds a community identifier, a selector, a cursor, and a
  count. A relay learns that a party pulled the last `PULL_BATCH` records. A
  relay does not learn that the user X has a subscription.
- **[COM-172]** A `PullRequest` MUST NOT carry a value that binds it to a
  client, a device, or an earlier session. **[COM-173]** A client MUST NOT pull
  two communities in one transport session. **[COM-174]** A client MUST select
  the `PULL_INTERVAL` of each community and of each relay separately.

  > *Cause.* An earlier draft named a rotating and unlinkable pull credential,
  > and no section defined it. A credential that a relay verifies comes from an
  > issuer, and an issuer that counts its credentials holds a subscriber list at
  > one remove. A pull with no credential builds no such list. `COM-173` keeps
  > the promise of §12.8 that a relay does not learn the subscriber overlap
  > between two communities. Part 16 §16.3 records what one session still
  > shows.

- A subscriber pulls from **two or more relays under different operators**, on a
  randomized schedule. Thus no one operator sees the full read pattern of a
  subscriber.
- **[COM-024]** **A community MUST NOT carry kind `0x06` or kind `0x07`.** **[COM-025]** A client MUST NOT
  emit a delivery receipt or a read receipt for a community post. **[COM-026]** A relay MUST
  reject such a record.

  > *Cause.* No subscriber list exists, on a relay or on an owner device. §12.8
  > calls that property structural. A receipt builds the list that this section
  > says does not exist.

- **The fan-out does not enumerate the subscribers.** There is no subscriber
  list. The relays do not hold one, and the owner devices do not hold one. The
  delivery is a pull and not a push.

  This property makes 50 000 subscribers tractable. The relay does not know the
  subscribers and does not track them. Thus the cost is O(pulls) and not
  O(members).

### 12.3.2 Author privacy

An author posts under a **community identity**. Each community gets a different
community identity.

```
CommunityIdentitySeed_g := 256 bits from the device CSPRNG
CommunityIdentityKey_g  := ML-DSA-65 keypair from CommunityIdentitySeed_g
pseudonym_g             := SHA3-256(CommunityIdentityKey_g.pk)      // 32 B
```

- **[COM-027]** At the join, a client MUST make `CommunityIdentitySeed_g` from the device
  CSPRNG. **[COM-028]** A client MUST NOT derive that seed from the `RootIdentity`, from
  `community_id`, or from other key material.

  > *Cause.* Part 4 §4.2.2 makes the queue keys in the same manner, and Part 7
  > rule `DEV-224` makes `device_id` in the same manner. A value that a party derives
  > from the root is a value that a seized root gives up. `community_id` is
  > public to each party that holds the community link. A derivation from the
  > root and from `community_id` gives a party that holds one root a list. That
  > list names the community identity of that user in each community that the
  > party observes. G13 does not permit that result.

- **[COM-029]** A member that holds a role in the community MUST make a second and independent
  seed for that role. **[COM-030]** That member MUST use the resulting **role pseudonym** in a
  community roster and in a moderation epoch (§12.5.2). **[COM-031]** A member MUST NOT sign a
  moderation epoch with the authoring pseudonym.

- **A role also holds a report key.** §12.5.1 makes an owner or an admin the
  designated verifier of an abuse report. A designated verifier needs a private key that it
  can use to decapsulate, and ML-DSA-65 holds no such operation.

  ```
  RoleSeed_r       := 256 bits from the device CSPRNG
  RoleSigningKey_r := ML-DSA-65 keypair from RoleSeed_r
  RoleReportKey_r  := Hybrid( HKDF-SHA3-256( ikm = RoleSeed_r,
                                 info = "umbra/v1/community-report", L = 96 ) )
  ```

  **[COM-376]** A member MUST derive `RoleReportKey_r`, and
  `CommunityContactKey_g` of §12.6.3, as 96 bytes of HKDF-SHA3-256 output
  under the label as the `info`, split by `Hybrid` of Part 5 §5.2. Part 11
  §11.3.3 derives the member KEM key of a group in the same manner. An
  earlier draft asked for 64 bytes, and a `UMBRA-KEM` keypair takes 96.

  **[COM-142]** A member that holds a role MUST derive `RoleReportKey_r` from
  the seed of that role. **[COM-143]** That member MUST publish the
  encapsulation key of `RoleReportKey_r` in its `RosterEntry` of §12.5.2.
  **[COM-144]** A member MUST NOT use `RoleSigningKey_r` for a key agreement.
  **[COM-145]** A member MUST NOT use `RoleReportKey_r` for a signature.

  > *Cause.* An earlier draft made the designated verifier of Part 14 §14.10
  > "the ML-DSA-65 role pseudonym". ML-DSA is a signature scheme. A
  > designated-verifier construction needs a verifier key that opens or
  > simulates, and a signature key does neither. The derivation above adds no
  > primitive, because `UMBRA-KEM` is the hybrid KEM of Part 5 §5.3.

  > *Cause.* A moderation epoch names its signer in the clear, and each
  > subscriber reads it. One key makes the whole posting history of that member
  > publicly attributable to the role. A second seed costs 32 bytes of local
  > state and zero wire bytes.

- **[COM-032]** A client MUST store each seed in the **local identity table**. That table also
  holds the pairwise salts of Part 4 §4.2.2 and the group roster seeds of Part
  11 §11.9.1.
- **[COM-033]** The client MUST hold the local identity table under the per-record encryption
  of Part 15 §15.6.4. **[COM-034]** The client MUST cover that table with the table MAC of
  Part 4 §4.6.
- A post carries `pseudonym_g`, which is 32 bytes. **[COM-035]** A post MUST NOT carry a
  public key. **[COM-036]** A checkpoint MUST carry `CommunityIdentityKey_g.pk`. **[COM-037]** A community
  roster and a moderation epoch MUST carry the public key of the role pseudonym
  that signs it.
- **[COM-038]** Before a client verifies a checkpoint signature, that client MUST hash the
  carried public key. **[COM-039]** If that hash differs from `pseudonym_g`, the client MUST
  reject the checkpoint. The same rule binds a community roster and a moderation
  epoch, and §12.5.2 rule 1 states it.
- A post moves through the relay chain. Thus the community relay does not see
  the IP address of an author.
- **A post has a relay-local rate limit for each pseudonym.** A post carries
  `pseudonym_g` in the clear, thus a relay applies the limit with no credential
  at all.

  **[COM-148]** A relay MUST apply `POST_RATE_LIMIT` for each `pseudonym` of
  each community that it serves. **[COM-149]** A relay MUST NOT need an
  anonymous credential to apply that limit. **[COM-150]** A relay MUST apply the
  proof of work of Part 14 §14.8 as the surge valve above that limit. The
  solution travels in the `Admission` of Part 14 §14.2 at the end of the `PUB`
  payload. **[COM-151]** A relay MUST NOT hold a rate-limit counter after
  `POST_RATE_WINDOW`.

  > *Cause.* An earlier draft gave a post an **ARC** credential that binds to
  > `presentationContext = community_id`. Part 14 §14.4 states that ARC is
  > **privately verifiable**, and that only a verifier which the nonprofit
  > operates can check it. §12.2 puts a community on `COMMUNITY_MIN_RELAYS`
  > relays under **different operators**. Thus the rate limit was unreachable at
  > each relay that the nonprofit does not run.
  >
  > A credential adds nothing here in any case. §12.9 forbids an automatic
  > rotation of a pseudonym, and Part 16 §16.1.1 calls that pseudonym the one
  > durable identifier in the system. A relay reads it on each post already.
  > Part 14 §14.4 keeps ARC for the Public Address rendezvous, which the
  > nonprofit does operate.

**The unlinkability property, stated in full.**

> A party holds `pseudonym_g` of an author. That party cannot link it to any of
> the three items below.
>
> - A pairwise identity of that author.
> - A Public Address of that author.
> - The community identity of that author in a different community.
>
> A party that holds the `RootIdentity` of that author gets no one of these
> three links. Only the local identity table gives a link, and that table stays
> on the devices of the user.

**The table travels with the account.**

- **[COM-040]** A client MUST put the local identity table in each of the three places below.

  - The provisioning payload of Part 7 §7.4.
  - The encrypted backup of Part 4 §4.7.2.
  - The archive of Part 7 §7.6.1.
- The local identity table is not history. **[COM-041]** `SYNC_MAX_AGE` and `SYNC_MAX_BYTES`
  MUST NOT remove an entry from that table.
- The social recovery of Part 4 §4.7.3 needs no change, because the Recovery
  Code opens the backup that holds the table.

**A lost community identity.**

- **[COM-042]** If a client does not hold `CommunityIdentitySeed_g`, that client MUST NOT post
  in that community. **[COM-043]** The client MUST tell the user that the community identity
  and its post history are lost. Only an explicit act of the user makes a new
  community identity for that community.
- The earlier posts of a lost community identity stay in the community, and the
  last checkpoint of that identity stays valid.

**One device owns each chain.**

- The roster chain of Part 7 §7.3.1 names one **chain owner** device for each
  community identity. That name is an `OwnerClaim` of scope `0x02`, and its
  `subject` is the `community_id` of §12.2. Only the chain owner appends to the
  chain of §12.4.1 and signs a checkpoint. **[COM-044]** A device that is not the chain
  owner MUST give the post
  text to the chain owner. That device uses the sync channel of Part 7 §7.5.1. A
  device claims the chain ownership with the mechanism of Part 7 §7.5.4.

  > *Cause.* Two devices that append at one index make two checkpoints with one
  > `start_index` and two heads. §12.4.3 would show that as a relay integrity
  > warning that names an innocent relay.

### 12.3.3 The pull and the publication

A subscriber reads a community with a **pull**. An author or an owner writes to
a community with a **publication**. Each one travels as a command of Part 6
§6.4, in the community range `0x80` to `0x85`, which holds the six commands
of the table below. A community command puts
`community_id` in the `queue_id` field, in the manner that an attachment command
puts `chunk_id` there. Part 6 §6.4 rules `WIR-309` and `WIR-310` keep a
community command out of a session and out of a cell that carries a queue
command.

| `cmd` | Name | Sent by | Payload |
| --- | --- | --- | --- |
| `0x80` | `PULL` | Subscriber | `PullRequest`, 75 B |
| `0x81` | `PAGE` | Relay | `PullResponse` |
| `0x82` | `PUB` | Author or owner | one community record of §12.4.4, then an `Admission` of Part 14 §14.2 |
| `0x83` | `PUBACK` | Relay | `seq` `u64` |
| `0x84` | `NREG` | Subscriber | `NotifyRegistration`, 162 B (§12.6.4) |
| `0x85` | `NUNREG` | Subscriber | `NotifyRegistration`, 162 B (§12.6.4) |

**The pull key.** Part 3 §3.2.3 keys the deniable authenticator of a command on
a queue secret. A community has no queue, and a pull has no client secret. Each
party derives one X25519 key from `community_id` in its place.

```
pull_sk := HKDF-SHA3-256( salt = "umbra/v1/community-pull",
                          ikm = community_id, L = 32 )
pull_pk := X25519( pull_sk, basepoint )
```

- **[COM-175]** A party MUST key the authenticator of a community command with
  `pull_sk` in the place of `Q*_auth_sk`. Part 3 §3.2.3 rule `NET-149` states
  the same binding. Part 5 §5.11 holds the label.
- **[COM-176]** A community command MUST put `community_id` in the `queue_id`
  field.

> *Cause.* `pull_sk` is public to each party that holds `community_id`, thus
> the authenticator proves nothing about the sender. It keeps the command header
> of Part 6 §6.4 uniform, and `corr_id` keeps the replay rejection of `NET-122`.
> A relay derives `pull_pk` from `community_id`, thus a relay needs no
> registration to verify a pull.

**The request.**

```
PullRequest {
    version        u8        // 0x01
    community_id   [32]u8
    selector       u8        // 0x01 to 0x04, see the table
    pseudonym      [32]u8    // the chain under selector 0x02, zero bytes otherwise
    from           u64       // the first seq, index, epoch_index, or meta_index
    count          u8        // 1 to PULL_BATCH
}
```

| `selector` | Name | `from` | The relay serves |
| --- | --- | --- | --- |
| `0x01` | The relay sequence | a `seq`, or the sentinel `0xFFFFFFFFFFFFFFFF` | each record with a `seq` at or above `from`, in `seq` order. Under the sentinel, the newest `count` records |
| `0x02` | One chain | an `index` | each `CommunityPost` or `PostStub` of `pseudonym` with an `index` at or above `from`, in `index` order. A `Checkpoint` of that chain follows the last `index` of its window |
| `0x03` | The control chain | an `epoch_index` | each `CommunityRoster`, each `ModeratorSet`, and each `ModerationEpoch` with an `epoch_index` at or above `from`, in `epoch_index` order |
| `0x04` | The metadata | a `meta_index` | each `CommunityMeta` of §12.7 with a `meta_index` at or above `from`, in `meta_index` order |

**The relay sequence.** A relay gives each record that it accepts one `seq`. The
value is relay-local. A different relay gives the same record a different
`seq`, thus a client holds one cursor for each relay. A `seq` that no record
holds is not a gap. A relay drops a body under `COM-217`, and it prunes a record
under §12.4.6.

- **[COM-177]** A relay MUST give each accepted record of a community a `seq`
  above each earlier `seq` of that community. **[COM-178]** A relay MUST NOT
  change the `seq` of a record. **[COM-179]** A relay MUST NOT give a pruned
  `seq` to a second record.
- **[COM-180]** A client MUST NOT compare a `seq` of one relay with a `seq` of
  another relay. A `seq` is not part of the record, and §12.2.1 gives the
  identifiers.

**The response.**

```
PullResponse {
    version        u8        // 0x01
    community_id   [32]u8
    selector       u8        // the selector of the request
    floor          u64       // the seq floor, or the chain floor of §12.4.6
    next           u64       // the value that follows the last entry
    count          u8        // 0 to PULL_BATCH
    entries        [count]PullEntry
}

PullEntry {
    seq            u64
    record_len     u16
    record         [record_len]u8   // one community record of §12.4.4
}
```

The header of a `PullResponse` is 51 bytes, and each entry adds 10 bytes to its
record. A `CommunityRoster` at `ROSTER_ENTRY_MAX` is 31 547 bytes, thus one
entry that holds it is 31 557 bytes. That page fits the `B3` L5 payload. A post
record with a 200-byte body is 246 bytes (§12.4.1), and `PULL_BATCH` such
entries are 7 680 bytes. With the header the page is 7 731 bytes, and it fits
the `B2` L5 payload of 8 074 bytes. A post at `MAX_POST_SIZE` is 8 013 bytes,
and a page that holds it is 8 074 bytes, which is that payload exactly.

- **[COM-181]** A relay MUST fill a `PAGE` in the order of the selector table.
  **[COM-182]** A relay MUST stop a page at `count` entries, or at the `B3` L5
  payload of Part 6 §6.9. **[COM-399]** Under selector `0x02`, the records
  of one `index` are one unit: each body or stub at that index, the
  `OperatorRemoval` of a stub, and the `Checkpoint` whose `end_index` is
  that index. A relay MUST put a unit in one page in full, or stop the page
  before it. Thus the `next` value of a page never skips a checkpoint.
- The **seq floor** of a community at one relay is the lowest `seq` that the
  relay holds for it, or 0 when it holds none. **[COM-183]** Under selector
  `0x01`, a relay MUST set `floor` to the seq floor. **[COM-184]** Under
  selector `0x02`, a relay MUST set `floor` to the chain floor of §12.4.6.
  **[COM-185]** Under selector `0x03` and selector `0x04`, a relay MUST set
  `floor` to 0.
- **[COM-186]** A relay MUST set `next` to the value that follows the last
  entry. **[COM-187]** If the page holds no entry, the relay MUST set `next` to
  `from`, and to 0 under the sentinel.
- **[COM-188]** A relay MUST reject a `PULL` whose `selector` is not `0x01` and
  whose `from` is the sentinel. **[COM-189]** A relay MUST reject a `PULL` whose
  `count` is 0 or above `PULL_BATCH`.

**The cursor.**

- **[COM-190]** A client MUST hold `next` of the last `PAGE` under selector
  `0x01` for each relay and each community. **[COM-191]** A client MUST use that
  value as `from` in its next pull under selector `0x01` from that relay.
- **[COM-192]** A client MUST set `count` to `PULL_BATCH` in each pull under
  selector `0x01`. Thus a first pull and a steady-state pull have one shape,
  and §12.4.4 rule 8 gives the cause.
- **[COM-193]** If `floor` is above the cursor, the client MUST treat each `seq`
  between the two as pruned at that relay. The relay serves from `floor`, and
  §12.4.6 gives the pruned state.
- **[COM-194]** If a page under selector `0x01` holds `PULL_BATCH` entries, the
  client MUST pull again in the same session. That rule binds a steady-state
  pull, and `COM-091` binds a first backfill.
- **[COM-195]** At a join, a client MUST make its first pull under selector
  `0x01` with the sentinel. **[COM-196]** At a join, a client MUST pull the
  control chain from `epoch_index` 0, and the metadata from `meta_index` 0.
  The client fills the history behind the first page with pulls at lower
  `from` values, under §12.4.4 rule 8.

**The publication.**

- **[COM-197]** A `PUB` MUST carry one record of type `0x01`, `0x03`, `0x04`,
  `0x05`, `0x06`, or `0x08`. **[COM-198]** A relay MUST reject a `PUB` that carries a
  `PostStub`. A relay makes each stub itself under §12.4.4 rule 1.
- **[COM-400]** A `PUB` payload holds one record and then the `Admission`. A
  relay MUST take the length of the record from its `type` and its count
  fields, and it MUST reject a payload whose `Admission` does not end at the
  end of the payload.
- **[COM-199]** A relay MUST reject a record whose `community_id` field differs
  from the `queue_id` of the command. A `CommunityPost` holds no such field,
  and the `queue_id` gives its community.
- **[COM-200]** A publisher MUST send a `PUB` of each record to each relay that
  the selected `CommunityMeta` (§12.7) names. **[COM-201]** A publisher MUST
  send a `PUB` again at each session until the relay answers with a `PUBACK`
  or a `NACK`.
- **[COM-202]** A relay MUST answer an accepted `PUB` with a `PUBACK` that
  carries the `seq` of the record. **[COM-203]** If the relay holds that record
  already, the relay MUST answer with the `seq` that it holds. **[COM-204]** A
  relay MUST answer a rejected `PUB` with a `NACK` of Part 6 §6.4.4, and not
  with a `PUBACK`. An earlier draft gave a rejected `PUB` no answer, and
  `COM-201` then made a publisher send a malformed record again forever.
- **[COM-205]** A relay MUST apply the admission control of Part 14 to a `PUB`
  of a `CommunityRoster` with `epoch_index` 0. **[COM-206]** A relay MUST NOT
  accept a record of a community before it holds the `CommunityRoster` with
  `epoch_index` 0. **[COM-207]** A relay MUST apply the identity check of
  §12.5.2 rule 5 to that roster.
- **[COM-208]** A relay MUST verify the signature of a `Checkpoint`, a
  `CommunityRoster`, a `ModeratorSet`, a `ModerationEpoch`, or a
  `CommunityMeta` before acceptance. **[COM-209]** A relay MUST apply §12.5.2
  rule 1 and rule 5 to a `CommunityRoster`, to a `ModeratorSet`, and to a
  `ModerationEpoch`. Rule 1 is the hash check, and
  rule 5 is the chain of authority. **[COM-210]** A relay MUST apply the hash
  check of `COM-038` to a `Checkpoint`.
- **[COM-211]** A relay MUST count a `PUB` under `POST_RATE_LIMIT` against the
  `pseudonym` of a `CommunityPost`, or the `actor` of another record.
  §12.6.2 gives a reaction and a repost their own limits, and §12.5.2 rule 11
  gives the control chain its own limits.
- **[COM-391]** A relay MUST reject a `CommunityPost` whose `body` does not
  parse as the `RichRecord` of `COM-158`, or whose `forward_depth` is not
  zero. The relay reads `inner_kind` for the limits of §12.6.2, thus it holds
  the parser already.
- **[COM-392]** A relay MUST count a `Checkpoint` against its `pseudonym` in a
  count of its own, at `POST_RATE_LIMIT` in each `POST_RATE_WINDOW`.
  **[COM-393]** A relay MUST reject a `Checkpoint` whose window holds an index
  that a held `Checkpoint` of that pseudonym covers, unless the two are one
  checkpoint under `COM-203`. A checkpoint covers one post at the least, thus
  the two rules bound the checkpoints of a chain by its posts. A relay does
  not measure `SIG_MIN_INTERVAL`: two checkpoints that an author sent 60 s
  apart can arrive 59 s apart, and a `NACK` there would stop the settlement
  of a correct window.
- **[COM-212]** A party MUST reject a `Checkpoint` whose window holds more than
  `SIG_INTERVAL` indexes. Rule 1 of §12.4.1 makes a larger window impossible
  for a conforming author.

**Two bodies at one pending triple.** A post carries no signature. Thus a relay
cannot tell the post of the author from a post that a second party puts at that
triple first. The checkpoint of the author decides between the two.

- **[COM-213]** A relay MUST accept a second `CommunityPost` with a different
  body at a triple that no held checkpoint covers. **[COM-214]** A relay MUST
  reject a third body at one triple. **[COM-215]** A relay MUST serve each
  body that it holds at a pending triple.
- A relay resolves a contested window when a `Checkpoint` that covers it
  verifies, and the relay holds a body at each index of that window.
  **[COM-216]** At that time, the relay MUST keep at each index the body that
  the recomputation of §12.4.4 rule 6 admits. **[COM-217]** The relay MUST drop
  each other body at that index. The recomputation tries each combination of
  one body for each contested index. `COM-212` bounds a window at
  `SIG_INTERVAL` indexes, thus it tries 32 combinations at the most.
- **[COM-218]** If a relay holds an admitted body at a triple, the relay MUST
  reject a different body at that triple.
- **[COM-394]** A relay that holds two bodies at a pending triple MUST accept
  a third body when a held `Checkpoint` covers the triple and the
  recomputation of §12.4.4 rule 6 admits that body. The relay then drops the
  two other bodies under `COM-217`. `COM-214` rejects each other third body.
  **[COM-395]** An author whose `PUB` of a post got a `NACK` MUST send that
  `PUB` again after the `PUBACK` of the `Checkpoint` that covers the post.

  > *Cause.* A second party that put two bodies at the next index of an
  > author made the relay reject the body of the author as the third one.
  > The window then never resolved at that relay. The signed head decides
  > which body is the body of the author, thus it also admits that body
  > late.
- **[COM-219]** If a relay serves two bodies at one triple, a client MUST hold
  both pending until a checkpoint covers it. **[COM-220]** A client MUST apply
  the selection of `COM-216` at that checkpoint.

> *Cause.* A relay that kept the first body only would let a second party block
> the author at that relay. The other relays would serve the body of the
> author, and §12.4.3 would then name an honest relay in a body divergence
> warning. Two candidates and one signed head resolve the contest at each
> party in the same way, and the bound of 32 comes from `SIG_INTERVAL`.

## 12.4 Authenticity: per-author hash chains with amortized signatures

A community post **carries authentication** under the community pseudonym of the
author. That authentication is not a signature on each post.

### 12.4.0 Why not a signature on each post

An ML-DSA-65 signature is **3 309 bytes**. A post of 200 bytes with a signature
is about 3.5 KB. That size does not fit the bucket `B1` (2 KiB), thus it goes
into `B2` (8 KiB). The result is a **cell-size increase of 16 times on the
traffic with the highest volume in the system**. At community scale that cost is
the largest cost in the protocol.

The usual alternative is a small classical signature, such as Ed25519 at 64
bytes. That alternative operates, but it adds a seventh primitive family and its
hash. It also makes the authenticity of a post the one classically secure part
of a design that is post-quantum elsewhere.

### 12.4.1 The construction

Each author keeps a **hash chain for each community**:

```
link_0   = SHA3-256("umbra/v1/community-chain" || community_id || pseudonym)
link_n   = SHA3-256(link_{n-1} || SHA3-256(post_n))
```

`link_n` is a value that the reader computes. A post record does not carry
`link_n`, and a relay does not serve `link_n`. §12.4.4 gives the record.

After a post, the author publishes one **ML-DSA-65 signature over the current
chain head**. That signature is a **checkpoint**. The signature also covers the
index of the head and the community id. Six rules give the cadence and the cost.

1. **[COM-045]** An author MUST publish a checkpoint when `SIG_INTERVAL` posts have no
   checkpoint. **[COM-046]** An author MUST also publish a checkpoint when the oldest post
   with no checkpoint reaches `SIG_MAX_AGE`. The first condition to occur
   applies.
2. **[COM-047]** An author MUST NOT publish more than one checkpoint in each
   `SIG_MIN_INTERVAL`.
3. **[COM-048]** An author MUST NOT publish a checkpoint that covers zero new posts. A
   withdrawal takes effect at the next checkpoint that rule 1 produces.

   > *Cause.* A checkpoint that covers zero new posts is out of cadence. A fixed
   > delay after a user action puts it there. Every relay and every subscriber
   > then reads a signed public marker that says the pseudonym withdrew a post.
   > The withdrawal hides the act inside a fixed 32-byte field for that reason,
   > and an out-of-cadence checkpoint defeats that field.

4. A checkpoint can cover exactly one post. That post record either fits the
   free space of the checkpoint bucket, or it does not fit. **[COM-049]** If it fits, the
   client MUST send the post and the checkpoint in one cell. **[COM-050]** If it does not fit,
   the client MUST send the checkpoint in a separate cell. Part 6 §6.4.1 makes
   batching mandatory. The paragraphs below give the free space and the bound.
5. **[COM-051]** The parameters of §12.9 MUST satisfy `SIG_MAX_AGE` at or above
   `SIG_INTERVAL × 3600 / POST_RATE_LIMIT` seconds. A parameter set that does
   not satisfy that condition makes `SIG_INTERVAL` unreachable.
6. **[COM-052]** The parameters of §12.9 MUST satisfy `PENDING_DEMOTE` above `SIG_MAX_AGE`
   plus the maximum `PULL_INTERVAL`. If they do not, a client demotes a post
   that settles on the normal cadence.

The checkpoint record has this structure. §12.4.4 names the namespace of the
`type` byte.

```
Checkpoint {
    version               u8        // 0x01
    type                  u8        // 0x05
    community_id          [32]u8
    pseudonym             [32]u8
    start_index           u32
    end_index             u32
    previous_signed_head  [32]u8
    current_head          [32]u8
    withdrawn             [8]u32    // WITHDRAW_MAX entries, 32 bytes
    public_key            [1952]u8  // CommunityIdentityKey_g.pk
    signature             [3309]u8  // ML-DSA-65, label "umbra/v1/community-checkpoint"
}
```

A checkpoint body is 5 431 bytes. The sum is 2 bytes of version and type, 136
bytes of chained fields, and a 32-byte `withdrawn` list. It also holds a
1 952-byte ML-DSA-65 public key and a 3 309-byte ML-DSA-65 signature. The 136
bytes are `community_id` 32, `pseudonym` 32, `start_index` 4, `end_index` 4,
`previous_signed_head` 32, and `current_head` 32. The `B2` L5 payload of Part 6
§6.9 is 8 074 bytes. The `PUB` payload ends with the 3-byte `Admission` of Part
14 §14.2. The `PAGE` framing of §12.3.3 costs 61 bytes for the page and 10 bytes
for a second entry. Thus the checkpoint leaves 2 569 bytes free.

A post record of §12.4.4 with a 200-byte body is 246 bytes, and it fits bucket
`B0`. §12.4.6 gives the storage that a relay holds for one pseudonym.

**The bound of rule 4.** A `CommunityPost` header is 46 bytes, which is version
1, type 1, `pseudonym` 32, `index` 4, `amends` 4, and `body_len` 4. A checkpoint
leaves 2 569 bytes free at `B2`. Rule 4 therefore batches a post record of at
most 2 569 bytes, which holds a body of at most 2 523 bytes. Above that bound
the client sends the post in one cell and the checkpoint in a second `B2` cell.

**The one band where the construction costs more.** A signature on each post
makes a record of the body plus 3 355 bytes. That sum is the 46-byte header and
the 3 309-byte signature. The record fits the 8 074-byte `B2` payload up to a
body of 4 719 bytes. Thus a body from 2 524 to 4 719 bytes costs 8 240 bytes
under the alternative and 16 480 bytes under rule 4. That band is the one case
where the construction costs more. Above 4 719 bytes the alternative needs
bucket `B3` at 32 860 bytes, and rule 4 stays at 16 480 bytes.

**The cost table below counts cells on the wire (Part 6 §6.9), and not payload
bytes.** A `B0` cell costs 560 bytes and a `B2` cell costs 8 240 bytes.

| | Wire cost for each post |
| --- | --- |
| A signature on each post | 8 240 B |
| A checkpoint at N = 1, inside the bound of rule 4 | 8 240 B |
| A checkpoint at N = 2 | 4 400 B |
| **A checkpoint at N = 5** | **2 096 B** |

> **The honest ratio.** The construction saves a factor of 3.9 against a
> signature on each post. It does not save the factor of 14 that a byte-only
> table gives. The amortization denominator is the post rate of one author, and
> no parameter changes that fact. An author that posts one time in an hour gets
> N = 1. At N = 1 the batch of rule 4 costs the same as the alternative. The
> paragraph above gives the one band where the construction costs more.

> **The signing tail.** ML-DSA-65 signing is a rejection loop with a mean of
> 5.10 iterations and no fixed bound. A measured worst case on an embedded ARM
> part is about 20 times the mean. A deadline of a few seconds on a phone has a
> tail that no parameter bounds. A missed deadline destroys the settlement of a
> correct post. That loss is a U6 failure, and `SIG_MAX_AGE` at 60 min removes
> that tail from the delivery path.

A reader verifies a post only after a signed checkpoint that covers that post
arrives. Before that checkpoint, the post is **pending relay data**. It is not
an authenticated statement by the pseudonym. A malicious relay can inject
pending posts, reorder them, or suppress them for a period. That relay cannot
make them settle as authentic, because the device of the author has to sign the
resulting chain head.

**[COM-053]** **A client MUST NOT display a pending post that only one relay serves.** **[COM-054]** A
client MUST hold that post until one of two events. The first event is a second
relay under a different operator that serves the same body at the same triple.
The second event is `PENDING_DEMOTE`.

> *Cause.* `COMMUNITY_MIN_RELAYS` is 3 with different operators. One relay that
> injects a post at an unoccupied index makes no cross-relay divergence, thus
> §12.4.3 does not detect it. This rule costs one pull interval of latency, and
> it removes the single-relay injection path.

**The trade:** a post is not fully verifiable until the next checkpoint arrives,
which can take `SIG_MAX_AGE`. **[COM-055]** A client MUST render a pending post in a visually
different state that does not attribute final authorship. **[COM-056]** A client MUST NOT use
a pending post as moderation evidence.

The table below gives the handling of a post that stays without a checkpoint:

| Elapsed | Client behavior |
| --- | --- |
| < `PENDING_DEMOTE` (90 min) | Shown, and marked visually as pending |
| ≥ `PENDING_DEMOTE` | Removed from the default timeline. The user reaches it under an explicit "unverified" filter |
| ≥ `PENDING_EXPIRE` (24 h) | Hidden from each default view. The client **keeps it locally** and does not destroy it silently |

**[COM-057]** **A client MUST NOT delete a pending post on a short timer.** A short timer
destroys the post of an author if the device of that author loses connectivity
after the publication. U6 does not permit a message that is permanently
undeliverable inside the retention window, thus that loss is a U6 failure. An
expiry hides a post, and an expiry does not erase a post.

A relay can withhold a checkpoint. No goal in Part 2 §2.3 prevents that
behavior, and Part 2 §2.5 gives guaranteed availability as a non-goal. G3 gives
the two limits that do hold. A relay cannot make a post settle as authentic,
because the device of the author has to sign the resulting chain head. A relay
cannot put a different body under a chain link, because that relay holds no
second preimage of SHA3-256. The answer to a withheld checkpoint is detection
and the replacement of the relay, and the answer is not prevention.

One relay can show a pattern of missing checkpoints while the other relays do
not. That pattern is a **checkpoint divergence** (§12.4.3.1 rule 4). **[COM-058]** A client
MUST show that pattern as a relay integrity warning that names the relay. **[COM-059]** A
client MUST NOT absorb it silently as a post expiry.

A checkpoint signature covers this preimage:

```
"umbra/v1/community-checkpoint" || community_id || pseudonym ||
start_index || end_index || previous_signed_head || current_head || withdrawn
```

The `withdrawn` field is a fixed list of `WITHDRAW_MAX` values of `u32`, which
is 32 bytes. Each value names a post index that the author withdraws, and an
unused slot carries the sentinel `0xFFFFFFFF`. `WITHDRAW_MAX` is 8. The field
has a fixed size, thus a checkpoint that withdraws nothing and a checkpoint that
withdraws eight posts have one size. §12.4.5 gives the withdrawal.

Four rules bind the list.

1. **[COM-060]** A withdrawal MAY name any index in the history of that pseudonym. That index
   is not only an index inside the current window.
2. **[COM-061]** A client MUST reject an entry that names an index outside the history of that
   pseudonym.
3. **[COM-062]** A client MUST reject a repeated index.
4. **[COM-063]** A client MUST reject a list that is not in strictly increasing order before
   the run of the sentinel.

The chain head stops truncation and reordering in the signed window. §12.4.4
rule 2 gives the reader each post hash of the window. The reader recomputes the
chain from that list, thus the reader detects a replaced body. §12.4.3 handles a
gap and a divergent checkpoint from different relays.

**[COM-064]** **A future revision MUST NOT fold a community checkpoint signature into a post
identifier.** Part 6 §6.1.1 rule 5 forbids a name that comes from the signature
bytes.

### 12.4.2 Why authenticate at all, given this differs from SimpleX

SimpleX Channels leaves the content messages unauthenticated deliberately, to
keep deniability. UMBRA makes the opposite decision **for communities only**,
and there are three causes:

1. **Resistance to a substitution in settled history.** With unsigned content,
   one compromised relay substitutes or drops posts for an unlimited period. If
   an adversary compromises each relay of a community, no party can detect the
   substitution. UMBRA permits short-lived pending relay data. But the settled
   history carries a signature from the pseudonym of the author.
2. **The deniability is gone before this point.** The content is public. A
   signature over a public post, attributed to a pseudonym, adds no exposure
   beyond the publication itself.
3. **Moderation needs attribution.** A ban on a pseudonym has no meaning if a
   party can forge a post from that pseudonym.

**This trade applies nowhere else.** A 1:1 message and a private-group message
stay unsigned and deniable (Part 5 §5.7). The signature here is over a
*pseudonym that is unlinkable to the person*. Thus it is not a signed
confession. It is a pseudonymous byline.

### 12.4.3 Cross-relay consistency

**[COM-065]** A client MUST verify that the posts from different relays are consistent. **[COM-066]** The
community MUST be the same, and **[COM-067]** the sequence MUST be the same. §12.4.3.1 defines
a gap and gives the settle window of a divergence. **[COM-068]** A client MUST show a
divergence to the user as a **relay integrity warning** that names the relays.

> SimpleX ships the multi-relay architecture. But SimpleX records that the
> detection of cross-relay consistency is **not built**. Without that detection,
> publication to more than one relay gives redundancy only, and it does not
> detect a relay that gives false data. UMBRA makes the detection
> mandatory, because it is the only mechanism that makes the statement "the
> relays are untrusted caches" correct and not aspirational.

#### 12.4.3.1 The definition of a gap

**A gap is an absence with no artifact that the client verified.**

An index inside a window that the client holds in full is in one of four
states.

| State at one relay | Condition | Client behavior |
| --- | --- | --- |
| A body | The relay serves one `CommunityPost` | Verify the chain. Render the post |
| An authorized absence | The relay serves one `PostStub`, and the client verified an artifact of §12.5.2 or an `OperatorRemoval` of §12.4.4 rule 10 that names that index | Verify the chain across the stub. Render the placeholder. This state is **not** a gap |
| A gap | The relay serves no record for that index, and the index is at or above the chain floor of that relay. Or the relay serves a stub and the client verified no artifact that names that index | Show a relay integrity warning that names the relay |
| Pruned | The index is below the chain floor of that relay (§12.4.6) | Show no warning. Keep the local copy if the client holds one, and show the end of the history otherwise |

1. **[COM-069]** A client MUST show a gap as a relay integrity warning that names the relay.
2. The client can verify the artifact for an index. **[COM-070]** In that case the client MUST
   treat a body and a stub at that index as equivalent. That rule applies at
   each relay. **[COM-071]** That client MUST NOT report a divergence.
3. **[COM-072]** If a client holds part of a window, that client MUST NOT report a gap inside
   that window. §12.4.4 rule 7 gives that case.
4. A **checkpoint divergence** is a second and separate condition. One relay
   serves no checkpoint for a window, and a different relay serves one. A client
   checkpoint can be absent from one relay for `SIG_MAX_AGE` plus the maximum
   `PULL_INTERVAL`. **[COM-073]** Before that time passes, a client MUST NOT report a
   checkpoint divergence. **[COM-074]** A client MUST report a divergence that stays past that
   time. **[COM-075]** A client MUST NOT show a
   checkpoint divergence as a post expiry.
5. **[COM-076]** A client MUST apply the settle window of rule 4 to a body divergence at one
   triple. **[COM-077]** A client MUST apply that same window to a stub divergence.
6. **[COM-078]** A client MUST NOT render an indicator on a settled post that comes from
   unsettled data.
7. **[COM-079]** The interface MUST keep a moderator removal, an author withdrawal, and a gap
   apart. They are three different statements about three different parties.

### 12.4.4 The post record and the stub

```
CommunityPost {
    version     u8        // 0x01
    type        u8        // 0x01
    pseudonym   [32]u8
    index       u32       // the position in the chain of that pseudonym
    amends      u32       // the index that this post corrects, or 0xFFFFFFFF
    body_len    u32
    body        [body_len]u8
}

PostStub {
    version     u8        // 0x01
    type        u8        // 0x02
    pseudonym   [32]u8
    index       u32
    post_hash   [32]u8    // SHA3-256(post_n)
}
```

> **These byte values are community record types.** Part 6 §6.1.1 rule 7 gives
> the namespace rule. This namespace holds eight values, and it is the type
> namespace of application kind `0x11` (Part 6 §6.6).
>
> - `0x01` names a `CommunityPost` (§12.4.4).
> - `0x02` names a `PostStub` (§12.4.4).
> - `0x03` names a `ModerationEpoch` (§12.5.2).
> - `0x04` names a `CommunityRoster` (§12.5.2).
> - `0x05` names a `Checkpoint` (§12.4.1).
> - `0x06` names a `CommunityMeta` (§12.7.1).
> - `0x07` names a `CommunityReport` (§12.5.3).
> - `0x08` names a `ModeratorSet` (§12.5.2).
>
> Five other namespaces of Part 6 use the same byte values with different
> meanings. Those namespaces are the cell command (§6.3), the queue command
> (§6.4), the L6 record kind (§6.4.2), the `PqFrame` kind (§6.5), and the
> application kind (§6.6). **[COM-080]** An implementation MUST give the community record type
> its own type. **[COM-081]** An implementation MUST NOT convert that type into another type.

1. **[COM-082]** A relay MUST serve `PostStub` in place of a body that an artifact of §12.5.2
   names. **[COM-083]** A relay MUST NOT serve a stub for a body that no such artifact names.
2. **[COM-084]** If a relay serves a checkpoint, that relay MUST serve a record for each index
   in the window. That record is one `CommunityPost` or one `PostStub`.
3. A checkpoint can name an index outside its own window in the `withdrawn`
   list. **[COM-085]** At that index a relay MUST serve a `PostStub`. That rule applies
   whenever that relay serves a window that holds it.
4. A reader computes `link_n = SHA3-256(link_{n-1} || post_hash)` across an
   absent body. Thus the chain verifies across an authorized removal.
5. The stub carries no reason field. A reason field makes a machine-readable
   redaction ledger at a compellable cache, and it lets a relay choose how an
   absence reads. A client derives the cause from the artifact that the client
   verified, and never from the stub.
6. A `CommunityPost` does not carry `link_n`, and a checkpoint does not cover a
   Merkle root. Rule 2 gives the reader each post hash of the window, thus the
   reader recomputes the chain from `previous_signed_head` to `current_head`.
   That recomputation detects a replaced body, a reordered window, and a
   truncated window.
7. **[COM-086]** If a client holds part of a window, that client MUST NOT verify
   that window. **[COM-087]** That client MUST NOT report a gap inside that
   window. **[COM-088]** The client MUST request the missing indexes from each
   of `COMMUNITY_MIN_RELAYS` relays under different operators. **[COM-089]** If
   an asked relay did not prune a missing index, the client MUST show a relay
   integrity warning. **[COM-090]** That warning MUST name each asked relay that
   did not prune that index. **[COM-221]** If each asked relay pruned a missing
   index, the client MUST NOT show a warning for that index. §12.4.6 gives the
   chain floor and the pruned state.
8. **[COM-091]** A client MUST spread a first-window backfill across two or more
   `PULL_INTERVAL` periods. **[COM-092]** A client MUST NOT issue a pull whose size separates
   a first subscription from a steady-state pull.
9. The `amends` field names the index that this post corrects, and the sentinel
   `0xFFFFFFFF` names no index. §12.4.5 gives the amendment.

10. **The operator removal.** A relay operator can hold a legal order that
    names one post at that relay. Without an artifact, the absence is a gap
    under §12.4.3.1, and the client names the relay in an integrity warning.
    The record below is the third artifact, and it authorizes the absence at
    the relay that signed it.

    ```
    OperatorRemoval {                 // a community record, type 0x09
        version         u8            // 0x01
        type            u8            // 0x09
        community_id    [32]u8
        pseudonym       [32]u8        // the author of the removed post
        index           u32
        post_hash       [32]u8        // SHA3-256(post_n), as in the PostStub
        relay_id        [32]u8        // Part 10 §10.5.3
        issued_at       u64           // Unix seconds, the clock of the relay
        signature       [3309]u8      // ML-DSA-65, "umbra/v1/operator-removal"
    }
    ```

    An `OperatorRemoval` is 3 451 bytes. The signature covers
    `"umbra/v1/operator-removal" || the bytes up to and not including
    signature`, under the identity key of the descriptor of `relay_id`. Part 5
    §5.11 holds the label.

    - **[COM-357]** A relay that removes a body under a legal order MUST serve
      an `OperatorRemoval` beside the stub. **[COM-358]** A relay MUST sign it
      under the identity key of its own descriptor.
    - **[COM-359]** A client MUST verify the signature against the descriptor
      of `relay_id`. **[COM-360]** A client MUST treat a stub with a verified
      `OperatorRemoval` as an authorized absence at that relay only.
      **[COM-361]** A client MUST NOT apply an `OperatorRemoval` at a different
      relay. **[COM-362]** A client that holds another relay of the community
      MUST fetch the body from that relay.
    - **[COM-363]** A client MUST render an operator removal differently from a
      moderator removal and from an author withdrawal.

    > *Cause.* An earlier draft let two artifacts authorize a stub, and both
    > needed a pseudonym key that a relay does not hold. A relay under a legal
    > order then had two options. It served the body and broke the order, or it
    > dropped the body and each client named it as a misbehaving relay. The
    > third artifact names the relay, thus the removal is attributable. It binds
    > one relay, thus the post stays at each other relay of §12.2.

> **The stub commits to the removed body.** `post_hash` is a hash of content
> that a party removed. A party that guesses a low-entropy post confirms that
> guess against the stub. This residual is acceptable here and only here,
> because §12.1 states that community content is public at publication. **[COM-093]** A
> private-group tombstone MUST NOT carry a hash of the deleted plaintext.


### 12.4.5 The author withdrawal and the amendment

An author withdraws a post, and an author amends a post. The chain of §12.4.1 is
append-only, thus neither operation removes `SHA3-256(post_n)`. Each operation
stops a conforming relay from serving the body.

**The withdrawal rides the checkpoint that already happens.** A withdrawal is
not a new record type. The `withdrawn` field of the checkpoint signature carries
it, and §12.4.1 gives the four rules that bind that list.

**[COM-094]** **A client MUST NOT publish a checkpoint whose cause is a withdrawal.** A
withdrawal travels in the next checkpoint that the ordinary cadence of §12.4.1
rule 1 produces. §12.4.1 rule 3 states the same prohibition for a checkpoint
that covers zero new posts.

> *Cause.* An author publishes a checkpoint on the ordinary cadence whatever
> happens. A withdrawal that changes a field inside that checkpoint creates no
> new event at a relay. An idle author that emits an out-of-cadence signed
> object a fixed delay after a user action publishes a per-pseudonym withdrawal
> beacon. Each relay and each subscriber then reads that beacon. A randomized
> delay does not remove it, because the object itself is the signal.

An author that does not post again does not withdraw. **[COM-095]** The interface MUST state
this plainly. **[COM-096]** The interface MUST NOT show a withdrawal as complete
before the checkpoint publishes. `SIG_MAX_AGE` is 60 min, thus an active author
withdraws inside about 63 minutes, which is `SIG_MAX_AGE` plus one maximum
`PULL_INTERVAL`. An idle author withdraws at the next post.

**The relay behavior.** **[COM-097]** A relay MUST serve `PostStub` in place of a body that a
verified checkpoint withdraws. §12.5.2 rule 3 gives the artifact rule without a
change, and the justifying artifact is the checkpoint signature in place of a
moderation epoch. A relay cannot fabricate a withdrawal, because a relay cannot
sign as the pseudonym. A relay that drops a body with no verified artifact makes
a **gap** under §12.4.3.1. §12.4.3 then requires the relay integrity warning
that names that relay.

**The residual, stated.** A withdrawal is a permanent, public, and
pseudonym-attributed pointer at the post that the author wanted gone. A party
that mirrors the community holds the body already, and `PULL_INTERVAL` is 30 to
180 seconds. Thus a post is public within minutes of its publication.

Four mitigations bound the damage.

1. The pointer sits inside a checkpoint that publishes anyway, thus it is not a
   distinguishable event.
2. The field has a fixed width, thus a withdrawal has no size signature.
3. The withdrawal waits for a checkpoint that the ordinary cadence produces,
   thus no object appears whose cause is the user action.
4. The interface states plainly that a party which read the post keeps it.

**This feature works against a future reader and a casual reader. It does not
work against a party that archived the community.** Part 16 §16.3 records that
residual.

**The amendment.** An amendment is an ordinary post, and its `amends` field
names the index that it corrects. An amendment adds text and removes nothing. An
author that also wants the earlier body gone withdraws that index in the same
checkpoint. Thus one mechanism serves a correction and a replacement.

- **[COM-098]** A client MUST render an amended post beside its amendment.
  **[COM-099]** A client MUST mark the earlier post as amended.
- **[COM-100]** If the earlier body is withdrawn, the client MUST show the `PostStub`
  placeholder of §12.4.4 in its place.
- **[COM-101]** A client MUST reject an `amends` value that names an index outside the history
  of that pseudonym. **[COM-398]** The history of a post ends below its own
  `index`, thus a party MUST reject a `CommunityPost` whose `amends` is not
  the sentinel and is at or above its `index`.

**What the interface states to an author.**

- Withdraw: "This stops the relays from giving out your post. A person who
  already read it keeps it. A person who copies the community keeps it. Your
  post stops being served in about an hour, and not at once."
- **[COM-102]** The interface MUST state that the withdrawal is permanent and public:
  "Readers see that you withdrew a post here. You cannot remove that mark."
- Amend: "This adds a correction beside your post. Choose to withdraw the
  earlier text as well, or leave it in place."

**What the interface states to a reader.**

- **[COM-103]** A removed post: the interface MUST show a placeholder that names the index and
  reads "a moderator removed this post". **[COM-104]** The entry MUST NOT vanish without a
  trace.
- **[COM-105]** A withdrawn post: the interface MUST show a placeholder that reads "the author
  withdrew this post". **[COM-106]** The interface MUST NOT use the moderator wording.
- **[COM-107]** An unexplained absence: the interface MUST show a relay integrity warning that
  names the relay. **[COM-108]** The interface MUST NOT show it as a removal or as a
  withdrawal.

Part 7 §7.5.7 prohibits one shared deletion affordance for a community and a
private conversation.

### 12.4.6 Retention and the pruned index

§12.2 makes a relay a cache, and a cache has a bound. This section gives that
bound. A relay keeps a post record for `COMMUNITY_RETENTION`, and it then prunes
the record. A pruned index is not a gap, and a client shows no warning for it.

**What a relay keeps.**

- **[COM-222]** A relay MUST keep a `CommunityPost`, a `PostStub`, and a
  `Checkpoint` for `COMMUNITY_RETENTION` after the relay accepts the record.
  **[COM-223]** A relay MUST NOT prune such a record before that time to make
  space.
- **[COM-224]** A relay MUST keep each record of the control chain and each
  `CommunityMeta` while it serves that community. §12.3.3 gives the three
  record types of the control chain. A join reads the control chain from `epoch_index` 0
  under `COM-196`, thus that chain has no retention bound.
- **[COM-225]** After `COMMUNITY_RETENTION`, a relay MAY prune a record. The
  two rules below give the order of a prune.
- **[COM-226]** A relay MUST prune a window as one unit, which is the
  `Checkpoint` and each record that it covers. Thus `COM-084` holds at each
  moment. **[COM-227]** A relay MUST NOT prune an index of a chain while it
  holds a lower index of that chain.

**The chain floor.** The **chain floor** of a pseudonym at one relay is one
above the highest index that the relay pruned from that chain. If the relay
pruned nothing, the chain floor is 0. The `floor` field of a `PullResponse`
under selector `0x02` carries it (§12.3.3). Each index below the chain floor is
**pruned** at that relay.

- **[COM-228]** A relay MUST reject a `PUB` of a `CommunityPost` whose `index`
  is below the chain floor of its pseudonym. **[COM-229]** A relay MUST reject a
  `PUB` of a `Checkpoint` whose `start_index` is below that chain floor. Thus a
  chain floor does not move down, and a second publication does not restart
  the retention of a pruned record.
- **[COM-230]** A client MUST treat an index below the chain floor of a relay
  as pruned at that relay. **[COM-231]** A client MUST NOT show a relay
  integrity warning for a pruned index. **[COM-232]** A client MUST NOT count a
  pruned index as a gap under §12.4.3.1. **[COM-233]** A client MUST NOT report
  a divergence between a relay that serves an index and a relay that pruned it.
- **[COM-234]** A client MAY keep a post that a relay pruned. The local history
  belongs to the user, and a prune at a relay does not delete it.

**The storage bound.** A pseudonym publishes at most `POST_RATE_LIMIT` posts in
an hour. A post record is at most 8 013 bytes, which is the 46-byte header and
`MAX_POST_SIZE`. Over `COMMUNITY_RETENTION` of 90 days that is 43 200 posts and
346.2 MB. `SIG_INTERVAL` gives one checkpoint for each 5 posts, which is 8 640
checkpoints at 5 431 bytes, or 46.9 MB. Thus one pseudonym costs a relay at
most 393.1 MB.

A typical author posts 5 times in a day with a 200-byte body. Over 90 days that
author holds 450 posts at 246 bytes, which is 110 700 bytes. The 90 checkpoints
at 5 431 bytes are 488 790 bytes. The sum is 599 490 bytes, and the checkpoints
are 82 % of it. A community of 1 000 such authors costs each of its relays about
600 MB.

- **[COM-235]** A relay whose store is full MUST reject a `PUB` of a
  `CommunityPost`. **[COM-236]** That relay MUST signal a capacity fault to the
  directory, in the manner of Part 13 rule `ATT-091`.
- **[COM-237]** A revision that changes `POST_RATE_LIMIT`, `MAX_POST_SIZE`,
  `SIG_INTERVAL`, or `COMMUNITY_RETENTION` MUST derive this section again.

**The attachment of a post.** A chunk of Part 13 lives `CHUNK_TTL`, which is 45
days, and a post lives `COMMUNITY_RETENTION`. Part 13 §13.3.3 gives `CRNW`,
which sets the erase time of a chunk to `CHUNK_TTL` after the renewal.
`CHUNK_LIFE_MAX` bounds the life of a chunk at 90 days.

- **[COM-238]** A client that fetches a chunk from a community record MUST send
  a `CRNW` for it in that session. Thus an attachment lives as long as a party
  reads its post, and not past the post.

**The re-seed.** An owner adds a relay to the `relays` list of a
`CommunityMeta` (§12.7.1). That relay holds nothing, and its chain floors are 0.

- **[COM-239]** An owner client that adds a relay MUST publish the control chain
  and each `CommunityMeta` to that relay. The control chain starts at
  `epoch_index` 0. **[COM-240]** That client MUST then publish to the new relay
  each record inside `COMMUNITY_RETENTION` that it holds, newest window first.
  **[COM-241]** A re-seed MUST publish a window in full, with its `Checkpoint`.

`POST_RATE_LIMIT` bounds a re-seed at 20 posts in an hour for each chain under
`COM-211`. Thus a new relay holds the full history of a busy chain after days.
The newest window first gives a subscriber the current posts at once.

> *Cause.* An earlier draft gave a relay no retention rule. A relay then held
> each post forever, or it pruned by a policy that no client could read. A
> client then showed a relay integrity warning for each pruned index, and an
> honest relay looked like a hostile one. The chain floor makes the prune
> visible in the protocol, and rule `COM-227` makes the floor one number.

### 12.4.7 An attachment in a community post

`MAX_POST_SIZE` of §12.9 sends larger content to an attachment, and this
section gives that attachment its carrier. A community post is public at
publication (§12.1), thus the `file_key` of the descriptor is public too.

- **[COM-340]** A `CommunityPost` MAY carry a `RichRecord` whose `inner_kind`
  is `0x02`, which is a `FileDescriptor` of Part 13 §13.3. **[COM-341]** Before
  the upload, the client MUST state that each party with the link reads the
  file.
- **[COM-342]** A reader that renews a chunk of a community attachment MUST
  send the `CRNW` of Part 13 §13.3.3. §12.7.1 gives the same renewal for an
  icon.
- **[COM-343]** A client MUST NOT download a community attachment without a
  user action, unless the user set an automatic download for that community.
  Part 13 §13.9 holds the row of this client of the chunk path.

## 12.5 Moderation

- The roles are `owner`, `admin`, `moderator`, `member`, and `observer`. **[COM-109]** A
  community MUST have two or more independent owners, and §12.5.2 rule 10 gives
  the cause. An M-of-N owner multisig is a future extension.
- The moderation of a community uses two objects, and **Part 11 §11.9 does not
  apply to a community**. A private group has no authoritative party. A
  community has the owner devices of §12.2. The two topologies are different,
  thus Part 12 states its own rules.

  A **community roster** gives the owner role or the admin role, or it takes
  that role away. A **moderator set** gives the moderator role, or it takes
  that role away. A **community moderation epoch** names a content action. The
  actions are the removal of a post, a ban on a pseudonym, a pin, a lock, and
  the reverse of each one. §12.5.2 gives the field list of each object, the
  signature preimage, the chain of authority, and the artifact rule. §12.3.2
  gives the key.

  - **[COM-110]** A community roster MUST carry a signature from the role pseudonym of an
    owner.
  - **[COM-292]** A moderator set MUST carry a signature from the role
    pseudonym of an owner or of an admin.
  - **[COM-111]** A moderation epoch MUST carry a signature from the role pseudonym of an
    owner, an admin, or a moderator.
  - Each object chains to the object before it, and §12.5.2 rule 6 gives the
    fork rule.
- A relay enforces the moderation as a **cache policy** and not as an authority.
  A relay drops the content that the signed moderation epoch names. If a relay
  refuses, the cross-relay consistency check detects that refusal, and the
  clients can drop that relay.
- **Ban evasion has no solution** in a system with no stable identity, and UMBRA
  makes no different claim. A banned user makes a new pseudonym. The mitigations
  are the relay-local rate limit of §12.3.2, the escalation of the posting cost
  under load (Equi-X, Part 14 §14.8), and moderator tools. Identity is not a
  mitigation.

### 12.5.1 Abuse reporting

Abuse reporting uses onion franking. The scope is communities only. UMBRA does
not frank a 1:1 message or a private-group message. UMBRA does not build a
global moderator key.

The designated verifier of an abuse report is the `RoleReportKey_r` of §12.3.2.
**[COM-112]** The community roster MUST name the role pseudonym of that key in
the admin role or above. A moderator is in the moderator set of §12.5.2, which
holds no report key, thus a moderator is not a designated verifier. **[COM-113]** An implementation MUST use that
definition in Part 14 §14.10. **[COM-152]** A reporter MUST take the
encapsulation key from the `report_ek` field of the `RosterEntry` of §12.5.2.
**[COM-153]** A reporter MUST NOT use an ML-DSA-65 key as the designated
verifier key. A franked abuse
report is moderation evidence at the moment it verifies, and it does not wait
for a checkpoint. §12.5.3 gives the report object, its carrier, and the queue
that receives it.

### 12.5.2 The community roster, the moderation epoch, and the artifact rule

```
CommunityRoster {
    version         u8            // 0x01
    type            u8            // 0x04
    community_id    [32]u8
    epoch_index     u32
    previous_epoch  [32]u8
    actor           [32]u8        // the role pseudonym of the signer
    actor_pk        [1952]u8      // the ML-DSA-65 public key of that role pseudonym
    entry_count     u8
    entries         [entry_count]RosterEntry
    cosign_count    u8            // 0, or the owner cosignatures of rule 12
    cosigns         [cosign_count]RosterCosign
    signature       [3309]u8      // ML-DSA-65, label "umbra/v1/community-roster"
}

RosterCosign {
    actor           [32]u8        // an owner role pseudonym of the roster before this one
    actor_pk        [1952]u8      // the ML-DSA-65 public key of that role pseudonym
    signature       [3309]u8      // ML-DSA-65, the preimage of signature
}

RosterEntry {
    role            u8            // 1 owner, 2 admin
    pseudonym       [32]u8        // the role pseudonym of that member
    report_ek       [1216]u8      // UMBRA-KEM encapsulation key of that role
    report_queue    QueueAddress  // 129 bytes, Part 6 §6.6.10, the report queue of §12.5.3
}

ModerationEpoch {
    version         u8            // 0x01
    type            u8            // 0x03
    community_id    [32]u8
    epoch_index     u32
    previous_epoch  [32]u8
    actor           [32]u8        // the role pseudonym of the signer
    actor_pk        [1952]u8      // the ML-DSA-65 public key of that role pseudonym
    actor_role      u8
    action_count    u8            // 1 to MOD_ACTION_MAX
    actions         [action_count]ModerationAction
    signature       [3309]u8      // ML-DSA-65, label "umbra/v1/community-moderation"
}

ModerationAction {
    kind            u8            // the table below
    target          [32]u8        // the community pseudonym, or zero bytes
    index           u32           // the table below
}

ModeratorSet {
    version         u8            // 0x01
    type            u8            // 0x08
    community_id    [32]u8
    epoch_index     u32
    previous_epoch  [32]u8
    actor           [32]u8        // the role pseudonym of the signer, owner or admin
    actor_pk        [1952]u8      // the ML-DSA-65 public key of that role pseudonym
    entry_count     u16           // 0 to MODERATOR_MAX
    entries         [entry_count][32]u8   // the role pseudonym of each moderator
    signature       [3309]u8      // ML-DSA-65, label "umbra/v1/moderator-set"
}
```

§12.4.4 names the namespace of the `type` byte. The value `0x03` names a
`ModerationEpoch`, the value `0x04` names a `CommunityRoster`, and the value
`0x08` names a `ModeratorSet`.

| `kind` | Name | `target` | `index` |
| --- | --- | --- | --- |
| 1 | Remove a post | the pseudonym | the post index |
| 2 | Ban a pseudonym | the pseudonym | the highest index that the ban removes, or `0xFFFFFFFF` for a ban with no removal |
| 3 | Pin a post | the pseudonym | the post index |
| 4 | Lock the community | zero bytes | the duration in seconds, or `0xFFFFFFFF` until an unlock |
| 5 | Unban a pseudonym | the pseudonym | `0xFFFFFFFF` |
| 6 | Unpin a post | the pseudonym | the post index |
| 7 | Unlock the community | zero bytes | `0xFFFFFFFF` |
| 8 | Restore a post | the pseudonym | the post index |

**The action kinds.**

- **[COM-295]** A client MUST reject a `ModerationEpoch` that carries a `kind`
  outside the table. **[COM-296]** A client MUST apply the actions on one
  (`target`, `index`) pair in chain order. The last action gives the state.
- **[COM-297]** If a kind 2 action carries an `index`, a relay MUST serve a
  `PostStub` at each index of `target` up to it. The sentinel `0xFFFFFFFF`
  carries no index. **[COM-298]** A relay MUST reject a `PUB` from a banned
  pseudonym until an action of kind 5 names that pseudonym.
- **[COM-299]** A relay MUST keep a removed body for the retention of
  §12.4.6. **[COM-352]** A relay MUST NOT serve a removed body while the
  removal stands. **[COM-300]** If a kind 8 action names an index whose body
  the relay holds, the relay MUST serve that body again. **[COM-301]** If a
  restore stands and a relay still serves a stub, the client MUST show the
  restore as pending. **[COM-302]** The client MUST NOT
  show a relay integrity warning for that stub.
- **[COM-303]** A client MUST show a pinned post at the top of the timeline
  until an action of kind 6 names it.
- **[COM-304]** While a lock stands, a relay MUST reject a `PUB` of a
  `CommunityPost`. **[COM-305]** A relay MUST measure a lock duration from its
  acceptance of the epoch. **[COM-353]** A client MUST measure a lock duration
  from its verification of the epoch. **[COM-306]** A client MUST show a lock
  and its end. **[COM-354]** A client MUST NOT let the user compose a post
  while a lock stands.

> *Cause.* An earlier draft had four kinds and no reverse. Thus a ban, a pin,
> and a lock were permanent, and a removal in error stayed. A ban with a
> removal of the history took one action for each post, at `MOD_ACTION_MAX`
> actions in one epoch. Kind 2 now folds the removal into the ban with one
> index, thus one action clears a spam chain. The `ModerationAction` keeps its
> 37 bytes, and no total of this section changes.

The signature of a `CommunityRoster` covers this preimage:

```
"umbra/v1/community-roster" || version || type || community_id || epoch_index ||
previous_epoch || actor || actor_pk || entry_count || entries
```

The signature of a `ModerationEpoch` covers this preimage:

```
"umbra/v1/community-moderation" || version || type || community_id ||
epoch_index || previous_epoch || actor || actor_pk || actor_role ||
action_count || actions
```

The signature of a `ModeratorSet` covers this preimage:

```
"umbra/v1/moderator-set" || version || type || community_id || epoch_index ||
previous_epoch || actor || actor_pk || entry_count || entries
```

The three labels are different, because the three objects are different types.
Part 5 §5.11 holds each label.

**The chain fields.** The three object types share one chain, and `epoch_index`
counts across them.

- **[COM-377]** `previous_epoch` MUST be the SHA3-256 of the predecessor bytes
  that its signature covers, without the label. It is zero bytes at
  `epoch_index` 0. No signature byte enters the value, thus `COM-022` holds
  for the control chain too, and two signatures over one object give one
  identifier.
- **[COM-378]** A verifier MUST reject an object whose `epoch_index` is not
  one above the `epoch_index` of the object that `previous_epoch` names.
- **[COM-381]** The `actor_role` byte MUST be 1 for an owner, 2 for an admin,
  and 3 for a moderator, and a verifier MUST reject an epoch whose
  `actor_role` differs from the role that rule 5 gives the `actor`.
  **[COM-382]** An action of kind 4 or kind 7 MUST come from an admin or an
  owner, because a lock stops each author of the community. Each other kind
  MAY come from a moderator.
- **[COM-383]** The `entries` of a `ModeratorSet` MUST be in strictly
  increasing byte order. **[COM-384]** A `CommunityRoster` MUST NOT name one
  `pseudonym` in two entries.
- **[COM-385]** The `CommunityRoster` at `epoch_index` 0 MUST name its `actor`
  in an owner entry, and it MUST carry no cosignature.

A `ModerationAction` is 37 bytes. A moderation epoch at `MOD_ACTION_MAX` is
6 105 bytes, and it uses bucket `B2`. That total is 104 bytes of fields, a
1 952-byte public key, 20 actions at 37 bytes, and a 3 309-byte signature. The
`B2` L5 payload of Part 6 §6.9 is 8 074 bytes, thus that object fits one `B2`
cell.

A `RosterEntry` is **1 378 bytes**. That is 1 byte of role, 32 bytes of
pseudonym, a 1 216-byte encapsulation key, and a 129-byte queue address. A
community roster at `ROSTER_ENTRY_MAX` is **31 547 bytes** with no
cosignature, and it uses bucket
`B3`. That total is 104 bytes of fields, a 1 952-byte public key, 19 entries at
1 378 bytes, and a 3 309-byte signature. Part 6 §6.9 gives the `B3` L5 payload
32 650 bytes, thus the object fits one `B3` cell. A 20th entry would take the
object to 32 924 bytes, which is above that payload, thus `ROSTER_ENTRY_MAX` is
19. **[COM-146]** A client MUST reject a
`CommunityRoster` with more than `ROSTER_ENTRY_MAX` entries. **[COM-147]** A
revision MUST derive this total again if it adds a field to `RosterEntry` or
raises `ROSTER_ENTRY_MAX`.

A `ModeratorSet` has 5 365 bytes of fixed fields, which are 104 bytes of
fields, a 1 952-byte public key, and a 3 309-byte signature. At `MODERATOR_MAX`
it is **30 965 bytes**, and it uses bucket `B3`. `COM-181` and `COM-182` bound
a record in a `PAGE` at 32 589 bytes. 850 entries give 32 565 bytes, thus 850
is the largest count that fits. `MODERATOR_MAX` is 800, and the 50 entries
of margin cover a later field. **[COM-293]** A client MUST reject a
`ModeratorSet` with more than `MODERATOR_MAX` entries. **[COM-294]** A revision
MUST derive this total again if it adds a field to `ModeratorSet` or raises
`MODERATOR_MAX`.

> *Cause of the split.* An earlier draft put a moderator in the
> `CommunityRoster`. Each entry carried a report key and a report queue at
> 1 378 bytes. `ROSTER_ENTRY_MAX` then bounded a community of 100 000 at 19
> role holders in total. A community of that size needs hundreds of
> moderators, and a moderator needs no report key. The `ModeratorSet` holds 32
> bytes for each moderator, and the roster keeps the two roles that receive a
> report. Part 2 §2.4.2 goal S4 names this bound.

> *The cost of the report key, stated.* An earlier draft gave a `RosterEntry` 33
> bytes, and a roster with 8 entries was 5 628 bytes in one `B2` cell. The
> report key of §12.3.2 makes an entry 1 249 bytes and it moves the object to
> `B3` at 32 860 bytes on the wire. The report queue of §12.5.3 makes an entry
> 1 378 bytes, and it takes one entry from the maximum. A community roster
> changes at a role change only, thus that cost is rare. The alternative is one report key for the whole
> community, and each moderator would then hold one private key. §12.3.2 keeps
> each role independent, and this specification pays the bytes for that
> property.

1. §12.3.2 gives the generation of a community pseudonym and of a role
   pseudonym. §12.3.2 gives `pseudonym_g = SHA3-256(pk)` as the 32-byte
   identifier. A role pseudonym has no checkpoint, because a role pseudonym does
   not post. A `CommunityRoster` and a `ModerationEpoch` therefore carry the
   public key of the signer in `actor_pk`. **[COM-114]** Before a client verifies the
   signature, that client MUST hash `actor_pk`. **[COM-115]** If that hash differs from
   `actor`, the client MUST reject the object.
2. **[COM-116]** An action of kind 1 MUST name the pair (`target`, `index`). **[COM-117]** A client MUST NOT
   resolve a removal by the index alone. Each pseudonym holds a separate chain,
   and each chain starts at index 0.
3. **[COM-118]** A relay MUST serve the artifact that justifies a stub, beside that stub.
   **[COM-396]** For a moderation epoch that means selector `0x03`, and for
   a checkpoint it means selector `0x02`, at the relay that serves the stub.
   An `OperatorRemoval` MUST follow its stub in the same `PAGE`, and the
   relay gives it a `seq` of its own under selector `0x01`.
   Exactly three artifacts authorize a stub. The first is a moderation epoch
   that names the index. The second is a checkpoint whose `withdrawn` list
   names the index. The third is an `OperatorRemoval` of §12.4.4 rule 10, which
   authorizes the absence at the relay that signed it and nowhere else.
4. **[COM-119]** A client MUST verify the artifact before that client accepts the absence. The
   verification has three steps. The client checks that `community_id` matches.
   The client checks the chain of authority of rule 5. The client verifies the
   ML-DSA-65 signature.
5. The chain of authority starts at the genesis key. §12.2 gives the community
   identity, and §12.2 states that `genesis_root_public_key` is the ML-DSA-65
   public key of an owner role pseudonym. **[COM-120]** If `epoch_index` is 0, the
   client MUST check that
   `SHA3-256("umbra/v1/community-id" \|\| admission \|\| actor_pk)` equals
   `community_id`. **[COM-121]** A client MUST reject a moderation
   epoch that neither the current `CommunityRoster` nor the current
   `ModeratorSet` authorizes. **[COM-122]** That `CommunityRoster` or that
   `ModeratorSet` MUST name the `actor` in a role that permits the action. **[COM-123]** A
   client MUST reject a `CommunityRoster` that an owner role pseudonym did not
   sign. **[COM-309]** A client MUST reject a `ModeratorSet` that no owner or admin
   role pseudonym of the current `CommunityRoster` signed.
6. **The chain, the concurrent successor, and the fork.** A community has two or
   more owners (rule 10) and more than one moderator. Thus two authorized
   parties can make a valid successor to one epoch at the same time. **That
   event is normal use, and it is not evidence of an attack.**

   - **[COM-124]** A client MUST reject an epoch whose `previous_epoch` names an object that
     the client cannot obtain. **[COM-135]** Before that rejection, the client MUST request
     the named object from the relay that served the epoch. A client that is
     behind the chain fetches, and it does not reject.
   - **[COM-136]** If two verified successors name one `previous_epoch` and **two different**
     values of `actor` sign them, the client MUST select one successor by the
     order below. **[COM-137]** The client MUST NOT show a fork for that case.

     1. The role precedence of the signer, which is owner, then admin, then
        moderator. The current `CommunityRoster` or the current `ModeratorSet`
        gives that role.
     2. If that does not resolve the two, the lower
        `SHA3-256(previous_epoch || actor)` in byte order.

     > *Cause of the hash.* An earlier draft took the lower `actor` in byte
     > order. A party grinds a role pseudonym with a low value in seconds. That
     > pseudonym then wins each race for the life of the community. The
     > hash binds the order to `previous_epoch`, which no party knows before
     > the race starts. Part 11 rule `GRP-117` takes the same order.

   - **[COM-138]** A client MUST NOT apply an entry of a `CommunityRoster` or
     of a `ModeratorSet` that it did not select.
   - **[COM-307]** A client MUST apply each action of a verified
     `ModerationEpoch` that names the selected `previous_epoch`. That rule
     holds whether or not the client selected that epoch. **[COM-308]** If two
     such epochs reverse each other on one `target` and `index`, the client
     MUST apply the selected epoch.
   - **[COM-139]** An actor whose `CommunityRoster` or `ModeratorSet` the
     network did not select MUST publish that object again against the
     selected epoch. **[COM-140]** That actor MUST
     use a new `epoch_index` and a new `previous_epoch` for that publication.
   - **[COM-141]** A client MUST NOT show an action as applied before that action lands on
     the selected chain.
   - **[COM-125]** If two verified successors name one `previous_epoch` and **one** value of
     `actor` signs them, the client MUST show the fork and MUST name that actor.
     That actor equivocated. **[COM-126]** That client MUST NOT select one successor
     silently.

   > *Cause.* An earlier draft treated each pair of successors as a fork and
   > required an alarm. Two moderators that act inside one minute produce that
   > pair on the ordinary path, thus the alarm fired on normal use and the
   > roster chain stopped. Part 11 §11.9.4 already resolves the same condition
   > for a private group with a deterministic order, and this rule takes that
   > order. The alarm now names the one condition that is evidence, which is one
   > signer that made two successors. A later draft applied the actions of
   > each sibling epoch under `COM-307`. Under the selection alone, a removal
   > that lost the selection stayed unapplied until its actor published it
   > again. A moderator that acts one time in a minute lost that race often. A
   > roster entry cannot take the same path. Two rosters at one index can name
   > different role holders, and the chain needs one current roster.
7. **[COM-127]** If a verification of rule 4 fails, a client MUST NOT have changed any record.
   A client applies an action only after each step of rule 4 succeeds.
8. **[COM-128]** A client MUST render a moderator removal and an author withdrawal
   differently.
9. **[COM-129]** A client MUST NOT render a cause that a stub states. §12.4.4 rule 5 gives the
   cause of that rule.
10. **[COM-130]** A community MUST have two or more owners. One owner is one point of failure
    for the moderation, and U6 does not permit that condition.
11. **The rate of the control chain.** **[COM-310]** A relay MUST reject a
    `ModerationEpoch` above `MOD_EPOCH_RATE` for one `actor`. **[COM-311]** A
    relay MUST reject a `ModerationEpoch` above `MOD_EPOCH_COMMUNITY_RATE` for
    one community. **[COM-312]** A relay MUST reject a `CommunityRoster` or a
    `ModeratorSet` above `ROSTER_RATE` for one community. **[COM-313]** A client
    MUST NOT walk more than `MOD_CHAIN_FETCH_MAX` predecessors under `COM-135`
    for one epoch. **[COM-355]** At that bound, the client MUST reject the
    epoch. Part 11 rule
    `GRP-076` discards an over-limit epoch of a group in the same manner.

12. **The owner majority.** **[COM-364]** A `CommunityRoster` that drops an
    owner entry MUST carry cosignatures from more than half of the current
    owners. The signer counts as one of them.
    **[COM-365]** A client MUST reject such a roster with fewer cosignatures.
    **[COM-366]** A cosignature MUST cover the preimage of `signature`, under
    the key of the named owner. **[COM-367]** A client MUST reject a roster
    whose `cosign_count` is not 0 and whose entries drop no owner.
    **[COM-379]** A verifier MUST apply rule 1 to the `actor_pk` of each
    cosignature, and it MUST reject a roster with a cosignature of its
    signer, of one owner two times, or of a party that the roster before it
    does not name as an owner. An owner that is demoted to admin counts as
    dropped. **[COM-380]** A `CommunityRoster` with its cosignatures MUST fit
    the 32 589 bytes of one `PAGE` record. A `RosterCosign` is 5 293 bytes,
    thus a roster with 1 cosignature holds 15 entries at the most, 2 give 12,
    3 give 8, and 4 give 4. A community that needs more drops the owner in one
    epoch and adds the other role holders again in the next, which needs no
    cosignature.

    > *Cause of the key.* A `RosterEntry` holds a report key and no signing
    > key. An owner that never signed a control object showed its ML-DSA-65
    > key nowhere, thus no verifier could check its cosignature. The key in
    > the cosignature costs 1 952 bytes on the rare epoch that drops an
    > owner, and a key in each `RosterEntry` would cost that on each roster.

    > *Cause.* An earlier draft let one owner sign a roster that removed each
    > other owner. Thus one seized owner device or one hostile owner took a
    > community in one epoch. `COM-130` requires two or more owners, and this
    > rule gives that count its meaning. A community with two owners needs
    > both to remove one, thus a lone hostile owner removes nobody. Part 2
    > §2.4 states that trade.

> **Why a relay cannot forge either artifact.** A relay holds no pseudonym key.
> Thus a relay cannot sign a checkpoint and cannot sign a moderation epoch under
> a pseudonym that the roster names. A relay that drops a body with no artifact
> makes a gap under §12.4.3.1. §12.4.3 then requires a relay integrity warning
> that names that relay.

### 12.5.3 The report record and the report queue

A report is a community record of type `0x07`, and it travels to one role
holder in a **report record**. The report record is an L6 record of Part 6
§6.4.2, with kind `0x03`. A community has no push channel to a role pseudonym.
Thus each role holder owns one **report queue** at a queue relay, and its
`RosterEntry` publishes the `QueueAddress` of that queue. Each member of the
community holds the roster, thus each member can write to that queue.

```
CommunityReport {                 // a community record, type 0x07
    version       u8              // 0x01
    type          u8              // 0x07
    community_id  [32]u8
    pseudonym     [32]u8          // the authoring pseudonym of the reported post
    index         u32             // the index of that post in the chain of that pseudonym
    post_hash     [32]u8          // SHA3-256 of the CommunityPost, as in a PostStub
    reason        u8              // the table below
    note_len      u8              // 0 to REPORT_NOTE_MAX
    note          [note_len]u8    // UTF-8
}

ReportRecord {                    // the L6 plaintext of kind 0x03, after the kind byte
    kem_ct        [1120]u8        // UMBRA-KEM.Encap( report_ek ), Part 5 §5.3
    nonce         [12]u8          // from the device CSPRNG
    ct            [n]u8           // ChaCha20-Poly1305( K_rep, nonce, AppMessage ), holds the 16-byte tag
}

K_rep = HKDF-SHA3-256( salt = "umbra/v1/report-key", ikm = ss, L = 32 )
```

The value `ss` is the shared secret of the encapsulation. The `AppMessage`
inside `ct` has kind `0x11`, and its body is the `CommunityReport`. The
associated data of `ct` is `kem_ct`. Part 5 §5.11 holds the label.

| `reason` | Name |
| --- | --- |
| `0x01` | Spam |
| `0x02` | Harassment |
| `0x03` | Illegal content |
| `0x04` | A breach of the community rules of §12.7.1 |
| `0x05` | Other |

**The list above is closed.** A revision that adds a reason adds a row.

**The size.** A `CommunityReport` is 104 bytes plus the note, and
`REPORT_NOTE_MAX` is 200. The `AppMessage` header is 30 bytes. Thus the L6
plaintext is at most 1 148 + 30 + 304 = 1 482 bytes. Part 6 §6.9 gives the
`B1` L6 record 1 926 bytes. **[COM-266]** A reporter MUST send a report record
in bucket `B1`. **[COM-267]** A revision MUST derive this total again if it
changes `REPORT_NOTE_MAX` or adds a field.

**The reporter.**

1. **[COM-268]** A reporter MUST select one entry of the current
   `CommunityRoster` with the device CSPRNG. **[COM-287]** Each entry MUST
   have the same probability. **[COM-269]** A reporter MUST NOT select an entry by its role,
   by its position, or by an earlier selection. Thus no role holder receives
   each report, and no reporter selects its own moderator.
2. **[COM-270]** A reporter MUST encapsulate to `report_ek` of that entry with
   `UMBRA-KEM`, and it MUST derive `K_rep` with the label above. **[COM-271]**
   A reporter MUST send the report record as a `SEND` to the queue of
   `report_queue` of that entry. The `SEND` travels over a circuit of Part 3
   §3.4.
3. **[COM-272]** A reporter MUST NOT put its own pseudonym, its own handle, or
   another identifier of itself in a report. A report names a post and a
   cause, and the role holder needs no more.
4. **[COM-273]** A client MUST offer a report action on each community post
   that it renders.

**The role holder.**

5. **[COM-274]** A role holder MUST make one report queue under Part 3 rule
   `NET-170` before the roster names its role. **[COM-275]** A roster signer
   MUST take `report_ek` and `report_queue` of an entry from the role holder
   over their pairwise channel. **[COM-288]** A roster signer MUST NOT make
   either value itself.
6. **[COM-276]** A role holder MUST subscribe to its report queue in each
   session that it opens under Part 3 §3.5.1. The report queue is then one
   more inbound queue of that session. **[COM-277]** A role holder MUST open such a session at least one
   time in each `REPORT_POLL_MAX`. §12.9 sets that value to 24 hours, and
   Part 16 §16.6 states the response expectation that it serves.
7. **[COM-278]** A role holder MUST NOT rotate a report queue under
   `ROTATE_AFTER` of Part 3 §3.2.4. **[COM-279]** A role holder MUST hold a
   report queue until `ROTATE_GRACE` after a roster without its entry
   succeeds. That roster is the first `CommunityRoster` that does not name the
   queue, and Part 3 §3.2.6 gives the period. **[COM-280]** A role holder MUST then send the `DEL` of Part 3
   rule `NET-020`.
8. **[COM-281]** A role holder MUST decapsulate `kem_ct` with `RoleReportKey_r`,
   derive `K_rep`, and open `ct`. **[COM-289]** A role holder MUST parse the
   plaintext as an `AppMessage` of kind `0x11` with a `CommunityReport` body.
   **[COM-282]** A role holder MUST discard a report record that fails one of
   those steps without a signal.
9. **[COM-283]** Before it shows a report, a role holder MUST fetch the post
   that `pseudonym` and `index` name under §12.3.3. **[COM-290]** The role
   holder MUST compare the hash of that post with `post_hash` before it shows
   the report. **[COM-284]** If the two hashes differ, the role holder MUST
   discard the report. **[COM-285]** If the chain holds no post at that pair,
   the role holder MUST try again at each pull. **[COM-291]** The role holder
   MUST discard such a report `REPORT_HOLD` after its arrival.
10. **[COM-286]** A role holder MUST NOT forward a report to a party outside
    the roster of that community. The `UMBRA-KEM` encapsulation makes the role
    holder the one reader. A forwarded plaintext is a claim with no evidence
    beyond the post that the chain already holds.

> *Cause.* Part 14 §14.10 and §12.5.1 named a designated verifier and an
> encapsulation key. No section named the object, the carrier, the queue, or
> the role holder that receives a report. A community is pull-only under
> §12.2, thus a role pseudonym had no inbox. SimpleX v6.3 of March 2025 carries
> a report over the group channel to each owner and moderator, and each of
> them reads each report. UMBRA sends a report to one role holder. A report to
> each of 19 queues costs 19 `B1` cells, and it gives 19 parties one claim. A
> shared write credential on the report queue lets each member write. The admission
> control of Part 14 bounds a flood as it bounds a `SEND` to any queue.
> `COM-278` exempts the report queue from the rotation of Part 3
> §3.2.4, because that rotation protects one pairwise link and a roster
> publishes this address. A rotation would cost one roster epoch of 31 547
> bytes for each role holder every 90 days.
>
> Part 3 rule `NET-195` counts a `SUB` as activity, thus a report queue with
> no report for `QUEUE_IDLE_TTL` survives while the role holder polls it.

### 12.5.4 The community mute

A subscriber mutes a pseudonym in one community. The mute is local. Part 14
§14.12 blocks a pairwise contact, and a community has no pairwise queue, thus
this section gives the community its own rule.

- **[COM-314]** A client MUST let the user mute a pseudonym in one community.
  **[COM-315]** A client MUST NOT render a post, a reaction, or a repost of a
  muted pseudonym in that community. **[COM-316]** The client MUST show the
  count of the hidden records, in the manner of Part 14 rule `ABU-038`.
  **[COM-317]** A client MUST NOT show a mention from a muted pseudonym as a
  mention.
- **[COM-318]** A client MUST verify the chain of a muted pseudonym under
  §12.4.1. A muted chain is part of the community, and its checkpoints stand.
- **[COM-319]** A client MUST NOT send a record for a mute, and it MUST NOT
  tell a relay. **[COM-320]** A client MUST hold the mute list of a community
  as the mutable state of Part 7 §7.5.3. **[COM-321]** A client MUST NOT hold
  more than `MUTE_LIST_MAX` pseudonyms in the mute list of one community.

> *Cause.* A user of a community of 100 000 has no tool against one author
> other than a report. A report asks a role holder to act. A mute acts at once
> and it tells no party. The muted author learns nothing, because no record
> leaves the device. Part 7 §7.5.3 carries the list to the other devices of
> the user inside the device set.

### 12.5.5 The creation and the second owner

`COM-130` gives a community two or more owners from its first roster, and
§12.5.2 rule 5 checks that roster at each relay. A `RosterEntry` names the
role pseudonym, the report key, and the report queue of one owner, and only
the device of that owner holds them. Thus the creator asks one contact for
its entry, on their pairwise channel, before the genesis. The exchange
travels in an `AppMessage` of kind `0x38` of Part 6 §6.6.1.

```
CommunityOwnerExchange {
    step           u8        // 0x01 offer, 0x02 accept, 0x03 decline, 0x04 formed
    community_id   [32]u8
    rest           [n]u8     // by step, below
}

offer     name_len u8, name [name_len]u8           // the name of the first metadata
accept    entry RosterEntry                        // 1 378 bytes, §12.5.2
decline   (empty)
formed    fragment [16]u8, relay_count u8,
          relays [relay_count][32]u8               // the relay_id of each relay of the metadata
```

An accept is 1 411 bytes, and the `AppMessage` header adds 30. That total
fits the `B1` L6 record of Part 6 §6.9. A formed step names each relay by its
full `relay_id`: the channel is private, and a `RelayRef` of §12.7 would cost
the second owner a resolution for no gain.

- **[COM-401]** A creator MUST make the genesis role seed of `COM-005` and a
  report queue of its own before it sends an offer. The `community_id` of the
  offer comes from that seed, and it does not change.
- **[COM-402]** A creator MUST send the offer to one contact, on the pairwise
  channel of that contact. **[COM-403]** A creator MUST NOT publish a
  `CommunityRoster` with `epoch_index` 0 before it holds an accept of that
  offer. The roster then names the owner entry of the creator and the entry
  of the accept.
- **[COM-404]** A party that accepts an offer MUST make a role seed from the
  device CSPRNG, in the manner of `COM-005`, and a report queue of its own,
  before it sends the accept. The entry of the accept names role 1.
  **[COM-405]** A party MUST NOT send an accept for an offer that it did not
  receive, and it MUST NOT send two accepts for one offer.
- **[COM-406]** A creator MUST drop an accept whose `community_id` names no
  offer that it holds for the sending contact, a second accept of one offer,
  and an entry whose role is not 1 or whose pseudonym is the pseudonym of the
  creator. A decline of a held offer ends that offer.
- **[COM-407]** When the relays of the first `CommunityMeta` have each
  answered the genesis roster and that meta with a `PUBACK`, the creator MUST
  send a formed step to the second owner. **[COM-408]** A party MUST take a
  formed step only for an accept that it sent to that contact. It then holds
  the community with its role seed, and it pulls it under `COM-196`.
- **[COM-409]** A party MUST drop an exchange whose `step` is not one of the
  four values, or whose `rest` does not have the length of its step.

> *Cause.* An earlier draft required two independent owners at the genesis,
> and a relay rejected a genesis roster with one owner. No section said how
> the entry of the second owner reached the creator. A creator that made both
> entries on one device held both role keys, and `COM-130` then protected
> nothing. The pairwise channel carries the exchange, thus no relay and no
> other member sees who owns the community before the roster names the two
> pseudonyms.

## 12.6 Notifications

A community defaults to `mentions` under Part 7 rule `DEV-222`, and the
device learns of a post from a digest. §12.6.4 gives the carrier of that
digest, and Part 8 §8.5.1 gives its budget.

The budget is not only a UX preference. FCM permits 5 000 messages in one hour
to one device, and each push that wakes the device costs one radio promotion
against the U5 battery budget that Part 8 §8.3 derives from Doze and from Part
2 §2.4. A busy community that makes one push for each message spends that
budget on one conversation. It then breaks the notifications for *each*
conversation on the device.

### 12.6.1 A mention and a reply in a community

Part 6 §6.6.5 gives the rich record. A community post is not an `AppMessage`
(§12.2.1), thus this section gives the two fields their carrier here.

- **[COM-158]** A `CommunityPost` MUST carry a mention list and a reply target
  in the first bytes of its `body`, under the `RichRecord` encoding of Part 6
  §6.6.5. **[COM-159]** A client MUST set `inner_kind` to `0x01` for a text
  post.
- **[COM-160]** A sender MUST compute a mention identifier under Part 6 §6.6.5,
  with the `community_id` as the scope and the pseudonym of the named member as
  the member key.
- **[COM-161]** A client MUST resolve a reply target and a thread root through
  the `community_reply_id` of Part 6 §6.6.5, and it MUST NOT resolve either
  one as a `msg_id`. A community post carries no `msg_id`, and the derivation
  binds the `community_id`, the `pseudonym`, and the `index` of §12.2.1.
- **[COM-162]** A client MUST NOT set a `forward_depth` above zero in a
  community. A community post is public at publication (§12.1), thus a forward
  count states nothing that the publication does not state already.

**A mention does not make a subscriber list.** §12.3.1 says that no subscriber
list exists, at a relay or at an owner device.

- **[COM-163]** A relay MUST NOT index a post by its mention list.
  **[COM-164]** A relay MUST NOT notify a party because a mention names that
  party. Part 8 §8.5 keeps a community notification a server-side digest, and a
  mention does not change that path.
- **[COM-165]** A client MUST find a mention of the user at the pull of §12.9,
  and it MUST NOT ask a relay for the posts that name it.

> *Cause.* A relay that answered "give me the posts that mention me" would learn
> the pseudonym of the party that asked, and it would learn that the party
> subscribes. §12.8 states that no such list exists, and this rule keeps that
> statement true. The cost is that a client finds a mention only after it pulls
> the post, and `PULL_INTERVAL` bounds that delay at 180 seconds.

**The default is `mentions`.** **[COM-166]** A client MUST default the
notification setting of Part 7 §7.5.9 to `mentions` for a community.
**[COM-167]** A client MUST let the user move that setting to `none` or to
`all`.

> *Cause.* An earlier draft defaulted a community to `none`, and Part 2 §2.4.2
> goal S2 names a contact from a public post that the user has to see first.
> A digest under Part 8 §8.5.1 costs a bounded wake count, and the `mentions`
> setting renders a post that names the user only.

### 12.6.2 A reaction and a repost

A reaction and a repost are chain records. Each one is a `CommunityPost`, thus
it has an index, a checkpoint, and the retention of §12.4.6. Each one is public
in the same manner as a post.

```
RepostBody {
    version           u8        // 0x01
    origin_community  [32]u8
    target_pseudonym  [32]u8
    target_index      u32
    link_len          u8        // 0 if origin_community is this community
    link              [link_len]u8   // the community link of §12.7
}
```

- **[COM-322]** A reaction MUST be a `CommunityPost` whose `RichRecord`
  `inner_kind` is `0x03`, with a `ReactionBody` of Part 6 §6.6.9. **[COM-323]**
  The `target` of that body MUST be the `community_reply_id` of the target
  post. **[COM-324]** A client MUST NOT set a reply target or a mention in a
  reaction.
- **[COM-397]** The `link` of a `RepostBody` MUST name `origin_community`,
  and `link_len` MUST be 0 exactly when `origin_community` is this community.
  A link with `COMMUNITY_RELAY_MAX` hints is 259 characters, and `link_len`
  is one byte, thus a client MUST drop hints from the end of the list until
  the link fits 255 bytes. Seven hints fit.
- **[COM-325]** A repost MUST be a `CommunityPost` whose `RichRecord`
  `inner_kind` is `0x0D`, with a `RepostBody`. **[COM-326]** If the client
  subscribes to the origin community, it MUST render a repost with the target
  post. **[COM-356]** If it does not, the client MUST render the repost with
  the link. **[COM-327]** A client MUST NOT join
  the origin community for a repost without a user action.
- **[COM-328]** A relay MUST count a reaction under `REACT_RATE_LIMIT` and a
  repost under `REPOST_RATE_LIMIT`. **[COM-329]** A relay MUST NOT count a
  reaction or a repost under `POST_RATE_LIMIT`. The relay reads the
  `inner_kind` byte of the body, and §12.1 makes that byte public.
- **[COM-330]** If the `flags` field of the current `CommunityMeta` sets
  bit 0, a relay MUST reject a reaction. **[COM-331]** If that field sets bit
  1, a relay MUST reject a repost. **[COM-332]** A client MUST NOT send a
  record that a set bit forbids.
- **[COM-333]** A client MUST tally a reaction count from the records that it
  pulled. **[COM-334]** A client MUST count a maximum of one reaction for each
  pseudonym and emoji. The last `action` of that pseudonym decides.
  **[COM-335]** A relay MUST NOT serve an aggregate count. §12.8 states what
  a count is.

> *Cause.* Part 2 §2.4.2 goal S2 needs a reaction, a repost, and a reply, and
> §12.6.1 gave the reply its carrier. A reaction as a chain record costs one
> index, and the checkpoint of §12.4.1 amortizes the signature. Thus the
> marginal cost is 46 bytes of header and a small body. A relay aggregate would
> be one number that no client can verify, and a client that pulls the records
> holds the same information. The owner dial in `flags` exists because a
> reaction is cheap to flood. The separate limits keep a flood of reactions
> away from the post budget.

### 12.6.3 A contact request to a pseudonym

An author that opts in publishes a contact key under its pseudonym. A reader
then sends the hello of Part 9 §9.6 to it, and the author stays a pseudonym
until the author accepts.

```
CommunityContactKey_g := Hybrid( HKDF-SHA3-256( ikm = CommunityIdentitySeed_g,
                                 info = "umbra/v1/community-contact", L = 96 ) )

CommunityContact {
    version         u8            // 0x01
    contact_pk      [1216]u8      // the encapsulation key, or zero bytes to withdraw
    rendezvous      QueueAddress  // 129 bytes, Part 6 §6.6.10
}
```

A `CommunityContact` is 1 346 bytes. Part 5 §5.11 holds the label.

- **[COM-336]** A client MUST NOT publish a `CommunityContact` without an
  explicit act of the user for that pseudonym. **[COM-337]** A
  `CommunityContact` MUST travel as a `CommunityPost` whose `RichRecord`
  `inner_kind` is `0x0E`. **[COM-338]** A client MUST take the newest verified
  `CommunityContact` of a pseudonym as its current one.
- **[COM-339]** The `rendezvous` queue MUST NOT be a queue that a
  `DirectoryEntry`, an `AddressEntry`, or a pairwise contact names.
  **[COM-344]** The author client MUST drain that queue under Part 8 §8.2.6.
- **[COM-345]** A reader MUST send the hello of Part 9 §9.6 to that queue, and
  it MUST encapsulate the hello to `contact_pk`. The upgrade of that section
  then follows. **[COM-346]** A client MUST show a hello under a pseudonym as a contact
  request that names the community and the pseudonym.
  **[COM-347]** The client MUST NOT accept that request without a user action.

> *Cause.* Part 2 §2.4.2 goal S2 names a contact from a public post. A reader
> that holds only a pseudonym had no path, because a pseudonym has no queue. The
> key comes from `CommunityIdentitySeed_g`. Thus a rotation of the pseudonym
> under `COM-132` drops the key with it, and no key links two pseudonyms. The
> reader ends its hello with the `Admission` of Part 14 §14.4, as in Part 9
> §9.6. The author shows nothing until it accepts. The author client verifies
> that `Admission`, and the queue relay reads a padded message. That
> verification is the rate limit of this path.

### 12.6.4 The notification queue and the digest

A community relay holds no subscriber list and no `k_tok`, thus it cannot push.
A subscriber in Instant mode makes one queue at a queue relay under Part 3
§3.2.6. It registers the `QueueAddress` of that queue with each community relay
of the community. The community relay writes a digest into that queue as a
sender, and the queue relay pushes as for any queue. Part 8 §8.5.1 gives the
client rules and the budget.

```
NotifyRegistration {              // the payload of NREG and of NUNREG, 162 bytes
    version        u8             // 0x01
    community_id   [32]u8
    queue          QueueAddress   // 129 bytes, Part 6 §6.6.10
}

NotifyDigest {                    // the L6 record of kind 0x04, Part 6 §6.4.2
    version        u8             // 0x01
    community_id   [32]u8
    post_count     u8             // posts since the previous digest, at most 255
}
```

A `NotifyDigest` is 34 bytes, and it travels sealed under `K_QE` of Part 6
§6.4.2 in one `B0` cell. The queue relay reads ciphertext, thus it does not
learn the community.

- **[COM-368]** A subscriber MUST send `NREG` on the session of that community
  under `COM-173`. **[COM-374]** A subscriber MUST NOT put a pseudonym in a
  `NotifyRegistration`. **[COM-369]** A community relay MUST hold a registration
  in memory only. **[COM-375]** A community relay MUST discard a registration 7
  days plus `CLOCK_SKEW` after its `NREG`. The relay measures that period from
  the `NREG`. **[COM-370]** A community relay MUST discard a registration at an
  `NUNREG` that names its queue.
- **[COM-371]** A community relay MUST write a `NotifyDigest` as a `SEND` to
  each registered queue when a post arrives, under the budget of Part 8 rule
  `NTF-072` and the silence of `NTF-073`. **[COM-372]** A community relay MUST
  NOT write a `NotifyDigest` that names a post, a pseudonym, or an index.
- **[COM-373]** A community relay MUST NOT link a registration to a pull. A
  pull carries no identifier, and a registration carries none, thus the relay
  holds two sets that meet nowhere.

> *Cause.* An earlier draft named a digest on the server, and no section named
> the server, the carrier, or the queue. A relay that holds no `k_tok` cannot
> push, and a queue relay holds no community. The registration gives the
> community relay a queue and nothing else. The relay learns the count of the
> registered queues and the queue relay of each, and Part 16 §16.3 states that
> residual. A registration on the community session of `COM-173` reaches the
> relay through the same chain as a pull, thus it shows no client address.

## 12.7 Discovery and the community link

A user joins a community by a link. The link names the community, and it holds
the key of the metadata blob. It also hints at the relays that served the
community when a party made it. Part 1 §1.8 names the link as an artifact.

```
umbra://c/<base32(community_id)>?r=<hints>#<128-bit fragment>

hints    = one to COMMUNITY_RELAY_MAX values of base32(RelayRef), with a comma between two values
meta_key = HKDF("umbra/v1/community-meta-blob" || community_id || fragment)
```

Part 5 §5.11 holds the label. `base32` is the encoding of Part 4 §4.2.3, with
no padding. `community_id` is 52 characters, the fragment is 26 characters, and
each hint is 20 characters. Part 13 §13.3.2 gives `RelayRef` and its resolution
through the directory.

- **[COM-242]** A client MUST make the fragment from the device CSPRNG at the
  creation. **[COM-243]** A client MUST derive `meta_key` from `community_id`
  and the fragment. **[COM-390]** The derivation is HKDF-SHA3-256 with the
  fragment as the `ikm`, no salt, the label and then `community_id` as the
  `info`, and 32 bytes of output. Part 9 §9.3.1 derives the key of a profile
  blob in the same manner. **[COM-244]** A client MUST NOT send the fragment, or a
  value that comes from it, to a relay.
- **[COM-245]** A client that shares a link MUST fill the hints from the
  `relays` list of the current `CommunityMeta`. **[COM-246]** A joiner MUST pull
  the metadata under `COM-196` from a hinted relay. **[COM-247]** After a
  `CommunityMeta` verifies, a client MUST use its `relays` list in the place of
  the hints.

> *Cause.* The relay reads `community_id` in each command, thus the identifier
> is not a secret. The fragment is the one value that a relay never sees. It
> keeps the name and the rules of a community out of the compellable set of Part
> 16 §16.1. The hints bootstrap a join, and the signed record is the authority
> after that.

### 12.7.1 The metadata record

A community has a name, a description, a set of rules, a category, and an icon.
Those five items travel in a `CommunityMeta`, which is a community record of
type `0x06` (§12.4.4). An owner signs the record, and the body is a blob under
`meta_key`. A relay serves the record, and it cannot read the body.

```
CommunityMeta {
    version         u8            // 0x01
    type            u8            // 0x06
    community_id    [32]u8
    meta_index      u32           // 0 at the creation, then one more at each change
    previous_meta   [32]u8        // SHA3-256 of the CommunityMeta at meta_index - 1, zero bytes at 0
    actor           [32]u8        // the owner role pseudonym of the signer
    actor_pk        [1952]u8      // the ML-DSA-65 public key of that role pseudonym
    relay_count     u8            // COMMUNITY_MIN_RELAYS to COMMUNITY_RELAY_MAX
    relays          [relay_count]RelayRef   // 12 bytes each, Part 13 §13.3.2
    flags           u8            // bit 0 reactions off, bit 1 reposts off (§12.6.2)
    nonce           [12]u8        // from the device CSPRNG
    body_len        u16
    body            [body_len]u8  // ChaCha20-Poly1305(meta_key, nonce, aad, CommunityMetaBody)
    signature       [3309]u8      // ML-DSA-65, label "umbra/v1/community-metadata"
}

CommunityMetaBody {
    version         u8            // 0x01
    category        u8            // the table below
    name_len        u8            // 1 to META_NAME_MAX
    name            [name_len]u8      // UTF-8
    text_len        u16           // 0 to META_TEXT_MAX
    text            [text_len]u8      // the description, UTF-8
    rules_len       u16           // 0 to META_RULES_MAX
    rules           [rules_len]u8     // UTF-8
    icon_len        u16           // 0, or the length of one FileDescriptor
    icon            [icon_len]u8      // a FileDescriptor of Part 13 §13.3, one chunk
}
```

The `aad` of the body is `community_id || meta_index`, with `meta_index` in
big-endian order. The signature covers `"umbra/v1/community-metadata"` and
then each byte of the record before `signature`. The fixed fields are 5 379
bytes, and `COMMUNITY_RELAY_MAX` relays add 96 bytes. A body at each maximum is
2 374 bytes of plaintext and a 16-byte tag, where the icon is one
`FileDescriptor` of 253 bytes at the most.

**[COM-386]** The `flags` field MUST sit in the signed record and not in the
sealed body. A relay applies `COM-330` and `COM-331`, and `COM-244` keeps
`meta_key` from each relay, thus a relay cannot read a field of the body. An
earlier draft put `flags` in the `CommunityMetaBody`, and no relay could
enforce the dial. Thus the largest `CommunityMeta` is 7 865 bytes, and a `PAGE` that
holds it is 7 926 bytes. Both fit the `B2` L5 payload of 8 074 bytes.

| `category` | Name |
| --- | --- |
| `0x00` | None |
| `0x01` | General |
| `0x02` | News |
| `0x03` | Technology |
| `0x04` | Art and music |
| `0x05` | Games |
| `0x06` | Sport |
| `0x07` | Education |
| `0x08` | Local |
| `0x09` | Support |
| `0x0A` | Other |

**The chain of the record.**

- **[COM-248]** An owner MUST publish a `CommunityMeta` with `meta_index` 0 at
  the creation, after the `CommunityRoster` with `epoch_index` 0.
- **[COM-249]** A party MUST reject a `CommunityMeta` that an owner role
  pseudonym of the current `CommunityRoster` did not sign. **[COM-250]** A
  party MUST apply the hash check of §12.5.2 rule 1 to `actor_pk`.
  **[COM-251]** A party MUST reject a `CommunityMeta` whose `previous_meta`
  differs from the hash of the `CommunityMeta` at `meta_index` − 1.
  **[COM-387]** That hash is the SHA3-256 of the bytes that the signature
  covers, without the label, in the manner of `COM-377`. **[COM-388]** The
  check of `COM-251` binds a party that holds the record at `meta_index` − 1.
  A party that does not hold it MUST NOT reject the record for that cause.
  **[COM-389]** When a `CommunityRoster` drops the owner that signed the
  current `CommunityMeta`, a remaining owner MUST publish a new
  `CommunityMeta`.

  > *Cause.* `COM-249` verifies a record under the current roster. At a join
  > and at a re-seed, a record of a former owner does not verify, and its
  > index stays empty at that party. A strict chain from `meta_index` 0 would
  > then stop at the first such record. `COM-253` selects the highest verified
  > record, and `COM-389` keeps that record under a current owner.
- **[COM-252]** A client MUST apply the successor order of §12.5.2 rule 6 to
  two verified `CommunityMeta` records at one `meta_index`. **[COM-253]** A
  client MUST select the verified `CommunityMeta` with the highest `meta_index`
  as the current metadata.
- **[COM-254]** A `CommunityMeta` MUST name at least `COMMUNITY_MIN_RELAYS`
  relays under different operators. **[COM-255]** A party MUST reject a
  `CommunityMeta` with more than `COMMUNITY_RELAY_MAX` relays. **[COM-256]** A
  revision that changes `CommunityMeta`, `CommunityMetaBody`, or a `META_*`
  value MUST derive the total above again.

**The body.**

- **[COM-257]** A client MUST reject a `CommunityMetaBody` whose `name_len`,
  `text_len`, or `rules_len` is above its maximum of §12.9. **[COM-258]** A
  client MUST reject a body whose `name`, `text`, or `rules` is not valid
  UTF-8. **[COM-259]** A client MUST show a `category` that the table above
  does not define as `0x00`. **[COM-348]** A client MUST treat a `flags` bit
  that §12.6.2 does not define as zero.
- **[COM-260]** An icon MUST be one attachment of one chunk under Part 13.
  **[COM-261]** A client MUST re-encode an icon under Part 9 rules `DIS-001`
  and `DIS-002` before the upload. **[COM-262]** An owner client MUST upload
  the icon again, and publish a new `CommunityMeta`, before `CHUNK_LIFE_MAX`
  passes from the upload. §12.4.6 gives the renewal that a reader sends.

**At a join.** `COM-004` makes the interface show what becomes visible, and
the metadata gives it the words.

- **[COM-263]** Before a user joins, the client MUST show the five items of the
  current `CommunityMeta`. **[COM-264]** The client MUST show the rules again
  before the first post of the user. **[COM-265]** A client MUST NOT show a
  name, a description, or an icon from a `CommunityMeta` that did not verify.

### 12.7.2 The public directory

**[COM-131]** A community MAY opt in to a listing in the
public directory of Part 9 §9.12. That section gives the `CommunityListing`,
its label in the transparency log, and the browse query.

The listing applies to each community separately, and it is off by default. Only
a party with the link can reach an unlisted community.

A listing is a public statement. It carries the name, the category, the
language, the activity bucket, and the link with its fragment. Thus each party
reads the `CommunityMetaBody` of a listed community. The exclusion of §12.8 for
the name, the description, and the rules ends for that community.

- **[COM-349]** Before an owner lists a community, the client MUST show the
  five items of the statement above. **[COM-350]** An owner client MUST publish
  a new `CommunityListing` at each `CommunityMeta` change, and before
  `LISTING_LEASE` ends. **[COM-351]** An owner client MUST let the owner
  withdraw the listing, and a withdrawal is a `CommunityListing` with
  `link_len` 0.

## 12.8 What each party learns

| Party | Learns | Does not learn |
| --- | --- | --- |
| **Community relay** | The post content, the post time, the pseudonymous authorship, the pull volume, and an encrypted metadata record | A subscriber identity or IP address, an author identity or IP address, the subscriber set, the subscriber overlap with other communities, and the name, the description, and the rules of the community. A listing under §12.7.2 ends the last exclusion |
| **All the community relays in collusion** | The items above, across the full community | The same exclusions. No party enumerated the subscribers |
| **A subscriber** | All the public content and all the pseudonyms | The real identity of an author, and the other pseudonyms of an author |
| **Legal process against a relay** | The public content, which was public | No subscriber list, because no subscriber list exists |
| **A party that browses the listing of Part 9 §9.12** | The name, the category, the language, the activity bucket, and the link of each listed community | The content before a join, and the subscriber set |

The important row is this: **there is no subscriber list to give.** That
property is structural, and it comes from pull-based delivery with a pull that
carries no client identifier (§12.3.3). It is not a policy promise.

A count in a community is a tally of the records that a relay served. A
reaction count of §12.6.2 and the activity bucket of Part 9 §9.12 are such
tallies. No party holds a subscriber count, and no relay serves an aggregate.

## 12.9 Parameters

| Parameter | Value |
| --- | --- |
| `COMMUNITY_MIN_RELAYS` | 3, with different operators |
| `PULL_INTERVAL` | randomized, 30–180 s while the client is active |
| `PSEUDONYM_ROTATION` | **[COM-132]** The client MUST NOT rotate automatically. A rotation loses the reputation and the history. Only the user starts a rotation |
| `POST_RATE_LIMIT` | 20 posts each hour for each pseudonym, relay-local (§12.3.2) |
| `POST_RATE_WINDOW` | 1 h (§12.3.2) |
| `ROSTER_ENTRY_MAX` | 19 entries in one community roster (§12.5.2) |
| `MODERATOR_MAX` | 800 entries in one `ModeratorSet` (§12.5.2) |
| `MOD_EPOCH_RATE` | 1 `ModerationEpoch` in each 60 s for one `actor`. The relay measures it from its acceptance of the previous epoch of that actor (§12.5.2 rule 11) |
| `MOD_EPOCH_COMMUNITY_RATE` | 12 `ModerationEpoch` records in each 60 s for one community, measured by the relay from its acceptance of each one (§12.5.2 rule 11) |
| `ROSTER_RATE` | 1 `CommunityRoster` or `ModeratorSet` in each 60 s for one community, measured by the relay from its acceptance of the previous one (§12.5.2 rule 11) |
| `MOD_CHAIN_FETCH_MAX` | 64 predecessors in one walk under `COM-135` (§12.5.2 rule 11) |
| `MUTE_LIST_MAX` | 1 000 pseudonyms in the mute list of one community (§12.5.4) |
| `REACT_RATE_LIMIT` | 120 reactions each hour for each pseudonym, relay-local (§12.6.2) |
| `REPOST_RATE_LIMIT` | 20 reposts each hour for each pseudonym, relay-local (§12.6.2) |
| `REPORT_NOTE_MAX` | 200 bytes of note in a `CommunityReport` (§12.5.3) |
| `REPORT_POLL_MAX` | 24 h between two sessions that subscribe to a report queue (§12.5.3) |
| `REPORT_HOLD` | 24 h, measured by the role holder from the arrival of a report whose post the chain does not hold yet (§12.5.3) |
| `DIGEST_INTERVAL` | 15 min default |
| `MAX_POST_SIZE` | 7 967 bytes, which is the `B2` L5 payload of Part 6 §6.9 (8 074 bytes) less the 46-byte `CommunityPost` header and the 61 bytes of `PAGE` framing (§12.3.3). Larger content is an attachment |
| `SIG_INTERVAL` | 5 posts |
| `SIG_MAX_AGE` | 60 min. **[COM-133]** This value MUST satisfy rule 5 of §12.4.1 |
| `SIG_MIN_INTERVAL` | 60 s |
| `PENDING_DEMOTE` | 90 min. **[COM-134]** This value MUST satisfy rule 6 of §12.4.1 |
| `PENDING_EXPIRE` | 24 h (hide, and do not delete) |
| `MOD_ACTION_MAX` | 20 actions in one moderation epoch |
| `WITHDRAW_MAX` | 8 indexes in one checkpoint. The field is 32 bytes, and it is always present |
| `PULL_BATCH` | 30 records in one `PAGE` (§12.3.3). `PULL_BATCH` posts with a 200-byte body fit one `B2` cell |
| `COMMUNITY_RETENTION` | 90 days at a relay for a post, a stub, and a checkpoint (§12.4.6). It equals `CHUNK_LIFE_MAX` of Part 13 §13.7 |
| `COMMUNITY_RELAY_MAX` | 8 relays in one `CommunityMeta` (§12.7.1) |
| `META_NAME_MAX` | 64 bytes of name in a `CommunityMetaBody` (§12.7.1) |
| `META_TEXT_MAX` | 512 bytes of description in a `CommunityMetaBody` |
| `META_RULES_MAX` | 1 536 bytes of rules in a `CommunityMetaBody`. §12.7.1 gives the total |
