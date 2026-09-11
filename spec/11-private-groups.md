# UMBRA Protocol Specification — Part 11: Private Groups (2–500)

**Status:** Draft
**Version:** 0.1.0-draft

---

## 11.1 The decision: no MLS

UMBRA does **not** use MLS (RFC 9420) for v1. This decision needs a cause,
because MLS is the obvious answer and it is the incorrect answer here.

MLS is a **server-fanout protocol**. Its primary property is a bandwidth of
O(log N) for each commit, through TreeKEM. That property counts the bandwidth
that the *server* saves when it fans one ciphertext out to N recipients. **UMBRA
has no server fanout.** With one-direction queues for each recipient, the sender
uploads N−1 copies of each message. At that point the table below applies:

| Scheme | Application message for each copy |
| --- | --- |
| MLS (ciphersuite 0x0001) | ~360 B |
| Sender keys | ~285 B |
| Pairwise Double Ratchet | ~257 B |

On the real wire of UMBRA, MLS is the **most expensive of the three**. MLS also
carries about 50 times the implementation surface and the audit surface.

The costs that MLS causes are the costs that UMBRA cannot pay:

- **`group_id` and `epoch` are cleartext by design.** RFC 9420 §16.4.1 states
  plainly that MLS gives no mechanism to protect them from the Delivery Service.
  A seized relay collects each member of a group in one query. A correction
  needs a rewrite of each `PrivateMessage` header for each recipient.
- **MLS needs a total order on the commits**, which is one commit in each epoch.
  UMBRA has no total order. Thus MLS needs a sequencer, and the party that
  sequences learns the group.
- **The full ratchet tree moves to each joiner.** That tree is 135 KB at N=500
  with a classical ciphersuite. It is about **21 MB** at N=5000 with a hybrid PQ
  ciphersuite.
- **PQ-MLS is a draft only** (`draft-ietf-mls-pq-ciphersuites`, and the
  codepoints are not decided). It increases a 500-member commit from 1.45 KB to
  **23 KB**. If the members update each day, the uplink is 11.5 MB for each
  device each day.
- The log-N claim does not survive a measurement. Soler and others
  (arXiv:2502.18303v2) measured that MLS scales **linearly** in practice. The
  cause is that ratchet-tree state management, and not the cryptography, is
  90–99 % of the cost.

Each deployment that ships MLS at scale solves these problems in the same
manner. That deployment gives the ratchet tree and the plaintext handshakes to a
central server. The examples are the voice gateway of Discord, the Conversation
Focus of GSMA RCC.16, the hub of MIMI, and the `distributionService` option.
UMBRA has no such server, and UMBRA does not want one.

**MLS stays a bridge option, and it is not a core option.** MIMI can reach RFC
status with a stable Minimal Metadata Room scheme. UMBRA can then operate an
optional gateway process. That process speaks MLS with MIMI on the outside, and
it speaks pairwise channels and sender keys internally. This method keeps DMA
interoperation. It also keeps three costs out of a core that has to
operate on a phone. Those three costs are a 130-page state machine, an O(N)
ratchet tree, and a total-ordering requirement.

## 11.2 Tiered by size

| Tier | Members | Mechanism | Fanout for each message |
| --- | --- | --- | --- |
| **T1** | 2–50 | Pairwise Double Ratchet fanout. **No group cryptography** | N=50 → ~102 KB |
| **T2** | 51–500 | Sender keys over the same pairwise queues, with lazy rekey | N=500 → ~1.05 MB |
| **T3** | 200–500, availability-sensitive | T2 with an optional re-broadcaster (§11.6) | 1 upload, 1.05 MB |

**This part counts a fan-out as the recipient count.** One sender reaches *N* −
1 recipients, because a sender does not send a copy to itself. §11.6 uses that
convention for a re-broadcaster, and §11.7.1 uses it for a receipt fan-out of
*N* × (*N* − 1).

Each figure above is *N* − 1 times 2 096 bytes, which Part 6 §6.9 gives as the
wire cost of one `B1` cell. Part 3 §3.12 puts the modal text of about 350 bytes
in bucket `B1`. The T2 figure is 499 × 2 096 = 1 045 904 bytes. The T1 figure is
49 × 2 096 = 102 704 bytes.

T1 exists because for a small group the simplest method is also the best method.
Each message is N−1 ordinary pairwise messages. A removal is free, because the
sender stops the transmission. The healing applies to each contact, and it
happens at that moment. There is no group state to desynchronize.

**What a membership costs in queues.** A member holds one pairwise channel with
each other member, and §11.9.1 gives the join flow that opens those channels.
The table below counts the state that a joiner holds at each tier.

| Tier | Inbound queues of a joiner | Transport sessions (Part 3 `NET-022`) | Push handles (Part 8 `NTF-033`) |
| --- | --- | --- | --- |
| T1 at *N* = 50 | 49 | 7 | 7 |
| T2 at *N* = 500 | 499 | 63 | 63 |

Each session and each handle holds at most 8 queues, thus the two counts are
*N* − 1 divided by 8, rounded up. A member that already holds a contact
relation with a member reuses that channel, and the counts above are the
maximum.

**The member identifier.** Each member of a group has one group-scoped
identifier:

```
member_id = SHA3-256( "umbra/v1/group-member" || group_id ||
                      GroupRosterKey_g.pk )[0..16]
```

`GroupRosterKey_g.pk` is the 1 952-byte ML-DSA-65 public key of §11.9.1, and
Part 5 §5.11 holds the label. The `granter_id` and the `grantee_id` of §11.9.2
are the `member_id` of the named member. The `actor_id` of §11.9.6 and the
member ID of §11.9.4 are the same value. **[GRP-154]** A client MUST compute
`member_id` with that derivation. **[GRP-155]** A client MUST NOT use an
identifier from outside the group as a member identifier. The value changes
with `group_id`, thus two groups that share a member carry two different
values. Part 6 §6.6.5 gives `mention_id` the same shape for the same cause.

### 11.2.1 The group record, and one `msg_id` for each send

A tier T1 send is an ordinary pairwise record on each of the *N* − 1 channels.
Thus a receiver needs a field that names the group, and a moderator needs a
target name that each member holds. The **group record** gives both.

```
GroupRecord {
    version      u8         // 0x01
    group_id     [32]u8
    inner_kind   u8         // a Part 6 §6.6 application kind
    inner_len    u32
    inner_body   [inner_len]u8
}
```

The group record is the body of an `AppMessage` of kind `0x12` (Part 6 §6.6.2).
Its overhead is 38 bytes.

1. **[GRP-110]** A sender MUST wrap each group **content** record in a `GroupRecord`. That
   rule applies to tier T1, to tier T2, and to tier T3.
2. **[GRP-111]** A receiver MUST route a `GroupRecord` to the group that `group_id` names. **[GRP-112]** A
   receiver MUST reject a `GroupRecord` whose `group_id` names no group that the
   receiver holds.
3. **[GRP-113]** A receiver MUST reject a `GroupRecord` whose `inner_kind` is `0x12`. There is
   no nested group record. **[GRP-120]** A sender MUST NOT wrap a group control record of kind
   `0x10`. **[GRP-121]** A receiver MUST reject a `GroupRecord` whose `inner_kind` is `0x10`.

   > *Cause.* A group control record names its group in its own body already.
   > §11.3.2 gives that field for a sender-key distribution, and §11.9.2 and
   > §11.9.6 sign that field in the preimage of an epoch. A wrapper would put
   > `group_id` in two places, and Part 6 §6.1.1 rule 4 permits one canonical
   > form only.
4. **[GRP-114]** A receiver MUST apply the class of `inner_kind` to the record. Part 7 §7.5.3
   gives the class of each kind.
5. In tier T2 and tier T3 the sender key already names the group. **[GRP-115]** A receiver
   MUST still check that `group_id` matches the group of the sender key that
   opened `inner`. **[GRP-116]** A receiver MUST reject the record on a mismatch. That check
   stops a replay of a record into a second group that shares one member.
6. **[GRP-150]** A receiver MUST reject a `GroupRecord` whose sender is not a
   member of the group that `group_id` names. The sender is the member that the
   L6 QueueE2E key names under GRP-014, and the local roster of that group
   gives the membership. This rule applies in each tier, and it subsumes the
   tier condition of GRP-115.

   > *Cause.* Tier T1 has no sender key, thus rule 5 did not reach it. A
   > removed member holds `group_id` and a pairwise channel with each member.
   > Without this rule that member still writes into the transcript of each
   > member, and §11.3.1 shows the user a removal that did not happen.

**The group identifier.** **[GRP-151]** The creator MUST make `group_id` from
the device CSPRNG at the creation of the group. **[GRP-152]** The creator MUST
NOT derive `group_id` from a member identity, from `GroupRosterSeed_g`, or from
an earlier `group_id`. **[GRP-153]** A member MUST reject an invitation to a
`group_id` that it already holds.

**One logical group send carries one `msg_id` to each member, in each tier.**
Part 6 §6.6 gives that rule. A sender draws one `msg_id` for the send and puts
that value in the `AppMessage` of each copy.

> *Cause, and the goal that it changes.* An earlier draft made a tier T1 sender
> draw a different `msg_id` for each recipient. The cause was G9, because one
> identical value in *N* − 1 pairwise conversations proves that two contacts
> hold one send from one correspondent. Inside a group that proof adds nothing.
> §11.5 states that a member learns the roster, thus two members of one group
> already know that they share each other and the sender. The value travels
> inside the AEAD of a pairwise channel, thus no party outside the group reads
> it.
>
> The earlier rule also broke §11.9.6. A moderation epoch names one `msg_id` for
> a target, and under that rule the epoch matched the history of one recipient
> only. A moderator could not act on a tier T1 post at all.
>
> The rule that stays is the pairwise rule. A sender still draws a different
> `msg_id` for each **conversation**, and a group is one conversation. Part 6
> §6.6 keeps WIR-062 and WIR-064, thus a forward and a re-share are still new
> messages with new values.

## 11.3 Sender keys (T2)

Each member holds a **sender key**, which is a symmetric chain key. The member
ratchets that key for each message with HMAC-SHA3-256. The member distributes
that key to each other member **over the PQ-protected pairwise channels**.

This mechanism lets the group content inherit post-quantum security (Part 5
§5.8), and it needs no KEM header for each member. The codebase holds **one** PQ
ratchet implementation. A group uses that implementation through the pairwise
channels, and the codebase does not hold a second copy.

```
member i sends:
    inner = AEAD(SenderChainKey_i.next(), msg)
    for each member j != i:
        outer_j = QueueE2E_Seal(QE_{i,j}, fresh_nonce(), inner)
        enqueue(outer_j) on queue(i -> j)
```

The value `inner` is one sender-key record:

```
SenderKeyRecord {
    version     u8        // 0x01
    generation  u32       // the sender-key generation of §11.3.2
    counter     u32       // the position on that sender chain, from 0
    nonce       [12]u8
    ct          [m]u8     // ChaCha20-Poly1305 output, and it holds the 16-byte tag
}
```

The L6 record kind `0x02` names a sender-key record (Part 6 §6.4.2 rule 5). The
record overhead is 37 bytes. The L6 layer encrypts the full record, thus a relay
reads no field of it. Part 6 §6.4.2 rule 6 fills the L6 record to one fixed
length for the bucket, thus `generation` and `counter` cost no wire byte that a
relay can measure.

**The chain and its two fields.**

```
CK_0    = HKDF-SHA3-256( "umbra/v1/sender-key", seed,
                         group_id || member_id || BE32(generation) )
MK_j    = HMAC-SHA3-256( CK_j, 0x01 )
CK_j+1  = HMAC-SHA3-256( CK_j, 0x02 )
inner   = ChaCha20-Poly1305( MK_j, nonce, ad, plaintext )
ad      = version || BE32(generation) || BE32(counter) || group_id
```

The value `seed` is 256 bits from the device CSPRNG, and the sender-key
distribution record of §11.3.2 carries it. The two constants `0x01` and `0x02`
are the constants of Part 5 §5.5.1. Part 5 §5.11 holds the label
`"umbra/v1/sender-key"`.

1. **[GRP-091]** A sender MUST set `counter` to the position of `MK_j` on that chain, and
   that position starts at 0.
2. **[GRP-092]** A sender MUST set `generation` to the generation of the sender key that it
   used.
3. **[GRP-093]** A sender MUST bind `ad` as the associated data of the inner AEAD. Thus a
   member that holds the chain key of that sender cannot move a record to a
   different position, to a different generation, or to a different group.
4. **[GRP-094]** A receiver MUST use `generation` to select the candidate sender key of the
   member that the L6 QueueE2E key names. **[GRP-095]** A receiver MUST NOT use `generation` to
   select a member. GRP-014 gives the attribution rule, and this field does not
   change it.
5. **[GRP-096]** A receiver MUST ratchet the selected chain forward to `counter`. **[GRP-097]** A receiver
   MUST store each message key that it skips at that step.
6. **[GRP-098]** A receiver MUST reject a record whose `counter` is more than
   `SENDER_KEY_MAX_SKIP` above the stored position of that chain. §11.10 gives
   that value.
7. **[GRP-099]** A receiver MUST hold a skipped sender-key message key under the
   `MAX_STORED`, `MAX_BYTES`, and `SKIP_TTL` limits of Part 5 §5.5.4. **[GRP-100]** A receiver
   MUST count those keys against `MAX_STORED_DEVICE`.
8. **[GRP-101]** A receiver MUST discard a record whose `counter` is at or below the position
   of a message key that it already used. **[GRP-102]** A receiver MUST NOT ratchet a chain
   backward.
9. **[GRP-103]** A receiver MUST take the values of Part 11 §11.7 from the key that opened
   the record, and not from the two fields. The two fields select a candidate,
   and the AEAD tag decides.

> *Cause.* An earlier draft carried no generation and no counter in this record.
> A receiver then held a chain at position *k* and could not tell whether an
> arriving record was at *k*, at *k+1*, or at *k+9*. §11.3.2 gives the receiver
> three candidate generations, but it gives no method to find the position
> inside one chain. A hole in the sequence of Part 6 §6.4.3 is normal, thus that
> state is the ordinary case and not an edge case. The two fields also give
> §11.7 the `chain_epoch` and the `counter` that its order rule needs.

The sender-key ciphertext `inner` is the same for each recipient, but no relay
sees it. **[GRP-001]** The per-queue layer (`QueueE2E_Seal`, Part 6 §6.4.2) MUST use a fresh
nonce. **[GRP-002]** That layer MUST give different relay-visible bytes for each recipient. **[GRP-003]** A
sender MUST fill the L6 record to the "L6 record on a `MSG`" row of Part 6 §6.9.
Part 6 §6.4.2 rule 6 states that rule.

**[GRP-004]** The test vectors MUST include a group send to 3 recipients. **[GRP-005]** Those vectors MUST
assert that the three L6 ciphertexts differ and that they decrypt to the same
`inner` value. A relay sees one opaque blob on one queue, and it cannot tell
that the blob is a group message.

### 11.3.0 Jitter of the fan-out

**[GRP-006]** **A client MUST dispatch a send to the members with an independent randomized
delay for each member.** The client draws that delay from an exponential
distribution with a mean of `FANOUT_JITTER`. §11.10 gives that mean as 400 ms.

**The total fan-out time follows the member count.** The total is the maximum of
*N* − 1 independent draws. At `GROUP_MAX` the p99 of that maximum is about
4.3 s, and `FANOUT_MAX_RATE` of 200 cells each second needs 2.5 s for 499 cells
before the jitter adds anything. **[GRP-122]** A revision MUST state the p99
total fan-out at `GROUP_MAX` when it changes `FANOUT_JITTER`, `FANOUT_MAX_RATE`,
or `GROUP_MAX`.

> **Deviation note.** An earlier draft said that a limit keeps the p99 total
> fan-out below 3 s at a mean of 400 ms. That statement does not hold at 500
> members. The mean of 400 ms stays, because it is the value that hides one send
> inside the jitter window of the next. The p99 figure moves to the measured
> 4.3 s.

> A fan-out at one moment is a membership beacon. The "flurry" attack
> (arXiv:2305.09799) identifies the group membership from the receipt bursts
> that occur at the same time. That attack scales only **logarithmically** with
> the total user count, thus it does not become more difficult as UMBRA grows. A
> dispatch of 500 messages in one burst tells a relay that observes two of those
> queues that the two queues belong to one group.

**[GRP-007]** The client MUST draw the delay for each member again at each send. A fixed
offset for each member is itself a fingerprint. The maximum fan-out rate for
each group is `FANOUT_MAX_RATE`, with a default of 200 cells/s. Above that rate
the sends queue, and they do not burst.

### 11.3.1 Lazy rekey

At a membership change, a member distributes its sender key again **only at its
next send**. At N=500, a removal thus costs about 121 KB for each *active
sender*, and not for each member. In a real group the active senders are a small
part of the roster.

The removal semantics are these. The removed member cannot decrypt a message
that a sender sent after the redistribution. The removed member can decrypt the
messages between the removal and the next send of a given sender.
**[GRP-008]** Implementations MUST show this behavior in the UI as "removed — will stop
receiving messages shortly". **[GRP-009]** Implementations MUST NOT show it as an instant
cut-off, because the protocol cannot support that claim.

A removal can be urgent, as with a compromise or with harassment. **[GRP-010]** The members
MUST then redistribute immediately, and not lazily. The UI shows this operation
as "remove and rotate now".

### 11.3.2 Which sender key opens `inner`

Each member stores a sender key under the triple (`group_id`, member,
`generation`). The sender-key distribution record travels as a `GroupControl` of Part 6 §6.6.3,
with the `control_type` value `0x01`, inside an application record of kind
`0x10`. That record carries `group_id`, a `generation` field of
`u32`, and the 32-byte `seed` of §11.3. The first sender key of a member in a
group has generation 0. The member increments the generation at each
redistribution.

```
SenderKeyDistribution {
    version      u8         // 0x01
    group_id     [32]u8
    generation   u32
    seed         [32]u8     // 256 bits from the device CSPRNG
}
```

**[GRP-104]** A member MUST make `seed` from the device CSPRNG at each redistribution. **[GRP-105]** A
member MUST NOT derive `seed` from `group_id`, from `GroupRosterSeed_g`, or from
an earlier seed.

- **[GRP-011]** A receiver MUST select the sender key by the L6 QueueE2E key that opened the
  record. That key names one member.
- **[GRP-012]** A receiver MUST try only the sender keys of that member. **[GRP-013]** A receiver MUST NOT
  try the sender keys of another member.
- **[GRP-014]** A receiver MUST attribute the record to the member that the L6 QueueE2E key
  names. **[GRP-015]** A receiver MUST NOT attribute a record by a field inside the record.
- **[GRP-016]** A receiver MUST accept a sender-key distribution only from the member that the
  L6 QueueE2E key names. **[GRP-017]** A receiver MUST accept that distribution only for the
  `group_id` in it.
- A receiver holds a highest generation for each member. **[GRP-018]** A
  receiver MUST discard an unsolicited distribution whose generation is at or
  below that generation. A distribution is unsolicited when the receiver holds
  no outstanding key request of §11.3.3 for that generation.
- **[GRP-019]** If no sender key of that member opens `inner`, the receiver MUST store the
  record in the undecryptable set. **[GRP-020]** The receiver MUST then send a
  key request of Part 6 §6.6.11 for that generation to that member (U9). The
  request travels on the existing pairwise queue. **[GRP-021]** The receiver
  MUST NOT try the sender keys of a different member.
- **[GRP-022]** A receiver MUST discard each sender key of a member at the removal of that
  member.
- **[GRP-023]** A receiver MUST hold a maximum of `SENDER_KEY_GENERATIONS` generations for
  each member. **[GRP-024]** A receiver MUST discard a superseded generation
  that is older than `SENDER_KEY_MAX_AGE`. **[GRP-158]** A receiver MUST keep
  the newest generation that it holds of each member, at each age. The
  defaults are 3 generations and 7 days.

> *Cause.* Each member holds the chain key of each other member. Without this
> rule, member B seals a record under the chain key of member A, and member C
> attributes that record to A. The L6 layer is a pairwise channel that already
> authenticates the peer, and this rule names that basis. The rule costs no wire
> byte and no primitive.
>
> The rule also stops a member from a replay of a record of another member. At
> N=500 it decreases the work for each record from 500 AEAD opens to 3. The
> attribution is not transferable, thus Part 5 §5.7 does not change.

> **The trade, stated.** Three retained generations for each member are three
> live symmetric chain keys on a seized device. `SENDER_KEY_GENERATIONS` and
> `SENDER_KEY_MAX_AGE` bound that window, and Part 16 §16.3 records it. Seven
> days matches the `HISTORY_WINDOW` maximum of §11.8.

### 11.3.3 The rotation, the retention, and the key request

§11.3.2 bounds what a receiver holds. This section gives the duty of the
sender, and it gives the repair path that U9 of Part 2 §2.4 names.

**The sender rotates, and the receiver does not expire the sender.** The
sender measures the age of a generation from the moment it made the `seed`.

- **[GRP-156]** A sender MUST distribute a new generation before the age of
  its current generation reaches `SENDER_KEY_ROTATION`. **[GRP-157]** A sender
  MUST NOT send a record under a generation whose age is above
  `SENDER_KEY_MAX_AGE`. §11.10 gives the two values, and the first one is below
  the second one.
- **[GRP-159]** A sender MUST retain the `seed` of each generation until
  `MSG_TTL` passes after its last send under that generation. **[GRP-160]** A
  sender MUST discard that `seed` after that period. Part 3 §3.2.4 gives
  `MSG_TTL`.

**The key request.** A receiver that holds a record in the undecryptable set
sends a key request under GRP-020. Part 6 §6.6.11 gives the record, the
carrier, and the rules that hold for a pairwise session and for a group alike.
The rules below hold for a group.

- **[GRP-161]** If a member holds the `seed` of a requested generation, it
  MUST answer with a key supply that carries that `SenderKeyDistribution`.
  **[GRP-162]** A member that does
  not hold that `seed` MUST answer with a key supply of status `not held`.
- **[GRP-163]** A receiver MUST accept a supplied distribution only while it
  holds an outstanding request for that generation. That rule covers a
  generation at or below the recorded highest one. **[GRP-164]** A receiver
  MUST NOT advance its recorded highest generation on a supplied
  distribution. The supplied generation counts
  against `SENDER_KEY_GENERATIONS`, and Part 6 rule `WIR-335` marks each record
  that it opens as recovered.

> *Cause.* An earlier draft expired a generation at the receiver after 7 days
> and put no rotation duty on the sender. A sender that rotated each 30 days
> thus made one undecryptable record for each expiry at each receiver. GRP-018
> then discarded the answer to the repair request. After a later generation
> arrives, a missed generation is by construction at or below the recorded
> highest one. Thus the request of GRP-020 could not succeed in the one state
> that produced an undecryptable record. No rule made the sender keep the
> `seed`, thus the member that a receiver asked could hold nothing.
>
> Signal tests the age of a sender key at the sender, with a default of 14
> days, and bounds the receiver by a count alone. This section takes that
> shape.

## 11.4 What UMBRA does *not* do

**[GRP-025]** **A client MUST NOT use a peer-to-peer mesh fan-out above about 20 members.**

> SimpleX operated a full P2P mesh for four years. That mesh needed N−1
> connections for each member and **O(N) introduction messages at each join**,
> across four message types. It also needed about **20 MB** of temporary storage
> on the client to schedule one message to a 1000-member group. A fix in March
> 2025 decreased that quantity by 100 times, to about 200 KB. The addition of
> the 300th member to a group made about 900 protocol messages and 299 new
> queues. The conclusion of SimpleX was that the design is "definitely not
> larger than a few hundred members." The replacement took four years.

UMBRA designs relay fan-out from the first commit.

## 11.5 Membership privacy

- **No relay learns the group membership.** A relay sees pairwise queues that
  carry opaque ciphertext. No mark shows that a queue belongs to a group.
- The group has **no existence on a server**. There is no group record, no group
  ID at a relay, and nothing for a party to seize.
- Group control messages (application kind `0x10`, Part 6 §6.6) move in the same
  pairwise channels as the content. On the wire a control message is
  indistinguishable from content in the same bucket.
- **A length does not show a group record.** A sender fills the L6 record to one
  fixed length for the bucket (Part 6 §6.4.2 rule 6). Thus a relay reads one
  `payload_len` for a group text and for a pairwise text.
- A granting epoch, a moderation epoch, and a join record (§11.9) use bucket
  `B2`, and they are not indistinguishable from the content. **[GRP-026]** A plain epoch MAY
  use bucket `B0` if it fits the §6.9 capacity of that bucket. The modal text
  message uses bucket `B1`, because Part 6 §6.9 gives `B0` a text capacity of
  155 bytes at the default chunk. The `AppMessage in a sender-key record` row
  of Part 6 §6.9 gives a sender-key record the same capacity.

**A member learns the roster.** That property is inherent. A member cannot send
to a person without the keys of that person. UMBRA hides the membership from the
*infrastructure*, and not from the participants.

## 11.6 Optional re-broadcaster (T3)

A large private group can make a phone upload 500 copies, and that cost is too
high. **[GRP-027]** Such a group MAY name one or more **re-broadcasters**.

A re-broadcaster has these properties:

- It holds **no group key**. It sees opaque ciphertext and a set of queue
  addresses, one for each recipient.
- It restores the economics of server-side fanout, which is one upload in place
  of 499.
- It learns the **set of recipient queue addresses** of the group, and it learns
  the size of that set for a given send. That set is the membership of the group
  at the queue layer, and it persists across each send. It does not learn which
  person holds a queue, and that limit holds **only if** each member established
  its queue with the re-broadcaster through the ordinary unlinkable-queue flow.

  > **This is a trade, and Part 2 §2.4 requires the text to state it.** Goal G11
  > of Part 2 §2.3 says that no relay learns the membership of a private group.
  > A re-broadcaster holds that membership as a queue set. Thus G11 holds for
  > tier T1 and for tier T2, and a group that names a re-broadcaster gives it up
  > against that party. GRP-028 states the same fact for one re-broadcaster, and
  > an earlier draft of this list said "and nothing else". Part 16 §16.3 records
  > the residual.

Requirements:

- **[GRP-028]** A group MUST permit **more than one** re-broadcaster. One re-broadcaster is
  one point of failure for delivery, and U6 does not permit that condition. One
  re-broadcaster also sees the recipient-set size for each send of the group.
  That view puts the metadata of the full group at one operator (A2), and it
  makes one compellable point (A5, G11).
- **[GRP-029]** A member client MUST fall back to direct fan-out if each re-broadcaster is
  unreachable.
- **[GRP-030]** The UI MUST show that the group uses a re-broadcaster.
  **[GRP-031]** The UI MUST name the operator of that re-broadcaster.
  **[GRP-123]** The UI MUST state that a re-broadcaster holds the queue set of
  the group. **[GRP-124]** The UI MUST show that statement at the join and at
  each change of the re-broadcaster set.
- **[GRP-032]** A re-broadcaster MUST receive one L6 QueueE2E ciphertext for each
  recipient. **[GRP-033]** A re-broadcaster MUST NOT change those bytes.
  **[GRP-034]** A re-broadcaster MUST NOT terminate the L6 layer. Thus §11.3.2
  holds in tier T3. A re-broadcaster decreases the number of uploads and the
  number of circuits. It does not decrease the number of bytes.

## 11.7 Ordering and consistency

- **[GRP-035]** A client MUST identify each record by the triple (group, sender, `msg_id`)
  (Part 6 §6.6). **[GRP-036]** A client MUST remove a duplicate by that triple. **[GRP-037]** A client MUST
  NOT use a ciphertext hash as an identifier, because Part 6 §6.1.1 rule 5
  prohibits that use.
- **[GRP-038]** A receiver MUST resolve a target only inside the group that carried the naming
  record. **[GRP-039]** A receiver MUST resolve that target only against the messages of the
  member that the L6 QueueE2E key names.
- The order of two records from **one sender** comes from the sender-chain
  position. That position is the lexicographic pair (`chain_epoch`, `counter`).

  | Context | `chain_epoch` | `counter` |
  | --- | --- | --- |
  | Tier T1, and each pairwise channel | The count of the completed DH ratchet steps in that direction | `n` of the Part 6 §6.5 header |
  | Tier T2 and tier T3 | The `generation` of the sender key that opened `inner` (§11.3.2) | The sender-chain counter of that key |

  The two values are local at the receiver, thus no field on the message path is
  necessary. **[GRP-040]** A receiver MUST take `chain_epoch` from the key that opened the
  record. **[GRP-041]** A receiver MUST NOT take `chain_epoch` from a count of the arrivals.
- The order of two records from **two different senders** comes from a local
  insertion sequence. That sequence belongs to the device that first put the
  record in the synced history. The sequence is a monotone counter on that
  device. **[GRP-042]** A client MUST NOT
  use a wall clock for the order. **[GRP-043]** A client MUST NOT use `sent_at` for the order.
  The insertion sequence is mutable state under Part 7 §7.5.3, thus the devices
  of one user converge on one order.
- If the two rules above do not resolve two records, the byte order of `msg_id`
  applies.
- **UMBRA gives no total order across the senders of a group.** Two members can
  see two different orders for two records that arrive at the same time. **[GRP-044]** The
  interface MUST NOT show the order as an agreed order.
- **UMBRA does not guarantee transcript consistency** against a malicious member
  that sends different content to different members. Detection needs a
  consistency protocol, and UMBRA has not accepted the cost of that protocol for
  v1. Part 16 states this limit. **[GRP-045]** A member MAY compare a rolling transcript
  digest out of band.

> *Cause.* A bare counter is not monotone in either tier. Part 7 §7.5.4 makes a
> new ratchet owner do an immediate DH step, which resets `n` in tier T1 and in
> each pairwise channel. §11.3.1 starts a new sender chain at each lazy rekey in
> tier T2. The pair (`chain_epoch`, `counter`) is monotone in both cases,
> because the reset of the counter and the increment of the epoch occur
> together.

### 11.7.1 A receipt in a group goes to the sender only

A member that reads a group message sends kind `0x07` **to the sender of that
message, and to no other member**. **[GRP-046]** A member MUST NOT fan a read receipt out to
the members. The same rule applies to the delivery receipt of kind `0x06`.

The message-info view of the sender then names each member that read the
message. A member does not see the read state of a message that another member
sent.

The table below counts cells for a group at the `GROUP_MAX` limit of 500
members. A `B0` cell costs 560 bytes (Part 6 §6.9).

| Topology | Cells for each message | For each member, for each message |
| --- | --- | --- |
| A fan-out to each member, which is 500 × 499 | 249 500 | 998 cells, about 559 KB |
| A sender-aggregated vector, and then a redistribution | 1 000 | 2 cells, about 1.1 KB |
| **To the sender only** | **500** | **1 cell, about 560 B** |

The fan-out topology costs about 168 MB each month at 10 group messages each
day. U4 sets the idle budget at 100 MB each month, thus the fan-out topology
alone exceeds U4 with one group.

Two properties come from the sender-only topology.

- **It adds no second fan-out.** §11.3.0 concedes that the flurry attack scales
  only logarithmically with the total user count. The jitter randomizes the order
  of a fan-out, and it does not remove the fan-out. A second fan-out for each
  message gives that attack a second sample set. This topology creates no second
  fan-out.
- **It needs no new state.** A receipt names one `msg_id` under the existing
  kind `0x07`, and Part 3 §3.5.4 gives the batch, the delay, and the carrier.
  There is no bitmap, no version counter, and no new wire kind.

**An offline sender.** The receipts wait in the queue of the sender under
`MSG_TTL`, which Part 3 sets at 45 days. The sender gets the full list at the
next connection. No other party waits for those receipts.

**The group setting.** The creator of a group sets the default for that group.
**[GRP-047]** **A member client MUST let its user override that default. **[GRP-048]** A member client MUST
NOT let a group compel a member to emit a read receipt.** Part 3 §3.5.4 keeps the default off for a new
contact.

> *Cause.* WhatsApp states that a user that turns off read receipts still
> reports in a group chat. A group is a read-receipt-always zone on that
> platform. In UMBRA that behavior lets a hostile group administrator, or a
> compelled one, collect a device-liveness series for each member.

## 11.8 Offline members and history

- **A new joiner receives no history by default.** History delivery needs the
  encryption of the backlog again for the joiner. That operation multiplies the
  cost, and it gives a new member a transcript from a period before that member
  joined. **[GRP-049]** An admin MAY turn on a limited history window by an explicit action.
  The default is off, and the maximum is 7 days.
- **An offline member is a forward-secrecy risk.** RFC 9420 §16.6 states this
  limit plainly for MLS, and the limit applies equally to sender keys. The keys
  stay in existence while one member has not deleted them.

  Thus UMBRA makes **automatic eviction mandatory for a member that stays
  silent longer than `GROUP_SILENT_EVICT`**, with a default of 30 days. §11.9.7
  gives the presence signal that measures that silence and the party that acts
  on it. **[GRP-050]** The UI
  MUST show this eviction. This is a security parameter and not housekeeping.
- **A group of two members is exempt.** Both members hold the `owner` role
  under §11.9, and tier T1 holds no sender key. The pairwise ratchet of Part 5
  gives the forward secrecy of that group. **[GRP-169]** A member of a group of
  two members MUST NOT evict the other member for silence.

## 11.9 Administration

The roles are `owner`, `admin`, `moderator`, `member`, and `observer`. **[GRP-051]** A group
MUST have two or more members with the `owner` role. One owner is one point of
failure for the administration, and U6 does not permit that condition.

### 11.9.0 Each group control object carries a type byte

Part 6 §6.6.3 gives the `GroupControl` wrapper and the seven control types.
This part defines seven objects that travel under application kind `0x10`.

| `control_type` | Object | Where |
| --- | --- | --- |
| `0x01` | `SenderKeyDistribution` | §11.3.2 |
| `0x02` | `JoinRecord` | §11.9.1 |
| `0x03` | Plain epoch | §11.9.2 |
| `0x04` | Granting epoch | §11.9.2 |
| `0x05` | Moderation epoch | §11.9.6 |
| `0x06` | `GroupPresence` | §11.9.7 |
| `0x07` | `GroupInvitation` | §11.9.1 |

**[GRP-125]** A sender MUST wrap each object of that table in a `GroupControl`.
**[GRP-126]** A receiver MUST take the object type from `control_type` alone.
**[GRP-127]** A receiver MUST NOT infer an object type from the length of a
record.

> *Cause.* An earlier draft put the objects under kind `0x10` and gave no
> type byte. A parser then had to tell a `SenderKeyDistribution` from a granting
> epoch by its length, and Part 6 §6.1.1 rule 4 permits one canonical form only.
> Part 7 §7.5.5 already carries this shape for a device-set control record.

### 11.9.1 The group roster key

```
GroupRosterSeed_g := 256 bits from the device CSPRNG
GroupRosterKey_g  := ML-DSA-65 keypair from GroupRosterSeed_g
```

- **[GRP-052]** A member MUST make `GroupRosterSeed_g` from the device CSPRNG at the join. **[GRP-053]** A
  member MUST NOT derive that seed from the `RootIdentity`. **[GRP-054]** A member MUST NOT
  derive that seed from `group_id`.
- **[GRP-055]** A member MUST store `GroupRosterSeed_g` in the **local identity table** of
  Part 4 §4.7.2. That table also holds the community identity seeds of Part 12
  §12.3.2 and the pairwise salts of Part 4 §4.2.2.
- **[GRP-056]** A member MUST make a different roster key for each group. **[GRP-057]** A member MUST NOT
  use a roster key outside the group that its table row names.
- **[GRP-058]** Each device of one member MUST use the same seed. Part 7 §7.4 and Part 7
  §7.5.1 carry the local identity table.

ML-DSA-65 is primitive 3 of Part 5 §5.1. This construction adds no primitive, no
crate, and no KDF label.

- **[GRP-059]** A `JoinRecord` MUST carry the ML-DSA-65 roster public key of
  the member that joins. A join record uses bucket `B2`, and §11.5 states that
  limit.

**The join flow.** A joiner needs a pairwise channel with each member, because
§11.3.2 attributes each group record by the L6 QueueE2E key. The flow below
opens those channels with one user action at the joiner and one at the
inviting admin. Each other member answers without a user action.

```
JoinRecord {
    version      u8          // 0x01
    group_id     [32]u8
    roster_pk    [1952]u8    // GroupRosterKey_g.pk of the joiner
}

GroupInvitation {
    version      u8          // 0x01
    group_id     [32]u8
    stage        u8          // 0x01 an offer, 0x02 a bundle
    body_len     u16
    body         [body_len]u8   // an offer: name_len u8 || name || roster_pk [1952]
                                // a bundle: a FileDescriptor of Part 13 §13.3
}

GroupInvitationBundle {
    version      u8          // 0x01
    group_id     [32]u8
    creator_pk   [1952]u8    // the roster public key of the creator
    epoch_count  u16
    epochs       [epoch_count]GrantingEpoch   // the authority path of §11.9.3
    member_count u16
    members      [member_count]MemberEntry
}

MemberEntry {
    roster_pk_hash  [32]u8   // SHA3-256 of the roster public key of the member
    role            u8
    invite_len      u16
    invite          [invite_len]u8   // a one-time invitation of Part 4 §4.3.1
}
```

A `JoinRecord` is 1 985 bytes. A `GroupInvitation` travels as a `GroupControl`
of Part 6 §6.6.3 with the `control_type` value `0x07`. The body of an offer is
the UTF-8 display name of the group and the `roster_pk` of the inviting admin.
The body of a bundle is a `FileDescriptor` of Part 13 §13.3, and that
descriptor names a `GroupInvitationBundle` on the chunk path. At `GROUP_MAX` the bundle
holds 500 one-time invitations, and it does not fit one `B3` cell.

1. The inviting admin sends an offer to the joiner on their pairwise channel.
   **[GRP-170]** A client MUST show an offer to the user, and it MUST NOT accept
   an offer without a user action. GRP-153 makes the client reject an offer
   for a `group_id` that it holds.
2. **[GRP-171]** A joiner that accepts MUST make `GroupRosterKey_g` under
   GRP-052 and send a `JoinRecord` on the same channel.
3. **[GRP-172]** The inviting admin MUST dispatch the plain epoch that adds the
   joiner together with that `JoinRecord` to each member. GRP-062 binds the
   roster key of the joiner through that record.
4. **[GRP-173]** The inviting admin MUST send a group request of Part 6 §6.6.7
   to each member for the joiner. That request names `group_id` and the
   `roster_pk_hash` of the joiner. Part 6 rule `WIR-344` makes a member that
   holds the plain epoch answer with a fresh one-time invitation, and no user
   action occurs. **[GRP-174]** A member MUST bind the pairwise channel that
   its grant opens to the roster entry that the request named. **[GRP-175]** A
   member MUST NOT answer a group request for a roster entry that its local
   roster does not hold.
5. **[GRP-176]** The admin MUST write the bundle on the chunk path of Part 13
   §13.3.3 over the connection of Part 13 §13.8. The admin fills each `invite`
   from the grant of that member, and then it sends the bundle stage to the
   joiner.
6. **[GRP-177]** A joiner MUST open each invitation of the bundle under Part 4
   §4.3.1. **[GRP-183]** A joiner MUST bind each channel that opens to the
   roster entry of that `MemberEntry`. **[GRP-178]** If the first-access lock
   of Part 4 rule `IDN-023` fails on an invitation, the joiner MUST show that
   event. The display names the member of that entry, and it names the
   inviting admin as the party that held the invitation.
7. In tier T2 the joiner then distributes its sender key under §11.3.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A group
> request tells each member that the joiner is a member, and a grant tells the
> inviting admin that the member answered. §11.5 states that a member learns
> the roster, thus this flow shows a member nothing that the roster does not
> show. G9 of Part 2 §2.3 holds against a party outside the group, and it does
> not hold between two members of one group. The inviting admin holds each
> invitation before the joiner does. An admin that opens an invitation itself
> takes the channel that a member binds to the joiner, and the first-access
> lock then fails at the joiner. GRP-178 shows that event, and Part 16 §16.3
> records the residual.

> *Cause.* An earlier draft gave the roster admission and nothing below it.
> The one introduction path in the tree was the contact share, and Part 6 rule
> `WIR-196` made each member answer by hand. A joiner at `GROUP_MAX` thus
> needed 499 approvals. Part 12 §12.6 lets a user join a community by a link,
> and a private group needs a join that costs the joiner one action.

### 11.9.2 Two classes of roster epoch

A **granting epoch** gives the `owner`, the `admin`, or the `moderator` role to a
member, or it takes that role away.

- **[GRP-060]** A granting epoch MUST carry an ML-DSA-65 signature from the roster key of the
  member that gives the role.
- **[GRP-061]** The signature MUST cover this preimage:

  ```
  "umbra/v1/group-grant" || group_id || epoch_index || previous_epoch_hash ||
  granter_id || grantee_id || grantee_roster_pk_hash || role
  ```

  Part 5 §5.11 holds the label `"umbra/v1/group-grant"`. **[GRP-106]** A signer MUST put that
  label first in the preimage. **[GRP-107]** A verifier MUST reject a signature over a
  preimage that carries a different label.
- **[GRP-062]** A verifier MUST check that signature against a roster key. An earlier granting
  epoch or a join record binds that roster key to the granter. The creator of
  the group is the first granter. A member receives the roster key of the
  creator in the group invitation.
- **[GRP-063]** A verifier MUST reject a granting epoch from a granter that holds a role below
  `admin`.

A **plain epoch** adds a member, removes a member that holds the `member` or the
`observer` role, or records a self-removal.

- **[GRP-064]** A plain epoch MUST NOT carry a signature.
- **[GRP-065]** A verifier MUST take the authority of a plain epoch from the L6 QueueE2E key
  that opened the record. That key names one member.
- **[GRP-066]** A verifier MUST discard a plain epoch if the local roster gives that member no
  role that permits the operation.

**[GRP-067]** A member client MUST offer a self-removal. A self-removal is a plain epoch, and
the L6 QueueE2E key names the member that leaves.

### 11.9.3 Retention of the granting chain

- **[GRP-068]** A member MUST retain each granting epoch on the authority path to a current
  role.
- **[GRP-069]** A member MUST discard a granting epoch that a later granting epoch supersedes,
  after that member verified the successor.

> *Cause.* A granting epoch is a transferable statement. Without this rule the
> seizure of one member device gives a transferable proof of each role grant.
> That proof covers each grant that each administrator made for the life of the
> group. This rule keeps the
> verification of a new joiner and removes the unbounded history.

### 11.9.4 Conflict, fork, and rate

- The epoch index gives the order of the roster chain. If two epochs name one
  predecessor, the role precedence applies, which is owner, then admin, then
  moderator. If that does not resolve the two epochs, the lower
  `SHA3-256(previous_epoch_hash || member_id)` applies. **[GRP-117]** A client
  MUST apply that order. Part 12 §12.5.2 rule 6 gives the cause of the hash,
  which is that a party grinds a low member identifier and a hash of the
  predecessor is not known before the race.
- **Two different members that make two successors is normal use.** **[GRP-118]** A client
  MUST NOT show a fork for that case. **[GRP-119]** A member whose epoch the order above did
  not select MUST publish that epoch again against the selected epoch.
- The roster is hash-chained. **[GRP-070]** If a member sees two different successors to one
  epoch **from one member**, that member MUST show the fork. **[GRP-071]** That member MUST NOT
  select one successor silently. One member that makes two successors
  equivocated, and that act is evidence.
- If the two successors are granting epochs, the signature names the party that
  made the fork. **[GRP-072]** The client MUST name that party.
- **[GRP-073]** If the two successors are plain epochs, the client MUST show that the members
  disagree. **[GRP-074]** The client MUST NOT name a party. A plain epoch carries no
  signature, thus the attribution is not transferable.
- Part 12 §12.5.2 rule 6 states the same three rules for a community.
- **[GRP-075]** A client MUST dispatch a granting epoch and a join record with the jitter of
  §11.3.0.
- `ROSTER_RATE_LIMIT` is 1 epoch for each member in each 60 s.
  `GROUP_EPOCH_RATE` is 6 epochs for each group in each 60 s. `GRANT_RATE` is 1
  granting epoch for each group in each 300 s **and** 4 granting epochs for each
  group in each 24 h. **[GRP-076]** A member MUST discard an epoch above one of these limits.

> *Cause.* Without a limit, one member denies the delivery to a 500-member group,
> and U6 does not permit that condition. Trail of Bits TOB-DISCE2EE-1 found this
> class of problem in an MLS deployment. The daily count bounds the cumulative
> cost. One granting epoch to 500 members costs 4.1 MB of uplink, thus a rate
> limit alone is not a bound.

### 11.9.5 What this costs, stated

> **This is a trade, and §2.4 requires the text to state it.** A granting epoch
> is a signed statement. A party that seizes the device of a member gets a
> transferable proof of the current role grants of the group. G10 covers the
> message content. After this change G10 does not cover the group
> administration, and Part 16 §16.3 records that exposure.
>
> A message stays unsigned, and a plain epoch stays unsigned. Part 5 §5.7 does
> not change. The `granter_id` and the `grantee_id` in a granting epoch are
> the group-scoped `member_id` of §11.2. Thus the proof names a member of this
> group, and it names no identity outside it. That statement is the full
> concession.
>
> A granting epoch, a moderation epoch, and a join record each use bucket `B2`,
> and content uses bucket `B1`. Two colluding queue relays that see two `B2`
> cells inside the §11.3.0 jitter window link the two queues to one group.
> `GRANT_RATE` bounds the frequency of a granting epoch, and it does not conceal
> the event. Part 16 §16.3 records that residual.

### 11.9.6 The moderation epoch and the two moderator actions

An author deletes, and a moderator deletes. The two use different authorization,
and they leave different evidence.

**An author deletion** uses kind `0x05`, exactly as Part 7 §7.5.6 gives it. A
receiver accepts it only when the L6 QueueE2E key that opened the record names
the member that sent the target. There is no role check and no signature, thus
the deniability of Part 5 §5.7 is untouched. A tombstone is terminal, and it
beats an edit from the same author at each position.

**A moderator action** has two forms.

| Action | The Part 15 §15.6.4 record key | Reversible | The member device |
| --- | --- | --- | --- |
| **Hide**, which is the default | Kept | Yes, by a later epoch | Keeps the data, out of the default view |
| **Remove** | Discarded | No | Overwrites the record |

Both actions travel inside a **moderation epoch**. A moderation epoch is a
signed and hash-chained roster object, in the manner of the granting epoch of
§11.9.2. Thus a private group gains the evidence property that Part 12 §12.4.1
gives a community.

1. **[GRP-077]** A moderation epoch MUST carry an ML-DSA-65 signature from the
   `GroupRosterKey_g` of the acting member.
2. **[GRP-078]** The signature MUST cover this preimage:

   ```
   "umbra/v1/group-moderation" || group_id || epoch_index ||
   previous_epoch_hash || actor_id || actor_role || action_count ||
   the action list
   ```

   Each action in the list names the action and the `msg_id` of the target.
   §11.2.1 makes that `msg_id` one value at each member, in each tier. The
   epoch MAY carry the `member_id` of the author beside the list as a rendering
   hint. **[GRP-179]** A signer MUST NOT put the author of a target in the
   preimage. **[GRP-180]** A client MUST resolve the author through `msg_ref`, and it
   MUST NOT take the author from the hint. Part 6 §6.6 keys each local index by
   that value.
   Part 5 §5.11 holds the label `"umbra/v1/group-moderation"`. **[GRP-108]** A signer MUST put that
   label first in the preimage. **[GRP-109]** A verifier MUST reject a signature over a
   preimage that carries a different label. The two group labels are different,
   thus a granting epoch and a moderation epoch cannot be confused.
3. **[GRP-079]** A verifier MUST check that signature against a roster key. An earlier
   granting epoch or a join record binds that roster key to the actor. **[GRP-080]** A client
   MUST NOT apply an action before that check succeeds.
4. **[GRP-081]** A verifier MUST reject a moderation epoch from a member that holds a role
   below `moderator`.
5. **[GRP-082]** A client MUST show a placeholder that names the action and the acting role.
   **[GRP-083]** The placeholder MUST NOT vanish without a trace.
6. **[GRP-084]** A moderator MUST NOT act on a message that an earlier epoch already removed.
7. `MOD_ACTION_MAX` is 20 actions in one moderation epoch.
8. **[GRP-085]** The interface MUST make **hide** the default. **[GRP-086]** A **remove** MUST need a second
   confirmation, and **[GRP-087]** the interface MUST state that a remove is not reversible.
9. A moderation epoch uses bucket `B2`, and §11.5 states that limit. **[GRP-088]** A client
   MUST dispatch a moderation epoch with the jitter of §11.3.0.
10. **[GRP-181]** A member MUST retain a moderation epoch only while it is the
    current statement about a target it holds. **[GRP-182]** A member MUST fold
    an older moderation epoch into local unsigned state and keep its hash for
    the chain check.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A
> moderation epoch is a signed statement that a named role acted on a named
> `msg_id`. An earlier draft also signed the author of the target. A
> moderator then swore to an attribution under a key that the granting chain
> binds to a person. That statement was transferable evidence against G10.
> The preimage now names no author, and GRP-181 bounds what a seized device
> holds to the current statements. A member that inspects the chain sees the
> hashes and the current epochs. It does not see each earlier act, and
> mitigation 3 below keeps the count at each epoch. Part 16 §16.3 records the
> residual.

**The residual, stated.** A compelled moderator destroys group history on the
device of each member. That cost is real. Part 16 §16.1 makes an empty
compellable set the method of this specification, and a moderator is a named
natural person inside a private group. Part 16 §16.1 records that party.

Four mitigations bound the damage.

1. The epoch chain records the act. A member that inspects the chain sees the
   time of the act, the acting role, and each target that the act named.
2. §11.9 requires two or more members with the `owner` role. Thus a compelled
   moderator does not leave the group without an administrator, and the owners
   read the act in the chain.
3. **[GRP-089]** At each epoch, a client MUST show the number of removals since the previous
   epoch.
4. A restore from a Part 4 §4.7.2 backup that predates the epoch recovers the
   messages. **[GRP-090]** The client MUST state that fact at the moment it applies a removal
   epoch.

**What the interface states.**

- Hide: "This takes the message out of the view of each member. A member keeps
  the message on their device, and a later change puts it back."
- Remove: "This deletes the message on the device of each member. You cannot
  undo this. Each member sees that you removed a message."
- At a removal epoch: "A moderator removed N messages. A restore from a backup
  that predates today brings them back."

> Part 12 §12.5 does **not** import this section. A community has the
> authoritative owner devices of Part 12 §12.2, and a private group has none.
> Part 12 states its own community roster and its own moderation epoch.

### 11.9.7 Presence, and the eviction that it drives

§11.8 evicts a member that stays silent longer than `GROUP_SILENT_EVICT`, and
it calls that rule a security parameter. This section gives the signal that the
rule reads and the party that acts on it.

**The signal is a presence record, and it is not a receipt.**

```
GroupPresence {
    version   u8         // 0x01
    group_id  [32]u8
}
```

The record is 33 bytes. It travels as a `GroupControl` of Part 6 §6.6.3 with the
`control_type` value `0x06`, inside an application record of kind `0x10`. It
fits bucket `B0`.

- **[GRP-128]** A member MUST emit a `GroupPresence` record in each
  `PRESENCE_INTERVAL` in which it sent no other record to that group.
  **[GRP-129]** A member MUST emit that record to each member that the local
  roster gives the role `admin` or above. **[GRP-130]** A member MUST NOT emit
  that record to a member below that role.
- **[GRP-131]** A member MUST dispatch a presence record with the jitter of
  §11.3.0.
- **[GRP-132]** An admin MUST count a member as silent when it took no record
  and no presence record from that member for `GROUP_SILENT_EVICT`.
  **[GRP-133]** An admin MUST then remove that member with a plain epoch of
  §11.9.2. **[GRP-134]** An admin MUST NOT remove a member that it counts as
  silent for a shorter period.
- **[GRP-166]** If the silent member holds `moderator` or above, the admin
  MUST first remove that role with a granting epoch. §11.9.2 lets a plain
  epoch remove a `member` or an `observer` only.
  **[GRP-167]** A member MUST NOT count a silence demotion against
  `GRANT_RATE`. A backlog of silent members at `GROUP_MAX` cannot clear under
  that rate.
- **[GRP-168]** If the removal leaves fewer than two owners, the admin MUST
  hold the removal. **[GRP-184]** The admin MUST then prompt each surviving
  owner to grant `owner` to another member. §11.9 rule GRP-051 gives the
  floor, and §11.8 exempts a group of two members.
- **[GRP-135]** A client MUST NOT treat a delivery receipt or a read receipt as
  a presence signal. Part 3 rule `NET-059` makes a receipt off by default, and
  §11.7.1 sends a receipt to one sender only.

**The cost.** A member emits at most one presence record in each
`PRESENCE_INTERVAL`, and §11.9 requires two or more owners. A group with 4
members at `admin` or above costs 4 `B0` cells for each member in each interval.
At the §11.10 interval of 7 days that is 4 × 560 = 2 240 bytes each week for
each member. The count follows the administrator count and it does not follow
`GROUP_MAX`.

> *Cause.* An earlier draft made the eviction mandatory and named no signal.
> `NET-059` makes a receipt off by default for a new contact, `GRP-047` lets a
> member override the group default, and §11.7.1 sends a receipt to the sender
> of one message only. Thus no member held the data that the rule needed, and
> two members reached two different eviction decisions. A presence record to the
> administrators gives one audience the same view, and §11.9.2 already gives an
> administrator the authority to make a plain epoch.
>
> The rule now measures **silence** and not connectivity. A member that reads
> and never posts emits a presence record, thus a lurker stays in the group. A
> member whose device is gone emits nothing, and RFC 9420 §16.6 gives the
> forward-secrecy cause that §11.8 states.

## 11.10 Parameters

| Parameter | Value |
| --- | --- |
| `GROUP_MAX` | 500 |
| `T1_MAX` (pairwise fanout) | 50 |
| `GROUP_SILENT_EVICT` | 30 days (§11.9.7) |
| `PRESENCE_INTERVAL` | 7 days (§11.9.7) |
| `HISTORY_WINDOW` | 0 (off) by default, maximum 7 days |
| `ROSTER_RATE_LIMIT` | 1 epoch for each member in each 60 s |
| `GROUP_EPOCH_RATE` | 6 epochs for each group in each 60 s |
| `GRANT_RATE` | 1 for each group in each 300 s, and 4 for each group in each 24 h |
| `SENDER_KEY_GENERATIONS` | 3 for each member |
| `SENDER_KEY_MAX_AGE` | 7 days, measured by the sender from the creation of the `seed` (§11.3.3) |
| `SENDER_KEY_ROTATION` | 5 days, measured in the same manner, and at a membership change (lazy, §11.3.1) |
| `SENDER_KEY_MAX_SKIP` | 1 000 records on one sender chain (§11.3), which equals `MAX_SKIP` |
| `KEY_REQUEST_RATE` | 8 key requests to one peer in each 24 h (Part 6 §6.6.11) |
| `FANOUT_JITTER` | exponential, mean 400 ms, p99 total fan-out < 3 s |
| `FANOUT_MAX_RATE` | 200 cells/s for each group |
| `POLL_GROUP_MAX` | 100 members (§11.11) |
| `MENTION_MAX` | 16 mentions in one record, and Part 6 §6.6.5 gives the field |
| `POLL_OPTION_MAX` | 12 options in one poll |

Part 12 §12.9 owns `MOD_ACTION_MAX`, and §11.9.6 quotes it. Rule `SCP-010` of
Part 1 gives one owner to each constant.

**The four periods hold one order.** **[GRP-165]** A revision MUST keep
`SENDER_KEY_ROTATION` below `SENDER_KEY_MAX_AGE`, `SENDER_KEY_MAX_AGE` at or
below `GROUP_SILENT_EVICT`, and `GROUP_SILENT_EVICT` at or below `MSG_TTL`.

> *Cause.* A sender rotates before its generation reaches the age at which a
> receiver may discard a superseded copy. Thus a live generation never expires
> at a receiver. A member that stays silent for `GROUP_SILENT_EVICT` leaves
> under §11.8 before its retained keys outlive their use. A record waits at
> most `MSG_TTL` in a queue, and GRP-159 keeps the `seed` for that period after
> the last send. Thus each record that arrives has a key that a request can
> reach.

## 11.11 A mention, a reply, and a poll in a group

Part 6 §6.6.5 gives the rich record and Part 6 §6.6.6 gives the poll. This
section gives the group rules for the three.

**The nesting order is fixed.** A group content record is a `GroupRecord` of
§11.2.1, and a rich record sits inside it.

```
AppMessage kind 0x12  →  GroupRecord( group_id )
                      →  inner_kind 0x09  RichRecord( reply, mentions, forward )
                      →  inner_kind 0x01  Text
```

- **[GRP-136]** A sender MUST put a `GroupRecord` outside a `RichRecord`.
  **[GRP-137]** A sender MUST NOT put a `GroupRecord` inside a `RichRecord`.
  Part 6 rule `WIR-163` rejects the second order.

**A mention names a member by its roster key.**

- **[GRP-138]** A sender MUST compute a mention identifier under Part 6
  §6.6.5, with the `group_id` as the scope and the ML-DSA-65 public key of the
  `GroupRosterKey_g` of the member as the member key.
- **[GRP-139]** A receiver MUST take that roster key from the join record of
  §11.9.1 or from a granting epoch of §11.9.2. **[GRP-140]** A receiver MUST
  discard a mention that names no member of the local roster.
- **[GRP-141]** A client MUST NOT show the mention list of a record to a member
  that the list does not name. Thus a member does not learn who else the sender
  named.

> *Cause of GRP-141.* The mention list travels to each member, because §11.3
> sends one ciphertext to each queue. A client that rendered the full list would
> tell each member which other members the sender chose. That is a social fact
> that the sender did not state to the group, and §11.5 already gives a member
> the roster and nothing more.

**A reply target is a `msg_id`, and §11.2.1 makes that value one value at each
member.** Thus a reply resolves at each member without a new field.

- **[GRP-142]** A receiver MUST resolve a reply target inside the group that
  carried the record. **[GRP-143]** A receiver MUST NOT resolve a reply target
  against a pairwise conversation.

**A poll has no total order, thus a count is local.**

- **[GRP-144]** A member MUST send a `PollVote` of Part 6 §6.6.6 to each member,
  with the fan-out of §11.3.0. **[GRP-145]** A member MUST NOT send a vote to
  the poll author alone.
- **[GRP-146]** A client MUST count the votes that it holds. **[GRP-147]** A
  client MUST NOT render a poll count as an agreed count. §11.7 gives a group no
  total order across senders, thus two members can hold two different counts at
  one moment.
- **[GRP-148]** A client MUST show that a count is the local view.

**The cost.** A poll is one fan-out and a vote is a second fan-out. At
`GROUP_MAX` one poll with a full turnout costs 499 cells for the poll and
499 × 499 cells for the votes. **[GRP-149]** Thus a client MUST NOT offer a poll
in a group above `POLL_GROUP_MAX` members. §11.10 gives that value.

> *The derivation of `POLL_GROUP_MAX`.* A vote is a `B0` cell at 560 bytes,
> because Part 6 §6.6.6 gives a vote a body of at most 30 bytes at
> `POLL_OPTION_MAX`. A group of *N* members that all vote costs
> *N* × (*N* − 1) cells. At *N* of 100 that is 9 900 cells and 5.54 MB across
> the group, which is 55 KB for each member. At *N* of 500 it is 249 500 cells
> and 140 MB, which is 279 KB for each member and one burst of 499 cells for
> each voter. §11.7.1 rejects the same shape for a receipt fan-out, and this
> limit follows that decision.
