# UMBRA Protocol Specification — Part 11: Private Groups (2–500)

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 11.1 The decision: no MLS, and no fan-out

UMBRA does **not** use MLS (RFC 9420) for v1. This decision needs a cause,
because MLS is the obvious answer and it is the incorrect answer here.

MLS is a **server-fanout protocol**. Its primary property is a bandwidth of
O(log N) for each commit, through TreeKEM. That property counts the bandwidth
that the *server* saves when it fans one ciphertext out to N recipients. UMBRA
has a group queue (§11.2), and that queue is a sequencer for records. It learns
what §11.5 says a group-queue relay learns, and no more. MLS would additionally
put `group_id`, `epoch`, and the ratchet tree at that party.

The costs that MLS causes are the costs that UMBRA cannot pay:

- **`group_id` and `epoch` are cleartext by design.** RFC 9420 §16.4.1 states
  plainly that MLS gives no mechanism to protect them from the Delivery Service.
  A seized relay collects each member of a group in one query. A correction
  needs a rewrite of each `PrivateMessage` header for each recipient.
- **MLS needs a total order on the commits**, which is one commit in each epoch.
  UMBRA has no total order across the two replicas of a group queue (§11.2.2),
  and §11.7 gives no total order across senders. Thus MLS needs a sequencer,
  and the party that sequences learns the group. The group queue orders
  records at one replica only, and it learns no epoch and no roster.
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
it speaks the group queue of §11.2 internally. This method keeps DMA
interoperation. It also keeps three costs out of a core that has to operate on
a phone. Those three costs are a 130-page state machine, an O(N) ratchet tree,
and a total-ordering requirement.

**And no fan-out.** UMBRA also does not send one copy of a group message to
each member. A group of 2 to 500 members uses **one relay-held group queue**,
replicated on two relays. A member uploads one record for each message. No
relay receives a recipient list.

> *Cause.* Draft 0.1.0 attributed each group record by the pairwise channel
> that carried it, and that one choice set every group cost. A text to 500
> members was 499 copies of one `B1` cell, which is 1.05 MB of uplink. A join
> at 500 members opened 499 pairwise channels. A membership change made each
> member distribute a sender key again, which is N × (N − 1) sends. A member
> of six 25-person groups held 144 inbound group queues. The pairwise
> attribution bought two properties: an insider cannot forge the authorship
> of a record, and no relay holds a roster. The pairwise tag vector of
> §11.3.3 keeps the two properties with a different mechanism, and it drops
> the fan-out. The tiers T1, T2, and T3 of 0.1.0, the sender keys, the lazy
> rekey, the re-broadcaster, and the fan-out jitter are retired. One
> mechanism serves every group size.

## 11.2 The group queue

A **group queue** is a relay-held, retained, many-reader mailbox. It is a queue
kind beside the pairwise queue of Part 3 §3.2, and Part 3 §3.2.7 owns that
kind. A relay that serves queues serves group queues, and no new relay role
exists. Part 6 §6.4.5 gives the eleven group-queue commands `GNEW`, `GIDS`,
`GPOST`, `GSEQ`, `GSUB`, `GMSG`, `GUNSUB`, `GKEY`, `GDEL`, `GNREG`, and
`GNUNREG`, and Part 6 §6.4.6 gives the record that a group queue holds. This
part states what a member does with them.

A group queue holds four credentials. The relay makes `GroupQueueId` from its
CSPRNG at `GNEW`. The reader credential `read_pk`, the writer credential
`write_pk`, and the owner credential `own_pk` are X25519 public keys. The
reader and writer credentials change at each group epoch, and §11.3.1 derives
them from the epoch secret. The owner credential comes from the creator's
CSPRNG, and every member of role `admin` or above holds it.

- **[GRP-185]** A member MUST authorize a group-queue command with the deniable
  authenticator of Part 3 §3.2.3, with `read_sk`, `write_sk`, or `own_sk` in
  the place of `Q*_auth_sk` and `GroupQueueId` in `queue_id`. Part 3 rule
  `NET-015` holds, thus no group-queue command carries a signature.
- **[GRP-186]** A member MUST carry a group-queue command on a transport
  session that carries no other command range. **[GRP-187]** One such session
  MUST carry one group queue.

**What the group queue costs.** The table below counts the wire bytes of Part 6
§6.9 for one text message of the modal 350 bytes of Part 3 §3.12, and it puts
the 0.1.0 figure for the same member count beside each one. A record fills to
the "record on a `GMSG`" row of the group-queue capacity table of Part 6 §6.9.
That row is the L5 payload of the bucket less the 4-byte `seq` of a `GMSG`,
which is 390, 1 926, 8 070, and 32 646 bytes at `B0` to `B3`. The dense tag
vector of §11.3.3 costs 12 bytes for each member, thus a record at N members
holds a text of `1 841 − 12N` bytes in `B1` and `7 985 − 12N` bytes in `B2`.
The modal text stays in `B1` up to N = 124.

| Cost | N = 3 | N = 25 | N = 120 | N = 500 |
| --- | --- | --- | --- | --- |
| Uplink for each message, this part (one record × `GROUP_REPLICAS`) | 2 × `B1` = 4 192 B | 4 192 B | 4 192 B | 2 × `B2` = 16 480 B |
| Uplink for each message, 0.1.0 ((N − 1) × `B1`) | 4 192 B | 50 304 B | 249 424 B | 1 045 904 B |
| Download for each member for each message, this part (one record from one replica) | 2 096 B | 2 096 B | 2 096 B | 8 240 B |
| Download for each member for each message, 0.1.0 | 2 096 B | 2 096 B | 2 096 B | 2 096 B |
| Rotation, each member downloads (§11.4.2) | one `B2` record, 8 240 B | one `B3` record, 32 860 B | one `B3` chunk, 32 860 B | one `B3` chunk, 32 860 B |
| Rotation, the rotator uploads (§11.4.2) | 2 × `B2` = 16 480 B | 2 × `B3` = 65 720 B | 5 chunks and a `B1` descriptor record, 168 492 B | 19 chunks and a `B2` descriptor record, 640 820 B |
| A membership change, 0.1.0 (each member sends (N − 1) `B1` and reads (N − 1) `B1`) | 4 192 B up, 4 192 B down | 50 304 B up, 50 304 B down | 249 424 B up, 249 424 B down | 1 045 904 B up, 1 045 904 B down |
| Join, the joiner downloads (§11.9.1: one `B2` offer, one `B1` or `B2` admit, the snapshot chunks of §11.9.8) | 1 chunk, 73 960 B | 2 chunks, 106 820 B | 5 chunks, 205 400 B | 21 chunks, 731 160 B |
| Join, each member downloads (one add record of §11.9.2) | `B1`, 2 096 B | `B1`, 2 096 B | `B2`, 8 240 B | `B2`, 8 240 B |
| Join, 0.1.0 | 2 pairwise channels | 24 pairwise channels | 119 pairwise channels | 499 pairwise channels, a 500-invitation bundle on the chunk path, 499 group requests |

The rotation rows and the join rows use two admins in the 25-member group and
in the 500-member group. §11.4.2 and §11.9.8 give each derivation.

### 11.2.1 Creation and replicas

`GROUP_REPLICAS` is 2. The creator makes one group queue on each of two relays,
and every member sends each record to the two of them.

**The group identifier.** **[GRP-151]** The creator MUST make `group_id` from
the device CSPRNG at the creation of the group. **[GRP-152]** The creator MUST
NOT derive `group_id` from a member identity, from `GroupRosterSeed_g`, or from
an earlier `group_id`. **[GRP-153]** A member MUST reject an invitation to a
`group_id` that it already holds. `group_id` travels inside the invitation and
inside the AEAD of each record, and no relay reads it. `GroupQueueId` is the
relay-side name, and it carries no relation to `group_id`.

- **[GRP-188]** The creator MUST make `own_sk` for each replica from the device
  CSPRNG. **[GRP-189]** The creator MUST NOT derive `own_sk` from `group_id`,
  from `GroupRosterSeed_g`, or from the epoch secret of §11.3.1.
  **[GRP-190]** The creator MUST make a different `own_sk` for each replica.
- **[GRP-191]** The creator MUST send `GNEW` to two relays whose entries carry
  different `operator_id` values and different jurisdiction blocs, under
  invariant 1 and invariant 2 of Part 3 §3.4.6. Part 10 §10.6.3 gives the bloc
  list. **[GRP-192]** A creator that finds no such pair MAY relax the bloc
  invariant in the manner of Part 3 rule `NET-200`, and Part 3 rule `NET-201`
  makes it show that relaxation.
- **[GRP-193]** A `GNEW` MUST end with an `Admission` of Part 13 §13.2. A
  group-queue creation is a gated path of that table.
- **[GRP-194]** A sender MUST send the same record bytes to each replica, each
  under the ARQ of Part 3 §3.7. **[GRP-195]** A client MUST put a record in the
  `accepted` state of Part 14 §14.9.1 when one replica returned `GSEQ`.
  **[GRP-196]** A client MUST continue the ARQ to the other replica in the
  background after that acceptance. **[GRP-197]** A client MUST report a
  replica that never accepts as a link fault under Part 10 §10.4.2.
- **[GRP-198]** A `GPOST` MUST NOT carry an `Admission`. The relay applies
  `GROUP_POST_RATE` of Part 3 §3.2.7 to each group queue, and Part 3 rule
  `NET-218` continues the ARQ after the `LIMIT` that it answers.

**No reachable replica.** **[GRP-199]** If a client reaches no replica of a
group, it MUST show one line at the top of the message list of that group and
keep each outbound record of that group `queued`. The line reads "The relays of
this group do not answer. Messages wait." **[GRP-200]** That line MUST end
without a user action when one replica accepts a session.

> *Cause.* Part 14 §14.9.2 holds a closed table of client-wide degraded
> states, and rule `IMP-081` keeps it closed. Two dead replicas are a
> condition of one conversation and not of the client, thus not a row of that
> table. Without a line the user sees a `queued` mark for hours and reads it
> as a failure, which rule `IMP-076` forbids. The line takes the form of the
> `ingress unreachable` row.

### 11.2.2 Subscription, cursors, and gap repair

The relay assigns `seq` for each group queue. It is a `u32` that starts at 1,
strictly increasing, and never reissued. It is relay-local, thus the two
replicas of one group give two unrelated sequences.

- **[GRP-201]** A client MUST NOT use `seq` as a message identifier or as an
  order across replicas. §11.7 gives the order.
- **[GRP-202]** A reader device MUST hold one cursor for each replica, as
  mutable state of Part 7 §7.5.3. There is no acknowledgment from a reader,
  and Part 3 §3.2.7 retains by time and by quota only.
- **[GRP-203]** A reader MUST subscribe to one replica in each session, chosen
  at random. **[GRP-204]** A reader MUST alternate the replicas across its
  sessions. A `GSUB` from a cursor with a backlog above `DRAIN_THRESHOLD`
  follows Part 3 rule `NET-037`.
- **[GRP-205]** A reader that observes a gap in the `counter` of one sender
  (§11.3.5) for longer than `GROUP_GAP_TIMEOUT` MUST open a session to the
  other replica and fetch from its cursor there. §11.10 gives 60 s.
  **[GRP-206]** A reader MUST discard a record that it already holds by the
  triple of `GRP-035`, whichever replica carried it. Part 6 rule `WIR-065`
  gives the same rule for a pairwise duplicate.
- **[GRP-207]** A device MUST hold a cursor at or above the newest epoch-key
  record of the group (§11.4.2) on one replica before it sends a `GPOST`. Thus
  a device never posts under a stale epoch after a rotation that it could have
  read.

**A replica that no circuit reaches.** Part 3 rule `NET-169` ends a build
after `CIRCUIT_BUILD_TIMEOUT`. A relay that is down is the case that the second
replica exists for, thus that end is not the end of the session.

- **[GRP-390]** A client whose circuit to one replica ends under `NET-169`
  MUST keep each other circuit of its group-queue session. It MUST fail each
  command that waited for the circuit that ended, and `GRP-195` takes the
  record at the other replica.
- **[GRP-391]** A reader whose `GSUB` found no circuit under `NET-169` MUST
  subscribe at the other replica in the same session. It MUST NOT try a third
  time in that session. `GRP-204` gives the replica of its next session.
- **[GRP-392]** A client whose group-queue session ends before an answer to a
  `GPOST` MUST send the same bytes in its next session, under Part 3 rule
  `NET-072`, and the relay answers with the `seq` that it holds (`NET-239`).
  **[GRP-393]** A client that sends a `GNEW` again in the same way MAY leave
  one empty group queue at a relay that answered the first one, and
  `GROUP_RETENTION` ends it.
- **[GRP-394]** A client whose group-queue link ends MUST wait
  `GROUP_RELINK_FIRST` before a new link. It MUST double the wait after each
  link that ended before a circuit was ready, up to `GROUP_RELINK_MAX`, and
  MUST return to `GROUP_RELINK_FIRST` after a link on which a circuit was
  ready.

> *Cause.* An earlier implementation ended the whole session when one
> circuit failed, and opened no new link on its own. A group then went silent
> until a record of a contact woke the client, and one relay that was down
> made the session of every group fail. The wait of `GRP-394` keeps a client
> whose guard is down from a burst of links, which the guard would see.
- A reader in Instant mode registers one notify queue for the group with
  `GNREG`, and Part 8 §8.5.2 gives that queue, its handle, and the digest that
  the relay writes into it.

> *Cause.* A single-reader queue of Part 3 §3.2 holds its cursor at the relay
> through the acknowledgment. A group queue has N readers, and a relay that
> held N cursors would hold a reader count with a liveness series for each
> one. The cursor at the device costs the relay nothing and tells it nothing.
> The two replicas do not exchange records, thus a record at one replica and
> not the other is the ordinary case after a `NACK`, and the reader repairs
> the gap itself.

### 11.2.3 Retention and quota

Part 3 §3.2.7 owns `GROUP_RETENTION` (30 days from acceptance),
`GROUP_QUEUE_QUOTA` (32 MiB of records for each group queue),
`GROUP_POST_RATE`, `GROUP_READ_GRACE` (30 days), `GROUP_WRITE_GRACE` (24 h),
`GROUP_IDLE_TTL` (60 days), and `GROUP_NOTIFIER_MAX`. The relay erases the
oldest record first when the retention or the quota bound is reached.

- **[GRP-208]** A client that was offline longer than `GROUP_RETENTION` MUST
  show a gap in the group, in the manner of Part 6 rule `WIR-117`. The records
  of that period are gone from each replica, and no party holds them for the
  client.
- **[GRP-209]** A client MUST NOT ask any member for a record that the
  retention erased. §11.8 gives the history rule.
- **[GRP-210]** A client that finds the group queue gone at each replica MUST
  show the group as closed. A relay erases a group queue at `GDEL` and after
  `GROUP_IDLE_TTL` without an accepted `GPOST` or `GSUB`.

`GROUP_RETENTION` equals `GROUP_SILENT_EVICT` of §11.9.7 deliberately. A member
silent for 30 days is evicted, thus no member needs a record older than the
retention. `GROUP_EPOCH_GRACE` of §11.3.2 equals `GROUP_WRITE_GRACE`
deliberately. A member that still writes under the previous epoch inside the
grace is a member whose record the relay still accepts.

## 11.3 The group record

Part 6 §6.4.6 gives the layout of `GroupQueueRecord`. Its fixed part is 24
bytes: `version`, `kind`, `epoch` (the group epoch `e`), `slot` (the slot index
`t`), a 12-byte `nonce`, and `body_len`. Kind `0x01` is a content record and
kind `0x02` is an epoch-key record (§11.4.2). The relay reads `version`,
`kind`, `epoch`, `slot`, and the bucket only.

- **[GRP-211]** A sender MUST fill a record to the fixed length of its bucket,
  in the manner of Part 6 rule `WIR-024`, with zero bytes inside `body` after
  the true content. For kind `0x01` the AEAD covers the fill.
- **[GRP-212]** A sender MUST draw `nonce` from the device CSPRNG for each
  content record. **[GRP-213]** A sender MUST set `nonce` to zero on an
  epoch-key record. That record has no record-level AEAD, and §11.4.2 gives
  the cause.

The body of a content record is `ChaCha20-Poly1305( K_rec(e,t), nonce,
ContentPlain, ad )` with `ad = "umbra/v1/group-record" || group_id || BE32(e)
|| BE32(t)`. §11.3.1 gives `K_rec`.

- **[GRP-214]** A sender MUST bind `ad` as the associated data of that AEAD.
  Thus a member that holds the slot key cannot move a record to a different
  slot, to a different epoch, or to a different group.

`ContentPlain` holds `sender_index` (the member index of §11.9.1), `counter`
(strictly increasing for each member in each epoch, from 1), `roster_epoch`
(the roster epoch whose active-member order gives the tag order), `tag_mode`
(`0x01` dense, `0x02` sparse), `tag_count`, the tags, `app_len`, one
`AppMessage` of Part 6 §6.6 in `app`, and the fill. Part 6 §6.4.6 gives the
layout. In dense mode the tags are one 12-byte tag for each active member at
`roster_epoch` in index order, sender included, and the sender's own position
holds 12 zero bytes. In sparse mode each entry is a member index and a tag, in
index order with no repeat.

- **[GRP-215]** A sender MUST use dense mode for every `AppMessage` kind except
  a `GroupControl` of type `0x06` (`GroupPresence`). **[GRP-216]** A sender
  MUST use sparse mode for a `GroupPresence`, with one entry for each member of
  role `admin` or above. **[GRP-217]** A receiver that finds no entry for
  itself in a sparse record MUST discard that record as unattributed, unless
  the receiver holds role `admin` or above and the record is a
  `GroupPresence`.
- **[GRP-218]** A sender MUST set `roster_epoch` to the newest roster epoch
  that its device holds.
- **[GRP-219]** A group content record MUST NOT carry a wrapper that names the
  group. The queue names the group, and `group_id` sits in `ad`.

> *Cause.* Draft 0.1.0 wrapped each group content record in a `GroupRecord`
> of kind `0x12` that carried `group_id`, because a group record travelled on
> a pairwise queue that carried other conversations. A group record now
> travels on the group queue only. Part 6 §6.6.2 retires kind `0x12`, and
> `ad` binds `group_id` so that a replay into a second group fails at the AEAD.

### 11.3.1 The epoch and the slot chain

Each group holds a **group epoch** `e`, a `u32` that starts at 1 at creation
and increases by 1 at each rotation (§11.4). The party that starts an epoch
draws the epoch secret `K_e` from its device CSPRNG.

A **slot** is one interval of `GROUP_SLOT` = 3 600 s. The slot index `t` is
`floor(unix_seconds / 3600)` from the device clock. An epoch starts at slot
`t_e`, and the epoch-key record of §11.4.2 records that value.

```
K_e          := 32 bytes from the device CSPRNG of the creator (e = 1) or of the rotator (e ≥ 2)
t            := floor( unix_seconds / GROUP_SLOT )

K_{e,t_e}    = HKDF-SHA3-256( salt = "", ikm = K_e,
                              info = "umbra/v1/group-slot" || group_id || BE32(e) || BE32(t_e), L = 32 )
K_{e,t+1}    = HKDF-SHA3-256( salt = "", ikm = K_{e,t},  info = "umbra/v1/group-slot-next",  L = 32 )
K_rec(e,t)   = HKDF-SHA3-256( salt = "", ikm = K_{e,t},  info = "umbra/v1/group-record-key", L = 32 )

read_sk_e    = clamp( HKDF-SHA3-256( salt = "", ikm = K_e, info = "umbra/v1/group-read",  L = 32 ) )
write_sk_e   = clamp( HKDF-SHA3-256( salt = "", ikm = K_e, info = "umbra/v1/group-write", L = 32 ) )
```

Part 5 §5.11 holds the five labels. `clamp` is the X25519 clamp of RFC 7748 §5,
as Part 5 rule `CRY-120` gives it.

- **[GRP-220]** The party that starts an epoch MUST draw `K_e` from the device
  CSPRNG. **[GRP-221]** That party MUST NOT derive `K_e` from `group_id`, from
  `GroupRosterSeed_g`, or from an earlier epoch secret.
- **[GRP-222]** A member MUST derive each slot key, the record key, and the
  two queue credentials with the calls above. **[GRP-223]** A member MUST
  compute `t` from the device clock, and Part 1 §1.9 applies to that clock.
- **[GRP-224]** A member MUST take `t_e` from the epoch-key record.
  **[GRP-225]** A member MUST NOT compute `t_e` from the arrival time of that
  record.

**The chain is one-way.** A party that holds `K_{e,t}` derives every later slot
key of epoch `e` and no earlier one. Thus a joiner that receives
`K_{e,t_join}` reads nothing before `t_join`, and no rotation is needed at a
join (§11.4.1).

**The queue credentials come from `K_e`.** `read_sk_e` and `write_sk_e` come
from the epoch secret and not from a slot key, thus they do not advance by the
hour. `own_sk` is never derived, and §11.2.1 makes the creator draw it.

**A joiner derives no credential.** A joiner receives `K_{e,t_join}` and never
`K_e`, because `K_e` gives every slot key of the epoch from `t_e` and would
open the records before the join.

- **[GRP-384]** An admit MUST carry `read_sk_e` and `write_sk_e`, and a joiner
  MUST take the two credentials from it. **[GRP-385]** A joiner MUST NOT
  derive a queue credential, because it holds no `K_e`. **[GRP-386]** A
  member that takes `K_e` from an epoch-key record (§11.4.2) MUST derive the
  two credentials from it and MUST NOT keep the pair of an earlier epoch
  after `GROUP_EPOCH_GRACE`. Part 6 §6.6.3 gives the two fields of the admit.

> *Cause.* The credentials are the reader set and the writer set of the group
> queue, and that set is the membership. A joiner is a member from its add
> record, thus the two values tell it nothing that the roster does not. The
> admin that admits it holds them already. The alternative, a `K_e` to the
> joiner, would give it each slot key from `t_e` and break §11.3.2 and the
> history window of `GRP-233`.

> *Cause.* Part 3 rules `NET-009` to `NET-014` make each queue key come from
> the device CSPRNG and from no shared secret, so that a seized relay cannot
> collect the queues of one user. The derivation of a group-queue credential
> from `K_e` is a stated exception to those rules. The writer set and the
> reader set of a group queue are the membership, and the membership holds
> `K_e` by definition. A credential that each member drew alone would need a
> distribution to each member, which is the fan-out that §11.1 removes. The
> exception reaches the reader and writer credentials of one group queue, and
> it reaches no pairwise queue of any member.

### 11.3.2 Forward secrecy and the slot window

- **[GRP-226]** A device MUST store, for each group, the triple
  `(e, t_old, K_{e,t_old})` with `t_old = t_now − GROUP_SLOT_WINDOW`, and no
  earlier slot key of that epoch. **[GRP-227]** A device MUST advance `t_old`
  by one slot each hour: derive `K_{e,t_old+1}` forward, overwrite, and
  zeroize the previous key. `GROUP_SLOT_WINDOW` is 24 slots.
- **[GRP-228]** A receiver MUST accept a content record only when its `slot`
  is in `[t_now − GROUP_SLOT_WINDOW, t_now + GROUP_SLOT_SKEW]`.
  `GROUP_SLOT_SKEW` is 2 slots. **[GRP-229]** A receiver MUST store a record
  outside that window in the manner of Part 6 rule `WIR-050`, treat it as
  evidence of a clock movement of Part 1 §1.9, and retry it after the next
  clock check. Part 14 §14.9.2 gives the `clock` line.
- **[GRP-230]** After a rotation to `e + 1`, a receiver MUST keep the state of
  epoch `e` for `GROUP_EPOCH_GRACE`. **[GRP-231]** A receiver MUST zeroize
  that state at the end of the grace. `GROUP_EPOCH_GRACE` is 24 h.
  **[GRP-232]** Inside that grace a receiver MUST accept a record of epoch `e`
  only from a member that its current roster holds.

Thus a seized device opens at most the last 24 h of retained records of the
current epoch, plus the records of the previous epoch inside the grace. This is
the forward secrecy of a group, and Part 15 §15.3 records what a seized device
plus the retained ciphertext of a replica gives.

**The history window.** `HISTORY_WINDOW` is 0 by default and 7 days at most.
**[GRP-049]** An admin MAY turn on a limited history window by an explicit
action. **[GRP-233]** An admin that turned on `HISTORY_WINDOW` = W MUST hand
the joiner `K_{e,t_join − W}` in the admit stage of §11.9.1 in the place of
`K_{e,t_join}`. **[GRP-234]** If that window crosses an epoch boundary, the
admin MUST hand the slot key at the start of the current epoch and no key of
an earlier epoch. The joiner then reads the retained records of that window
from a replica.

> *Cause.* Draft 0.1.0 held three sender-key generations for each member on a
> device for 7 days, and a seized device opened every record of every member
> over that period. The slot chain replaces that with one key for each group,
> and `GROUP_SLOT_WINDOW` bounds the exposure to 24 h without a rotation. A
> shorter window makes a device that slept through the night miss its morning
> records. The history window hands the joiner an older slot key and no
> re-encryption.

### 11.3.3 The pair key and the tag vector

Each member holds three keys for each group, derived from `GroupRosterSeed_g`
of §11.9.1 in the local identity table of Part 4 §4.7.2:

```
GroupRosterKey_g   ML-DSA-65 keypair from GroupRosterSeed_g, as 0.1.0; pk 1 952 B
GroupPairKey_g     X25519:  sk = clamp( HKDF-SHA3-256( salt = "", ikm = GroupRosterSeed_g,
                                                       info = "umbra/v1/group-pair", L = 32 ) )
GroupKemKey_g      UMBRA-KEM: Hybrid( HKDF-SHA3-256( salt = "", ikm = GroupRosterSeed_g,
                                                       info = "umbra/v1/group-kem", L = 96 ) )
                   with Hybrid and the 96-byte split of Part 5 §5.2; pk 1 216 B
```

Rule `GRP-058` makes each device of one member use the same seed, thus each
device holds the same three keys.

The tag of a record to member `j` from member `i` is a two-party MAC under a
pair key:

```
ss_ij   = X25519( GroupPairKey_g.sk_i, GroupPairKey_g.pk_j )      // abort on an all-zero output, as CRY-040
K_ij    = HKDF-SHA3-256( salt = "", ikm = ss_ij,
                         info = "umbra/v1/group-tag" || group_id || min(pk_i, pk_j) || max(pk_i, pk_j), L = 32 )
tag_j   = HMAC-SHA3-256( K_ij, "umbra/v1/group-tag" || group_id || BE32(e) || BE32(t)
                               || BE16(sender_index) || BE32(counter) || BE32(roster_epoch)
                               || SHA3-256(app) )[0..12]
```

`min` and `max` compare the two 32-byte public keys in byte order. `K_ij` is
symmetric in `i` and `j`, thus each pair computes it once and caches it.
`GROUP_TAG_LEN` is 12 bytes.

- **[GRP-235]** A member MUST derive `GroupPairKey_g` and `GroupKemKey_g` with
  the calls above. **[GRP-236]** A member MUST take `pair_pk` and `kem_pk` of
  another member from that member's roster entry (§11.9.1). **[GRP-237]** A
  member MUST abort the pair-key derivation on an all-zero `ss_ij`, as Part 5
  rule `CRY-040` does for a decapsulation.
- **[GRP-238]** A sender MUST compute one tag for each active member of
  `roster_epoch` other than itself, with the derivation above. **[GRP-239]** A
  sender MUST put 12 zero bytes at its own position of a dense vector.
- **[GRP-240]** A receiver MUST verify the tag at its own position under
  `K_{sender,self}`, where `sender_index` names the sender. **[GRP-241]** A
  receiver MUST reject a record whose tag fails. **[GRP-242]** A receiver MUST
  NOT report a tag failure to any party. **[GRP-243]** A receiver MUST
  attribute a record to the member that its verified tag names.
  **[GRP-244]** A receiver MUST NOT attribute a record to a member on
  `sender_index` alone.
- **[GRP-245]** A member MUST zeroize the cached `K_ij` of a member at that
  member's removal.

**What the tag gives.** The receiver can forge a tag to itself, thus a record
proves authorship to no third party, and G10 of Part 2 §2.3 holds for group
content. A third member cannot forge a tag to `j` without `K_ij`, thus an
insider cannot impersonate another member. The tag covers `SHA3-256(app)`,
`e`, `t`, `counter`, and `roster_epoch`, thus an insider that holds the slot
key cannot change the content, the position, or the roster view of a record
that another member sent.

**What the tag costs.** The dense vector costs 12 bytes for each member. At
`GROUP_MAX` = 500 that is 6 000 bytes, and §11.2 puts a record at 500 members
in `B2` for a text of up to 1 985 bytes. A group of up to 124 members keeps the
modal text in `B1`. The tag computation is one HMAC for each member at the
sender and one at the receiver.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The pair
> key is classical, in line with Part 5 §5.4.4, which makes authentication
> classical in v1. A quantum adversary that holds the pair public keys of two
> members and joins the group could forge tags between them. The pair public
> keys travel inside the group only, in the roster entries. Part 15 §15.3
> records that residual, and `sig_id` agility of Part 5 §5.10 is the migration
> path. Group **confidentiality** stays post-quantum: the slot chain reaches
> each member through `UMBRA-KEM` in the epoch-key record of §11.4.2, and Part
> 5 rule `CRY-024` holds.

> *Cause.* Draft 0.1.0 attributed a record by the L6 QueueE2E key of the
> pairwise channel that carried it, thus it needed one channel for each pair
> of members. The tag vector attributes a record by one 12-byte MAC for each
> receiver under a static Diffie–Hellman between two group-scoped keys. That
> costs 12N bytes inside the AEAD and no channel. A signature under
> `GroupRosterKey_g` would cost 3 309 bytes and would make each record
> transferable evidence against G10. An unkeyed hash would let any member
> forge any other.

### 11.3.4 Sending

1. The sending device is the **group sender owner** of the device set
   (§11.12).
2. **[GRP-246]** The sender MUST set `t` to `floor(now / 3600)`, derive
   `K_{e,t}` from its stored state, and set `counter` to the last value it sent
   in epoch `e` plus 1. The first record of a member in an epoch carries
   `counter` = 1.
3. Build `ContentPlain` with the newest roster epoch the device holds, compute
   the tags, encrypt, and fill, under the rules of §11.3 and §11.3.3.
4. `GPOST` the same bytes to each replica under §11.2.1. **[GRP-247]** A
   sender MUST NOT add a dispatch delay, a per-recipient dispatch, or a rate
   cap of its own to a group send. The one cap is `GROUP_POST_RATE` at the
   relay.
5. §11.2.2 holds: the device holds a cursor at or above the newest epoch-key
   record before the post.

**[GRP-248]** A sender MUST draw one `msg_id` for one group send, and Part 6
rule `WIR-060` states the same rule. A group is one conversation, and a
moderation epoch of §11.9.6 names that value.

> *Cause.* Draft 0.1.0 dispatched each send to N − 1 members with an
> exponential jitter, because a burst of N − 1 cells at one moment was a
> membership beacon (the "flurry" attack of arXiv:2305.09799). One record on
> one queue makes no burst, thus the jitter retires with the fan-out.

### 11.3.5 Receiving

A receiver processes the records of one replica in `seq` order, and it takes
the steps below for each content record.

1. **[GRP-249]** A receiver MUST reject a record with an unknown `version` or
   `kind`. **[GRP-250]** A receiver MUST reject a record whose `epoch` is
   neither the current epoch nor the previous epoch inside
   `GROUP_EPOCH_GRACE`.
2. Check the slot window under §11.3.2, and derive `K_{e,t}` forward from the
   stored state.
3. Open the AEAD. **[GRP-251]** A receiver MUST treat an AEAD failure, a tag
   failure, and a parse failure as one error value, in the manner of Part 6
   rule `WIR-032`.
4. Parse `ContentPlain`, and resolve `roster_epoch` against the local roster
   history. **[GRP-252]** A receiver MUST hold a record whose `roster_epoch`
   is above its newest roster epoch, without a tag check and without a change
   to the `counter` state of the sender, until it applies a roster record that
   brings its roster to that epoch. **[GRP-253]** A receiver MUST discard a
   held record when `GROUP_ROSTER_WAIT` passes after its arrival.
   **[GRP-254]** A receiver MUST show a gap for a discarded held record, in
   the manner of §11.2.3. `GROUP_ROSTER_WAIT` is 24 h. **[GRP-255]** A
   receiver that holds such a record MUST fetch from the other replica under
   §11.2.2, because the missing roster record is a gap. **[GRP-256]** A
   receiver MUST discard a record whose `roster_epoch` is below the roster
   epoch of its own admission. Its sender held no entry for the receiver, and
   the vector holds no tag for it.
5. Locate the receiver's own tag. In dense mode that is its rank among the
   active members of `roster_epoch`, in index order. In sparse mode that is
   its own index. Verify the tag under §11.3.3.
6. **[GRP-257]** A receiver MUST reject a record whose `sender_index` names no
   member of the receiver's **current** roster. A removed member's in-flight
   records under the old epoch fail here, whatever `roster_epoch` they name.
   `GRP-407` of §11.12 states the one exception, a rival re-key.
7. **[GRP-258]** A receiver MUST identify the record by the triple of
   `GRP-035`. **[GRP-259]** A receiver MUST track `counter` for each (sender,
   epoch) pair, for the gap detection of §11.2.2 and the order of §11.7. A
   repeated or lower `counter` is not a security event; the record is a
   duplicate or a reorder.
8. Route the `AppMessage` under Part 6 §6.6 and the class rules of Part 7
   §7.5.3.

**The roster record and the records after it.** A roster record of §11.9.2 is a
content record of kind `0x01` that carries a `GroupControl`, and the steps above
apply to it.

- **[GRP-260]** A receiver MUST apply a verified roster record before it
  evaluates any record with a higher `seq` on the same replica. **[GRP-261]**
  A receiver MUST evaluate a content record against the active-member set of
  the `roster_epoch` that the record names, and against the current roster
  for step 6. **[GRP-262]** A receiver MUST hold a roster record whose
  predecessor it does not hold, under the same wait as a held content record,
  together with each content record that names an epoch at or above it.
- **[GRP-263]** A receiver MUST keep the active-member set of each roster epoch
  from its own admission epoch onward, for `GROUP_RETENTION` after that epoch.
  A record names a roster epoch inside `GROUP_RETENTION` at most.

> *Cause.* The order of records on one replica is the order in which that
> replica accepted them, and the roster chain carries its own order in
> `epoch_index` and `previous_epoch_hash` (§11.9.4). The two orders agree
> whenever one sender posted the roster record and then its content, because
> that sender posts under the roster it holds. They differ when the other
> replica accepted the roster record first and this replica has not yet
> received it. A held record costs one bucket of storage for
> `GROUP_ROSTER_WAIT`, and a discarded one costs a visible gap. An earlier
> draft of this section rejected such a record at once, and a member that
> read the slower replica lost each record that followed a join for the
> length of one session.

## 11.4 Rotation

A rotation starts a new group epoch. It gives every member that the new roster
holds a new epoch secret, and it gives no such secret to a member that the
roster no longer holds.

### 11.4.1 The rotation trigger

A **rotation trigger** is a fact on the roster chain that every member reads:
a roster record that removes an index (a plain epoch that removes a member, a
granting epoch that removes a role and the member, an eviction under §11.9.7,
or a self-removal under `GRP-067`), a `RekeyRecord` that moves a member to new
keys (§11.12), or the age of the epoch. Any member acts on a trigger. The
authority to change the roster stays where §11.9 puts it; the authority to
rotate does not, because a rotation needs no secret that a plain member lacks.

- **[GRP-264]** An admin that removes a member MUST rotate in the same action,
  directly after the roster record that removes it. That rule holds for a
  plain epoch that removes a member, for a granting epoch that removes a role
  and the member, and for an eviction under §11.9.7.
- **[GRP-355]** Any active member MAY rotate at a trigger. **[GRP-356]** A
  receiver MUST reject an epoch-key record whose rotator is the index that the
  trigger excludes, or whose rotator is not active at the `roster_epoch` of
  that record. **[GRP-357]** A receiver MUST reject an epoch-key record for
  which the roster chain holds no trigger since the epoch-key record of the
  epoch before it.
- **[GRP-358]** A member that reads a trigger it did not cause MUST draw a
  delay from an exponential distribution with mean `ROTATE_BACKOFF_ROLE` if
  it holds a role at `moderator` or above, and with mean
  `ROTATE_BACKOFF_MEMBER` otherwise. **[GRP-380]** An implementation MAY
  draw that delay as `mean × ln(2^32 / (u + 1))` from one uniform 32-bit
  `u`, with a logarithm from the bit length and a sixteen-entry table of
  the fraction; the shape of the distribution is what the backoff needs,
  and not its precision. **[GRP-359]** That member MUST rotate at
  the end of the delay if no epoch-key record that answers the trigger arrived
  before it, and it MUST NOT rotate if one did. The admin that causes a
  trigger draws no delay, under `GRP-264`.
- **[GRP-360]** Any member MUST rotate, under the same backoff, when
  `GROUP_EPOCH_MAX_AGE` passes after `t_e` and no epoch-key record of a later
  epoch has arrived. §11.10 gives 30 days.
- **[GRP-267]** A member MUST NOT rotate at a join. §11.3.1 gives the cause:
  the slot chain is one-way, and the joiner receives the slot key of its join
  slot. **[GRP-268]** A member MUST NOT rotate at a promotion. A promotion
  delivers the owner credentials to the promotee by a one-slot epoch-key
  record of the current epoch (§11.4.3).

**The order of operations** at a rotation by member R:

1. If R is the acting admin, post the roster record that causes the rotation,
   and take `GSEQ` from each replica.
2. Draw `K_{e+1}`, set `t_{e+1} = t_now`, build one slot for every member the
   new roster holds, and post the epoch-key record (or its descriptor record)
   to each replica.
3. **[GRP-361]** A rotator that holds `own_sk` MUST send `GKEY` with
   `read_pk_{e+1}` and `write_pk_{e+1}` to each replica after that replica
   returned `GSEQ` for the epoch-key record. **[GRP-362]** A rotator MUST NOT
   send `GKEY` to a replica before that replica accepted the epoch-key record.
   **[GRP-363]** A member of role `admin` or above that installs an epoch it
   did not credential MUST send `GKEY` for that epoch to each replica at once.
   A second `GKEY` with the same keys changes nothing at the relay.
4. Switch its own sending to `e + 1`.

The relay keeps the previous `read_pk` for `GROUP_READ_GRACE` and the previous
`write_pk` for `GROUP_WRITE_GRACE`, thus a member that has not yet read the
epoch-key record still reads and still writes inside the grace. Until an admin
sends `GKEY`, the excluded party keeps the relay credentials of the old epoch:
it fetches ciphertext that it cannot open, and it posts records that every
receiver rejects under §11.3.5. Part 15 §15.3 records that residual.

- **[GRP-398]** A member whose `GPOST` or `GSUB` under the credentials of the
  newest epoch it holds is refused MUST send the same command again at once
  under the credentials of the epoch before it, while `GROUP_EPOCH_GRACE`
  holds them, and it MUST count only a refusal of that second command under
  `GRP-210`. The relay takes the credentials of an epoch at a `GKEY` alone,
  and a rotator below `admin` sends none.

> *Cause.* An earlier form named no credential for the time between an
> installation and the `GKEY` of that epoch. A member that installed the new
> epoch wrote under its pair, the relay refused it, and two refusals closed
> the group under `GRP-210`. After a rotation by a plain member with no
> admin online, each member that posted closed the group on its own device.
> The second command costs one round trip at a switch of epoch. Two
> rotations inside one `GROUP_EPOCH_GRACE` with no `GKEY` between them leave
> a member with no pair that the relay holds, and Part 15 §15.3 records that
> residual.

**Two rotators at once.** Two members can post two epoch-key records for one
epoch `e + 1` before either reads the other. **[GRP-273]** A member that
verifies two epoch-key records for one epoch MUST install the secret of the
record whose rotator has the lower member index, and it MUST keep the other
secret as an alternate for `GROUP_EPOCH_GRACE`. **[GRP-274]** A receiver MUST
try the alternate secret of an epoch when the record key of that epoch fails
to open a record. **[GRP-364]** A rotator that reads an epoch-key record for
the epoch it posted, from a lower member index, MUST switch to that secret,
and if it holds `own_sk` it MUST send `GKEY` with the credentials of that
secret to each replica.

> *Cause.* Draft 0.1.0 rotated a sender key at each membership change, lazily
> at the next send of each sender. An earlier form of this section let only an
> admin rotate, because the rotator also sent `GKEY`. That put the exclusion
> of a leaver, and of a device in hostile hands, behind the presence of one
> role holder, and a group whose admins sleep kept an excluded party inside
> for hours. The two acts are separate. Every member holds every KEM key of
> the roster, thus any member makes the secret that excludes a party. Only the
> excluded party cannot, because it would know the secret it made, and
> `GRP-356` keeps it out. `GKEY` needs `own_sk`, and it buys relay hygiene
> only, thus it waits for an admin at no cost to confidentiality. The backoff
> keeps a 500-member group from 500 rotations at one trigger, and the index
> rule of `GRP-273` makes the few that race resolve the same way at every
> member.

### 11.4.2 The epoch-key record

Kind `0x02` of `GroupQueueRecord`, and Part 6 §6.4.6 gives the layout of its
`EpochKeyBody` and `KemSlot`. The body holds `roster_epoch`, a `carrier` byte
(`0x01` inline, `0x02` chunked), `slot_count`, and then the slots inline or a
`FileDescriptor` of Part 12 §12.3 that names an object of the concatenated
slots. The body has no slot-key layer, because a member that missed the
previous epoch must still open its slot. The relay therefore reads
`slot_count`, which is the active member count at `roster_epoch` less the
members the rotation excludes, and §11.5 states that leak.

A `KemSlot` holds the member `index` it serves, a 1 120-byte `kem_ct` from
`UMBRA-KEM.Encap( GroupKemKey_g.pk )` of that member, and `ct`, which seals a
`SlotPayload` of the rotator's index, `k_e`, a 12-byte `tag`, `own_count`, and
`own_count` owner secrets:

```
K_slot = HKDF-SHA3-256( salt = "", ikm = ss, info = "umbra/v1/group-epoch-slot" || group_id || BE32(e) || BE16(index), L = 32 )
ad     = "umbra/v1/group-epoch-slot" || group_id || BE32(e) || BE16(index)
ct     = ChaCha20-Poly1305( K_slot, 0^12, SlotPayload, ad )
tag    = HMAC-SHA3-256( K_{rotator,index}, "umbra/v1/group-epoch-tag" || group_id
                        || BE32(e) || BE32(t_e) || BE32(roster_epoch) || k_e )[0..12]
```

`ss` is the `UMBRA-KEM` shared secret of that slot, and `K_{rotator,index}` is
the pair key of §11.3.3 between the rotator and the member the slot serves. A
slot is 1 185 bytes at a plain member (`own_count` 0) and 1 249 bytes at a
member of role `admin` or above (`own_count` = `GROUP_REPLICAS`).

- **[GRP-276]** A rotator MUST build one slot for each member the new roster
  holds, in index order, and no slot for a member it removes. **[GRP-277]** A
  rotator of role `admin` or above MUST set `own_count` to `GROUP_REPLICAS`
  for a member of role `admin` or above and to 0 for each other member.
  **[GRP-387]** A rotator below `admin` MUST set `own_count` to 0 in every
  slot, because it holds no `own_sk`. **[GRP-278]** A rotator MUST put
  `own_sk` of replica 1 and then of replica 2 in `own_sks`, in the replica
  order of the roster snapshot (§11.9.8).
- **[GRP-279]** A rotator MUST use a fresh `Encap` for each slot. The nonce is
  zero, because `K_slot` is fresh for each slot by construction.
- **[GRP-280]** A rotator MUST carry the slots inline when the record fits the
  "record on a `GMSG`" row of `B3`, and chunked otherwise. That row holds 27
  slots when at most 9 of them are admin slots, and 26 slots otherwise.
- **[GRP-281]** In the chunked carrier, a rotator MUST write the object as
  blocks of `SEGMENT_SIZE` bytes (Part 12 §12.2.3), each block holding
  `slots_per_chunk` slots in index order and then zero bytes, so that no slot
  crosses a chunk boundary. **[GRP-282]** A rotator MUST set `slots_per_chunk`
  to the largest value at which every block fits `SEGMENT_SIZE`. At
  `SEGMENT_SIZE` of 32 634 bytes that is 27, or 26 when more than 9 admin
  slots fall in one block. **[GRP-283]** A rotator MUST write that object on
  the chunk path of Part 12 §12.3.3 under `CNEW`, and Part 12 §12.4 makes the
  replicas.
- **[GRP-284]** A member MUST fetch the one chunk that holds its slot, which is
  chunk `floor(p / slots_per_chunk)` for its rank `p` among the included
  members. **[GRP-285]** A member MUST NOT fetch another chunk of that object.
  Part 12 rule `ATT-142` applies to the descriptor. Each segment seals on its
  own under Part 12 §12.2.3, thus one chunk opens without the others.
- **[GRP-406]** A rotator MUST post the chunked epoch-key record only after
  the object reached the chunk path, and MAY write the object again when that
  failed. A rotator that gives up holds an epoch that no member holds; each
  member that meets a record of it asks for it under §11.4.3.

**[GRP-388]** A member MUST read the inline slots of an epoch-key record
under the slot lengths that the roles of its own roster give, and, when that
read fails or its own slot does not open under it, under the lengths of a
record whose every `own_count` is 0. No field in the clear names the rotator,
thus the reader cannot take the rotator's role from the record.

> *Cause.* An earlier form of `GRP-277` made `own_count` follow the roles of
> the roster alone, and the relay learns the slot lengths from the record.
> `GRP-355` lets any active member rotate, and a member below `admin` holds
> no `own_sk`, thus that form asked a plain rotator for a secret it does not
> have. Naming the rotator in the clear would tell the relay which member
> rotates, which §11.5 does not grant it, and a per-slot `own_count` byte in
> the clear would name each admin. The two layouts differ in length alone,
> thus the reader tries both and loses one parse.

**Reading the record.** **[GRP-286]** A member that reads an epoch-key record
MUST decapsulate its slot, verify `tag` under `K_{rotator,self}`, verify the
rotator's role, install `(e + 1, t_{e+1}, K_{e+1,t_{e+1}})`, derive the queue
credentials of `e + 1`, and keep the state of epoch `e` for
`GROUP_EPOCH_GRACE`. **[GRP-383]** The `slot` field of the epoch-key record
header MUST carry `t_{e+1}`, and a member MUST take `t_e` of `GRP-224` from
that field. **[GRP-287]** A member MUST NOT install an epoch secret
whose `tag` fails. **[GRP-288]** A member MUST NOT install an epoch secret from
an epoch-key record whose `epoch` is below its current epoch, or equal to it
other than under the two-rotator rule of §11.4.1 and the one-slot record of
§11.4.3.

**What a rotation costs.** At 3 members with two owners the record is 24 + 7 +
2 × 1 249 + 1 185 = 3 714 bytes, in `B2`. At 25 members with two admins it is
29 784 bytes, in `B3`. At 120 members the object is 5 chunks, and at 500
members it is 592 500 bytes plus 64 bytes for each admin, in 19 chunks. A
member downloads one `B2` record, one `B3` record, or one `B3` chunk, which is
at most 32 860 bytes. The rotator uploads the record to two replicas, or the
chunks once and a descriptor record to two replicas, and the chunk relay pushes
the replicas of Part 12 §12.4. Draft 0.1.0 made each of N senders upload N − 1
`B1` cells at a change. The chunk relay learns what Part 12 §12.9 says it
learns from one chunk, and Part 12 rule `ATT-066` adds a row for this client
of the chunk path.

> *Cause.* An epoch-key record inside a slot-key AEAD would need the previous
> slot key to open, and the member whose device slept through a rotation is
> exactly the member that lacks it. The slot therefore seals under a KEM to
> the member's own key, and the count of slots is the one field the relay
> reads.

### 11.4.3 The key supply

A member that holds no slot in the current epoch, because its slot was omitted
or failed to open, asks for one. Part 6 §6.6.11 gives the `KeyRequest` and the
`KeySupply`. For a group, `scope` `0x02` means "the group epoch", `epoch` is
the epoch the member lacks, and `index` is 0.

- **[GRP-289]** A member that lacks the current epoch secret MUST send a
  `KeyRequest` of scope `0x02` as a group record under the previous epoch,
  while `GROUP_WRITE_GRACE` and `GROUP_EPOCH_GRACE` hold. **[GRP-290]**
  Outside those graces, the member MUST send that `KeyRequest` on a pairwise
  channel to any member of the group that it holds a channel with. Part 6
  rules `WIR-456` and `WIR-457` state the same carrier.
- **[GRP-375]** Any active member that reads a `KeyRequest` of scope `0x02`
  from an index that the current roster holds MUST answer, after the backoff
  of §11.4.1 and only if no one-slot epoch-key record for that index arrived
  first, with a one-slot epoch-key record of the current epoch for that
  member, inline with `slot_count` 1 and `own_count` 0, and then with a
  `KeySupply` of status `0x01` on the path that carried the request. For scope
  `0x02` the `body` of a `KeySupply` is empty, and status `0x01` means "a
  one-slot epoch-key record was posted". **[GRP-376]** A member that receives
  a `KeyRequest` of scope `0x02` on a pairwise channel MUST answer it at once
  when `GRP-404` permits, because no other member read it, and MUST post it
  otherwise as a group record that keeps the `index` of `WIR-523`, thus
  another member answers under the backoff. The supply is sealed to the key
  of the member that `index` names, thus a false `index` gains nothing.
- **[GRP-377]** A member MUST NOT answer a `KeyRequest` from an index that the
  current roster does not hold. **[GRP-404]** A member MUST NOT answer it for
  an index that the active set at the `roster_epoch` of the current epoch
  does not hold, and a member that holds no `K_e` of that epoch MUST NOT
  answer it. **[GRP-295]** A member MUST NOT send more than
  `KEY_REQUEST_RATE` epoch requests for one group in each 24 h. **[GRP-378]**
  A member MUST discard an epoch request above that rate. §11.10 gives 8.
- **[GRP-297]** If no path exists, the member MUST show the group as
  "membership lapsed", and it needs a new invitation. **[GRP-405]** A member
  that shows a group as lapsed and then installs the epoch it lacked MUST
  show the group as open again.

> *Cause of `GRP-404`.* An earlier form answered any index that the roster
> holds. A member that joined inside the current epoch holds the chain from
> its join slot, and it lacks nothing that it may hold; `K_e` would give it
> each slot key from `t_e`, thus each record before its join, which
> `GRP-385` forbids. The rotation of the epoch included each member that it
> served, and the active set at its `roster_epoch` names them.

The same one-slot record delivers the owner credentials to a newly promoted
admin. **[GRP-298]** An admin that promotes a member to `admin` or above MUST
post a one-slot epoch-key record of the current epoch for that member with
`own_count` = `GROUP_REPLICAS`, directly after the granting epoch.
**[GRP-400]** That record MUST carry `k_e` of 32 zero bytes, and its `tag`
MUST cover that value. A receiver MUST take `own_sks` from a slot whose
`k_e` is zero and MUST install no epoch from it, and it MUST reject such a
slot of an epoch other than its current one or with `own_count` 0.

**The owner credentials after an admin leaves them.** `own_sk` is a secret of
the relay and not of an epoch, thus a rotation of §11.4 leaves it where it was.

- **[GRP-401]** An admin that takes the role `admin` or above from a member
  MUST draw a new `own_sk` for each replica from the device CSPRNG, send a
  `GKEY` that carries the new `own_pk` under the `own_sk` it replaces to
  each replica (`WIR-522`), and post a record of `GRP-400` with the new
  credentials to each other member at `admin` or above.
- **[GRP-402]** When a member that held the owner credentials left the roles
  at `admin` or above, or left the group, the active member at `admin` or
  above with the lowest index MUST do the same after the backoff of
  `GRP-358`, and no other admin MUST do it for that departure. After a
  demotion, whose admin acts under `GRP-401`, it MUST first wait
  `ROSTER_RATE_LIMIT`. It MUST NOT act when a record of `GRP-400` reached it
  during that wait.

> *Cause of `GRP-401` and `GRP-402`.* No earlier rule took `own_sk` back. An
> admin that lost its role or left the group kept it, and `own_pk` never
> changed at the relay. It could send a `GKEY` of keys that it alone knew and
> lock every member out of the queue, or a `GDEL`. Two admins that acted on
> one departure would each draw a set, and one set would fail at the relay,
> thus one admin acts for each departure. Two departures at once can still
> give two sets, and Part 15 §15.3 records that residual.

> *Cause of `GRP-400`.* A promotee may have joined inside the current epoch,
> and `GRP-385` keeps `K_e` from a joiner, because `K_e` gives each slot key
> from `t_e` and thus each record before the join. A one-slot record that
> carried `K_e` gave it that history at a promotion. The owner credentials
> are all that the record has to deliver.
**[GRP-379]** A receiver MUST reject a slot whose `own_count` is above 0 when
the rotator held a role below `admin` at the `roster_epoch` of the record,
because only an admin holds `own_sk`.

> *Cause.* Draft 0.1.0 answered a key request with the sender key of one
> member on the pairwise channel of the two parties, and the rate bounded the
> requests to one peer. A group now has one secret for each epoch, held by
> every member, thus any member can answer under the backoff of §11.4.1, and
> no repair waits for a role holder. The rate bounds the requests for one
> group. The one-slot record reuses the epoch-key layout, thus the
> promotion path and the repair path are one code path.

## 11.5 Membership privacy, and what the relay learns

- **No relay learns the group membership.** A group queue holds no membership
  list and no per-reader state other than the live sessions and the
  notifiers. A record names a member by an index inside the AEAD, and the
  index is meaningful inside the group only.
- **There is no group record at a relay other than the group queue**, and the
  group queue names no member. `GroupQueueId` is a random relay-side value
  with no relation to `group_id`, to any member, and to any pairwise queue.
- **The group-queue relay learns** that the queue exists, the count of reader
  sessions and writer sessions, the arrival time and the bucket of each
  record, the exact member count at each rotation from `slot_count` of the
  epoch-key record, and the count of notifiers and the queue relay of each
  notify queue. It learns no identity, no pairwise queue of any member, no
  content, no sender index, and no membership list. Part 3 §3.11 and Part 2
  §2.7 state the same list, Part 3 §3.11.1 records the active probe "delay a
  reader session and watch the cursor", and Part 15 §15.1 holds the
  compellable row.
- **A member learns the roster.** That property is inherent. A member cannot
  tag a record to a person without a key of that person. UMBRA hides the
  membership from the *infrastructure*, and not from the participants.

> *Cause.* This list is strictly less than the optional re-broadcaster of
> draft 0.1.0 learned, which was the queue set of the group, and that party
> is retired. The list replaces the accepted 0.1.0 residual "the ingress relay
> reads the recipient count from a fan-out burst" with "the group-queue relay
> reads the member count from an epoch-key record". Part 15 §15.3 records
> each residual below.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The
> group-queue relay reads the member count of a group at each rotation, from
> the slot count of the epoch-key record. It reads the count and no identity.
> A slot-key layer over that record would hide the count and would lock out
> the member that slept through the previous epoch (§11.4.2). UMBRA accepts
> this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The
> group-queue relay holds the activity timeline and the bucket of each record
> of a group for `GROUP_RETENTION`, and A5 reaches it there. §11.2.1 puts the
> queue on two relays under different operators in different blocs, and a
> reader alternates them, thus one relay sees about half of the reader
> sessions and every record. UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** An
> ingress relay and a group-queue relay in collusion join a reader circuit to
> the group it reads and to an IP address. That is the same class as the
> two-ended collusion of Part 3 §3.11, and the three-hop chain of Part 3 §3.4
> is the one defense. UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A removed
> member reads the ciphertext of the group for `GROUP_READ_GRACE` after its
> removal, because the relay keeps the previous `read_pk` for that period. It
> holds no slot key of the new epoch, thus it reads timing and buckets only. A
> shorter grace locks out a member whose device slept through the rotation.
> UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A seized
> device (A6) with the retained ciphertext of a replica opens the last
> `GROUP_SLOT_WINDOW` hours of records of the current epoch, and the previous
> epoch inside `GROUP_EPOCH_GRACE`. §11.3.2 gives the one-way chain that
> bounds it. UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** An
> insider that holds a quantum computer forges a tag between two members
> whose pair public keys it holds. §11.3.3 states the classical posture and the
> migration path. UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A member
> that leaves keeps reading the group until any other member reads its
> self-removal and rotates (§11.4.1), which is one backoff after the first
> member comes online. A leaver cannot rotate, because it would know the
> secret it made. Until an admin sends `GKEY`, the leaver also keeps the relay
> credentials of the old epoch, and it fetches ciphertext it cannot open.
> UMBRA accepts this residual.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The chunk
> relay that holds a chunked epoch-key object sees one anonymous fetch for
> each member at each rotation, and Part 12 §12.9 holds the row. It learns a
> download count and no group. UMBRA accepts this residual.

## 11.6 What UMBRA does *not* do

**[GRP-025]** **A client MUST NOT use a peer-to-peer mesh fan-out above about
20 members.**

> SimpleX operated a full P2P mesh for four years. That mesh needed N−1
> connections for each member and **O(N) introduction messages at each join**.
> The addition of the 300th member to a group made about 900 protocol messages
> and 299 new queues. The conclusion of SimpleX was that the design is
> "definitely not larger than a few hundred members." The replacement took
> four years.

**A group carries no delivery receipt, no read receipt, and no typing
indicator.** **[GRP-299]** A member MUST NOT send a receipt of Part 6 §6.6.9
kind `0x06` or kind `0x07` in a group. **[GRP-300]** A member MUST NOT send a
typing indicator of kind `0x08` in a group. **[GRP-301]** A client MUST NOT
show a `delivered` or a `read` state for a group record; the states of Part 14
§14.9.1 that a group record reaches are `queued`, `accepted`, and `failed`.

> *Cause.* Every record on a group queue is a record that every reader
> downloads. A receipt from each reader for each message is N records for one
> message, and N² in the aggregate at each member. At `GROUP_MAX` and 10
> messages each day that is 500 × 500 × 10 × 560 bytes, which is 1.4 GB each
> day across the group and 2.8 MB each day for each member, against the U4
> budget of 100 MB each month. Draft 0.1.0 sent a receipt to the sender only
> on the pairwise channel, and no such channel exists now. WhatsApp reports a
> read receipt in a group from a user that turned receipts off, and that
> behavior lets a hostile or a compelled administrator collect a
> device-liveness series for each member. The presence record of §11.9.7 is
> the one liveness signal, at one interval of 7 days. Draft 0.1.0 also let a
> large group name an optional party that held its queue set and fanned each
> send out; the group queue gives one upload for each message to every group,
> and no party holds a queue set.

**A group does not detect transcript inconsistency.** §11.7 states that limit.

## 11.7 Ordering and consistency

- **[GRP-035]** A client MUST identify each record by the triple (group,
  sender, `msg_id`) (Part 6 §6.6). **[GRP-036]** A client MUST remove a
  duplicate by that triple. **[GRP-037]** A client MUST NOT use a ciphertext
  hash as an identifier, because Part 6 §6.1.1 rule 5 prohibits that use.
- **[GRP-038]** A receiver MUST resolve a target only inside the group that
  carried the naming record. **[GRP-039]** A receiver MUST resolve that target
  only against the messages of the member that the verified tag names.
- The order of two records from **one sender** is the lexicographic pair
  (`epoch`, `counter`) of the record. `epoch` is the group epoch `e` of the
  record header, and `counter` is the field of `ContentPlain`, both under the
  AEAD and the tag. **[GRP-302]** A receiver MUST take that pair from the
  record that its verified tag attributes. **[GRP-303]** A receiver MUST NOT
  take an order from a count of the arrivals or from `seq`.
- The order of two records from **two different senders** comes from a local
  insertion sequence. That sequence belongs to the device that first put the
  record in the synced history. The sequence is a monotone counter on that
  device. **[GRP-042]** A client MUST NOT use a wall clock for the order.
  **[GRP-043]** A client MUST NOT use `sent_at` for the order. The insertion
  sequence is mutable state under Part 7 §7.5.3, thus the devices of one user
  converge on one order.
- If the two rules above do not resolve two records, the byte order of
  `msg_id` applies.
- **UMBRA gives no total order across the senders of a group.** Two members
  can see two different orders for two records that arrive at the same time,
  and the two replicas of one group give two different `seq` orders.
  **[GRP-044]** The interface MUST NOT show the order as an agreed order.
- **UMBRA does not guarantee transcript consistency** against a malicious
  member that sends different content to different members. Such a member
  sends two records with two counters, and each receiver sees one of them.
  Detection needs a consistency protocol, and UMBRA has not accepted the cost
  of that protocol for v1. Part 15 §15.2.4 states this limit. **[GRP-045]** A
  member MAY compare a rolling transcript digest out of band.

> *Cause.* Draft 0.1.0 took the one-sender order from the pairwise ratchet
> position in tier T1 and from the sender-key generation in tier T2, and both
> sources retire with the tiers. The pair (`epoch`, `counter`) is monotone,
> because `counter` starts at 1 in each epoch and `epoch` increases by 1 at
> each rotation. The pair sits inside the record and not in a receiver state,
> thus a receiver that repaired a missed epoch under §11.4.3 still holds it.

## 11.8 Offline members and history

- **A new joiner receives no history by default.** The slot chain of §11.3.1
  is one-way, thus a joiner that receives `K_{e,t_join}` opens no record
  before its join slot. `GRP-049` lets an admin turn on a history window of
  at most 7 days, and §11.3.2 gives the joiner the older slot key. No party
  encrypts a backlog again for a joiner.
- **A member that returns after an absence** reads from its cursor on a
  replica. It derives each slot key forward from its stored state, and it
  reads every retained record of its epochs. A member that was away longer
  than `GROUP_RETENTION` shows a gap under §11.2.3. A member that missed a
  rotation asks for its slot under §11.4.3.
- **An offline member is a forward-secrecy risk.** RFC 9420 §16.6 states this
  limit plainly for MLS, and the limit applies to the epoch secret of a
  group. The secret stays in existence while one member has not deleted it.
  Thus UMBRA makes **automatic eviction mandatory for a member that stays
  silent longer than `GROUP_SILENT_EVICT`**, with a default of 30 days.
  §11.9.7 gives the presence signal that measures that silence and the party
  that acts on it. **[GRP-050]** The UI MUST show this eviction. This is a
  security parameter and not housekeeping.
- **A group of two members is exempt.** Both members hold the `owner` role
  under §11.9. **[GRP-169]** A member of a group of two members MUST NOT evict
  the other member for silence. The epoch of such a group rotates at
  `GROUP_EPOCH_MAX_AGE` as any other, and each rotation costs two slots.

> *Cause.* Draft 0.1.0 exempted a group of two because tier T1 held no group
> key. A group of two now holds an epoch secret, and the exemption stays,
> because a group of two with one member evicted is no group. The 30-day
> rotation of §11.4.1 bounds the life of that secret as in a larger group.

## 11.9 Administration

The roles are `owner`, `admin`, `moderator`, `member`, and `observer`.
**[GRP-051]** A group MUST have two or more members with the `owner` role. One
owner is one point of failure for the administration, and U6 does not permit
that condition. `ROLE_HOLDER_MAX` is 16 members at `moderator` or above.
**[GRP-304]** A granter MUST NOT give a role at `moderator` or above when the
roster already holds `ROLE_HOLDER_MAX` such members. That bound sizes the
sparse presence vector of §11.9.7 and the authority path of §11.9.8.

### 11.9.0 Each group control object carries a type byte

Part 6 §6.6.3 gives the `GroupControl` wrapper and its type byte. This part
defines seven objects that travel under application kind `0x10`.

| `control_type` | Object | Where |
| --- | --- | --- |
| `0x01` | Retired in 0.2.0-draft; the value never returns | — |
| `0x02` | `JoinRecord` | §11.9.1 |
| `0x03` | Plain epoch | §11.9.2 |
| `0x04` | Granting epoch | §11.9.2 |
| `0x05` | Moderation epoch | §11.9.6 |
| `0x06` | `GroupPresence` | §11.9.7 |
| `0x07` | `GroupInvitation` | §11.9.1 |
| `0x08` | `SnapshotNotice` | §11.9.8 |

**[GRP-125]** A sender MUST wrap each object of that table in a `GroupControl`.
**[GRP-126]** A receiver MUST take the object type from `control_type` alone.
**[GRP-127]** A receiver MUST NOT infer an object type from the length of a
record. The epoch-key record of §11.4.2 is not a `GroupControl`; it is kind
`0x02` of `GroupQueueRecord`, because the relay must tell it from a content
record to apply nothing but its bucket, and a member must open it without a
slot key.

### 11.9.1 The group keys and the join flow

```
GroupRosterSeed_g := 256 bits from the device CSPRNG
GroupRosterKey_g  := ML-DSA-65 keypair from GroupRosterSeed_g
GroupPairKey_g    := X25519 keypair from GroupRosterSeed_g       (§11.3.3)
GroupKemKey_g     := UMBRA-KEM keypair from GroupRosterSeed_g    (§11.3.3)
```

- **[GRP-052]** A member MUST make `GroupRosterSeed_g` from the device CSPRNG
  at the join. **[GRP-053]** A member MUST NOT derive that seed from the
  `RootIdentity`. **[GRP-054]** A member MUST NOT derive that seed from
  `group_id`.
- **[GRP-055]** A member MUST store `GroupRosterSeed_g` in the **local identity
  table** of Part 4 §4.7.2. That table also holds the pairwise salts of Part 4
  §4.2.2.
- **[GRP-056]** A member MUST make a different roster key for each group.
  **[GRP-057]** A member MUST NOT use a roster key outside the group that its
  table row names. The same two rules hold for the pair key and the KEM key,
  because the three come from one seed.
- **[GRP-058]** Each device of one member MUST use the same seed. Part 7 §7.4
  and Part 7 §7.5.1 carry the local identity table.

ML-DSA-65 is primitive 3 of Part 5 §5.1, and X25519 and `UMBRA-KEM` are the
primitives of Part 5 §5.3. This construction adds no primitive and no crate.
It adds the labels `"umbra/v1/group-pair"` and `"umbra/v1/group-kem"` to Part
5 §5.11.

**The member index and the roster entry.** Every member holds a **member
index**, a `u16` that the admin that adds it assigns. Part 6 §6.6.3 gives the
99-byte `GroupMemberEntry`: `index`, `role`, `pair_pk`, `roster_pk_hash` (the
SHA3-256 of `GroupRosterKey_g.pk`), and `kem_pk_hash` (the SHA3-256 of
`GroupKemKey_g.pk`).

- **[GRP-305]** An admin MUST assign a new member the lowest index above every
  index that the roster ever used. **[GRP-306]** A group MUST NOT reuse an
  index. `GROUP_INDEX_MAX` is 65 535, and a group that exhausts the space
  admits nobody.
- **[GRP-307]** A member MUST store the full `kem_pk` of every active member,
  because any member may become an admin and a rotator needs each one. That
  is 1 216 bytes for each member and 608 KB at `GROUP_MAX`. **[GRP-308]** A
  member MUST verify a `kem_pk` and a `roster_pk` against the hash in the
  roster entry before it uses either one.
- The full `roster_pk` of a member travels in each signed roster object that
  it makes, a granting epoch or a moderation epoch, and in the invitation for
  the creator and the inviting admin. A member that signs nothing never shows
  its `roster_pk`.

**The join flow.** The flow below costs one user action at the joiner and one
at the inviting admin. No other member acts, and no pairwise channel with any
other member is needed or created. Part 6 §6.6.3 gives the layouts of
`JoinRecord` and `GroupInvitation`.

1. The inviting admin sends a `GroupInvitation` of stage `0x01` (an offer) to
   the invitee on their pairwise channel. It carries `group_id`, the display
   name, the admin's `roster_pk`, and the creator's `roster_pk`. **[GRP-170]**
   A client MUST show an offer to the user, and it MUST NOT accept an offer
   without a user action. `GRP-153` makes the client reject an offer for a
   `group_id` that it holds.
2. **[GRP-309]** A joiner that accepts MUST make `GroupRosterSeed_g` under
   `GRP-052`, derive the three keys, and send a `JoinRecord` on the same
   channel. That record carries `group_id`, `pair_pk`, `roster_pk_hash`, and
   the full `kem_pk`, and it is 1 313 bytes.
3. **[GRP-310]** The inviting admin MUST post a plain epoch of §11.9.2 that
   adds the joiner, with the `JoinRecord` fields and the new `index`, as a
   group record to each replica. **[GRP-311]** The admin MUST take `GSEQ`
   from each replica before step 4.
4. **[GRP-312]** The admin MUST then send a `GroupInvitation` of stage `0x02`
   (an admit) on the pairwise channel. It carries `group_id`, the `index`, the
   epoch `e`, `t_join`, `K_{e,t_join}` (or the history-window key of §11.3.2),
   `read_sk_e` and `write_sk_e` (`GRP-384`), the `roster_epoch` of the add,
   and for each replica the `relay_id`, the
   `GroupQueueId`, and the `seq` of the add at that replica, and a
   `FileDescriptor` of a `RosterSnapshot` at that `roster_epoch` (§11.9.8).
5. **[GRP-313]** The joiner MUST fetch the snapshot, verify it under §11.9.8,
   subscribe to one replica from the `seq` of the add, install the epoch
   state, and apply each roster record after `roster_epoch` from the queue.
   It derives each `K_ij` of §11.3.3 lazily, at the first record to or from
   that member.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The
> inviting admin learns that the joiner joined, and every member learns it
> from the add record. §11.5 states that a member learns the roster, thus this
> flow shows a member nothing that the roster does not show. G9 of Part 2 §2.3
> holds against a party outside the group, and it does not hold between two
> members of one group. The admin holds `K_{e,t_join}` before the joiner does,
> and it holds it as a member already.

> *Cause.* Draft 0.1.0 opened one pairwise channel between the joiner and
> each member, through a group request to each member and a bundle of N − 1
> one-time invitations on the chunk path, because attribution needed a
> channel. The first-access lock of Part 4 rule `IDN-023` could then fail at
> the joiner on an invitation that the admin opened itself. The tag vector
> needs a public key of each member and no channel, and the snapshot carries
> every key. The group request of Part 6 §6.6.7 for a join, the invitation
> bundle, its member entries, and the first-access-lock residual of a join
> are retired.

### 11.9.2 Two classes of roster epoch

Every roster object is a `GroupControl` inside a content record of §11.3, and
the tag vector of that record names its sender. The roster is a hash chain.
Each epoch carries `epoch_index` and `previous_epoch_hash`.

- **[GRP-389]** A member that posts a roster object MUST build the record that
  carries it under the roster epoch that stands before that object, and MUST
  apply the object to its own roster after it built that record.

> *Cause.* The tag vector of a content record covers the active set of the
> `roster_epoch` that the record names, and §11.3.5 gives each receiver its
> tag by its rank in that set. A maker that applied the object first would
> name the epoch the object creates: an add would name a set that no other
> member holds yet, thus every member would hold the record under `GRP-252`
> and nothing would ever resolve it, and a removal would name a set without
> the member it removes, thus that member would never read why its records
> stopped verifying.

- **[GRP-314]** A member MUST compute the hash of a roster epoch as the
  SHA3-256 of the `GroupControl` payload bytes of that epoch. **[GRP-315]** A
  member MUST put that value in `previous_epoch_hash` of the successor.

A **granting epoch** gives the `owner`, the `admin`, or the `moderator` role to
a member, or it takes that role away.

- **[GRP-060]** A granting epoch MUST carry an ML-DSA-65 signature from the
  roster key of the member that gives the role.
- **[GRP-061]** The signature MUST cover this preimage:

  ```
  "umbra/v1/group-grant" || group_id || epoch_index || previous_epoch_hash ||
  granter_index || grantee_index || grantee_roster_pk_hash || role
  ```

  `granter_index` and `grantee_index` are the `u16` member indices of
  §11.9.1. Part 5 §5.11 holds the label `"umbra/v1/group-grant"`.
  **[GRP-106]** A signer MUST put that label first in the preimage.
  **[GRP-107]** A verifier MUST reject a signature over a preimage that
  carries a different label.
- **[GRP-062]** A verifier MUST check that signature against the roster key
  that the epoch carries, whose hash the roster entry of the granter binds
  (`GRP-316`, `GRP-317`). The creator of the group is the first granter. A
  member receives the roster key of the creator in the group invitation.
- **[GRP-063]** A verifier MUST reject a granting epoch from a granter that
  holds a role below `admin`.
- **[GRP-316]** A granting epoch and a moderation epoch MUST carry the full
  `roster_pk` of the member that signs it. **[GRP-317]** A verifier MUST
  check that `roster_pk` against the `roster_pk_hash` of the roster entry of
  that member before it verifies the signature under it. **[GRP-399]** A
  verifier of a snapshot MUST reject it when a member at `moderator` or
  above is neither the creator nor the grantee of that role in the last
  granting epoch of the path that names it.

> *Cause of `GRP-316` in this form.* An earlier form made a grant at
> `moderator` or above carry the key of the grantee. The roster holds only
> the hash of the key of a member below `moderator`, thus no admin held the
> key that such a grant needed, and a promotion could not be built. The key
> of the signer is the one that a verifier needs, the signer always holds
> it, and a grant stays the same size. A moderator that never grants shows
> its key in its first moderation epoch, which is when a verifier first
> needs it. `RekeyRecord` carried the key of its signer from the start.

A **plain epoch** adds a member, removes a member that holds the `member` or
the `observer` role, or records a self-removal.

- **[GRP-064]** A plain epoch MUST NOT carry a signature. **[GRP-382]** A
  plain epoch that adds or removes a member MUST come from a member at
  `admin` or above, and a self-removal from the member that leaves; a
  verifier MUST discard each other plain epoch under `GRP-066`.
- **[GRP-318]** A verifier MUST take the authority of a plain epoch from the
  tag vector of the record that carried it. The verified tag names one
  member, and §11.3.3 gives that attribution.
- **[GRP-066]** A verifier MUST discard a plain epoch if the local roster
  gives that member no role that permits the operation.
- **[GRP-319]** A plain epoch that adds a member MUST carry the `JoinRecord`
  fields of that member and its new `index`. **[GRP-320]** A verifier MUST
  reject an add whose `index` is not the lowest index above every index the
  roster ever used. **[GRP-381]** A verifier MUST run every check of an
  epoch before it records that epoch as a successor of its predecessor,
  thus a rejected epoch never counts as one of the two successors of
  `GRP-070`.

**[GRP-067]** A member client MUST offer a self-removal. A self-removal is a
plain epoch, and the tag vector names the member that leaves.

> *Cause.* Draft 0.1.0 took the authority of a plain epoch from the L6
> QueueE2E key of the pairwise channel. The tag vector is the attribution of
> every group record now, and a plain epoch is one such record. The granting
> epoch and the moderation epoch keep their signatures, because a new joiner
> verifies the authority path from the snapshot, and it holds no pair key
> with a granter that left. The group-scoped member identifier of 0.1.0 and
> its label retire; the index is the name of a member inside the group, and
> it is 2 bytes in the preimage in place of 16.

### 11.9.3 Retention of the granting chain

- **[GRP-068]** A member MUST retain each granting epoch on the authority path
  to a current role.
- **[GRP-069]** A member MUST discard a granting epoch that a later granting
  epoch supersedes, after that member verified the successor.

> *Cause.* A granting epoch is a transferable statement. Without this rule the
> seizure of one member device gives a transferable proof of each role grant.
> That proof covers each grant that each administrator made for the life of
> the group. This rule keeps the verification of a new joiner and removes the
> unbounded history.

### 11.9.4 Conflict, fork, and rate

- The epoch index gives the order of the roster chain. If two epochs name one
  predecessor, the role precedence applies, which is owner, then admin, then
  moderator. If that does not resolve the two epochs, the lower
  `SHA3-256(previous_epoch_hash || BE16(index))` applies, where `index` is the
  member index of the party that made the epoch. **[GRP-117]** A client MUST
  apply that order. The hash has a cause. A party can grind a low identifier,
  and no party knows the hash of the predecessor before the race. An admin
  assigns an index and a member does not select it, and the hash keeps the
  order unpredictable all the same.
- **Two different members that make two successors is normal use.**
  **[GRP-118]** A client MUST NOT show a fork for that case. **[GRP-119]** A
  member whose epoch the order above did not select MUST publish that epoch
  again against the selected epoch.
- The roster is hash-chained. **[GRP-070]** If a member sees two different
  successors to one epoch **from one member**, that member MUST show the fork.
  **[GRP-071]** That member MUST NOT select one successor silently. One member
  that makes two successors equivocated, and that act is evidence.
- If the two successors are granting epochs, the signature names the party
  that made the fork. **[GRP-072]** The client MUST name that party.
- **[GRP-073]** If the two successors are plain epochs, the client MUST show
  that the members disagree. **[GRP-074]** The client MUST NOT name a party.
  A plain epoch carries no signature, thus the attribution is not
  transferable.
- The two replicas of §11.2.1 give no total order, and a roster record is one
  post to each of them. The order of the roster is the order of the chain,
  through `epoch_index` and `previous_epoch_hash`, and never the `seq` of a
  replica.
- `ROSTER_RATE_LIMIT` is 1 epoch for each member in each 60 s.
  `GROUP_EPOCH_RATE` is 6 epochs for each group in each 60 s. `GRANT_RATE` is
  1 granting epoch for each group in each 300 s **and** 4 granting epochs for
  each group in each 24 h. **[GRP-076]** A member MUST discard an epoch above
  one of these limits.

> *Cause.* Without a limit, one member fills the group queue of a 500-member
> group, and U6 does not permit that condition. Trail of Bits TOB-DISCE2EE-1
> found this class of problem in an MLS deployment. The daily count bounds
> the cumulative cost. One granting epoch is a `B2` record that 500 members
> download, which is 4.1 MB across the group, thus a rate limit alone is not
> a bound. `GROUP_POST_RATE` at the relay bounds the queue, and these limits
> bound what a member applies.

### 11.9.5 What this costs, stated

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A
> granting epoch is a signed statement. A party that seizes the device of a
> member gets a transferable proof of the current role grants of the group.
> G10 covers the message content. G10 does not cover the group
> administration, and Part 15 §15.3 records that exposure.
>
> A message stays unsigned, and a plain epoch stays unsigned. Part 5 §5.7 does
> not change. The `granter_index` and the `grantee_index` in a granting epoch
> are the member indices of §11.9.1, and `grantee_roster_pk_hash` names a key
> that this group alone holds. Thus the proof names a member of this group,
> and it names no identity outside it. That statement is the full concession.
>
> A granting epoch, a moderation epoch, and an add record each use bucket `B2`
> in a group above about 25 members, and a text uses bucket `B1`. The
> group-queue relay reads the bucket of each record, thus it learns that a
> roster event occurred, and it learns no more than that. `GRANT_RATE` bounds
> the frequency of a granting epoch, and it does not conceal the event. §11.5
> states the bucket leak, and Part 15 §15.3 records it.

### 11.9.6 The moderation epoch and the two moderator actions

An author deletes, and a moderator deletes. The two use different
authorization, and they leave different evidence.

**An author deletion** uses kind `0x05`, exactly as Part 7 §7.5.6 gives it. A
receiver accepts it only when the verified tag of the record names the member
that sent the target. There is no role check and no signature, thus the
deniability of Part 5 §5.7 is untouched. A tombstone is terminal, and it beats
an edit from the same author at each position.

**A moderator action** has two forms.

| Action | The Part 14 §14.6.4 record key | Reversible | The member device |
| --- | --- | --- | --- |
| **Hide**, which is the default | Kept | Yes, by a later epoch | Keeps the data, out of the default view |
| **Remove** | Discarded | No | Overwrites the record |

Both actions travel inside a **moderation epoch**. A moderation epoch is a
signed and hash-chained roster object, in the manner of the granting epoch of
§11.9.2. Thus the signature names the acting member, and the chain records
the act.

1. **[GRP-077]** A moderation epoch MUST carry an ML-DSA-65 signature from the
   `GroupRosterKey_g` of the acting member.
2. **[GRP-078]** The signature MUST cover this preimage:

   ```
   "umbra/v1/group-moderation" || group_id || epoch_index ||
   previous_epoch_hash || actor_index || actor_role || action_count ||
   the action list
   ```

   `actor_index` is the member index of the acting member. Each action in the
   list names the action and the `msg_id` of the target. §11.3.4 makes that
   `msg_id` one value at each member. The epoch MAY carry the member index of
   the author beside the list as a rendering hint. **[GRP-179]** A signer MUST
   NOT put the author of a target in the preimage. **[GRP-180]** A client MUST
   resolve the author through `msg_ref`, and it MUST NOT take the author from
   the hint. Part 6 §6.6 keys each local index by that value. Part 5 §5.11
   holds the label `"umbra/v1/group-moderation"`. **[GRP-108]** A signer MUST
   put that label first in the preimage. **[GRP-109]** A verifier MUST reject
   a signature over a preimage that carries a different label. The two group
   labels are different, thus a granting epoch and a moderation epoch cannot
   be confused.
3. **[GRP-079]** A verifier MUST check that signature against the roster key
   that the epoch carries, whose hash the roster entry of the actor binds
   (`GRP-316`, `GRP-317`). **[GRP-080]** A
   client MUST NOT apply an action before that check succeeds.
4. **[GRP-081]** A verifier MUST reject a moderation epoch from a member that
   holds a role below `moderator`.
5. **[GRP-082]** A client MUST show a placeholder that names the action and
   the acting role. **[GRP-083]** The placeholder MUST NOT vanish without a
   trace.
6. **[GRP-084]** A moderator MUST NOT act on a message that an earlier epoch
   already removed.
7. `MOD_ACTION_MAX` is 20 actions in one moderation epoch.
8. **[GRP-085]** The interface MUST make **hide** the default. **[GRP-086]** A
   **remove** MUST need a second confirmation, and **[GRP-087]** the interface
   MUST state that a remove is not reversible.
9. A moderation epoch is one record on the group queue, and it uses bucket
   `B2` in a group above about 25 members. §11.9.5 states that limit.
10. **[GRP-181]** A member MUST retain a moderation epoch only while it is the
    current statement about a target it holds. **[GRP-182]** A member MUST
    fold an older moderation epoch into local unsigned state and keep its
    hash for the chain check.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A
> moderation epoch is a signed statement that a named role acted on a named
> `msg_id`. An earlier draft also signed the author of the target. A
> moderator then swore to an attribution under a key that the granting chain
> binds to a person. That statement was transferable evidence against G10.
> The preimage now names no author, and `GRP-181` bounds what a seized device
> holds to the current statements. A member that inspects the chain sees the
> hashes and the current epochs. It does not see each earlier act, and
> mitigation 3 below keeps the count at each epoch. Part 15 §15.3 records the
> residual.

**The residual, stated.** A compelled moderator destroys group history on the
device of each member. That cost is real. Part 15 §15.1 makes an empty
compellable set the method of this specification, and a moderator is a named
natural person inside a private group. Part 15 §15.1 records that party.

Four mitigations bound the damage.

1. The epoch chain records the act. A member that inspects the chain sees the
   time of the act, the acting role, and each target that the act named.
2. §11.9 requires two or more members with the `owner` role. Thus a compelled
   moderator does not leave the group without an administrator, and the
   owners read the act in the chain.
3. **[GRP-089]** At each epoch, a client MUST show the number of removals
   since the previous epoch.
4. A restore from a Part 4 §4.7.2 backup that predates the epoch recovers the
   messages. **[GRP-090]** The client MUST state that fact at the moment it
   applies a removal epoch.

**What the interface states.**

- Hide: "This takes the message out of the view of each member. A member keeps
  the message on their device, and a later change puts it back."
- Remove: "This deletes the message on the device of each member. You cannot
  undo this. Each member sees that you removed a message."
- At a removal epoch: "A moderator removed N messages. A restore from a backup
  that predates today brings them back."

> *Cause.* Draft 0.1.0 dispatched a moderation epoch with the fan-out jitter
> and named the actor by the group-scoped member identifier. Both retire: a
> moderation epoch is one post, and `actor_index` names the actor.

### 11.9.7 Presence, and the eviction that it drives

§11.8 evicts a member that stays silent longer than `GROUP_SILENT_EVICT`, and
it calls that rule a security parameter. This section gives the signal that
the rule reads and the party that acts on it.

**The signal is a presence record, and it is not a receipt.** `GroupPresence`
travels as a `GroupControl` of type `0x06`, and Part 6 §6.6.3 gives its
layout. It is a sparse-tag record under §11.3, with one tag for each member of
role `admin` or above. At `ROLE_HOLDER_MAX` entries the record is under 390
bytes, thus it fits bucket `B0`.

- **[GRP-128]** A member MUST emit a `GroupPresence` record in each
  `PRESENCE_INTERVAL` in which it sent no other record to that group.
  **[GRP-321]** A member MUST tag that record for each member that the local
  roster gives the role `admin` or above, and for no other member.
  **[GRP-322]** A member below `admin` that reads a `GroupPresence` MUST
  discard it without a report.
- **[GRP-395]** A `GroupPresence` MUST carry the `counter` of the last record
  that its sender sent in that epoch, or 0 before the first, and it MUST NOT
  advance that counter. A receiver MUST NOT apply `GRP-259` or the gap of
  `GRP-205` to a `GroupPresence`. `GRP-246` gives the counter of each other
  record.
- **[GRP-132]** An admin MUST count a member as silent when it took no record
  and no presence record from that member for `GROUP_SILENT_EVICT`.
  **[GRP-396]** An admin MUST measure that silence over the time that it
  watched: for a member whose last record it did not see, the silence starts
  when this admin first holds that member and that role. A member that
  joins starts its silence at its add.
  **[GRP-397]** An admin MUST draw the backoff of `GRP-358` before the
  removal of `GRP-133`, and MUST NOT remove a member whose removal by another
  admin arrived during that backoff.
  **[GRP-133]** An admin MUST then remove that member with a plain epoch of
  §11.9.2. **[GRP-134]** An admin MUST NOT remove a member that it counts as
  silent for a shorter period. §11.4.1 makes the admin rotate directly after
  that removal.
- **[GRP-166]** If the silent member holds `moderator` or above, the admin
  MUST first remove that role with a granting epoch. §11.9.2 lets a plain
  epoch remove a `member` or an `observer` only. **[GRP-167]** A member MUST
  NOT count a silence demotion against `GRANT_RATE`. A backlog of silent
  members at `GROUP_MAX` cannot clear under that rate.
- **[GRP-168]** If the removal leaves fewer than two owners, the admin MUST
  hold the removal. **[GRP-184]** The admin MUST then prompt each surviving
  owner to grant `owner` to another member. §11.9 rule `GRP-051` gives the
  floor, and §11.8 exempts a group of two members.
- **[GRP-135]** A client MUST NOT treat a delivery receipt or a read receipt
  as a presence signal. §11.6 gives a group no receipt.

**The cost.** A member emits at most one presence record in each
`PRESENCE_INTERVAL`, and that record is one `B0` record to each replica. At the
§11.10 interval of 7 days that is 2 × 560 = 1 120 bytes each week for each
member, whatever the administrator count. Every member downloads every presence
record, which is at most N × 560 bytes each week for each member, and 280 KB
each week at `GROUP_MAX`.

> *Cause.* Draft 0.1.0 sent one `B0` cell to each administrator on a pairwise
> channel, with the fan-out jitter. A sparse-tag record on the group queue
> reaches every reader, and only an administrator finds a tag in it. A member
> below `admin` reads that a presence record arrived and reads no more, and
> §11.5 already gives a member the roster. The rule measures **silence** and
> not connectivity. A member that reads and never posts emits a presence
> record, thus a lurker stays in the group. A member whose device is gone
> emits nothing, and RFC 9420 §16.6 gives the forward-secrecy cause that
> §11.8 states.
>
> *Cause of `GRP-395` to `GRP-397`.* An earlier form let a presence record
> take the next counter of its sender. A member below `admin` cannot verify
> it, thus it saw a hole in that counter at each presence record, and
> `GRP-205` sent it to the other replica for a record that no replica would
> give it, until the quiet member posted again. A device that became an
> admin, or that restored an old store, holds no history of the silence of
> any member, and it would remove every member at once without `GRP-396`.
> Two admins that count one silence would each post a removal on one
> predecessor, and `GRP-070` would show a fork; the backoff of `GRP-397`
> lets the first removal reach the second admin before its own.

### 11.9.8 The roster snapshot

A joiner needs the roster entries, the KEM public key of every active member,
and the authority path of §11.9.3 at the moment of its admission. The
`RosterSnapshot` carries the three as one object on the chunk path of Part 12
§12.3.3 under `CNEW`, and Part 6 §6.6.3 gives its layout: `version`,
`group_id`, `roster_epoch`, `chain_hash` (the hash of the roster epoch it
describes), the roster entries, the `kem_pk` of every active member, and the
authority path as the granting epochs on the path of every current role holder
in chain order.

- **[GRP-323]** The inviting admin MUST write a snapshot at the `roster_epoch`
  of the add, or reuse one it wrote at that same `roster_epoch`.
  **[GRP-324]** The admin MUST put the authority path in the snapshot object
  and not in the admit. **[GRP-325]** An admit MUST carry no granting epoch.
- **[GRP-326]** A joiner MUST verify `chain_hash` against the hash of the
  roster epoch that the add record names, verify each granting epoch of the
  path under §11.9.2, and verify each `kem_pk` against the `kem_pk_hash` of
  its entry. **[GRP-403]** A joiner MUST verify the path in chain order from
  the creator as `owner`, MUST take the role of a granter from the path at
  that point, and MUST take the key hash of a granter from its entry or,
  for a granter that left the group, from the grant of the path that named
  it. A grant stays valid after its granter lost its role. **[GRP-327]** A joiner MUST reject a snapshot that fails one of
  those checks. **[GRP-328]** A joiner MUST show a rejected snapshot as a
  failed admission.
- **[GRP-329]** A member that restores from a backup and lacks a `kem_pk`
  MUST fetch the newest snapshot named by any admit it holds, or ask an admin
  with a `KeyRequest` of scope `0x03`. Scope `0x03` means "the roster
  snapshot". **[GRP-330]** An admin that reads a `KeyRequest` of scope `0x03`
  MUST answer with a `SnapshotNotice` (type `0x08`) as a group record that
  carries a fresh descriptor at the current `roster_epoch`.

**What a snapshot costs.** A snapshot at N members is 77 + 1 317N bytes plus
the path. At 500 members that is 50 KB of entries and 609 KB of KEM keys, 21
chunks with two owners on the path, and at most 23 chunks at
`ROLE_HOLDER_MAX`. The joiner fetches the chunks under Part 12 §12.3.3, which
is 21 × 32 860 = 690 060 bytes at 500 members, once at its join. Draft 0.1.0
made the joiner open 499 pairwise channels for the same admission.

> *Cause.* The authority path at `ROLE_HOLDER_MAX` is 16 granting epochs, and
> each one carries a 1 952-byte `roster_pk` and a 3 309-byte signature, which
> is about 86 KB. Bucket `B3` holds 32 441 bytes of `AppMessage`, thus the
> path fits the admit up to 5 role holders and not beyond. One carrier for
> every group size is simpler than two, and the joiner fetches the snapshot
> in every case, thus the path travels in the snapshot and the admit carries
> two replica references, one key, and one descriptor.

## 11.10 Parameters

| Parameter | Value |
| --- | --- |
| `GROUP_MAX` | 500 |
| `GROUP_REPLICAS` | 2 (§11.2.1) |
| `GROUP_SLOT` | 3 600 s (§11.3.1) |
| `GROUP_SLOT_WINDOW` | 24 slots (§11.3.2) |
| `GROUP_SLOT_SKEW` | 2 slots (§11.3.2) |
| `GROUP_EPOCH_MAX_AGE` | 30 days from `t_e`, measured by each admin (§11.4.1) |
| `GROUP_EPOCH_GRACE` | 24 h from the installation of the next epoch, measured by the receiver (§11.3.2) |
| `GROUP_ROSTER_WAIT` | 24 h from the arrival of the held record, measured by the receiver (§11.3.5) |
| `GROUP_GAP_TIMEOUT` | 60 s from the first record above the gap, measured by the reader (§11.2.2) |
| `GROUP_RELINK_FIRST` | 1 s from the end of a group-queue link, measured by the client (§11.2.2) |
| `GROUP_RELINK_MAX` | 60 s (§11.2.2) |
| `ROTATE_BACKOFF_ROLE` | exponential, mean 10 s, drawn by a member at `moderator` or above at a trigger it did not cause (§11.4.1) |
| `ROTATE_BACKOFF_MEMBER` | exponential, mean 60 s, drawn by a member below `moderator` at a trigger (§11.4.1) |
| `GROUP_TAG_LEN` | 12 bytes (§11.3.3) |
| `GROUP_INDEX_MAX` | 65 535 (§11.9.1) |
| `ROLE_HOLDER_MAX` | 16 members at `moderator` or above (§11.9) |
| `GROUP_ALL_NOTIFY_MAX` | 50 members. Part 7 §7.5.9 defaults a group above it to `mentions`, and Part 8 §8.5 rule `NTF-018` uses it |
| `GROUP_SILENT_EVICT` | 30 days (§11.9.7) |
| `PRESENCE_INTERVAL` | 7 days (§11.9.7) |
| `HISTORY_WINDOW` | 0 (off) by default, maximum 7 days (§11.3.2) |
| `ROSTER_RATE_LIMIT` | 1 epoch for each member in each 60 s |
| `GROUP_EPOCH_RATE` | 6 epochs for each group in each 60 s |
| `GRANT_RATE` | 1 for each group in each 300 s, and 4 for each group in each 24 h |
| `MOD_ACTION_MAX` | 20 actions in one moderation epoch (§11.9.6) |
| `KEY_REQUEST_RATE` | 8 in each 24 h: epoch requests for one group (§11.4.3), and pairwise requests to one peer (Part 6 §6.6.11 rule `WIR-337`) |
| `POLL_GROUP_MAX` | 100 members (§11.11) |
| `MENTION_MAX` | 16 mentions in one record, and Part 6 §6.6.5 gives the field |
| `POLL_OPTION_MAX` | 12 options in one poll |

Part 3 §3.2.7 owns `GROUP_RETENTION`, `GROUP_QUEUE_QUOTA`, `GROUP_POST_RATE`,
`GROUP_READ_GRACE`, `GROUP_WRITE_GRACE`, `GROUP_IDLE_TTL`, and
`GROUP_NOTIFIER_MAX`. Part 8 §8.5.2 owns `GROUP_DIGEST_MIN_GAP`. Rule
`SCP-010` of Part 1 gives one owner to each constant.

**The periods hold one order.** **[GRP-331]** A revision MUST keep
`GROUP_EPOCH_GRACE` equal to `GROUP_WRITE_GRACE`, `GROUP_EPOCH_MAX_AGE` at or
below `GROUP_SILENT_EVICT`, `GROUP_SILENT_EVICT` equal to `GROUP_RETENTION`,
and `GROUP_RETENTION` at or below `MSG_TTL`. **[GRP-332]** A revision that
changes `GROUP_MAX`, `GROUP_TAG_LEN`, or the bucket ladder MUST derive the
cost table of §11.2, the `B1` member bound of §11.3.3, and `POLL_GROUP_MAX`
again.

> *Cause.* A member that still writes under the previous epoch inside the
> epoch grace is a member whose `GPOST` the relay still accepts, thus the two
> graces are one period. An epoch rotates before a silent member is evicted,
> thus no epoch secret outlives the eviction of the member that missed it. A
> member silent for the eviction period needs no record older than the
> retention. A pairwise carrier of the key request of §11.4.3 holds a record
> for `MSG_TTL`, thus the retention sits at or below it.

## 11.11 A mention, a reply, and a poll in a group

Part 6 §6.6.5 gives the rich record and Part 6 §6.6.6 gives the poll. This
section gives the group rules for the three.

**The nesting order is fixed.** A group content record is the `app` of a
`GroupQueueRecord` of §11.3, and a rich record sits inside it.

```
GroupQueueRecord( kind 0x01 )  →  ContentPlain.app
                               →  AppMessage kind 0x09  RichRecord( reply, mentions, forward )
                               →  inner_kind 0x01       Text
```

**[GRP-333]** A sender MUST NOT put a wrapper that names the group inside a
`RichRecord`, and Part 6 rule `WIR-163` rejects such an `inner_kind`.

**A mention names a member by its pair key.**

- **[GRP-334]** A sender MUST compute a mention identifier under Part 6
  §6.6.5, with `group_id` as the scope and the 32-byte `pair_pk` of the
  member's roster entry as the member key. **[GRP-335]** A receiver MUST take
  that `pair_pk` from the roster entry of §11.9.1. **[GRP-140]** A receiver
  MUST discard a mention that names no member of the local roster.
- **[GRP-141]** A client MUST NOT show the mention list of a record to a
  member that the list does not name. Thus a member does not learn who else
  the sender named.

> *Cause.* Draft 0.1.0 computed the mention identifier from the ML-DSA-65
> roster public key, and every member held that key through the join flow. A
> member below `moderator` never shows its `roster_pk` now, and every member
> holds the `pair_pk` of every member in the roster entry. The identifier
> stays scoped to `group_id`, thus the G9 argument of Part 6 §6.6.5 holds as
> before. The mention list travels to each member, because one record on the
> group queue reaches every reader. A client that rendered the full list
> would tell each member which other members the sender chose, and that is a
> social fact that the sender did not state to the group.

**A reply target is a `msg_id`, and §11.3.4 makes that value one value at
each member.** Thus a reply resolves at each member without a new field.

- **[GRP-142]** A receiver MUST resolve a reply target inside the group that
  carried the record. **[GRP-143]** A receiver MUST NOT resolve a reply target
  against a pairwise conversation.

**A poll has no total order, thus a count is local.**

- **[GRP-336]** A member MUST send a `PollVote` of Part 6 §6.6.6 as one group
  record. **[GRP-337]** A member MUST NOT send a vote to the poll author on a
  pairwise channel. Every member reads the vote, and every member counts.
- **[GRP-146]** A client MUST count the votes that it holds. **[GRP-147]** A
  client MUST NOT render a poll count as an agreed count. §11.7 gives a group
  no total order across senders, thus two members can hold two different
  counts at one moment.
- **[GRP-148]** A client MUST show that a count is the local view.

**The cost.** A poll is one record and each vote is one record that every
member downloads. **[GRP-149]** Thus a client MUST NOT offer a poll in a group
above `POLL_GROUP_MAX` members. §11.10 gives that value.

> *The derivation of `POLL_GROUP_MAX`.* A vote is a `B1` record at 100
> members, because the dense tag vector of §11.3.3 is 1 200 bytes at that
> size and a vote body is at most 30 bytes at `POLL_OPTION_MAX`. A group of
> *N* members that all vote costs each member *N* records of download. At *N*
> of 100 that is 100 × 2 096 = 209 600 bytes, about 210 KB, for each member
> for one full-turnout poll. At *N* of 500 a vote is a `B2` record, and one
> poll costs each member 500 × 8 240 = 4.12 MB. U4 of Part 2 §2.4 sets the
> idle budget at 100 MB each month, and one weekly poll at 500 members would
> take 16 % of it. The vote uploads once and not *N* − 1 times, thus the bound
> follows the download and not the fan-out of draft 0.1.0.

## 11.12 Multi-device: the group sender owner

A member's devices share the three group keys of §11.9.1 through the local
identity table. Each device reads the group on its own, and one device writes.

- **[GRP-338]** Exactly one device of a member, the **group sender owner**,
  MUST post the group records of that member, for every group of the user.
  **[GRP-339]** That device MUST hold `counter` for each group as mutable
  state of Part 7 §7.5.3, and the sync channel converges it.
- **[GRP-340]** A device that does not own the group sender MUST compose the
  record and hand the plaintext to the owner as an interactive sync record,
  exactly as a pairwise send under Part 7 §7.5.4. Part 7 rules `DEV-193` to
  `DEV-196`, `DEV-047`, and `DEV-048` apply, thus the composing device draws
  `msg_id` and the owner does not.
- **[GRP-341]** Ownership MUST change by an `OwnerClaim` of scope `0x04`,
  whose `subject` is `SHA3-256( K_set || 0x04 || 32 zero bytes )` under Part 7
  rule `DEV-226`. One claim covers every group of the user. **[GRP-342]** At a
  change, the new owner MUST continue `counter` from the synced value. A
  collision from a race is a reorder at receivers and not a security event
  (§11.3.5).
- **[GRP-343]** Every device of a member MUST subscribe to a replica on its
  own circuit with its own cursor, under §11.2.2. **[GRP-344]** Every device
  of a member MUST open its own slot of each epoch-key record. The slot seals
  to `GroupKemKey_g`, which every device of the member holds.
- A record carries no device identifier, and Part 7 rule `DEV-132` holds.

**A device in hostile hands, and the re-key.** Every device of a member holds
the three group keys of §11.9.1 and the current epoch secret. Part 7 §7.7
heals each pairwise channel at a revocation with a ratchet step that the
revoked device cannot follow. No such step exists for a group key, because
every device of the member holds the same seed. Thus a revoked device that an
attacker holds reads the group, and it opens its slot of each later epoch-key
record, until the member moves to new keys and the old index is rotated out.
The re-key below is that move, and it needs no admin.

- **[GRP-345]** At a device revocation of Part 7 §7.7 and at a full identity
  reset of Part 7 §7.7.1, a remaining device MUST make a new
  `GroupRosterSeed_g` for each group that the user holds, and it MUST derive
  the three keys of §11.9.1 from it.
- **[GRP-365]** For each such group, that device MUST post a `RekeyRecord` of
  Part 6 §6.6.3 as a group record. The record chains the roster: it carries
  `epoch_index` and `previous_epoch_hash` under `GRP-314` and `GRP-315`, the
  old index, the old roster public key, the three new public values, the new
  index, and a signature under the old roster key.
- **[GRP-366]** A receiver MUST verify a `RekeyRecord` under Part 6 rule
  `WIR-478`, and it MUST reject a `new_index` that breaks `GRP-320`.
  **[GRP-367]** A receiver MUST then apply the record as a roster record:
  `old_index` leaves the active set, and `new_index` enters it with the new
  keys and the role of `old_index`. **[GRP-368]** A `RekeyRecord` is a
  rotation trigger of §11.4.1, and the index it excludes is `old_index`.
- **[GRP-369]** A member that verifies two `RekeyRecord`s for one `old_index`
  with one `previous_epoch_hash` MUST apply the record whose SHA3-256 is
  lower, and it MUST show the fork under `GRP-070`, because one member made
  two successors.
- **[GRP-407]** A receiver MUST take a `RekeyRecord` from the index that the
  re-key at the head of the roster chain excluded, when the record names the
  roster epoch before that head. That index left the active set with the
  head, and `GRP-257` would drop the rival that `GRP-369` compares.
  **[GRP-408]** A member MUST take a `RekeyRecord` under its own index,
  although a record carries no tag for its sender. The signature of the
  record under the old roster key names the maker. **[GRP-409]** A receiver
  MUST NOT drop a `RekeyRecord` for its `counter` under `GRP-259`, because two
  holders of the keys of one index count apart. The roster knows a re-key it
  holds by its hash.
- **[GRP-410]** A client MUST keep the fact that the head of its roster chain
  is a re-key, with its predecessor, until the next roster epoch. A rival
  that arrives after the chain moved past the re-key MUST show the fork under
  `GRP-070`, and it MUST change nothing. **[GRP-411]** A member whose own
  re-key a rival replaced MUST read with the keys and the index before its
  re-key again, and it MUST keep the seed of its re-key for `GRP-370`.
  **[GRP-412]** A linked device that applied a re-key of its own index from
  the group queue MUST adopt the seed of that re-key when the sync item of
  Part 7 rule `DEV-300` brings it, with no second apply. The chain knows the
  re-key by its hash.

  > *Cause.* Both re-keys take the same new index, because each one names
  > the same predecessor. The rival therefore changes the keys at that index
  > and the head hash. The two replicas give no order, and a device that
  > holds the keys of a removed device can grind a lower hash. The loser
  > learns of the rival from the record alone, because no member tags a
  > record for its own sender.
- **[GRP-370]** The device whose record lost MUST send its
  `RekeyRecord` on a pairwise channel to a member of role `admin` or above
  that it holds a channel with, with `epoch_index` and `previous_epoch_hash`
  set to zero, and it MUST NOT post a second `RekeyRecord` as a group record.
- **[GRP-348]** An admin that receives a `RekeyRecord` on a pairwise channel
  MUST verify it under Part 6 rule `WIR-478`. **[GRP-349]** The admin MUST
  discard a record that fails that check, and it MUST NOT act on it.
  **[GRP-371]** The admin MUST then post a plain epoch that removes the index
  that the record names as its current index, post a plain epoch that adds
  the new keys under a new index, and send the admit of §11.9.1 step 4 on the
  same pairwise channel. The removal is a rotation trigger of §11.4.1.
  **[GRP-351]** The admin MUST NOT reuse the removed index.
- **[GRP-372]** The member MUST zeroize the old seed and the old three keys
  when an epoch-key record with a slot for its new index arrives. Until then
  the old keys stay, because the member still reads the group with them.
- **[GRP-373]** The interface MUST show each group whose re-key waits for a
  rotation or for an admit. **[GRP-374]** If the record of the user lost
  under `GRP-369` and the user holds no pairwise channel with an admin of
  that group, the interface MUST state that the group needs a new invitation,
  and the client MUST send a self-removal of its current index under
  `GRP-067`, which is a rotation trigger. The leaving member is the attacker's
  device as much as its own.
- The new seed reaches the other devices of the member through the local
  identity table of Part 7 §7.5.1, as any group seed does.

**A single device.** A user with one phone restores onto a new phone from the
recovery phrase and the backup of Part 4 §4.7.2. That backup carries the group
seeds, thus the new phone posts the same `RekeyRecord`. Without a backup the
new phone holds no group key, and the user tells an admin out of band; the
admin posts a plain epoch that removes the index, any member rotates, and the
user joins again under §11.9.1. In each case the exclusion of the old keys
waits for no role holder.

**This is a trade, and Part 2 §2.4 requires the text to state it.** From the
moment an attacker holds a device until the first other member rotates after
the `RekeyRecord`, that device reads every group of the member. The window is
one backoff after the first other member comes online. The attacker's device
holds the same old roster key, thus it can post a `RekeyRecord` of its own; if
its record wins under `GRP-369`, the user is out of that group until an admin
acts on the pairwise path, and the attacker's device is in until the user's
self-removal or the admin's removal is rotated. The attacker must unlock the
device first, at the cost that Part 14 §14.6.4 gives one passphrase attempt,
while the user revokes at once. Part 15 §15.3 records the residual.

> *Cause.* Draft 0.1.0 said that a full identity reset does not change a
> group roster key, and it gave no rule for a group after a revocation. Under
> the group queue that silence is a hole: the KEM key of a member seals every
> later epoch to that member, thus a rotation alone excludes nothing that the
> revoked device holds. An earlier form of this section sent the re-key to an
> admin over a pairwise channel and let only the admin act, thus the exclusion
> waited for one role holder. The record now travels on the group queue, any
> member rotates, and the pairwise path stays for the device that lost the
> race, because that path is the one channel the revocation closed to the
> attacker's device. The race itself is the race that Part 7 §7.7 already
> accepts for a device revocation.

> *Cause.* Draft 0.1.0 had no group sender owner, because a group send was
> N − 1 pairwise sends and each pairwise ratchet already had an owner. The
> `counter` of §11.3 is one value for each member in each epoch, and two
> devices that post at once would give two records one value. One owner
> keeps the pair (`epoch`, `counter`) monotone in the ordinary case, and the
> reorder rule covers the race at an ownership change.
