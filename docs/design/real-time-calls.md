# Voice calls over UMBRA relays

**Status:** Proposal, revised after two independent reviews. This document is not normative. It adds no rule ID and it changes no part of `spec/`.
**Date:** 2026-10-31

This document proposes a voice call for a later version. Part 2 §2.5 lists real-time media as an omission of v1. This document supplies the three items that §2.5 asks for: a latency target, a metadata cost, and a residual.

## Status after review

**No reviewer has read this text.** The final revision replaced the shared path design with directional paths (§4.2). Each fix below is untested and unreviewed.

**A reader must not assume these items.**

- No measurement exists. No UMBRA call exists, and each figure here is cited, derived, or proposed.
- The budget does not close on paper. The known sum is 473 ms to 580 ms against a limit of 400 ms (§3).
- A call does not hide its time. A contact who also watches a link can match the time of a call to that link (§8.1 row 11).
- Profile A is a control and profile C is a candidate. Neither has a measured precedent in this form (§7).

**The review blockers.**

| Blockers | State in this text |
| --- | --- |
| First review B1, B5, B6 | Fixed in text. The second review read an earlier form |
| First review B2, B3; second review X1, X3 | Replaced by a smaller key schedule (§5.4). The off-air step is gone. Not reviewed |
| Second review X2 | Removed. No shared draw exists (§4.2) |
| Second review X4 | Replaced by a simpler rejoin (§4.4, §6). Not reviewed |
| First review B4 | Fixed for a timing pattern through an honest splice relay alone. The rest is O1 |

**Open items.**

| # | Open item | Why it stays open |
| --- | --- | --- |
| O1 | Contact plus observer: the call time, a hostile splice relay, a forged frame, and a hostile pin that writes to a hostile contact | Each one survives the splice clock (§8.1 row 11) |
| O2 | The latency budget | It needs Stage 0 |
| O3 | `THR-002` fails for a call when A1 holds both links | It is the core of the mode. The owner must accept it or end this work |
| O4 | A shared pin gives one relay the two addresses | No detection exists that does not show the pin to the contact |
| O5 | Pin oracle and guard discovery at each relay that a contact names | A party that cannot join shows that to the peer, and a hostile relay meets a hostile hop 2 (§8.1 row 21) |
| O6 | The replacement limit of §10.6.2 | The hourly limit does not fit a call. A rule change is needed |
| O7 | Calls on a provisional network | The owner decides (§8.2) |
| O8 | G5 fails inside a call | No KEM step exists (§5.4) |
| O9 | No signal reads the delay of one path | A slow path stays in use. Profile C only tolerates it (§7) |
| O10 | A microphone service from a background wake | Not verified. A failure removes a large share of "Rings" in §5.2 |

## 1. Summary

A call uses constant-rate media circuits. Hop 1 and hop 2 add no delay. A memory-only splice function at layer 3 joins two half circuits, and it sends cells to the receiver on a fixed clock of its own. Each path carries one direction, and the receiver picks its relay. Each circuit keeps the chained cipher, and an end-to-end frame layer sits above the circuit. No path uses peer-to-peer media or one TURN relay.

**A call is an opt-in mode with a weaker guarantee than a message.** A party that watches the two ends can see that the two parties talk at the same time (§8).

**The chosen design.** The owner set these seven items before this document. §1.1 lists the changes.

1. Two active media circuits from a monitored set, each a lossless 3-hop circuit with the existing chained cipher.
2. A constant cell clock at 40 ms, one `B0` cell for each tick on each path, with no silence suppression, no Poisson pacing, and no per-hop delay. **The owner reversed the "no relay clock" part at the splice relay after the first review.**
3. Opus at 32 kbit/s with 40 ms frames, two copies on two paths, and the first copy plays. Spare cell space can carry the previous frame.
4. A memory-only splice relay joins the two parties. The callee must be online.
5. An end-to-end frame layer with its own counter and MAC above the circuit. Only a failed circuit ends, and the monitored set replaces it.
6. No fall back to peer-to-peer media or to one TURN relay.
7. No video and no group calls in the first version. No datagram hop cipher for now.

**The figure classes.**

| Class | Meaning |
| --- | --- |
| Measured | A measurement on UMBRA hardware or on the UMBRA network. This document holds no such figure. |
| Cited | A figure from a source of §13. |
| Derived | A figure that this document calculates from the spec or from a cited figure. |
| Proposed | A value that this document selects. No source supports the value. The plan of §11 tests it. |
| Not verified | A statement that no verified source supports. |

### 1.1 Changes to the chosen design

| # | Item | Evidence | Effect in this document |
| --- | --- | --- | --- |
| D1 | Item 1: two active circuits from a monitored set | Donar used 6 active links, and each frame took 2 of them by rotation. The paper states that `n1ST = 1`, which is 2 active links, "yields high latencies". TorFone sent duplicates on two static links and reached 23 % to 47 % of successful calls. Donar reached at least 87 % at the same wire cost. | The monitored set is removed (§7). Profile A is the two-path control. **This document expects it to miss the target.** Profile C is the candidate. |
| D2 | Item 5: replacement from a monitored set | Part 10 `REL-014` and `REL-015` forbid a replacement that follows a local measurement. §10.6.2 allows one replacement in each 1-hour epoch for each layer. | A path changes only at a failure, by a new draw. `REL-014` holds. The hourly limit needs a change (O6). |
| D3 | Budget | The spec model gives 210 ms for one 3-hop circuit. A spliced path has six links, thus 420 ms. | §3 states this as the first risk. The model may be too high, because Donar held 6 relays under 360 ms on Tor. |
| D4 | Item 3: previous frame in the spare space | Donar sends the previous frame on a *different* link. With two fixed lossless paths, each path already holds each frame. | Profile A sends no previous frame. Profile C does. |
| D5 | Item 4: one path that two parties share | The first review showed that a contact can write a pattern through a relay that it names. The second review showed that two parties cannot compute a shared draw. | Each path carries one direction, and its receiver picks the relay (§4.2). |
| D6 | "No one relay learns both parties" | Each client pins two ingress relays, and both pins carry a call. Two clients share a pin with a probability of 100 % at 2 ingress relays, 38 % at 10, and 8 % at 50 (derived, equal weights). | The launch network cannot hold this property (O4). |
| D7 | Launch network as a call network | The inventory holds one layer 2 relay and two ingress relays, thus no two paths are disjoint. All relays share one ASN, thus no chain meets invariants 1 and 3 of §3.4.6. | The launch network is a test floor only. §11 defines a test bed. |

Item 2 changes at the splice relay alone. Hop 1 and hop 2 keep no delay. Item 6 and item 7 stand. Item 5 stands with one addition: the frame nonce comes from an implicit cell index (§6).

## 2. Goals and non-goals

**Goals.**

- Carry two-party voice with mouth-to-ear delay at or below the G.114 planning limit of 400 ms (§3).
- Keep G1 to G4 and G10 for call content, with the primitives of Part 5. G5 holds from one call to the next and not inside a call (§5.4).
- Keep the address of each party out of the call data that the other party gets.
- Give no single relay the two parties, with the exceptions of §4.5.
- Keep a failed circuit from ending the call.

**Non-goals.**

- Hide from a party that watches both ends that a call took place (§8).
- Stop a contact who works with a network observer from matching the time of a call (§8.1 row 11).
- The 150 ms transparent delay of G.114. Six links do not reach it.
- Reach an offline callee. A call has no durable queue.
- Video, group calls, and a link to a telephone network.
- A linked device that takes a call. The owner device alone reads the pairwise queues (Part 7 §7.5.4).

**Rejected for now.** A datagram hop cipher stays rejected. The Tor report of 2018 states that a loss-tolerant design loses the property that one altered cell breaks all later cells, and that it opens a one-bit-per-cell channel. Yodel tolerates loss, but it needs synchronous rounds and 15 hops, and it gives 990 ms one way. `QuicLink` in `crates/umbra-transport/src/native.rs` holds one stream and no datagram, and no caller dials it in v1.

## 3. Latency target and budget

**Proposed target.** Mouth-to-ear delay at p99 of the frames is at or below 400 ms, in at least 86 % of calls of 5 minutes and of 90 minutes. Donar uses this form of target. It reports 86 % in its abstract and at least 87 % in §6.1 for DOUBLE-SEND with 6 relays.

Donar excludes capture and playout. Its 360 ms is 400 ms less one 40 ms frame. Thus 360 ms is too high a limit here. The limit for the network, the splice clock, and the jitter buffer is:

```
L_net = 400 ms - 40 ms - X
X     = T_capture + T_encode + T_cipher + T_decode + T_playout
```

| Stage, one way | Figure | Class | Note |
| --- | --- | --- | --- |
| Frame time | 40 ms | Cited | Donar `Tframe` |
| Capture, encode, frame cipher | `T_capture`, `T_encode`, `T_cipher` | Not verified | Stage 0 |
| Client to ingress, then two relay legs | 60, 75, 75 ms | Derived | Part 3 §3.12 model |
| Splice clock | The table below | Derived | The phase of a half is fixed for a call |
| Splice queue, at full depth | 80 ms in profile A, 120 ms in profile C | Derived | §4.4 |
| Two relay legs, then ingress to client | 75, 75, 60 ms | Derived | The same legs in the other half |
| **Propagation** | **420 ms** | **Derived** | Six links. Part 3 `NET-137` requires a real measurement |
| Relay work at 5 visits | `T_relay` | Not verified | Stage 0, §4.8 |
| Jitter buffer | Up to p99 less the minimum | Cited | Donar treats an ideal buffer as adding no more than this |
| Decode, playout | `T_decode`, `T_playout` | Not verified | Stage 0 |

| Known sum (40 + 420 + clock), derived | First of two copies, mean | One copy, mean | Worst phase |
| --- | --- | --- | --- |
| Profile A, 40 ms period | 13.3 ms, sum 473 ms | 20 ms, sum 480 ms | 40 ms, sum 500 ms |
| Profile C, 120 ms period | 40 ms, sum 500 ms | 60 ms, sum 520 ms | 120 ms, sum 580 ms |

**Each sum is above 400 ms before each unknown term.** The model gives a bound and not a typical value, and §3.12 states that it is not a measurement. Two facts pull in opposite directions:

- Donar held 6-relay links under 360 ms on Tor in January 2021. That result used rotation over 6 links, and both ends ran on one machine.
- Part 3 §3.4.6 forces each chain across three operators and three blocs. Tor has no such rule.

If Stage 0 shows that the conformant chains do not close the budget, three options remain. Each one costs a security property.

| Option | Effect | Cost |
| --- | --- | --- |
| A latency bound on the draw, from directory data | Shorter links | A smaller set of chains, with no local measurement (`REL-014`). §3.12 names LAMP-style selection, and no rule holds it (§10) |
| Splice at layer 2 | 4 links, 270 ms in the model | Breaks `NET-167` and the fixed hop count of §3.4.2. The splice relay then sits next to each ingress relay |
| A higher target | No change to the network | The call exceeds the G.114 planning limit. Kill criterion 1 covers this case |

## 4. The media circuit

### 4.1 Three circuit types

```
Path p, Alice to Bob. Bob picked S.

Alice == hop1 == hop2 == S == hop2 == hop1 == Bob
   send half               receive half

Each client builds its own half. Each half is an ordinary 3-hop chain
that ends at S. A second set of paths, picked by Alice, carries Bob to Alice.
```

| Property | Message circuit | Bulk circuit (Part 12 §12.8) | Media circuit (proposed) |
| --- | --- | --- | --- |
| `delay_class` | Fast, Balanced, or Private | Mode of the conversation | New value: Media |
| Per-hop delay (`NET-338`) | Mode | Mode | None |
| Clock toward the client | Poisson tick (`NET-291`) | Tick, with `NET-360` | Fixed clock at the splice relay |
| Buckets | All | Mostly `B3` | `B0` alone |
| Rate | Follows use | Follows a window | Fixed by the profile, policed at hop 1 |
| Endpoint | Queue relay | Chunk relay | Splice function |
| Durable state | Queue records | Chunks | None |
| Cell bound | 8 192, margin 64 | 8 192, margin 2 048 | 524 288 (§4.7) |
| Age bound | 4 h | 4 h | 4 h |
| Client connection | Interactive link | Separate (`NET-074`) | Interactive link of a pin, never a bulk link |
| Cipher | `NET-108`, `NET-116` | The same | The same |

`NET-131` and `NET-132` do not change. Each half is lossless and in order. The splice relay consumes each cell of a send half as an endpoint does, and it starts each cell of the receive half.

### 4.2 Directional paths

**Each path carries one direction, and its receiver picks the splice relay.** The receiver draws the relay from its own current manifest under `REL-196`, with the queue relays of the conversation removed, and it names the relay to the sender.

| Result | Cause |
| --- | --- |
| No shared draw, no seed, no common manifest | Each party draws from its own view. A relay that the sender does not hold in its manifest leaves that one path unjoined (`NET-085`) |
| A contact cannot write through its own relay | A relay that the contact names carries traffic toward the contact alone. Each cell toward the victim passes a relay that the victim drew |
| Each party balances its own downlink | It picks a relay for each half with its own pins and its own `NET-032` check |
| No tie-break | The receiver owns each path: its choice, its replacement, its budget |

**The cost.** A party holds twice the circuits. Accept-to-audio grows, because the caller learns the relays of the callee in the first cells (§5.1). A contact still names the relays of the send halves of the victim (§8.1 row 21).

### 4.3 Choice of layers

Each half is a stratified chain under §3.4.1. Hop 1 is a pin, hop 2 is a draw from layer 2, and hop 3 is the splice relay. `NET-309` already makes a client build a chain to a required last relay. Each client applies `NET-032` to its own half. No client knows the half of the other party, thus `NET-032` does not bind the pair of halves. §4.5 lists what that leaves.

The first version holds one link to each pin during a call. The reference client holds one link in a run (Part 10 §10.6.1), thus this is new client work. On one pin, all circuits of a client share one TCP connection, so a loss on that connection stalls each of them. A client with one pin takes no call.

Media circuits share the interactive link of a pin, thus media cells mix with message cells. The link to the second pin carries media alone. That is the secondary connection of Part 10 §10.6.1 (§8.1 row 17).

### 4.4 The splice function

**Check of Part 9 §9.6.** §9.6 is not a usable base. It is a durable queue that takes a one-way hello in bucket `B3`. It joins no two circuits. The design takes one idea from it: a value that the two parties share.

**A new relay role is not needed.** The splice is a function of a layer 3 relay, in the manner of the group queue. It stays in the one relay population of §3.10.1, and `REL-150` already binds the last hop. `NET-165` to `NET-167` do not change. The descriptor needs one new `roles` bit.

**The commands (sketch).** These are L5 commands on a media circuit. Only the splice relay reads them.

| Command | Direction | Content |
| --- | --- | --- |
| `SPLICE_OPEN` | Client to relay | `token [32]u8`, the role (send or receive), the period, and an `Admission` |
| `SPLICE_WAIT` | Relay to client | No second half yet |
| `SPLICE_JOIN` | Relay to client | The two halves are joined |
| `SPLICE_BUSY` | Relay to client | The media cap is full |

**The join (proposed).**

1. The relay holds a keyed hash of each token in memory alone, for the life of the path. It writes nothing to the store, thus `NET-298` has no effect. `SPLICE_TABLE_MAX` bounds the table.
2. A first `SPLICE_OPEN` waits for at most `SPLICE_TTL` of 90 s, which is `RING_WINDOW` of 60 s plus `RING_TIME` of 30 s.
3. A second `SPLICE_OPEN` with the same token and the other role joins the two circuits.
4. While a half is missing, a `SPLICE_OPEN` with that token and the missing role takes its place. This is a rejoin. It needs no second token, and it works more than once. The relay ends each other later use.
5. The relay ends a Media circuit with no `SPLICE_OPEN` after 5 s. It ends a Media circuit that carries a queue command, and a non-Media circuit that carries a `MEDIA` cell. It ends a circuit that sends a `MEDIA` cell before `SPLICE_JOIN`.

**The splice clock (proposed).** This is the owner decision on first-review finding B4.

1. A receive half has a clock from `SPLICE_JOIN` on, with the period of its `SPLICE_OPEN` and a random phase. A send half gets relay commands alone.
2. At each tick the relay sends a waiting relay command first. Else it sends the oldest cell of the queue. With an empty queue it sends a relay `PADDING` cell.
3. A queue holds at most 3 cells at a period of 40 ms, and 2 cells at a period above that. A full queue drops its oldest cell. A relay command is never dropped.
4. The relay reads the depth after the send. When the depth stays at 1 or more for 1 s, the relay drops the oldest cell once, and the timer starts again. A period above 40 ms takes 3 s.

**The drop in rules 3 and 4 is necessary.** Cells enter and leave at one rate, thus a backlog from one stall never drains by itself. A stale frame has no value, so the relay drops it. The frame layer accepts that gap (§6). `NET-132` does not fire, because the relay consumed the cell on its half.

**The end of one half (proposed).** A half ends at a `DESTROY`, a `CircuitDestroy`, or 15 s with no forward cell on a send half. The relay does not end the other half at once. It keeps that half for `SPLICE_HOLD`, which is 3 s plus Exp(mean 3 s), at most 15 s. The clock runs on a receive half during the hold, and the relay drops the cells of a send half with no receiver. After the hold, the relay ends the other half under `NET-322`. The hold has two functions: the kill signal does not cross at once, and a handover has a recovery path.

### 4.5 What each position learns

| Position | Learns | Does not learn |
| --- | --- | --- |
| Hop 1 | The client address, a one-way stream, its start and its end, and the next relay | The splice relay, the other party |
| Hop 2 | The two adjacent relays, the same stream | Each client address |
| Splice relay | Two hop 2 relays, the token, that the two circuits are one path, the start and the end, and the arrival time of each cell | Each client address, the content, the other paths of the call when another relay holds them |

The table holds for one honest pair of halves. **Three cases break it.**

- **A shared pin.** A relay that is hop 1 for both parties sees the two addresses, and it can match the streams. This case breaks `THR-006` for that call. Pins last 60 to 120 days, thus the exposure repeats.
- **A shared operator or bloc.** An operator, or a state that reaches a bloc, with a pin of each party links the two ends. With a share `c/n` of ingress capacity the probability is `(1 - (1 - c/n)^2)^2` (Donar §5). At 10 % that is 3.6 % of contact pairs (derived).
- **A provisional network.** One operator runs each relay (§8).

Shared hop 2 is a smaller case. It joins two ingress relays and no address.

### 4.6 `NET-028`, the modes, and the binding of the class

`NET-028` holds if Media is a value of `delay_class`. One circuit then carries one mode. `NET-337` must take the new value. `NET-080` fails as written, because a call is visible in the cell count. It must scope to the three message modes, and §3.9.1 must state the new class.

`NET-029` binds a client alone, so the last relay must enforce it for Media (§4.4, rule 5 of the join). Hop 1 and hop 2 cannot read a command.

**The class needs a binding.** Part 3 §3.9 states that a hop before the last can change the field. Media gives that change a new effect: a hostile hop 1 can remove the delay and the rate rules of hop 2 on a message circuit of a user who never opted in. Thus the client must add `delay_class` to the prologue of `UMBRA-NKhfs` (Part 5 §5.4.9). A changed class then fails `tag1`, and the relay aborts. This change covers each mode, and each circuit build changes.

### 4.7 `CIRCUIT_MAX_CELLS` and `CIRCUIT_MAX_AGE`

| Quantity | Arithmetic | Result (derived) |
| --- | --- | --- |
| Time to the relay bound at 25 cells/s | 8 192 / 25 | 327.7 s, about 5 min 28 s |
| Time to the client stop | (8 192 - 64) / 25 | 325.1 s |
| Time to the spare start | (8 192 - 64 - 512) / 25 | 304.6 s |
| The same three at 8.33 cells/s | | 16.4 min, 16.3 min, 15.2 min |
| Rotations of one 25 cells/s circuit in 1 h | 3 600 / 304.6 | 11.8 |
| Build bytes for one party in 1 h, profile A | 4 × 12 × 12 576 B | 604 KB, 0.30 % of 201.6 MB |
| Key agreements for one call, profile A | 24 in each 304.6 s | 0.079 each second |

The bytes are not the cost. The cost is new chains. Each rotation draws new hop 2 relays, and Donar §5 notes that repeated circuits degrade security (the predecessor attack). One draw is one half. This table gives the probability of at least one hostile hop 2 in one hour, at a 10 % share of layer 2 (derived, equal weights). A hostile hop 2 learns a stream and not a party.

| Profile | Draws, recommended bound | Result | With a used budget (§7) | Result | Draws at 8 192 cells | Result |
| --- | --- | --- | --- | --- | --- | --- |
| A | 8 | 57 % | 24 | 92 % | 102 | Above 99.9 % |
| C | 24 | 92 % | 40 | 98.5 % | 119 | Above 99.9 % |

**Recommendation.** Set `MEDIA_CIRCUIT_MAX_CELLS = 524 288`, which is 5.8 h at 25 cells/s. `CIRCUIT_MAX_AGE` of 4 hours then binds. `REL-201` is the precedent for a circuit that leaves the cell count. The change touches `NET-321`, `NET-210`, and the vector of Part 6 §6.8. A relay counts relay `PADDING` cells in this bound.

The spec states no cryptographic cause for 8 192, and Stage 5 must confirm that. If a cause exists, keep 8 192: the rotation below works at either bound.

**A rotation with no gap.** A call reaches the age margin at 3 h 57 min, which is the start of `CIRCUIT_SPARE_LEAD`.

1. The receiver rotates one path in each 30 s. Each other path carries the frames.
2. It names a new relay in a `PATH_NEW` item (§5.4). Both parties build, and the new path joins before the cut.
3. The sender moves the path. The receiver reads the old path for 1 s, and then each party sends `DESTROY`. `CIRCUIT_RETIRE_WAIT` of 30 s needs a media value (§10).

### 4.8 The relay path

The current relay does not meet the budget. Each item below comes from `crates/umbra-relay/src/server.rs` or from the spec.

| Problem | Effect | Proposed change |
| --- | --- | --- |
| `run_node` serves each cell on one task, and a key agreement runs on it (cause of `NET-332`) | One build holds each media cell back | A separate task for media cells |
| The outputs of one group wait for the store commit (`NET-298`) | A media cell waits for a disk sync of another client | A media cell leaves outside the commit group |
| A `B3` upload window shares the FIFO of a relay link | 128 × 32 860 B at 250 Mbit/s is 135 ms (derived) | Keep one relay link. Send media cells first, and keep at most 64 KiB unsent in the socket, which is 2.1 ms at 250 Mbit/s (derived) |
| The `seq` of a session is `u24`, `WIR-139` closes the link at the wrap, and `NET-290` ends each circuit of that link | At 279 calls one ingress-to-middle link carries 13 950 cells/s. It wraps in about 20 minutes (derived) | A wider `seq` for a relay link, or a second link that takes over before the wrap |

**The police (proposed).** Hop 1 alone polices, and it cannot read the profile. It holds each Media circuit to 25 cells/s, in `B0` alone, with a burst bound of 50 cells, and each address to `MEDIA_CELLS_PER_ADDRESS` of 100 cells/s. That is 448 kbit/s of media priority for one address, against 917 Mbit/s with no such cap (derived from `LINK_CIRCUITS_MAX` and `RELAY_CONN_PER_IP`). A party sends 50 cells/s, thus two calls fit on one shared address.

Hop 2 does not police. A burst after a stall passes to the splice relay, and the bounded queue absorbs it. A stall on a relay link ends a path only when its gap passes `GAP_MAX` (§6): 16 s at 25 cells/s and 48 s at 8.33 cells/s (derived). Stage 4 tests this bound.

**The price (proposed).** `SPLICE_OPEN` needs a proof of work at each effort, as `ABU-106` requires for `CNEW`. An `Admission` of kind `0x00` is free at effort 0, and one open buys up to 201.6 MB. A rejoin pays it too. A relay at its media cap answers with `SPLICE_BUSY`.

## 5. Signaling

### 5.1 The flow

```
1. Caller : opts in, checks 5.3, draws its P receive relays,
            and sends CallOffer on the pairwise queue path.
2. Caller : after a random wait of 1 s to 5 s, builds its P receive halves,
            and sends SPLICE_OPEN.
3. Callee : reads the offer, and rings when the checks of 5.3 pass.
4. Callee : user accepts. Draws its P receive relays. Builds its receive
            halves, and its send halves to the relays of the offer.
5. Relay  : SPLICE_JOIN. Cells flow from the callee to the caller.
6. Callee : sends the setup items of 5.4, and then voice.
7. Caller : derives K_call, builds its send halves to the relays of the callee.
8. Caller : sends voice, and acknowledges the setup.
9. Either : sends an end item in-band. The streams stop.
```

**No automatic answer.** The callee sends no "ringing" record, no "busy" record, and no receipt for a call record. A record that follows an arrival with no user action is the round-trip signal of Part 3 §3.5.4, which had a median of 1 480 ms against sealed sender. A decline is a user action, and it uses `CallEnd`.

**The queue path stays apart from the end of a call.** `CallEnd` serves a decline and a caller cancel before the join. A normal end is an in-band item, because a queue event at the end time feeds the attack of §8.1 row 4. The wait in step 2 moves the circuit builds away from the `SEND` of the offer. A half that waits carries no cell, thus the two streams start near one time (§8.1 row 4).

**Costs (derived).** An unanswered call costs the builds alone: 75 KB for six halves.

| Accept to audio, cold builds | Profile A | Profile C |
| --- | --- | --- |
| Caller hears callee: build 0.81 s (§3.12), join 0.42 s, 3 setup cells, path 0.42 s | 1.77 s | 2.01 s |
| Callee hears caller: then build, join, and path again | 3.42 s | 3.66 s |

A proof of work adds more.

### 5.2 Ring limits

The offer takes the message path, thus it takes the message latency.

| Callee state | Offer arrives | Class | Result |
| --- | --- | --- | --- |
| Online, Balanced conversation | p50 1.6 s, p95 3.9 s | Cited, model of §3.12 | Rings |
| Online, Fast conversation | p50 1.1 s, p95 3.4 s | Cited, model of §3.12 | Rings |
| Client unlocked, device idle, Instant or Direct | p50 3 s, p95 15 s, p99 60 s | Cited, U3 target | Rings |
| Client locked, Instant or Direct | An alert at the U3 time | Cited, U3 | **No ring.** See below |
| Periodic | Up to 30 min | Cited, Part 8 §8.3 | Missed call |
| Private | 20 to 30 min, or at the unlock | Cited, Part 8 §8.3 | Missed call |
| Off | At the next open | Cited | Missed call |

**A locked client cannot ring.** `IMP-127` makes a locked client hold no key. It cannot read the offer, and the 69-byte blob of Part 8 §8.2.2 names a queue and no call. The user sees the usual alert of `NTF-136`, unlocks in up to 4.5 s (U8b), and then reads the offer. The blob must not name a call, because a change to it adds a class of wake.

**Proposed windows.** `RING_WINDOW` is 60 s, which is the U3 p99. `RING_TIME` is 30 s. An offer outside the window shows as a missed call. The age reads `offer_time`, because `WIR-076` keeps `sent_at` advisory, with a tolerance `CALL_CLOCK_SKEW` of 300 s. A stale offer inside that tolerance rings, finds no party at the token, and ends as a missed call after 5 s. A call to a locked or sleeping client fails often, and the product text must state this.

**A call in progress must hold the lock.** `IMP-119` sets an idle lock of 15 minutes by default and 30 at most, and `IMP-127` stops the network at the lock. With no change, a quiet call ends at the lock. The hold keeps `K_store` in RAM for the call (§8.1 row 20).

### 5.3 Records

These are new `AppMessage` kinds on the ratchet, of a new class, Call signal. The class Ephemeral does not fit, because the client does not store such a kind, and a missed call must stay. The store keeps the conversation and the time of a missed call alone. It keeps no duration, no `K_offer`, and no relay.

```
CallOffer {                     // bucket B1, 1 466 B at P = 6
    call_id     [16]u8          // CSPRNG
    offer_time  u64
    K_offer     [32]u8          // CSPRNG
    kem_ek      [1216]u8        // UMBRA-KEM public key, fresh for this call
    codec       u8              // 0x01 Opus, 32 kbit/s, 40 ms
    profile     u8              // sets P
    relays      [P][32]u8       // relay_id of each receive path of the caller
}

CallEnd {                       // bucket B0, a decline or a cancel
    call_id     [16]u8
    reason      u8
}
```

**The checks.** A party acts on an offer only when each of these holds. The caller runs the same list before step 1, without the last two items.

- The conversation is Fast or Balanced.
- The directory is not provisional, except in a test build.
- The user opted in (§8.2).
- This device owns the ratchet.
- The client holds two pins.
- `call_id` is new, and no other call runs.
- `offer_time` is inside the window of §5.2.
- The named relays are distinct, at most two share an operator, and none holds a queue of this conversation.

A callee that fails a check stays silent. A caller applies the last check to the relays of the setup, and it ends the call on a violation. A party that sees a relay outside its manifest, or a relay that fails `NET-032` on both pins, skips that path and sends no refusal.

### 5.4 Key agreement

The key schedule uses Part 5 primitives alone.

**Path identity.** `path_id` `p` never returns in a call. The first `P` values, `0` to `P - 1`, are the receive paths of the caller. The next `P` values are the receive paths of the callee. A later path takes the next value of its receiver: even for the caller, odd for the callee, from `2P` up.

```
Token(p) <- HKDF-SHA3-256(salt = K_offer, ikm = "",
                          info = "umbra/v1/call-token" || call_id || BE16(p), L = 32)
SK(p)    <- HKDF-SHA3-256(salt = K_offer, ikm = "",
                          info = "umbra/v1/call-setup" || BE16(p), L = 32)

(ct, ss)   <- UMBRA-KEM.Encap(kem_ek)              // callee
ss         <- UMBRA-KEM.Decap(kem_sk, kem_ek, ct)  // caller
transcript <- SHA3-256("umbra/v1/call-transcript" || call_id || kem_ek || ct)
K_call     <- HKDF-SHA3-256(salt = K_offer, ikm = ss,
                            info = "umbra/v1/call-key" || transcript, L = 32)

CK(p,0)   <- HKDF-SHA3-256(salt = K_call, ikm = "",
                           info = "umbra/v1/call-path" || BE16(p), L = 32)
CK(p,n+1) <- HKDF-SHA3-256(salt = CK(p,n), ikm = "",
                           info = "umbra/v1/call-rekey", L = 32)
n         =  cell_index / 1 500
```

Each path carries one direction, thus a key has no direction input. Each `(key, nonce)` pair is unique, because `p` never returns and the index only moves forward.

**The setup.** On each joined path of the caller, the callee sends `ct` and its `P` relays under `SK(p)`. These take 3 cells. The caller reads them from the first path that delivers them.

**The delivery rule.** A cell can be lost now, because the splice relay can drop it. Each setup, `PATH_NEW`, and end item carries an item number. A sender repeats an item on each live path toward the peer, each 1 s, until the `ack` field names it. A receiver treats a repeat as a no-op. The `ack` needs a path in the other direction, thus the first setup items repeat until the caller has its send halves. An end item stops after 2 s with no `ack`, and the hold covers the rest.

**The erasure list.**

| Value | Erased at |
| --- | --- |
| `kem_sk`, `ss` | Directly after `K_call` exists |
| `K_call` | Directly after `CK(p,0)` of each of the first `2P` paths exists |
| `K_offer` | When `K_call` exists at that party, after `SK` and `Token` of the first paths exist |
| `SK(p)` | Callee: at the `ack` of the setup. Caller: when path `p` left setup, or 5 s after `K_call` |
| `CK(p,n)` | After a check passes under a later key |
| Each key of a call attempt | At a cancel, a decline, a timeout, or the end of the call |

A `CK(p,0)` that has sealed nothing shows nothing. `Token(p)` opens no traffic, and it lives for the life of the path.

**A later path.** For a replacement or an age rotation, the receiver sends `PATH_NEW`: `path_id`, the relay, a random token, and a random `CK(p,0)`. Thus a later path needs no erased key. The sender checks the relay as §5.3 does, and it delays its build by a draw from the `SPLICE_HOLD` distribution (§7).

| Property | How it holds |
| --- | --- |
| Binding to the session | `K_offer` travels under a message key of the ratchet of Part 5 §5.5. Only the contact reads it |
| Post-quantum confidentiality (G2) | The `UMBRA-KEM` secret enters `K_call` |
| Forward secrecy (G4) | Each chain steps each 1 500 cells, which is 60 s at 25 cells/s and 180 s at 8.33 cells/s |
| Post-compromise security (G5) | **Not inside a call.** A party that reads one chain key reads the rest of that chain, and a `PATH_NEW` on it shows later paths. The next call heals, because its `K_offer` and its KEM are fresh |
| Deniability (G10) | No signature. Authentication is implicit, as in Part 5 §5.7 |
| Separation of paths | Each path has its own chain, thus two relays see different bytes for one frame |

Skipped-message keys live 45 days (Part 5 §5.5.4), which is the cause to mix in the fresh KEM secret.

## 6. Frame format

This is a sketch and not a wire format. A media cell is a `B0` cell with a new command byte, and the closed list of `WIR-135` must grow by one.

```
body after the last hop layer, 480 B:
    command   u8          // 0x09 MEDIA
    ct        [462]u8     // ChaCha20-Poly1305 of MediaPlain
    tag       [16]u8
    marker    u8          // 0x80, WIR-011

key   = CK(p,n), or SK(p) in setup
nonce = BE96(cell_index)  // implicit, not on the wire
ad    = call_id

MediaPlain {              // 462 B
    ack       u16         // the highest item number seen in order
    items                 // each: kind u8, len u16, body
    padding               // zero bytes to 462 B
}

kind 0x01 voice    seq u32, Opus frame
kind 0x02 no voice seq u32
kind 0x03 setup    item u16, fragment
kind 0x04 control  item u16, PATH_NEW
kind 0x05 end      item u16
```

One cell can hold two voice items and a control item. `cell_index` is the index of the last sealed cell of that path, plus one. Index 0 is the first `MEDIA` cell of the path. A rejoin keeps the index. No cell carries the index, and `seq` sits inside the ciphertext. A relay `PADDING` cell is outside the frame layer and uses no index. Each relay after the splice sees it as an ordinary `B0` cell, because the hop layers hide its command byte.

**The gap rule.** The receiver accepts a forward gap: on a failed check it tries the next index, up to `GAP_MAX` of 400 cells. It derives a later `CK` for a trial, and it erases an older `CK` only after a check passes. One cell that fails each index of the window ends the path. While a path is in setup the receiver tries `SK` too.

| Act at the splice relay | Result |
| --- | --- |
| Drops a cell | The far relays see no change, because `PADDING` fills the tick. The receiver loses one copy of a frame. A run above `GAP_MAX` ends the path |
| Delays a cell | A delay inside the queue bound changes no far timing. A hostile relay that runs no clock passes timing on (§8.1 row 11) |
| Repeats or reorders a cell | The index moved forward, thus each check fails and the path ends |
| Alters or injects a cell | Each check fails and the path ends |

The relay gets a selective drop, and it reaches the receiving client alone. The per-cell channel to a far relay stays closed.

**The rules (proposed).**

1. A frame is 160 B at 32 kbit/s and 40 ms (derived). Donar reports 172 B, and the 12 B difference is likely the RTP header (not verified).
2. A sender seals each frame once for each path that carries it.
3. A sender makes a cell at the tick, and not before. If a socket is full, it skips that tick and it seals nothing. An index thus never repeats, and no sealed cell waits for a stale time.
4. A sender keeps at most one cell unsent in the socket.
5. A receiver that ends a path on a failed check follows the delay rule of §7.
6. The receiver holds one `seq` window for voice in each direction. It is 64 frames wide, which is 2.56 s. It plays the first copy of a frame, and it drops each later copy.
7. The receiver sets its jitter buffer to the p99 of the first-copy delay over the last window. It drops a later frame, and Opus loss concealment fills the gap. Donar treats 1 % of frames as the limit of unnoticed loss.
8. A tick with silence still sends a cell, with a no-voice item. The cell size and the cell rate do not change, thus a variable Opus frame shows nothing to a relay.

## 7. Paths

**Decision: remove the monitored set.** The design holds a static set of paths for each direction, with no ranking, no sampling, and no move of live traffic. Profile B (two active paths with sampling) is removed. It needs an off-air chain step, an on and off command, and a shared slot rule, and each one failed review. The splice clock blinds its soft signals, because the clock restores exact spacing, thus a slow path gives no signal and the profile has no working trigger. Donar also reports high latency at `n1ST = 1`, thus no evidence supports its cost. Profile D (Donar ranked, 6 of 12) needs the same machinery and a change of `REL-014`, and it stays out. The cost is the clock of profile C. Against profile A, the first copy pays a mean of 40 ms in place of 13.3 ms, and the worst phase pays 120 ms in place of 40 ms. The known sum rises from 473 ms to 500 ms at the mean, and from 500 ms to 580 ms at the worst phase. A party holds 12 circuits in place of 4, and 92 % in place of 57 % of calls hold a hostile hop 2 in one hour at a 10 % share. If neither profile passes Stage 2, ranking is new design work and not a tuning step.

| Profile | Paths for each direction `P` | Frames placed | Period of one receive half | Circuits for each party | Evidence |
| --- | --- | --- | --- | --- | --- |
| A: control | 2, 1 on each pin | Each frame on both | 40 ms | 4 | TorFone: 23 % to 47 % |
| C: candidate | 6, 3 on each pin | Each frame on 2 of 6 by round robin, and the previous frame in the next cell, on another path | 120 ms | 12 | Donar shape, with no rank. No exact precedent |

Stage 1 also runs `P = 4`, with a period of 80 ms: first copy 26.7 ms, worst phase 80 ms, 16 draws, 81.5 % (derived). No source reports that value. Donar reports good results at 6 and 8 active links.

**Each pin carries 25 cells/s.** An honest client sends one cell for each tick on each pin, and it skips a tick only when a socket is full. The receiver picks 3 relays for each pin, or 1 in profile A, thus the splice clocks give each link 25 cells/s toward the client. A relay that fails `NET-032` on one pin can force an uneven split of the send halves. A path that does not join leaves its ticks empty on that pin. The access link then shows a lower rate.

**No probe and no monitor.** Each path carries frames, thus no extra cell exists. A late path stays in rotation, and the first copy wins. No signal reads the delay of one path (O9).

**Failure.** The only signals are `CircuitDestroy`, a closed link, and one cell that fails each index of the window. A call counts as dropped after 25 frames with no audio, which is 1 s, as in Donar. A handover has its own measure below.

1. The receiver owns each path, and it alone starts a replacement. The sender sees the end, and it waits for `PATH_NEW`.
2. A receiver that ends a path on a failed check marks it dead at once. It sends `DESTROY` and starts a replacement after a draw from the `SPLICE_HOLD` distribution. Thus a forged cell does not show on the link at once.
3. A receiver spends at most `CALL_REPLACE_MAX` of 4 replacements in each hour of a call. An age rotation does not count. A sender refuses a `PATH_NEW` above that count. Donar reports 7 % to 16 % of links failed after 1 h, which is up to 1.9 of 12 paths (derived).
4. At a budget of zero, a receiver stops the replacements and warns the user. With no live path in one direction, the call ends.
5. Repeated forced replacement is a link fault (`REL-016`).

**This is not a full defense.** Herrmann and Grothoff, the source of `REL-014`, show that a client that follows performance lets an adversary steer it. A relay on a path ends that path with one bad cell (Part 3 §3.4.5), thus a hostile relay can end each path that does not suit it, up to the budget. A media circuit carries no `LOOP` cell, thus the measure of §3.11.1 does not apply, and `REL-016` names no relay. §4.7 gives the draws at a used budget. Stage 5 measures this.

**A handover.** `WIR-525` ends each circuit of a link that drops with a frame in flight, and `WIR-543` ends a parked circuit at its first backward cell. A move from Wi-Fi to cellular thus ends each half of that party. The far halves stay for `SPLICE_HOLD`. The party opens two links, builds new halves, and sends `SPLICE_OPEN` with each token. The far party rebuilds nothing, and each index continues. The floor is 0.81 s for a build and 0.42 s for the join, before TLS, the session open, and the proof of work, thus 1.23 s or more (derived). The median hold is 5.08 s (derived). A loss that outlasts the hold ends that path.

## 8. Security changes

### 8.1 The changes

Each row is one change. The trade rows of Part 2 §2.4 and the residual rows of Part 15 §15.3 must carry them.

| # | Change | Rule or goal touched | Residual |
| --- | --- | --- | --- |
| 1 | No per-hop delay | `NET-338`, `NET-039`, Part 3 §3.0 | Under the trilemma a call has no strong anonymity against A4. |
| 2 | A fixed clock in place of Poisson pacing | `NET-035`, `NET-036`, `NET-291`, `NET-038` | The splice clock keeps `NET-036` in its substance: the schedule toward the client does not follow an arrival. It is a fixed clock and not the Poisson clock. A client uplink has no relay clock before the splice. |
| 3 | No queue | `THR-003`, `NET-298`, U6 | The splice table is memory only. The callee must be online. A relay under an order can log joins for the future (A5). |
| 4 | Call start and end exposed | G8, `THR-002`, A1, A4 | The two streams start and end near one time. A simulation traced 98.3 % of calls from these times alone with no chaff. It assumed a global observer at 1 s, one month, no noise, and a carrier trace of 2010, and competing authors wrote it. It shows the direction and not a rate for UMBRA. Cover must match 28 KB/s and not the 8 KB/s of Herd. That costs 2.42 GB each day for each direction (derived), against a U4 budget of 100 MB each month. **Always-on cover is not possible on a phone.** |
| 5 | Correlation across paths | G6, G7 | Separate keys remove matching bytes. Random phases remove one matching clock. The paths of a call still start and end together. No source measured this. |
| 6 | A1 at both ends | `THR-002`, G8 | **This row is the largest loss.** Part 2 defines A1 as "one or more network links", and a national carrier can hold the links of both parties. A1 can confirm the pair from the times of the call, and the splice clock does not change that. The rule fails as written, and it must scope out calls. |
| 7 | Provisional network | `THR-007`, `NET-340`, `NET-343`, assumption 3 of §2.6 | One operator runs each relay of each path and links the two parties at a token. G6 to G8 already fail against that operator for messages, because it holds the two ends of a queue. A call adds the time and the length of each call, in real time. |
| 8 | Fingerprint of a call | `NET-080`, `NET-061`, §3.8.1 | Two TLS links at 25 records/s of one size mark a call, for any observer of the access link. The clock of the relay hides the skew of the far sender from the receiver link. The local uplink still shows the skew of its own device. |
| 9 | A shared pin | `THR-004`, `THR-006`, G8 | §4.5. One relay holds the two addresses. Launch network: each call. |
| 10 | Forced failure | `REL-014`, §3.11.1 | §7. A hostile relay can end each path that does not suit it, up to the budget. `NET-134` requires a new row in §3.11.1. |
| 11 | Timing patterns | §3.11.1, `NET-134`, G8 | See the table below. |
| 12 | New active position at the splice | §3.11.1 | The splice relay can drop, delay, repeat, or alter a cell. §6 gives each result. It keeps the availability attack, which Part 2 §2.5 accepts. |
| 13 | Free bandwidth | Part 13 | §4.8. The price and the caps bound one address. A party with many addresses still takes capacity. |
| 14 | Platform path | `THR-013`, A7, §14.6.6 | The microphone and the speaker are platform interfaces. Do not register the call with a platform call log or a telecom service. |
| 15 | The kill signal | §3.11.1, `NET-134` | One hostile relay on one half ends that half. The hold delays the far end by a random time of at least 3 s. It blurs the signal and does not remove it. A rebuild shows as `B1` cells (`NET-150`) on one access link. |
| 16 | Link to the queue path | G7, §3.11.1 | §5.3 keeps the queue relays of the conversation out of the named relays, as far as each party knows them. §5.1 separates the builds and the end. The two views of the queue relays can differ during a rotation. The offer still precedes a build at the ingress by a few seconds. |
| 17 | Link shapes | Part 10 §10.6.1, §3.9.1 | The link to the second pin carries media alone, which is the form that Tor proposal 291 attacks from the 5-tuples and the timestamps. At a low call count a media step stands out on a relay link. Stage 5 sets a minimum count. |
| 18 | G5 inside a call | G5 | §5.4. A short compromise opens the rest of that call. |
| 19 | Cross-contact linking | G9 | The voice identifies a user to each contact. Over a long call, the frame count against the relay clock can show a stable device skew. |
| 20 | The lock waits for a call | `IMP-119`, `IMP-127`, A6 | The store stays open while a call runs, and a seized phone in a call is unlocked. |
| 21 | Contact-named relays | G7, `THR-006`, O5 | A contact names the relay at the end of each send half of the victim. That relay sees the hop 2 of the victim. With a hostile hop 2 share of 10 %, 19 % of profile A calls and 47 % of profile C calls show a hostile relay the hop 2 next to a pin of the victim (derived). The caller also reads which paths join. That shows a conflict of the relay with both pins, over 60 to 120 days, for a hostile contact and for an honest one. A `PATH_NEW` adds up to 4 relays each hour. |

**Timing patterns after the splice clock.** A pattern here is a delay or a skip of cells that a party writes on one side and reads on the other side.

| Writer | Reader | Result |
| --- | --- | --- |
| Hostile contact, skips its ticks | Hop 1 of the victim, or A1 on the victim link | **Closed** with an honest splice relay. `PADDING` fills each skip |
| Hostile contact, through a relay that it names | Any reader on the victim side | **Closed.** That relay carries traffic toward the contact alone |
| Hostile hop before the splice, delays cells | Hop 2 or hop 1 of the far half, or A1 on the far link | **Closed** with an honest splice relay, for any delay below the end of the path |
| Hostile hop 1 or hop 2 | Hostile splice relay, or a later hop of the same half | **Open.** The clock sits after that part of the path. That pair links one half to its address only |
| Hostile hop on a send half | Hostile contact | **Open.** The contact reads `MEDIA` against `PADDING` at each tick. A hostile pin of the victim plus a hostile contact confirm the victim link |
| Hostile contact | Any reader, through a hostile splice relay on a path that the victim picked | **Open.** A hostile relay does not run the clock. The contact cannot select that relay. At a 10 % share, 19 % of profile A calls and 47 % of profile C calls hold one (derived) |
| Hostile contact, one forged `MEDIA` cell | Hop 1 of the victim, or A1 | **Reduced.** The victim marks the path dead and acts after a random delay of at least 3 s (§7). Each mark costs a replacement |
| Hostile contact, `PATH_NEW` | Hop 1 of the victim, or A1 | **Reduced.** The same delay, up to 4 marks in each hour |
| Hostile contact | A1 or a compelled pin at a candidate link | **Open.** The contact knows the answer time and the end time. It can match them to a stream at a candidate link, with repeated calls. No clock changes this |
| Path end | Each far hop | **Reduced.** Row 15 |

Thus a re-clock at the splice closes the delay watermark across the splice for a hostile hop before it. It does not close a watermark on the same half, a watermark that a contact reads, or any event that the clock cannot hide: start, end, and path end.

### 8.2 Opt-in and the stated guarantee

Calls are off by default on each device. Each user turns them on with one explicit action. Onboarding does not ask (`NTF-011`, U1). The first call to each contact shows the statement below.

**The proposed statement.**

> A call hides what you say, and your contact does not get your address from it. Your own entry relay sees your address, as it does for messages. It does not see who you call, unless your contact uses the same entry relay. A call does not hide that you are in a call. A party that watches both of your connections can see that you two talk at the same time. A contact who also watches your connection can match the time of a call to you.

**Which modes may call.**

| Setting | Place a call | Take a call |
| --- | --- | --- |
| Fast or Balanced conversation | Yes | Yes |
| Private conversation | **No** | **No** |
| Direct or Instant notifications | Yes | Rings |
| Periodic, Private, or Off notifications | Yes, while the client is open | Missed call only |
| Client locked | No | Alert, then missed call in most cases |
| Provisional network | **No, except a test build** | **No, except a test build** |

A user who selects Private mode for a conversation asks for a delay of 2.1 s against correlation. A call removes that delay. Thus the two do not mix.

The provisional row is a recommendation, and the owner decides it. Under this row the launch network ships no calls. The alternative is to allow calls with the statement and `NET-343` on the screen, because row 7 adds time and length and no new link in kind.

## 9. Capacity

### 9.1 Relay load

The load is the same for each value of `P`, because one party always sends 50 cells/s.

| Step | Arithmetic | Result (derived) |
| --- | --- | --- |
| Cell cost | Part 6 §6.9 | 560 B |
| Cells of one party, each way | 2 × 25 | 50 cells/s |
| Cells of one call | 2 × 50 | 100 cells/s |
| Relay visits of one cell | G, M, S, M, G | 5 |
| Visits of one call | 100 × 5 | 500 visits/s |
| Relay receive load of one call | 500 × 560 × 8 | 2.24 Mbit/s, and the same to send |
| Earlier estimate | 3 × 500 / 2.24 | 670 calls |

The earlier estimate assumes an even spread, no other traffic, and full links. The launch network has no even spread. It runs the classes of `deploy/ansible/inventory.example.yml`.

| Position | Share | Load of one call | Capacity | Ceiling, full load | Ceiling, 50 % load |
| --- | --- | --- | --- | --- | --- |
| Two ingress relays | 2/5 | 0.896 Mbit/s | 2 × 250 Mbit/s | 558 | 279 |
| **One layer 2 relay** | **2/5** | **0.896 Mbit/s** | **250 Mbit/s** | **279** | **139** |
| Three layer 3 relays | 1/5 | 0.448 Mbit/s | 3 × 250 Mbit/s | 1 674 | 837 |

- The ceiling of the launch network is **279 calls at full load**, and about **139 calls at 50 % load**. The 50 % figure is proposed. A constant-rate flow needs headroom, and no source gives the value.
- If the middle relay took the whole server `east-2` the limit is 500 / 1.045 = 478 calls, with `exit-3` at an even share.
- With 52 B of TCP/IP headers for each cell, the ceilings are 255 and 127 calls.
- The signer holds no relay, thus it adds no capacity. Each server has 4 GB of memory.
- These ceilings assume no message traffic. Calls and messages share each link.
- The splice clock adds no cell in steady state, because `PADDING` fills a tick that a `MEDIA` cell left empty. It adds one timer for each receive half.

| Item | Value |
| --- | --- |
| **Measured `B0` cells per second per core** | **About 228 000 forward over 64 links, on one hop (Linux container on a Ryzen 5900X, loopback, median of 3). Windows gives about 119 000. No launch server gives a value yet.** |
| Cell demand at the middle relay | 200 cells/s for each call, 55 800 cells/s at 279 calls, 27 800 cells/s at 139 calls (derived) |
| Cell demand at the splice relay | 100 cells/s for each call over 3 relays. Each cell costs 2 layers and 2 HKDF updates (`NET-205`, `NET-206`) |
| CPU ceiling at the middle relay | About 1 140 calls for each core that serves cells (228 000 / 200, derived), above the link ceiling. This value holds for the bench host only |

The current relay serves cells on one task, thus one core for each relay is the honest count until §4.8 changes that.

| Build load | Value (derived) |
| --- | --- |
| Monitoring | 0 |
| Call start, profile A | 8 halves, 24 key agreements |
| Call start, profile C | 24 halves, 72 key agreements |
| Rotation at 8 192 cells | 22 key agreements each second at 279 calls, over all relays |
| Rotation at the recommended bound | Near zero below 4 h |

### 9.2 Phone

| Item | Arithmetic | Result | Class |
| --- | --- | --- | --- |
| Wire rate, each way | 2 × 25 × 560 × 8 | 224 kbit/s | Derived |
| Bytes in 1 h, each way | 224 kbit/s × 3 600 s | 100.8 MB | Derived |
| Bytes in 1 h, both ways | | 201.6 MB | Derived |
| The same with TCP/IP headers, 612 B a cell | | 245 kbit/s, 220 MB | Derived |
| Against U4, 100 MB each month | 100 / 100.8 | One 30-minute call equals the monthly idle budget | Derived |
| One hour each day for 30 days | | About 6 GB | Derived |
| Overhead against the voice | 224 / 32 | 7 times | Derived |
| Radio draw | 9.1 mWh / 18 s | 1.82 W | Derived, unmeasured |
| Radio cost in 1 h | 1.82 Wh / 15.4 Wh | 11.8 % of the U5 battery | Derived, lower bound |
| CPU cost | 100 cells/s, 3 hop layers each, 100 AEAD operations, Opus, audio | Not verified | Stage 3 |

The radio row uses the tail model of Part 3 §3.12. Active transfer costs more than the tail, thus the row is a lower bound. Stage 3 needs a power monitor, as `NET-101` states for the other radio figures.

## 10. Changes that a real version needs

These are changes for a later commit. Each one is a minor version under `AGENTS.md`.

| Part | Rule or section | Change |
| --- | --- | --- |
| 1 | §1.7, the parameter table | New parameters and new quoting sections |
| 2 | §2.4 | New goal U11 for latency, with a row in §2.4.1 (`THR-011`) |
| 2 | Trade table (`THR-010`) | One row for each row of §8.1 |
| 2 | `THR-002`, §2.2 A1, §2.3 G5 to G8 | Scope out a call, or state the limit in a note |
| 2 | §2.5 | Remove the real-time media omission. Add calls to the summary of §2.7 |
| 3 | §3.1, §3.11 | The splice function. New learned items for each position |
| 3 | §3.11.1 (`NET-134`) | New rows for rows 10, 11, 12, and 15 of §8.1 |
| 3 | `NET-028`, `NET-029`, `NET-337`, `NET-338`, `NET-039` | Media as a fourth `delay_class` with no delay. The last relay enforces the split |
| 3 | `NET-035`, `NET-036`, `NET-038`, `NET-291` | The fixed clock of the splice relay as a new case. `NET-360` does not cover it |
| 3 | `NET-321`, `NET-322`, §3.4.3 table | `MEDIA_CIRCUIT_MAX_CELLS`, `SPLICE_HOLD`, and a media value of `CIRCUIT_RETIRE_WAIT` |
| 3 | `NET-080`, §3.9, §3.9.1 | Scope to the three message modes |
| 3 | `NET-074`, `NET-290` | Media on an interactive link, and the media-first rule on a relay link |
| 3 | §3.6.1 | A measure for a circuit with no `LOOP` cell |
| 3 | §3.8 | Keep the rejection of WebRTC. State that a call uses TCP |
| 3 | §3.12, `NET-137` | Add the call budget. Give the LAMP-style selection a rule, or remove the sentence |
| 5 | §5.4.9 | `delay_class` in the prologue, with new vectors (`CRY-116`) |
| 5 | §5.1, §5.11 (`CRY-031`) | The labels of §5.4 |
| 6 | `WIR-139` | The relay-link wrap of §4.8 |
| 6 | `WIR-135`, §6.4, §6.6, §6.8 | The `MEDIA` command, the commands of §4.4, new kinds after `0x39`, and new vectors. `NET-210` at the new bound |
| 7 | §7.5.3, §7.5.4 | The class Call signal, and the owner device rule |
| 8 | §8.3 | The ring result of each mode. The blob stays as it is |
| 10 | §10.5.3, §10.6.1, §10.6.2 | A `roles` bit, one link to each pin during a call, and a replacement budget for a call |
| 13 | §13.2, §13.8 | A proof of work on `SPLICE_OPEN` at each effort, and the caps of §4.8 |
| 14 | `IMP-119`, `IMP-127` | A call holds the lock |
| 14 | §14.6.1, §14.6.6, §14.9 | The FFI surface, the microphone path, no call log, and call states |
| 15 | §15.2.2, §15.3 | Calls under the A4 section, and one row for each row of §8.1 |

After a change to a rule, run `python scripts/reqindex.py`.

### 10.1 Dependency register

The relay needs no new crate. It reads no media.

The Android library has 45 R3 crates against a cap of 50 (Part 14 §14.2.3). `IMP-007` has no row for a media codec. A new row and a named register are needed (`IMP-002`).

| Option | R3 cost | Cost and risk |
| --- | --- | --- |
| **Platform codec through the Kotlin side (recommended first)** | 0 crates | `minSdk` is 29. Opus encoder support at that level is not verified. Devices can differ, and the platform (A7) sees the audio. It sees the microphone in each case |
| `libopus` by a Rust binding | About 1 to 2 crates (estimate) | A C library in the Android build, and `unsafe` code, which §14.3 forbids outside `umbra-simd`. The license allow list holds `BSD-3-Clause`. The license of the binding is not verified |
| Opus in Rust | Not verified | No verified source names a crate of production quality |

No WebRTC stack enters the build, because Part 3 §3.8 rejects it. The AEAD and the KDF are in R1 already, thus R1 and R2 do not change.

## 11. Staged plan

The numbers below are proposed, except where a source is named. **The call rate has one gate before phones, at the end of Stage 2.** Stage 1 records the call rate and passes on no call-rate value.

**Test bed T.** One manifest of a test network holds 4 ingress relays, 8 layer 2 relays, and 8 layer 3 relays, over at least 3 autonomous systems, 3 blocs, and 3 labeled operators, so that the chains meet §3.4.6. The paths of profile C cannot be fully disjoint on T, and the Donar statement on uncorrelated failure does not transfer. The launch relays give a floor only.

**Sample.** Each configuration takes 200 calls at each length. That gives ±4.8 % at 86 %, at 95 % confidence (derived).

| Stage | Work | Exit criterion |
| --- | --- | --- |
| 0. Bench | Measure `X` on a mid-tier Android phone. Measure `B0` cells/s/core. Measure propagation on T and on the launch relays (`NET-137`) | `X` is known. On T, chain propagation at p50 and at p99 stays below `L_net` less the splice clock of profile A. §9 holds a value measured on a launch relay |
| 1. Build and measure | A Rust harness with scripted audio, no phone, on T. Profiles A and C, and `P = 4`. The splice function and clock, the frame layer, and the separate task of §4.8 | Each profile completes its sample. The report holds call rate, drop rate, and splice-clock cost. **No pass value on the call rate** |
| 2. Gate | Tune each profile, at most two rounds | One profile reaches `L_net` in at least 86 % of calls, with drops at or below 3 % of the sample, which a true 2 % rate (Donar) passes 89 % of the time (derived) |
| 3. Phones | Two real phones on LTE and Wi-Fi, in the passing profile | Mouth-to-ear p99 at or below 400 ms in at least 86 % of calls. At least 90 % of handovers keep the call, with a gap at or below 3 s at p95. A power monitor reading for one hour. Bytes for one hour within 10 % of §9.2 |
| 4. Relay load | A load run on T at 100 calls with live message traffic | Message delivery stays inside U2. Call p99 stays within 20 ms of Stage 3. No relay link wrap ends a path. A stall below the `GAP_MAX` time ends no path |
| 5. Security | The tests below. A `/crypto-review` of §4.6, §5.4, §6, and the media bound. A review by a party outside the project | Each test meets its threshold. No review holds an open blocker. Each sentence of the statement of §8.2 matches a test result |
| 6. Opt-in release | Spec changes of §10, the opt-in screens, and a non-provisional directory, unless the owner decides otherwise | All earlier exits hold on the production relay set |

**The Stage 5 tests.** Each runs at 50 concurrent calls or more on T, which is also the minimum call count for release.

| Test | Threshold |
| --- | --- |
| A pattern from a contact, read at the victim link, honest splice relay | AUC at or below 0.55 |
| A pattern from a hop before the splice, read at the far link, honest splice relay | AUC at or below 0.55 |
| One passive relay with no shared pin picks the partner of a stream | At or below 1 % above chance |
| A forged frame, read at the victim link | Measure and report the bits for each call |
| Forced failure at a 10 % relay share, full budget | Measure and report the hostile-draw rate |

**The bands between an exit and a kill.** The owner decides each one: Stage 2 from 70 % to 86 % after two tuning rounds, Stage 3 from 60 % to 86 %, and handovers that keep the call from 50 % to 90 %.

**Kill criteria.** Any one of these results ends this work, or it sends the design back to research.

1. On T, chain propagation leaves no room for `L_net` at p99, and the options of §3 fail review.
2. After Stage 2, no profile reaches 70 % of calls under `L_net`. Donar reached at least 87 % on Tor, thus a low result means that the design and not the tuning has failed.
3. In Stage 3, the passing profile reaches below 60 % of calls under 400 ms. No source measures this case.
4. Below 50 % of handovers keep the call, and no change short of QUIC repairs it.
5. One hour of call uses more than 30 % of a 15.4 Wh battery.
6. At 100 calls, the message path leaves U2, and the media-first rule does not repair it.
7. The measured cell rate cannot carry 100 calls on T at 50 % load.
8. One passive relay with no shared pin picks the partner above 1 % over chance in a test of Stage 5, and no change repairs it.
9. The target needs a change to `NET-116`, `NET-131`, or `NET-132`. That change is a new design, and item 7 rejects it for now.

## 12. Open questions

### 12.1 Decisions

1. Do calls ship on a provisional network (§8.2)?
2. Is the exception to `THR-002` for A1 acceptable at all? Row 6 of §8.1 is the core of the mode.
3. Can two clients detect a shared pin? A salted hash in the offer shows the pin to the contact, because the relay list is public and short. A private set intersection needs extra rounds on a slow path. If a client detects a shared pin, the only answer is to use the other pin alone, and then one TCP link carries both copies.
4. Must hop 3 run the key update on a media circuit? The frame layer protects the payload, and the update costs 2 HKDF calls for each cell at the splice relay.
5. Must a call run a KEM step in control items for G5 inside a call (O8)?
6. Can a client use one hop 2 for its send halves on one pin, to cut row 21 to 19 % in profile C? This joins the failure of those halves.

### 12.2 What no source measured

- Any voice call on a mobile access link over an anonymity path. Donar ran both ends on one machine, and its laptop test had no latency data.
- Any voice call under Tor congestion control or Conflux. Donar used Tor 0.4.4 in January 2021, and no replication exists.
- A constant-rate circuit, or a relay clock in a voice path. Donar did not pace its cells.
- A round robin over 6 paths with no rank. Donar ranked its links.
- The rate at which a splice queue must drop cells on a real network.
- Paths of one call on relays that a small network shares. Donar reports that failures across Tor links do not seem to be correlated, on a 6 000-relay network.
- The start and end attack on a network of this size, the correlation of the paths of one call, and a delay watermark against this design.
- The battery cost of a call, and Android capture, encode, decode, and playout delay.
- The research did not verify any claim on Opus FEC, on CBR and VBR leakage, on RFC 9221, on MASQUE, on Conflux, or on Tor congestion control. This document uses none of them as evidence.

## 13. Sources

Only 25 of 124 extracted research claims were verified. Each statement outside the rows below is not verified.

| Key | Source | Status |
| --- | --- | --- |
| Donar | Bromberg et al., "Donar: Anonymous VoIP over Tor", NSDI 2022, https://www.usenix.org/system/files/nsdi22-paper-bromberg.pdf | Verified. The author of this document also read §2 to §6 and Appendix A of the paper for D1, D4, and §7. No replication exists |
| G.114 | ITU-T G.114, 150 ms and 400 ms, as Donar §2 quotes it | Cited through Donar |
| Herd | Le Blond et al., "Herd", SIGCOMM 2015, https://conferences.sigcomm.org/sigcomm/2015/pdf/papers/p639.pdf | Verified. The 98.3 % is a simulation |
| Yodel | Lazar et al., "Yodel", SOSP 2019, https://pdos.csail.mit.edu/papers/yodel:sosp19.pdf | Verified |
| Tor 2018 | Tor side-channel report, https://research.torproject.org/techreports/side-channel-analysis-2018-11-27.pdf | Verified. It is not a proof |
| TorFone | As Donar §6 reproduces and measures it | Cited through Donar |
| Herrmann and Grothoff | As Part 10 §10.6.2 cites it | Cited through the spec |
| Spec and code | `spec/`, `crates/umbra-relay/src/server.rs`, `crates/umbra-transport/src/native.rs`, `deploy/ansible/` at 0.46.3 | Read directly |
