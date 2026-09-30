# UMBRA Protocol Specification — Part 10: Relay Directory, Measurement, and Selection

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 10.1 The finding that determines this design

**Each deployed bandwidth-reputation system in an anonymity network has broken,
and the break always has the same shape.** Continuous relay weights in
proportion to the performance make a false statement a profitable, cheap, and
low-risk investment.

| System | Measured inflation achieved |
| --- | --- |
| Tor TorFlow | **177×** — a relay dropped its real throughput from 22.5 MiB/s to 0.2 MiB/s and gained 177× the consensus weight |
| EigenSpeed (PCA aggregation) | up to **420×**, or the ejection of honest relays |
| Tor sbws (deployed since 2018) | **28.03×** under the TorMult and MirageFlow co-residency cluster attack (NDSS 2024) |

TorMult needs **10 servers and 109 relays** to reach half of the traffic of Tor.
TorMult also defeats the defenses that hide the measurer. A classifier
identifies a measurement flow at F1 > 99 % from the first five packets.

Two designs have proven bounds. PeerFlow reaches 4.52× and needs measurement
periods of one week. FlashFlow reaches 1.33× and needs 30 s of saturating echo
traffic. **No party has deployed one of the two designs.** The live consensus of
Tor on 2026-08-23 showed that only **5 of 9** directory authorities emitted a
bandwidth value.

Performance-adaptive peer selection is also a deanonymization oracle. Herrmann
and Grothoff (PETS 2011) deanonymized an I2P Eepsite with 70 PlanetLab nodes.
Those nodes were less than 3.6 % of the network, at 64 kb/s each. The method was
a selective DoS against the "fast tier" of the victim, and then observation of
that tier as it refilled with attacker nodes.

The owner of UMBRA needs high-quality relays to have priority. This part gives
that property, and it does **not** build the mechanism that has failed at each
deployment.

## 10.2 Discrete capacity classes, not continuous weights

This decision has the largest effect in this part.

```
C0 =  1 Mbit/s      C1 =  4 Mbit/s      C2 = 16 Mbit/s      C3 = 64 Mbit/s
```

- **The selection is uniform in a class.** The directory sizes the class
  populations for each layer, thus the expected load matches the class capacity.
- A relay declares its own class in `capacity_class`, and that declaration is
  the upper bound. A measurement confirms the class, and the directory writes
  the confirmed class in the `class` field of the `RelayEntry` of §10.5.3. A
  client reads `class` and it does not read `capacity_class`. **[REL-001]** A
  class **MAY increase by a maximum of one step in each 7-day epoch**.
- **The demotion.** **[REL-095]** If a class test verifies below the `class`
  of the entry, the directory MUST set `class` to the verified class.
  The change applies at the next consensus. **[REL-096]** A directory authority
  MUST NOT apply a staging delay or a step limit to a demotion.
- **The cadence.** **[REL-097]** A directory authority SHOULD measure each
  relay above C0 one time in each `MEASURE_INTERVAL`. **[REL-098]** If a relay
  has no verifying report inside `MEASURE_STALE`, a directory authority MUST
  set its `class` to C0. The directory authority measures each of the two
  periods from the slot of the last verifying report. §10.11 gives the two
  values.

This rule limits the payoff of one bandwidth-inflation step to **4×**, which is
one class step in one 7-day epoch. The ladder has three steps, thus the payoff
over the full ladder is **64×** in three epochs or more. The published payoffs
were 177×, 420×, and 28×, and each one is a cumulative figure. The rule needs
**no cryptography**. It needs the measurement fleet of §10.3, and §15.6.1
prices that fleet. A demotion needs no delay, because a false claim is what the
delay defends against, and a lower class is not a claim.

Uniform selection in a class also moves the Gini coefficient of the relay
selection to the flat end of the Snader–Borisov family. That end of the trade
favors anonymity.

## 10.3 Measurement: saturating echo, scheduled by co-residency cluster

UMBRA adopts the `MEAS_ECHO` primitive of FlashFlow, over the 512-byte `B0` cell
of UMBRA:

```
measurer opens k sockets
sends echo cells for the relay to decrypt and re-emit
for t = 30 s
with aggregate measurer capacity >= 2.25x the class ceiling being claimed
→ bound: <= 1.33x inflation
```

**[REL-002]** A relay MUST decrypt each `MEAS_ECHO` cell that a measurer sends to it. **[REL-003]** That
relay MUST then re-emit that cell to the measurer.

**The wire value is `0x07`**, and Part 6 §6.3 holds the closed cell-command
table that carries it. `MEAS_ECHO` is a cell command and it is not a queue
command, thus Part 6 §6.4 gives it no entry. **[REL-040]** A measurer MUST send a
`MEAS_ECHO` cell in bucket `B0`. **[REL-041]** A relay MUST reject a `MEAS_ECHO`
cell in a different bucket, because a larger bucket turns the echo into an
amplifier.

**One rule differs from the FlashFlow specification, and it is important.**
Measure a group of relays **in the same 30-second slot** if those relays share
one of these items:

- an ASN
- an IPv4 /24, or an IPv6 /48
- a declared family certificate
- a detected co-residency fingerprint

This rule is the only defense against the *n × N* cluster inflation of TorMult.
Its cost is measurer capacity. §10.6 lets one ASN hold 10 % of the chain
population of a bloc, and §10.5.3 works with about 3 000 relays. A cluster of
300 relays at class C2 needs 300 × 36 Mbit/s, which is 10.8 Gbit/s, in one
30-second slot. No cheap measurer fleet holds that burst, thus a large cluster
is measured in samples.

- **[REL-099]** If a cluster holds `CLUSTER_FULL` relays or fewer, the directory
  MUST measure the full cluster in one slot.
- **[REL-100]** If a cluster holds more than `CLUSTER_FULL` relays, the
  directory MUST select `CLUSTER_SAMPLE` relays of it for each slot. The
  selection uses the VRF of §10.4.1. **[REL-101]** The directory MUST measure
  each relay of such a cluster inside `ceil(n / CLUSTER_SAMPLE)` slots. The
  value `n` is the cluster size. **[REL-102]** The directory MUST show the
  selection of a slot only after the epoch closes.

A sampled cluster keeps a residual. A relay outside the sample of a slot can
lend capacity to a relay inside it. The VRF selection is not predictable, thus
the cluster does not know which relays to feed. Part 15 §15.3 records that
residual.

A class test proves a **threshold** only, which is the question "does this relay
hold 16 Mbit/s?". A class test does not estimate a value. Thus the measurer
budget is much smaller than the FlashFlow budget. A class-C2 test needs 36
Mbit/s of measurer capacity for 30 seconds, and not a full-rate speed test.

The class test and the honesty probe are two different measurements. The
authorized session of §10.3.1 governs a class test, and the relay under test
knows the 30-second window. The FlashFlow echo is a cooperative protocol, and
that knowledge does not weaken its bound. The honesty probe of §10.4.1 rides
on a loop cell, and rules `REL-005` and `REL-006` hide which cells score. A
relay cannot serve the probe well and serve the other traffic badly, because
it cannot tell the two apart.

### 10.3.1 A measurement session needs authorization

`MEAS_ECHO` makes a relay decrypt and re-emit a cell. Without an authorization
that primitive is a reflector that each party reaches, and it also answers the
question "is this address an UMBRA relay?".

A measurer opens a session with a `MEAS_OPEN` cell of Part 6 §6.3, and that cell
carries the certificate below.

```
MeasurerCert {
    version       u8        // 0x01
    measurer_id   [16]u8
    mldsa_pk      [1952]u8  // the short-lived key of §10.5.1
    not_after     u64       // the consensus epoch after which it is void
    sig_count     u8        // 2 to 7
    sigs          [sig_count]AuthoritySig   // ML-DSA-65, label
                                            // "umbra/v1/measurer-cert"
}
```

`AuthoritySig` is the structure of §10.5.2. The certificate is **8 598 bytes**
at 2 signatures and **25 148 bytes** at 7. `REL-065` puts a 3 309-byte
signature beside it, thus a `MEAS_OPEN` cell uses bucket `B3`. Part 5 §5.11
holds the label. Each signature covers this preimage:

```
"umbra/v1/measurer-cert" || version || measurer_id || mldsa_pk || not_after
```

- **[REL-064]** A measurer MUST open a measurement session with a `MEAS_OPEN`
  cell. **[REL-065]** A measurer MUST carry a `MeasurerCert` and a signature
  over the circuit identifier in that cell.
- **[REL-066]** A relay MUST verify each signature of the certificate against
  the key set of the current `DirectoryRoot`. **[REL-103]** A relay MUST count
  2 or more valid signatures under different `authority_index` values before
  it accepts a `MeasurerCert`. **[REL-067]** A relay MUST reject a certificate
  whose `not_after` is below the current consensus epoch.
- **[REL-104]** A relay MUST reject a `MeasurerCert` whose `measurer_id` the
  `revoked` list of the current `DirectoryRoot` names. **[REL-105]** If a
  measurer key is lost or compromised, a directory authority MUST put its
  `measurer_id` in `revoked`. The entry appears at the next consensus.
  **[REL-106]** A directory authority MUST keep that entry in `revoked` until
  the `not_after` of the certificate passes. §10.5.2 gives the list, and
  `MEASURER_REVOKE_MAX` bounds it.
- **[REL-068]** A relay MUST reject a `MEAS_ECHO` cell that arrives outside an
  open measurement session. **[REL-069]** A relay MUST rate-limit a rejected
  measurement attempt, and it MUST NOT answer above that rate.
- **[REL-070]** A directory authority MUST issue a `MeasurerCert` with a
  lifetime of `MEASURER_CERT_TTL` or less. §10.11 gives that value.

> *Cause.* An earlier draft made a relay decrypt and re-emit each `MEAS_ECHO`
> cell that "a measurer" sent, and no rule bound the cell to the measurer key
> that §10.5.1 already issues. §10.11 sets a class-C2 test at 36 Mbit/s for 30
> seconds, thus an unauthorized party made a relay spend that work at will.
> `REL-041` bounds the amplification by the bucket, and it does not bound the
> volume. The rule above puts the existing measurer key on the path.
>
> A second draft gave the certificate one authority signature and no
> revocation. One authority then minted a measurer alone, and a leaked measurer
> key stayed valid for `MEASURER_CERT_TTL`, which is 7 days. Both facts gave
> back the reflector that this section removes. Two signatures make a
> certificate a decision of two authorities. The `revoked` list closes the
> window of a leak at the next consensus.

## 10.4 The primary reputation signal is negative and behavioral

A party can buy speed. A party cannot buy honesty. Thus the primary reputation
signal of UMBRA is **negative link reputation in the Miranda style**. The loop
cover traffic that Part 3 §3.6.1 makes mandatory drives that signal.

```
1. Every relay issues a signed receipt for each accepted cell batch.
2. A failed client loop triggers an isolation query along the chain.
3. A relay that acknowledged receipt but dropped is EXPELLED.
4. An unresolvable A-B fault removes the LINK A-B, not either node.
5. A dense-subgraph search runs over the link-fault graph each epoch.
```

**An honest relay loses O(1) links at an incident. An attacker loses Θ(n)
links** and then cannot occupy a chain. The evaluation of Miranda used n=100
with 33 malicious nodes. That evaluation found each detectable malicious mix
after the removal of 8 % of the semi-honest links.

This signal measures honesty and not speed. A party cannot buy it with
bandwidth. It also uses the traffic that UMBRA generates for the cover function.

The loop-failure input comes from the foreground only. A client makes a cover
cell in the foreground only (Part 3 §3.6.2), thus a client gives about 72 loop
samples each day. **[REL-004]** The directory MUST size the detection window for that rate.

### 10.4.2 The two objects that carry that signal

The five steps above name a receipt and an isolation query. This section gives
each one a structure, a rate, and a cost.

**The link receipt is between two adjacent relays.** A client never holds one.

```
LinkReceipt {
    version      u8        // 0x01
    from_relay   [32]u8    // the relay_id of the sender
    to_relay     [32]u8    // the relay_id of the receiver
    epoch        u64       // the consensus epoch of §10.11
    window       u32       // the batch index inside that epoch
    cell_count   u32
    batch_root   [32]u8    // Merkle root over the tag of each cell
    sig          [3309]u8  // ML-DSA-65, label "umbra/v1/link-receipt"
}
```

The receipt is **3 422 bytes**. Part 5 §5.11 holds the label. The signature
covers each field but `sig`, after the label.

- **[REL-071]** A relay MUST issue a `LinkReceipt` for each batch of
  `RECEIPT_WINDOW` cells that it takes from an adjacent relay. **[REL-072]** A
  relay MUST sign that receipt with the `identity_pk` of its descriptor.
- **[REL-073]** A relay MUST retain each receipt that it issued and each receipt
  that it took, for `RECEIPT_RETENTION`. **[REL-074]** A relay MUST erase a
  receipt after that period.
- **[REL-075]** A relay MUST NOT put a client address, a queue identifier, or a
  payload byte in a receipt. The Merkle root covers the `tag` of each cell
  only, and Part 3 §3.4.4 makes each hop compute a new tag. Thus a receipt
  names a link and it does not name a user. Part 15 §15.1 holds that row.

**The relay hello.** A relay that takes a link does not know the relay at its
other end: a relay dials the next layer as a client dials the first. Thus the
dialing relay names itself, and only a link whose peer is named carries
receipts.

```
RelayHello {                     // the value of an UMBRA_RELAY_HELLO capsule
    version      u8              // 0x01
    relay_id     [32]u8          // the relay that dialed
    sig          [3309]u8        // ML-DSA-65, label "umbra/v1/relay-hello"
}
```

The hello is **3 342 bytes**. The signature covers the label, `relay_id`, and
the `session_id` of the `Open` of that link, thus a hello of one link does not
name the dialer on another link.

- **[REL-173]** A relay that dials a relay MUST send a `RelayHello` right after
  the `Open` of Part 6 §6.2.3. **[REL-174]** A relay MUST verify a
  `RelayHello` under the `identity_pk` of that `relay_id` in the relay set that
  it holds. A link with no hello that verified is a client link, and a relay
  MUST NOT issue a receipt on a client link.

**The window.** The leaf of a cell is the leaf of the Merkle tree of §10.5.3
over the 16-byte `tag` of the cell as the link carried it, and `batch_root` is
the root of that tree over the leaves of a window in the order of the link.
The tag is the output of the rugged PRP of Part 3 §3.4.4, thus two cells share
one only by chance.

- **[REL-175]** A relay MUST count the cells that it takes on each relay link
  in the order of that link, in windows of `RECEIPT_WINDOW` cells. The first
  window of each epoch is window 0. **[REL-176]** A relay MUST close a partial
  window at the end of each consensus epoch and issue its receipt, thus a cell
  late in an epoch gets a receipt too.
- **[REL-177]** A relay MUST send each receipt that it issues to the other end
  of that link, as the value of an `UMBRA_RECEIPT` capsule of Part 6 §6.2.1.
- **[REL-178]** A relay that takes a receipt MUST verify its signature under
  the `identity_pk` of `to_relay`, and it MUST compute `batch_root` over the
  leaves of the next `cell_count` cells that it sent on that link. It MUST drop
  a receipt that fails either check, and it MUST keep the leaves of a receipt
  that it keeps, for the proof of a query.

**The link-fault report is from a client to a directory authority.** It carries
no signature, because a client holds no key that a third party verifies and a
signature would give A5 a durable statement about that client.

```
LinkFaultReport {
    version      u8        // 0x01
    epoch        u64
    hop1         [32]u8
    hop2         [32]u8
    hop3         [32]u8
    loops_sent   u16
    loops_lost   u16
}
```

The report is **109 bytes**, thus it fits bucket `B0`.

- **[REL-076]** A client MUST send a `LinkFaultReport` when its loop-failure
  rate on one chain reaches `LOOP_FAULT_RATE` in one epoch. **[REL-077]** A
  client MUST NOT sign a `LinkFaultReport`.
- **[REL-078]** A client MUST carry a `LinkFaultReport` in a scheduled cover
  slot or in a push-wake session. Part 3 §3.6.2 gives the slot, and Part 8
  §8.4 gives the session. In a push-wake session the report is one `B0`
  cell. **[REL-107]** A client MUST NOT send more than one `LinkFaultReport`
  in one push-wake session. **[REL-079]** A client MUST NOT open a session for
  the only purpose of a `LinkFaultReport`. In the foreground the report
  replaces the cover cell of its slot. In a push-wake session it is one real
  cell, and a fault is a rare event.

**The loop count.** A client counts the loops of each chain in each epoch. A
relay at the end of the chain sends a loop back on the circuit that carried it
(Part 3 `NET-060`), thus the client counts a loop cell that comes back on a
circuit of that chain.

- **[REL-163]** A client MUST count, for each chain and each consensus epoch,
  each loop that it sent and each loop that came back. **[REL-164]** A loop
  that has not come back after `LOOP_RETURN_WAIT` is lost. **[REL-165]** A
  client MUST NOT apply `LOOP_FAULT_RATE` to a chain with fewer than
  `LOOP_FAULT_MIN` loops in the epoch, because one lost loop of three is no
  signal.

**The report queue.** A `LinkFaultReport` names three relays of the chain of a
client. The report travels to an authority through a queue that the authority
reads, and the report is sealed to that authority, thus the relay that holds
the queue reads no chain.

```
ReportQueue {
    version          u8          // 0x01
    authority_index  u8          // the index of the authority in the key set
    epoch            u64         // the first consensus epoch that it serves
    address          [129]u8     // a QueueAddress of Part 6 §6.6.10
    report_pk        [32]u8      // X25519 public key
    sig              [3309]u8    // ML-DSA-65, label "umbra/v1/report-queue"
}

SealedReport {                   // 157 bytes, the L6 record of kind 0x08
    ephemeral_pk     [32]u8      // X25519 public key of the sender, fresh
    ciphertext       [125]u8     // the LinkFaultReport and the 16-byte tag
}
```

The `ReportQueue` is **3 480 bytes**. Part 5 §5.11 holds the label. The
signature covers each field but `sig`, after the label, under the key of the
authority at `authority_index` in the current `DirectoryKeySet`. The
`RelayManifest` of §10.5.5 carries the report queues after its entries.

The key of a `SealedReport` is `HKDF-SHA3-256` with the X25519 output of
`ephemeral_pk` and `report_pk` as the input key, `ephemeral_pk || report_pk`
as the salt, and the label `"umbra/v1/link-fault-seal"` as the info. The AEAD
is ChaCha20-Poly1305 with a nonce of 12 zero bytes, because each key seals one
report.

- **[REL-166]** A directory authority MUST publish one `ReportQueue`, and it
  MUST read that queue at least once in each epoch. **[REL-167]** An
  authority that makes the manifest MUST carry the newest report queue of
  each authority that published one.
- **[REL-168]** A client MUST verify each `ReportQueue` under the key set that
  verified the root, and it MUST drop one whose signature fails, whose
  `authority_index` names no key of the set, or whose `epoch` is above the
  epoch of the root.
- **[REL-169]** A client MUST send each `LinkFaultReport` to the report queue
  of one authority that it draws at random from the verified report queues,
  as a `SealedReport` under the `report_pk` of that queue. A client that holds
  no verified report queue MUST drop the report.
- **[REL-181]** A client MUST send a report on a ready circuit whose last relay
  holds a verified report queue, and it MUST build no circuit for a report
  before the report waited `REPORT_WAIT`. **[REL-182]** After that wait, a
  client in the foreground MUST build one circuit to the relay of a report
  queue that it draws at random, at most once in each epoch, and the report
  goes on that circuit.
- **[REL-170]** An authority MUST drop a `SealedReport` that does not open, and
  a report whose `epoch` is neither the current epoch nor the one before it.

> *Cause of `REL-182`.* A client holds circuits to the relays of its own
> queues and of the queues of its contacts, and the relay of a report queue
> can be none of them; a test network kept a report that never left. The wait
> puts at least `REPORT_WAIT` between the fault and the build, and a client
> builds circuits for its own queues at other times too.

> *Cause.* An earlier draft gave the report a size and a slot and no
> destination: a `B0` cell names a queue, and no queue of an authority
> existed. The seal uses X25519 alone. A hybrid encapsulation with
> ML-KEM-768 takes 1 088 bytes, and the L6 record of a `B0` cell holds 357
> bytes, thus a hybrid seal would move the report out of `B0` and out of the
> cover slot, where it becomes a visible event. A later quantum adversary that
> opens a stored report learns that some client, which the circuit hid, lost
> loops on three named relays in a past epoch. Part 9 §9.5.4 states the other
> place where UMBRA is not post-quantum.

**The forced replacement.** A **forced replacement** is a new chain that a
client draws because a build of its chain failed, or because a circuit of that
chain ended with no teardown by the client. `REL-014` forbids a replacement
for a local performance measurement, and a failure is no measurement.

- **[REL-171]** A client MUST count the forced replacements of each consensus
  epoch. **[REL-172]** When that count reaches `FORCED_REPEAT` in one epoch, the
  client MUST send one `LinkFaultReport` that names the chain of the last
  failure. In that report `loops_sent` MUST hold the builds and the loops that
  the client tried on that chain in the epoch, and `loops_lost` those that
  failed. This rule is `REL-016`, and the report goes as each other report.

**The fault rate of a relay.** The reports of one epoch name a relay in a hop
field. The **fault rate** of that relay is that report count divided by the
count of chains that the relay carried in the epoch. The chain count is a
statistic of §10.8, thus the authority reads the noised value.

- **[REL-080]** A directory authority MUST run an isolation query on a relay
  whose fault rate reaches `RELAY_FAULT_RATE` in one epoch. **[REL-112]** A
  directory authority MUST NOT run that query from fewer than
  `FAULT_MIN_REPORTS` reports. **[REL-108]** A directory authority MAY run an
  isolation query on one link on its own evidence. §10.11 gives the two
  values.

**The isolation query is an active directory operation.** The receipts commit
to `circ_id` and `tag`, and Part 3 §3.4.4 rewrites both at each hop. Thus a
forensic query cannot match a batch at one link with a batch at the next. The
authority therefore makes its own evidence with a probe that it builds.

- **[REL-109]** At an isolation query, a directory authority MUST build a
  circuit through the relay under query and its reported neighbor. The
  reported neighbor is the adjacent relay that the reports name. The authority
  builds the circuit under Part 3 §3.4, thus it is an ordinary client circuit.
  **[REL-110]** That authority MUST send a loop cell on that circuit.
  **[REL-111]** That authority MUST record the `tag` of the probe cell at each
  hop. The authority computed each layer, thus it holds each tag. The loop
  cell is a probe of §10.4.1.
- **[REL-081]** That authority MUST then request the receipt that covers the
  probe cell from each relay of the circuit. The request names the `tag` of
  the cell at that hop. The relay answers with the receipt and a Merkle
  inclusion proof of the cell. **[REL-082]** A relay MUST give its
  receipts to a directory authority at an isolation query.

```
ReceiptQuery {                   // the body of POST /receipt at a relay
    version          u8          // 0x01
    authority_index  u8
    epoch            u64         // the consensus epoch of the probe
    tag              [16]u8      // the cell as one link carried it
    sig              [3309]u8    // ML-DSA-65, label "umbra/v1/receipt-query"
}

ReceiptAnswer {
    version          u8          // 0x01
    found            u8          // 0x00 none, 0x01 a receipt that this relay
                                 // issued, 0x02 a receipt that it took
    receipt          LinkReceipt // present when found is not 0x00
    leaf_index       u32         // present when found is not 0x00
    step_count       u8          // present when found is not 0x00, 0 to 16
    steps            [step_count]{ side u8, sibling [32]u8 }
}
```

The query is **3 335 bytes**, and the signature covers each field but `sig`,
after the label. A relay issued the receipt of a cell that reached it, and it
took the receipt of a cell that it sent, thus the two values of one cell at
one hop name the two sides of one link.

- **[REL-179]** A relay MUST answer a `ReceiptQuery` that verifies under the
  key of that authority in the key set of the relay set that it holds. The
  answer MUST give the receipt of that `epoch`, issued or taken, whose window
  holds the leaf of `tag`, and the inclusion proof of that leaf. A
  relay that holds no such receipt MUST answer `found` 0x00. **[REL-180]** A
  relay MUST refuse a query that does not verify with HTTP status 403 and no
  body.
- **[REL-186]** A relay MUST answer at most `RECEIPT_QUERY_MAX` queries of one
  authority in one consensus epoch of its own clock, and the queries of §10.8
  count in that bound. **[REL-187]** A relay MUST refuse each further query of
  that authority in that epoch with HTTP status 429 and no body.

> *Cause of `REL-186`.* A query costs the relay one signature check, a search
> of its receipts, and an inclusion proof. One isolation query asks one relay
> at most twice, because a middle relay is the far end of one link and the near
> end of the next. The bound thus lets one authority run 30 or more isolation
> queries through one relay in each epoch, and one authority key that an
> attacker holds cannot keep a relay busy with queries.
> *Cause.* An earlier draft made the leaf of a cell and the query name its
> `circ_id` and its tag, and said that the authority holds each value because
> it encrypted each layer. Part 3 `NET-154` makes the relay before a hop draw
> the `circ_id` of the link to that hop, thus a client holds the `circ_id` of
> its first link alone, and the query could not name the cell at hop 2 or at
> hop 3. The client computes the tag of each layer, thus the tag alone names
> the cell at each hop.

- A **contradiction** is a denial of a batch by a relay whose signature the
  query holds over that batch. A relay that forwarded a batch holds the receipt
  that the next relay issued for it. **[REL-083]** A directory authority MUST
  expel a relay that makes a contradiction at an isolation query.
- **[REL-084]** If the query does not name one relay, a directory authority MUST
  remove the link and it MUST NOT remove either relay. Step 4 of §10.4 states
  the same rule. A relay that gives no answer to a query is such a case, and
  the authority removes the link.

**The removed link.** An expelled relay leaves the relay set, and the manifest
lists it no more. A removed link keeps both relays, thus the manifest carries
the link itself, and each client avoids it.

```
LinkRemoval {                    // in the RelayManifest after its report queues
    version      u8              // 0x01
    epoch        u64             // the consensus epoch of the verdict
    relay_a      [32]u8          // the lower relay_id of the two
    relay_b      [32]u8          // the higher relay_id
    sig_count    u8              // 5 to 7
    sigs         [sig_count]AuthoritySig   // ML-DSA-65, label "umbra/v1/link-removal"
}
```

Each signature covers the label, `version`, `epoch`, `relay_a`, and `relay_b`,
under the key of its authority in the key set of the root. Part 5 §5.11 holds
the label.

- **[REL-183]** The directory authorities MUST sign a `LinkRemoval` for each
  link that they remove, and each manifest MUST carry it for
  `LINK_REMOVAL_EPOCHS` after its `epoch`.
- **[REL-184]** A client MUST verify a `LinkRemoval` under the key set of the
  root as it verifies a root (`REL-007`), and it MUST drop one that fails, one
  whose `relay_a` is not below its `relay_b`, and one whose `epoch` is more than
  `LINK_REMOVAL_EPOCHS` before the epoch of the root.
- **[REL-185]** A client MUST reject a chain in which two adjacent relays form
  a removed link, in either order. Each relay of the link stays in each other
  chain.

> *Cause.* An earlier draft removed a link and gave the removal no carrier,
> thus no client could avoid the link. A removal changes the paths of each
> client, thus it takes the signatures of a root and not the key of one
> authority.

**The dense-subgraph search.** Step 5 of §10.4 runs at each consensus epoch
over the **link-fault graph**. That graph has one vertex for each relay of the
set and one edge for each `LinkRemoval` that the manifest carries.

- **[REL-188]** The directory authorities MUST peel the link-fault graph at
  each epoch. While a relay holds `LINK_FAULT_DEGREE` or more edges, they MUST
  expel the relay with the most edges, the lower `relay_id` first at a tie, and
  they MUST take the edges of that relay out of the graph before the next step.

> *Cause.* An honest relay loses one link for each attacker that drops on a
> link to it. An attacker loses one link for each relay whose traffic it drops.
> Thus the relay with the most edges is an attacker before it is a victim, and
> its expulsion takes one edge from each of its victims. One incident expels no
> relay. **The residual.** `LINK_FAULT_DEGREE` attackers that each give up one
> link to one honest relay expel that relay, and each attacker stays. The trade
> costs the attackers one link each for one honest relay, and the Miranda
> evaluation of §10.4 names the same residual.

**The cost.** A relay signs one receipt for each `RECEIPT_WINDOW` cells. §10.9.1
sizes a held 2 h session at 7 200 cells, thus a relay signs about 7 receipts for
each such session on each link. That cost falls on a relay on mains power. In
the foreground a client pays 0 cells, because a report replaces a cover cell.

> *Cause.* An earlier draft said that each relay issues a signed receipt for each
> accepted cell batch, and that a failed client loop triggers an isolation query.
> Neither object had a structure, a size, a rate, or a budget row. An ML-DSA-65
> signature is 3 309 bytes, thus a receipt for each cell would have been the
> largest recurring cost in the system. The window above makes it 3 422 bytes for
> each 1 024 cells.
>
> A later draft fired the query at `FAULT_THRESHOLD`, which was 8 reports for
> one link in one epoch. About 3 000 relays give about 10⁶ links between two
> layers, and each client gives about 72 loop samples each day. Eight reports on
> one link in one hour then needed more than a million foreground clients. A
> fixed count fired on a small network and never fired on a large one. A rate
> against the chains of one relay has no such denominator. The same draft
> carried a report in a cover slot only, and Part 3 §3.6.2 gives tier C no
> slot. A relay that failed against backgrounded clients was invisible.
>
> That draft also made `REL-083` a forensic test over two receipts whose
> committed values are disjoint by construction. Miranda resolves the same
> case with the party that built the packet, which holds each per-hop value.
> The authority is that party for its own probe. The probe adds no key and no
> party.

### 10.4.1 Indistinguishability of a probe from real traffic

A design can also use positive measurement. **[REL-005]** In that case a probe MUST be
**VRF-selected and cryptographically committed**. **[REL-006]** The directory MUST show the
probe only after the epoch closes. Thus a probe is indistinguishable from real
traffic while it moves. A relay that can tell a probe from a user packet serves
the probes well and serves the other traffic badly.

The loop cover cells of UMBRA are the correct vehicle. The directory VRF-selects
a subset of those cells as scored measurements.

## 10.5 The directory is a Byzantine broadcast, not a plurality vote

The directory uses **N = 7 authorities, and a consensus needs 5 of the 7**
signatures over a Merkle root of the relay set. The mechanism is an
authenticated synchronous Byzantine Broadcast. **The 5-of-7 rule is a
multi-signature and not a threshold construction.** §10.5.2 gives the object,
the preimage, and the verification rules.

> Luo and others (IEEE S&P 2024) showed that **one compromised Tor directory
> authority out of nine can equivocate**. Such an authority gives a targeted
> client a malicious consensus with a correct signature. Tor carries that flaw
> today. Luo and others also showed that a five-minute DDoS against a majority
> of the authorities stops the consensus fully. That event occurred in January
> 2021 and in August 2010.

Requirements:

- **[REL-007]** A client MUST verify the 5-of-7 multi-signature of §10.5.2. **[REL-008]** A client MUST
  also gossip the
  consensus digest in band, over the existing queue traffic and loop traffic.
  This method gives UMBRA an always-on equivocation detector at no cost. It
  needs no separate monitoring service, and it makes no new correlator.
- **[REL-160]** The consensus digest, source `0x02` of Part 6 §6.6.4, MUST be
  the SHA3-256 over the preimage that the signatures of the `DirectoryRoot`
  cover (§10.5.2), with `epoch` the consensus epoch of that root. Thus two
  roots of one epoch that differ in any signed field give two digests. The
  rules `DIS-028` to `DIS-032` of Part 9 §9.5.3 give the rate, the slot, and
  the contact of a consensus digest as of a tree head.
- **[REL-161]** A client MUST compare the consensus digest of a contact
  against the digest of the root that it verified at that epoch, and it MUST
  show an equivocation warning when the two differ. A client that holds no
  root of that epoch MUST drop the digest. **[REL-162]** A client MUST keep
  the digest of each root that it verified for the validity of that root,
  thus a contact one epoch behind still compares.
- The **epoch is 1 hour and the validity is 3 hours**. Thus a five-minute DDoS
  against the authorities causes staleness and not an outage.
- **[REL-009]** A client MUST fetch the `RelaySetDiff` of §10.5.3 only when the
  radio is on for another cause (Part 3 §3.6.2). **[REL-010]** A client MUST
  NOT open a session for the only purpose of a directory diff. A validity of 3
  hours holds a client over a gap between two such occasions.
- An **ML-DSA-65 public key identifies an authority, and an address does not**. A
  supermajority of the current set can rotate the key set. An offline recovery
  key under a legally separate arrangement supports that rotation. §10.5.2 gives
  the rotation object.
- The signed relay manifest moves over **each available bootstrap carrier** of
  Part 3 §3.10. The `RelaySetDiff` of §10.5.3 and the `BlocList` of §10.6.3
  move beside it. Thus one carrier is not a single point of failure for
  directory freshness, and U6 delivery reliability holds. The manifest carries
  the 5-of-7 multi-signature over a Merkle root, thus a carrier needs no trust.
  A legal order against one carrier, or against the host jurisdiction of one
  authority, removes one carrier only (A5).

### 10.5.1 Separate who signs from who measures

| Role | Count | Properties |
| --- | --- | --- |
| **Directory authority** | 7 | Seven legal persons under separate control, in three or more jurisdiction blocs. Rules `REL-121` to `REL-124` state each property. The long-lived signing keys stay offline where that is possible |
| **Measurer** | many | Cheap and disposable, with a short-lived signing key that two or more authorities issue |

The seven authorities are the trust anchor of this part. Thus their
independence is a requirement, and it is not a description.

- **[REL-121]** The nonprofit MUST admit a directory authority only when a
  legal person operates it. **[REL-122]** The nonprofit MUST NOT admit two
  directory authorities under one beneficial control. **[REL-123]** The
  nonprofit MUST place the seven authorities in three or more jurisdiction
  blocs of §10.6.3. **[REL-124]** The nonprofit MUST publish the legal person,
  the jurisdiction, and the bloc of each authority. The nonprofit is the entity
  of Part 15 §15.6.
- **[REL-125]** The directory authorities MUST set `independent_count` of the
  `DirectoryKeySet` to the count of authorities under different beneficial
  control. **[REL-126]** A client MUST show the user a `provisional directory`
  state while `independent_count` is below `AUTHORITY_FLOOR`. §10.11 gives
  `AUTHORITY_FLOOR` as 5. `keyset_hash` covers `independent_count`, thus a
  change of the count is a key-set rotation under `REL-036`.

> *Cause.* An earlier draft said "legally hardened, and jurisdictionally
> diverse", and no rule tested either phrase. Part 2 §2.6 assumption 6 rests on
> the count of signing keys that one adversary holds. One legal person that
> operates four authorities holds four keys under one order, and the assumption
> then fails at a count of seven. The rules above make the independent count a
> published fact that the authorities sign. The client shows a launch that has
> not reached the floor.

A measurement report is a signed tuple `(relay_id, class_claimed,
class_verified, slot_id, measurer_id)`. An authority accepts a class only after
**3 or more independent measurer reports from 2 or more different ASes**.

> This rule is the operational lesson from the live consensus of Tor. Only 5 of
> the 9 authorities give a bandwidth value, because the combination of the two
> roles makes the work too heavy to staff.

### 10.5.2 The directory root object

**[REL-025]** A directory authority MUST sign a `DirectoryRoot` with ML-DSA-65. Part 5 §5.1
gives ML-DSA-65 as primitive 3, and the primitive register holds no threshold
scheme. **[REL-026]** An implementation MUST NOT use a threshold signature construction.

```
DirectoryRoot {
    version           u8          // 0x01
    epoch             u64         // the consensus epoch of §10.11
    epoch_start_unix  u64         // epoch × 3 600, in Unix seconds
    root              [32]u8      // the Merkle root over the relay set
    keyset_hash       [32]u8      // SHA3-256 over the canonical authority key set
    bloc_hash         [32]u8      // SHA3-256 over the canonical BlocList of §10.6.3
    revoked_count     u8          // 0 to MEASURER_REVOKE_MAX
    revoked           [revoked_count][16]u8   // the measurer_id of each revoked MeasurerCert
    sig_count         u8          // 5 to 7
    sigs              [sig_count]AuthoritySig
}

AuthoritySig {
    authority_index  u8
    sig              [3309]u8  // ML-DSA-65, label "umbra/v1/directory-root"
}

DirectoryKeySet {
    version            u8          // 0x01
    keyset_epoch       u64         // strictly increasing
    authority_count    u8          // 7
    independent_count  u8          // authorities under different beneficial control, §10.5.1
    keys               [authority_count][1952]u8   // ML-DSA-65 public keys
}

SignedKeySet {
    keyset           DirectoryKeySet
    sig_count        u8          // 5 to 7
    sigs             [sig_count]AuthoritySig   // under the PREVIOUS key set
}
```

`DirectoryKeySet` carries no signature field, and that omission is deliberate.
`keyset_hash` is the SHA3-256 over the canonical `DirectoryKeySet` encoding, and
a signature inside that encoding would make the hash refer to itself.
`SignedKeySet` is the transport form, and `DirectoryKeySet` is the hashed form.
**[REL-042]** A directory authority MUST distribute a key set as a `SignedKeySet`.
**[REL-043]** A client MUST compute `keyset_hash` over the `keyset` field alone,
and it MUST NOT include `sig_count` or `sigs` in that hash.

Each signature covers this preimage:

```
"umbra/v1/directory-root" || version || epoch || epoch_start_unix || root ||
keyset_hash || bloc_hash || revoked_count || revoked
```

The canonical key set is the byte encoding of `DirectoryKeySet` above, and
`keyset_hash` is the SHA3-256 of that encoding. A `DirectoryRoot` with 5
signatures and no revocation is 16 665 bytes, and one with 7 signatures is
23 285 bytes. Each revocation adds 16 bytes, thus the largest form is 23 541
bytes. Part 6 §6.9 gives the `B3` `L5 payload` row 32 650 bytes, thus each form
fits one `B3` cell.

**The verification rules.**

1. **[REL-027]** A client MUST reject a `sig_count` below 5 or above 7.
2. **[REL-028]** A client MUST reject a repeated `authority_index`. **[REL-029]** A client MUST reject an
   `authority_index` at or above `authority_count`.
3. **[REL-030]** A client MUST reject a `sigs` list that is not in ascending order of
   `authority_index`. Part 6 §6.1.1 rule 4 requires one canonical form.
4. **[REL-031]** A client MUST verify each signature against the key at its
   `authority_index` in the key set that the client holds. **[REL-032]** A client MUST count
   5 or more **valid** signatures before it accepts the object. A count of the
   entries is not a count of the valid signatures.
5. **[REL-033]** A client MUST reject a `DirectoryRoot` whose `keyset_hash` differs from the
   hash of the key set that the client holds. **[REL-119]** A directory
   authority MUST set `bloc_hash` to the SHA3-256 over the canonical `BlocList`
   of §10.6.3. **[REL-120]** A client MUST reject a `DirectoryRoot` whose
   `revoked_count` is above `MEASURER_REVOKE_MAX`.
6. **[REL-034]** A client MUST reject a `DirectoryRoot` whose `epoch` is below the highest
   epoch that the client verified.

   **The epoch names a start time.** §10.11 gives the epoch a length of 1 hour,
   and it gives the consensus a validity of 3 hours. Consensus epoch `E` starts
   at `E × 3 600` Unix seconds, and it ends before `(E + 1) × 3 600`.
   **[REL-117]** A directory authority MUST set
   `epoch_start_unix` to `epoch × 3 600`. **[REL-118]** A client MUST reject a
   `DirectoryRoot` whose `epoch_start_unix` differs from `epoch × 3 600`. The
   field makes the origin of the epoch count an explicit signed statement. Part
   3 §3.2.6 and Part 4 §4.7.2 derive their week from that count.

   **The freshness test is against the client clock, and it is not against the
   highest epoch.** `REL-034` already rejects each epoch below the highest
   verified one, thus a second test against that same value can never fire.
   The device clock is not trusted material, and Part 1 §1.9 says that it
   moves. A `DirectoryRoot` is trusted material, and it names a time. Thus the
   client takes its time from the root.

   A `DirectoryRoot` is valid from `epoch_start_unix` to `epoch_start_unix`
   plus `CONSENSUS_VALIDITY`. The **clock correction** is the distance from
   the device clock, at the moment the client accepted that root, to that
   span: `epoch_start_unix` minus the device clock when the device clock is
   before the span, zero inside it, and the end of the span minus the device
   clock after it. The **client clock** is the device clock plus the
   correction. A client holds one
   correction or none. Each rule of this section that names a clock names the
   client clock.

   **[REL-035]** A client MUST reject a `DirectoryRoot` whose `epoch_start_unix`
   is more than `CONSENSUS_VALIDITY` plus `CLOCK_SKEW` before the client clock.
   **[REL-113]** A client with no correction MUST NOT apply `REL-035`.
   **[REL-114]** A client with no correction MUST record the correction from
   the first `DirectoryRoot` that it accepts. **[REL-044]** If an accepted
   `DirectoryRoot` starts more than `CLOCK_SKEW` after the client clock, a
   client MUST record a new correction. That root gives the new correction.
   **[REL-115]** After a clock movement of Part 1 §1.9, a client MUST discard
   the correction. §10.11 gives `CLOCK_SKEW` as 1 hour.

   > *Cause of the span.* An earlier form took the correction from
   > `epoch_start_unix` alone. A root starts at the top of its hour and a
   > client reads it up to `CONSENSUS_VALIDITY` later, thus a client with a
   > correct clock got a correction of up to that validity, moved its clock
   > back, and showed the `corrected` state from each root older than
   > `CLOCK_SKEW`. A test of the reference client failed on it in the last
   > seconds of an hour.

   A client is in one of three clock states. It is `unsynchronized` while it
   holds no correction. It is `synchronized` while the magnitude of the
   correction is at or below `CLOCK_SKEW`. It is `corrected` while that
   magnitude is above `CLOCK_SKEW`. **[REL-116]** A client MUST show the user
   the `corrected` state.

   **[REL-045]** A client build MUST ship the epoch number that held at the build
   time. **[REL-046]** A client with no verified epoch MUST reject a
   `DirectoryRoot` whose `epoch` is below that shipped number.

   > *Cause.* A client with no history has no highest verified epoch, thus
   > `REL-034` binds nothing at the first launch. Without `REL-045` and
   > `REL-046` an ingress relay serves one correctly signed but arbitrarily old
   > consensus to each new client, and that client then selects a path from a
   > relay set that the directory retired. The signatures verify, and the object
   > is stale. A build timestamp costs one `u64` and it closes that window to
   > the age of the build.
   >
   > An earlier draft tested freshness against the device clock, and it
   > rejected a root that started more than `CLOCK_SKEW` after that clock. A
   > phone with a clock one day behind then rejected each fresh root, and it
   > accepted no root at all. Part 3 §3.4 selects no path without an accepted
   > root, thus that client lost the network and not freshness alone. The
   > rules above take the time from the root, because a root that verifies is
   > authenticated evidence of the time. `REL-034` keeps the epochs monotone
   > under it. A stale root at the first launch gives a stale
   > correction, and Part 15 §15.3 records that residual. `REL-046` bounds it
   > to the age of the build, and `REL-044` heals it at the first fresh root.

**The key-set rotation.**

7. **[REL-036]** A client MUST accept a `DirectoryKeySet` only with 5 or more valid ML-DSA-65
   signatures from the **previous** key set. Each of those signatures covers
   `"umbra/v1/directory-keyset" || version || keyset_epoch ||`
   `SHA3-256(the new canonical key set)`. Part 5 §5.11 holds that label, and it
   is not the label of a `DirectoryRoot`.
8. **[REL-037]** A client MUST reject a `DirectoryKeySet` whose `keyset_epoch` is at or below
   the `keyset_epoch` that the client holds.
9. **[REL-038]** The offline recovery arrangement MUST hold one key of the 7. That key gives
   a rotation when a legal order or a compromise removes an authority, and the
   remaining authorities cannot reach 5 without it.
10. **[REL-039]** A client build MUST ship the genesis `DirectoryKeySet`. Part 15 §15.5 puts
    the build under binary transparency, thus that key set is under the same
    scrutiny as the code.

> *Cause.* An earlier draft said "one 5-of-7 threshold signature" and "a
> threshold public key". Part 5 §5.1 lists no threshold construction, and the
> message core is closed at six primitive families. A list of 5 to 7 ordinary
> ML-DSA-65 signatures needs no new primitive, and it gives one property that a
> threshold scheme does not: a verifier reads **which** authorities signed.
> §10.5 says that one compromised authority in Tor can equivocate, and a named
> signer set is the evidence that makes an equivocation attributable.
>
> The cost is size. A threshold signature would be 3 309 bytes and this object
> is 16 665 bytes at the minimum. §10.5 fetches the directory on a session that
> the client opened for another cause, at a validity of 3 hours, thus that size
> falls on about 8 fetches each day. Part 3 §3.12 carries the cost in its
> directory row.

### 10.5.3 The relay descriptor and the relay-set tree

§10.5.2 signs a Merkle root over the relay set. This section gives the object
that the tree holds and the hash construction of the tree. It gives the rule
that a client applies before it uses one entry. Without this section a client
holds a signed root and no method to read a relay out of it. A relay signs a
descriptor, and the directory authority wraps it in an entry that carries the
facts that the authority verified.

```
RelayDescriptor {
    version          u8          // 0x01
    relay_id         [32]u8      // SHA3-256 over identity_pk
    identity_pk      [1952]u8    // ML-DSA-65, signs this descriptor
    ntor_pk          [32]u8      // X25519 static, the s of UMBRA-NKhfs (Part 5 §5.4.9)
    addr_v4          [4]u8       // 0.0.0.0 when the relay has no IPv4 address
    addr_v6          [16]u8      // all zero when the relay has no IPv6 address
    port             u16
    host             [64]u8      // the co-tenant host name of Part 3 §3.8, ASCII, zero-padded
    asn              u32
    jurisdiction     [2]u8       // ISO 3166-1 alpha-2
    family_id        [32]u8      // SHA3-256 over the family certificate of 10.6
    capacity_class   u8          // 0 to 3, for C0 to C3, the declared upper bound
    roles            u8          // bit 0 queue, 1 chain, 2 ingress offered, 3 attachment
    chunk_store_gib  u32         // the declared store of Part 12 §12.7, in GiB
    valid_after      u64         // the first consensus epoch of this descriptor
    sig              [3309]u8    // ML-DSA-65, "umbra/v1/relay-descriptor"
}
```

The fixed width is **5 464 bytes**. An earlier draft carried a 1 184-byte
static ML-KEM-768 key in this descriptor, and no handshake consumed it. Part 5
§5.4.9 gives the cause of its removal. **[REL-127]** A relay MUST set
`chunk_store_gib` to the store that it declares under Part 12 §12.7, in GiB. A
relay without the attachment role sets the field to 0. The queue role (bit 0)
covers the group queues of Part 3 §3.2.7 as well as the pairwise queues: a
relay that serves queues serves group queues, and no separate role bit exists
for them.

**[REL-047]** A relay MUST publish its descriptor in the encoding above.
**[REL-048]** A relay MUST sign the descriptor with `identity_pk` over this
preimage, and Part 5 §5.11 holds the label:

```
"umbra/v1/relay-descriptor" || the descriptor bytes up to and not including sig
```

**[REL-143]** A relay MUST set `host` to the DNS name that the TLS
certificate of its co-tenant site names, in ASCII, with zero bytes after the
name. **[REL-144]** A client MUST reject a descriptor whose `host` is empty,
holds a byte outside the DNS name characters, or holds a non-zero byte after
a zero byte. Part 3 rule `NET-282` verifies the certificate against that
name.

> *Cause.* An earlier draft gave the descriptor an address and a port and no
> name. Part 3 §3.8 puts the relay behind the reverse proxy of a real site
> under a public CA certificate, and a client that verifies that certificate
> needs the name it carries. Without the field a client either skipped the
> check or held a name from outside the signed descriptor.

**[REL-049]** A relay MUST set `relay_id` to `SHA3-256(identity_pk)`.
**[REL-050]** A client MUST reject a descriptor whose `relay_id` differs from
that hash. **[REL-051]** A client MUST verify `sig` against `identity_pk` before
it uses any field of a descriptor.

> *Cause.* The diversity fields of §10.6 decide a path, and a directory
> authority that fabricates a descriptor selects the path of a client. A
> self-signature does not stop a false *declaration*, and §10.6 already says so.
> It stops a **substitution**: no authority set can put a key that it holds in
> place of the key of a listed relay. Trust assumption 6 of Part 2 §2.6 assumes
> that no adversary holds five directory signing keys. This signature bounds
> the damage when that assumption weakens.

**The entry.** The tree holds an entry, and the entry holds the descriptor:

```
RelayEntry {
    descriptor     RelayDescriptor
    operator_id    [32]u8      // one opaque value for each beneficial control
    class          u8          // the verified class of §10.2, 0 to 3
    flags          u8          // bit 0 ingress, bit 1 layer 3, bit 2 pending (§10.5.4)
}
```

The entry is **5 498 bytes**. Part 6 §6.9 gives the `B3` `L5 payload` row
32 650 bytes, thus one `B3` cell carries 5 entries. The relay signs the
descriptor, and the directory authority sets the three fields after it. The
signed root covers the entry, thus the three fields carry the 5-of-7
multi-signature.

- **[REL-128]** A directory authority MUST set `operator_id` from the
  beneficial-control declaration of the dossier of §10.6. Two relays under one
  beneficial control carry one `operator_id`. The authority selects an opaque
  value, and the value does not name the person.
- **[REL-129]** A directory authority MUST set `class` at or below
  `capacity_class` of the descriptor. §10.2 gives the measurement that sets
  it.
- A relay is **ingress eligible** when three conditions hold. Its `roles` bit 2
  is set. Its `class` is C2 or above, under §10.6.1. Its staging of §10.7.1 is
  complete. **[REL-130]** A directory authority MUST set `flags` bit 0 only for
  an ingress eligible relay.
- **[REL-131]** A directory authority MUST NOT take `operator_id`, `class`, or
  `flags` from a relay.
- **[REL-132]** A client MUST take the class, the operator, and the ingress
  eligibility of a relay from the entry. **[REL-133]** A client MUST use a relay
  at hop 1 only when `flags` bit 0 of its entry is set. **[REL-134]** A client
  MUST NOT use a relay whose `flags` bit 0 is set at hop 2 or at hop 3.

> *Cause.* An earlier draft put the verified class, the operator, and the
> ingress eligibility in no object. The client read `capacity_class`, which
> the relay declares. §10.2 said that a measurement confirms the class, and
> no field held the confirmed value. Part 3 §3.4.6 invariant 1 named
> "operator" and no field carried it. §10.5.4 assigned the ingress layer by a
> hash over each relay, and §10.6.1 then rejected two thirds of that layer.
> The entry carries each verified fact under the signed root, and the relay
> signs nothing that it cannot know.

**The tree.** The relay set is a Merkle tree over the entries:

```
leaf(e)        = SHA3-256( 0x00 || entry bytes )
node(l, r)     = SHA3-256( 0x01 || l || r )
```

**[REL-052]** A directory authority MUST prefix a leaf hash with `0x00` and a
node hash with `0x01`. **[REL-053]** An implementation MUST NOT compute a leaf
hash and a node hash under one construction.

> *Cause.* Without the two prefixes an attacker presents an internal node as a
> leaf, and the tree admits a second preimage. RFC 6962 §2.1 gives this
> separation, and each tree in this specification uses it. Part 9 §9.5 uses the
> KEYTRANS construction, which carries its own separation.

**[REL-054]** A directory authority MUST order the leaves by `relay_id`, from
the lowest value to the highest value. **[REL-055]** That authority MUST NOT put
two leaves with one `relay_id` in one tree. **[REL-056]** A directory authority MUST
carry the last node of a level with an odd node count to the next level without
a change. **[REL-063]** That authority MUST NOT duplicate that node.

**[REL-057]** A client MUST verify the inclusion proof of an entry before it
selects the relay of that entry. The proof is against the `root` of a
`DirectoryRoot` that the client accepted. **[REL-058]** A client MUST reject
an entry with no inclusion proof.

A proof is the sibling hash of each level, from the leaf to the root. A set of
about 3 000 relays gives a proof of 12 hashes, which is 384 bytes.

**The relay-set diff.** A client that holds the tree of one epoch needs the
change to the next, and it needs the free store of each attachment relay. One
unsigned object carries both:

```
RelaySetDiff {
    version        u8          // 0x01
    epoch          u64         // the epoch of the DirectoryRoot beside it
    base_epoch     u64         // the epoch that this diff applies to
    removed_count  u16
    removed        [removed_count][32]u8   // the relay_id of each removed entry
    added_count    u16
    added          [added_count][32]u8     // the relay_id of each added or changed entry
    leaf_count     u16
    store_levels   [ceil(leaf_count / 4)]u8   // 2 bits for each leaf, in leaf order
}
```

A **store level** is a two-bit value. Level 0 is a relay without the attachment
role, or a free store below `CHUNK_SIZE`. Level 1 is a free store below
`CHUNK_STORE_MIN`. Level 2 is a free store below `CHUNK_STORE_TARGET`. Level 3
is a free store at or above `CHUNK_STORE_TARGET`. Part 12 §12.7 owns the three
constants.

- **[REL-135]** A directory authority MUST publish one `RelaySetDiff` beside
  each `DirectoryRoot`. **[REL-136]** A directory authority MUST set each store
  level from the free store that the relay reported in that epoch. Rule
  `ATT-091` of Part 12 gives the report.
- No signature covers the diff. The two lists are a hint, and `REL-057`
  verifies each entry against the signed root. A false store level costs a
  writer one failed `CNEW` or `BNEW` under Part 12, and it costs nothing else.
  Part 12 rule `ATT-144` makes a writer prefer level 2 and level 3.

At 3 000 relays the levels are 750 bytes. At about 8 changes in each epoch the
two lists are 256 bytes. With the 23-byte fixed part one diff is 1 029 bytes,
and the 8 fetches of one day cost 8 232 bytes. Part 3 §3.12 carries that
figure. A free store is not a traffic counter, and a two-bit level at 100 GiB
steps is not a raw value. Thus §10.8 does not bind it.

Part 13 §13.8 puts a `PowChallenge` beside each descriptor. The relay signs
that object, it sits outside the tree, and rule `ABU-064` makes an authority
serve it with the descriptor. A client that holds a descriptor fetches the
challenge alone on the same path.

**[REL-059]** If the entry width, the relay count, or the fetch schedule
changes, a revision MUST derive both rows again. The rows are the directory row
and the entry row of Part 3 §3.12. The directory row counts the consensus
fetches and the diffs, and the entry row counts each entry that a build fetches
with its proof. A client fetches an entry when it selects a relay. The ingress
pin of §10.6.1 lasts 60 to 120 days, thus the two ingress entries amortize over
that period.

### 10.5.4 The layer assignment

Part 3 §3.4.1 assigns each chain relay to layer 2 or to layer 3, and `NET-027`
prohibits an operator from selecting that layer. Layer 1 is the **ingress
population**, which is the set of relays with `flags` bit 0 in the entry of
§10.5.3. The **chain population** is the set of relays with `roles` bit 1 and
without that flag. The assignment over the chain population is a public
function of the consensus at the **admission** of the relay:

```
layer(relay_id) = 2 + ( SHA3-256( "umbra/v1/relay-layer"
                                || root || BE64(epoch) || relay_id ) mod 2 )
```

Here `root` and `epoch` are the fields of the `DirectoryRoot` that first
lists the relay, and that root lists it as **pending**. An admission takes
two roots, because a value that already exists when an operator picks
`relay_id` is a value that the operator grinds against.

**The pending root.** **[REL-156]** A directory authority MUST list a relay
of the chain population in one root with `flags` bit 2 set and bit 1 clear
before it places the relay. **[REL-157]** An authority MUST NOT set bit 1 in
the same root as bit 2. **[REL-158]** A client MUST NOT select a relay whose
entry sets bit 2 for any hop, and a relay MUST NOT open a circuit to one. A
pending entry carries the address and the keys of the relay, thus an
operator tests its relay against the directory, and no client routes
through it.

- **[REL-060]** A directory authority MUST compute the layer of a relay of
  the chain population one time, with the function above, under the root
  that listed the relay as pending. It MUST set `flags` bit 1 of the first
  entry that clears bit 2 when the value is 3, and it MUST keep that bit in
  each later entry of that `relay_id`. A relay with no queue role serves no
  last hop (`REL-150`), thus the authority MUST clear bit 1 for it, and that
  relay is of layer 2.
- **[REL-061]** A client MUST take the layer of a candidate for hop 2 and hop
  3 from `flags` bit 1 of its entry, and a relay MUST take its own layer from
  its own entry. **[REL-151]** A client MUST reject an entry that sets bit 1
  with bit 0, that sets bit 1 with no queue role or no chain role in `roles`,
  or that sets a bit above bit 2.
- **[REL-062]** A relay MUST NOT declare its own layer, and a descriptor
  carries no layer field.
- The roots are a public record, thus each party can compute the function
  again for each listed relay. **[REL-152]** A directory authority MUST NOT
  sign a root over an entry whose bit 1 differs from the function.
- **[REL-159]** The relays of the first root of a directory MUST take their
  layer under `GENESIS_ROOT` at epoch 0, with no pending root. That root is
  the trusted setup of the directory, and no operator submits a relay to it
  after it exists.

> *Cause.* An earlier draft named a **verifiable random function** here. A VRF
> proves that a holder of a secret key produced an output, and this assignment
> has no secret and no prover. Each party holds the same consensus root and
> computes the same value, thus a plain hash gives the full property and a proof
> carries no information. The root is multi-signed and no operator predicts
> it, thus an operator cannot select a position by a choice of `relay_id`.
> That argument needs the binding root to come after the choice, and the
> pending root of `REL-156` is what makes it come after.
>
> A later draft bound the function to the last root **before** the first root
> that lists a relay. That root exists while the operator still chooses
> `relay_id`, and `relay_id` is the hash of a key that the operator makes.
> One bit costs about two key generations, thus every operator selected its
> own layer and the sentence above was a claim with no mechanism behind it.
>
> A later draft put the ingress layer in this function, at one third of the
> population. §10.6.1 admits class C2 and above to the ingress role, and
> §10.7.1 stages an ingress relay for 14 days. Thus the hash placed a relay at
> layer 1 that the two rules then rejected. The function now covers hops 2 and
> 3, and the directory sets the ingress flag. That draft also bound the
> function to "the root of that epoch". A client with a 3-hour-old root then
> had no rule for the current epoch.
>
> A later draft made each client compute the function under the most recent
> root that it held, again at each root. The epoch is 1 hour, thus a relay
> changed its layer at about each second root. A queue lives at one relay for
> weeks, Part 3 rules `NET-166` and `NET-167` make a relay enforce its layer,
> and the key schedule of Part 3 §3.4.4 takes the layer as `hop_index`. Thus a
> queue relay that the hash moved to layer 2 refused each circuit that ended
> at it, and its queues were out of reach for that hour. That draft also said
> that "a relay enforces no layer", which those two rules contradict. The
> layer is now a fact of the admission. The entry carries it under the 5-of-7
> multi-signature, as it carries the ingress flag. The operator still selects
> no position: the root of the function comes after the key of the relay. An
> operator can select layer 2 with a descriptor that offers no queue role.
> Layer 2 sees no client address and no queue, thus that choice gives the
> least.
>
> This change also keeps the primitive register closed. Part 5 §5.1 registers
> `ECVRF-Edwards25519-SHA512-TAI` as AUX-3 for two uses, and neither one is this
> assignment. Keccak is primitive 6 of the message core, thus the function above
> adds nothing. §10.4.1 keeps AUX-3, because a probe selection **does** need a
> secret key and a proof.
>
> This function uses the label `"umbra/v1/relay-layer"`, and Part 5 §5.11 holds
> it. An earlier draft used `"umbra/v1/relay-descriptor"` with a prefix byte of
> `0x02`. That label already names the descriptor signature, and Part 5 rule
> `CRY-031` forbids two object types under one label. The note of that draft
> also said that one label carried three domains. §10.5.3 gives the leaf hash
> and the node hash no label at all, thus that note described a construction
> that this part does not hold. The two tree prefixes `0x00` and `0x01` stay in
> §10.5.3, and they separate a leaf from a node inside the tree.

**[REL-150]** A client MUST NOT use a relay at hop 3 when `roles` bit 0 of its
descriptor is not set. The last relay of a circuit serves the commands of the
client, and a relay with no queue role serves none. The layer function gives
each relay a value, thus a client MUST NOT read the layer of a relay with
`flags` bit 0 as a place in the chain population.

### 10.5.5 The relay manifest

§10.5 and Part 3 §3.10 move a signed relay manifest over each bootstrap
carrier. The manifest is one root and a set of entries, each with its proof
under that root. A carrier gives the whole relay set, or a part of it: an
invitation of a contact carries the few relays that the first circuits need.

```
RelayManifest {
    version       u8              // 0x01
    root_len      u16
    root          [root_len]u8    // a DirectoryRoot of §10.5.2
    entry_count   u16
    entries       [entry_count]ProvenEntry
    queue_count   u8              // 0 to 7, absent in a manifest of an earlier build
    queues        [queue_count]ReportQueue   // §10.4.2
    removal_count u16             // absent with no removal
    removals      [removal_count]LinkRemoval // §10.4.2
}

ProvenEntry {
    entry         RelayEntry      // 5 498 bytes, §10.5.3
    step_count    u8              // 0 to 16
    steps         [step_count]{ side u8, sibling [32]u8 }
}
```

The steps go from the leaf to the root. A `side` of `0x00` puts the sibling
on the left of the running hash, and `0x01` puts it on the right. Part 9 §9.5
uses the same form. A tree of 3 000 leaves gives 12 steps, thus one proven
entry is 5 895 bytes. The five relays of a first contact are about 29 KB, and
the root adds 17 KB to 24 KB.

- **[REL-145]** A carrier MUST give the manifest in the encoding above, with
  the entries in ascending order of `relay_id`. **[REL-146]** A client MUST
  verify the root under §10.5.2 before it verifies one entry. The signature
  of an entry costs an ML-DSA-65 verification, and a carrier must not spend
  that work of a client under a root that no authority signed.
- **[REL-147]** A client MUST reject the whole manifest when one entry fails
  `REL-050`, `REL-051`, `REL-057` or `REL-144`, when two entries are not in
  ascending order of `relay_id`, when a `step_count` is above 16, or when a
  `side` is not `0x00` or `0x01`. A manifest that the client rejects MUST
  leave the accepted root, the highest epoch and the clock correction of
  §10.5.2 as they were.
- **[REL-148]** A client MUST reject an entry whose `valid_after` is above
  the `epoch` of the root.
- **[REL-149]** A client MUST reject a manifest whose root names a
  `bloc_hash` that differs from the hash of the `BlocList` that the client
  holds. The blocs decide invariant 2 of Part 3 §3.4.6, and a client that
  tests a chain under another list tests another rule. The `BlocList` moves
  beside the manifest, under §10.5.

> *Cause.* An earlier draft named a "signed relay manifest" in three parts
> and gave it no bytes. A client held a rule for a root and a rule for one
> entry, and it held no object that a carrier could hand to it. A manifest
> with proofs serves both uses of Part 3 §3.10 with one form: the full set
> from an HTTPS endpoint, and the few relays inside an invitation.

## 10.6 Path selection: hard constraints, not soft weights

**[REL-011]** A client MUST reject a chain if two of its relays share one of these items:

- a family certificate
- an IPv4 /16 or an IPv6 /48
- an ASN
- a jurisdiction bloc, and §10.6.3 gives that list

The directory enforces two ceilings in each **population** of each bloc.
§10.5.4 defines the ingress population and the chain population. The **family
ceiling** is 3 % of the population, or one relay when one relay is larger.
**[REL-139]** A directory authority MUST NOT list relays of one family above
the family ceiling in one population of one bloc. **[REL-140]** A directory
authority MUST NOT list an ASN above 10 % of one population of one bloc. Thus
no measurement error and no reputation bug can concentrate a path inside one
bloc.

A family declaration uses the **family certificate of §10.6.3**, which has the
shape of Tor proposal 321. That certificate is mandatory in v1. UMBRA does not
use an O(n²) list in the `MyFamily` style.

The layer assignment comes from the consensus root at the admission of the
relay (§10.5.4), and the directory sets the ingress flag (§10.5.3). Thus an operator **cannot select its
position**. This property removes the KAX17 strategy, which collects the
ingress positions and the middle positions.

The diversity fields do not authenticate themselves. Thus admission to the
directory needs a signed operator dossier. That dossier holds these fields:

- the legal entity, or the individual operator
- the beneficial-control declaration, from which the authority sets
  `operator_id` of §10.5.3
- the family certificate
- the hosting ASN
- the jurisdiction of operation
- a contact for abuse and for legal process

**[REL-012]** Directory authorities MUST verify the dossier before the first listing. **[REL-013]** They
MUST verify it again at a material change.

This dossier does not stop a shell company. It also does not stop a false
declaration by a state-level adversary. It changes such an act into detectable
fraud. It also gives the path selector concrete facts to enforce, in place of
relay claims with no audit.

### 10.6.1 Ingress relays: two, long-lived, high floor

- **Two pinned ingress relays.** Not one, and not three.

  UMBRA has more path restrictions than Tor. With one ingress relay, the
  documented failure mode of Tor proposal 291 occurs. That failure is an
  involuntary secondary connection with no multiplexing, which carries one
  circuit. An attacker attacks that connection from the 5-tuples and the
  timestamps alone.

- **Rotation: a minimum confirmed lifetime of 60 days, and 120 days if the
  lifetime is unconfirmed.**
- **Only class C2 and above are eligible for the ingress role.** An equivalent
  floor costs about 7 % of the capacity. It also decreases the pool to about
  1000 relays. It thus makes a Sybil attack at botnet scale too expensive at the
  one position that sees a client IP address.

**The life of a pin.** A pin is the `relay_id` of an ingress relay, the time
of the pin on the client clock of §10.5.2, and a confirmed flag. A pin is
**confirmed** when a circuit through that relay held its three hops.

- **[REL-153]** A client MUST keep its pins in the store of Part 14 §14.6.4.
  At each relay set that it accepts, it MUST keep a pin while the entry of
  that relay holds `flags` bit 0 and the lifetime of the pin runs. It MUST
  end a pin for no other cause, and `REL-014` names the cause that tempts.
- **[REL-154]** A client MUST fill an open place with a random draw from the
  ingress eligible relays of the accepted set. The two pins MUST NOT share an
  `operator_id` or a `family_id`, because one operator with the two pins sees
  each connection of that client for 60 days. A set with one eligible relay
  gives one pin, and the second place stays open. Part 3 rules `NET-344` and
  `NET-345` relax the operator bound in a provisional directory.
- **[REL-155]** A client MUST NOT dial an ingress relay that is no pin. After
  a dial of one pin that failed, the next run MUST dial the other pin. Thus
  the loss of one ingress relay does not stop delivery (U6).
- The invariants of Part 3 §3.4.6 can forbid a chain from one pin to the
  relay of one queue. A client that holds a link to each pin builds that
  circuit from the other one. The reference client of 0.2.0-draft holds one
  link in a run, and rule `NET-315` of Part 3 makes that queue wait.

### 10.6.2 Relay replacement does not follow local performance

**[REL-014]** A client MUST NOT replace a relay because of a local performance measurement.
This rule is the direct lesson of Herrmann and Grothoff.

- A relay set is **fixed for an epoch and comes from the directory**.
- A consensus-random draw from the same class and the same layer replaces a
  failed relay. **[REL-015]** The client MUST NOT select "the fastest peer that I have seen".
- Replacements have a rate limit of a maximum of one in each epoch for each
  layer, with hysteresis.
- **[REL-016]** A client MUST report **repeated forced replacement to the directory as a link
  fault**. **[REL-017]** A client MUST NOT absorb such an event silently.

An adversary that runs a DoS against the current relays of a client gets nothing
more than a slow client.

### 10.6.3 The family certificate and the jurisdiction bloc

`REL-011` rejects a chain whose relays share a family or a jurisdiction bloc.
The `RelayDescriptor` of §10.5.3 carries `family_id` and `jurisdiction`. The
directory authority verifies the first object below, and the client verifies
the second.

**The family certificate.**

```
FamilyCert {
    version       u8          // 0x01
    family_name   [32]u8      // a label that the operator selects
    member_count  u16         // 1 to FAMILY_MAX
    members       [member_count][32]u8   // the relay_id of each member
    valid_after   u64         // the first consensus epoch
    sig_count     u8          // equal to member_count
    sigs          [sig_count][3309]u8    // ML-DSA-65, one for each member
}
```

Each member signs this preimage with the `identity_pk` of its descriptor. Part 5
§5.11 holds the label:

```
"umbra/v1/relay-family" || version || family_name || member_count ||
members || valid_after
```

- **[REL-085]** A relay MUST sign the family certificate of each family that it
  declares, with the `identity_pk` of its own descriptor. **[REL-086]** A relay
  MUST set `family_id` of its descriptor to the SHA3-256 of that certificate.
- A **member** is a relay whose descriptor carries the hash of the certificate.
  **[REL-087]** A directory authority MUST verify each signature of a family
  certificate before it lists a member. **[REL-088]** A directory authority
  MUST reject a certificate whose `sig_count` differs from `member_count`.
  **[REL-089]** A directory authority MUST reject a certificate that does not
  name the relay whose descriptor carries its hash.
- **[REL-090]** A directory authority MUST retain the family certificate of
  each `family_id` that a listed descriptor names. A relay submits the
  certificate with the dossier of §10.6, and a client does not fetch it.
- **[REL-137]** A client MUST take the family of a relay from `family_id` of
  its entry. **[REL-138]** A client MUST NOT fetch a family certificate to
  apply `REL-011`.

> *Cause.* An earlier draft called this object "an Ed25519-style family
> certificate". Part 5 §5.1 removes Ed25519 from the design and rule `CRY-005`
> forbids a primitive that the register does not hold. That draft also gave the
> object no field list, no signature algorithm, and no verification rule, and
> `REL-011` and `family_id` each depend on it. The certificate above uses
> ML-DSA-65, which is primitive 3 of Part 5 §5.1, and it adds no primitive.
>
> A signature from each member is what makes the declaration mutual. One relay
> cannot put another relay in its family, thus no operator shrinks the
> conformant chain set of a competitor.
>
> A later draft made the client verify the certificate, and `REL-090` made the
> authority serve it. A client then fetched up to `FAMILY_MAX` signatures,
> which is 212 KB, to test one fact that the authority had tested at admission.
> The authority now verifies the certificate one time, and the signed root
> carries `family_id` in the entry. The relay signs `family_id` in its own
> descriptor, thus no authority moves a relay into a family.

**The jurisdiction bloc.** A bloc is a set of ISO 3166-1 alpha-2 codes whose
states share a legal-assistance arrangement or an intelligence-sharing
arrangement. Part 3 §3.4.6 invariant 2 rejects a chain whose relays sit in one
bloc. §10.12 holds the list of v1.

```
BlocList {
    version      u8          // 0x01
    bloc_count   u8
    blocs        [bloc_count]Bloc
}

Bloc {
    code_count   u8
    codes        [code_count][2]u8   // ISO 3166-1 alpha-2, in ascending byte order
}
```

The canonical encoding orders the codes of a bloc in ascending byte order, and
it orders the blocs by their first code. The list of §10.12 is 66 bytes.

- **[REL-091]** A directory authority MUST publish the bloc list as a
  `BlocList` beside each `DirectoryRoot`. **[REL-141]** A client MUST verify
  that the SHA3-256 of the `BlocList` equals `bloc_hash` of the accepted
  `DirectoryRoot` before it applies `REL-092`. **[REL-092]** A client MUST take
  the bloc of a relay from that list and from the `jurisdiction` field of the
  descriptor. **[REL-093]** A client MUST treat a code that no bloc names as a
  bloc of its own.
- **[REL-094]** A directory authority MUST NOT change the bloc list without the
  5-of-7 signature of §10.5.2. `bloc_hash` sits under that signature, thus a
  new list is a new `DirectoryRoot`.
- The list has a **feasibility floor**. The floor holds when `BLOC_MIN` blocs
  or more each hold `BLOC_LAYER_SHARE` or more of the ingress population and
  of the chain population. **[REL-142]** A directory authority MUST NOT
  publish a `BlocList` under which the current relay set does not reach the
  floor. §10.11 gives `BLOC_MIN` as 3 and `BLOC_LAYER_SHARE` as 10 %. Part 3
  §3.4.6 gives the client rule for a relay set below the floor. Part 15
  §15.6.1 gives the recruitment target that keeps the set above it.

> *Cause.* An earlier draft gave Part 3 §3.4.6 a jurisdiction **code** and gave
> §10.6 a jurisdiction **bloc**, and no section defined a bloc. The two rules
> selected different chains, and `NET-033` makes that difference a failure. Part
> 3 §3.4.6 now takes the bloc, and this section defines it. The list is a
> published statement about law, thus it changes rarely and the consensus
> carries it.
>
> A later draft published the list "in the consensus" and gave it no encoding,
> no hash, and no content. `REL-094` then bound an object that no signature
> covered, and `NET-033` failed closed against a constraint that no client
> could read. §10.12 holds the list, `bloc_hash` puts it under the root, and
> the floor states when the list is one that a client can satisfy.

## 10.7 Sybil defense

### 10.7.1 Staging

A newly admitted relay carries **cover traffic and measurement traffic only**
before it becomes eligible for a user cell:

- **4 days** for the chain role and the queue role,
- **14 days** for the ingress layer. The directory sets `flags` bit 0 of the
  entry of §10.5.3 at the end of that period, under `REL-130`.

The growth limit of one class in each epoch adds to this delay. Thus the path of
a relay to real influence takes **weeks**. That delay is the property that
defeats a flash Sybil flood. KAX17 collected more than 900 relays and operated
from 2017 to 2021, because no such ramp existed.

### 10.7.2 Automated Sybil detection from day one

The four sybilhunter techniques run as a **mandatory automated directory
function**:

1. A churn time series for each flag, with a threshold that **scales with the
   network size**. The static threshold of Tor was 50 new fingerprints in each
   consensus, and that threshold was the documented bug.
2. A Pearson correlation over the uptime matrix of the relay set, to find
   synchronized reboots.
3. A nearest-neighbor ranking of the descriptor strings by Levenshtein distance.
4. Detection of fingerprint rotation.

The alerts go to a human, but the system **makes them automatically**. In 2026
the Sybil detection of Tor stays manual, and that is the cause that KAX17
operated for four years. Add active probing with loop cover. Six of the Sybil
groups in the USENIX 2016 study were invisible to a passive descriptor analysis.

## 10.8 Publish no raw per-relay traffic counter

A relay gives a statistic to the directory. **[REL-018]** That statistic MUST pass through
**two-aggregator additive secret sharing and Laplace noise**. The calibration of
PeerFlow applies, which is `b = σ/ε` with σ = 1 MiB and ε = 0.1.

**[REL-019]** A directory authority MUST NOT publish a raw per-relay counter. **[REL-020]** A directory
authority MUST publish the noised value only. The bandwidth classes of §10.2,
the measurement of §10.3, and the Sybil detection of §10.7.2 each read the
noised value.

The carried-chain count of §10.4.2 is such a statistic, and it is a count and
not a byte volume. Its scale is σ = 1 chain at the same ε, thus `b` is 10
chains. A noised count near zero makes the fault rate of a small relay large,
and `REL-112` is the floor that holds in that case.

**The shares of the chain count.** The two directory authorities at index 0
and index 1 of the key set are the two **aggregators**. Each aggregator asks
each relay for its share with a signed query.

```
StatQuery {                      // the body of POST /stat at a relay
    version          u8          // 0x01
    authority_index  u8          // 0 or 1, the aggregator
    epoch            u64         // the consensus epoch of the count
    sig              [3309]u8    // ML-DSA-65, label "umbra/v1/stat-query"
}

StatAnswer {
    version          u8          // 0x01
    found            u8          // 0x00 no share, 0x01 a share
    share            u64         // 0 when found is 0x00
}
```

The query is **3 319 bytes**, and the signature covers each field but `sig`,
after the label. The answer is **10 bytes**.

- **[REL-189]** A relay MUST count the chains that it carries in each consensus
  epoch. A chain is each circuit that the relay opens as one hop.
- **[REL-190]** At the end of an epoch a relay MUST draw a uniform 64-bit value
  `r` and keep two shares: share 0 is `count + r` and share 1 is `−r`, modulo
  2⁶⁴. **[REL-191]** A relay MUST discard the count when it holds the shares,
  and it MUST discard the shares after `RECEIPT_RETENTION`.
- **[REL-192]** A relay MUST answer a `StatQuery` of aggregator *k* that
  verifies under `REL-179` with share *k*. A relay MUST refuse a query of each
  other authority with HTTP status 403 and no body.
- **[REL-193]** An aggregator MUST add an integer sample of Laplace(`b`) to each
  share that it takes, before any other party reads the share.
  **[REL-194]** An authority MUST read the chain count of a relay as the sum of
  the two noised shares modulo 2⁶⁴, read as a signed value, and it MUST read a
  negative sum as 0.
- **[REL-195]** An authority MUST compute the fault rate of `REL-080` for an
  epoch after the end of that epoch, from the shares of that epoch.

> *Cause.* Each share alone is uniform, thus one aggregator learns nothing of
> the count. Each aggregator adds the full noise, thus the noise of an honest
> aggregator protects the count when the other one colludes with a reader. This
> is the additive construction of PrivEx-S2 with two parties. The sum of two
> noises is the price of that bound, and `REL-112` holds the floor that a large
> noise on a small count needs.

Implement the PrivEx-S2 construction directly, which is about 300 lines. Do
**not** take a dependency on `draft-ietf-ppm-dap`. That draft is at draft-19,
and its VDAF dependency is unpublished. A moving unpublished standard is the
dependency surface that the KISS constraint prohibits.

## 10.9 Relay scheduling

Implement **KIST-style scheduling** in the Rust relay. The relay reads the
kernel TCP state, which is `notsent_bytes` in `tcp_info` and the headroom in
`SO_SNDBUF`. The relay then writes only the quantity that the kernel can send.
Thus the socket queue stays shallow, and the userspace scheduler controls the
order.

The deployed Tor measurements show these results:

- circuit congestion −30 %
- latency −18 %
- throughput about +10 %
- −660 ms (−23.5 %) for an interactive stream

**UMBRA rejects the Torchestra-style separation of interactive and bulk
connections at the relay layer.** Torchestra gives a delay improvement of 32–40
%. But two connection classes are two traffic populations that an observer can
tell apart at each hop. That objection is the same anonymity-set partitioning
objection that withdrew the 2-hop Fast mode in Part 3 §3.4.2.

> Note that this rule does *not* conflict with the requirement in Part 3 §3.8. A
> **client** separates interactive traffic from bulk traffic. That
> separation is between the client and its ingress relay. At that point the
> observer sees one client. The rejected design makes separate populations *in*
> the relay fabric, where the separation divides each user.

### 10.9.1 The outbound budget of a queue relay

**[REL-021]** **An operator MUST size the outbound budget of a queue relay against 7 200
cells.** That count is the emission of one held session of 2 h. Part 3 §3.5.2
makes the inbound pacing clock mandatory, and Part 3 §3.9 sets `PACING_MEAN` to
1 s. One tick emits one cell, thus a held session of 2 h emits 7 200 cells.

**[REL-022]** An operator MUST NOT size that budget against the real message count. Almost
every one of those cells is cover. Under the Part 3 §3.12 mix model 26 ticks of
the 7 200 carry a real receive, and the other 7 174 carry cover. A real receive
carries the modal text, which needs bucket `B1`.

**[REL-023]** **An operator MUST size the byte budget of that session against 4 071 936
bytes.** That total holds 7 174 × 560 = 4 017 440 bytes of `B0` cover. It also
holds 26 × 2 096 = 54 496 bytes of `B1` delivery. The sum is about 4.07 MB, and
Part 6 §6.9 gives the wire cost of each bucket. **[REL-024]** An operator MUST NOT size that
budget at the `B0` cost of all 7 200 cells. That figure is 4 032 000 bytes, and
it is about 1 percent low.

Part 3 §3.6.3 puts this load on the relay deliberately. The relay runs on mains
power with flat-rate bandwidth, and the phone does not originate the cover. An
earlier draft sized this budget near 400 KB for each session, which is about a
tenth of the figure above. An operator that sizes against that earlier figure
runs out of egress capacity.

## 10.10 The Notification Delivery Relay is a separate track

The NDR (Part 8) is **not** part of this reputation system. A deployment
operates one NDR, and a reputation score over one party carries no information:
a client has no second NDR to select instead. The NDR holds a different kind of
trust, and a different mechanism measures it. That mechanism is a transparency
log of its software builds, a published no-logging policy, and a warrant canary.

A combination with the general relay reputation implies a substitutability that
UMBRA does not have. A later revision that lets a third party operate an NDR
beside the NDR of the deployment enters that NDR in the relay reputation as a
relay with the notification role, and this section then applies to it.

> *Cause.* An earlier draft kept the NDR out of the reputation system because
> one platform forced one operator on it. Part 8 §8.7 now lets a deployment
> operate its own NDR, thus the cause above is the one that holds without a
> platform.

## 10.11 Parameters

| Parameter | Value |
| --- | --- |
| Capacity classes | C0 1 / C1 4 / C2 16 / C3 64 Mbit/s |
| `GENESIS_ROOT` | 32 zero bytes: the root under which the relays of the first root take their layer (`REL-159`) |
| Class growth cap | 1 class up in each 7-day epoch, and a demotion applies at the next consensus (§10.2) |
| `MEASURE_INTERVAL` | 7 d between two class tests of one relay (§10.2) |
| `MEASURE_STALE` | 21 d without a verifying report, then class C0 (§10.2) |
| Measurement duration | 30 s saturating echo |
| Measurer capacity | ≥ 2.25× the class ceiling claimed |
| Reports for each class | ≥ 3 measurers from ≥ 2 ASes |
| `CLUSTER_FULL` | 16 relays, the largest cluster that one slot measures in full (§10.3) |
| `CLUSTER_SAMPLE` | 16 relays of a larger cluster in each slot (§10.3) |
| `MeasurerCert` size | 8 598 B at 2 signatures, 25 148 B at 7, in bucket `B3` (§10.3.1) |
| `MEASURER_REVOKE_MAX` | 16 entries in `revoked` of a `DirectoryRoot` (§10.3.1) |
| Directory authorities | 7, and a consensus needs 5 of 7 ML-DSA-65 signatures (§10.5.2) |
| `AUTHORITY_FLOOR` | 5 authorities under different beneficial control (§10.5.1) |
| `DirectoryRoot` size | 16 665 B at 5 signatures, 23 285 B at 7, and 16 B more for each revocation (§10.5.2) |
| `RelayEntry` width | 5 498 B, and 5 entries in one `B3` cell (§10.5.3) |
| Consensus epoch / `CONSENSUS_VALIDITY` | 1 h / 3 h, and epoch `E` starts at `E × 3 600` Unix seconds (§10.5.2) |
| `CLOCK_SKEW` | 1 h, and §10.5.2 rules REL-035 and REL-044 use it |
| Ingress relays | 2, pinned |
| Ingress rotation | 60 d confirmed, 120 d unconfirmed |
| Ingress eligibility | class ≥ C2, and `flags` bit 0 of the entry carries it (§10.5.3) |
| Staging period | 4 d chain and queue, 14 d ingress |
| Family / ASN ceiling | 3 % or one relay / 10 %, of one population of one bloc (§10.6) |
| `BLOC_MIN` | 3 blocs at the feasibility floor (§10.6.3) |
| `BLOC_LAYER_SHARE` | 10 % of the ingress population and of the chain population (§10.6.3) |
| Queue relay outbound budget | 7 200 cells, or 4.07 MB, for each held 2 h session (§10.9.1) |
| `MEASURER_CERT_TTL` | 168 consensus epochs, which is 7 days (§10.3.1) |
| `RECEIPT_WINDOW` | 1 024 cells for each link receipt (§10.4.2) |
| `RECEIPT_RETENTION` | 48 h (§10.4.2) |
| `LOOP_FAULT_RATE` | 20 % of the loops of one chain in one epoch (§10.4.2) |
| `RELAY_FAULT_RATE` | 2 % of the carried chains of one relay in one epoch (§10.4.2) |
| `FAULT_MIN_REPORTS` | 3 link-fault reports (§10.4.2) |
| `LOOP_RETURN_WAIT` | 120 s, the wait after which a loop is lost (§10.4.2) |
| `LOOP_FAULT_MIN` | 10 loops of one chain in one epoch (§10.4.2) |
| `FORCED_REPEAT` | 2 forced replacements in one epoch (§10.4.2) |
| `REPORT_WAIT` | 15 min, the wait of a report before it builds a circuit (§10.4.2) |
| `LINK_REMOVAL_EPOCHS` | 168 epochs (7 days), the life of a removed link (§10.4.2) |
| `LINK_FAULT_DEGREE` | 8 removed links of one relay, the step of the dense-subgraph search (§10.4.2) |
| `RECEIPT_QUERY_MAX` | 64 queries of one authority at one relay in one epoch (§10.4.2) |
| Chain-count noise | σ = 1 chain, ε = 0.1, thus b = 10 chains (§10.8) |
| `FAMILY_MAX` | 64 members in one family certificate (§10.6.3) |

## 10.12 Annex: the jurisdiction bloc list

This annex is normative. It holds the `BlocList` of v1, and `REL-094` governs a
change. A bloc names states that share one arrangement under which one order,
or one exchange, reaches a relay in each of them.

| Bloc | Codes | Arrangement |
| --- | --- | --- |
| 1 | AT BE BG HR CY CZ EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE | Regulation (EU) 2023/1543, the European Production Order, with an emergency deadline of 8 hours |
| 2 | AU CA GB NZ US | The UKUSA agreement of the five parties |

Denmark does not take part in Regulation (EU) 2023/1543, thus `DK` is a bloc of
its own under `REL-093`. Each code that no row names is also a bloc of its own
under that rule. Part 15 §15.6 records the regulation and its deadlines.

The list is a statement about law, and it is not a statement about the trust of
a state. A relay in a bloc is not a worse relay. Two relays in one bloc are one
order away from a joint view, and that is the fact that `REL-011` tests.

At launch the floor of §10.6.3 needs a third bloc that holds 10 % of each
population, and that third bloc is one state. Part 15 §15.6.1 sets the
recruitment target for it.
