# UMBRA Protocol Specification — Part 6: Wire Format and Encoding

**Status:** Draft
**Version:** 0.1.0-draft

---

## 6.1 Encoding philosophy

The wire format of UMBRA is **fixed-layout binary with explicit lengths and no
self-description**. There is no TLV, no protobuf, no CBOR, no JSON, and no
schema-driven codec in the path that a relay can see.

**Rationale.** A parser is the location where a protocol breaks. A
self-describing format is a parser with an attack surface that grows with its
expressiveness. A fixed-layout format has one shape for each message type and
each field at a known offset. Its parse function is a sequence of bounds-checked
slices, and it has no loop over a type tag that an attacker controls. Such a
format also fuzzes well, verifies well under bounded model checking, and gives
byte-identical output across implementations, which UMBRA needs (Part 15 §15.5).

The cost is that a new field needs a version increment. That cost is the
intended incentive.

### 6.1.1 Rules

1. All integers are **unsigned and big-endian**.
2. Each variable-length field has an explicit `u16` or `u32` length before it,
   or the field has a fixed width. There are no delimiters and no terminators.
3. Each message starts with a `u8` version. A message that has more than one
   type carries a `u8` type directly after the version. The queue end-to-end
   record (§6.4.2) and the ratchet record (§6.5) each have one type, thus each
   carries a version and no type.
4. **Canonical encoding is mandatory.** **[WIR-001]** A parser MUST reject an encoding that is
   not the unique canonical form. **[WIR-002]** A parser MUST reject a non-minimal length,
   trailing bytes, and a set reserved bit. **[WIR-003]** A parser MUST reject padding that
   does not match the specified pattern.
5. **[WIR-004]** **A party MUST NOT use ciphertext bytes or signature bytes for one of three
   functions.** Those three functions are an identifier, a deduplication key,
   and an order tiebreak. **[WIR-005]** **A party MUST NOT use a value that comes from those
   bytes for one of those three functions.** A hash of a ciphertext is such a
   value.

   The ML-DSA hint-malleability defect of RustCrypto (CVE-2026-24850, which used
   `<=` in place of `<`) is a canonical-encoding failure. A malleable identifier
   changes such a defect into a protocol-level attack. Bitcoin shows the same
   class at a larger scale. The transaction identifier covered the signature,
   thus a party that relayed a transaction changed that identifier with no
   private key. BIP 141 removed the signature from the identifier preimage.

   ChaCha20-Poly1305 does not commit to its key, thus one ciphertext can open to
   two different plaintexts under two different keys. Facebook deduplicated an
   abuse report by ciphertext. That construction let a sender deliver an image
   that the recipient could not report (Dodis and others, CRYPTO 2018).
6. **[WIR-006]** A parser MUST be total. Each input parses to a correct structure, or the
   parser returns an error. There are no panics, no unbounded allocations, and
   no recursion.
7. **Each byte value in this specification is in one namespace.** Part 6 gives
   five namespaces. These are the cell command (§6.3), the queue command (§6.4),
   the L6 record kind (§6.4.2), the `PqFrame` kind (§6.5), and the application
   kind (§6.6). A byte value has a meaning only inside its own namespace. **[WIR-007]** A part
   outside Part 6 MAY declare a namespace of its own. Part 12 §12.4.4 declares
   the community record type, and Part 7 §7.5.5 declares the device-set control
   type.

   The two rules below hold for each namespace.

   - **[WIR-008]** A parser MUST read a byte value in the namespace of its own layer only.
   - **[WIR-009]** An implementation MUST give each namespace a separate type. **[WIR-010]** An
     implementation MUST NOT convert one type into another.

   This specification also follows two editorial conventions for a namespace.
   Part 6 names the namespace with each byte value that it gives. A part outside
   Part 6 names the namespace where it defines a byte value. These two
   conventions guide an author of a revision, and they are not conformance
   requirements.

## 6.2 Layer map

```
┌──────────────────────────────────────────────────────────────┐
│ L1  Transport          TLS 1.3 record or QUIC stream,        │
│                        WebSocket frame, RFC 9297 capsule     │
├──────────────────────────────────────────────────────────────┤
│ L2  Session frame      session id, sequence, resend window   │
├──────────────────────────────────────────────────────────────┤
│ L3  Cell               fixed bucket: B0 512 / B1 2K / B2 8K  │
│                        / B3 32K, post-onion padded           │
├──────────────────────────────────────────────────────────────┤
│ L4  Onion cell         telescoped circuit state, routing, UIV+│
├──────────────────────────────────────────────────────────────┤
│ L5  Queue command      NEW/SEND/SUB/ACK/DEL/… + deniable auth│
├──────────────────────────────────────────────────────────────┤
│ L6  Queue E2E          per-queue AEAD layer (QE)             │
├──────────────────────────────────────────────────────────────┤
│ L7  Ratchet record     encrypted header + body + PQ braid    │
├──────────────────────────────────────────────────────────────┤
│ L8  Application        message content                       │
└──────────────────────────────────────────────────────────────┘
```

The layers L4 to L7 each carry their own encryption. A relay at hop *n* can
decrypt one L4 layer and nothing else. Part 3 §3.8 names the first three layers
of this map.

### 6.2.1 The transport framing (L1)

Part 3 §3.8 puts the cell stream in an HTTP/1.1 Upgrade to a WebSocket-shaped
stream over TLS 1.3, or in a QUIC stream. On each of the two transports the
stream carries capsules in the format of RFC 9297 §3.2. A capsule gives the
receiver the length of the frame that it carries.

```
Capsule {
    type      varint      // 0x0B52 UMBRA_CELL, or 0x0B53 UMBRA_SESSION
    length    varint      // the byte count of value, in the 4-byte form
    value     [length]u8  // a SessionFrame (§6.2.2), or a session control
                          // record (§6.2.3)
}
```

The two fields use the variable-length integer of RFC 9000 §16. **[WIR-216]** A
sender MUST encode `type` in the 2-byte form. **[WIR-217]** A sender MUST encode
`length` in the 4-byte form. Thus the capsule header is 6 bytes at each bucket.
RFC 9000 §16 permits a longer form than the minimum, and §6.1.1 rule 4 permits
one form only. **[WIR-218]** A receiver MUST reject a capsule whose `type` is
not `0x0B52` or `0x0B53`.

**The cell length comes from the capsule.** **[WIR-219]** A receiver MUST take
the cell length from `length`, and that length is `length` minus 12.
**[WIR-220]** A receiver MUST reject an `UMBRA_CELL` capsule whose `length` is
not 524, 2 060, 8 204, or 32 780. **[WIR-221]** A receiver MUST reject an
`UMBRA_SESSION` capsule whose `length` does not equal the length that §6.2.3
gives for its `op`.

**The WebSocket frame.** **[WIR-222]** A sender on the TCP transport MUST put
one capsule in one WebSocket binary frame with the FIN bit set. **[WIR-223]** A
sender MUST NOT put two capsules in one frame. **[WIR-224]** A sender MUST NOT
split a capsule across two frames. RFC 6455 §5.3 masks each client frame with a
4-byte key, and a relay frame carries no mask. Each capsule length is between
126 and 65 535 bytes, thus the frame header is 4 bytes at each bucket. A client
frame therefore adds 8 bytes, and a relay frame adds 4 bytes.

**The TLS record.** RFC 8446 §5.1 caps a record at 2¹⁴ bytes of plaintext.
**[WIR-225]** If a WebSocket frame fits one TLS record, the sender MUST put that
frame in one record. **[WIR-226]** If the frame does not fit one record, the
sender MUST split it across the smallest count of records. **[WIR-227]** A
sender MUST NOT put two frames in one record. **[WIR-228]** A sender MUST NOT
add record padding under RFC 8446 §5.4. Each record adds 22 bytes, which is the
5-byte header, the 1-byte inner content type, and the 16-byte tag. A `B3` frame
needs three records, and each other bucket needs one record.

§6.9 derives the wire cost of each bucket from these rules. The QUIC transport
carries the same capsules in one stream, and its packet cost differs. Each
budget of this specification uses the TCP figure.

> *Cause.* An earlier draft counted 29 bytes of framing at each bucket. That
> count was a 4-byte session identifier, a 3-byte sequence, a flag byte, and a
> 21-byte record expansion. That draft named no capsule and no WebSocket frame,
> and a `B3` cell exceeds the RFC 8446 record cap. Part 3 §3.8 mandates
> the capsule, and a capsule carries an explicit length. This section binds the
> cell length to that length, thus a receiver holds a delimiter without a
> bucket field (§6.3).

### 6.2.2 The session frame (L2)

L2 sits between the capsule of L1 and the cell of L3. It carries one cell, and
it gives the resend window of Part 3 §3.7 item 4 its cursor.

```
SessionFrame {
    session_id   [8]u8    // CSPRNG, one value for each session (§6.2.3)
    seq          [3]u8    // big-endian, the frame index in this session
    flags        u8       // bit 0: this frame is a resend. bits 1-7: zero
    cell         [L]u8    // the L3 cell, 512 / 2048 / 8192 / 32768
}
```

**The frame overhead is 12 bytes.** The capsule header adds 6 bytes, the client
WebSocket header adds 8 bytes, and one TLS record adds 22 bytes. Thus the L1
and L2 framing of a `B0` cell is 48 bytes, and §6.9 gives that cell a wire
cost of 560 bytes.

**[WIR-136]** A client MUST make `session_id` from the device CSPRNG at the
open of a session (§6.2.3). **[WIR-137]** A client MUST NOT reuse a `session_id`
across two sessions to one relay.

**[WIR-138]** A sender MUST increase `seq` by one for each frame, and it MUST
start at zero. **[WIR-139]** A sender MUST close the session before `seq` wraps.
A `u24` gives 16 777 216 frames, and `CIRCUIT_MAX_CELLS` of Part 3 §3.4.3 is
8 192, thus a wrap does not occur in a conformant session.

**[WIR-140]** A sender MUST set bit 0 of `flags` on a resend, and it MUST keep
`seq` at the value of the first transmission. **[WIR-141]** A receiver MUST
ignore a frame whose `seq` it already accepted. **[WIR-142]** A receiver MUST
reject a frame whose `flags` holds a non-zero value above bit 0.

> *Cause.* Part 3 §3.7 item 4 gives the client an in-flight window of 1 000 and
> one cursor for each queue, and neither value has a carrier below L5 without
> this frame. The frame is **not** a reliability layer of its own. TLS and QUIC
> give the ordering and the retransmission of L1, and the ARQ of Part 3 §3.7
> gives the end-to-end recovery. This frame gives the resend marker that lets a
> relay drop a duplicate without a decryption of the cell.
>
> `session_id` is not a client identifier. It lives for one session, which
> §6.2.3 ends, and `NET-022` already caps a session at 8 queues.

### 6.2.3 Session open, resume, and close

Part 3 §3.8 makes the session independent of the connection. A connection drop
rotates the connection, and the session continues. Three control records in an
`UMBRA_SESSION` capsule give that behavior a wire form.

```
SessionOpen {                     // op 0x01, 41 bytes
    op              u8
    session_id      [8]u8
    session_secret  [32]u8        // from the device CSPRNG
}

SessionResume {                   // op 0x02, 29 bytes
    op              u8
    session_id      [8]u8
    resume_count    u32           // 1 at the first resume of the session
    auth            [16]u8
}

SessionClose {                    // op 0x03, 9 bytes
    op              u8
    session_id      [8]u8
}

auth = HMAC-SHA3-256( session_secret,
                      "umbra/v1/session-resume" || session_id || BE32(resume_count) )[0..16]
```

| Parameter | Value |
| --- | --- |
| `SESSION_RESUME_WINDOW` | 4 hours. The relay measures it from the moment that it observes the close of the connection. The client measures it from the moment that it observes the same close |

- **[WIR-229]** A client MUST send a `SessionOpen` or a `SessionResume` as the
  first capsule of each transport connection. **[WIR-230]** A relay MUST close a
  connection whose first capsule is not one of those two records.
- **[WIR-231]** A client MUST draw `session_secret` from the device CSPRNG at
  each open. **[WIR-232]** A relay MUST hold `session_id`, `session_secret`, the
  next `seq`, and the accepted `seq` values for the life of the session.
  **[WIR-233]** A relay MUST close a connection whose `SessionOpen` names a
  `session_id` that a live session of that relay holds.
- **[WIR-234]** A client MUST set `resume_count` to 1 at the first resume of a
  session. **[WIR-235]** A client MUST increase `resume_count` by one at each
  later resume of that session. **[WIR-236]** A client MUST compute `auth` with
  the derivation above.
- **[WIR-237]** A relay MUST verify `auth` before it binds the connection to
  the session. **[WIR-238]** A relay MUST reject a `SessionResume` whose
  `resume_count` is not above the last value that it accepted. **[WIR-239]** If
  the verification fails, the relay MUST close the connection. **[WIR-240]** A
  relay MUST NOT report the cause of that close.
- **[WIR-241]** When a relay accepts a `SessionResume`, it MUST bind the session
  to the new connection. **[WIR-242]** If the previous connection of that
  session is open, the relay MUST close it.
- **[WIR-243]** A relay MUST hold the state of a session for
  `SESSION_RESUME_WINDOW` after it observes the close of the connection.
  **[WIR-244]** If the window ends with no accepted resume, the relay MUST
  discard that state. **[WIR-245]** If a client observed the close more than
  `SESSION_RESUME_WINDOW` before, it MUST open a new session.
- **[WIR-246]** If a client ends a session by its own choice, it MUST send a
  `SessionClose` before it closes the connection. **[WIR-247]** A relay MUST
  discard the session state when it receives a `SessionClose`. **[WIR-248]**
  Each party MUST erase `session_secret` when the session ends.
- **[WIR-360]** At the end of a push wake, a client MUST close the connection
  without a `SessionClose`. **[WIR-361]** If the next wake to that ingress
  starts inside `SESSION_RESUME_WINDOW`, the client MUST send a
  `SessionResume`. Rule `WIR-246` does not apply to that close, because the
  client does not end the session.

Part 5 §5.11 holds the label. A late resume fails at the relay, and the client
then opens a new session at the cost of one round trip. The two parties measure
two separate durations from one event, and no rule compares their clocks.

> *Cause.* An earlier draft gave the session a 4-byte identifier, no
> authenticator, and no rule for a relay that saw one identifier on two
> connections. Part 10 §10.9.1 sizes a held session at about 566 bytes each
> second. Thus a relay with 1 Gbit/s of egress carries about 220 000 sessions.
> The 32-bit birthday bound reached even odds near 77 000 sessions, and the
> 64-bit bound at 220 000 sessions is about 1.3 × 10⁻⁹.
>
> `NET-073` forbids TLS resumption and 0-RTT. This section resumes the L2
> session over a full TLS handshake, thus it takes nothing from that rule. The
> authenticator binds the resume to a secret that the open carried inside TLS,
> thus a party that guesses a `session_id` cannot take a session. Part 3 §3.7
> item 4 recovers the frames that were in flight at the drop, and this section
> adds no acknowledgment at L2.

> *Cause of the 4 hours.* An earlier draft set `SESSION_RESUME_WINDOW` to 60 s.
> A push wake of Part 8 §8.4.1 then opened a new session at each wake, and each
> new session paid a circuit build. Part 3 §3.4.3 sets `CIRCUIT_MAX_AGE` to 4
> hours, and a circuit does not outlive its session, thus the window is the same
> 4 hours. Part 3 §3.12 gives the builds that the resume saves. The cost has two
> parts. A relay holds the session state for 4 hours, which is about 1 KB. A
> resume links two wakes of one client across a network change. Part 16 §16.3
> records that residual.

## 6.3 Cell

```
Cell {
    circ_id         [16]u8        // rewritten by each hop; unlinkable across hops
    tag             [16]u8        // UIV+ / POLYVAL rugged-PRP tag for this hop
    body            [L]u8         // L in {480, 2016, 8160, 32736}
}                                 // total = 512 / 2048 / 8192 / 32768
```

**The onion overhead is 32 bytes, and it is constant at each hop.** There is no
KEM material in a cell. The circuits are telescoped, thus a client pays the KEM
cost one time at the build (Part 3 §3.4.3). The cell size does not change along
the path. Thus the wire does not show the path length, and it does not show the
circuit position.

The total cell length gives the bucket. There is no bucket field. A field that
gives a size that the receiver knows is a free malleability surface.

In `body`, the first byte after the decryption is a command:

```
0x00  PADDING     rest of body is padding
0x01  RELAY       forward to the next hop
0x02  DATA        queue command for this hop (see 6.4)
0x03  EXTEND      circuit extension (build only), carries HopHello, Part 3 §3.4.3
0x04  EXTENDED    circuit extension response, carries HopReply, Part 3 §3.4.3
0x05  DESTROY     tear down
0x06  LOOP        cover cell to be reflected back to the originator
0x07  MEAS_ECHO   measurement echo, Part 10 §10.3
0x08  MEAS_OPEN   measurement session open, Part 10 §10.3.1
```

**[WIR-135]** A relay MUST reject a cell whose command byte is above `0x08`. The
list above is closed, and §6.1.1 rule 4 permits one canonical form only.

`MEAS_OPEN` carries the `MeasurerCert` of Part 10 §10.3.1. Requirement
`REL-068` makes a relay reject a `MEAS_ECHO` cell outside a measurement session
that a `MEAS_OPEN` cell opened. **[WIR-143]** A measurer MUST send a
`MEAS_OPEN` cell in bucket `B3`. §10.3.1 gives the certificate 8 598 bytes at
two signatures, and `REL-065` adds a 3 309-byte session signature. Thus the
payload exceeds the 8 074-byte `B2` payload of §6.9.

`MEAS_ECHO` carries the saturating echo of Part 10 §10.3 over the `B0` cell.
Requirement `REL-002` makes a relay decrypt each `MEAS_ECHO` cell that a
measurer sends to it, and `REL-003` gives the response rule. §10.4.1 makes the
cell indistinguishable from a loop cover cell to each party but the two
endpoints of the measurement.

> **These byte values are cell commands.** The value `0x01` is `RELAY` here,
> `NEW` in §6.4, an L6 ratchet record in §6.4.2, `hdr` in §6.5, and Text in
> §6.6. The value `0x02` is `DATA` here, `IDS` in §6.4, an L6 sender-key record
> in §6.4.2, `ek` in §6.5, and an attachment descriptor in §6.6. The value
> `0x04` is `EXTENDED` here, `ct2` in §6.5, and Edit in §6.6. The value `0x05`
> is `DESTROY` here, `mac` in §6.5, and Delete in §6.6. The value `0x07` is
> `MEAS_ECHO` here, and §6.4 gives it no queue command. Rule 7 of §6.1.1 keeps
> them apart.

**[WIR-011]** The padding in `body` MUST be zero bytes after one marker byte of `0x80`. This
is the ISO/IEC 7816-4 style. **[WIR-012]** A receiver MUST verify the padding
pattern. **[WIR-013]** A receiver MUST reject malformed padding.

> Padding code is easy to make incorrectly, and it is on the path of each
> message. Trail of Bits found this class of bug in SimpleX in November 2022.
> The padding function failed for longer messages, and the unpadding function
> threw an exception for shorter messages. Test vectors for the padding at each
> bucket boundary are mandatory.

## 6.4 Queue commands (L5)

```
Command {
    version         u8            // 0x01
    cmd             u8            // see table
    corr_id         [16]u8        // random, unique for each command
    queue_id        [32]u8        // RecipientId, SenderId, ChunkId, or community_id, by cmd
    auth            [32]u8        // deniable authenticator (Part 3 §3.2.3)
    payload_len     u16
    payload         [payload_len]u8
}
```

The command header is 84 bytes. The field `auth` is 32 bytes and it is a MAC. **[WIR-014]** A
party MUST NOT compute `auth` as an AEAD ciphertext.

| `cmd` | Name | Sent by | Payload |
| --- | --- | --- | --- |
| `0x01` | `NEW` | Recipient | 2 public keys, requested params, then an `Admission` of Part 14 §14.2 |
| `0x02` | `IDS` | Relay | `RecipientId`, `SenderId`, relay DH pk |
| `0x10` | `SEND` | Sender | L6 record |
| `0x11` | `MSG` | Relay | `seq` `u32`, L6 record |
| `0x12` | `ACK` | Recipient | `seq` `u32`, cumulative |
| `0x20` | `SUB` | Recipient | — |
| `0x21` | `UNSUB` | Recipient | — |
| `0x30` | `NKEY` | Recipient | notifier public key |
| `0x31` | `NID` | Relay | `notifier_id` |
| `0x40` | `DEL` | Recipient | — |
| `0x50` | `QUOTA` | Relay | remaining capacity |
| `0x51` | `NACK` | Relay | `NackPayload`, 17 B, §6.4.4 |
| `0x60` | `COVER` | Sender or recipient | zero-filled, indistinguishable from `SEND` and `MSG` |
| `0x70`–`0x7B` | Attachment commands | Uploader, downloader, or relay | Part 13 §13.3.3 gives the twelve commands and their payloads |
| `0x80`–`0x83` | Community commands | Subscriber, publisher, or relay | Part 12 §12.3.3 gives the four commands and their payloads |

**[WIR-015]** `COVER` MUST be bit-indistinguishable from a real command after the L4
encryption. A relay that makes inbound pacing cover (Part 3 §3.5.2) emits cells
with the shape of `MSG`.

Part 13 §13.3.3 gives the attachment commands. Those commands put a `chunk_id`
in `queue_id`. **[WIR-107]** An attachment command MUST travel on the separate connection of
Part 13 §13.8. **[WIR-108]** A client MUST NOT batch an attachment command with a queue
command.

**One attachment command travels between two relays.** `CRPUT` of Part 13
§13.4.1 carries a chunk from the relay that holds it to a replica relay.

Part 12 §12.3.3 gives the community commands. Those commands put a
`community_id` in `queue_id`. **[WIR-309]** A community command MUST travel on
a transport session that carries no queue command. **[WIR-310]** A client MUST
NOT batch a community command with a command of another range.

> *Cause.* A pull carries no client identifier (Part 12 §12.3.1). A queue
> command in the same session would give the relay one, because a queue names
> its recipient. The batch rule keeps a `Cell` inside one range. Thus a relay
> that serves a queue and a community reads no pull beside a queue command.

- **[WIR-211]** A relay MUST send a `CRPUT` on a direct transport session to
  the target relay. **[WIR-212]** A relay MUST NOT send a `CRPUT` over a client
  circuit.
- **[WIR-213]** A `CRPUT` MUST carry a `payload_len` of 32 682, which is the
  32-byte `storage_token` and `CHUNK_SIZE`. That length is above the `B3` L5
  payload of §6.9, and a `CRPUT` sits in no cell and in no bucket.
- **[WIR-214]** A client MUST NOT send a `CRPUT`. **[WIR-215]** A relay MUST
  reject a `CRPUT` that arrives over a circuit.

> *Cause.* A relay-to-relay transfer has a relay at each end, thus no party of
> that transfer is a user. Part 3 §3.3 pads a cell to hide a user record, and
> that measure buys nothing here. The direct session also keeps the 2 hops of
> onion overhead off a transfer that carries no user address.

### 6.4.1 Batching

**[WIR-016]** A client MUST pack each command that is ready together into one cell, up to
the command area of the bucket. **[WIR-109]** A client MUST NOT send a cell that carries one
command when a second ready command fits the command area of that cell.
**Batching is mandatory and it is not optional.** Without batching, an `ACK` of
88 bytes costs a full cell, and the fixed-size design then destroys the mobile
data budget. Part 12 §12.4.1 rule 4 depends on this rule.

A `SEND` and a `MSG` each take the command area of the bucket (§6.4.2 rule 6). A
`MSG` fills that area exactly, and a `SEND` leaves 4 bytes. Thus a client packs
only a command that carries a small payload or no payload.

### 6.4.2 Queue end-to-end record (L6)

The payload of `SEND` and the payload of `MSG` carry one queue end-to-end
record.

```
QueueE2E {
    version   u8        // 0x01
    nonce     [12]u8    // random, from the device CSPRNG
    ct        [n]u8     // ChaCha20-Poly1305 output, and it holds the 16-byte tag
}
```

1. **[WIR-017]** A party MUST key the record with `K_QE`. The derivation is
   `K_QE = HKDF-SHA3-256("umbra/v1/queue-e2e", QE, SenderId)`. The
   value `QE` is the 32-byte per-queue secret of Part 3 §3.2.2.

   > *Cause.* An earlier draft put `RecipientId || SenderId` in the info string.
   > A sender has to compute `K_QE` to seal a `SEND`, thus that draft made the
   > sender hold `RecipientId`. Part 3 §3.2.1 states that `RecipientId` is known
   > only to the queue owner, and rule `NET-117` of that section states the
   > prohibition. `SenderId` is unique to the queue and the queue address
   > carries it, thus it gives the derivation the same separation.
2. **[WIR-018]** A party MUST use ChaCha20-Poly1305 with a 12-byte nonce and a 16-byte tag.
   **The L6 overhead is 32 bytes.** That total is 1 byte of `version`, 12 bytes
   of `nonce`, and the 16-byte tag. It also holds the 2-byte true length of rule
   5, which sits inside the ciphertext. **[WIR-106]** A revision MUST count that true
   length in each capacity row of §6.9.
3. **[WIR-019]** A sender MUST draw `nonce` from the device CSPRNG for each record.
   **[WIR-020]** A sender MUST NOT use a counter. **[WIR-021]** A sender MUST NOT
   repeat a nonce under one `K_QE`.
4. **[WIR-022]** A party MUST bind `version || SenderId` as the associated data.
5. The plaintext starts with a `u16` true length and then a `u8` L6 record kind.
   The value `0x01` names a ratchet record (§6.5), and the value `0x02` names a
   sender-key record (Part 11 §11.3). The value `0x03` names a report record
   (Part 12 §12.5.3). The value `0x04` names a `NotifyDigest` (Part 12 §12.6.4).
   **[WIR-023]** A receiver MUST reject an unknown kind.
6. **[WIR-024]** **A sender MUST fill the L6 record to a fixed length for the bucket.** That
   length is the "L6 record on a `MSG`" row of §6.9. That row gives 390 bytes at
   bucket `B0`. **[WIR-025]** Thus the `payload_len` of a `SEND` MUST equal that row.

   **[WIR-026]** The `payload_len` of a `MSG` MUST equal the L5 payload row of §6.9. That row
   gives 394 bytes at bucket `B0`. A `MSG` payload carries a `u32` sequence
   number before the L6 record, thus the two lengths differ by 4 bytes.

   **[WIR-027]** A receiver MUST take the true length from the `u16` inside the ciphertext. **[WIR-028]** A
   sender MUST fill the remainder with zero bytes inside the ciphertext. A relay
   prepends the sequence number to the L6 record that the `SEND` carried. **[WIR-029]** A
   relay MUST NOT move the message to a different bucket at that step.

   The command header of §6.4 is 84 bytes, and it sits inside the command area.
   Thus a `MSG` fills the command area exactly: 84 + 394 = 478 at bucket `B0`. A
   `SEND` reaches 84 + 390 = 474 and leaves 4 bytes. The cell padding of §6.3
   covers those 4 bytes.

> *Cause.* A relay parses `payload_len` in the clear. A sender-key record skips
> L7. Thus without this rule a relay reads the exact plaintext length. A relay
> then separates a group record from a pairwise record by that length alone.
> Part 11 §11.5 and G11 do not permit that result. The cell is padded to the
> bucket in any case, thus this rule costs no wire byte and no cell.

7. A relay reads the version, the nonce, and the bucket only. Thus a relay
   cannot tell a group record from a pairwise record. This rule is the wire half
   of Part 11 §11.5.
8. **[WIR-030]** A receiver MUST reject a record with an unknown version.
   **[WIR-031]** A receiver MUST reject a record whose tag does not verify.
   **[WIR-032]** A receiver MUST NOT report which check failed.
9. **[WIR-033]** A sender MUST make a new queue before the message count of that queue reaches
   `ROTATE_AFTER` (Part 3 §3.2.4).
10. **[WIR-034]** On a group send, a sender MUST draw a fresh nonce for each recipient. **[WIR-035]** The
    test vectors of §6.8 MUST hold a group send to 3 recipients. **[WIR-036]** Those vectors
    MUST assert that the three records differ. **[WIR-037]** Those vectors MUST assert that
    the three plaintexts are equal. **[WIR-038]** Those vectors MUST also assert that a
    20-byte group text and a 20-byte pairwise text give one `payload_len`.

### 6.4.3 Queue teardown, acknowledgment, and the absence of a sender withdrawal

1. `DEL` deletes the queue. The recipient sends it, `QR_auth` authorizes it, and
   the payload is empty.
2. **[WIR-039]** On a `DEL`, a relay MUST erase the queue record and each stored ciphertext. **[WIR-040]** A
   relay MUST also erase the sequence counter and the link between the
   `RecipientId` and the `SenderId`. **[WIR-041]** **A relay MUST NOT retain an identifier of
   a deleted queue. [WIR-042] A relay MUST NOT keep a record that a queue existed.** A
   later command that names an unknown identifier gets a `NACK` with reason
   `REJECTED` (§6.4.4), which is the response to a failed `auth` also.
3. **[WIR-043]** At the end of a queue rotation, a client MUST send `DEL` to the old relay
   (Part 3 §3.2.4). **[WIR-044]** A client MUST send each `DEL` at an independent delay with
   the rotation jitter of Part 3 §3.2.4. **[WIR-045]** A client MUST NOT send more than one
   `DEL` in one transport session.
4. **[WIR-046]** **A client MUST NOT send `DEL` at a device revocation.** Part 7 §7.7 step 2b
   makes an immediate DH ratchet step and step 2c makes a fresh queue. Those two
   steps cut the revoked device. A `DEL` at that moment names a set of queues at
   one instant. Two colluding relays then link those queues to one person (A3,
   G7).
5. A relay gives each accepted `SEND` a sequence number. That number is a `u32`
   and it starts at 1 on a new queue. That number counts up by one for each
   accepted message on that queue. **[WIR-047]** A relay MUST NOT derive the sequence number
   from the ciphertext, because §6.1.1 rule 5 forbids that derivation.
6. `MSG` carries the sequence number of the message that it delivers. **[WIR-110]** A relay
   MUST emit each `MSG` of a queue that it holds and that no `ACK` covers.
   **[WIR-111]** A relay MUST NOT erase a message before `MSG_TTL` and before an `ACK`
   covers it. The randomized delay of Part 3 §3.5.3 gives the emission order,
   thus a gap in the arrival order can close by itself.
7. `ACK` carries one sequence number and it is cumulative. `QR_auth` authorizes
   it. An `ACK` names a sequence number `s`. **[WIR-048]** A relay MUST then delete each
   message on that queue with a sequence number at or below `s`.

   **An `ACK` does not reach the sending device.** An `ACK` is an instruction to
   the relay. **[WIR-049]** A relay MUST NOT forward an `ACK` to the sender. Part 7 §7.5.5
   gives the device-set acknowledgment, which is an application record on the
   reverse sync queue.

   **A cumulative `ACK` deletes each message below the named number, thus an
   `ACK` across a hole destroys a message that no party delivered.** Four rules
   close that path.

   - **[WIR-112]** A recipient MUST NOT send an `ACK` that names `s` before it received
     each message of that queue at or below `s`.
   - **[WIR-113]** If the lowest sequence number that a recipient did not receive is `h`, that
     recipient MUST set `s` below `h`.
   - **[WIR-114]** A recipient MUST count a record that it stored under rule 8 as received.
     An undecryptable record is a received record, and it is not a hole.
   - **[WIR-115]** A recipient MUST NOT acknowledge a `MSG` before it commits that record to
     the local database.

   A hole can stay open. A relay that holds a message and does not emit it
   blocks the acknowledgment point, and `QUEUE_QUOTA` then stops the queue. Two
   rules bound that state.

   - **[WIR-116]** If a hole at `h` stays open for `ACK_HOLE_TIMEOUT`, a recipient MAY send an
     `ACK` above `h`. Part 3 §3.2.4 gives `ACK_HOLE_TIMEOUT`.
   - **[WIR-117]** A recipient that acknowledges above a hole MUST show a delivery gap for
     that conversation. **[WIR-118]** That recipient MUST NOT show the conversation as
     complete.

   > *Cause.* The relay assigns the sequence number, thus a hole is a statement
   > by the relay and it is not evidence of a loss (rule 9 below). But a
   > cumulative acknowledgment across that hole makes the statement true. The
   > recipient then holds no copy, the relay holds no copy, and no party can
   > tell that the message existed. `ACK_HOLE_TIMEOUT` trades that outcome
   > against a queue that a hostile relay can freeze.

8. **[WIR-050]** A recipient MUST store a record that it cannot decrypt before it acknowledges
   a later record. Thus a decryption retry after a ratchet repair stays possible,
   and Part 11 §11.3.2 can request a missing sender-key generation.
9. **[WIR-051]** A recipient MAY use a hole in the sequence to find that a relay did not
   deliver a message. **[WIR-052]** A recipient MUST NOT treat the sequence as proof of a
   loss, because the relay assigns the sequence.
10. **[WIR-053]** A client MUST NOT use the sequence number as a message identifier. The
    number has queue scope, a relay assigns it, and a rotation resets it.
11. **The protocol gives no sender-side withdrawal.** No command withdraws an
    enqueued ciphertext. **[WIR-054]** A relay MUST reject a delete command that `QS_auth`
    authorizes.
12. To recall a message that a recipient already holds, a client sends the
    tombstone of §6.6, which is kind `0x05`. That mechanism is a request to the
    client of the recipient. **[WIR-055]** A client MUST NOT show a deletion as an
    enforcement.

> *Cause.* A withdrawal delivers no security property. The relay is the party
> that would have to obey, and a relay that reports a deletion can keep the
> ciphertext. A withdrawal also gives the holder of `QS_auth` a destructive
> action on the queue of the recipient. GHSL-2026-082 and GHSL-2026-095 record
> that exact class of defect in a shipped messenger in 2026.

### 6.4.4 The rejection, `NACK`

A relay rejects a command under about 140 rules of this specification, and
`QUOTA` was the one rejection with a wire form. A client could not tell an
authorization failure from a dropped cell, a relay outage, or a queue that
`WIR-039` erased. Each of the four looked like the absence of an inbound cell,
which Part 3 §3.5.2 fills with a cover cell. `NACK` gives each rejection one
wire form. It travels in the place of a cover cell, thus it adds no cell that an
observer can count.

```
NackPayload {                     // 17 bytes
    corr_id         [16]u8        // the corr_id of the rejected command
    reason          u8            // the table below
}
```

| `reason` | Name | The relay sends it when |
| --- | --- | --- |
| `0x01` | `REJECTED` | the relay does not hold the object of `queue_id`, `auth` does not verify, `corr_id` repeats under `NET-122`, or the payload does not parse |
| `0x02` | `ADMISSION` | the admission control of Part 14 refuses the command, and a credential of Part 14 §14.2 would admit it |
| `0x03` | `LIMIT` | a rate limit or a size bound of this specification rejects the command, and a later retry can pass |
| `0x04` | `BUSY` | the relay holds no capacity for the command, in the sense of Part 13 rule `ATT-091` |
| `0x05` | `VERSION` | the `version` of the command is not one that the relay serves |

**The list above is closed.** A rejection rule of this specification maps onto
one row. A rule that names no row maps onto `REJECTED`. The object of
`queue_id` is a queue, a chunk, or a community.

1. **[WIR-313]** A relay MUST answer a command that it rejects with one `NACK`.
   **[WIR-314]** That `NACK` MUST carry the `corr_id` of the rejected command.
   **[WIR-315]** A relay MUST select `reason` from the table above.
   **[WIR-316]** A relay MUST NOT send a `reason` outside the table.
2. **[WIR-317]** A relay MUST send `REJECTED` for an unknown `queue_id` and
   for a failed `auth` alike. A second value would tell the sender that a queue
   exists, and `WIR-041` and `WIR-042` close that oracle.
3. **[WIR-318]** If the command header of §6.4 does not parse, the relay MUST
   drop the cell without a `NACK`. The header holds `corr_id`, thus no answer
   can name the command.
4. **[WIR-319]** A relay MUST send a `NACK` on the circuit that carried the
   command, in bucket `B0`. **[WIR-320]** A relay MUST send a `NACK` in the
   place of the cover cell of an inbound pacing tick. Part 3 §3.5.2 gives the
   tick. **[WIR-321]** A relay MUST NOT send a `NACK` outside a tick.
   **[WIR-322]** A relay MUST send a pending `NACK` before a pending `MSG` of
   the same session.
5. **[WIR-323]** A client MUST discard a `NACK` whose `corr_id` names no
   command of the same transport session. **[WIR-324]** A client MUST NOT send
   the same command bytes again after a `REJECTED` or a `VERSION`.
   **[WIR-325]** After an `ADMISSION`, a client MUST obtain the credential of
   the Part 14 §14.2 row before it sends again. That row is the row of the path
   of the command.
6. **[WIR-326]** A client MUST NOT report a `reason` to a party other than the
   user. Rule `WIR-032` keeps the failed check of a receiver inside the device
   that observed it, and this rule applies the same bound to a `NACK`.
7. A `NACK` and a `QUOTA` are two signals. `QUOTA` under `NET-017` reports the
   state of a queue that accepted the command, and a `NACK` reports a command
   that the relay did not accept.

> *Cause.* A typed rejection costs one retry where a silent drop cost a
> timeout, and Part 14 §14.8 makes the difference visible. A relay under load
> raises its proof-of-work effort. A client that holds a stale effort gets an
> `ADMISSION` in one tick and a fresh challenge from the directory. Without
> the signal that client waits for a delivery that never comes. Five reasons
> are few by design. SMP defines a wider taxonomy, and each extra value that
> separates a state of the relay from another is one more oracle.

## 6.5 Ratchet record (L7)

```
RatchetRecord {
    version         u8            // 0x02
    ctx             RatchetCtx    // 4 bytes, outside hdr_ct and body_ct
    hdr_nonce       [12]u8
    hdr_ct          [56]u8        // AEAD(header_key): dh_pk 32 | pn 4 | n 4 | tag 16
    pq_frame_len    u8            // 0, 39, 71, or 135
    pq_frame        [pq_frame_len]u8
    body_nonce      [12]u8
    body_ct         [...]u8       // AEAD(message_key), includes 16 B tag
}

RatchetCtx {
    session_tag     [2]u8         // SHA3-256( "umbra/v1/session-tag" || RK )[0..2]
    send_index      u16           // the low 16 bits of the record count of
                                  // this sender in this session
}

PqFrame {
    epoch           u32           // the braid epoch of Part 5 §5.5.2, big-endian
    kind            u8            // 1 hdr, 2 ek, 3 ct1, 4 ct2, 6 parity
    index           u16
    chunk           [w]u8         // w in {32, 64, 128}
}
```

The ratchet record less the body is 86 bytes, and a braid frame is 7 bytes plus
the chunk width. Part 5 §5.6 counts both, and §6.9 takes the figures from
there.

The ratchet header **always carries encryption**. Cleartext `dh_pk`, `pn`, and
`n` fields let a relay link records into sessions and profile the cadence of a
conversation.

**The context field.** `RK` is the initial root key that the split of Part 5
§5.4.8 gives. Thus the two parties of one session derive one `session_tag`.
The L6 layer of §6.4.2 encrypts the full record, thus a relay reads no field of
`ctx`. The queue peer reads the field without a header key. Part 5 §5.11 holds
the label.

- **[WIR-249]** A sender MUST compute `session_tag` with the derivation above.
  **[WIR-250]** A sender MUST set `send_index` to zero on the first record of a
  session. **[WIR-251]** A sender MUST increase `send_index` by one for each
  later record of that session, modulo 65 536.
- **[WIR-252]** A receiver MUST read `ctx` before it decrypts `hdr_ct`.
  **[WIR-253]** If a receiver cannot decrypt `hdr_ct`, it MUST classify the
  failure from `session_tag`, from `send_index`, and from the `epoch` of the
  braid frame. **[WIR-254]** A receiver MUST use `send_index` to find the hole
  that Part 7 §7.5.6 rule `DEV-097` names.
- **[WIR-255]** A receiver MUST reject a `version` that is not `0x02`.

Part 2 §2.4 rule `THR-009` names a session identifier, a ratchet epoch, and a
message index. This field carries the first and the third, and the braid frame
carries the second.

**The braid frame.** **[WIR-256]** A sender MUST set `epoch` to the epoch of
Part 5 §5.5.2, which rule `CRY-064` binds as `BE32(epoch)`. **[WIR-257]** A
receiver MUST reject a `pq_frame_len` that is not 0, 39, 71, or 135.
**[WIR-258]** A receiver MUST reject an `index` at or above the chunk total *n*
that Part 5 §5.5.2 gives for the width. **[WIR-349]** A receiver MUST reject a
`kind` of `0x00`, of `0x05`, or of `0x07` or above. Part 5 rule `CRY-082`
gives `kind` for a data chunk, and rule `CRY-129` gives the parity value.

> *Cause of the `kind` values.* An earlier draft listed `0 none` and `5 mac`.
> A frame with no chunk has `pq_frame_len` zero and no `kind` byte, thus the
> value `0x00` named no frame. The codeword of Part 5 §5.5.2 carries no MAC,
> because the hash in `header` checks the rebuilt key. The parity chunks had
> no value. The value `0x05` stays retired.

> *Cause of the epoch width.* An earlier draft gave `epoch` one byte, and Part 5
> §5.5.3 forces a new epoch every 100 messages or 7 days. A busy pair reached
> epoch 256 inside 25 600 messages, and the two sides then derived different
> root keys under `BE32(epoch)`. The three added bytes cost 3 bytes of `B0`
> text.
>
> *Cause of the context field.* An earlier draft put the session identifier and
> the message index inside `hdr_ct` only. A receiver that lost the header key
> could not read them in the one case where `THR-009` needs them.

## 6.6 Application messages (L8)

```
AppMessage {
    version         u8            // 0x02
    kind            u8
    msg_id          [16]u8        // message identifier, from the device CSPRNG
    sent_at         u64           // milliseconds; sender clock, advisory only
    body_len        u32
    body            [body_len]u8
}
```

`AppMessage` version `0x02` carries `msg_id`, which is 16 bytes. The field
`msg_id` is at layer L8. Thus it is above each encryption layer of §6.2, and it
does not change at L1, at L4, at L6, or at L7.

One logical message carries one `msg_id` at the sender and at each device of
the sender. That message carries the same `msg_id` at each recipient and at each
device of each recipient. The value is the same on each sync channel of Part 7
§7.5.1. The L6 ciphertexts still differ for each recipient, as Part 11 §11.3
requires.

Each tier of Part 11 §11.2 carries `msg_id`. Tier T1 has no group cryptography,
and tier T1 carries an `AppMessage` on each pairwise channel. Thus tier T1 has a
message identifier. Part 11 §11.2.1 wraps each group record in a `GroupRecord`
of kind `0x12`, and §6.6.2 gives that structure.

**[WIR-056]** A sender MUST draw `msg_id` from the device CSPRNG. **[WIR-057]** A sender MUST NOT derive
`msg_id` from the content or from a counter. **[WIR-058]** A sender MUST NOT use a value that
a different conversation also holds.

**[WIR-059]** A sender MUST draw a new `msg_id` for each message and for each conversation.
**A group is one conversation.** **[WIR-060]** A group send MUST carry one `msg_id` to each
member. That rule applies to tier T1, to tier T2, and to tier T3 of Part 11
§11.2. **[WIR-061]** An edit or a tombstone MUST name the `msg_id` of the target.

> *Cause.* A moderation epoch of Part 11 §11.9.6 names one `msg_id` for a
> target. A per-recipient value in tier T1 matched the history of one recipient
> only, thus a moderator could not act on a tier T1 post.
>
> The G9 cost of one shared value is zero inside a group. Part 11 §11.5 states
> that a member learns the roster, thus two members already know that they share
> the sender. The value travels inside the AEAD of a pairwise channel, thus no
> party outside the group reads it. Part 11 §11.2.1 gives the full statement.
>
> The rule against a shared value across two **different** conversations stays.
> WIR-058 forbids one value in two conversations, and WIR-062 makes a forward
> and a re-share new messages.

**[WIR-062]** A client MUST NOT copy a `msg_id` that it received from a peer. A forward, a
quote, and a re-share are new messages. **[WIR-063]** A sender MUST draw a new `msg_id` for
each one.

**[WIR-064]** A sender MUST NOT use one `msg_id` two times on one chain. **[WIR-065]** A receiver MUST
reject the second use. **[WIR-066]** A receiver MUST NOT change a record that the first use
named. The triple of conversation, sender, and `msg_ref` is one address. Part 7
§7.5.3 deduplicates on that address. Part 7 §7.5.6 builds the edit and the
deletion on it.

**The stored reference is `msg_ref`.** **[WIR-067]** A client MUST derive
`msg_ref = SHA3-256(K_set || msg_id)` truncated to 16 bytes. The value `K_set`
is the `DeviceSetKey` of Part 4 §4.2. **[WIR-068]** A client MUST use `msg_ref` for each
stored reference to a message. Those stored references are the deduplication
address of Part 7 §7.5.3 and the retransmission key of Part 7 §7.5.5. They also
include the edit target and the deletion target of Part 7 §7.5.6.

**[WIR-069]** A client MUST NOT store a raw `msg_id` as a key, as an index, or as a join
column. Each device of one device set holds one `K_set`, thus each device
derives the same `msg_ref`. A device set therefore deduplicates and orders on
`msg_ref` across the set. The wire carries the raw `msg_id`.

A record that a client has not yet delivered needs the raw value again at the
send. **[WIR-070]** Thus a client MAY hold a raw `msg_id` inside the stored body of an
undelivered record. Part 7 §7.5.5 rule 1 retains an unacknowledged sync record,
and Part 3 §3.5.4 holds a queued receipt. **[WIR-071]** A client MUST erase that raw value
when the retention ends. **[WIR-072]** A client MUST NOT index such a body by the raw value. **[WIR-073]** A
client MUST NOT copy that raw value into a different row.

> *Cause.* One logical message carries one `msg_id` at each device of the sender
> and at each device of each recipient. A raw stored key is thus a direct join
> key between two seized devices, and between two seized parties (A6, G9). The
> keyed value gives no such join, because a different device set uses a
> different `K_set`. An undelivered body is not a key, and no index reaches it.
> Part 7 §7.5.5 rule 5 bounds that retention at `SYNC_MAX_AGE`, and Part 3
> §3.5.4 bounds the receipt hold at `RECEIPT_MAX_HOLD`.

| `kind` | Meaning | Class (Part 7 §7.5.3) |
| --- | --- | --- |
| `0x01` | Text | Insertion |
| `0x02` | Attachment descriptor (Part 13) | Insertion |
| `0x03` | Reaction (§6.6.9) | Insertion |
| `0x04` | Edit | Revision |
| `0x05` | Delete (tombstone) | Tombstone |
| `0x06` | Delivery receipt (§6.6.9) | Peer signal |
| `0x07` | Read receipt (§6.6.9) | Peer signal |
| `0x08` | Typing indicator (§6.6.9) | Ephemeral |
| `0x09` | Rich record (§6.6.5) | The class of `inner_kind` |
| `0x0A` | Poll (§6.6.6) | Insertion |
| `0x0B` | Poll vote (§6.6.6) | Insertion |
| `0x0C` | Contact share (§6.6.7) | Insertion |
| `0x0D` | Community repost (Part 12 §12.6.2), inside a `CommunityPost` only | Insertion |
| `0x0E` | Community contact (Part 12 §12.6.3), inside a `CommunityPost` only | Insertion |
| `0x10` | Group control (§6.6.3, Part 11) | Control |
| `0x11` | Community record (Part 12 §12.4.4), inside a report record only | Control |
| `0x12` | Group record (§6.6.2, Part 11 §11.2.1) | The class of `inner_kind` |
| `0x20` | Device-set sync (Part 7) | Mutable state or control, by the sub-kind |
| `0x30` | Key-change notice (Part 4 §4.5.1) | Control |
| `0x31` | Transparency digest (§6.6.4, Part 9 §9.5.3) | Control |
| `0x32` | Conversation timer (§6.6.8, Part 7 §7.5.8) | Control |
| `0x33` | Queue address (§6.6.10, Part 3 §3.2.6) | Control |
| `0x34` | Key request (§6.6.11, Part 2 §2.4 U9) | Control |
| `0x35` | Key supply (§6.6.11) | Control |
| `0x36` | Verification commit (Part 4 §4.5.2) | Ephemeral |
| `0x37` | Verification reveal (Part 4 §4.5.2) | Ephemeral |

**[WIR-362]** A parser MUST reject a body of kind `0x36` or `0x37` whose
length is not 32. Part 4 §4.5.2 gives the two layouts.

For kind `0x01` the body is UTF-8 text with no further structure.
**[WIR-259]** A parser MUST reject a body of kind `0x01` that is not valid
UTF-8. For kind `0x03`, for kind `0x06`, for kind `0x07`, and for kind `0x08`,
§6.6.9 gives the body. Part 3 §3.5.4 sets `RECEIPT_BATCH_MAX` and gives the
emission rules of a receipt.

For kind `0x20`, the body starts with a `u8` sub-kind. The value `0x01` names
mutable state and the value `0x02` names a control record. Part 7 §7.5.3 gives
the class of each value. Part 7 §7.5.5 gives the `DeviceSetControl` structure
that sub-kind `0x02` carries, and it gives the device-set control type
namespace.

For kind `0x10` the body is a `GroupControl`, and §6.6.3 gives that structure.
For kind `0x31` the body is a `DigestBody`, and §6.6.4 gives that structure.
For kind `0x33` the body is a `QueueAddress`, and §6.6.10 gives that structure.

**Kind `0x11` carries a community record.** Its type namespace is the
community record type of Part 12 §12.4.4, and the body starts with the
`version` and `type` bytes of that namespace. One carrier holds that kind,
which is the report record of Part 12 §12.5.3. **[WIR-144]** A parser MUST
reject a body of kind `0x11` whose `type` is not `0x07`. **[WIR-145]** A parser
MUST reject an `AppMessage` of kind `0x11` that arrives in a ratchet record or
in a sender-key record.

> *Cause.* An earlier draft reserved this kind, and `WIR-144` required a type
> namespace before an object used it. The report record is that object, and
> the two rules now bound the kind to its one carrier. Part 12 delivers each
> other community object over the pull path of §12.3.3.

**Kinds `0x0D` and `0x0E` travel inside a community post only.** For kind
`0x0D` the body is a `RepostBody`, and Part 12 §12.6.2 gives that structure.
For kind `0x0E` the body is a `CommunityContact`, and Part 12 §12.6.3 gives
that structure. **[WIR-359]** A parser MUST reject an `inner_kind` of `0x0D`
or of `0x0E` in a ratchet record or in a sender-key record.

For kind `0x04` the body is an `EditBody`, and for kind `0x05` the body is a
`DeleteBody`. §6.6.1 gives the two structures. Part 7 §7.5.6 gives the edit
window, the authorization, and the interface rules.

Each kind of this table is in exactly one class of Part 7 §7.5.3. **[WIR-074]** A new kind
MUST declare its class in this table. **[WIR-075]** A client MUST NOT process a kind that
declares no class.

> **These byte values are application kinds.** A cell command of §6.3 and a
> queue command of §6.4 use the same byte values with different meanings. An L6
> record kind of §6.4.2 and a `PqFrame` kind of §6.5 also do.

The field `sent_at` is **advisory only**. **[WIR-076]** An implementation MUST NOT use it for
a security decision, for an ordering guarantee, or for a replay check. Mobile
clocks are unreliable, and an attacker can influence them. The sender-chain
position and the local insertion sequence give the order (Part 7 §7.5.3).

**[WIR-077]** Typing indicators (`0x08`) MUST be off by default. They multiply the message
rate by about a factor of ten. They also push a conversation into the traffic
regime where correlation attacks operate best.

### 6.6.1 The edit body and the delete body

```
EditBody {
    version     u8            // 0x01
    target      [16]u8        // the `msg_id` of the message that this record edits
    new_body    [body_len - 17]u8
}

DeleteBody {
    version     u8            // 0x01
    scope       u8            // 0x01 the devices of one user, 0x02 the other party
    targets     [k][16]u8     // k = (body_len - 2) / 16
}
```

**The edit body.** There is no inner length field, because `body_len` gives the
size. **[WIR-078]** A parser MUST reject a `body_len` below 18. **[WIR-079]** A parser MUST reject a
`new_body` that is not valid UTF-8. **[WIR-080]** A receiver MUST resolve the
target of an edit through each `GroupRecord` wrapper and each `RichRecord`
wrapper. **[WIR-260]** A receiver MUST apply an edit only when the innermost
kind of the target is `0x01`. **[WIR-081]** A receiver MUST reject an edit that names an attachment
descriptor, a reaction, or a control kind.

**[WIR-261]** A receiver MUST replace the innermost text of the target only.
**[WIR-262]** A receiver MUST NOT change the `reply_target`, the `thread_root`,
or the mention list of the target. A group text is a `GroupRecord` around a
text, and a reply is a `RichRecord` around a text. Part 7 §7.5.6 and
Part 11 §11.11 apply an edit to both, and this rule makes that possible.

**[WIR-082]** A receiver MUST accept an edit only from the sender of the target. **[WIR-083]** The ratchet
direction gives that authorization, and a client MUST NOT sign an edit.

At bucket `B0` a `new_body` holds a maximum of **138 bytes**. §6.9 gives 155
bytes to the body of an `AppMessage` at `B0`. That figure is the `Text, default
chunk` row. The two fixed fields take 17 bytes, thus 138 bytes remain. An edit
above that size uses bucket `B1`. Part 16 §16.3 records the consequence of that
step.

> *Cause of the resolution rule.* An earlier draft applied an edit to a message
> of kind `0x01` only. A group text is kind `0x12`, and a reply is kind `0x09`.
> Thus that draft rejected every edit of a group message and every edit of a
> reply. Part 7 §7.5.6 states that its rules apply to a private group, and this
> rule makes the two parts agree.

**The delete body.** The value `0x01` of `scope` names a deletion for the
devices of one user, and the value `0x02` names a deletion for the other party.
Part 7 §7.5.3 gives the routing of each value. **[WIR-084]** A receiver MUST reject a record
whose scope byte does not match the channel that carried it.

**[WIR-085]** A parser MUST reject a record when (`body_len` − 2) mod 16 is not 0. **[WIR-086]** A parser
MUST reject a `k` of 0. **[WIR-087]** A parser MUST reject a `k` above `DELETE_BATCH_MAX`. **[WIR-088]** A
parser MUST reject a target list that is not in strictly increasing byte order.
**[WIR-089]** A parser MUST reject a repeated target. These rules give one canonical form, as
§6.1.1 rule 4 requires.

`DELETE_BATCH_MAX` is **9**. §6.9 gives 155 bytes to the body of an
`AppMessage` at bucket `B0`. The two fixed bytes leave 153 bytes, and each
target takes 16 bytes. Thus the maximum is 9. **[WIR-090]** A revision MUST derive this value
again if the bucket ladder or the default chunk width changes. **[WIR-091]** If more targets
wait, the client MUST split them across two records.

> *Cause.* A batch that does not fit `B0` moves the cell into bucket `B1`. Such
> a cell is then the one oversized cell in a private conversation, and a relay
> aims a drop at it. `DELETE_BATCH_MAX` is a security parameter, and it is not a
> bandwidth choice.

> **The scope byte does not defend against an attacker.** The record travels
> inside an AEAD under a channel key. The byte defends against a routing error
> at the sender. Such an error turns a private deletion into a permanent
> placeholder on the device of a contact, with no method to recall it.

### 6.6.2 The group record

Kind `0x12` carries a group record. Part 11 §11.2.1 gives the rules.

```
GroupRecord {
    version      u8         // 0x01
    group_id     [32]u8
    inner_kind   u8         // an application kind of §6.6
    inner_len    u32
    inner_body   [inner_len]u8
}
```

The fixed part is 38 bytes. **[WIR-119]** A parser MUST reject a `body_len` below 39. **[WIR-120]** A
parser MUST reject a record where `body_len` does not equal 38 plus `inner_len`.
**[WIR-121]** A parser MUST reject an `inner_kind` of `0x12` or of `0x10`. **[WIR-122]** A parser MUST
reject an `inner_kind` that this specification does not define. Part 11 §11.2.1
rule 3 gives the cause of the `0x10` rejection.

At bucket `B0` an `inner_body` holds a maximum of **117 bytes**. §6.9 gives 155
bytes to the body of an `AppMessage` at `B0`, and the fixed part takes 38 bytes.
A group text above that size uses bucket `B1`. Part 3 §3.12 puts the modal text
in bucket `B1` already, thus this wrapper moves no cell of the model. A
sender-key record of Part 11 §11.3 uses the same row (§6.9), thus the figure
holds at each of the three tiers.

**[WIR-123]** A client MUST take the class of a group record from `inner_kind`. Part 7
§7.5.3 gives that class. **[WIR-124]** A client MUST NOT treat a group record as a class of
its own.

### 6.6.3 The group control record

Kind `0x10` carries a group control record. Part 11 gives seven such objects,
and this structure gives the type byte that names each one.

```
GroupControl {
    version       u8         // 0x01
    control_type  u8         // see the table
    payload       [n]u8      // the object that `control_type` names
}
```

> **These byte values are group control types.** §6.1.1 rule 7 gives the
> namespace rule. This namespace holds seven values.
>
> - `0x01` names a `SenderKeyDistribution` (Part 11 §11.3.2).
> - `0x02` names a `JoinRecord` (Part 11 §11.9.1).
> - `0x03` names a plain epoch (Part 11 §11.9.2).
> - `0x04` names a granting epoch (Part 11 §11.9.2).
> - `0x05` names a moderation epoch (Part 11 §11.9.6).
> - `0x06` names a `GroupPresence` record (Part 11 §11.9.7).
> - `0x07` names a `GroupInvitation` (Part 11 §11.9.1).
>
> The five other namespaces of this part use the same byte values with different
> meanings.

The fixed part is 2 bytes. **[WIR-146]** A sender MUST wrap each group control
object in a `GroupControl`. **[WIR-147]** A parser MUST reject a `control_type`
that the table above does not hold. **[WIR-148]** An implementation MUST give
the group control type its own type. **[WIR-149]** An implementation MUST NOT
convert that type into another type.

> *Cause.* An earlier draft put the objects under kind `0x10` and gave
> no type byte. A parser then had to tell a `SenderKeyDistribution` from a
> granting epoch by its length, and §6.1.1 rule 4 permits one canonical form
> only. Part 7 §7.5.5 already carries this shape for the device-set control
> record, and this section takes it.

### 6.6.4 The transparency digest

Kind `0x31` carries a transparency digest. Part 9 §9.5.3 gossips the tree head
of the handle directory, and Part 10 §10.5 gossips the consensus root. Part 16
§16.5 gossips the release log head. The three use one structure.

```
DigestBody {
    version   u8        // 0x01
    source    u8        // 0x01 the Part 9 tree head
                        // 0x02 the Part 10 consensus root
                        // 0x03 the Part 16 §16.5 release log head
    epoch     u64       // the epoch or the tree size that the digest names
    digest    [32]u8
}
```

The body is 42 bytes. §6.9 gives the body of an `AppMessage` 155 bytes at
bucket `B0`, thus the record fits `B0` at each of the three sources.

**[WIR-150]** A sender MUST set `source` to a value that the table above holds.
**[WIR-151]** A parser MUST reject a `body_len` that is not 42. **[WIR-152]** A
parser MUST reject a `source` that the table above does not hold.
**[WIR-153]** A client MUST NOT emit a cell whose only content is a
transparency digest. Part 3 §3.6.2 rule NET-064 puts the record in a scheduled
cover slot, thus it replaces the cover cell of that slot and it adds no cell.

> *Cause.* Part 9 §9.5.3 and Part 10 rule `REL-008` each require an in-band
> gossip, and Part 16 §16.4 names that gossip as the answer to directory
> equivocation. An earlier draft gave the gossip no wire field, no application
> kind, and no capacity row. Thus no implementation could carry it.

### 6.6.5 The rich record

A reply, a mention, and a forward each name a property of a record and not a new
record type. One wrapper carries the three, thus a text does not pay for a
feature that it does not use.

```
RichRecord {
    version        u8         // 0x02
    reply_target   [16]u8     // the record that this record answers,
                              // or 16 zero bytes for no reply
    thread_root    [16]u8     // the first record of the thread,
                              // or 16 zero bytes for no thread
    forward_depth  u8         // 0 for an original record
    mention_count  u8         // 0 to MENTION_MAX
    mentions       [mention_count][16]u8
    inner_kind     u8         // an application kind of §6.6
    inner_len      u32
    inner_body     [inner_len]u8
}
```

The fixed part is **40 bytes**, and each mention adds 16 bytes. At bucket `B0`
an `inner_body` with no mention holds a maximum of **115 bytes**. §6.9 gives 155
bytes to the body of an `AppMessage` at `B0`.

**The reference value.** In a pairwise conversation and in a group,
`reply_target` and `thread_root` each hold a `msg_id`. In a community the two
fields each hold a `community_reply_id`, because a community post carries no
`msg_id` (Part 12 §12.2.1).

```
community_reply_id = SHA3-256( "umbra/v1/community-reply"
                               || community_id || pseudonym || BE32(index) )[0..16]
```

The values `community_id`, `pseudonym`, and `index` are the fields of Part 12
§12.2.1, and Part 5 §5.11 holds the label. **[WIR-263]** A sender in a community
MUST compute each reference value with the derivation above. **[WIR-264]** A
client MUST compute the `community_reply_id` of each community post that it
holds. **[WIR-308]** A client MUST match a reference value against those
values.

- **[WIR-161]** A parser MUST reject a `body_len` below 41. **[WIR-162]** A
  parser MUST reject a record where `body_len` does not equal 40 plus
  `mention_count` times 16 plus `inner_len`. **[WIR-265]** A parser MUST reject
  a `version` that is not `0x02`.
- **[WIR-163]** A parser MUST reject an `inner_kind` of `0x09`, of `0x10`, or
  of `0x12`. There is no nested rich record, and a rich record does not carry a
  control record or a group record.
- **[WIR-164]** A parser MUST reject a `mention_count` above `MENTION_MAX`.
  **[WIR-165]** A parser MUST reject a repeated mention value. **[WIR-166]** A
  parser MUST reject a mention list that is not in strictly increasing byte
  order.
- **[WIR-167]** A client MUST take the class of a rich record from `inner_kind`.
  **[WIR-168]** A client MUST NOT give a rich record a class of its own.
- **[WIR-169]** A sender MUST set `reply_target` to 16 zero bytes when the
  record answers no message. **[WIR-170]** A client MUST store a non-zero
  `reply_target` as the `msg_ref` of §6.6.
- **[WIR-171]** A receiver MUST resolve `reply_target` inside the conversation
  that carried the record. **[WIR-172]** A receiver MUST NOT search a different
  conversation. **[WIR-173]** A receiver MUST render a reply whose target it
  does not hold as a reply to an absent message, and it MUST NOT drop the
  record.

**The thread.** A thread is the set of records that share one `thread_root`,
and the root is a record that answers no message.

- **[WIR-266]** A sender MUST set `thread_root` to 16 zero bytes when the record
  is in no thread. **[WIR-267]** A sender MUST set `thread_root` to a record
  whose own `reply_target` is zero. **[WIR-268]** A sender MUST NOT set a
  non-zero `thread_root` on a record whose `reply_target` is zero.
- **[WIR-269]** A sender MUST set `thread_root` to zero on a pairwise channel.
  **[WIR-270]** A receiver MUST reject a non-zero `thread_root` on a pairwise
  channel.
- **[WIR-271]** A receiver MUST resolve `thread_root` under the rules of
  `WIR-171` to `WIR-173`. **[WIR-272]** A client MUST store a non-zero
  `thread_root` as the `msg_ref` of §6.6 in a group. **[WIR-273]** A client MUST
  group the records that share one `thread_root` in its interface.

**The mention identifier.** A mention names a member of a group or of a
community, and it never names a party of a pairwise conversation.

```
mention_id = SHA3-256( "umbra/v1/mention" || scope_id || member_key )[0..16]
```

The value `scope_id` is the `group_id` of Part 11 §11.2.1 or the `community_id`
of Part 12 §12.2. The value `member_key` is the ML-DSA-65 public key of the
`GroupRosterKey_g` of that member, or the community pseudonym of that member.
Part 5 §5.11 holds the label.

- **[WIR-174]** A sender MUST compute a mention identifier with the derivation
  above. **[WIR-175]** A sender MUST set `mention_count` to zero on a pairwise
  channel. **[WIR-176]** A receiver MUST reject a non-zero `mention_count` on a
  pairwise channel.

> *Cause of the scope binding.* The derivation takes the conversation
> identifier, thus one member holds a different mention identifier in each group
> and in each community. Two hostile members of two different groups therefore
> cannot match a mention list across those groups. Goal G9 of Part 2 §2.3 holds
> against colluding contacts, and an unscoped member identifier would be a
> perfect linker in the manner of Part 9 §9.7.

**The forward depth.** **[WIR-177]** A client MUST increase `forward_depth` by
one when a user forwards a record. **[WIR-178]** A client MUST NOT decrease that
value. **[WIR-179]** A client MUST set the value to zero on an original record.
Part 6 §6.6 rule `WIR-062` keeps a forward a new message with a new `msg_id`,
thus the depth is the one datum that survives a forward.

### 6.6.6 The poll and the poll vote

```
Poll {
    version       u8        // 0x01
    flags         u8        // bit 0 more than one choice, bit 1 hidden until close,
                            // bits 2-7 zero
    open_seconds  u32       // the period after the local receive time, or 0 for no close
    q_len         u8
    question      [q_len]u8         // UTF-8
    option_count  u8        // 2 to POLL_OPTION_MAX
    options       [option_count]PollOption
}

PollOption {
    len           u8
    text          [len]u8           // UTF-8
}

PollVote {
    version       u8        // 0x01
    target        [16]u8    // the `msg_id` of the poll
    choice_count  u8        // 1 to POLL_OPTION_MAX
    choices       [choice_count]u8  // the option index, counted from zero
}
```

| Parameter | Value |
| --- | --- |
| `POLL_QUESTION_MAX` | 200 bytes of `question` |
| `POLL_OPTION_TEXT_MAX` | 100 bytes of option `text` |

A poll at `POLL_QUESTION_MAX`, at `POLL_OPTION_MAX`, and at
`POLL_OPTION_TEXT_MAX` is 8 + 200 + 12 × 101 = 1 420 bytes. Inside a
`GroupRecord` and a `RichRecord` it is 1 498 bytes, thus each poll fits bucket
`B1` (§6.9). A vote at `POLL_OPTION_MAX` is 30 bytes, thus each vote fits
bucket `B0`.

- **[WIR-180]** A parser MUST reject an `option_count` below 2 or above
  `POLL_OPTION_MAX`. **[WIR-181]** A parser MUST reject a `question` or an
  option `text` that is not valid UTF-8. **[WIR-182]** A parser MUST reject a
  `body_len` that does not equal the sum of the fields above. **[WIR-274]** A
  parser MUST reject a `q_len` above `POLL_QUESTION_MAX`. **[WIR-275]** A parser
  MUST reject an option `len` of zero or above `POLL_OPTION_TEXT_MAX`.
- **[WIR-183]** A parser MUST reject a `choices` list that is not in strictly
  increasing order. **[WIR-184]** A parser MUST reject a repeated choice.
  **[WIR-185]** A parser MUST reject a choice at or above the `option_count` of
  the target. **[WIR-186]** A parser MUST reject a `choice_count` above 1 when
  bit 0 of `flags` is zero.
- **[WIR-187]** A receiver MUST measure `open_seconds` from its own local
  receive time of the poll. **[WIR-188]** A receiver MUST NOT use `sent_at` for
  that measurement, and `WIR-076` states the same rule.
- **[WIR-189]** A receiver MUST discard a vote that arrives after the period
  closed. **[WIR-190]** A receiver MUST count one vote for each sender, and it
  MUST take the last vote of that sender by the sender-chain position of Part 11
  §11.7.

> *The count is local, and it is not authoritative.* Part 11 §11.7 gives a group
> no total order across senders. Thus two members can hold two different counts
> at one moment. **[WIR-191]** A client MUST NOT render a poll count as an
> agreed count, and Part 11 §11.11 states the same limit.

### 6.6.7 The contact share

A pairwise address names one contact relation (Part 4 §4.2.2). Thus a user
cannot give the address of Bob to Carol, and a contact share is a three-record
flow that asks Bob first.

```
ContactShare {
    version    u8        // 0x01
    type       u8        // 0x01 request, 0x02 grant, 0x03 offer,
                         // 0x04 group request
    name_len   u8
    name       [name_len]u8    // UTF-8, the petname that the sender uses
    body_len   u16
    body       [body_len]u8    // empty for a request, a one-time invitation
                               // of Part 4 §4.3.1 for a grant and for an offer,
                               // group_id || roster_pk_hash for a group request
}
```

The flow has three records. Alice asks Bob, Bob answers Alice, and Alice tells
Carol.

1. Alice sends a `request` to Bob. That record names Carol by the petname that
   Alice uses, and it carries no address.
2. Bob answers Alice with a `grant`. That record carries a **fresh one-time
   invitation** that Bob made under Part 4 §4.3.1.
3. Alice sends an `offer` to Carol. That record carries the invitation of step 2.

- **[WIR-192]** A client MUST NOT put a pairwise address of a third party in a
  contact share. **[WIR-193]** A client MUST NOT put a Public Address of a third
  party in a contact share.
- **[WIR-194]** A client MUST send a `request` before it sends an `offer`.
  **[WIR-195]** A client MUST NOT send an `offer` that carries an invitation
  which no `grant` gave it.
- **[WIR-196]** A client MUST show a `request` of type `0x01`, and it MUST NOT
  answer it without a user action. **[WIR-358]** A client MUST show an `offer`
  of type `0x03`, and it MUST NOT accept it without a user action. Part 2
  §2.4.2 goal S4 names that offer as the introduction path. **[WIR-197]** A
  parser MUST reject a
  `body_len` above zero on a record of type `0x01`. **[WIR-198]** A parser MUST
  reject a `body_len` of zero on a record of type `0x02` or of type `0x03`.
- **[WIR-199]** A client MUST make a fresh invitation for each `grant`.
  **[WIR-200]** A client MUST NOT reuse one invitation across two grants.

**The group request.** A record of type `0x04` asks a member of a private
group for a channel to a joiner, and Part 11 §11.9.1 gives the flow. The body
is the 32-byte `group_id` and the 32-byte SHA3-256 hash of the roster public
key of the joiner.

- **[WIR-343]** A parser MUST reject a `body_len` that is not 64 on a record of
  type `0x04`.
- **[WIR-344]** If the two conditions below hold, a client MUST answer a group
  request with a `grant` without a user action. The local roster of that group
  holds the named roster entry. The sender holds the `admin` role or a higher
  role in that group. **[WIR-345]** In each other case a client MUST discard a
  group request, and it MUST NOT show it. Part 11 rule `GRP-174` binds the
  channel that the grant opens to that roster entry.

> *Cause.* The user consented to the joiner when the plain epoch of Part 11
> §11.9.2 arrived, and the roster is the record of that consent. A second
> approval at each of 499 members made a join at `GROUP_MAX` cost 499 user
> actions.

> *Cause.* Part 4 §4.2.2 gives each contact relation its own identity, and Part
> 2 §2.3 goal G9 says that two contacts cannot show that they share a
> correspondent. A share that carried the address that Alice uses for Bob would
> hand Carol exactly that proof. The three records keep the property, and they
> also make the introduction consensual, which is the behavior that a user
> expects from a person and not from a directory.
>
> The one-time invitation of Part 4 §4.3.1 carries a first-access lock, thus
> Bob learns whether a party other than Carol opened it.

### 6.6.8 The conversation timer

```
ConversationTimer {
    version   u8        // 0x01
    seconds   u32       // one value of the set below, or 0 to turn the timer off
}
```

The body is 5 bytes. Part 7 §7.5.8 gives the enforcement, the retention, and the
interaction with a backup.

- **[WIR-201]** A sender MUST set `seconds` to one value of the set that Part 7
  §7.8 gives. **[WIR-202]** A receiver MUST reject a value that the set does not
  hold.

> *Cause of the fixed set.* A free-form period is a fingerprint. A conversation
> at 4 337 seconds names itself, and a party that reads two such records links
> the two conversations. The set holds nine values, thus a timer carries at most
> 3.17 bits.

### 6.6.9 The reaction, the typing indicator, and the receipt

```
ReactionBody {                    // kind 0x03
    version     u8                // 0x01
    target      [16]u8            // the `msg_id` that the reaction names
    action      u8                // 0x01 add, 0x02 remove
    emoji_len   u8                // 1 to REACTION_MAX_BYTES
    emoji       [emoji_len]u8     // UTF-8
}

TypingBody {                      // kind 0x08
    version     u8                // 0x01
    state       u8                // 0x01 typing started, 0x02 typing stopped
}

ReceiptBody {                     // kind 0x06 and kind 0x07
    version     u8                // 0x01
    count       u8                // 1 to RECEIPT_BATCH_MAX
    targets     [count][16]u8     // `msg_id` values, in strictly increasing byte order
}
```

| Parameter | Value |
| --- | --- |
| `REACTION_MAX_BYTES` | 64 bytes. The longest emoji sequence of Unicode 16 is 35 bytes of UTF-8 |
| `TYPING_INTERVAL` | 10 s. The sender measures it from its last typing record to one peer |
| `TYPING_TTL` | 15 s. The receiver measures it from the receipt of the record |

**The reaction.** A reaction is 19 bytes plus `emoji_len`, thus it fits bucket
`B0` at each length.

- **[WIR-276]** A parser MUST reject an `emoji_len` of zero or above
  `REACTION_MAX_BYTES`. **[WIR-277]** A parser MUST reject an `emoji` that is
  not valid UTF-8. **[WIR-278]** A parser MUST reject an `action` that is not
  `0x01` or `0x02`. **[WIR-279]** A parser MUST reject a `body_len` that does
  not equal 19 plus `emoji_len`.
- **[WIR-280]** A client MUST store `target` as the `msg_ref` of §6.6.
  **[WIR-281]** A receiver MUST apply a remove action only to a reaction with
  the same sender, `emoji`, and target.
  **[WIR-282]** A receiver MUST resolve `target` under the rules of `WIR-171`
  and `WIR-172`.

**The typing indicator.** The body is 2 bytes. `WIR-077` keeps the indicator
off by default.

- **[WIR-283]** A parser MUST reject a `state` that is not `0x01` or `0x02`.
  **[WIR-284]** A parser MUST reject a `body_len` that is not 2.
- **[WIR-285]** A sender MUST NOT send two typing records to one peer inside
  `TYPING_INTERVAL`. **[WIR-286]** A receiver MUST clear a typing state
  `TYPING_TTL` after it received the record that set it. **[WIR-287]** A client
  MUST NOT store a typing record after it processed it.

**The receipt.** A receipt is 2 bytes plus 16 bytes for each target. Part 3
§3.5.4 derives `RECEIPT_BATCH_MAX` from the `B0` row of §6.9.

- **[WIR-288]** A parser MUST reject a `count` of zero or above
  `RECEIPT_BATCH_MAX`. **[WIR-289]** A parser MUST reject a `body_len` that does
  not equal 2 plus `count` times 16. **[WIR-290]** A parser MUST reject a target
  list that is not in strictly increasing byte order. **[WIR-291]** A parser
  MUST reject a repeated target.
- **[WIR-292]** A client MUST store each target as the `msg_ref` of §6.6.
  **[WIR-293]** A receiver MUST resolve each target under the rules of
  `WIR-171` and `WIR-172`.

> *Cause.* An earlier draft declared the three kinds in the table of §6.6 and
> gave them no structure. Part 3 §3.5.4 and Part 7 §7.5.3 state rules for a
> receipt, and `WIR-077` states a rule for a typing indicator. Thus each rule
> named an object that no parser could read.

### 6.6.10 The queue address

A queue address is the set of values that a sender needs before it writes to
one queue. The queue owner makes the queue with a `NEW` of §6.4, and it gives
the address to the sender. Part 3 §3.2.6 gives the four carriers of the address
and the rules of a rotation and of a re-establishment. This section gives the
structure and the parser rules.

```
QueueAddress {                    // 129 bytes
    version         u8            // 0x01
    relay_id        [32]u8        // the relay that holds the queue, Part 10 §10.5.3
    sender_id       [32]u8        // the SenderId of Part 3 §3.2.1
    qs_auth_sk      [32]u8        // the QS_auth private key of Part 3 §3.2.2
    qe              [32]u8        // the QE of Part 3 §3.2.2
}
```

As the body of an `AppMessage` of kind `0x33` the record is 159 bytes, thus it
uses bucket `B0`. The address carries no `RecipientId`, and Part 3 rule
`NET-117` gives the cause. The address carries no relay descriptor. The sender
resolves `relay_id` in the consensus that it holds, under Part 10 rule
`REL-057`.

1. **[WIR-327]** A parser MUST reject a `QueueAddress` whose `version` is not
   `0x01`. **[WIR-328]** A parser MUST reject a body of kind `0x33` whose
   `body_len` is not 129.
2. **[WIR-329]** A client MUST NOT send a record of kind `0x33` on a group
   channel or on a community channel. A queue belongs to one pairwise channel.
3. **[WIR-330]** A receiver MUST accept a record of kind `0x33` only from the
   receiving chain of the session. The ratchet direction gives the
   authorization, and Part 4 rule `IDN-059` uses the same basis.
4. **[WIR-331]** After the grace period of Part 3 §3.2.6 ends, a client MUST
   erase the `QueueAddress` that a newer address replaced. The old address
   holds a private key.

> *Cause.* Part 3 §3.2.2 said that the owner "gives `QE` to the sender in the
> queue address". No part gave that address a layout or a carrier. Two
> mandatory operations named it. Those are the rotation of Part 3 §3.2.4 and
> the re-establishment of Part 7 rule `DEV-135`. SimpleX carries the same
> values in its `QADD` and `QKEY` messages, and UMBRA carries them in one
> record.

### 6.6.11 The key request and the key supply

Part 2 rule `THR-009` makes a receiver classify a failure alone and then ask
the sender. This section gives that request and its answer. A request names
one pairwise session or one group sender key.

```
KeyRequest {                      // kind 0x34
    version   u8        // 0x01
    scope     u8        // 0x01 a pairwise session, 0x02 a group sender key
    id        [32]u8    // the session identifier, or the group_id
    epoch     u32       // the ratchet epoch, or the sender-key generation
    index     u32       // the send_index of the record, or 0 for scope 0x02
}

KeySupply {                       // kind 0x35
    version   u8        // 0x01
    scope     u8        // as in the request
    id        [32]u8    // as in the request
    epoch     u32       // as in the request
    index     u32       // as in the request
    status    u8        // 0x01 supplied, 0x02 not held, 0x03 resent
    body_len  u16
    body      [body_len]u8    // a SenderKeyDistribution for status 0x01, or empty
}
```

A `KeyRequest` is 42 bytes and a `KeySupply` without a body is 45 bytes, thus
each one fits bucket `B0`. A key request travels on the pairwise channel
between the two parties, in each scope.

**The two scopes answer two different failures.** In a pairwise session a
receiver derives each skipped key itself, and the braid of Part 5 §5.5.3 heals
a lost frame. A record that the receiver still cannot open is a record that
the sender chain never carried in a form the receiver can reach. The answer to
a request of scope `0x01` is therefore a re-send and not a key. In a group the
receiver derives nothing, and the answer to a request of scope `0x02` is the
`SenderKeyDistribution` of the named generation.

1. **[WIR-332]** A parser MUST reject a `scope` value or a `status` value that
   this section does not name.
2. **[WIR-333]** A client MUST send a key request on the pairwise channel with
   the party that sent the record. **[WIR-346]** A client MUST NOT send a key
   request on a group channel or on a community channel.
3. **[WIR-334]** A receiver MUST accept a key supply only on the channel on
   which it sent the request. **[WIR-347]** A receiver MUST discard a key
   supply that matches no outstanding request of its own. A request is
   outstanding while the receiver awaits an answer for that `scope`, `id`,
   `epoch`, and `index`. The L6 QueueE2E key of that channel names the peer,
   and no field of the supply does.
4. **[WIR-335]** A client MUST mark each record that a supplied sender key
   opens as recovered. **[WIR-336]** The interface MUST NOT show a recovered
   record as a record whose sender chain the client verified in order. Part 11
   §11.3.1 gives the ordinary attribution.
5. **[WIR-337]** A client MUST NOT send more than `KEY_REQUEST_RATE` key
   requests to one peer in each 24 hours. Part 11 §11.10 gives that value.
   **[WIR-338]** A receiver MUST discard a key request above that rate.
6. For scope `0x01`: **[WIR-339]** If a sender holds the logical message that
   `index` names, it MUST send that message again. **[WIR-348]** That re-send
   MUST carry the original `msg_id` under the current ratchet state. The
   supply then carries status `resent`.
   **[WIR-340]** A sender that does not hold it MUST answer with status `not
   held`. WIR-065 discards the copy if the first send arrives later.
7. For scope `0x02`: Part 11 §11.3.3 gives the answer and the acceptance rule.
8. **[WIR-341]** A client that takes status `not held` MUST show the record as
   a delivery failure under Part 2 §2.4 U9.

> *Cause.* Part 2 rule `THR-009`, Part 7 rule `DEV-098`, and Part 11 rule
> `GRP-020` each named a key request. No part gave it a record, a carrier,
> or an acceptance rule. A supply that any party could send was a path to
> plant a sender key. Thus rule 3 binds the supply to the channel of the
> request. Rule 4 keeps a supplied key from lending a record the attribution
> of an ordered chain.

## 6.7 Version negotiation

```
version_range {
    min             u8
    max             u8
}
```

The two parties select `min(max_a, max_b)`. **[WIR-092]** The two parties MUST abort if that
value is below the `min` value of one of them. There is no feature negotiation
beyond the version number and the suite identifiers of Part 5 §5.10. A version
is an atomic and fully specified wire format, and it is not a set of options.

**[WIR-093]** **Downgrade protection:** an implementation MUST bind the negotiated version and
the two advertised ranges into the handshake transcript hash. Thus a downgrade
causes a handshake failure and not a silent loss of strength.

## 6.8 Test vectors

**[WIR-094]** Each structure in this part MUST have canonical test vectors. **[WIR-095]** The vectors MUST
cover these cases:

- The minimum length and the maximum length of each variable field.
- Each bucket boundary, for the padding and for the unpadding.
- Each rejection case, which is a non-minimal length, trailing bytes, a nonzero
  reserved field, malformed padding, an unknown version, and an unknown command.
- An unknown value in each of the five namespaces, with the rejection of each
  one. **[WIR-096]** A vector MUST cover a cell body that carries an application kind value at
  the command offset. **[WIR-097]** The parser MUST reject that cell.
- The capsule of §6.2.1. **[WIR-294]** The vectors MUST cover one
  `UMBRA_CELL` capsule at each bucket and one `UMBRA_SESSION` capsule at each
  op. **[WIR-295]** The parser MUST reject each case below.
  - A `type` of `0x0B54`, and a `type` in the 4-byte form.
  - A `length` in the 2-byte form.
  - An `UMBRA_CELL` capsule of `length` 525.
  - A `SessionResume` of `length` 41.
- The session control records of §6.2.3. **[WIR-296]** The vectors MUST cover
  an open, a resume with a correct `auth`, and a close. **[WIR-297]** The relay
  MUST reject the two cases below.
  - A resume with one changed bit of `auth`.
  - A resume whose `resume_count` repeats the last accepted value.
- The `RatchetRecord` and the `PqFrame` of §6.5. **[WIR-298]** The vectors MUST
  cover the three cases below. **[WIR-299]** The parser MUST reject the three
  cases that follow them.
  - A record at each of the four `pq_frame_len` values.
  - A `send_index` that wraps from 65 535 to 0.
  - An `epoch` at 255 and at 256.
  - A parity chunk with a `kind` of `0x06` at index 36 of the 64-byte width.
  - A `pq_frame_len` of 68.
  - An `index` of 41 at the 64-byte width.
  - A `version` of `0x01`.
  - A `kind` of `0x05`.
- The queue end-to-end record of §6.4.2, with one boundary vector for each row
  of the capacity table of §6.9. **[WIR-300]** The vectors MUST cover a
  sender-key record at each `AppMessage` row, and one record one byte above
  each row.
- The length pair of §6.4.2 rule 6, at each of the four buckets. **[WIR-098]** A vector MUST
  hold a `SEND` and the `MSG` that a relay makes from that `SEND`. **[WIR-099]** The vector
  MUST assert both `payload_len` values. **[WIR-100]** The vector MUST assert one bucket for
  the two commands.
- A group send to 3 recipients, as §6.4.2 rule 10 states.
- The `EditBody` and the `DeleteBody` of §6.6.1. **[WIR-101]** The vectors MUST cover the
  four cases below.
  - The minimum length and the maximum length of each variable field.
  - The bucket boundary at 138 bytes of `new_body`.
  - The bucket boundary at `DELETE_BATCH_MAX` targets.
  - An edit of a group text, and an edit of a reply. **[WIR-301]** The vectors
    MUST assert that the `group_id`, the `reply_target`, the `thread_root`, and
    the mention list do not change.
- Each rejection case of §6.6.1. **[WIR-102]** The parser MUST reject each case below.
  - A `body_len` below 18.
  - A `new_body` that is not valid UTF-8.
  - An edit whose innermost target kind is `0x02`.
  - A `k` of 0.
  - A `k` above `DELETE_BATCH_MAX`.
  - A target list that is not in strictly increasing byte order.
  - A repeated target.
  - A scope byte that does not match the channel.
- The `GroupRecord` of §6.6.2. **[WIR-125]** The vectors MUST cover the four cases below.
  **[WIR-126]** The parser MUST reject each of the four.
  - A `body_len` below 39.
  - A `body_len` that does not equal 38 plus `inner_len`.
  - An `inner_kind` of `0x12`.
  - An `inner_kind` of `0x10`.
- The `SenderKeyRecord` of Part 11 §11.3. **[WIR-127]** The vectors MUST cover a record at
  `counter` 0, a record that skips 3 positions, and a record above
  `SENDER_KEY_MAX_SKIP`. **[WIR-128]** The vectors MUST also cover a record whose
  `generation` names a key that the receiver does not hold.
- The `Roster` of Part 7 §7.3.1. **[WIR-129]** The vectors MUST cover the three cases below.
  **[WIR-130]** The parser MUST reject the second case and the third case.
  - An epoch that a device of the previous epoch signed.
  - An epoch that a revoked device signed.
  - An epoch whose `prev_hash` does not chain.
- The `DirectoryRoot` of Part 10 §10.5.2. **[WIR-131]** The vectors MUST cover the four cases
  below. **[WIR-132]** The parser MUST reject the last three cases.
  - Five valid signatures.
  - Four valid signatures with one invalid signature.
  - A repeated `authority_index`.
  - A `sigs` list that is not in ascending order.
- The `FileDescriptor` of Part 13 §13.3. **[WIR-133]** The vectors MUST cover a correct
  `commit` value and an incorrect `commit` value. **[WIR-134]** The vectors MUST cover the
  13-chunk boundary at bucket `B1`.
- The `GroupControl` of §6.6.3. **[WIR-154]** The vectors MUST cover one record
  of each of the seven control types. **[WIR-155]** The parser MUST reject a
  `control_type` of `0x00` and a `control_type` of `0x08`.
- The `KeyRequest` and the `KeySupply` of §6.6.11. **[WIR-342]** The vectors
  MUST cover one request and one supply in each scope, and one supply of each
  status.
- The `DigestBody` of §6.6.4. **[WIR-156]** The vectors MUST cover one record of
  each of the three sources. **[WIR-157]** The parser MUST reject a `body_len`
  that is not 42 and a `source` of `0x04`.
- The onion cell of Part 3 §3.4.4. **[WIR-158]** The vectors MUST cover one
  forward cell and one backward cell across three hops, at each of the four
  buckets. **[WIR-159]** The vectors MUST assert that the cell length does not
  change at a hop. **[WIR-160]** The vectors MUST hold a negative case where one
  bit of `body` changes at hop 2, and the endpoint rejects the cell.
- The `RichRecord` of §6.6.5. **[WIR-203]** The vectors MUST cover the five
  cases below. **[WIR-204]** The parser MUST reject the eight cases that follow
  them.
  - A record with no reply and no mention.
  - A record with a reply target.
  - A record with a reply target and a thread root.
  - A record at `MENTION_MAX`.
  - A community reply with its `community_reply_id`.
  - A nested `inner_kind` of `0x09`.
  - A `mention_count` above `MENTION_MAX`.
  - A repeated mention, and a mention list out of order.
  - A non-zero `mention_count` on a pairwise channel.
  - A non-zero `thread_root` on a pairwise channel.
  - A non-zero `thread_root` with a zero `reply_target`.
  - A `thread_root` that names a record with a non-zero `reply_target`.
  - A `version` of `0x01`.
- The `Poll` and the `PollVote` of §6.6.6. **[WIR-205]** The vectors MUST cover
  the three cases below. **[WIR-206]** The parser MUST reject the six cases that
  follow them.
  - A poll at 2 options.
  - A poll at `POLL_OPTION_MAX`.
  - A poll at `POLL_QUESTION_MAX` and `POLL_OPTION_TEXT_MAX`.
  - An `option_count` of 1.
  - A choice at the `option_count`.
  - A repeated choice.
  - A `choice_count` above 1 on a single-choice poll.
  - A `q_len` of 201.
  - An option `len` of 0.
- The `ReactionBody`, the `TypingBody`, and the `ReceiptBody` of §6.6.9.
  **[WIR-302]** The vectors MUST cover the three cases below. **[WIR-303]** The
  parser MUST reject the six cases that follow them.
  - A reaction at 1 byte and at `REACTION_MAX_BYTES`.
  - A typing record of each state.
  - A receipt at 1 target and at `RECEIPT_BATCH_MAX`.
  - An `emoji_len` of 65.
  - An `action` of `0x03`.
  - A `state` of `0x00`.
  - A receipt `count` of 0.
  - A receipt `count` above `RECEIPT_BATCH_MAX`.
  - A receipt target list out of order.
- The text body of §6.6. **[WIR-304]** The parser MUST reject a body of kind
  `0x01` that is not valid UTF-8.
- The `ContactShare` of §6.6.7. **[WIR-207]** The vectors MUST cover one record
  of each of the three types. **[WIR-208]** The parser MUST reject a non-empty
  body on a request and an empty body on a grant.
- The `ConversationTimer` of §6.6.8. **[WIR-209]** The vectors MUST cover each
  value of the Part 7 §7.8 set. **[WIR-210]** The parser MUST reject a value
  that the set does not hold.
- The key hierarchy of Part 5 §5.2, as rule `CRY-121` requires. **[WIR-350]**
  That vector MUST give each key of the diagram, with `RootIdentity`,
  `salt_c`, `j`, and `r` stated.
- The `UMBRA-KEM` vectors of Part 5 rules `CRY-045` and `CRY-046`.
- One complete `UMBRA-XKhfs` transcript, as Part 5 §5.4.8 requires, and the
  second transcript of Part 5 rule `CRY-103`, in which the two advertised
  ranges differ. **[WIR-351]** The vectors MUST hold the flight 1 of Part 5
  rule `CRY-127`, whose `mode` byte is `0x02`. The responder aborts on that
  flight.
- The braid codeword of Part 5 §5.5.2 at each of the three widths.
  **[WIR-352]** The vectors MUST give the full codeword, the `header`, and
  the seeds `d` and `z` of the sender. **[WIR-353]** The vectors MUST assert
  that no 32-byte window of the codeword equals `d` or `z`.
- The rekey schedule of Part 5 rule `CRY-134`, in which `T` occurs while an
  epoch is incomplete and the epoch continues under one epoch number.
- One complete `UMBRA-NKhfs` transcript, as Part 5 §5.4.9 requires.
- The hop 3 key update of Part 3 §3.4.4. **[WIR-354]** The vectors MUST give
  a forward cell and a backward cell after one update. **[WIR-355]** The
  vectors MUST give the key set after `CIRCUIT_MAX_CELLS` updates.
- The at-rest store of Part 15 §15.6.4. **[WIR-356]** The test MUST run three
  steps on one stated plaintext record. The steps are a write, a deletion under
  Part 7 rule `DEV-099`, and the checkpoint of Part 15 rule `IMP-043`.
  **[WIR-357]** After each step, the test MUST assert that the three files
  hold no 16-byte window of that plaintext. The three files are the database
  file, the write-ahead log, and the journal.
- The `HopHello` and the `HopReply` of Part 3 §3.4.3. **[WIR-311]** The vectors
  MUST cover one `EXTEND` cell and one `EXTENDED` cell in bucket `B1`.
  **[WIR-312]** The relay MUST drop the three cases below.
  - A build cell whose `tag` is not 16 zero bytes.
  - An `EXTEND` cell whose `relay_id` names another relay.
  - A build cell whose command byte is `DATA`.
- Byte-for-byte equality across the portable build, the AVX2 build, and the NEON
  build (Part 15 §15.5).

Part 15 §15.5.2 gives the location of the vectors, the `PROVENANCE.md` file, and
the state of that location today. A test suite that reaches the network at test
time is a suite that an air-gapped auditor cannot run. Such a suite is also a
supply-chain dependency at verification time.

## 6.9 Layer overhead and bucket capacity

**The wire cost.** The table below counts the bytes that one cell puts on the
TCP transport of §6.2.1, from the client to the relay. A relay-to-client cell
carries no WebSocket mask, thus it costs 4 bytes less at each bucket. Each
budget of this specification uses the client-to-relay figure as the bound for
the two directions.

| Value | `B0` | `B1` | `B2` | `B3` |
| --- | --- | --- | --- | --- |
| Cell | 512 | 2 048 | 8 192 | 32 768 |
| `SessionFrame`, which is the cell and 12 bytes (§6.2.2) | 524 | 2 060 | 8 204 | 32 780 |
| Capsule, which is the frame and 6 bytes (§6.2.1) | 530 | 2 066 | 8 210 | 32 786 |
| WebSocket frame, which is the capsule and 8 bytes | 538 | 2 074 | 8 218 | 32 794 |
| TLS records | 1 | 1 | 1 | 3 |
| **Wire cost**, which is the frame and 22 bytes for each record | **560** | **2 096** | **8 240** | **32 860** |

**The wire cost of one `B0` cell is 560 bytes.** A `B1` cell costs 2 096
bytes, a `B2` cell costs 8 240 bytes, and a `B3` cell costs 32 860 bytes.
Seven other parts give each fan-out figure and each session figure with these
four constants. Part 1 §1.7 lists the quoting sections. A `B3` frame needs three records, because 32 794 bytes exceed
the 2¹⁴-byte record cap two times.

**The capacity.** The table below counts the bytes that each layer leaves for
the layer above it.

| Value | `B0` | `B1` | `B2` | `B3` |
| --- | --- | --- | --- | --- |
| Cell | 512 | 2 048 | 8 192 | 32 768 |
| `body` | 480 | 2 016 | 8 160 | 32 736 |
| Command area | 478 | 2 014 | 8 158 | 32 734 |
| L5 payload | 394 | 1 930 | 8 074 | 32 650 |
| L6 record on a `MSG` | 390 | 1 926 | 8 070 | 32 646 |
| L7 record | 358 | 1 894 | 8 038 | 32 614 |
| `AppMessage`, default chunk | 185 | 1 721 | 7 865 | 32 441 |
| `AppMessage` in a sender-key record | 185 | 1 721 | 7 865 | 32 441 |
| Text, default chunk | 155 | 1 691 | 7 835 | 32 411 |
| Text, no chunk | 226 | 1 762 | 7 906 | 32 482 |

Each row below the `L5 payload` row comes from the row above it by a subtraction:

| Step | Bytes | Cause |
| --- | --- | --- |
| `L5 payload` to `L6 record on a MSG` | 4 | The `u32` sequence number of a `MSG` (§6.4.2 rule 6) |
| `L6 record on a MSG` to `L7 record` | 32 | The L6 overhead of §6.4.2 rule 2, which holds the 2-byte true length |
| `L7 record` to `AppMessage`, default chunk | 173 | 86 bytes of ratchet record, a 71-byte PQ braid frame, and the 16-byte body tag (Part 5 §5.6) |
| `L7 record` to `AppMessage` in a sender-key record | 173 | 37 bytes of sender-key record (Part 11 §11.3), and 136 bytes of fill under `WIR-305` |
| `AppMessage`, default chunk to `Text`, default chunk | 30 | The `AppMessage` header of §6.6 |
| `Text`, default chunk to `Text`, no chunk | −71 | The record carries no PQ braid frame |

**The sender-key row.** A sender-key record (§6.4.2 rule 5) skips L7, and its
own overhead is 37 bytes. Thus 321 bytes of `AppMessage` would fit that record
at `B0`. **[WIR-305]** A sender MUST compute the bucket of a sender-key record
from the `AppMessage` rows of a ratchet record. **[WIR-306]** A sender MUST fill
the 136-byte difference with zero bytes inside the sender-key ciphertext, after
the `AppMessage`. **[WIR-307]** A receiver MUST take the `AppMessage` length
from `body_len` and ignore the fill.

> *Cause of the sender-key row.* A relay cannot tell a group record from a
> pairwise record (§6.4.2 rule 7, Part 11 §11.5). A larger group capacity would
> put a 200-byte group text in `B0` and the same pairwise text in `B1`. Thus
> the bucket would name the path. An earlier draft gave the table no row for
> the sender-key path, and Part 11 §11.5 quoted the ratchet figure for it.

**[WIR-103]** A client MUST compute the bucket from the capacity table. **[WIR-104]** A client MUST NOT put a
message in a bucket that does not hold it. The capacity of this table is a
client-side selection rule. **[WIR-105]** A relay MUST NOT read a capacity from a served cell.
Rule 6 of §6.4.2 fixes the `payload_len` of a `SEND` and of a `MSG` for each
bucket.
