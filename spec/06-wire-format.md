# UMBRA Protocol Specification — Part 6: Wire Format and Encoding

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

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
   seven namespaces. These are the cell command (§6.3), the queue command
   (§6.4), the L6 record kind (§6.4.2), the group queue record kind (§6.4.6),
   the `PqFrame` kind (§6.5), the application kind (§6.6), and the group
   control type (§6.6.3). A byte value has a meaning only inside its own namespace. **[WIR-007]** A part
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
    type      varint      // 0x0B52 UMBRA_CELL, 0x0B53 UMBRA_SESSION, or
                          // 0x0B54 UMBRA_REPLICA
    length    varint      // the byte count of value, in the 4-byte form
    value     [length]u8  // a SessionFrame (§6.2.2), a session control
                          // record (§6.2.3), or one CRPUT command (§6.4)
}
```

The two fields use the variable-length integer of RFC 9000 §16. **[WIR-216]** A
sender MUST encode `type` in the 2-byte form. **[WIR-217]** A sender MUST encode
`length` in the 4-byte form. Thus the capsule header is 6 bytes at each bucket.
RFC 9000 §16 permits a longer form than the minimum, and §6.1.1 rule 4 permits
one form only. **[WIR-218]** A receiver MUST reject a capsule whose `type` is
not `0x0B52`, `0x0B53`, or `0x0B54`.

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
4-byte key, and a relay frame carries no mask. The length of each cell capsule
is between 126 and 65 535 bytes, thus the frame header is 4 bytes at each
bucket. A client frame therefore adds 8 bytes, and a relay frame adds 4 bytes.

**[WIR-499]** A sender MUST put an `UMBRA_SESSION` capsule in a frame with the
7-bit length form of RFC 6455 §5.2, because that capsule is 47, 35, or 15
bytes. Its frame header is 2 bytes. **[WIR-500]** A receiver MUST reject a
frame in the 16-bit length form whose length is below 126, and a frame in the
64-bit length form. Thus each length has one frame form.

> *Cause.* An earlier draft gave each capsule the 16-bit form. A session
> capsule is below 126 bytes, and RFC 6455 gives that length the 7-bit form
> only. Thus no client could send the `SessionOpen` of `WIR-229`, and no
> session opened on the TCP transport.

**[WIR-485]** A relay MUST NOT negotiate the `permessage-deflate` extension of
RFC 7692, or any other WebSocket extension, on an L1 connection. A browser
offers that extension without a choice of the web client of Part 15 §15.7,
and a compressed cell has a length that its plaintext shapes. **[WIR-486]** A
web client sends each capsule through the WebSocket API of its browser, thus
rules `WIR-225` to `WIR-228` bind the native client and the relay, and the
browser decides the record layout of the client.

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

**[WIR-501]** Each direction of a session holds a `seq` of its own. A relay
frames each cell that it sends with its own `seq`, and a client applies
`WIR-141` to it.

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
> §6.6. The value `0x02` is `DATA` here, `IDS` in §6.4, a retired L6 kind in
> §6.4.2, an epoch-key record in §6.4.6, `ek` in §6.5, and an attachment
> descriptor in §6.6. The value
> `0x04` is `EXTENDED` here, `ct2` in §6.5, and Edit in §6.6. The value `0x05`
> is `DESTROY` here, a handshake record in §6.4.2, `mac` in §6.5, and Delete
> in §6.6. The value `0x07` is
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
    queue_id        [32]u8        // RecipientId, SenderId, ChunkId, community_id, or GroupQueueId, by cmd
    auth            [32]u8        // deniable authenticator (Part 3 §3.2.3)
    payload_len     u16
    payload         [payload_len]u8
}
```

The command header is 84 bytes. The field `auth` is 32 bytes and it is a MAC. **[WIR-014]** A
party MUST NOT compute `auth` as an AEAD ciphertext.

| `cmd` | Name | Sent by | Payload |
| --- | --- | --- | --- |
| `0x01` | `NEW` | Recipient | `NewPayload`, 64 bytes and an `Admission` of Part 14 §14.2 |
| `0x02` | `IDS` | Relay | `IdsPayload`, 96 bytes |
| `0x03` | `IRES` | Recipient | — |
| `0x04` | `ILINK` | Relay | the link identifier of Part 4 §4.3.1, 24 bytes |
| `0x05` | `IPUT` | Recipient | `IputPayload`, the length of the L6 record of the bucket |
| `0x06` | `IGET` | The party that holds the link | `IgetPayload`, 56 bytes |
| `0x07` | `IBLOB` | Relay | `IblobPayload`, the length of the L6 record of the bucket |
| `0x10` | `SEND` | Sender | L6 record |
| `0x11` | `MSG` | Relay | `seq` `u32`, L6 record |
| `0x12` | `ACK` | Recipient | `seq` `u32`, cumulative |
| `0x20` | `SUB` | Recipient | — |
| `0x21` | `UNSUB` | Recipient | — |
| `0x30` | `NKEY` | Recipient | the notifier public key of Part 8 §8.2.4, 32 bytes |
| `0x31` | `NID` | Relay | `notifier_id`, 32 bytes |
| `0x32` | `NPK` | Relay | the notification key of the relay, an `UMBRA-KEM` public key of 1 216 bytes, Part 8 §8.2.3 |
| `0x33` | `NBIND` | Recipient | the sealed `NotifyBinding` of Part 8 §8.2.3, 1 234 bytes |
| `0x40` | `DEL` | Recipient | — |
| `0x50` | `QUOTA` | Relay | the remaining record count of the queue, `u32`, 4 bytes |
| `0x51` | `NACK` | Relay | `NackPayload`, 17 B, §6.4.4 |
| `0x60` | `COVER` | Sender or recipient | zero-filled, indistinguishable from `SEND` and `MSG` |
| `0x70`–`0x7B` | Attachment commands | Uploader, downloader, or relay | Part 13 §13.3.3 gives the twelve commands and their payloads |
| `0x80`–`0x85` | Community commands | Subscriber, publisher, or relay | Part 12 §12.3.3 gives the six commands and their payloads |
| `0x90`–`0x9A` | Group-queue commands | Member, admin, or relay | §6.4.5 gives the eleven commands and their payloads |

```
NewPayload {                      // the payload of NEW, 67 bytes at an Admission of kind 0x00
    qr_auth_pk      [32]u8        // QR_auth of Part 3 §3.2.2, X25519
    qs_auth_pk      [32]u8        // QS_auth of Part 3 §3.2.2, X25519
    admission       Admission     // Part 14 §14.2, 3 bytes and the body
}

IdsPayload {                      // the payload of IDS, 96 bytes
    recipient_id    [32]u8        // RecipientId of Part 3 §3.2.1
    sender_id       [32]u8        // SenderId of Part 3 §3.2.1
    relay_session_pk [32]u8       // RelaySession_pk of Part 3 §3.2.3, X25519
}
```

```
IputPayload {                     // the payload of IPUT
    link_id         [24]u8        // the value of the ILINK
    blob_len        u16           // the true length of the blob
    blob            [blob_len]u8  // the InvitationBlob of Part 4 §4.3.1
    fill            [..]u8        // zero bytes, to the L6 record length of the bucket
}

IgetPayload {                     // the payload of IGET, 56 bytes
    link_id         [24]u8
    lock_pk         [32]u8        // X25519, from the device CSPRNG, for this fetch alone
}

IblobPayload {                    // the payload of IBLOB
    blob_len        u16
    blob            [blob_len]u8
    fill            [..]u8        // zero bytes, to the L6 record length of the bucket
}
```

**The invitation commands.** Part 4 §4.3.1 gives their function.

- **[WIR-505]** The `payload_len` of an `IPUT` and of an `IBLOB` MUST equal the
  "L6 record on a `MSG`" row of §6.9 at the bucket of the cell. Thus a blob has
  the length of a `SEND` at its relay, and the length names no bundle. A blob
  with the bundle of Part 5 §5.4.1 takes bucket `B1`.
- **[WIR-506]** A sender MUST fill with zero bytes, and a receiver MUST reject
  a payload whose fill holds another byte or whose `blob_len` is zero.
- **[WIR-507]** The queue owner signs an `IRES` and an `IPUT` under `QR_auth`,
  with the `RecipientId` in `queue_id`. A relay MUST answer an `IRES` with an
  `ILINK` that holds 24 bytes from its CSPRNG. A relay MUST hold one link
  identifier for one queue, and a second `IRES` ends the first link.
- **[WIR-508]** A relay MUST accept an `IPUT` one time for a link identifier,
  from the queue of its `IRES` alone, and it MUST answer with an `ILINK` of
  that identifier. A relay MUST delete a link identifier that gets no `IPUT`
  inside `INVITE_RESERVE_TTL`, which is 600 s.
- **[WIR-509]** The party that fetches signs an `IGET` under the private half
  of `lock_pk`, with a `queue_id` of zero, as a `NEW` signs under its new
  `QR_auth`. A relay MUST verify `auth` under `lock_pk` before it answers.
- **[WIR-510]** At the first `IGET` that verifies, a relay MUST answer with the
  blob, delete the blob and the link identifier, and put `lock_pk` in the
  place of the `QS_auth` of the queue. From that point the queue takes a
  `SEND` under `lock_pk` alone.
- **[WIR-511]** A relay MUST answer an `IGET` for an identifier that it does
  not hold with the `NACK` reason `REJECTED`, and `WIR-317` gives that one
  reason to an unknown link, to a link with no blob, and to an `auth` that
  does not verify.

> *Cause of the two steps.* Part 4 rule `IDN-160` binds the link identifier as
> the associated data of the blob, and Part 4 §4.3.1 makes the relay draw that
> identifier. Thus the owner learns the identifier before it seals. A client
> that drew the identifier could pick the identifier of a second queue.

**The answer of a relay.** A relay answers a command, and it starts a command
of its own, such as a `MSG`, a `GMSG`, and a `COVER`.

- **[WIR-494]** A relay MUST put the `corr_id` of a command in the `corr_id`
  field of its answer. A `NACK` and a `GSEQ` carry that value in the payload
  also, and the two MUST agree. **[WIR-495]** A relay MUST draw the `corr_id`
  of a command that it starts from its CSPRNG.
- **[WIR-496]** A relay MUST answer an accepted `SEND` with one `QUOTA` under
  `WIR-494`. That `QUOTA` is the relay acknowledgment of Part 3 §3.7, and it
  travels in the place of a cover cell in the manner of `WIR-320`.
  **[WIR-497]** A client MUST take a `QUOTA` or a `NACK` as an answer only
  when its `corr_id` names a command of the same circuit that holds no answer
  yet, and it MUST discard each other one.
- **[WIR-498]** A client MUST NOT use a `corr_id` two times on one circuit.

> *Cause.* Part 3 §3.7 runs the ARQ of a record until a relay acknowledges it.
> A `GPOST` had the `GSEQ`, and a pairwise `SEND` had no acknowledgment on the
> wire. Rule `NET-017` already made the relay signal the quota of a queue,
> thus the `QUOTA` carries the acknowledgment and no new command exists. An
> `IDS`, a `PAGE`, a `PUBACK`, and each attachment answer name their command
> through the same field.

A `NEW` requests no parameter. The relay applies its own quota of Part 3
§3.2.4, and `QUOTA` reports it. **[WIR-487]** A party MUST reject a command
of `ACK`, `NKEY`, `NID`, `QUOTA`, `NACK`, `SUB`, `UNSUB`, or `DEL` whose
`payload_len` differs from the length that the table above gives.
**[WIR-488]** A party MUST reject a `NEW` whose `payload_len` differs from 64
plus the length of its `Admission`, and an `IDS` whose `payload_len` is not
96.

> *Cause.* An earlier draft named "requested params" in the payload of a
> `NEW` and gave them no field. No section of this specification defines a
> parameter that a recipient requests, thus the field does not exist, and a
> parser needs one canonical length under §6.1.1 rule 4.

**[WIR-512]** A relay MUST NOT answer a `COVER` of a client. An accepted
`ACK`, `SUB`, `UNSUB`, or `DEL` has no answer command: the records of a `SUB`
are its effect, and a `NACK` reports a refusal.
**[WIR-513]** A client MUST NOT hold a `COVER`, an `ACK`, a `SUB`, an `UNSUB`,
or a `DEL` in the table of the commands that wait for an answer. A `NACK` for
one of them then names no command of the session, and `WIR-323` drops it. A
lost `ACK` costs a second delivery, which the cursor of `IMP-135` drops.

> *Cause.* An earlier draft gave no answer to these commands and no rule for
> the table of the client. A client that held each `ACK` until an answer held
> it for the life of the session.

**[WIR-015]** `COVER` MUST be bit-indistinguishable from a real command after the L4
encryption. A relay that makes inbound pacing cover (Part 3 §3.5.2) emits cells
with the shape of `MSG` in a queue session, and with the shape of `GMSG` in a
group-queue session (§6.4.5).

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

§6.4.5 gives the group-queue commands. Those commands put a `GroupQueueId` in
`queue_id`. **[WIR-363]** A group-queue command MUST travel on a transport
session that carries no command of another range. **[WIR-364]** A client MUST
NOT batch a group-queue command with a command of another range.
**[WIR-365]** One transport session MUST carry the commands of one group queue
only. **[WIR-366]** A party MAY send a `COVER` in a group-queue session.
**[WIR-367]** A `COVER` in a group-queue session MUST have the shape of a
`GMSG`. The inbound pacing of Part 3 §3.5.2 applies to a group-queue session
exactly as to a queue session.

> *Cause.* A group queue names no member, and a pairwise queue names its
> recipient. A session that carried both would give the relay the link that
> Part 11 §11.5 forbids. One group queue for each session keeps two groups of
> one member apart at the relay in the same way.

- **[WIR-211]** A relay MUST send a `CRPUT` on a direct transport session to
  the target relay. **[WIR-212]** A relay MUST NOT send a `CRPUT` over a client
  circuit.
- **[WIR-213]** A `CRPUT` MUST carry a `payload_len` of 32 682, which is the
  32-byte `storage_token` and `CHUNK_SIZE`. That length is above the `B3` L5
  payload of §6.9, and a `CRPUT` sits in no cell and in no bucket.
- **[WIR-214]** A client MUST NOT send a `CRPUT`. **[WIR-215]** A relay MUST
  reject a `CRPUT` that arrives over a circuit.
- **[WIR-515]** A relay MUST send a `CRPUT` as the value of one
  `UMBRA_REPLICA` capsule, on a connection of §6.2.1 that it opens for that
  copy. The value is the command of §6.4 with its header, 32 766 bytes, and
  a receiver MUST reject each other length. The capsule is outside the
  session of §6.2.3: it has no sequence number, no resend, and no answer.
  **[WIR-516]** The sender MUST set `corr_id` and `auth` of that command to
  zero bytes, and the receiver MUST NOT read them. The `storage_token` of the
  payload is the one authority of a copy (Part 13 rules `ATT-107` and
  `ATT-108`).

> *Cause of the capsule.* An earlier draft put the `CRPUT` on "a direct
> transport session" and gave it no frame. A `SessionFrame` holds a cell of
> one bucket, and `WIR-213` puts a `CRPUT` in no cell. The session adds a
> resend window, and a copy needs none: rule `ATT-113` of Part 13 makes the
> uploader find a copy that did not arrive. A token holder that is no relay
> can send the capsule, and it then stores the chunk that it registered,
> which a `CPUT` gives it too.
>
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
`MSG` fills that area exactly, and a `SEND` leaves 4 bytes. A `GPOST` and a
`GMSG` of §6.4.5 take the same two lengths. Thus a client packs only a command
that carries a small payload or no payload.

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
   `K_QE = HKDF-SHA3-256(salt = "", ikm = QE, info = "umbra/v1/queue-e2e"
   || SenderId, L = 32)`. The value `QE` is the 32-byte per-queue secret of
   Part 3 §3.2.2.

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
   The value `0x01` names a ratchet record (§6.5). The value `0x02` named a
   sender-key record in an earlier draft, and it is retired. The value `0x03`
   names a report record (Part 12 §12.5.3). The value `0x04` names a `NotifyDigest` (Part 12 §12.6.4).
   The value `0x05` names a handshake record, which the text after rule 6
   gives.
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

**The handshake record.** A flight of `UMBRA-XKhfs` (Part 5 §5.4.8) travels
as an L6 record of kind `0x05`. No ratchet exists before flight 3, thus the
flight skips L7, and the queue end-to-end layer alone covers it.

```
HandshakeRecord {                 // the content of an L6 record of kind 0x05
    flight          u8            // 0x01, 0x02, or 0x03
    body            var           // that flight, in the layout of Part 5 §5.4.8
}
```

- **[WIR-502]** A party MUST send each flight of `UMBRA-XKhfs` as a
  `HandshakeRecord`, and in the smallest bucket whose L7 row of §6.9 holds the
  record. Flight 1 is 2 339 bytes and more, thus it takes bucket `B2`.
- **[WIR-503]** A receiver MUST drop a `HandshakeRecord` whose `flight` is not
  the flight that the queue waits for, and it MUST keep the state of the
  handshake. Thus a replayed flight and a flight from a second holder of the
  bundle end no handshake that is in progress.
- **[WIR-504]** A receiver MUST drop a record of kind `0x01` on a queue whose
  handshake is not complete, because no ratchet state can open it.
- Flight 1 arrives on the queue that the bundle names (Part 5 §5.4.1). Flight
  2 arrives on the queue that `app_1` names (Part 3 rule `NET-173`). Flight 3
  arrives on the queue of flight 1. Then the two queues carry ratchet records,
  one queue for each direction.

> *Cause.* An earlier draft said that flight 1 travels inside the queue
> end-to-end layer, and it gave the flight no record kind. Rule `WIR-023` then
> made each receiver reject it. A kind of its own lets a receiver separate a
> flight from a ratchet record before it has a ratchet. The `flight` byte
> costs one byte, and it lets a receiver drop a late flight with no trial
> decryption of a 2 339-byte record.

> *Cause.* A relay parses `payload_len` in the clear. Without this rule a
> relay reads the exact plaintext length of each record. That length separates
> a receipt from a reaction, and a short text from a long one, and G11 does
> not permit that result. The cell is padded to the bucket in any case, thus
> this rule costs no wire byte and no cell. An earlier draft gave this rule a
> second cause: a sender-key record skipped L7, and its length alone separated
> a group record from a pairwise record. In 0.2.0-draft no group record
> travels on a pairwise queue (§6.4.5), and the rule stays for its pairwise
> cause.

7. A relay reads the version, the nonce, and the bucket only. A group record
   travels on a group queue (§6.4.5) and never on a pairwise queue, thus a
   relay that serves a pairwise queue holds no group record. §6.4.6 gives the
   fields that a group-queue relay reads, and Part 11 §11.5 gives what that
   relay learns.
8. **[WIR-030]** A receiver MUST reject a record with an unknown version.
   **[WIR-031]** A receiver MUST reject a record whose tag does not verify.
   **[WIR-032]** A receiver MUST NOT report which check failed.
9. **[WIR-033]** A sender MUST make a new queue before the message count of that queue reaches
   `ROTATE_AFTER` (Part 3 §3.2.4).
10. This rule is retired in 0.2.0-draft. A group send is one `GPOST` of
    §6.4.5 to each replica of the group queue, and no per-recipient record
    exists.

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
   and the key request of §6.6.11 can recover the record.
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
`queue_id` is a queue, a chunk, a community, or a group queue.

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

### 6.4.5 Group-queue commands

A group queue is the relay-held, retained, many-reader mailbox of Part 3
§3.2.7, and Part 11 §11.2 gives its use. This section gives the eleven
commands of the range `0x90` to `0x9A` and their payloads. Part 3 §3.2.7 owns
the behavior rules and the constants `GROUP_RETENTION`, `GROUP_QUEUE_QUOTA`,
`GROUP_POST_RATE`, `GROUP_READ_GRACE`, `GROUP_WRITE_GRACE`, `GROUP_IDLE_TTL`,
and `GROUP_NOTIFIER_MAX`. Part 11 §11.3 gives the record that the queue
carries, and §6.4.6 gives its layout.

A group-queue command uses the 84-byte `Command` header of §6.4, and it puts
the 32-byte `GroupQueueId` in `queue_id`. It keys the deniable authenticator
of Part 3 §3.2.3 with `read_sk`, `write_sk`, or `own_sk` in the place of
`Q*_auth_sk`. Part 11 §11.3.1 derives the first two from the group epoch, and
the creator draws `own_sk` from its CSPRNG. `NET-015` holds: no group-queue
command carries a signature.

| `cmd` | Name | Sent by | Auth key | Payload |
| --- | --- | --- | --- | --- |
| `0x90` | `GNEW` | Creator | `own_sk` of its own payload, as `NEW` goes under `QR_auth_sk` | `GnewPayload`, 99 bytes and the `Admission` body |
| `0x91` | `GIDS` | Relay | — | `GroupQueueId`, 32 bytes |
| `0x92` | `GPOST` | Member | `write_sk` | one `GroupQueueRecord` of §6.4.6, at the "record on a `GMSG`" row of §6.9 |
| `0x93` | `GSEQ` | Relay | — | `GseqPayload`, 20 bytes |
| `0x94` | `GSUB` | Member | `read_sk` | `from_seq` `u32`, 4 bytes |
| `0x95` | `GMSG` | Relay | — | `seq` `u32`, then one `GroupQueueRecord`; the L5 payload row of §6.9 |
| `0x96` | `GUNSUB` | Member | `read_sk` | empty |
| `0x97` | `GKEY` | Admin | `own_sk` | `GkeyPayload`, 64 bytes |
| `0x98` | `GDEL` | Admin | `own_sk` | empty |
| `0x99` | `GNREG` | Member | `read_sk` | `GroupNotifyRegistration`, 130 bytes |
| `0x9A` | `GNUNREG` | Member | `read_sk` | `GroupNotifyRegistration`, 130 bytes |

```
GnewPayload {                     // the payload of GNEW, 99 bytes at an Admission of kind 0x00
    read_pk         [32]u8        // the reader credential of epoch 1, X25519
    write_pk        [32]u8        // the writer credential of epoch 1, X25519
    own_pk          [32]u8        // the owner credential, X25519
    admission       Admission     // Part 14 §14.2, 3 bytes and the body
}

GseqPayload {                     // the payload of GSEQ, 20 bytes
    corr_id         [16]u8        // the corr_id of the GPOST that it acknowledges
    seq             u32           // the sequence number that the relay gave the record
}

GsubPayload {                     // the payload of GSUB, 4 bytes
    from_seq        u32           // the relay emits each retained record with a seq above this value
}

GkeyPayload {                     // the payload of GKEY, 64 bytes
    read_pk         [32]u8        // the reader credential of the new epoch
    write_pk        [32]u8        // the writer credential of the new epoch
}

GroupNotifyRegistration {         // the payload of GNREG and of GNUNREG, 130 bytes
    version         u8            // 0x01
    queue           QueueAddress  // 129 bytes, §6.6.10; a notify queue that the reader made for this group
}
```

A `GroupNotifyRegistration` has the shape of the `NotifyRegistration` of Part
12 §12.6.4 without `community_id`, because `queue_id` names the group queue.
Part 8 §8.5.2 gives the notify queue of a group and the digest that the relay
writes into it.

**The parser.**

- **[WIR-368]** A party MUST reject a command whose `cmd` is between `0x9B`
  and `0x9F`. **[WIR-369]** A party MUST reject a group-queue command whose
  `payload_len` differs from the length that the table above gives for its
  `cmd`.
- **[WIR-370]** A `GPOST` MUST carry a `payload_len` equal to the "record on
  a `GMSG`" row of the group-queue capacity table of §6.9. **[WIR-371]** A
  `GMSG` MUST carry a `payload_len` equal to the L5 payload row of §6.9. Thus
  a `GMSG` fills the command area exactly, and a `GPOST` leaves 4 bytes, as a
  `MSG` and a `SEND` do under §6.4.2 rule 6. **[WIR-372]** A relay MUST NOT
  move a record to a different bucket between the `GPOST` and the `GMSG`.

**Creation and admission.**

- **[WIR-373]** A relay MUST apply the admission control of Part 14 §14.2 to
  a `GNEW`. Part 14 §14.2 gives that path a row, and the fallback is the proof
  of work of Part 14 §14.8. **[WIR-374]** A relay MUST NOT apply an admission
  gate to a `GPOST`. **[WIR-375]** A relay MUST answer a `GPOST` above
  `GROUP_POST_RATE` with a `NACK` of reason `LIMIT`.
- **[WIR-376]** A relay MUST make `GroupQueueId` from its CSPRNG at each
  accepted `GNEW`. **[WIR-377]** A relay MUST answer an accepted `GNEW` with
  one `GIDS` in the same session.
- **[WIR-517]** A creator MUST key the authenticator of a `GNEW` with the
  `own_sk` whose public half sits in `own_pk` of that same payload.
  **[WIR-518]** A relay MUST verify a `GNEW` under the `own_pk` of its
  payload, and it MUST NOT accept a `GNEW` under `read_pk` or under
  `write_pk`. A relay holds no key of the group before the `GNEW`, thus the
  command carries the key that verifies it, as a `NEW` carries `QR_auth_pk`.
  `own_pk` is the durable credential of the queue: `read_pk` and `write_pk`
  leave at the next `GKEY`, and a `GNEW` under one of them would authorize
  the creation under a key that the group replaces at its first rotation.

**The sequence number.** The relay gives each accepted record a `seq`, in the
manner of §6.4.3 rule 5.

- **[WIR-378]** A relay MUST start `seq` at 1 on a new group queue.
  **[WIR-379]** A relay MUST give each accepted record a `seq` above each
  earlier `seq` of that group queue. **[WIR-380]** A relay MUST NOT give the
  `seq` of an erased record to a second record. **[WIR-381]** A relay MUST NOT
  derive `seq` from the record bytes, because §6.1.1 rule 5 forbids that
  derivation.
- `seq` is relay-local. The two replicas of one group give two unrelated
  sequences. **[WIR-382]** A client MUST NOT use `seq` as a message
  identifier. **[WIR-383]** A client MUST NOT use `seq` as an order across
  replicas. A reader holds one cursor for each replica, and Part 3 §3.2.7
  gives that rule. Part 7 §7.5.3 gives the class of the cursor.

**The post and its acknowledgment.**

- **[WIR-384]** A relay MUST answer an accepted `GPOST` with one `GSEQ` that
  carries the `corr_id` of that `GPOST`. The `GSEQ` sits in the place that
  Part 3 §3.7 gives the acknowledgment of a `SEND`.
- **[WIR-385]** If a relay holds a record whose bytes equal the
  `GroupQueueRecord` of a `GPOST`, it MUST answer with the `seq` that it
  holds. **[WIR-386]** That relay MUST NOT store a second copy. A sender under
  the ARQ of Part 3 §3.7 sends one record to a replica again in a later
  session, and this rule makes that send idempotent, in the manner of Part 12
  rule `COM-203`. The comparison selects nothing but a stored `seq`, and
  `WIR-382` keeps that value out of the three functions of `WIR-004`. A
  comparison that fails stores a second record, and the `msg_id` rule
  `WIR-065` removes the duplicate at each reader.

**The subscription.** There is no acknowledgment from a reader.

- **[WIR-387]** On a `GSUB`, a relay MUST emit each retained record of the
  group queue with a `seq` above `from_seq`, in `seq` order. **[WIR-388]**
  While the session lives, a relay MUST emit each record that it accepts
  after the `GSUB` to that session. A backlog above `DRAIN_THRESHOLD` follows
  `NET-037`.
- **[WIR-389]** A relay MUST NOT erase a record on an action of a reader.
  Part 3 §3.2.7 retains by `GROUP_RETENTION` and by `GROUP_QUEUE_QUOTA`.
- **[WIR-519]** A relay MUST emit a `GMSG` of an accepted `GPOST` to each
  session that subscribed, and the relay MUST NOT emit a second `GMSG` for a
  record whose bytes `WIR-385` matched. The reader holds that record already,
  and `WIR-065` would drop the copy at its `msg_id`.

**The rotation of the credentials.**

- **[WIR-390]** On a `GKEY`, a relay MUST replace `read_pk` and `write_pk`
  with the two values of the payload. **[WIR-391]** A relay MUST keep the
  previous `read_pk` for `GROUP_READ_GRACE` after the `GKEY`. **[WIR-392]** A
  relay MUST keep the previous `write_pk` for `GROUP_WRITE_GRACE` after the
  `GKEY`.
- **[WIR-393]** Inside `GROUP_READ_GRACE`, a relay MUST accept a `GSUB`, a
  `GUNSUB`, a `GNREG`, or a `GNUNREG` under either read key. **[WIR-394]**
  Inside `GROUP_WRITE_GRACE`, a relay MUST accept a `GPOST` under either
  write key.
- **[WIR-395]** When a grace ends, a relay MUST erase the previous key.
  **[WIR-396]** A relay MUST reject a command under an erased key with a
  `NACK` of reason `REJECTED`. **[WIR-397]** A relay MUST hold one previous
  read key and one previous write key only, thus a second `GKEY` inside a
  grace replaces the previous key. Part 11 §11.4.1 bounds the rotation rate.

**The deletion.**

- **[WIR-398]** On a `GDEL`, a relay MUST erase the group queue, each record,
  each notify registration, and each key that it holds for the queue.
  **[WIR-399]** A relay MUST NOT retain an identifier of a deleted group
  queue. **[WIR-400]** A relay MUST NOT keep a record that a group queue
  existed. A later command that names it gets `REJECTED` (§6.4.4), as
  `WIR-317` gives.

**The notify registration.**

- **[WIR-401]** A parser MUST reject a `GroupNotifyRegistration` whose
  `version` is not `0x01`. **[WIR-402]** A relay MUST answer a `GNREG` above
  `GROUP_NOTIFIER_MAX` registrations with a `NACK` of reason `LIMIT`. Part 3
  §3.2.7 gives the retention of a registration, and Part 8 §8.5.2 gives the
  client rules.

Part 11 §11.3.4 and §11.3.5 give the sending and the receiving rules of a
member, including the records that a reader stores for a later retry.

> *Cause.* An earlier draft carried a group message as one pairwise `SEND`
> for each member under a sender key, with a jitter across the sends, and it
> gave a large group a re-broadcaster. A message to 500 members then cost 499
> sends, and a membership change cost each member 499 sends more. The group
> queue puts one record at a relay that holds no membership list, and §6.4.6
> gives the tag vector that keeps the attribution the pairwise channel gave.
> Part 11 §11.1 gives the argument, and Part 11 §11.5 gives what the
> group-queue relay learns.

### 6.4.6 The group queue record

The payload of a `GPOST`, and the payload of a `GMSG` after `seq`, carry one
group queue record. It is the L6 record of a group queue, and it sits in the
place of the `QueueE2E` record of §6.4.2. There is no L7 under it. The record
is the AEAD layer, and its `body` carries the application record directly.
The record carries no `group_id`, because the queue names the group; the
associated data binds `group_id` instead.

```
GroupQueueRecord {                // the L6 record of a group queue
    version         u8            // 0x01
    kind            u8            // 0x01 a content record, 0x02 an epoch-key record
    epoch           u32           // the group epoch e of Part 11 §11.3.1
    slot            u32           // kind 0x01: the slot index t; kind 0x02: the start slot t_e of the epoch
    nonce           [12]u8        // kind 0x01: from the device CSPRNG, fresh for each record
                                  // kind 0x02: 12 zero bytes
    body_len        u16
    body            [body_len]u8  // kind 0x01: the AEAD output over a ContentPlain
                                  // kind 0x02: an EpochKeyBody, then the fill
}
```

The fixed part is 24 bytes.

> **These byte values are group queue record kinds.** §6.1.1 rule 7 gives the
> namespace rule. This namespace holds two values, and the six other namespaces
> of this part use the same byte values with different meanings.

**The content record.** For kind `0x01`:

```
body = ChaCha20-Poly1305( key = K_rec(e, t), nonce, plaintext = ContentPlain, ad )
ad   = "umbra/v1/group-record" || group_id || BE32(e) || BE32(t)
```

Part 11 §11.3.1 derives `K_rec(e, t)` from the slot chain of the epoch, and
Part 5 §5.11 holds the label. The 16-byte tag sits at the end of `body`.

```
ContentPlain {
    sender_index    u16           // the member index of the sender, Part 11 §11.9.1
    counter         u32           // strictly increasing for each (member, epoch); 1 on the first record of an epoch
    roster_epoch    u32           // the roster epoch whose active-member order gives the tag order
    tag_mode        u8            // 0x01 dense, 0x02 sparse
    tag_count       u16           // dense: the active member count at roster_epoch, the sender included
                                  // sparse: the count of SparseTag entries
    tags            [..]u8        // dense: [tag_count][12]u8, in member-index order ascending;
                                  //   the position of the sender holds 12 zero bytes
                                  // sparse: [tag_count]SparseTag, in index order ascending, no repeat
    app_len         u16
    app             [app_len]u8   // one AppMessage of §6.6
    fill            [..]u8        // zero bytes to the fixed length of the bucket
}

SparseTag {                       // 14 bytes
    index           u16           // the member index that the tag serves
    tag             [12]u8
}
```

The fixed fields of `ContentPlain` are 15 bytes. A dense vector costs
`GROUP_TAG_LEN`, which is 12 bytes, for each active member, and a sparse entry
costs 14 bytes. Part 11 §11.3.3 derives each tag from the pair key of the
sender and the receiver. Part 11 §11.3.4 gives the sending rules, and Part 11
§11.3.5 gives the receiving rules and the acceptance of a record.

**The fill.**

- **[WIR-403]** A sender MUST fill a `GroupQueueRecord` to the "record on a
  `GMSG`" row of the group-queue capacity table of §6.9 for its bucket.
  **[WIR-404]** For kind `0x01`, a sender MUST put the fill inside
  `ContentPlain` after `app`, thus the AEAD covers it. **[WIR-405]** For kind
  `0x02`, a sender MUST put the fill inside `body` after the `EpochKeyBody`.
  **[WIR-406]** `body_len` MUST equal that row minus 24. **[WIR-407]** A
  receiver MUST verify that each fill byte is zero.
- **[WIR-408]** A relay MUST read `version`, `kind`, `epoch`, `slot`, and the
  bucket of a `GroupQueueRecord`, and no other field. **[WIR-409]** A relay
  MUST reject a `GPOST` whose `version` or `kind` the table above does not
  hold.

**The parser at a receiver.**

- **[WIR-410]** A receiver MUST reject a record whose `version` is not
  `0x01`. **[WIR-411]** A receiver MUST reject a record whose `kind` is not
  `0x01` or `0x02`. **[WIR-412]** A receiver MUST reject a content record
  whose tag does not verify, and `WIR-032` applies to that rejection.
- **[WIR-413]** A parser MUST reject a `tag_mode` that is not `0x01` or
  `0x02`. **[WIR-414]** In dense mode, a parser MUST reject a `tag_count` that
  does not equal the active member count of the receiver's roster at
  `roster_epoch`. The receiver knows that count from its roster, and no field
  of the record states it. **[WIR-415]** In sparse mode, a parser MUST reject
  a list that is not in strictly increasing `index` order. **[WIR-416]** A
  parser MUST reject a repeated `index` in a sparse list. **[WIR-417]** A
  parser MUST reject a `ContentPlain` whose fields end after the plaintext
  ends.
- **[WIR-418]** A sender MUST use dense mode for each `AppMessage` but a
  `GroupControl` of type `0x06`. **[WIR-419]** A sender MUST use sparse mode
  for a `GroupControl` of type `0x06`, with one entry for each member of role
  `admin` or above. **[WIR-420]** A receiver that finds no entry for its own
  index in a sparse record MUST discard that record.
- **[WIR-421]** A sender MUST draw `nonce` from the device CSPRNG for each
  content record. **[WIR-422]** A sender MUST set `nonce` to 12 zero bytes on
  an epoch-key record. An epoch-key record has no AEAD layer at the record
  level, and each slot carries its own.

**The epoch-key record.** For kind `0x02`, `body` is an `EpochKeyBody`. It
carries the secret of a new epoch to each member under that member's KEM
key, and Part 11 §11.4.2 gives the rotation. The body has no slot-key layer,
because a member that missed the previous epoch has to open its slot. The
relay therefore reads `slot_count` when it reads the bucket, and Part 11 §11.5
states that leak.

```
EpochKeyBody {
    roster_epoch    u32           // the roster epoch whose active members hold slots
    carrier         u8            // 0x01 inline, 0x02 chunked
    slot_count      u16           // the active member count at roster_epoch, less the members that the rotation excludes
    // carrier 0x01:
    slots           [slot_count]KemSlot   // in member-index order ascending
    // carrier 0x02:
    slots_per_chunk u16
    desc_len        u16
    descriptor      [desc_len]u8  // a FileDescriptor of Part 13 §13.3 that names the slot object
}

KemSlot {                         // 1 185 bytes at own_count 0; 1 249 bytes at own_count 2
    index           u16           // the member index that the slot serves
    kem_ct          [1120]u8      // UMBRA-KEM.Encap( GroupKemKey_g.pk of that member ), Part 5 §5.2
    ct              [n]u8         // ChaCha20-Poly1305( K_slot, 12 zero bytes, SlotPayload, ad )
                                  // n = 47 + 32 × own_count + 16
}

SlotPayload {                     // 47 bytes at own_count 0; 111 bytes at own_count 2
    rotator         u16           // the member index of the rotator
    k_e             [32]u8        // the epoch secret K_e of Part 11 §11.3.1
    tag             [12]u8        // HMAC-SHA3-256( K_{rotator,index}, "umbra/v1/group-epoch-tag" || group_id
                                  //   || BE32(e) || BE32(t_e) || BE32(roster_epoch) || k_e )[0..12]
    own_count       u8            // 0 for a member below admin; GROUP_REPLICAS for a member at admin or above
    own_sks         [own_count][32]u8   // own_sk of each replica, in the order of the roster snapshot
}

K_slot = HKDF-SHA3-256( salt = "", ikm = ss, info = "umbra/v1/group-epoch-slot" || group_id || BE32(e) || BE16(index), L = 32 )
ad     = "umbra/v1/group-epoch-slot" || group_id || BE32(e) || BE16(index)
```

The fixed part of an `EpochKeyBody` is 7 bytes, and the chunked carrier adds
4 bytes and the descriptor. The value `ss` is the shared secret of the
decapsulation. Part 11 §11.3.3 gives `K_{i,j}`, Part 11 §11.4.2 gives the
acceptance of a slot, and Part 5 §5.11 holds the two labels.

**The carrier.** An inline record holds 27 plain-member slots at bucket `B3`
(7 + 27 × 1 185 = 32 002 bytes, and the `B3` record `body` row of §6.9 is
32 622). A one-slot record is 1 256 bytes of body, and it fits bucket `B1`.
The chunked carrier names a slot object on the chunk path of Part 13
§13.3.3, of class `CNEW`, under `ATT-142`. The object is a sequence of
segments of `SEGMENT_SIZE` (Part 13 §13.7). Segment `k` holds the slots at
ranks `k × slots_per_chunk` to `(k + 1) × slots_per_chunk − 1`, in
member-index order, and then zero bytes to `SEGMENT_SIZE`. The rank of a slot
is its position among the included members, counted from 0. At 500
plain-member slots the object is 592 500 bytes of slots in 19 segments, and a
member downloads one `B3` chunk, which is 32 860 bytes on the wire (§6.9).

- **[WIR-423]** A rotator MUST use the inline carrier when 7 plus the sum of
  the slot sizes fits the record `body` row of §6.9 at bucket `B3`.
  **[WIR-424]** Otherwise a rotator MUST use the chunked carrier.
  **[WIR-425]** A rotator MUST set `slots_per_chunk` to the greatest value at
  which the slots of each segment fit `SEGMENT_SIZE`. **[WIR-426]** A parser
  MUST reject a `slots_per_chunk` of 0. A member fetches the one segment that
  holds its slot, and Part 11 §11.4.2 gives that rule.
- **[WIR-427]** A parser MUST reject a `carrier` that is not `0x01` or
  `0x02`. **[WIR-428]** A parser MUST reject an inline body whose length
  before the fill does not equal 7 plus the sum of the slot sizes. The
  receiver knows `own_count` of each index from the roles of its roster.
  **[WIR-429]** A parser MUST reject a slot list that is not in strictly
  increasing `index` order. **[WIR-430]** A parser MUST reject a repeated
  `index` in a slot list. **[WIR-431]** A parser MUST reject an `own_count`
  that is not 0 or `GROUP_REPLICAS`.

Part 11 §11.3 and §11.4 give the key derivations and the acceptance rules of
the two record kinds. Part 11 §11.10 owns `GROUP_REPLICAS` and
`GROUP_TAG_LEN`.

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
§7.5.1. On a pairwise channel the L6 ciphertexts differ for each recipient. In
a group one `GroupQueueRecord` of §6.4.6 carries the message to every member.

A group message carries `msg_id` in the `AppMessage` that is the `app` of a
`GroupQueueRecord`. No wrapper names the group, because the group queue names
it, and §6.6.2 records the retired wrapper.

**[WIR-056]** A sender MUST draw `msg_id` from the device CSPRNG. **[WIR-057]** A sender MUST NOT derive
`msg_id` from the content or from a counter. **[WIR-058]** A sender MUST NOT use a value that
a different conversation also holds.

**[WIR-059]** A sender MUST draw a new `msg_id` for each message and for each conversation.
**A group is one conversation.** **[WIR-060]** A group send MUST carry one `msg_id` to each
member. One `GPOST` of §6.4.5 carries that one value to each replica of the
group queue of Part 11 §11.2. **[WIR-061]** An edit or a tombstone MUST name the `msg_id` of the target.

> *Cause.* A moderation epoch of Part 11 §11.9.6 names one `msg_id` for a
> target. An earlier draft carried a small group on pairwise channels with a
> per-recipient value. That value matched the history of one recipient only,
> thus a moderator could not act on such a post.
>
> The G9 cost of one shared value is zero inside a group. Part 11 §11.5 states
> that a member learns the roster, thus two members already know that they share
> the sender. The value travels inside the AEAD of the group record, thus no
> party outside the group reads it. Part 11 §11.3 gives the full statement.
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
| `0x12` | Retired; it was the group record wrapper (§6.6.2) | — |
| `0x20` | Device-set sync (Part 7) | Mutable state or control, by the sub-kind |
| `0x30` | Key-change notice (Part 4 §4.5.1) | Control |
| `0x31` | Transparency digest (§6.6.4, Part 9 §9.5.3) | Control |
| `0x32` | Conversation timer (§6.6.8, Part 7 §7.5.8) | Control |
| `0x33` | Queue address (§6.6.10, Part 3 §3.2.6) | Control |
| `0x34` | Key request (§6.6.11, Part 2 §2.4 U9) | Control |
| `0x35` | Key supply (§6.6.11) | Control |
| `0x36` | Verification commit (Part 4 §4.5.2) | Ephemeral |
| `0x37` | Verification reveal (Part 4 §4.5.2) | Ephemeral |

**[WIR-362]** A parser MUST reject a body of kind `0x36` whose length is
not 64, and a body of kind `0x37` whose length is not 32. Part 4 §4.5.2 gives
the two layouts.

For kind `0x01` the body is UTF-8 text with no further structure.
**[WIR-259]** A parser MUST reject a body of kind `0x01` that is not valid
UTF-8. For kind `0x03`, for kind `0x06`, for kind `0x07`, and for kind `0x08`,
§6.6.9 gives the body. Part 3 §3.5.4 sets `RECEIPT_BATCH_MAX` and gives the
emission rules of a receipt.

For kind `0x20`, the body starts with a `u8` sub-kind. The value `0x01` names
mutable state, the value `0x02` names a control record, and the value `0x03`
names a synced conversation record. Part 7 §7.5.3 gives the class and the
layout of each value. Part 7 §7.5.5 gives the `DeviceSetControl` structure
that sub-kind `0x02` carries, and it gives the device-set control type
namespace.

For kind `0x10` the body is a `GroupControl`, and §6.6.3 gives that structure.
For kind `0x31` the body is a `DigestBody`, and §6.6.4 gives that structure.
For kind `0x33` the body is a `QueueAddress`, and §6.6.10 gives that structure.

**Kind `0x11` carries a community record.** Its type namespace is the
community record type of Part 12 §12.4.4, and the body starts with the
`version` and `type` bytes of that namespace. One carrier holds that kind,
which is the report record of Part 12 §12.5.3. **[WIR-144]** A parser MUST
reject a body of kind `0x11` whose `type` is not `0x07`. **[WIR-432]** A parser
MUST reject an `AppMessage` of kind `0x11` that arrives in a ratchet record or
in a group queue record.

> *Cause.* An earlier draft reserved this kind, and `WIR-144` required a type
> namespace before an object used it. The report record is that object, and
> the two rules now bound the kind to its one carrier. Part 12 delivers each
> other community object over the pull path of §12.3.3.

**Kinds `0x0D` and `0x0E` travel inside a community post only.** For kind
`0x0D` the body is a `RepostBody`, and Part 12 §12.6.2 gives that structure.
For kind `0x0E` the body is a `CommunityContact`, and Part 12 §12.6.3 gives
that structure. **[WIR-433]** A parser MUST reject an `inner_kind` of `0x0D`
or of `0x0E` in a ratchet record or in a group queue record.

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
`new_body` that is not valid UTF-8. **[WIR-434]** A receiver MUST resolve the
target of an edit through each `RichRecord` wrapper. **[WIR-260]** A receiver
MUST apply an edit only when the innermost
kind of the target is `0x01`. **[WIR-081]** A receiver MUST reject an edit that names an attachment
descriptor, a reaction, or a control kind.

**[WIR-261]** A receiver MUST replace the innermost text of the target only.
**[WIR-262]** A receiver MUST NOT change the `reply_target`, the `thread_root`,
or the mention list of the target. A group text is the `app` of a
`GroupQueueRecord` (§6.4.6), and a reply is a `RichRecord` around a text.
Part 7 §7.5.6 and Part 11 §11.11 apply an edit to both, and this rule makes
that possible.

**[WIR-082]** A receiver MUST accept an edit only from the sender of the target. **[WIR-083]** The ratchet
direction gives that authorization, and a client MUST NOT sign an edit.

At bucket `B0` a `new_body` holds a maximum of **138 bytes**. §6.9 gives 155
bytes to the body of an `AppMessage` at `B0`. That figure is the `Text, default
chunk` row. The two fixed fields take 17 bytes, thus 138 bytes remain. An edit
above that size uses bucket `B1`. Part 16 §16.3 records the consequence of that
step.

> *Cause of the resolution rule.* An earlier draft applied an edit to a message
> of kind `0x01` only. A reply is kind `0x09`, and a group text of that draft
> was a wrapper of kind `0x12`. Thus that draft rejected every edit of a group
> message and every edit of a reply. Part 7 §7.5.6 states that its rules apply
> to a private group, and this rule makes the two parts agree. 0.2.0-draft
> retires the wrapper, and the rule stays for the reply.

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

This section is retired in 0.2.0-draft. Kind `0x12` is retired; a group
content record is the `app` of a `GroupQueueRecord` (§6.4.6), and it needs no
wrapper because the queue names the group.

### 6.6.3 The group control record

Kind `0x10` carries a group control record. Part 11 gives seven such objects,
and this structure gives the type byte that names each one. A group control
record travels as the `app` of a `GroupQueueRecord` (§6.4.6), except a
`JoinRecord` and a `GroupInvitation`, which travel on the pairwise channel
between the inviting admin and the joiner.

```
GroupControl {
    version       u8         // 0x01
    control_type  u8         // see the table
    payload       [n]u8      // the object that `control_type` names
}
```

> **These byte values are group control types.** §6.1.1 rule 7 gives the
> namespace rule. This namespace holds eight values and one retired value.
>
> - `0x01` is retired. It named a `SenderKeyDistribution` in an earlier draft.
> - `0x02` names a `JoinRecord` (below, and Part 11 §11.9.1).
> - `0x03` names a plain epoch (Part 11 §11.9.2).
> - `0x04` names a granting epoch (Part 11 §11.9.2).
> - `0x05` names a moderation epoch (Part 11 §11.9.6).
> - `0x06` names a `GroupPresence` record (Part 11 §11.9.7).
> - `0x07` names a `GroupInvitation` (below, and Part 11 §11.9.1).
> - `0x08` names a `SnapshotNotice` (below, and Part 11 §11.9.8).
> - `0x09` names a `RekeyRecord` (below, and Part 11 §11.12).
>
> The six other namespaces of this part use the same byte values with different
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

**The join record and the invitation.** Part 11 §11.9.1 gives the join flow.
The inviting admin sends an offer, the joiner answers with a `JoinRecord`, the
admin posts the plain epoch that adds the joiner, and the admin sends an
admit. The three records travel on the pairwise channel between the two
parties, and the plain epoch travels as a group record.

```
JoinRecord {                      // 1 313 bytes, control type 0x02
    version           u8          // 0x01
    group_id          [32]u8
    pair_pk           [32]u8      // GroupPairKey_g.pk of the joiner, Part 11 §11.3.3
    roster_pk_hash    [32]u8      // SHA3-256( GroupRosterKey_g.pk ) of the joiner
    kem_pk            [1216]u8    // GroupKemKey_g.pk of the joiner, Part 11 §11.3.3
}

GroupInvitation {                 // control type 0x07; the fixed part is 36 bytes
    version           u8          // 0x01
    group_id          [32]u8
    stage             u8          // 0x01 an offer, 0x02 an admit
    body_len          u16
    body              [body_len]u8   // an InvitationOffer, or an InvitationAdmit
}

InvitationOffer {                 // 3 905 bytes and the name
    name_len          u8
    name              [name_len]u8   // UTF-8, the display name of the group
    admin_roster_pk   [1952]u8    // GroupRosterKey_g.pk of the inviting admin
    creator_roster_pk [1952]u8    // GroupRosterKey_g.pk of the creator
}

InvitationAdmit {                 // 249 bytes and the descriptor
    index             u16         // the member index that the admin gave the joiner
    epoch             u32         // the group epoch e at the admit
    t_join            u32         // the slot index at which the key of the joiner starts
    slot_key          [32]u8      // K_{e,t_join}, or the history-window key of Part 11 §11.3.1
    read_sk           [32]u8      // read_sk_e of Part 11 §11.3.1
    write_sk          [32]u8      // write_sk_e of Part 11 §11.3.1
    roster_epoch      u32         // the roster epoch of the snapshot
    replica_count     u8          // GROUP_REPLICAS
    replicas          [replica_count]ReplicaRef
    desc_len          u16
    descriptor        [desc_len]u8   // a FileDescriptor of Part 13 §13.3 that names a RosterSnapshot at roster_epoch
}

ReplicaRef {                      // 68 bytes
    relay_id          [32]u8      // Part 10 §10.5.3
    group_queue_id    [32]u8      // the GroupQueueId at that relay
    seq_of_add        u32         // the seq of the plain epoch that added the joiner, at that relay
}
```

- **[WIR-520]** An admit MUST carry `read_sk_e` and `write_sk_e` of the
  epoch that it names. **[WIR-521]** A parser MUST reject an admit whose
  `body_len` is not 249 plus `desc_len`. The two credentials come from `K_e`
  under Part 11 §11.3.1, and the admit hands the joiner `K_{e,t_join}` and
  never `K_e`, because `K_e` opens each slot of the epoch from its start. A
  joiner therefore derives no credential, and without them it authorizes no
  `GSUB` at either replica. Part 11 rule `GRP-384` states the same rule at
  the member.

**The roster objects.** Part 11 §11.9.2, §11.9.6, and §11.9.7 give the
fields and the signature preimages of the plain epoch, the granting epoch, the
moderation epoch, and the presence record. The four layouts below carry those
fields in the order of the preimages.

```
PlainEpoch {                      // control type 0x03; no signature (GRP-064)
    version           u8          // 0x01
    group_id          [32]u8
    epoch_index       u32         // Part 11 §11.9.2
    previous_epoch_hash [32]u8    // Part 11 §11.9.2
    op                u8          // 0x01 add, 0x02 remove, 0x03 self-removal
    // op 0x01:
    index             u16         // the new index, GRP-320
    pair_pk           [32]u8      // the JoinRecord fields of the joiner
    roster_pk_hash    [32]u8
    kem_pk            [1216]u8
    // op 0x02:
    index             u16         // the index removed
    // op 0x03: no field; the tag vector names the member that leaves
}

GrantingEpoch {                   // control type 0x04; GRP-060 signs it
    version           u8          // 0x01
    group_id          [32]u8
    epoch_index       u32
    previous_epoch_hash [32]u8
    granter_index     u16
    grantee_index     u16
    grantee_roster_pk_hash [32]u8
    role              u8          // the role after the epoch, in the set of GroupMemberEntry
    granter_roster_pk [1952]u8    // the key of the granter; its hash is in its entry (GRP-316)
    sig               [3309]u8    // ML-DSA-65 over the preimage of GRP-061
}

ModerationEpoch {                 // control type 0x05; GRP-077 signs it
    version           u8          // 0x01
    group_id          [32]u8
    epoch_index       u32
    previous_epoch_hash [32]u8
    actor_index       u16
    actor_role        u8
    action_count      u8          // 1 to MOD_ACTION_MAX
    actions           [action_count]ModAction
    actor_roster_pk   [1952]u8    // the key of the actor; its hash is in its entry (GRP-316)
    sig               [3309]u8    // ML-DSA-65 over the preimage of GRP-078
}

ModAction {                       // 19 bytes
    action            u8          // 0x01 hide, 0x02 remove, 0x03 unhide
    target            [16]u8      // the msg_id of the target
    author_hint       u16         // a rendering hint, or 0xFFFF; not in the preimage (GRP-179)
}

GroupPresence {                   // control type 0x06, 1 byte
    version           u8          // 0x01
}
```

The preimage of a granting epoch takes `group_id || BE32(epoch_index) ||
previous_epoch_hash || BE16(granter_index) || BE16(grantee_index) ||
grantee_roster_pk_hash || role` after its label. The preimage of a moderation
epoch takes `group_id || BE32(epoch_index) || previous_epoch_hash ||
BE16(actor_index) || actor_role || action_count || (action || target)` for
each action after its label, and `author_hint` stays out of it.

- **[WIR-489]** A parser MUST reject an `op` of a `PlainEpoch` that the
  layout above does not hold, and a `PlainEpoch` whose length does not equal
  the sum of the fields of its `op`. **[WIR-490]** A parser MUST reject a
  `GrantingEpoch` or a `ModerationEpoch` whose length does not hold the one
  1 952-byte roster key of its signer and the 3 309-byte signature after
  the fields before them. **[WIR-491]** A parser
  MUST reject an `action_count` of 0 or above `MOD_ACTION_MAX`, and an
  `action` that the layout above does not hold. **[WIR-492]** A parser MUST
  reject a `GroupPresence` whose length is not 1.

> *Cause.* An earlier draft named the four objects, gave their preimages,
> and gave them no layout. Two implementations then chose two byte orders,
> and no vector of `WIR-479` could exist. The layouts follow the preimages,
> thus a verifier reads the signed bytes from the record in one pass.

The authority path is each granting epoch of Part 11 §11.9.2 on the path of
every current role holder, concatenated, as `GRP-068` keeps it.

A `JoinRecord` is 1 345 bytes as an `AppMessage`, thus it uses bucket `B1`.
An offer is 3 973 bytes and the name as an `AppMessage`, thus it uses bucket
`B2`. An admit is 510 bytes as an `AppMessage` at 3 members (a one-segment
descriptor of 257 bytes), thus it uses bucket `B1`; at `GROUP_MAX` the
descriptor of a 21-segment snapshot is 2 657 bytes, the admit is 2 910
bytes, and it uses bucket `B2`. A granting epoch carries an ML-DSA-65
signature of 3 309 bytes and a roster public key of 1 952 bytes, thus a path
at `ROLE_HOLDER_MAX` is about 86 KB and fits no cell. The authority path
therefore travels in the `RosterSnapshot` in every case, under Part 11
§11.9.8 rules `GRP-324` and `GRP-325`, and the admit carries none.

- **[WIR-435]** A parser MUST reject a `JoinRecord` whose length is not
  1 313. **[WIR-436]** A parser MUST reject a `stage` that is not `0x01` or
  `0x02`. **[WIR-437]** A parser MUST reject an offer whose `body_len` does
  not equal 3 905 plus `name_len`. **[WIR-438]** A parser MUST reject a `name`
  that is not valid UTF-8.
- **[WIR-439]** A parser MUST reject a `replica_count` that is not
  `GROUP_REPLICAS`. **[WIR-440]** A parser MUST reject an admit whose
  `body_len` does not equal 185 plus `desc_len`.
- **[WIR-474]** A parser MUST reject an admit that carries a granting epoch.
  The `RosterSnapshot` below carries the authority path.
- **[WIR-443]** A client MUST send a `JoinRecord` and a `GroupInvitation` on
  the pairwise channel between the inviting admin and the joiner, and on no
  other channel. **[WIR-444]** A receiver MUST discard a `JoinRecord` or a
  `GroupInvitation` that arrives as a group record.
- **[WIR-445]** A client MUST send a group control record of type `0x03`,
  `0x04`, `0x05`, `0x06`, or `0x08` as the `app` of a `GroupQueueRecord`, and
  on no pairwise channel. **[WIR-446]** A receiver MUST discard a group
  control record of one of those types that arrives on a pairwise channel.

> *Cause.* An earlier draft gave the invitation a bundle of one-time
> invitations, one for each member, and the joiner opened a pairwise channel
> to each of them. A join at `GROUP_MAX` then cost 499 channels and 499
> first-access locks. The group queue of §6.4.5 needs no channel between two
> members, thus the admit carries the queue, the epoch key, and a snapshot of
> the roster, and nothing else.

**The roster snapshot and its notice.** Part 11 §11.9.8 gives the writer, the
reader, and the acceptance rules of a snapshot.

```
SnapshotNotice {                  // 39 bytes and the descriptor, control type 0x08
    version           u8          // 0x01
    group_id          [32]u8
    roster_epoch      u32         // the roster epoch that the snapshot describes
    desc_len          u16
    descriptor        [desc_len]u8   // a FileDescriptor of Part 13 §13.3 that names a RosterSnapshot
}

GroupMemberEntry {                     // 99 bytes
    index             u16         // the member index, Part 11 §11.9.1
    role              u8          // 0x01 observer, 0x02 member, 0x03 moderator, 0x04 admin, 0x05 owner
    pair_pk           [32]u8      // GroupPairKey_g.pk
    roster_pk_hash    [32]u8      // SHA3-256( GroupRosterKey_g.pk )
    kem_pk_hash       [32]u8      // SHA3-256( GroupKemKey_g.pk )
}

RosterSnapshot {                  // an object on the chunk path of Part 13 §13.3.3, class CNEW
    version           u8          // 0x01
    group_id          [32]u8
    roster_epoch      u32
    chain_hash        [32]u8      // the hash of the roster epoch that it describes, Part 11 §11.9.2
    entry_count       u16
    entries           [entry_count]GroupMemberEntry    // index ascending
    key_count         u16
    keys              [key_count]MemberKemKey     // every active member, index ascending
    path_len          u32
    path              [path_len]u8   // the authority path of Part 11 §11.9.3, in chain order
}
```

**[WIR-493]** The `path` MUST be a sequence of `BE16(len) || GroupControl`
entries, each a granting epoch of Part 11 §11.9.2 under its wrapper, in
chain order; a parser MUST reject a `path` that ends inside an entry or that
holds a `control_type` other than `0x04`.

```

MemberKemKey {                    // 1 218 bytes
    index             u16
    kem_pk            [1216]u8    // GroupKemKey_g.pk
}
```

The fixed part of a `RosterSnapshot` is 77 bytes. At `GROUP_MAX` the object
is 49 500 bytes of entries and 609 000 bytes of KEM keys, thus 658 577 bytes
without a path, in 21 segments of `SEGMENT_SIZE`. At 3 members it is 4 028
bytes, in one segment. A `SnapshotNotice` that names a one-segment snapshot
is 328 bytes as an `AppMessage`, and it uses bucket `B1` of the group-queue
capacity table of §6.9 at 3 members. A notice that names a 21-segment
snapshot is 2 728 bytes, and it uses bucket `B3` at `GROUP_MAX`.

- **[WIR-447]** A parser MUST reject a `SnapshotNotice` whose length does not
  equal 39 plus `desc_len`.
- **[WIR-448]** A parser MUST reject a `role` that the table above does not
  hold. **[WIR-449]** A parser MUST reject an `entries` list that is not in
  strictly increasing `index` order. **[WIR-450]** A parser MUST reject a
  `keys` list that is not in strictly increasing `index` order.
  **[WIR-451]** A parser MUST reject a `keys` entry whose `index` names no
  entry of `entries`. **[WIR-452]** A parser MUST reject a `kem_pk` whose
  SHA3-256 differs from the `kem_pk_hash` of its entry. **[WIR-453]** A
  parser MUST reject a `RosterSnapshot` whose length does not equal the sum
  of its fields.

**The re-key record.** Part 11 §11.12 makes a member replace its three group
keys after a device revocation or a full identity reset. The record carries
the chain fields of a roster record, the old index, the old roster public key,
the three new public values, the new index, and a signature under the old
roster key.

```
RekeyRecord {                     // 6 614 bytes, control type 0x09
    version           u8          // 0x01
    group_id          [32]u8
    epoch_index       u32         // the roster epoch of this record; zero on a pairwise channel
    previous_epoch_hash [32]u8    // Part 11 §11.9.2; zero on a pairwise channel
    old_index         u16         // the member index that the member holds
    old_roster_pk     [1952]u8    // GroupRosterKey_g.pk of that index
    new_index         u16         // the lowest index above every index the roster used
    pair_pk           [32]u8      // the new GroupPairKey_g.pk
    roster_pk_hash    [32]u8      // SHA3-256 of the new GroupRosterKey_g.pk
    kem_pk            [1216]u8    // the new GroupKemKey_g.pk
    sig               [3309]u8    // ML-DSA-65 under the old roster key
}
```

The signature covers the preimage `"umbra/v1/group-rekey" || group_id ||
epoch_index || previous_epoch_hash || old_index || old_roster_pk || new_index
|| pair_pk || roster_pk_hash || kem_pk`, and Part 5 §5.11 holds the label. As
an `AppMessage` the record is 6 646 bytes, thus it uses bucket `B2`.

- **[WIR-482]** A parser MUST reject a `RekeyRecord` whose length is not
  6 614. **[WIR-483]** A client MUST send a `RekeyRecord` as a group record,
  or on a pairwise channel to a member of role `admin` or above with
  `epoch_index` and `previous_epoch_hash` zero, and on no other channel.
  **[WIR-484]** A receiver MUST discard a `RekeyRecord` on a pairwise channel
  whose chain fields are not zero, and a `RekeyRecord` in a group record
  whose chain fields are zero. **[WIR-478]** A receiver MUST verify `sig`
  against `old_roster_pk`, and `SHA3-256(old_roster_pk)` against the
  `roster_pk_hash` of `old_index` in its roster, before it acts on the
  record. Part 11 §11.12 gives the action on each carrier.

> *Cause.* A device in hostile hands holds every group key of the member,
> thus it can post the same record. Part 11 §11.12 resolves two records for
> one index by a hash, and it keeps the pairwise channel to an admin as the
> path of the device that lost, because that channel is the one the
> revocation of Part 7 §7.7 heals. The old roster key binds the request to
> the index that the member holds.

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
  of `0x12`. There is no nested rich record, a rich record does not carry a
  control record, and the value `0x12` is retired.
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

The value `scope_id` is the `group_id` of Part 11 §11.2 or the `community_id`
of Part 12 §12.2. The value `member_key` is the 32-byte `GroupPairKey_g`
public key of that member (Part 11 §11.3.3), or the community pseudonym of
that member. Part 5 §5.11 holds the label.

> *Cause of the pair key.* An earlier draft took `member_key` from the
> ML-DSA-65 roster key of the member. In 0.2.0-draft the full roster key of a
> plain member travels to no other member; a `GroupMemberEntry` of §6.6.3 carries
> `pair_pk` and a hash of the roster key. The pair key is the value that each
> member holds for each other member.

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
`RichRecord` it is 1 460 bytes, thus each poll fits bucket `B1` on a pairwise
channel (§6.9). In a group at `POLL_GROUP_MAX` the dense tag vector of §6.4.6
adds 1 200 bytes, and the poll takes bucket `B2` of the group-queue capacity
table. A vote at `POLL_OPTION_MAX` is 30 bytes, thus each vote fits bucket
`B0` on a pairwise channel and bucket `B1` in a group at `POLL_GROUP_MAX`.

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
    type       u8        // 0x01 request, 0x02 grant, 0x03 offer; 0x04 retired
    name_len   u8
    name       [name_len]u8    // UTF-8, the petname that the sender uses
    body_len   u16
    body       [body_len]u8    // empty for a request, a one-time invitation
                               // of Part 4 §4.3.1 for a grant and for an offer
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

**The value `0x04` is retired.** An earlier draft used a record of type
`0x04`, the group request, to open a pairwise channel between a joiner and
each member of a private group without a user action at that member. In
0.2.0-draft a joiner holds a pairwise channel with the inviting admin only
(Part 11 §11.9.1), thus the request has no use. **[WIR-454]** A parser MUST
reject a `type` that is not `0x01`, `0x02`, or `0x03`.

> *Cause.* The group request served the all-pairs join of the earlier draft,
> in which a join at `GROUP_MAX` opened 499 pairwise channels. The group queue
> of §6.4.5 needs none of them, and the rules `WIR-343` to `WIR-345` retire
> with the request.

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
- **[WIR-514]** A read receipt, kind `0x07`, is a marker that moves forward. A
  sender MUST name in it the newest message of the conversation that the user
  saw, and it MUST NOT name an earlier one beside it. A receiver MUST take
  each message that it sent in that conversation at or before the newest
  named target, and that a relay accepted, as read. A delivery receipt, kind
  `0x06`, names each message that it reports, because an arrival is a fact
  of one message and the order of two arrivals is not the order of two sends.
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
one pairwise session, one group epoch, or one roster snapshot.

```
KeyRequest {                      // kind 0x34
    version   u8        // 0x01
    scope     u8        // 0x01 a pairwise session, 0x02 the group epoch, 0x03 the roster snapshot
    id        [32]u8    // the session identifier, or the group_id
    epoch     u32       // scope 0x01: the ratchet epoch
                        // scope 0x02: the group epoch that the requester lacks
                        // scope 0x03: the roster epoch that the requester holds
    index     u32       // the send_index of the record, or 0 for scope 0x02 and 0x03
}

KeySupply {                       // kind 0x35
    version   u8        // 0x01
    scope     u8        // as in the request
    id        [32]u8    // as in the request
    epoch     u32       // as in the request
    index     u32       // as in the request
    status    u8        // 0x01 posted, 0x02 not held, 0x03 resent
    body_len  u16
    body      [body_len]u8    // empty in each scope of this draft
}
```

A `KeyRequest` is 42 bytes and a `KeySupply` without a body is 45 bytes, thus
each one fits bucket `B0` on a pairwise channel. In a group the dense tag
vector of §6.4.6 sets the bucket: `B1` at 25 members and `B2` at `GROUP_MAX`,
by the group-queue capacity table of §6.9.

**The three scopes answer three different failures.** In a pairwise session a
receiver derives each skipped key itself, and the braid of Part 5 §5.5.3 heals
a lost frame. A record that the receiver still cannot open is a record that
the sender chain never carried in a form the receiver can reach. The answer to
a request of scope `0x01` is therefore a re-send and not a key. In a group a
member that holds no slot in the current epoch derives nothing, and the answer
to a request of scope `0x02` is a one-slot epoch-key record of §6.4.6 for
that member, posted on the group queue (Part 11 §11.4.3). A member that lacks
the KEM keys of the roster, after a restore from a backup, asks for the
snapshot, and the answer to a request of scope `0x03` is a `SnapshotNotice`
of §6.6.3 with a fresh descriptor, posted on the group queue (Part 11
§11.9.8). In scope `0x02` and in scope `0x03` the `body` of the `KeySupply`
is empty, and status `0x01` means that the answering member posted the
record.

1. **[WIR-332]** A parser MUST reject a `scope` value or a `status` value that
   this section does not name.
2. **[WIR-455]** A client MUST send a key request of scope `0x01` on the
   pairwise channel with the party that sent the record. **[WIR-456]** A
   client MUST send a key request of scope `0x02` or `0x03` as a group record
   on the group queue when it holds a write credential inside
   `GROUP_WRITE_GRACE` and an epoch inside `GROUP_EPOCH_GRACE`. **[WIR-457]**
   Otherwise a client MUST send that request on a pairwise channel with a
   member of the group. **[WIR-458]** A client MUST NOT send a key request on
   a community channel. A member below `admin` that receives a request of
   scope `0x02` or `0x03` on a pairwise channel posts it again as a group
   record, and Part 11 §11.4.3 gives that rule. A member that holds no path
   shows the group as lapsed, under the same section.
3. **[WIR-459]** A receiver MUST accept a key supply of scope `0x01` only on
   the channel on which it sent the request. **[WIR-347]** A receiver MUST
   discard a key supply that matches no outstanding request of its own. A
   request is outstanding while the receiver awaits an answer for that
   `scope`, `id`, `epoch`, and `index`. The L6 QueueE2E key of that channel
   names the peer, and no field of the supply does. **[WIR-460]** A receiver
   MUST accept the answer to a request of scope `0x02` or `0x03` under the
   rules of Part 11 §11.4.2 and §11.9.8, and not by the channel that carried
   the request. The answer is a group record, and the group queue carries it
   to every member. **[WIR-461]** A member that answers a request of scope
   `0x02` or `0x03` MAY send a `KeySupply` of status `0x01` on the channel
   that carried the request, and the requester takes nothing from it but the
   report.
4. **[WIR-462]** A client MUST mark each record that it opens under an epoch
   secret from a one-slot epoch-key record as recovered. **[WIR-463]** The
   interface MUST NOT show a recovered record as a record whose `counter` the
   client tracked without a gap. Part 11 §11.3.5 gives the ordinary
   attribution.
5. **[WIR-337]** A client MUST NOT send more than `KEY_REQUEST_RATE` key
   requests to one peer in each 24 hours. Part 11 §11.10 gives that value.
   **[WIR-464]** A client MUST NOT post more than `KEY_REQUEST_RATE` key
   requests to one group queue in each 24 hours. **[WIR-338]** A receiver
   MUST discard a key request above that rate.
6. For scope `0x01`: **[WIR-339]** If a sender holds the logical message that
   `index` names, it MUST send that message again. **[WIR-348]** That re-send
   MUST carry the original `msg_id` under the current ratchet state. The
   supply then carries status `resent`.
   **[WIR-340]** A sender that does not hold it MUST answer with status `not
   held`. WIR-065 discards the copy if the first send arrives later.
7. For scope `0x02`: Part 11 §11.4.3 gives the answer, which is a one-slot
   epoch-key record of §6.4.6 on the group queue, and the acceptance rule.
   The same record carries the owner credentials to a member that a granting
   epoch promoted. For scope `0x03`: Part 11 §11.9.8 gives the answer, which
   is a `SnapshotNotice` of §6.6.3 on the group queue.
8. **[WIR-341]** A client that takes status `not held` MUST show the record as
   a delivery failure under Part 2 §2.4 U9.

> *Cause.* Part 2 rule `THR-009`, Part 7 rule `DEV-098`, and an earlier Part 11
> rule each named a key request. No part gave it a record, a carrier,
> or an acceptance rule. A supply that any party could send was a path to
> plant a key. Thus rule 3 binds a pairwise supply to the channel of the
> request, and a group answer to the acceptance rules of the epoch-key record,
> which verify the rotator's tag and role. Rule 4 keeps a supplied key from
> lending a record the attribution of a gap-free counter. An earlier draft
> gave scope `0x02` to a sender-key generation and carried the key in the
> supply body; 0.2.0-draft posts the key on the group queue, thus one answer
> serves every member that lacks it.

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
- An unknown value in each of the seven namespaces, with the rejection of each
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
  of the capacity table of §6.9.
- The length pair of §6.4.2 rule 6, at each of the four buckets. **[WIR-098]** A vector MUST
  hold a `SEND` and the `MSG` that a relay makes from that `SEND`. **[WIR-099]** The vector
  MUST assert both `payload_len` values. **[WIR-100]** The vector MUST assert one bucket for
  the two commands.
- The `EditBody` and the `DeleteBody` of §6.6.1. **[WIR-101]** The vectors MUST cover the
  four cases below.
  - The minimum length and the maximum length of each variable field.
  - The bucket boundary at 138 bytes of `new_body`.
  - The bucket boundary at `DELETE_BATCH_MAX` targets.
  - An edit of a group text, and an edit of a reply. **[WIR-465]** The vectors
    MUST assert that the `reply_target`, the `thread_root`, and the mention
    list do not change.
- Each rejection case of §6.6.1. **[WIR-102]** The parser MUST reject each case below.
  - A `body_len` below 18.
  - A `new_body` that is not valid UTF-8.
  - An edit whose innermost target kind is `0x02`.
  - A `k` of 0.
  - A `k` above `DELETE_BATCH_MAX`.
  - A target list that is not in strictly increasing byte order.
  - A repeated target.
  - A scope byte that does not match the channel.
- The `GroupQueueRecord` of §6.4.6, with one boundary vector for each row of
  the group-queue capacity table of §6.9. **[WIR-466]** The vectors MUST cover
  the six cases below. **[WIR-467]** The named receiver MUST reject the two
  cases that follow them.
  - The slot chain of Part 11 §11.3.1: three consecutive slot keys from one
    `K_e`, and the assertion that `K_{e,t}` does not give `K_{e,t-1}`.
  - One dense content record at 3 members with a 350-byte text, in bucket
    `B1`.
  - One dense content record at 500 members with a 350-byte text, in bucket
    `B2`.
  - One sparse record that carries a `GroupPresence`.
  - One inline epoch-key record at 3 members.
  - The segment of the slot at rank 299 in a chunked epoch-key record of 500
    plain-member slots, which is segment 11 at a `slots_per_chunk` of 27.
  - A content record in which one byte of the tag of the named receiver
    changes.
  - A content record whose `sender_index` names no member of the current
    roster of the receiver.
- The group-queue commands of §6.4.5. **[WIR-468]** The vectors MUST cover one
  `GKEY`, one `GSUB` under the previous read key inside `GROUP_READ_GRACE`,
  and one `GPOST` under the previous write key inside `GROUP_WRITE_GRACE`.
  **[WIR-469]** The relay MUST reject a `GSUB` under the previous read key
  after `GROUP_READ_GRACE`, and a `GPOST` under the previous write key after
  `GROUP_WRITE_GRACE`.
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
- The `GroupControl` of §6.6.3. **[WIR-479]** The vectors MUST cover one record
  of each of the eight control types. **[WIR-480]** The parser MUST reject a
  `control_type` of `0x00`, of `0x01`, and of `0x0A`. **[WIR-481]** The vectors
  MUST hold one `RekeyRecord` with a correct signature and one with a changed
  `old_index`, and the parser MUST reject the second. The `GroupInvitation`
  vectors cover both stages.
- The `RosterSnapshot` and the `GroupMemberEntry` of §6.6.3. **[WIR-471]** The
  vectors MUST cover a snapshot at 3 members in one segment, and the segment
  count of a snapshot at `GROUP_MAX`, which is 21.
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
the two directions. A web client of Part 15 §15.7 sends the same frames
through the stack of its browser, and that stack decides the record count;
each budget uses the figure of this table for it.

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
Seven other parts give each group figure and each session figure with these
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
| Text, default chunk | 155 | 1 691 | 7 835 | 32 411 |
| Text, no chunk | 226 | 1 762 | 7 906 | 32 482 |

Each row below the `L5 payload` row comes from the row above it by a subtraction:

| Step | Bytes | Cause |
| --- | --- | --- |
| `L5 payload` to `L6 record on a MSG` | 4 | The `u32` sequence number of a `MSG` (§6.4.2 rule 6) |
| `L6 record on a MSG` to `L7 record` | 32 | The L6 overhead of §6.4.2 rule 2, which holds the 2-byte true length |
| `L7 record` to `AppMessage`, default chunk | 173 | 86 bytes of ratchet record, a 71-byte PQ braid frame, and the 16-byte body tag (Part 5 §5.6) |
| `AppMessage`, default chunk to `Text`, default chunk | 30 | The `AppMessage` header of §6.6 |
| `Text`, default chunk to `Text`, no chunk | −71 | The record carries no PQ braid frame |

**The group-queue capacity.** The table below counts the bytes that a
`GroupQueueRecord` of §6.4.6 leaves for the tag vector and for the
`AppMessage` at each bucket. A group record has no L7, thus its subtraction
differs from the pairwise table above. A `GMSG` carries the L5 payload row,
and a `GPOST` carries the "record on a `GMSG`" row (§6.4.5).

| Value | `B0` | `B1` | `B2` | `B3` |
| --- | --- | --- | --- | --- |
| L5 payload, which is the `GMSG` payload | 394 | 1 930 | 8 074 | 32 650 |
| Record on a `GMSG`, which is the `GPOST` payload | 390 | 1 926 | 8 070 | 32 646 |
| Record `body` | 366 | 1 902 | 8 046 | 32 622 |
| `ContentPlain` | 350 | 1 886 | 8 030 | 32 606 |
| Tags and `app` | 335 | 1 871 | 8 015 | 32 591 |
| `app` at 3 members | 299 | 1 835 | 7 979 | 32 555 |
| `app` at 25 members | 35 | 1 571 | 7 715 | 32 291 |
| `app` at 120 members | — | 431 | 6 575 | 31 151 |
| `app` at 500 members | — | — | 2 015 | 26 591 |
| Text at 3 members | 269 | 1 805 | 7 949 | 32 525 |
| Text at 25 members | 5 | 1 541 | 7 685 | 32 261 |
| Text at 120 members | — | 401 | 6 545 | 31 121 |
| Text at 500 members | — | — | 1 985 | 26 561 |

Each row below the `L5 payload` row comes from the row above it by a
subtraction:

| Step | Bytes | Cause |
| --- | --- | --- |
| `L5 payload` to `Record on a GMSG` | 4 | The `u32` `seq` of a `GMSG` (§6.4.5) |
| `Record on a GMSG` to `Record body` | 24 | The fixed part of `GroupQueueRecord` (§6.4.6) |
| `Record body` to `ContentPlain` | 16 | The AEAD tag of a content record |
| `ContentPlain` to `Tags and app` | 15 | `sender_index` 2, `counter` 4, `roster_epoch` 4, `tag_mode` 1, `tag_count` 2, and `app_len` 2 |
| `Tags and app` to `app` at N members | 12 × N | The dense tag vector, `GROUP_TAG_LEN` for each active member, the sender included |
| `app` to `Text` | 30 | The `AppMessage` header of §6.6 |

A dash marks a bucket that holds no record at that member count. The modal
350-byte text of Part 3 §3.12 takes bucket `B1` at 3 members, at 25 members,
and at 120 members, and bucket `B2` at 500 members. Bucket `B1` holds that
text up to 124 members. An epoch-key record of §6.4.6 uses the `Record body`
row: the inline carrier holds 27 plain-member slots at `B3`, and a one-slot
record fits `B1`.

**[WIR-472]** A sender MUST compute the bucket of a group record from the
group-queue capacity table. **[WIR-473]** A revision that changes the fixed
part of `GroupQueueRecord`, the fixed fields of `ContentPlain`, or
`GROUP_TAG_LEN` MUST derive this table again.

> *Cause.* An earlier draft gave the pairwise table a sender-key row that
> equalled the ratchet row, because a relay could not tell a group record from
> a pairwise record, and a larger group capacity would have named the path by
> the bucket. A group record now travels on a group queue only (§6.4.5), the
> relay knows the queue kind from the command, and the table gives the group
> record its own capacity. The rules `WIR-305` to `WIR-307` retire with that
> row.

**[WIR-103]** A client MUST compute the bucket from the capacity table. **[WIR-104]** A client MUST NOT put a
message in a bucket that does not hold it. The capacity of this table is a
client-side selection rule. **[WIR-105]** A relay MUST NOT read a capacity from a served cell.
Rule 6 of §6.4.2 fixes the `payload_len` of a `SEND` and of a `MSG` for each
bucket.
