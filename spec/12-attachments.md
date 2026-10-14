# UMBRA Protocol Specification — Part 12: Attachments and Large Objects

**Status:** Draft
**Version:** 0.28.1
**Date:** 2026-10-14

---

## 12.1 Requirements

**[ATT-001]** An attachment mechanism MUST meet the four requirements below. A
naive design does not meet them.

1. **[ATT-002]** **The mechanism MUST NOT make the sender stay online** until
   each recipient fetches the file.
2. **[ATT-003]** **The mechanism MUST NOT make the sender upload the file again
   for each group member.** With an incorrect design, a 20 MB file to a
   500-member group costs 10 GB of upload.
3. **[ATT-004]** **A relay MUST NOT be able to tell that two chunks belong to
   one file.**
4. **[ATT-005]** **A relay MUST NOT be able to tell that two chunks belong to
   one user.**

## 12.2 Structure

The client divides an attachment into **fixed-size chunks of `CHUNK_SIZE`**
(bucket `B3`, Part 3 §3.3). The value of `CHUNK_SIZE` is 32 650 bytes, and §12.7
derives it from Part 6 §6.9. Only the last chunk carries padding, and §12.2.3
gives the scheme for that padding. The client
distributes the chunks across **more than one relay, and different
organizations operate those relays**. Each chunk carries an independent random
credential.

```
File ──▶ pad and segment (§12.2.3) ──▶ seal each one (§12.3.1) ──▶ N chunks
                                                              │
      ┌───────────────────────────────────────────────────────┤
      ▼                    ▼                    ▼             ▼
   Relay A             Relay B             Relay C        Relay A
   chunk 0             chunk 1             chunk 2        chunk 3
   cred_0 (random)     cred_1 (random)     cred_2         cred_3
   ↑ each chunk has its own fresh X25519 credential —
     a relay cannot link two chunks to one file or one user
```

### 12.2.1 Why one chunk size, not four

The XFTP of SimpleX gives four chunk sizes, which are 64 KB, 256 KB, 1 MB, and 4
MB. XFTP tells a sender to mix two sizes in one file, to balance the upload
count against the metadata. UMBRA uses **one** size, because the mix of chunk
sizes is itself a fingerprint. The multiset of the sizes decreases the plausible
range of the file size. A strategy with mixed sizes decreases that range more
than one size does.

One size costs more requests for a large file. That cost is the correct trade
under the adversary model of Part 2. One size also reduces the bucket ladder to
one attachment class.

### 12.2.2 Per-chunk anonymous credentials

The client registers each chunk under an **independent random X25519
credential**, and it makes a new credential for each chunk. Thus a relay cannot
find these three facts:

- that two chunks belong to the same file
- that the same user uploaded two chunks
- how many recipients a chunk has

A command carries the deniable authenticator of Part 3 §3.2.3 for its
authorization. A command does not carry a signature.

### 12.2.3 The segments and the padding of the last one

An attachment is a sequence of **segments**. Each segment is `SEGMENT_SIZE`
bytes of plaintext, and §12.3.1 seals each one on its own with a 16-byte tag.
Thus one sealed segment is exactly one chunk of `CHUNK_SIZE` bytes, and a
receiver verifies each chunk with the bytes that the chunk carries.

The descriptor carries no true size, and §12.3 keeps it that way deliberately.
Thus the padding itself carries the boundary, and only the last segment
carries it.

```
padded  = plaintext || 0x80 || 0x00 × k    // a whole multiple of SEGMENT_SIZE
plain_i = padded[ i × SEGMENT_SIZE .. (i + 1) × SEGMENT_SIZE )
```

**[ATT-059]** A sender MUST pad `plaintext` with one marker byte of `0x80` and
then zero bytes. This is the ISO/IEC 7816-4 style, and Part 6 §6.9 rule
`WIR-011` uses the same style for a cell body.

**[ATT-060]** A sender MUST select the smallest *k* that makes the length of
`padded` a whole multiple of `SEGMENT_SIZE`. **[ATT-061]** A sender MUST append
the marker byte even when the length of `plaintext` is already a whole multiple
of `SEGMENT_SIZE`. That case adds one more segment, which holds the marker byte
and then zero bytes.

**[ATT-062]** A receiver MUST read the last segment from its last byte toward
its first byte. **[ATT-177]** A receiver MUST pass over each `0x00` byte of that
read. **[ATT-063]** The first byte that is not `0x00` MUST be `0x80`, and a
receiver MUST reject the file when that byte holds a different value.
**[ATT-064]** A receiver MUST remove that marker byte and each zero byte after
it. The result is the tail of `plaintext`.

**[ATT-065]** A receiver MUST NOT read the padding of a segment whose tag
failed under §12.3.1. A failed tag rejects the chunk, and the padding of a
rejected chunk states nothing.

Then `chunk_count` is the length of `padded` divided by `SEGMENT_SIZE`, and
`padded_size` of §12.3 equals `chunk_count` times `CHUNK_SIZE`.

**The handle-addressed chunk.** A backup root of Part 4 §4.7.2 and a
dead-channel blob of Part 3 §3.2.6 are one chunk each. Their writers seal them
under keys of their own. **[ATT-147]** The writer of a handle-addressed chunk
MUST pad its sealed object under the scheme above. The unit is `CHUNK_SIZE` in
place of `SEGMENT_SIZE`. **[ATT-148]** A reader of such a chunk MUST reject a
sealed object shorter than 16 bytes. That object holds a tag at the minimum.

> *Cause.* One AEAD over the full file puts its one tag at the end of the last
> chunk. A receiver then verifies nothing before it holds each chunk, thus no
> progressive render is possible. A segment carries its own tag inside the same
> `CHUNK_SIZE`, and the marker byte is in the plaintext and not in the
> ciphertext. `SEGMENT_SIZE` is 16 bytes below `CHUNK_SIZE`, and §12.7 states
> both.
>
> `ATT-061` is the rule that a padding implementation usually gets wrong.
> Without it a `plaintext` that ends in `0x00` is indistinguishable from a
> `plaintext` that ends earlier and carries zero padding.

## 12.3 The file descriptor

The client delivers the descriptor **in** the pairwise channel or the group
channel. The client does not give the descriptor to a relay:

```
FileDescriptor {
    version        u8
    level          u8          // 0x00 the refs address data chunks
                               // 0x01 the refs address manifest chunks (§12.3.4)
    file_key       [32]u8      // XChaCha20-Poly1305 key
    file_nonce     [24]u8
    commit         [32]u8      // the key commitment of §12.3.1
    digest         [32]u8      // SHA3-256 of the plaintext
    media_seconds  u16         // the duration of an audio or a video object,
                               // and 0 when the class carries no duration
    ref_count      u32         // the ChunkRef count in this descriptor
    padded_size    u32         // the data chunk count times CHUNK_SIZE. TRUE size
                               // not carried: the 12.2.3 padding gives the boundary
    mime_class     u8          // 0x01 image, 0x02 video, 0x03 audio,
                               // 0x04 voice, 0x05 doc, 0x06 other
    pixel_w        u16         // the width of an image or a video, else 0
    pixel_h        u16         // the height of an image or a video, else 0
    refs           [ref_count]ChunkRef
}

ChunkRef {                     // 120 B
    relay_id       [32]u8
    chunk_id       [32]u8
    cred_pk        [32]u8
    replicas       [2]RelayRef  // MANDATORY redundancy, see 12.4
}

RelayRef {                     // 12 B, see 12.3.2
    relay_hint     [12]u8
}
```

The fixed part of `FileDescriptor` is **137 bytes**, and one `ChunkRef` is **120
bytes**. Thus a descriptor of *n* refs is 137 + 120*n* bytes. §12.3.2 derives
the width of `RelayRef`, §12.3.4 gives the manifest level, and §12.7 gives the
ref count that each bucket holds.

The data chunk count is `padded_size` divided by `CHUNK_SIZE`. **[ATT-067]** A
receiver MUST take the data chunk count from that division. **[ATT-068]** A
parser MUST reject a `padded_size` that `CHUNK_SIZE` does not divide.

**[ATT-069]** A sender MUST set `media_seconds` for a `mime_class` of audio,
of voice, or of video. **[ATT-070]** A sender MUST set `media_seconds` to zero
for each other class. **[ATT-071]** A sender MUST NOT send a voice object above
`VOICE_MAX_SECONDS`. §12.7 gives that value. The voice class is a recording
that the client made in the conversation, and the audio class is a file that
the user selected.

- **[ATT-153]** A sender MUST set `pixel_w` and `pixel_h` for an image and for a
  video, after the re-encode of `ATT-155`. **[ATT-154]** A receiver MUST size
  the placeholder of an image or a video from those two fields. It needs no
  chunk for that.

**The metadata and the re-encode.** A photograph carries a location, a device
model, and a time in its metadata fields. A recipient that saves the file gives
those fields to each platform service.

- **[ATT-155]** A sender MUST re-encode an image, an audio, a voice, or a video
  object before the encryption. The re-encode follows Part 9 rules `DIS-001` and
  `DIS-002`, thus the object carries no metadata field. **[ATT-156]** A sender
  MUST re-encode an image above `IMAGE_REENCODE_BYTES` to at most that size.
  **[ATT-157]** If the user selects the original for one send, the sender MUST
  skip both re-encodes for that send and MUST state that the original carries
  its metadata fields.
- **[ATT-195]** A container that the re-encode writes MUST name no time: a
  sender MUST set the creation and the modification time of each MP4 header
  box (`mvhd`, `tkhd`, `mdhd`) to zero, and a value of the platform that names
  the device or its system MUST become zeros of the same length.
  **[ATT-196]** An audio object that a sender encodes again MAY keep the name
  that the user picked, with the extension of its new type.
- **[ATT-158]** A client MUST NOT reuse a `file_key`, a `file_nonce`, or a
  `ChunkRef` across two conversations. A forward is a new upload under a fresh
  key and fresh chunks.

> *Cause.* A profile picture loses its metadata fields under Part 9. Without
> `ATT-155`, a photograph in a conversation keeps them. The original stays
> available for one send, because a document scan or a print needs its
> resolution. A shared `ChunkRef` across two conversations gives one relay a
> download count that joins the two, and it gives a recipient of the first
> conversation a `read_sk` for the second.

The descriptor deliberately **omits the original filename and the exact size**.
The encrypted message body carries the filename, if the message carries the
filename at all (Part 6 §6.6, `WIR-531`). No field that a relay sees carries
the filename. The field `mime_class` is coarse, because a MIME type with full
detail is a fingerprint.

- **[ATT-192]** A sender MUST NOT put a name in the body of an image, a video,
  or a voice object. The name of a camera file holds the time of the capture,
  and `ATT-155` removes that time from the object itself.
- **[ATT-193]** A receiver MUST show a `mime_class` that it does not know as a
  file of class `0x06`. A later version can add a class, and a file of that
  class still arrives.
- **[ATT-194]** A sender SHOULD put a preview of Part 6 rule `WIR-533` in the
  body of an image and of a video: a thumbnail of low quality, at most
  `PREVIEW_SIDE` on its longest side. It MUST make the preview from the object
  after the re-encode of `ATT-155`, as a new JPEG, thus the preview carries no
  metadata field.

### 12.3.1 Key-committing AEAD is mandatory

**[ATT-006]** The attachment AEAD MUST be key-committing. Plain
ChaCha20-Poly1305 and AES-GCM are **not** key-committing. **[ATT-007]** The test
suite of this specification MUST include a negative vector that fails on the
construction that does not commit.

UMBRA reaches that property with one SHA3-256 pass over the key and the nonce.
The construction is this:

```
commit  = SHA3-256( "umbra/v1/file-commit" || file_key || file_nonce )   // 32 B
nonce_i = file_nonce[0..20] || BE32(i)
chunk_i = XChaCha20-Poly1305( file_key, nonce_i, plain_i,
                              ad = BE32(i) || last_i )        // CHUNK_SIZE
```

The value `file_nonce` is 24 bytes and the device CSPRNG gives it. §12.2.3
gives `plain_i`, which is segment *i*. The value `last_i` is `0x01` for the
last segment and `0x00` for each other one. Part 5 §5.11 holds the label
`"umbra/v1/file-commit"`.

1. **[ATT-025]** A sender MUST put `commit` in the `FileDescriptor` of §12.3.
2. **[ATT-026]** A receiver MUST compute `commit` again from `file_key` and
   `file_nonce`. **[ATT-027]** A receiver MUST compare the two values in
   constant time.
3. **[ATT-028]** If the two values differ, a receiver MUST reject the
   descriptor. **[ATT-029]** A receiver MUST NOT fetch a chunk of a descriptor
   that it rejected.
4. **[ATT-030]** A receiver MUST make that comparison before it decrypts a
   chunk.
5. **[ATT-149]** A sender MUST seal each segment under `nonce_i` and the
   associated data above. **[ATT-150]** A receiver MUST reject a chunk whose
   tag fails. **[ATT-151]** A receiver MUST reject a file whose last chunk
   under `padded_size` carries `last_i` of `0x00`. **[ATT-159]** A receiver
   MUST reject a file in which a chunk before the last one carries `last_i` of
   `0x01`. Thus a truncated or an extended file fails at the chunk that shows
   it.
6. **[ATT-031]** A receiver MUST verify `digest` against the full plaintext
   after the decryption. **[ATT-032]** A receiver MUST NOT present a file as
   complete, save it, or forward it before that check succeeds. **[ATT-152]** A
   receiver MAY render the verified segments of a media object in chunk order
   before that check completes. A media object is an image, an audio, a voice,
   or a video object. Part 14 rule `IMP-044` gives the destination of the
   plaintext.

   > *Cause of the render.* Each chunk carries its own tag under `ATT-149`,
   > and `ATT-150` rejects a chunk that fails. Thus a verified prefix is
   > authentic bytes of the object, and a player that starts on it shows the
   > user nothing that the sender did not seal. The digest still closes the
   > file, because it binds the segments to one plaintext under one value that
   > the descriptor carries. With one tag for the whole file, a receiver
   > verifies nothing before the last chunk.

The pair (`file_key`, `file_nonce`) binds to one 32-byte value. Thus a party
that wants one ciphertext to open under two keys has to find a SHA3-256
collision. The check also costs nothing at the moment it counts most, because a
receiver rejects an incorrect key before it downloads the chunks.

> Facebook shipped message franking that did not frank, because AES-GCM is not
> key-committing (the invisible salamanders result, CRYPTO 2018). The correction
> is one more SHA3-256 pass over the key and the nonce. UMBRA v1 ships
> attachments, thus this risk is real.

### 12.3.2 `RelayRef` is a compact directory reference

`RelayRef` is **12 bytes**, and the width is fixed. Part 1 §1.4 gives each byte
string a fixed width or a length prefix. An undefined width makes
`FileDescriptor` unencodable, thus this section states the width.

```
RelayRef {
    relay_hint     [12]u8   // the first 12 bytes of
                            // SHA3-256("umbra/v1/relayref" || relay_id)
}
```

The value is a directory reference, and it is not a relay key. A client resolves
`relay_hint` against the relay set of the current consensus (Part 10 §10.5). The
client holds that consensus already, thus a resolution needs no fetch. The full
32-byte `relay_id` stays in `ChunkRef`, thus the first replica of a chunk needs
no directory lookup at all.

**The width derivation.** Part 6 §6.9 gives the `B1` `L5 payload` row 1 930
bytes. The fixed part of `FileDescriptor` is 137 bytes, and each `ChunkRef` is
96 bytes plus two `RelayRef` values. The model file of Part 3 §3.12 is 400 KB,
which is 13 chunks. A second row of §6.9 is tighter, and that row decides the
width. The client sends the descriptor as the body of an `AppMessage`, and §6.9
gives that body 1 691 bytes at `B1` with the default chunk. Part 5 §5.5.2 gives
the same body 1 723 bytes at `B1` with the 32-byte chunk:

```
137 + 13 × (96 + 2R) ≤ 1 930    L5 payload at B1                     gives  R ≤ 20
137 + 13 × (96 + 2R) ≤ 1 723    AppMessage body at B1, 32-byte chunk gives  R ≤ 13

R = 12  →  ChunkRef = 120 B  →  13 chunks = 137 + 1 560 = 1 697 B
```

UMBRA sets *R* to 12, because 12 gives a `ChunkRef` of 120 bytes and 120 is a
multiple of 8. The margin against the 1 723-byte row is 26 bytes. A 13-chunk
descriptor is 6 bytes above the 1 691-byte default-chunk row. Thus the client
sends it with the 32-byte chunk under Part 5 §5.5.2 rule `CRY-018`. The ref
ceilings of §12.7 hold at the 137-byte fixed part: 13 refs at `B1`, 64 refs at
`B2`, and 269 refs at `B3`. A 12-byte
hint gives 96 bits against a second preimage on the identity of a relay. A
relay that wants the traffic of another relay has to find that preimage first.
**[ATT-049]** A revision that adds a field to `FileDescriptor` or to `ChunkRef`
MUST derive `R` again from Part 6 §6.9.

**A rotation of the directory epoch does not break a stored descriptor.** Part
10 §10.11 gives the consensus epoch as 1 hour, and §12.7 gives `CHUNK_LIFE_MAX`
as 28 days. Thus a stored descriptor outlives 672 consensus epochs. `RelayRef` names
the identity of a relay, and it does not name a position in a consensus. Thus a
rotation of the epoch changes no byte of a stored descriptor. A reference that
named a directory index would break at the first rotation.

The four rules below hold at a retrieval.

1. **[ATT-008]** A client MUST resolve `relay_hint` against the current
   consensus. **[ATT-009]** A client MUST NOT fetch an older consensus to
   resolve a reference, because Part 10 §10.5 forbids a session for the only
   purpose of a directory diff.
2. **[ATT-010]** If `relay_hint` matches no relay in the current consensus, the
   client MUST treat that replica as unreachable. **[ATT-011]** The client MUST
   then try another replica under §12.4.
3. **[ATT-012]** If `relay_hint` matches two or more relays in the current
   consensus, the client MUST treat that replica as unresolvable. **[ATT-013]**
   The client MUST then try another replica under §12.4.
4. If no replica of a chunk resolves, the transfer fails. **[ATT-014]** The
   client MUST report that failure to the user, and **[ATT-015]** the client
   MUST NOT show a partial file.

**The residual.** A chunk lives for `CHUNK_TTL`, which is 14 days. A relay that
leaves the directory inside that window removes one replica. §12.4 gives three
replicas under three operators, thus two replicas remain. **[ATT-016]** A
revision MUST measure the relay churn rate over 28 days before it lowers
`REPLICAS`.

**The null reference.** A `RelayRef` of 12 zero bytes names no relay. A backup
object of Part 4 §4.7.2 lives at `BACKUP_REPLICAS` relays, which is 2, thus the
second `RelayRef` of each of its refs is null. **[ATT-141]** A client MUST set a
`RelayRef` that names no relay to 12 zero bytes. **[ATT-142]** A receiver MUST
reject a `FileDescriptor` with a null `RelayRef` on a pairwise or group
channel. `ATT-018` requires three references on those channels.

### 12.3.3 The chunk commands

Part 6 §6.4 gives the command header. An attachment command uses that header,
and it puts the `chunk_id` in the `queue_id` field. A `CPRF` also answers each
accepted write, and item 11 gives that answer. Four of the twelve commands
belong to the replication of §12.4.1, and one registers a backup-class chunk.
Part 3 §3.2.3 gives the deniable authenticator that the `auth` field carries.
**[ATT-033]** An attachment command MUST NOT carry a signature.

| `cmd` | Name | Sent by | Payload |
| --- | --- | --- | --- |
| `0x70` | `CNEW` | Uploader | `cred_pk` 32 B, `read_pk` 32 B, then an `Admission` of Part 13 §13.2 |
| `0x71` | `CID` | Relay | `storage_token` 32 B |
| `0x72` | `CPUT` | Uploader | the chunk, exactly `CHUNK_SIZE` bytes |
| `0x73` | `CGET` | Downloader | empty |
| `0x74` | `CDAT` | Relay | the chunk, exactly `CHUNK_SIZE` bytes |
| `0x75` | `CDEL` | Uploader | empty |
| `0x76` | `CREP` | Uploader | the replica targets of §12.4.1 |
| `0x77` | `CRPUT` | Relay | `storage_token` 32 B and the chunk, exactly `CHUNK_SIZE` bytes |
| `0x78` | `CVFY` | Uploader | `nonce` 16 B |
| `0x79` | `CPRF` | Relay | `proof` 32 B |
| `0x7A` | `CRNW` | Downloader | empty |
| `0x7B` | `BNEW` | Uploader | `cred_pk` 32 B, `read_pk` 32 B, then an `Admission` of Part 13 §13.2 |

Each chunk carries two independent X25519 credentials.

```
cred_sk    := 256 bits from the device CSPRNG, one for each chunk
read_sk    := HKDF-SHA3-256("umbra/v1/chunk-read", file_key, chunk_index_be32)
```

1. **[ATT-034]** An uploader MUST make `cred_sk` from the device CSPRNG for each
   chunk. **[ATT-035]** An uploader MUST NOT derive `cred_sk` from `file_key`.
   **[ATT-036]** An uploader MUST NOT use one `cred_sk` for two chunks.
   **[ATT-160]** An uploader MUST retain the `cred_sk` of each chunk until the
   chunk is erased. `CHUNK_LIFE_MAX` after the `CNEW` ends that retention too.
   **[ATT-161]** When a client applies a deletion to a record with a descriptor
   it uploaded, it MUST send `CDEL` for each `ChunkRef`. A deletion is a
   tombstone of Part 7 §7.5.6 or a timer expiry of Part 7 §7.5.8. The `CDEL`
   goes to each relay of the ref. A recipient holds no `cred_sk`, thus a
   deletion by a recipient erases nothing at a relay, and Part 7 §7.5.6 states
   that limit.
2. **[ATT-037]** A client MUST derive `read_sk` of a file chunk from `file_key`
   and the index of the chunk. A handle-addressed chunk of §12.4.2 takes
   `read_sk` from its writer, under Part 4 rule `IDN-093` and Part 3 rule
   `NET-183`.
   Thus each party that holds the descriptor authorizes a `CGET`, and the
   descriptor carries no extra byte. Part 5 §5.11 holds the label
   `"umbra/v1/chunk-read"`. **[ATT-182]** A client MUST derive `read_sk` as
   `HKDF-SHA3-256(salt = "", ikm = file_key, info = "umbra/v1/chunk-read" ||
   BE32(chunk_index), L = 32)`, and it MUST clamp the result as an X25519
   scalar.
3. **[ATT-038]** A relay MUST select `storage_token` from its own CSPRNG.
   **[ATT-039]** A relay MUST NOT derive `storage_token` from `cred_pk`, from
   `read_pk`, or from the chunk bytes. **[ATT-055]** An uploader MUST select
   `chunk_id` from the device CSPRNG, and it MUST select one value for each
   chunk. **[ATT-056]** An uploader MUST NOT derive `chunk_id` from `file_key`,
   from `cred_pk`, from `read_pk`, or from the chunk bytes. **[ATT-057]** An
   uploader MUST use the same `chunk_id` at each of the `REPLICAS` relays that
   hold one chunk. **[ATT-058]** A relay MUST reject a `CNEW` whose `chunk_id`
   names a chunk that the relay holds.

   > *Cause.* §12.4 makes `REPLICAS` copies of each chunk mandatory, and §12.3
   > gives a replica 12 bytes of `RelayRef` and no chunk identifier of its own.
   > If each relay selects its own `chunk_id`, a downloader resolves which
   > relay holds a replica and has no identifier to request from it. The
   > mandatory redundancy is then unreachable at the one moment that needs it.
   > One client-selected value addresses each replica, and it keeps `ChunkRef`
   > at 120 bytes.
   >
   > One shared `chunk_id` gives two colluding replica relays nothing new. Those
   > two relays hold **byte-identical ciphertext** already, thus a comparison of
   > the stored bytes links the two copies with no identifier at all. The value
   > comes from the client CSPRNG, thus it carries no relation to `file_key`, to
   > the file content, or to a different chunk of the same file. §12.2.2 keeps
   > each of its three properties.
   >
   > `ATT-058` stops a squat. Without it a hostile client registers a
   > `chunk_id` that an honest upload later picks, and the honest upload then
   > fails or overwrites. The registration is first-come, and `CHUNK_TTL`
   > releases it.
4. **[ATT-040]** A relay MUST authorize `CPUT` and `CDEL` against `cred_pk`
   only. **[ATT-041]** A relay MUST authorize `CGET` and `CRNW` against
   `read_pk` only. **[ATT-180]** A relay MUST authorize `CREP` and `CVFY`
   against `cred_pk` only, and it MUST authorize a `CNEW` and a `BNEW` against
   the `cred_pk` that the payload carries, in the same manner as Part 6 §6.4
   authorizes a `NEW` against the key in its payload. **[ATT-181]** A pending
   registration whose bytes never arrive MUST leave the relay at `CHUNK_TTL`
   after the `CNEW` or the `BNEW`, and the relay MUST count it as `CHUNK_SIZE`
   of used store until then.
5. **[ATT-042]** The authorized bytes of a `CPUT` MUST hold `storage_token`.
   Thus a relay binds the upload to the registration that gave the token. Part 3
   §3.2.3 rule `NET-120` gives the encoding, which puts `storage_token` in the
   `bind` field of the authorized bytes.
6. **[ATT-043]** A `CPUT` and a `CDAT` MUST carry exactly `CHUNK_SIZE` bytes.
   **[ATT-044]** A relay MUST reject a `CPUT` of a different length. §12.2 pads
   the last chunk of a file to that length.
7. **[ATT-045]** A relay MUST apply the admission control of Part 13 to a
   `CNEW`. A `CNEW` names no earlier state, in the same manner as the `NEW` of
   Part 6 §6.4.
8. **[ATT-046]** A relay MUST erase a chunk at `CDEL`, and at `CHUNK_TTL` after
   the `CPUT` or after the last accepted `CRNW`. **[ATT-047]** A relay MUST NOT
   retain the identifier of an erased chunk. **[ATT-125]** A relay MUST NOT set
   the erase time of a chunk later than `CHUNK_LIFE_MAX` after the `CNEW`.
   **[ATT-126]** A relay MUST NOT answer a `CRNW`. A client that needs the chunk
   fetches it, and the fetch shows the state. The rule covers a `CRNW` that the
   relay refuses too. A `CRNW` for a chunk that the relay does not hold, and
   one whose authenticator fails, each get silence and no `NACK`. A relay could
   give a `NACK` for a chunk that it does not hold, and no answer for one that
   it holds. That difference would show the state that the rule keeps for a
   fetch.

   > *Cause.* A chunk lives 14 days. A `CRNW` at a fetch keeps a chunk that a
   > party still reads. `CHUNK_LIFE_MAX` bounds each renewal, thus a renewal
   > cannot keep a chunk for ever. An uploader that wants a chunk gone sends
   > `CDEL`, and a renewal does not override that command.
9. **[ATT-048]** A client MUST send an attachment command on the separate
   connection of §12.8.
10. **The backup class.** A `BNEW` registers a **backup-class chunk**, and a
    `CNEW` registers an attachment chunk. The two classes differ in the erase
    time and in nothing else. Part 4 §4.7.2 writes each backup object and the
    backup root in this class, and Part 3 §3.2.6 writes the dead-channel blob
    in it. **[ATT-127]** A relay MUST hold a backup-class chunk for `BACKUP_TTL`
    after the `CPUT` or the `CRPUT` that gave the bytes. Part 4 §4.8 gives that
    value. **[ATT-128]** A relay MUST reject a `CRNW` on a backup-class chunk.
    **[ATT-129]** A relay MUST apply each other rule of this section to a
    backup-class chunk as to an attachment chunk. The bound of `ATT-125` does
    not apply to that class. **[ATT-130]** A relay MUST apply the admission
    control of Part 13 to a `BNEW` as to a `CNEW`. **[ATT-131]** A client MUST
    NOT register a backup object under `CNEW`, and it MUST NOT register an
    attachment under `BNEW`. **[ATT-132]** A client MUST register a
    backup-class chunk at `BACKUP_REPLICAS` relays under different operators.
    `ATT-017` does not apply to that class.

    > *Cause.* Part 4 rule `IDN-073` holds a backup object for `BACKUP_TTL`, and
    > rule `IDN-075` sends it under the commands of this section. A `CNEW`
    > erases a chunk at `CHUNK_TTL`, which is 14 days. A relay cannot tell the
    > two retentions apart unless a command carries the class. One extra
    > registration command carries it, and a relay that holds no `BNEW` for a
    > `chunk_id` applies `CHUNK_TTL`. No `BGET` exists, because a `CGET` against
    > `read_pk` reads a chunk of each class.

11. **The answer to a write.** `ATT-099` sends a `CREP` after the `CPUT`
    succeeds, and a client that erases a chunk must learn that the relay did
    it. A `CPRF` carries each of the three answers, under the `corr_id` of
    the command (Part 6 rule `WIR-494`), thus no new command exists.
    **[ATT-186]** A relay MUST answer an accepted `CPUT` and an accepted
    `CREP` with a `CPRF` whose `proof` is `SHA3-256(corr_id || chunk)`, where
    `corr_id` is the 16 bytes of that command and `chunk` is what the relay
    holds. **[ATT-187]** A relay MUST answer an accepted `CDEL` with a `CPRF`
    of 32 zero bytes. **[ATT-188]** A client MUST compare the `proof` of
    `ATT-186` against the value from its own copy, and it MUST take a
    difference as a failed `CPUT` under `ATT-118`.

    > *Cause.* If a `CPUT`, a `CREP` and a `CDEL` get no answer but a `NACK`,
    > a client reads the absence of a `NACK` as success, and no time bounds an
    > absence. The `corr_id` comes from the CSPRNG of the
    > client for each command (`WIR-498`), thus it is a nonce of the form
    > that `ATT-114` asks for. The answer to a `CPUT` is then a first proof
    > of possession at no extra command.

### 12.3.4 The manifest level

A descriptor of *n* refs is 137 + 120*n* bytes, and §12.7 gives one cell 269
refs at bucket `B3`. A direct descriptor therefore stops at 269 data chunks,
which is 8.78 MB. `MAX_FILE_SIZE` is far above that value.

**The answer is one level of indirection, and the manifest is itself a file.**

```
level 0x00   the refs address data chunks            up to 269 chunks
level 0x01   the refs address manifest chunks        up to 72 899 data chunks
```

At level `0x01` the client builds the **manifest**, which is the concatenation
of the `ChunkRef` of each data chunk, in chunk order. The client then treats
that manifest exactly as a file.

```
manifest       = ChunkRef_0 || ChunkRef_1 || … || ChunkRef_{n-1}
K_manifest     = HKDF-SHA3-256( "umbra/v1/file-manifest", file_key, file_nonce )
```

The client segments the manifest under §12.2.3, and it seals each segment under
§12.3.1 with `K_manifest` in place of `file_key`. The `read_sk` of each
manifest chunk takes `K_manifest` as the `ikm` of `ATT-182` in the same manner,
thus the key of a data chunk opens no manifest chunk. It uploads those chunks under
§12.3.3 with `REPLICAS` copies. The descriptor then carries a `ChunkRef` for
each manifest chunk.

- **[ATT-072]** A client MUST use level `0x00` when the data chunk count is at
  or below the ref count that the descriptor bucket holds. For an attachment
  that count is `MESSAGE_DESCRIPTOR_REFS`, which leaves room in the record
  for the largest name, preview, and caption of Part 6 rules `WIR-531` and
  `WIR-535`.
  **[ATT-073]** A client MUST use level `0x01` above that count. **[ATT-074]** A parser MUST
  reject a `level` above `0x01`.
- **[ATT-075]** A client MUST derive `K_manifest` with the label above, and Part
  5 §5.11 holds that label. **[ATT-076]** A client MUST NOT encrypt a manifest
  under `file_key` itself.
- **[ATT-077]** A client MUST order the `ChunkRef` values of a manifest by the
  chunk index, from the lowest index to the highest index. **[ATT-078]** A
  receiver MUST reject a manifest whose length is not a whole multiple of 120
  bytes after the padding is removed. **[ATT-183]** A client MUST derive
  `K_manifest` as `HKDF-SHA3-256(salt = "", ikm = file_key, info =
  "umbra/v1/file-manifest" || file_nonce, L = 32)`. **[ATT-184]** A manifest
  carries no digest of its own: the tag of each manifest chunk under
  `K_manifest` authenticates it, and a receiver MUST accept a manifest whose
  chunks each verify under §12.3.1 and whose distinct `chunk_id` count equals
  the data chunk count of `padded_size`; two refs of one `chunk_id` are
  replicas of one chunk under `ATT-176`.
- **[ATT-079]** A receiver MUST rebuild the full manifest before it fetches a
  data chunk. **[ATT-080]** A receiver MUST NOT present a file as complete
  before it verifies `digest` under `ATT-031`.
- **[ATT-081]** A relay MUST NOT tell a manifest chunk from a data chunk. Each
  one is `CHUNK_SIZE` bytes under an independent random credential, thus §12.2.2
  holds without a change.

**The ceiling that this gives.** One manifest chunk holds 271 refs, because
`SEGMENT_SIZE` of 32 634 divided by 120 is 271 with 114 bytes left. A `B3`
descriptor holds 269 manifest refs. Thus one level addresses 269 × 271 = 72 899
data chunks, which is about **2.22 GiB**. `MAX_FILE_SIZE` of §12.7 is the policy
limit below that structural ceiling. **[ATT-082]** A revision MUST define a
second manifest level before it raises `MAX_FILE_SIZE` above 2.22 GiB.

> *Cause.* A descriptor that spans more than one cell is one answer to a file
> above 269 data chunks. It is the worse answer, because the descriptor travels in the
> pairwise channel, which is the metered path, and a 250 MiB file needs about
> 964 KB of descriptor. The manifest moves those bytes onto the attachment path
> of §12.8, where they cost 30 chunks and no message cell. The descriptor then
> stays at 3 737 bytes and one `B2` cell.

## 12.4 Redundancy is mandatory

Each chunk lives at `REPLICAS` relays under **different operators**. §12.4.1
gives the flow that puts it there, and the client uploads one copy.

**[ATT-017]** A client MUST register each chunk at **three or more relays under
different `operator_id` values** of Part 10 §10.5.3. Part 3 rule `NET-344`
relaxes the operator part in a provisional directory. **[ATT-018]** The
descriptor MUST carry the three references. **[ATT-123]** A client MUST NOT
upload more than one copy of a chunk, and §12.4.1 makes the relay push the
others.

> Without replicas, one relay outage breaks a transfer. Ordinary users do not
> accept that reliability failure.

At a retrieval, the client tries the replicas in an order that the client
randomizes. **[ATT-019]** The client MUST NOT use a fixed order. Thus the relay
load does not encode the order of the replicas.

### 12.4.1 The relay makes the copies, and the client does not

**A client uploads one copy of a chunk. The relay that takes that copy pushes
the other `REPLICAS` − 1 copies.**

```
client ──CNEW──▶ relay A     client ──CNEW──▶ relay B     client ──CNEW──▶ relay C
       ◀─CID───              ◀─CID───                     ◀─CID───
                                                     (three small commands,
                                                      three storage tokens)

client ──CPUT───────────▶ relay A        one chunk, CHUNK_SIZE bytes
client ──CREP───────────▶ relay A        the refs and tokens of B and C

                          relay A ──CRPUT──▶ relay B
                          relay A ──CRPUT──▶ relay C

client ──CVFY──▶ relay B                 a sampled proof of possession
       ◀─CPRF──
```

**The registration stays with the client.** The client sends `CNEW` to each of
the `REPLICAS` relays and it keeps the `storage_token` of each one. That token
is what stops a relay from pushing bytes into a relay that no client named.

- **[ATT-096]** A client MUST send `CNEW` to each of the `REPLICAS` relays of a
  chunk before it sends `CPUT`. **[ATT-097]** A client MUST send `CPUT` to one
  of those relays only.
- **[ATT-098]** A client MUST send `CREP` to the relay that took the `CPUT`.
  **[ATT-099]** A client MUST send `CREP` after that `CPUT` succeeds.

**The `CREP` payload.**

```
CrepPayload {
    version        u8        // 0x01
    target_count   u8        // 1 to HOT_REPLICAS - 1
    targets        [target_count]ReplicaTarget
}

ReplicaTarget {
    relay_id       [32]u8    // the relay that takes the copy
    storage_token  [32]u8    // the token that the CID of that relay gave
}
```

A `ReplicaTarget` is 64 bytes, thus a `CREP` at `REPLICAS` of 3 carries 130
bytes and it fits bucket `B0`. A `CREP` at `HOT_REPLICAS` of 6 carries 322 bytes
and it fits bucket `B1`, and a `CREP` for a backup-class chunk at
`BACKUP_REPLICAS` of 2 carries one target. **[ATT-185]** A relay MUST reject a
`CREP` whose `target_count` is 0 or above `HOT_REPLICAS` − 1. `ATT-057` makes
the `chunk_id` one value at each replica, thus the `queue_id` field of the
command names the chunk at each target and a target needs no identifier of its
own.

- **[ATT-100]** A client MUST put the `storage_token` that each target issued in
  the target of that relay. **[ATT-101]** A client MUST NOT put a token of one
  relay in the target of another relay.
- **[ATT-102]** A relay MUST send one `CRPUT` to each target of a `CREP`.
  **[ATT-103]** A relay MUST put the `storage_token` of that target in the
  `CRPUT` payload. **[ATT-104]** A relay MUST send the bytes that the `CPUT`
  gave it, without a change.
- **[ATT-105]** A relay MUST NOT send a `CRPUT` to a relay that a `CREP` did not
  name. **[ATT-106]** A relay MUST NOT keep a `storage_token` of another relay
  after it sends the `CRPUT` that uses it.

**The target authorizes on the token, and not on the credential.**

- **[ATT-107]** A relay MUST authorize a `CRPUT` against the `storage_token`
  that its own `CID` issued for that `chunk_id`. **[ATT-108]** A relay MUST NOT
  authorize a `CRPUT` against `cred_pk`. The pushing relay holds no `cred_sk`,
  and Part 3 §3.2.3 keys the deniable authenticator on that secret.
- **[ATT-109]** A relay MUST accept one `CRPUT` for each registration.
  **[ATT-110]** A relay MUST reject a second `CRPUT` for a `chunk_id` that it
  holds. `ATT-058` states the same rule for a `CNEW`.
- **[ATT-111]** A relay MUST reject a `CRPUT` whose payload is not 32 682 bytes.
  **[ATT-112]** A relay MUST erase the `storage_token` of a registration when it
  accepts the chunk.

**The client verifies a sample, because a relay can drop a push in silence.**

```
proof = SHA3-256( nonce || chunk )
```

- **[ATT-113]** A client MUST send a `CVFY` to each replica relay for each
  chunk that the relay holds. **[ATT-114]** A client MUST draw `nonce`
  from the device CSPRNG for each `CVFY`.
- **[ATT-115]** A relay MUST answer a `CVFY` with a `CPRF` that carries the
  value above. **[ATT-116]** A relay MUST answer with an unknown-chunk response
  when it holds no chunk at that `chunk_id`.
- **[ATT-117]** A client MUST compare `proof` against the value that it computes
  from its own copy. **[ATT-118]** If the two values differ, or if the relay
  answers unknown-chunk, the client MUST send `CNEW` and `CPUT` to a fresh relay
  for that chunk. **[ATT-119]** The client MUST report the relay that failed as
  a link fault under Part 10 §10.4.2.

- **[ATT-189]** A registration, a `CPUT` or a `CREP` that a relay refuses,
  or that gets no answer, fails the chunk before its copies exist. The client
  MUST then start that chunk again at a new draw of relays that leaves out
  the relay that failed, under a new `chunk_id` and a new `cred_sk`
  (`ATT-036`, `ATT-055`), and it MUST send a `CDEL` to each relay that gave
  it a `storage_token` for the old start. It SHOULD send one also to each
  relay of the old start whose registration has no answer yet. That relay can
  register after the new start, and a relay refuses a `CDEL` of a chunk that it
  does not hold at no cost. A registration that the client leaves alone holds
  `CHUNK_SIZE` of that relay until `CHUNK_TTL` (`ATT-181`).
- **[ATT-190]** A `CVFY` can arrive before the copy that it asks for, because
  the copy travels on a connection of its own. A client MUST ask again some
  times before it applies `ATT-118` to a relay that answers unknown-chunk. A
  client MUST bound the time that it waits for one answer, and the count of
  the new relays and the new starts of one chunk. Past that count the upload
  fails, and the message fails with it. The reference client asks 6 times,
  waits 30 seconds, and stops at 3. Its wait before each new ask is two times
  the wait before, from 1 second, thus a copy has about 30 seconds to arrive.
- **[ATT-197]** A relay set can hold no fresh relay for a chunk: each other
  relay holds a copy, failed, or is of an operator of a copy. When a relay of
  such a chunk still answers unknown-chunk after the asks of `ATT-190`, the
  client MUST send the `CPUT` to that relay itself, under the `storage_token`
  that the relay gave at its registration. This `CPUT` counts as a new relay
  under the bound of `ATT-190`. When the relay refuses that `CPUT`, the client
  MUST ask for the proof again, because the copy of the first relay arrived in
  that time. A relay whose proof differs gets no such `CPUT`, and `ATT-118`
  holds for it.

  > *Cause.* A copy that did not arrive is a fault of the path between two
  > relays, and the relay that waits for it did nothing wrong. A network with
  > three file relays, or with one operator, has no fresh relay. Without this
  > rule one late copy fails the whole upload there.

**Each copy.** **[ATT-120]** A client MUST verify each copy of each chunk.
**[ATT-121]** A client MUST NOT leave a copy out, because a relay that could
predict the copies that go unchecked would replicate those alone and drop the
others. A sample saves about 8 MiB of `B0` cells on a file of 250 MiB, and it
repairs only the chunk whose copy fails, thus the other copies that a bad
relay drops stay lost.

**What this costs and what it saves.**

| | Client uplink for a 250 MiB object | Chain traffic at 3 hops | Direct relay to relay |
| --- | --- | --- | --- |
| A client that uploads 3 copies | 762.0 MiB | 2.23 GiB | 0 |
| **The rule above** | **267.7 MiB** | **803 MiB** | **503.9 MiB** |

§12.7.2 derives each figure. The saving is 2.85 times on the uplink of the
device, and the relay carries the difference on a mains-power link with
flat-rate bandwidth. Part 3 §3.6.3 applies the same principle to the cover
traffic, and Part 10 §10.2 already ranks a relay by its capacity class.

**The residual, stated.**

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The relay
> that takes the `CPUT` learns the `relay_id` of the other `REPLICAS` − 1
> relays for that chunk. A client that uploads each copy itself gives no relay
> that fact.
>
> The bound is that §12.3.3 already concedes the linkage. The three replicas
> hold **byte-identical ciphertext**, thus a comparison of the stored bytes
> links the three copies with no identifier at all. The rule above removes the
> collusion step and it adds no new capability. Part 15 §15.3 records the
> residual.
>
> **[ATT-122]** A client MUST select the `REPLICAS` relays of one chunk
> independently of the relays of each other chunk. Thus no relay learns the
> replica set of a second chunk of the same file, and §12.2.2 holds without a
> change.

### 12.4.2 The handle-addressed chunk

A **handle-addressed chunk** is a backup-class chunk whose `chunk_id` is a value
that the reader derives without the writer. The backup root of Part 4 §4.7.2,
the dead-channel blob of Part 3 §3.2.6, and the three chunks of a device
link of Part 7 §7.4 are such chunks. Each of them
gives the reader a secret from which it derives the `chunk_id`, the `read_sk`,
and the content key. That reader holds no descriptor, thus it needs a rule that
names the relays without one. The rule is a rank over the relay set that each
party holds.

```
rank(h, r) = SHA3-256( "umbra/v1/chunk-place" || h || relay_id_r )
```

The value `h` is the `chunk_id`. The value `r` ranges over the relays of the
current consensus that declare the attachment role (Part 10 §10.5.3, `roles`
bit 3). The **placement list** of `h` is that set in ascending order of
`rank`. The list drops each relay whose `family_id` an earlier relay of the
list holds. Part 5 §5.11 holds the label.

1. **[ATT-133]** A writer MUST select the first `BACKUP_REPLICAS` relays of the
   placement list of `h`. **[ATT-134]** If a `BNEW` at a selected relay fails,
   the writer MUST replace that relay with the next of the list. **[ATT-135]**
   A writer MUST send `CPUT` to the selected relay of the lowest rank and
   `CREP` for the others, under §12.4.1.
2. **[ATT-136]** A reader MUST send `CGET` to the relays of the placement list
   in list order, and it MUST try each distinct chunk that they give until
   one opens: a relay that serves bytes that do not open hides no chunk. A
   read that no relay answered with a chunk or with a plain refusal knows
   nothing of the handle, and it is no empty handle. **[ATT-137]** A reader MUST NOT
   ask more than `PLACE_PROBE` relays for one `h`. §12.7 sets that value to 4.
3. **[ATT-138]** Before a writer replaces the chunk under one `h`, it MUST send
   `CDEL` to each relay that holds it. `ATT-058` rejects a registration under
   a held identifier, and that rule applies to each class.
4. **[ATT-139]** A party MUST compute the placement list from the consensus
   that it holds. **[ATT-143]** A party MUST NOT fetch a consensus for that
   computation. Part 10 §10.5 forbids a session for the only purpose of a
   directory diff.
5. **[ATT-140]** If a handle-addressed chunk has no named write credential, the
   writer MUST use a random `cred_sk` of `ATT-034`. Part 4 §4.7.2 names one
   for the backup root, and Part 3 §3.2.6 names none for the dead-channel
   blob.

A handle-addressed chunk is one exception to `ATT-055` and `ATT-056`. The
identifier comes from a secret that the two readers share and that no relay
holds. Thus the three properties of §12.2.2 hold under the same argument.

> *Cause.* Part 4 §4.7.2 derives `backup_handle_epoch`, and that value names
> no relay. Without a placement rule, a restore needs a stored relay list, and
> the lost device holds that list. A rank over the consensus gives the reader and
> the writer one list from public data and one secret. In the common case, two
> relays that join between the write and the read take at most two places at
> the list head. `PLACE_PROBE` of 4 covers that drift for `BACKUP_REPLICAS` of
> 2. A `CGET` of a missing chunk costs one `B0` command and one `NACK`.

## 12.5 Post-quantum protection

The file key moves in the PQ-protected channel, which is the pairwise channel or
the group channel. Thus the attachment inherits post-quantum confidentiality
**at no cost**. There is no KEM for each chunk, and there is no KEM header on a
chunk.

This design closes a gap in the reference system. The XFTP of SimpleX encrypts a
file with the NaCl `secret_box` and has **no KEM**. Its group channel also has
no PQ layer. Thus an archived attachment to a group is fully exposed
harvest-now-decrypt-later material. Part 5 §5.8 makes group PQ protection
mandatory in UMBRA, and that rule is the cause that this inheritance operates.

## 12.6 Group attachments

The sender uploads the file **one time for the group**. §12.4 makes that upload
`REPLICAS` copies of each chunk, and that factor does not follow the group size.
One group record of Part 11 §11.3 carries the descriptor to each member. Thus
three properties hold:

- The upload cost is O(1) in the group size, and it is not O(N).
- The descriptor cost is one group record, and the descriptor is small. A
  1-chunk descriptor is 257 bytes and a 13-chunk descriptor is 1 697 bytes, and
  bucket `B1` holds both. Part 6 §6.9 gives 155 bytes of `B0` text at the
  default chunk and 226 bytes with no chunk. Thus no descriptor fits `B0`.
- A relay that holds a chunk learns a download count and nothing else. That
  relay does not learn the group, the membership, or the file.

## 12.7 Parameters

| Parameter | Value |
| --- | --- |
| `CHUNK_SIZE` | 32 650 B |
| `SEGMENT_SIZE` | 32 634 B, which is `CHUNK_SIZE` less the 16-byte tag (§12.2.3) |
| `MAX_FILE_SIZE` | **250 MiB** (§12.7.2) |
| `CHUNK_TTL` | 14 days, below `MSG_TTL` (§12.7.1) |
| `CHUNK_LIFE_MAX` | 28 days. §12.3.3 rule 8 bounds a renewed chunk |
| `REPLICAS` | 3, on different operators |
| `MAX_CONCURRENT_CHUNKS` | 128 up, 32 down, and §12.7.2 derives both from the bandwidth-delay product |
| `RELAYREF_WIDTH` | 12 B (§12.3.2) |
| `MAX_DESCRIPTOR_REFS` | 269, which is one `B3` cell |
| `MANIFEST_REFS_PER_CHUNK` | 271, which is `SEGMENT_SIZE` divided by 120 |
| `MAX_DATA_CHUNKS` | 72 899, which is about 2.22 GiB (§12.3.4) |
| `VOICE_MAX_SECONDS` | 900, which is 15 minutes |
| `UPLOAD_QUOTA_DAY` | 512 MiB for each token or proof-of-work solution each day, before the replicas |
| `CHUNK_STORE_MIN` | 100 GiB for a relay that declares the attachment role (§12.10) |
| `CHUNK_STORE_TARGET` | 200 GiB (§12.10) |
| `LARGE_FILE_WARN` | 25 MiB (§12.7.2) |
| `PLACE_PROBE` | 4 relays for one handle (§12.4.2) |
| `IMAGE_REENCODE_BYTES` | 2 MiB (§12.3) |
| `FILE_NAME_MAX` | 255 bytes of UTF-8, the name of Part 6 rule `WIR-531` |
| `PREVIEW_MAX` | 6 144 bytes, the JPEG thumbnail of Part 6 rule `WIR-533` |
| `CAPTION_MAX` | 1 024 bytes of UTF-8, the caption of Part 6 rule `WIR-535` |
| `PREVIEW_SIDE` | 128 pixels, the longest side of that thumbnail (`ATT-194`) |
| `MESSAGE_DESCRIPTOR_REFS` | 207, which is `MAX_DESCRIPTOR_REFS` less the 62 refs of the largest trailer of Part 6 rules `WIR-531` and `WIR-535` (`ATT-072`) |
| `AUTO_DOWNLOAD_DEFAULT` | 25 MiB, which equals `LARGE_FILE_WARN` (Part 14 rule `IMP-167`) |
| `CHUNK_EGRESS_BUDGET_DAY` | 4 × `CHUNK_STORE_TARGET` of egress in one day, measured by the relay from midnight UTC (§12.11) |
| `CHUNK_FETCH_RATE` | 60 `CGET` for one chunk in one hour, measured by the relay from the first fetch of the hour (§12.11) |
| `HOT_REPLICAS` | 6 replicas of one chunk at the most. It bounds the targets of a `CREP` (§12.4.1) |

> *The derivation of `CHUNK_SIZE`.* A chunk travels as the whole payload of one
> command at bucket `B3`. Part 6 §6.9 gives the `L5 payload` row 32 650 bytes at
> `B3`. Thus `CHUNK_SIZE` is 32 650 bytes.
>
> The `B3` cell is 32 768 bytes, and 118 bytes of that cell carry the layers
> below the payload. Those 118 bytes are 32 bytes of `circ_id` and cell tag, 2
> bytes of cell command and padding marker, and the 84-byte command header.
> **[ATT-020]** If the bucket ladder or the command header changes, a revision
> MUST derive this value again.

> *The descriptor ceiling.* A descriptor of *n* refs is 137 + 120*n* bytes
> (§12.3.2). Part 6 §6.9 gives the body of an `AppMessage` with no PQ chunk 226,
> 1 762, 7 906, and 32 482 bytes at the four buckets. Thus one cell holds no ref
> at `B0`, 13 refs at `B1`, 64 refs at `B2`, and 269 refs at `B3`. Part 5 §5.5.2
> rule `CRY-018` selects the chunk width that fits the bucket. **[ATT-021]** A
> client MUST select the bucket of a descriptor from those four values.
>
> §12.3.4 makes a ref address a manifest chunk above 269 data chunks, thus the
> structural ceiling is 72 899 data chunks and about 2.22 GiB. **[ATT-022]** A
> client MUST NOT send an attachment above `MAX_FILE_SIZE`. **[ATT-023]** A
> revision MUST derive §12.7.2 again before it raises that value.

### 12.7.1 `CHUNK_TTL` is two weeks

`CHUNK_TTL` is 14 days, and the `MSG_TTL` of Part 3 §3.2.4 is 45 days. A relay
holds an undelivered message for `MSG_TTL`, and a descriptor is the body of such
a message. Thus a recipient that returns on day 20 gets the descriptor and finds
each chunk gone.

- **[ATT-050]** A client MUST show a file whose download finds no chunk, and
  whose record is older than `CHUNK_TTL`, as expired. It MUST NOT offer a new
  attempt for that file, because no party re-uploads the chunks.
- **[ATT-051]** A revision that changes `CHUNK_TTL` MUST state the loss above
  again against `MSG_TTL`.

> *Cause.* A chunk store holds each chunk for `CHUNK_TTL`, thus the store of a
> relay and the time that a flood holds it are both about a third of the
> figures at 45 days (§12.10). The cost is a U6
> reliability failure on the path of a recipient that stays away more than two
> weeks: the message arrives, and its file does not. A group whose epoch keys
> travel on the chunk path (Part 11 `GRP-284`) sees the same loss for a member
> that stays away that long, and the key supply of Part 11 §11.4.3 repairs it.
> SimpleX holds a file for 48 hours, thus this value sits between that design
> and a `CHUNK_TTL` equal to `MSG_TTL`.

**[ATT-162]** A revision MUST hold `BACKUP_TTL` of Part 4 §4.8 at or above
`BACKUP_LOOKBACK` weekly epochs less one epoch. **[ATT-163]** A revision MUST
hold `BACKUP_TTL` above `BACKUP_FULL_INTERVAL` plus `BACKUP_HISTORY_DAYS`. The
first bound keeps each epoch of a restore inside the retention of a
backup-class chunk, and Part 4 rule `IDN-074` gives the other direction. The
second bound keeps the newest full object and its 45 days of deltas alive
together.

The cost of a longer `CHUNK_TTL` is relay storage and nothing else. A chunk is 32 650
bytes of ciphertext under a key that no relay holds. Part 3 §3.2.4 states the
same trade for `MSG_TTL`, which is that stored ciphertext is a storage cost and
not an exposure. The `CHUNK_TTL` of 14 days is longer than the 48 hours of
SimpleX.

Three rules bound the failure that stays.

1. **[ATT-052]** If each replica of a chunk is gone, the client MUST report the
   failure to the user and MUST name the file. A replica whose `relay_hint`
   resolves to no relay is out of reach under `ATT-010`, and it is no statement
   that its chunk is gone. Thus a fetch that such a replica stops is a failure
   that the user can try again. `CHUNK_LIFE_MAX` after the client took the
   record of the file, no relay holds a chunk of it. A fetch that fails from
   then on is the failure of this rule. The file is gone, and no new attempt
   fetches it.
2. **[ATT-053]** The client MUST NOT show a partial file. §12.3.2 rule 4 states
   the same rule for an unresolvable reference.
3. **[ATT-054]** The client MUST offer the sender a re-send of the file. A
   re-send is a new upload with new credentials, and it is not a lease
   extension.

### 12.7.2 What a 250 MiB attachment costs, stated

`MAX_FILE_SIZE` is 250 MiB, which is 262 144 000 bytes.

| Quantity | Value |
| --- | --- |
| Data chunks | 8 033, which is 262 144 000 and the pad marker divided by `SEGMENT_SIZE` of 32 634, rounded up |
| Manifest chunks | 30, and §12.3.4 derives them |
| Chunks in total | 8 063 |
| Descriptor | 137 + 30 × 120 = 3 737 bytes, thus one `B2` cell |
| `CNEW` and `CID`, 3 for each chunk | 24 189 commands, batched 3 to a `B0` cell under Part 6 §6.4.1, which is 8 063 cells and 4.31 MiB |
| `CPUT`, 1 for each chunk | 8 063 `B3` cells at 32 860 bytes, which is **252.7 MiB** |
| `CREP`, 1 for each chunk | 8 063 commands, batched 2 to a `B0` cell, which is 4 032 cells and 2.15 MiB |
| `CVFY`, 1 for each copy | 16 126 `B0` cells and 8.61 MiB |
| **Client uplink** | **about 267.7 MiB** |
| `CDEL` at a deletion, 3 for each chunk | 24 189 commands, batched 3 to a `B0` cell, which is 8 063 cells and 4.31 MiB |
| Direct relay to relay, 2 `CRPUT` for each chunk | 16 126 × 32 766 = about 503.9 MiB |
| Download at one replica | 8 063 × 32 860 = about 252.7 MiB |
| Upload time, Fast mode, 5 Mbit/s uplink | about **7.5 minutes**, and the uplink binds it |
| Upload time, Balanced mode | about **7.5 minutes**, and the uplink binds it |
| Upload time, Private mode | about **7.5 minutes**, and the uplink binds it |
| Download time at 20 Mbit/s, Fast, Balanced, Private | about 2, 5.5, and 19 minutes |

**The round-trip model.** A chain of Part 3 §3.12 costs about 210 ms of
propagation in each direction. Thus a round trip is about 0.42 s in Fast mode.
Balanced mode adds an Erlang(3) delay of mean 0.45 s in each direction under
Part 3 §3.9. Private mode adds 2.1 s in each direction. Thus a round trip is
about 1.32 s in Balanced mode and about 4.62 s in Private mode. The window of
`MAX_CONCURRENT_CHUNKS` holds 128 chunks up, which is 4 206 080 bytes in flight,
and 32 chunks down, which is 1 051 520 bytes.

**The turn of the window.** The answer to a `CPUT` and to a `CGET` leaves its
relay when the relay serves the command (Part 3 rule `NET-360`), with no wait
for the pacing clock of Part 3 §3.5.2. One turn of the window is one round
trip: about 0.42 s in Fast mode, 1.32 s in Balanced mode, and 4.62 s in
Private mode. A window divided by its
turn gives the throughput, and the smaller of that figure and the link rate
gives the time. A file of 8 MiB is 257 chunks, thus its upload takes about
14 s in each mode at a 5 Mbit/s uplink, and that uplink binds it. The start
of the circuits, the proofs, and the manifest chunk add some round trips. With
a wait of `PACING_MEAN` in each of those steps, a measurement on the launch
network gave 38 to 45 s for such a file on a 22 Mbit/s uplink, and about 20 s
of it were those steps. With no such wait the same file took 18 to 21 s. Of
that time the device used about 9 s for the 15 solutions of Part 13 rule
`ABU-107`, one after the other, and the registrations ran one window ahead
only. With the solutions made at one time on each thread of the device, and
with the registrations of `ATT-199`, the file took 15 to 18 s. The
registrations of a chunk run before its `CPUT` takes its place in the window,
and its `CREP` and its `CVFY` run after it, thus neither adds a turn.

- **[ATT-164]** A client MUST NOT hold more than 128 `CPUT` in flight.
  **[ATT-198]** A client MUST start an upload with a window of 32 `CPUT`. It MUST
  add 2 to the window for each `CPUT` whose answer comes inside 8 s. It MUST take
  4 from the window for each `CPUT` whose answer comes after 15 s, and it MUST
  halve the window at each `CPUT` with no answer inside the bound of `ATT-190`.
  The window MUST NOT go below 8.
  **[ATT-199]** A client MUST NOT hold more than 256 chunks that register or
  that wait for their `CPUT` with their tokens.
  **[ATT-165]** A client MUST NOT hold more than 32 `CGET` in flight.
  **[ATT-166]** A client MUST send the `CREP` of a chunk while the `CPUT` of the
  next chunk is in flight. **[ATT-178]** A client MUST NOT wait for the `CRPUT`
  of a replica before the next `CPUT`. **[ATT-167]** A client MUST build the
  attachment circuit of §12.8 in the privacy mode of the conversation that
  carries the descriptor.

> *Cause.* A window of 8 fills a 5 Mbit/s uplink at a 0.42 s round trip. The
> delay of the mode and the load of a relay make the turn longer: a
> measurement on the launch network gave about 4 s, with one pacing wait of
> 1 s in it that `NET-360` held then. A window of 8 then carries
> 0.5 Mbit/s, and a window of 128 carries about 8 Mbit/s. A relay holds no count
> of the `CPUT` of one client, thus the window is a limit of the client only.
> The clock of a step starts when its command enters the link. A window of 128
> on an uplink of 1 Mbit/s holds its last `CPUT` for 34 s, which is above the
> bound of `ATT-190`. Thus the window of `ATT-198` starts small and follows the
> time of the answers. A registration takes a round trip of its own, and it
> waits behind the bytes of the `CPUT` on its link. With the registrations one
> window ahead, each `CPUT` left when its registration ended, and the window
> stayed empty. Thus `ATT-199` lets the registrations run 256 chunks ahead. A
> registration with no bytes holds `CHUNK_SIZE` of the store of a relay until
> `CHUNK_TTL` (`ATT-181`), thus the count has a bound. The download window of 32 fills a 20 Mbit/s downlink
> at the model turn. A bulk circuit in
> a faster mode than its conversation shows the mode of that conversation to
> the ingress relay, which Part 3 §3.9.1 forbids.

**A 250 MiB attachment costs about 267.7 MiB of the uplink of the device.**
§12.4.1 makes the relay carry the copies, thus the device pays about 1.07 times
the object and not 3.0 times it. The remaining 7 percent is the `CNEW` traffic,
the `CREP` traffic, the `CVFY` of each copy, and the padding of the `B3`
bucket.

No usability goal of Part 2 §2.4 caps an attachment upload. A client that sends
such an object on a metered plan still spends about 268 MiB of that plan, and
this section states that plainly. A deletion of the same object costs 4.31 MiB
more, under `ATT-161`.

**[ATT-083]** A client MUST show the uplink cost of an attachment above
`LARGE_FILE_WARN` before it starts the upload. **[ATT-084]** A client MUST let
the user cancel at that point. **[ATT-085]** A client MUST NOT start an upload
above that size on a metered network without a user action.

> **Erasure coding, examined and rejected.** A systematic Reed-Solomon code
> lowers the storage factor from 3.0 to 1.5. Part 5 §5.5.2 already specifies
> such a code over GF(2¹⁶), thus the code itself adds no primitive and no crate.
> At *k* of 8 and *r* of 4 the twelve fragments of one group sit four on each of
> three operators, and any eight rebuild the group.
>
> **The code is not compatible with §12.4.1.** A systematic code needs one party
> to hold each of the *k* data chunks of a group at one moment, because the
> parity is a function of all of them. That party is a client or a relay, and
> neither works.
>
> - A relay that computes the parity holds 8 chunks of one file. §12.2.2 states
>   that a relay cannot find that two chunks belong to the same file, thus this
>   path gives up a stated property.
> - A client that computes the parity uploads 12 fragments for each 8 chunks,
>   which is a factor of 1.5 on the link of the device. §12.4.1 gives that link
>   a factor of 1.04. Thus the code costs the device 44 percent more upload to
>   save relay storage, and §12.10 already sizes that storage.
>
> Two more costs stand against it. A file below *k* chunks needs padding to a
> whole group, thus a 30 KB object costs 12 chunks and about 392 KB. A rule that
> applies the code above a size threshold makes two classes of object, and
> §12.2.1 rejects exactly that shape for the chunk size, because the variation
> is itself a fingerprint. A single operator outage also needs 8 fragment reads
> to rebuild one chunk, against 1 read under a replica.
>
> `ATT-016` gates any change to `REPLICAS` on a measurement of the relay churn
> over 28 days. No party has that measurement. **[ATT-124]** A revision that
> takes the code above MUST make that measurement first, and it MUST state the
> §12.2.2 concession or the device cost in the Part 2 §2.4 table.

## 12.8 Transport separation

**[ATT-024]** An attachment transfer MUST use a **separate connection**, or
separate QUIC streams, from the interactive messaging. Head-of-line blocking on
the retransmit of one chunk stalls the chat delivery. That stall occurs on the
lossy mobile links where UMBRA has to operate.

A mix of the two traffic types also makes the composite flow shape more
distinctive. A1 reads the timing and the volume of the interactive messages
inside that composite flow. Part 3 §3.2.5 and Part 3 §3.5.2 protect the same
property, which is G8. This rule makes no claim of flow-level undetectability
(Part 3 §3.8.1).

## 12.9 What relays learn

| Party | Learns | Does not learn |
| --- | --- | --- |
| **Chunk relay** | That a client uploaded a blob of `CHUNK_SIZE` bytes under a random credential. The download count and the times. Which registrations one proof-of-work solution admitted (Part 13 `ABU-107`): at most `POW_CHUNK_ALLOWANCE` chunks of one upload at that relay, which the relay thus joins to each other | The file identity, and the chunks of the same file that another solution or a token admitted. Each other file of the uploader, because no solution serves two uploads (Part 13 `ABU-108`). The uploader identity and the recipient identity. The filename, the size before the padding, and the content |
| **Chunk relay that holds a backup object** | The same items. Part 4 §4.7.2 writes a backup under the rotating handle of that section, thus the relay reads a random 32-byte handle and ciphertext | Which user owns the backup, and the Recovery Code that opens it. Part 4 §4.7.1 splits that code, and Part 15 §15.1 holds the two rows |
| **The three replica operators in collusion** | That one chunk is in three locations | Nothing that links that chunk to a different chunk or to a user |
| **Each relay that holds a chunk of one file, in collusion** | The chunk count, and thus an approximate padded file size | The content, the participants, and the filename |
| **Chunk relay that holds the catch-up object of Part 7 §7.5.1** | The same items as the first row, under the random credential of that object | The device set, and which device of the set wrote or read it |
| **Chunk relay that holds the dead-channel blob of Part 3 §3.2.6** | The same items as the second row, under the handle of that section | The two parties of the channel, because the handle is a derived value that neither party publishes |
| **Chunk relay that holds a chunk of a device link of Part 7 §7.4** | The same items as the second row, under a handle that the two devices derive. The `LinkOffer` sits unsealed at the relay. The offer is a version byte, a `link_pk`, and padding. Thus the relay that holds it can tell that the chunk is a link offer, and it learns the time of one link event | The device set, the two devices, and each later chunk of the link, which sits under another handle and is sealed |
| **Chunk relay that holds the group-state object of Part 7 rule `DEV-298`** | The same items as the second row: one backup-class object under a random credential, and one fetch for each other device of the set | The group, the device set, and that the object is a group state and not a backup |
| **Chunk relay that holds a chunk of the epoch-key object of Part 11 §11.4.2** | That one member fetched one chunk of an object of the size the member count gives, and the download count of each chunk, which is the number of members whose slot sits in that chunk | The member index of the fetcher and the group. The relay does not learn a group identifier, because the descriptor travels in a group record and not to the chunk relay |
| **Chunk relay that holds a chunk of a roster snapshot of Part 11 §11.9.8** | The same items as the first row, and a download count of one for each joiner that the same snapshot served | The group, the roster, and the joiner, because the descriptor travels in the admit stage of the invitation on a pairwise channel |

**The residual of the first row.** `ATT-004` holds for two chunks that two
admissions cover, and `ATT-005` holds for the chunks of two uploads. Neither
rule holds for the chunks of one upload that one solution admits at one relay.
The relay reads the same solution on each of those registrations, and Part 13
`ABU-107` makes it count them. The relay thus joins those chunks to each other,
and it learns a lower bound of the padded size of one file. It joins them to no
chunk of another upload and to no party. A client that pays each registration
with a token of its own leaves no such set. Part 15 §15.3 holds the row.

**[ATT-066]** A revision that adds a client of the chunk path MUST add a row to
this table. The clients of that path today are the attachment of §12.3, the
backup of Part 4 §4.7.2, the catch-up object of
Part 7 §7.5.1, the dead-channel blob of Part 3 §3.2.6, the epoch-key object of
Part 11 §11.4.2, and the roster snapshot of Part 11 §11.9.8.

## 12.10 The relay storage budget

`MAX_FILE_SIZE` of 250 MiB moves the storage cost of an attachment relay from a
detail to a deployment constraint. Part 10 §10.9.1 sizes the outbound budget of
a queue relay, and this section sizes the store of an attachment relay.

**The steady-state formula.** A relay holds each chunk for `CHUNK_TTL`, thus the
store reaches a steady state at that period.

```
stored_bytes = users × upload_bytes_each_day × REPLICAS × CHUNK_TTL
             ÷ attachment_relay_count
```

Part 3 §3.12 models a moderate user at 2 files each day. The media mix of those
files is 80 percent images at about 400 KB after the re-encode of `ATT-156`. The
rest is 15 percent voice notes at about 200 KB and 5 percent documents at about
2 MB. The mean is about 452 KB, thus the day is about 904 KB. That user costs
904 KB × 3 × 14 = **38 MB** of network storage at the steady state. A `CRNW` of
§12.3.3 extends a chunk to `CHUNK_LIFE_MAX` at the most, thus a chunk that a
party renews costs two times that figure.

| Store | Moderate users that it holds |
| --- | --- |
| `CHUNK_STORE_MIN`, 100 GiB | about 2 830 |
| `CHUNK_STORE_TARGET`, 200 GiB | about 5 650 |

- **[ATT-086]** A relay that declares the attachment role MUST hold
  `CHUNK_STORE_MIN` of free storage. **[ATT-087]** A relay MUST publish the
  declared store in `chunk_store_gib` of its descriptor of Part 10 §10.5.3.
  **[ATT-088]** A directory authority MUST reject an attachment role from a
  relay whose `chunk_store_gib` is below `CHUNK_STORE_MIN`.
  - While the directory is provisional (Part 10 `REL-126`), the floor of
    `ATT-086` and `ATT-088` does not apply. That is the bootstrap period of
    Part 3 `NET-340` to `NET-345`, in which the project runs each relay. A
    relay with the attachment role can then declare less than
    `CHUNK_STORE_MIN`, and an authority admits it. `ATT-087` holds
    unchanged: the relay publishes the store that it holds, and the store
    level of `ATT-144` shows a writer the smaller store.
  - The floor applies from the first directory that is not provisional. A
    relay below it then loses the attachment role.
- The `RelaySetDiff` of Part 10 §10.5.3 carries a two-bit store level for each
  relay. **[ATT-144]** A writer SHOULD prefer a relay at store level 2 or 3 for
  a `CNEW` or a `BNEW`. The level is advisory, and a false level costs the
  writer one failed registration.
- **[ATT-089]** A relay MUST reject a `CNEW` when its store holds less free
  space than `CHUNK_SIZE`. **[ATT-090]** A relay below `CHUNK_STORE_TARGET` of
  stored bytes MUST NOT erase a chunk before `CHUNK_TTL` to make space.
  **[ATT-168]** A relay above `CHUNK_STORE_TARGET` MAY erase attachment chunks
  before `CHUNK_TTL`, oldest renewal first. The stored bytes of these two
  rules are the bytes of the held chunks. A pending registration of `ATT-181`
  counts for the reject of `ATT-089` and holds no bytes. Thus a relay MUST NOT
  erase a chunk to make space for a pending registration. A relay whose pending
  registrations alone pass `CHUNK_STORE_TARGET` MAY drop the oldest of them
  before `CHUNK_TTL`. **[ATT-179]** Such a relay MUST NOT erase a backup-class
  chunk. **[ATT-091]** A relay MUST signal that condition to the directory as a
  capacity fault.

  > *Cause of the conditional.* Without the conditional, a relay that declares
  > the target and fills it holds two rules that a full store cannot both obey,
  > which are the reject of `ATT-089` and the hold of `ATT-090`. The target is the store that the
  > relay promised, and an erase above it costs a chunk that a `CGET` then
  > finds at a replica. The client reports the loss under `ATT-052` when each
  > replica is gone.

**One uploader must not fill a relay.** Part 13 §13.2 gates the allocation of
attachment storage with a token or a proof of work, and this section gives that
gate a number.

- **[ATT-092]** A relay MUST apply `UPLOAD_QUOTA_DAY` for each token and for
  each proof-of-work solution that admits a registration (Part 13 `ABU-107`).
  The token or the solution is the **quota holder**, and the relay counts
  `CHUNK_SIZE` on the holder at each registration that the holder admits. One
  token admits one registration, because a token spends once (Part 13
  §13.7); one solution admits `POW_CHUNK_ALLOWANCE` registrations.
  **[ATT-093]** A relay MUST reject a `CNEW` above that quota.
  **[ATT-094]** A relay MUST NOT hold a quota counter after 24 hours.

At `UPLOAD_QUOTA_DAY` of 512 MiB, one holder costs 512 MiB × 3 × 14 = **21
GiB** of network storage at the steady state, spread across the attachment relay
population. A solution admits `POW_CHUNK_ALLOWANCE` registrations of Part 13
§13.13 and a token admits one. Both are far below that quota, thus the
allowance binds first, and no holder reaches the quota in v1. The quota is the
bound that stays when a later version raises the allowance.

> *Cause.* One quota counter for all uploads that carry no token holds each
> upload of a relay while no token issuer runs. One party that spends 512 MiB
> in a day then stops each attachment and each backup at that relay until the
> next day. A counter for each solution makes a flood cost a puzzle for each
> 2 MiB, and it takes no allowance from any other party.

**[ATT-095]** A revision that raises `MAX_FILE_SIZE`,
`UPLOAD_QUOTA_DAY`, `REPLICAS`, `CHUNK_TTL`, or `CHUNK_LIFE_MAX` MUST derive
this section again.

> *Why the quota counter is not an identifier of a party.* §12.2.2 gives each
> chunk an independent random credential, thus the credentials join no two
> chunks to one uploader. The quota therefore binds to the **token** of Part 13
> §13.3 or to the **solution** of Part 13 §13.8.1, and not to a party. A token
> admits one chunk, thus its counter joins nothing. A solution admits up to
> `POW_CHUNK_ALLOWANCE` chunks of one upload at one relay, and the relay joins
> those chunks to each other: §12.9 states that residual. No solution serves
> two uploads (Part 13 `ABU-108`), thus no counter joins two files or two
> conversations. Part 13 §13.7 keeps the spend set relay-local and
> epoch-scoped, and `ATT-094` gives the counter the same lifetime.

**The store of an attachment relay.** A backup under `BNEW` lives for
`BACKUP_TTL`, and Part 7 §7.6 restores a device from it. A relay that loses
its chunks at a restart loses a replica of each file and each backup that it
held, and a restart of many relays at one time loses whole files.

- **[ATT-191]** An attachment relay MUST commit each chunk that a `CPUT` or a
  `CRPUT` gave to durable storage before it sends the answer of that command,
  under Part 3 rules `NET-298` and `NET-299`. It MUST commit the erase time
  that a `CRNW` moves, and it MUST erase the chunk from that storage at a
  `CDEL`, at its erase time, and at the trim of `ATT-168`. The store holds the
  identifier, the class, the two credentials, the registration time, the time
  of the last renewal, the erase time, and the bytes. It MUST NOT hold a
  registration that waits for its bytes, a storage token, the fetch rate of
  `ATT-171`, or the egress budget of §12.11. A restart ends each of those, and
  an upload whose registration ended starts again.

## 12.11 The relay egress budget

A store bounds what a relay holds, and this section bounds what it serves. An
attachment to a large group fetches many times from one chunk. A relay without
a bound serves it until its link fails for each other client.

- **[ATT-169]** A relay MUST NOT serve more than `CHUNK_EGRESS_BUDGET_DAY` of
  chunk bytes in one day. **[ATT-170]** Above that budget, a relay MUST answer
  a `CGET` with a `NACK` of reason `BUSY`, and Part 6 §6.4.4 gives the reason.
- **[ATT-171]** A relay MUST NOT serve one chunk more than `CHUNK_FETCH_RATE`
  times in one hour. **[ATT-172]** Above that rate, a relay MUST answer a
  `CGET` of that chunk with a `NACK` of reason `LIMIT`.
- **[ATT-173]** A client that receives `BUSY` or `LIMIT` for a chunk MUST fetch
  the next replica of the `ChunkRef`. **[ATT-174]** A client MUST NOT send the
  same `CGET` to the same relay again inside one hour.
- A manifest of §12.3.4 can hold further refs of one chunk. **[ATT-176]** A
  receiver MUST treat two refs with one `chunk_id` as replicas of one chunk.

> *Cause.* `CHUNK_EGRESS_BUDGET_DAY` is four times the store, thus a relay
> serves each stored byte about four times a day at most, and Part 10 §10.9.1
> sizes the outbound link that carries it. `CHUNK_FETCH_RATE` of 60 caps one
> chunk at one fetch a minute. A client that meets the cap fetches the next
> replica. A relay that sheds a fetch in silence makes the client wait, thus
> each refusal carries a `NACK`.
