# UMBRA Protocol Specification — Part 4: Identity

**Status:** Draft
**Version:** 0.9.0-draft
**Date:** 2026-10-02

---

## 4.1 The problem this part solves

Two demands pull in opposite directions:

- **Unlinkability.** No party can find that two conversations belong to the same
  person. This applies to a relay, to a contact, and to a government. The
  strongest form of this property is an identity with no global identifier.
- **Discoverability.** Ordinary persons want other persons to find them. A
  "message me" link and a handle make a messenger social and not clinical. A reconnection with a contact that lost your address does
  the same. Matrix does this correctly, and designs without identifiers give it
  up.

UMBRA solves this problem with a **layered identity**. There is one root secret,
three different public faces, and a one-way derivation between them. The user
gets one root seed and one sense of "my account". The network sees
unrelated keys.

## 4.2 The three layers

```
                    RootIdentity  (256-bit seed)
                    device-local · never transmitted · no wire representation
                                 │
              ┌──────────────────┼──────────────────────┐
              │ KDF              │ KDF                  │ KDF
              ▼                  ▼                      ▼
    PairwiseIdentity_c    PublicAddressKey_j     DeviceSetKey
    one per contact       optional, opt-in       (Part 7)
    the default           the social layer
    ─────────────────     ──────────────────
    Alice sees A₁         umbra:pub:7f3c…       links your own
    Bob sees   A₂         + optional @handle    devices together
    Carol sees A₃
    (mutually unlinkable)
```

### 4.2.1 Root Identity

```
RootIdentity := 256 bits from the device CSPRNG
```

The first device makes the Root Identity one time. It is the only secret that
can rebuild the identity. It has **no representation that the network can see**.
No field in an UMBRA message contains it. No field comes from it in a
recoverable form, and no field is a commitment to it.

- **[IDN-001]** A device MUST NOT send the Root Identity to a relay.
- **[IDN-002]** A device MUST transfer the Root Identity to a different device of the same
  user only on the device-link channel. Part 7 gives that channel, which is an
  in-person flow or an authenticated side-channel flow.
- **[IDN-003]** The client MUST let the user recover the Root Identity from its
  **root seed**, which the client exports as `RecoveryDigits` of type `0x0004`
  of §4.7.7. The seed holds 256 bits of entropy.

The root seed rebuilds the `RootIdentity`. The seed alone does not rebuild the
local identity table. The encrypted backup of §4.7.2 holds the `RootIdentity`
and that table. Thus the Recovery Code recovers the full account, and the root
seed alone recovers the `RootIdentity` only. Refer to §4.7.

> *Cause of `IDN-003`.* An earlier draft gave the seed as a 24-word BIP-39
> phrase. §4.7.7 then took each other secret of the user from words to
> digits, on the cause of the transcription error rate, and `IDN-150` forbids
> a word list for those secrets. One word list beside three digit strings
> gave the user two forms and two error rates. The seed now takes the form of
> the other secrets, with its type and its check.

### 4.2.2 Pairwise Identity — the default

Each contact relation gets its own long-term keypair:

```
salt_c            := 16 bytes from the device CSPRNG, stored locally per contact
PairwiseIdentity_c := Hybrid( Expand("umbra/v1/pairwise" || salt_c, 96) )
                      → X25519 keypair + ML-KEM-768 keypair
```

Part 5 §5.2 defines `Expand` and `Hybrid`, and CRY-118 to CRY-120 give the
rules of the split.

Each contact of a user sees a **different** long-term key. Two contacts that
compare their data learn nothing. They hold two unrelated public keys.

The salt is random, and it does not come from the contact. Thus a contact that
later learns the `RootIdentity` cannot list the other pairwise identities of the
user without the local salt table.

**Queues are separate from identity.** Part 3 §3.2.2 gives the rule. The device
makes the queue keys directly from the CSPRNG for each queue, and it does *not*
derive them from other material. Pairwise identity keys authenticate the
channel, and queue keys address the channel. A relay sees only the queue keys.

### 4.2.3 Public Address — the opt-in social layer

```
PublicAddressKey_j := Hybrid( Expand("umbra/v1/public-address" || BE32(j), 96) )
                      → X25519 keypair + ML-KEM-768 keypair,  j = 0, 1, 2, …
```

A **Public Address** is a long-term address that a user can publish. It lets a
stranger start contact. To publish a Public Address is an explicit, informed,
and revocable act, and it is off by default. A publication writes the
`AddressEntry` of Part 9 §9.3.3, and §4.3.3 gives the request path.

**[IDN-004]** A user MAY hold more than one Public Address at the index `j`. The addresses of
one user are mutually unlinkable. **[IDN-005]** A user MAY hold a professional address and a
personal address. **[IDN-006]** A user MAY retire an address and move to the index `j+1`. That
move does not cause the loss of the root identity.

§4.2.5 binds one **Profile** to each index `j`. The client makes Profile 0 at
the first launch, and Profile 0 has no directory entry. Publication stays an
explicit, informed, and revocable act.

**Wire form:**

```
umbra:pub:<base32(SHA3-256(PublicAddressKey_j.pk)[0..20])>
        # 32 characters, for example umbra:pub:7f3ck2mq9x4vhn8dpwr5esa1
```

**[IDN-157]** A client MUST encode the 20 bytes in the Crockford base32
alphabet `0123456789abcdefghjkmnpqrstvwxyz`, in lower case, with no padding,
and with the spare low bits of the last character at zero. **[IDN-158]** A
client that reads an address MUST fold upper case to lower case, and it MUST
read `o` as `0` and `i` and `l` as `1`, as that alphabet permits.

> *Cause.* An earlier draft wrote "base32" and named no alphabet, and its
> example held the digits 1, 8, and 9, which the alphabet of RFC 4648 lacks.
> Two implementations then read one string as two addresses. The Crockford
> alphabet holds the example, and its folding rules absorb the transcription
> errors of a string that a user reads aloud.

#### The unlinkability property in full

> An adversary has `PairwiseIdentity_c.pk` for a contact *c*. That adversary
> also has `PublicAddressKey_j.pk`. Without `RootIdentity`, that adversary
> cannot find that the two keys belong to the same user. The probability of
> success is not better than the probability of a guess.

This property holds because the two keys are outputs of a one-way KDF under
different domain-separation labels. The derivation from one root gives the user
one root seed. The KDF keeps the two keys unlinkable. An adversary that
holds the `RootIdentity` can link all the keys. But such an adversary has won
against each other measure in this specification.

#### What a Public Address costs, stated honestly

Cryptographic unlinkability is not behavioral unlinkability. A published address
is a fixed point, and a party can monitor it over time. Thus UMBRA has three
requirements:

1. **Separate infrastructure.** **[IDN-007]** A client MUST put the inbound request queues of
   a Public Address on different relays from a pairwise queue. **[IDN-008]** A client MUST
   also put them in different transport sessions from a pairwise queue. **[IDN-009]** The
   public address of a user MUST NOT decide which relays hold the pairwise
   inboxes of that user.

   > *Rationale.* The Account ID of Session is a permanent X25519 public key.
   > That key selects a swarm of 5 to 7 nodes deterministically. A swarm
   > changes at a node churn only, and the user does not control that event.
   > Thus a small number of operators get the full lifetime arrival and poll
   > telemetry for that identity. This document has not verified the swarm
   > detail against the current Session code. UMBRA does not repeat this
   > design.

2. **A one-way door out of the public layer.** A contact request arrives at a
   Public Address. After the user accepts the request, the client **moves the
   conversation to a fresh pairwise identity and to fresh queues**. The client
   does not use the public address for that conversation again. The public layer
   is a doorbell and not a mailbox.

3. **An honest UI.** **[IDN-010]** At the moment of publication, the interface MUST state that
   a published address is a persistent identifier. **[IDN-011]** The interface MUST also state
   that a party can monitor such an address over time. **[IDN-012]** The interface MUST also
   state that pairwise invitations do not have this property. **[IDN-013]** Implementations
   MUST NOT show the two paths as equal in privacy.

### 4.2.4 Handle — optional human-readable name

```
@alice            → resolves to → (HK_pub, rendezvous)
```

A handle resolves to the handle key and to the rendezvous queue of Part 9
§9.3. It does not resolve to the Public Address string of §4.2.3, and Part 9
§9.3.3 indexes that string under its own label. An earlier draft drew the arrow
toward `umbra:pub:`, and no directory field held that value.

Handles help usability only. They are not authoritative. **[IDN-014]** The client MUST tell
the user to verify a handle out of band before a security-relevant decision.
Part 9 gives the directory, its transparency log, and its defenses against
enumeration.

**The handle key.** A directory entry of Part 9 §9.3 holds a public key
`HK_pub`. That key is the public half of a handle key, which the client derives
from the root identity:

```
HandleKey_{j,r} := Hybrid( Expand("umbra/v1/handle-key" || BE32(j) || BE32(r), 96) )
                   → X25519 keypair + ML-KEM-768 keypair,  r = 0, 1, 2, …
```

`j` is the index of the Public Address of §4.2.3 that the handle names. `r` is
the rotation counter of the handle key of that address. Part 5 §5.11 holds the
label.

- **[IDN-104]** A client MUST publish the public half of `HandleKey_{j,r}` as
  the `HK_pub` of the handle of `PublicAddressKey_j`. **[IDN-105]** A client
  MUST NOT publish a public half of `PublicAddressKey_j` as an `HK_pub`.
- **[IDN-106]** A client MUST increase `r` by one at each rotation of the
  handle key. **[IDN-107]** A client MUST NOT publish two handle keys with one
  pair `(j, r)`.
- **[IDN-108]** A client MUST hold the current `r` of each `j` in the local
  identity table. §4.7.2 backs that table up.

**The restore.** A restored client holds the `r` that the last backup wrote,
and the user can have rotated the key after that write. The client finds the
current `r` against its own directory entry.

- **[IDN-109]** After a restore of §4.7.2, a client MUST look up each handle
  that the restored local identity table names. **[IDN-110]** The client MUST
  compare the newest `HK_pub` of that entry against the public half of
  `HandleKey_{j,r}`. A tombstone version of Part 9 §9.9.2 holds no `HK_pub`,
  and the client skips it. **[IDN-118]** The client MUST try each `r` from the
  restored counter to that counter plus `HANDLE_KEY_LOOKAHEAD`. **[IDN-111]**
  The client MUST set `r` to the first value that matches.
- **[IDN-112]** If no value matches, the client MUST show the handle as lost.
  **[IDN-113]** If no value matches, the client MUST NOT register the handle
  again without an explicit confirmation from the user.

Part 9 §9.9.2 reserves a tombstoned label for the restored client, and it
gives the takeover warning that a lost handle causes.

> *Cause.* An earlier draft named `HK_pub` in Part 9 §9.3 and derived it
> nowhere. A client that lost each device then held no private half, and it
> could not answer the renewal challenge of Part 9 §9.9.1. The derivation from
> the root identity with a rotation counter recovers the key from a stale
> backup. The separate label keeps `HK_pub` unlinkable to `PublicAddressKey_j`.
> Thus a crawl of the directory does not link a handle to a Public Address
> string that a person shared elsewhere.

### 4.2.5 Profile — the name and the picture of a Public Address

```
Profile_j {
    name            UTF-8, ≤ 32 bytes, optional
    picture_source  enum { GENERATED, SELECTED }
    handle          optional, and Part 9 publishes it
}
```

A **Profile** is a name and a picture, and it binds to one Public Address index
`j`. §4.2.3 makes the addresses of two indexes mutually unlinkable. Thus a user
holds more than one Profile, and the unlinkability of those Profiles comes from
§4.2.3 and needs no new mechanism.

**Profile 0 exists at the first launch.** The client makes Profile 0 without a
user action. Profile 0 has the index `j = 0`, a generated picture, no name, and
no directory entry. U1 permits a maximum of 6 taps to the first message, and U1
prohibits a security decision before the inbox is reachable. **[IDN-015]** Thus the client
MUST NOT show a setup screen for a Profile.

**Publication stays opt-in.** A Profile does not enter the Part 9 directory
until the user publishes a handle for that Profile. §4.2.3 makes publication an
explicit, informed, and revocable act, and this section does not change it.

> *Cause.* Mandatory publication removes the private tier. A user that never
> publishes is then a member of an enumerable set, and Part 9 §9.3 concedes that
> the directory has no enumeration resistance.

#### The generated picture

The generated picture is a letter and a color.

```
letter = the first character of Profile_j.name, in upper case.
         If the name is empty, the client shows a neutral glyph.

color  = PALETTE[ SHA3-256("umbra/v1/avatar-color" || PublicAddressKey_j.pk)
                  mod PALETTE_SIZE ]
```

1. The picture costs zero bytes on the wire. The client renders it from the
   Public Address, and the contact holds that address.
2. The picture differs for each Profile, because the color comes from
   `PublicAddressKey_j.pk`.
3. The user does not select the color. Thus the user cannot put one color on two
   Profiles by accident.
4. The picture is a function of the Public Address. Two contacts that hold that
   address can already link, thus the picture gives those contacts no new fact.

`PALETTE_SIZE` is 12. **[IDN-016]** The palette MUST give a sufficient contrast ratio in a
light theme and in a dark theme. A letter and a color give about 400
combinations, and that count is too small to be a fingerprint. The low entropy
is a requirement here, and it is not a limit.

#### The selected picture

**[IDN-017]** A user MAY select a picture in place of the generated picture. That picture goes
in the encrypted blob of Part 9 §9.3.1, and Part 9 §9.3.1 gives the re-encode
rule.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** A selected
> picture is the same bytes at each party that resolves the Profile. Thus two
> such parties compare the bytes and prove that they share a correspondent. G9
> holds against A2 and colluding contacts, thus this is a cost against a stated
> goal. Part 9 §9.7 rejects the same shape for a root signature, and it calls
> such a signature a perfect linker. A per-recipient salt randomizes the
> ciphertext, and it does not randomize the payload.
>
> The cost is bounded, and the bound is what makes the feature acceptable. The
> parties that compare the picture reached the user through one Public Address.
> Those parties hold one 32-character address string, thus they can already
> link. The picture adds no capability inside one Profile.

#### The cross-Profile rules

A user that puts one value on two Profiles links two addresses that §4.2.3 makes
unlinkable. The strength of that link comes from the entropy of the value, thus
the rules are proportional.

| The user reuses | Strength as proof | Rule |
| --- | --- | --- |
| A selected picture | Near-certain, because the entropy is high | **[IDN-018]** The client MUST warn. **[IDN-019]** The client MUST get an explicit confirmation |
| A name | Weak to moderate, and it depends on the rarity | **[IDN-020]** The client SHOULD warn |
| A letter and a color | None, because the client derives them | No rule is necessary |

The client detects a reused picture with a hash of the image bytes. That check
is local, and it needs no relay and no directory.

#### A contact gets no pushed Profile

**[IDN-021]** A client MUST NOT dispatch a Profile as a fan-out to its contacts. **[IDN-022]** A client MUST
NOT emit a cell whose only content is a Profile.

> *Cause 1, the contact count.* A fan-out of about 150 cells inside one short
> window is an event that the Part 3 §3.12 budget does not produce. Part 10
> §10.6.1 pins two ingress relays for 60 to 120 days, and Part 3 §3.11 gives
> such a relay the cell counts. That relay reads the burst size and learns the
> contact count of the user. Part 2 §2.2 states that UMBRA prevents A1 from
> learning the number of different conversations.
>
> *Cause 2, the pull is worse.* A stored and addressable picture invites a fetch
> after a change notice. Part 3 §3.5.4 forbids that shape. The sealed sender of
> Signal failed against a statistical disclosure attack. That attack needed
> fewer than 5 messages, at a median round trip of 1 480 ms.

A party that reaches the user through a Public Address gets the Profile from the
Part 9 §9.3.1 blob. That party gets the Profile one time, at the moment of
contact. That party holds the
link fragment already, thus the fetch adds no event.

A party that reaches the user through a one-time invitation (§4.3.1) gets no
Profile by default. That path is authenticated out of band, thus the two parties
know each other.

Part 9 §9.8 gives the **pet-avatar**, which the viewer assigns and which no
party receives.

## 4.3 Contact establishment paths

UMBRA has three paths. The order below starts with the most private path.

### 4.3.1 One-time invitation (default, strongest)

The user delivers a short link or a QR code out of band. The link operates one
time only.

```
https://<invitation-host>/i#<fragment>
   fragment = 256 bits of key material || 192 bits of server-generated link ID
              || RelayRef of the relay that holds the blob (Part 12 §12.3.2)
```

The **invitation host** is one host that the nonprofit operates, and the
client package names it. The **invitation landing document** is the document
that the host serves at `/i`. That document tells a party without the client
where to get the client. A browser does not send a fragment, thus the host
learns the open and not the invitation.

- **[IDN-120]** The landing document MUST hold no script. **[IDN-121]** The
  landing document MUST NOT reference a resource on a second host.
- **[IDN-122]** The invitation host MUST serve `/.well-known/assetlinks.json`.
  That file names the client package and the path `/i`.
- **[IDN-123]** A client MUST register the link as an Android App Link. Thus a
  tap on a device with the client opens the client, and no browser sees the
  link.
- **[IDN-124]** A client MUST NOT open the landing document. **[IDN-125]** A
  client MUST NOT put the fragment in a request to any host.
- **[IDN-126]** A relay MUST delete a blob that no party fetched within
  `INVITE_TTL`. The relay measures that period from the store of the blob.
  **[IDN-127]** A client MUST treat an invitation as deleted at `INVITE_TTL`
  after the issue. The client measures that period from the issue, and Part 5
  rule `CRY-123` then erases the prekey. **[IDN-128]** A client MUST show the
  remaining lifetime beside an invitation that no party consumed.

**[IDN-159]** A client MUST write the fragment after `#` as the 68 bytes
above in base64url with no padding. A browser rewrites no character of that
alphabet in a fragment, and the string is 91 characters.

The relay that the `RelayRef` names stores an **encrypted blob** that it cannot
read. The blob key comes from
`HKDF("umbra/v1/invite-blob" || SHA3-256(link_fragment))`, which is
`HKDF-SHA3-256(salt = "", ikm = SHA3-256(fragment), info =
"umbra/v1/invite-blob", L = 32)`. Part 5 §5.11
holds that label. That key is different from the link ID
that the relay knows, thus a seized relay gives only ciphertext.

```
InvitationBlob {                  // the object the relay stores under the link ID
    version       u8              // 0x01
    nonce         [24]u8          // from the device CSPRNG
    sealed        var             // XChaCha20-Poly1305( blob_key, nonce, the bundle of Part 5 §5.4.1,
                                  //                     ad = link_id )
}
```

**[IDN-160]** A client MUST seal the bundle in the layout above, with the
192-bit link ID as the associated data, thus a blob moved under a second link
ID fails to open. **[IDN-161]** A client MUST reject a blob whose `version` is
not `0x01` or whose `sealed` field does not open under the key of the
fragment.

> *Cause.* An earlier draft put the relay host in the link. An App Link needs
> a host list that the client package states in advance, and a relay set
> changes. Thus the link opened a browser on each device, and
> the relay served a page that UMBRA did not specify. One host with a static
> document gives the platform a list of one. The `RelayRef` in the fragment
> names the relay to the client, and no host sees it. A hostile invitation host
> serves a different document, and Part 15 §15.3 records that residual. The
> first-access lock below detects a fetch that such a host makes.

The blob carries the full invitation. The invitation holds the responder static
key, the one-time ML-KEM encapsulation key, the profile, the preferences, and
the relay bundle. Refer to Part 5 §5.4.1. The blob AEAD protects the
encapsulation key, and Part 5 §5.4.5 states that no relay serves a prekey.

The fixed portion is **cryptographically bound to the one queue**. This binding
prevents redirection to a different queue.

**First-access lock.** The first fetch locks the queue with the authorization
key of the party that fetched it. If an observer fetches the blob, the
connection of the intended recipient fails. Thus a passive link-interception
attack becomes an event that **the two parties detect**. **[IDN-023]** Implementations MUST
implement this lock for one-time invitations.

**The commands.** Part 6 §6.4 gives five commands for this path. The inviter
makes the queue of the invitation with a `NEW`, and it asks the relay of that
queue for a link identifier with an `IRES`. It seals the bundle under the
fragment and stores the blob with an `IPUT`. The party that holds the link
sends an `IGET` with a lock key that it drew for this fetch.

- **[IDN-164]** A client MUST draw the 256 bits of key material of the
  fragment from the device CSPRNG, and it MUST NOT give them to a relay. The
  relay holds the link identifier and the ciphertext.
- **[IDN-165]** A client MUST give the link to the user after the relay
  answered the `IPUT`, and not before. A link with no blob behind it fails at
  the other party.
- **[IDN-166]** A client that accepts a link MUST write to the queue of the
  bundle under its lock key, and not under the `QS_auth` of the bundle. The
  relay put the lock key in the place of that `QS_auth` at the fetch (Part 6
  rule `WIR-510`). Thus a party that reads the bundle by another path writes
  no flight 1 to a queue that a fetch locked.
- **[IDN-167]** A client whose `IGET` gets a `NACK`, or whose blob does not
  open under the fragment, MUST tell the user that the link gives no
  invitation. It MUST name the fetch by a second party as a cause, and it MUST
  ask the user to tell the inviter. That report is the detection of
  `IDN-023`: the intended party holds no contact, and the inviter holds one
  that it did not expect.
- **[IDN-168]** A client MUST resolve the `RelayRef` of the fragment before the
  `IGET`, and it MUST send the `IGET` on a circuit whose last hop is that
  relay.
- **[IDN-169]** The store of an inviter MUST hold the fragment of an
  invitation that waits, thus the client shows the link again after a
  restart. It MUST delete the fragment with the invitation (Part 14 rule
  `IMP-136`).

> *What the lock does not do.* A party that reads the link first fetches the
> blob, takes the lock, and runs the handshake as the invitee. The inviter
> then holds a contact with that party. The lock makes that event visible to
> the intended party, and the verification of §4.5 makes it visible to the
> inviter. It prevents nothing alone.

### 4.3.2 Reusable contact link

The user can give this link to many parties. The user can print it on a card or
put it in an email signature. It is a Public Address in link form.

A reusable link **cannot** have the first-access lock. This limit is inherent
and it is not an implementation gap. **[IDN-024]** The UI MUST state this limit.

**Wire form:**

```
umbra://p/<base32(SHA3-256(PublicAddressKey_j.pk)[0..20])>
        # 32 characters after the prefix, the address of §4.2.3
```

**[IDN-129]** A reusable link MUST carry the address of §4.2.3 and no other
value. The link and the `umbra:pub:` string name one `AddressEntry` of Part 9
§9.3.3, and §4.3.3 gives the request that either one starts.

### 4.3.3 Public Address / handle

A stranger looks up `@alice`, or pastes `umbra:pub:…`, and sends a contact
request.

- **[IDN-130]** A client MUST accept a pasted `umbra:pub:` string and a link
  of §4.3.2 as the start of a contact request. **[IDN-132]** The client MUST
  look that address up under Part 9 §9.3.3. **[IDN-131]** Before the client sends the hello of Part
  9 §9.6, it MUST check that `SHA3-256(address_pk)[0..20]` equals the address.
  Part 2 §2.4.2 goal S1 sets the tap count and the latency of that path.

A request to a Public Address ends with one `Admission` of Part 13 §13.2,
inside the hello. The addressee client verifies a cross-relay token of Part 13
§13.3.1 or a proof of work of Part 13 §13.4, and no relay reads it. Part 13
§13.4 gives the rules and the limit of each epoch.

## 4.4 What a contact learns

A contact learns the data that you send to that contact, and that you are you. A
contact does **not** learn these items:

- Your `RootIdentity`, or data from which a party can derive it.
- Your other contacts, or your other pairwise identities.
- Your Public Address, if you do not share it.
- How many devices you have, or which device sent a given message (Part 7).
- Which relays hold your other queues.

Two colluding contacts cannot show that they share a correspondent. This
property is goal G9.

## 4.5 Key verification

UMBRA makes a **safety number** for each pairwise channel. The safety number is
a 60-digit decimal form of `SHA3-256` over the pairwise identity public keys of
the two parties in canonical order. The client shows the number in groups of
five digits. The client also gives a QR encoding that a device can scan.

Requirements:

- **[IDN-025]** A key change MUST cause a **blocking notice in the conversation**. A passive
  banner is not sufficient. The research on safety-number verification shows
  clearly that users ignore passive indicators.
- **[IDN-026]** The verification state MUST apply to each pairwise identity. **[IDN-027]** The state MUST
  continue through a queue rotation, a relay change, and a device link. A user
  that verified Bob does not verify Bob again after Bob adds a tablet
  (usability goal U7).
- **[IDN-175]** A client MUST keep the verification state as the pairwise
  identity public key of the contact that the user verified. The contact
  counts as verified only while that key is equal to the key that the
  channel holds. Thus the state of an earlier key gives nothing to a later
  key, and the notice of §4.5.1 needs no separate step that clears it.
- **[IDN-176]** A scan or an entry of a safety number that is equal to the
  number of the device, by its digits alone, MUST set the same state as a
  confirmed short code. A number that is not equal MUST set nothing.
- **[IDN-028]** The UI MUST NOT imply that unverified conversations are insecure. Such
  conversations are protected against each adversary but an active
  man-in-the-middle at the first contact.

### 4.5.1 The key-change notice

A user replaces a pairwise identity after a full identity reset (Part 7 §7.7.1)
or after a deliberate replacement. The client tells each contact with a
**key-change notice**.

A `PairwiseIdentity_c` holds an X25519 keypair and an ML-KEM-768 keypair
(§4.2.2). **Neither keypair signs data.** Thus a key-change notice carries no
signature, and the ratchet of the session that carries it gives the
authentication. Part 5 §5.7 keeps the deniability of the channel for that
reason.

```
KeyChangeNotice {
    version        u8         // 0x01
    new_x25519_pk  [32]u8
    new_mlkem_pk   [1184]u8
}
```

The notice is the body of an `AppMessage` of kind `0x30` (Part 6 §6.6). The body
is 1 217 bytes, thus the record uses bucket `B1`.

1. **[IDN-055]** A client MUST send a key-change notice inside the established pairwise
   ratchet session with that contact. **[IDN-056]** A client MUST NOT send it on a new
   session or on a group channel.
2. **[IDN-057]** A client MUST NOT sign a key-change notice. **[IDN-058]** A client MUST NOT carry a
   signature over the new keys inside the notice.
3. **[IDN-059]** A receiver MUST accept a key-change notice only from the receiving chain of
   that session. The ratchet direction gives that authorization, and Part 6
   §6.6.1 uses the same basis for an edit.
4. **[IDN-060]** A receiver MUST bind the two new public keys into the next handshake
   transcript with that contact. Part 5 §5.11 requires the full transcript
   binding, thus a substituted key gives a handshake failure and not a silent
   loss.
5. **[IDN-061]** A receiver MUST show the blocking notice of §4.5, and IDN-025 states that
   rule. **[IDN-062]** A receiver MUST NOT apply the new keys before the user answers that
   prompt.
6. **[IDN-063]** A client MUST send one key-change notice to each contact with an
   independent randomized delay for each contact. **[IDN-064]** A client MUST draw that delay
   from an exponential distribution with a mean of `SWEEP_SPREAD`. Part 7 §7.5.6
   gives that parameter.
7. **[IDN-065]** A client MUST NOT broadcast one statement about a new key to more than one
   contact. Part 9 §9.7 gives the cause, which is that one such statement is a
   perfect linker against G9.

> **This is a trade, and Part 2 §2.4 requires the text to state it.** The notice
> carries no signature, thus the ratchet of the session is the only
> authentication. An attacker that holds the ratchet state of a session sends a
> notice that carries its own keys. Goal G5 of Part 2 §2.3 says that a channel
> heals after an attacker loses access. If the user accepts the prompt of
> IDN-061, that healing does not occur and the attacker holds the channel.
>
> The alternative is a signature under a long-term key. Part 5 §5.7 and Part 9
> §9.7 each reject that alternative, because it ends the offline deniability of
> G10 and it makes a perfect linker against G9. This specification keeps the
> unsigned notice and puts the weight on the prompt. Part 15 §15.3 records the
> residual.

8. **[IDN-089]** The blocking notice of §4.5 MUST state that acceptance ends the
   post-compromise healing of Part 5 §5.5 for that contact. **[IDN-090]** That
   notice MUST offer an out-of-band verification before the acceptance.
   **[IDN-091]** The interface MUST NOT make the acceptance the default action.
   **[IDN-092]** The interface MUST NOT let a user accept the notice for more
   than one contact in one action.

> *Cause.* An earlier draft said that "the outgoing pairwise key signs the
> replacement key". A pairwise identity holds no signing keypair, thus no
> implementation could obey that sentence. The ratchet already authenticates
> each record on the channel, and a signature would also break the offline
> deniability of Part 5 §5.7.

### 4.5.2 The verification ceremony

Trust assumption 5 of Part 2 §2.6 rests on a ceremony that a user completes
one time. A 60-digit comparison is a ceremony that a user skips. This section
gives two affordances, and the QR scan is the first one.

- **[IDN-140]** The verification screen MUST offer the QR scan of the safety
  number first. **[IDN-141]** The manual ceremony MUST be the short code below.
  The 60-digit safety number stays available behind the short code, for a
  transcript and for a comparison at a distance in time.

**The short code.** Each party draws a nonce, commits to it, and reveals it
after it holds the commit of the peer. Both parties then derive one six-digit
code, and the users compare that code by voice or in person.

```
VerifyCommit {                    // kind 0x36, Part 6 §6.6
    commit    [32]u8              // SHA3-256("umbra/v1/sas-commit" || nonce)
    answers   [32]u8              // the commit of the peer that this commit
                                  // answers, or 32 zero bytes for a start
}

VerifyReveal {                    // kind 0x37, Part 6 §6.6
    nonce     [32]u8              // from the device CSPRNG
}

pk_lo, pk_hi     = the two pairwise identity public keys, in canonical order
nonce_lo         = the nonce of the party that holds pk_lo
code             = BE32( SHA3-256("umbra/v1/sas" || pk_lo || pk_hi
                                  || nonce_lo || nonce_hi)[0..4] ) mod 10^6
```

The client shows `code` as six decimal digits, with a leading zero where the
value needs one. Part 5 §5.11 holds the two labels.

- **[IDN-142]** A client MUST send `VerifyCommit` before it holds the nonce of
  the peer. **[IDN-143]** A client MUST NOT send `VerifyReveal` before it holds
  the `VerifyCommit` of the peer. **[IDN-144]** A client MUST reject a
  `VerifyReveal` whose hash under the label differs from the commit that it
  holds.
- **[IDN-145]** A client MUST draw a fresh nonce for each ceremony.
  **[IDN-146]** A client MUST NOT show a code from an earlier ceremony.
- **The pairing of two commits.** A commit with a zero `answers` field is a
  **start**, and each other commit is an **answer**. **[IDN-170]** A client
  that gets a start MUST end the ceremony that it holds, draw a fresh nonce,
  and send an answer that names that start. **[IDN-171]** A client MUST take
  an answer only while it holds a start of its own with no commit of the
  peer, and only when `answers` is equal to the commit of that start. It MUST
  drop each other answer. **[IDN-172]** A client that gets a start while its
  own start has no answer MUST compare the two commits as byte strings. It
  MUST drop the start of the peer when its own commit is the lower one, and
  it MUST obey `IDN-170` when its own commit is the higher one. Thus two
  starts that cross give one ceremony, and the two clients select the same
  one.
- **[IDN-173]** A `VerifyReveal` that `IDN-144` rejects MUST NOT end the
  ceremony. The reveal of a ceremony that a later start replaced can arrive
  late, and it gives an adversary nothing: the commit that the client holds
  binds the one nonce that gives a code.
- **[IDN-174]** A ceremony MUST NOT continue after the run of the client that
  holds it. A nonce serves one comparison between two persons, thus it has no
  stored form.
- **[IDN-147]** A client MUST set the verification state of §4.5 at a user
  confirmation that the two codes match. **[IDN-148]** A client MUST NOT set
  that state from the exchange alone. The exchange gives two clients one
  number, and the comparison between two persons is the verification.

> *Cause of the `answers` field.* An earlier draft held the commit alone.
> A user that starts two times in a row then gets the answer to the first
> start while the second start waits. The client cannot tell that answer from
> a new start of the peer, and each of the two clients starts again at each
> commit of the other one, without an end. The field names the start, thus a
> late answer pairs with nothing and the client drops it.

> *Cause.* An active adversary at the first contact holds two channels, one to
> each party, and two pairwise key sets. That adversary needs the two codes to
> match. The commit binds each nonce before the reveal, thus the adversary
> cannot select a nonce after it reads the other one. The adversary then
> matches two codes with a probability of one in 10⁶ for each ceremony, and
> Part 15 §15.3 states that residual. Without the commit, an adversary that
> reveals last selects its nonce against the known code, and the short code
> gives nothing.

## 4.6 Local database integrity

The local database is part of the cryptographic trusted computing base. Part 14
§14.6.4 encrypts each record with XChaCha20-Poly1305 under a key for each
record. That construction detects a change to a record. It does not detect the
removal of a record, and it does not detect a substitution between two records.
Thus five rules apply, and they apply to each table.

1. **[IDN-029]** The associated data of each record MUST hold the table identifier and the
   surrogate row identifier. Thus a party cannot move a record from one row into
   another row.
2. **[IDN-030]** A `row_id` MUST be unique inside its table. **[IDN-031]** A client MUST reject a table that
   holds two live rows with one `row_id`. **[IDN-032]** A client MUST report that condition in
   the same manner as a MAC mismatch.
3. **[IDN-033]** Each table MUST carry a **table MAC**. The MAC covers the contents of each
   live row, and it does not cover the row count alone:

   ```
   K_tab     = HKDF-SHA3-256( salt = empty, ikm = K_store,
                              info = "umbra/v1/table-mac", L = 32 )
   row_tag_i = HMAC-SHA3-256( K_tab, 0x01 || table_id || row_id_i ||
                              record_tag_i )
   accum     = row_tag_1 XOR row_tag_2 XOR … XOR row_tag_r
   table_mac = HMAC-SHA3-256( K_tab, 0x02 || table_id || row_count ||
                              commit_counter || accum )
   ```

   The value `record_tag_i` is the 16-byte XChaCha20-Poly1305 tag of that
   record. Part 14 §14.6.4 gives that tag. The value `commit_counter` is
   monotone for each table. `K_store` is the at-rest master key of Part 5
   §5.2, and Part 14 §14.6.4 wraps it. **[IDN-034]** A client MUST derive
   `K_tab` from `K_store` under the label `"umbra/v1/table-mac"`. **[IDN-035]**
   A client MUST NOT write `K_tab` to storage. Part 5 §5.11 holds the label.

   - **[IDN-066]** A client MUST compute `row_tag_i` over the record tag of the live row.
     **[IDN-067]** A client MUST NOT compute it over the plaintext of the row.
   - **[IDN-068]** A client MUST update `accum` incrementally. At a change to one row, the
     client XORs the old `row_tag` out and XORs the new `row_tag` in. Thus one
     commit batch costs work in the number of changed rows, and IDN-037 holds.
   - **[IDN-069]** A client MUST use the two prefix bytes `0x01` and `0x02` above. The two
     HMAC uses take different input, thus they need different domain
     separation.

   > *Cause.* An earlier draft covered `table_id`, `row_count`, and
   > `commit_counter` only. Under that MAC an attacker replaced the ciphertext
   > of one row with an earlier valid ciphertext of that same row, and the MAC
   > still verified. The row count did not change, and IDN-029 binds the
   > ciphertext to the row but the table MAC did not read that binding. The
   > accumulator above reads the record tag of each live row, thus a
   > substitution and a per-row rollback each change `table_mac`.
   >
   > The accumulator is an XOR of keyed tags in the manner of the XOR-MAC
   > construction of Bellare, Guérin, and Rogaway. `K_tab` derives from
   > `K_store`, which the secure element entangles under Part 14 §14.6.4. Thus
   > an attacker without the unlocked store cannot compute a `row_tag`, and it
   > cannot cancel one term against another.
   >
   > *Cause of the derivation.* An earlier draft held `K_tab` in the platform
   > keystore as an HMAC-SHA256 key with no user authentication, and it
   > entangled `K_tab` with a secure-element key; the keystore of every v1
   > platform does not hold an HMAC key that the table needs without a
   > platform limit, thus the key moved into software. A client changes a
   > table only while it holds `K_store`, because each record key derives from
   > `K_store`.
   > Thus a key that derives from `K_store` gives the same detection against
   > a party without the unlocked store. The MAC moves to HMAC-SHA3-256, which
   > is the MAC of Part 5, because a software key has no keystore limit on the
   > hash.
4. **[IDN-036]** A client MUST update the table MAC at each commit batch. **[IDN-037]** A client MUST NOT
   compute a table MAC by a scan of a table at the unlock. **[IDN-038]** A client MUST verify
   each table MAC at the unlock.
   **[IDN-193]** The set of tables MUST carry a MAC of the same form, under
   `table_id = 0x00`: one `row_tag` for each table that the store holds, with
   the `table_id` of that table as `row_id` and 16 zero bytes as
   `record_tag`. At the unlock the client MUST verify that MAC, and that its
   `accum` and `row_count` equal those of the tables whose MAC the client
   read. A store of an earlier build holds no set MAC, and the client writes
   it at its next commit together with a mark in the local identity table. A
   client that holds that mark and finds no set MAC MUST treat the store as
   a MAC mismatch under `IDN-039`.

   > *Cause.* Each table MAC covers the rows of its own table. A party with
   > the file that deleted the MAC row of a table and each row of it left
   > no MAC to fail, and the unlock read the table as one that never held a
   > row. The set MAC names each table, thus that deletion fails at the
   > unlock. The mark sits beside the root seed, thus a party that drops the
   > mark drops the identity.
5. **[IDN-039]** If a table MAC does not match at the unlock, the client MUST tell the user.
   **[IDN-040]** The client MUST NOT continue silently.
6. The check at the unlock reads the stored `accum`, and `IDN-037` keeps a scan
   out of that path. Thus a changed row shows only when a scan compares the
   rows with `accum`. **[IDN-162]** After the unlock, a client MUST compute
   `accum` and `row_count` of each table from a scan of its rows, outside the
   unlock path, one time or more in each 24 hours that the store is open.
   **[IDN-163]** A client MUST report a difference in the manner of `IDN-039`.

The message table, the tombstone table, the contact table, the queue table, the
verification table, and the local identity table are each under these rules.
This specification states the property and does not enumerate the tables,
because an enumeration omits the next table.

> *Rationale.* Trail of Bits finding #6 against SimpleX (July 2024, medium)
> shows an attack. An attacker changes the application database, substitutes
> queue addresses and keys, and mounts a MITM. SimpleX **accepted this finding
> and did not correct it**. The argument was that a compromised device can also
> change the display.
>
> That argument is weak. Forensic tools and malware can change a database
> without full interactive control, and detection is cheap.

**Two limits, stated.**

> The table MAC detects the removal of a row. A removal changes `row_count` and
> it changes `accum`. The MAC also detects a substitution between two rows. It
> also detects a rollback of one row to an earlier ciphertext. Each of those two
> changes `accum`.
>
> The MAC does **not** detect a rollback of the full database file. That
> rollback restores a consistent `commit_counter` and a consistent `accum`
> together. The platforms give no monotonic counter that survives a device
> restore.
>
> The MAC detects a change by a party that cannot run code on the device. It
> does not detect a change by a party that holds code execution while the
> client holds `K_store` in RAM. The cause is that `K_tab` derives from
> `K_store`. Part 14 §14.6.4 gives the auto-lock that ends that period, and
> Part 15 §15.2.1 documents that state.

## 4.7 Account recovery

Most private messengers lose users at this point, and the honest options are all
uncomfortable.

The metadata-private group of messengers is Threema, Session, and SimpleX.
Session restores an Account ID from a recovery phrase, and it restores no
message history. Threema and SimpleX give self-custody only. A user of those
two that did not export a backup in advance recovers nothing. This document
found no published recovery rate for any of the three, and that absence is
unverified. UMBRA does better and does not make an escrow.

### 4.7.1 The Recovery Code

At the first launch, the client makes a **256-bit Recovery Code**. The code has
**two independent halves**, and §4.7.3 gives the cause:

```
C_user   = 128 bits from the device CSPRNG    the user half
C_social = 128 bits from the device CSPRNG    the social half
RecoveryCode = C_user || C_social
BackupRootKey = Argon2id(RecoveryCode, salt, m ≥ 64 MiB, t ≥ 3)
```

**[IDN-070]** A client MUST make `C_user` and `C_social` as two independent
CSPRNG outputs. **[IDN-071]** A client MUST derive `BackupRootKey` from the two
halves together. **[IDN-072]** A party MUST NOT derive `BackupRootKey` from one
half.

**[IDN-177]** A client MUST derive `BackupRootKey` with `salt` of the 20
bytes `"umbra/v1/backup-salt"`, with `m` of exactly 64 MiB, with `t` of
exactly 3, and with a parallelism of 1. Part 5 §5.11 holds the label.

> *Cause of `IDN-177`.* An earlier draft named a salt and floors for `m` and
> `t`, and it gave no value for any of them. A restore holds the code and
> nothing else, thus each input of the KDF must be a constant. A fixed salt
> gives an attacker no table across users, because the code carries 256
> random bits and no dictionary covers it.

Recovery is a rare operation, and it can accept 365 ms or more. Thus the KDF is
deliberately expensive.

The client does **not** escrow the Recovery Code silently by default. The client
makes the code locally and seals it under the platform keystore for use on the
current device. The client exports the code on demand as the `RecoveryDigits`
of §4.7.7, in grouped decimal digits. **[IDN-041]** The client MUST NOT
export the code as 64 hexadecimal characters. That format has the worst
measured results for human transcription.

**[IDN-042]** Mainstream builds MAY give platform-cloud backup of the Recovery
Code through Android Block Store. **[IDN-043]** Such backup
MUST be an explicit opt-in with a plain warning. **[IDN-044]** The warning MUST
state that the backup makes a recovery dependency. That dependency is on the
Google account of the user. **[IDN-045]** The warning
MUST also name the legal process of that platform. **[IDN-046]** De-Googled
builds, F-Droid builds, direct-download builds, and the high-risk configuration
MUST default to local self-custody recovery only.

### 4.7.2 Encrypted backup

The client encrypts the backup under `BackupRootKey` and stores it **on relays
as opaque blobs**. The backup holds these items:

- the root identity, the contact list, and the **local identity table** with
  the handle key rotation counter `r` of §4.2.4
- the pairwise queue state and the group memberships
- the source watermark of each source device (Part 7 §7.5.2)
- the text history
- media, which is opt-in and has a size limit

The **local identity table** holds the pairwise salts of §4.2.2. That table
also holds the group roster seed `GroupRosterSeed_g` of each group, and the
three group keys of Part 11 §11.9.1 (the roster key, the pair key, and the KEM
key) derive from that seed. The client makes each of these values from the
device CSPRNG, thus the root seed alone does not rebuild them. The local
identity table is not history. **[IDN-047]** A retention limit MUST NOT remove an entry from
that table.

**Requirements on the blob:**

- The client stores the backup under a **rotating and unlinkable credential**,
  and not under a stable identifier for each user. A client that knows the
  Recovery Code derives these four values:

  ```
  epoch               = floor( consensus_epoch / 168 )        // the weekly epoch, as BE32
  backup_handle_epoch = HMAC-SHA3-256( BackupRootKey,
                                       "umbra/v1/backup-handle" || epoch )
  backup_write_cred   = HMAC-SHA3-256( BackupRootKey,
                                       "umbra/v1/backup-write" || epoch )
  backup_read_cred    = HMAC-SHA3-256( BackupRootKey,
                                       "umbra/v1/backup-read" || epoch )
  backup_key_epoch    = HMAC-SHA3-256( BackupRootKey,
                                       "umbra/v1/backup-key" || epoch )
  ```

  `consensus_epoch` is the `epoch` field of the most recent `DirectoryRoot` of
  Part 10 §10.5.2 that the client accepted, and 168 such epochs make one week.
  **[IDN-119]** A client MUST compute the weekly epoch from the most recent
  `DirectoryRoot` that it accepted. A restore fetches the root over a path,
  thus a restoring client holds a `DirectoryRoot` before it computes the first
  handle. Part 3 §3.2.6 uses the same weekly epoch. A relay sees random 32-byte
  handles. A relay cannot list the backups. A relay also cannot link the
  sequential handles of one user without the Recovery Code.
- **The backup root.** The four values name one chunk, the **backup root**,
  and that chunk names each stored backup object. The root is a
  handle-addressed chunk of Part 12 §12.4.2. **[IDN-093]** A client MUST write
  the backup root with `chunk_id` of `backup_handle_epoch`, `cred_sk` of
  `backup_write_cred`, and `read_sk` of `backup_read_cred`. **[IDN-094]** A
  client MUST seal the root under `backup_key_epoch` as the `sealed` field
  below. **[IDN-114]** A client MUST pad the result under Part 12 §12.2.3.

  ```
  BackupRootChunk {                     // the chunk plaintext, before the padding
      nonce        [24]u8               // from the device CSPRNG
      sealed       var                  // XChaCha20-Poly1305( backup_key_epoch, nonce, BackupRoot,
                                        //   ad = backup_handle_epoch )
  }

  BackupRoot {
      version      u8                   // 0x01
      count        u8                   // 1 to BACKUP_ROOT_ENTRIES
      entries      [count]BackupEntry   // entry 0 is the latest full object
  }

  BackupEntry {                         // 980 bytes at most
      kind         u8                   // 0x01 a full object, 0x02 a delta object
      desc_len     u16
      descriptor   [desc_len]u8         // a FileDescriptor of Part 12 §12.3
  }
  ```

  **[IDN-095]** A client MUST write each backup object as a file of Part 12
  §12.3 in the backup class. Part 12 §12.3.3 rule 10 gives that class.
  **[IDN-115]** A client MUST record the `FileDescriptor` of that file as one
  `BackupEntry`. **[IDN-096]** A client MUST use level `0x01` for a backup
  object above `BACKUP_DESC_REFS` data chunks. Part 12 rules `ATT-072` and
  `ATT-073` do not apply to a backup object. **[IDN-097]** A client MUST put
  the latest full object at entry 0, and then each later delta in write order.
  **[IDN-098]** A
  client MUST write the root again after each object write, under Part 12 rule
  `ATT-138`. **[IDN-099]** After a full write succeeds, a client MUST send
  `CDEL` for each object that the new root does not name. **[IDN-100]** A
  client MUST NOT send `CDEL` for the root of an earlier epoch.
- **The restore.** **[IDN-101]** At a restore, the client MUST fetch the root
  of the current epoch, and then of each earlier epoch. **[IDN-116]** The
  client MUST stop when a root opens under its `backup_key_epoch`, or after
  `BACKUP_LOOKBACK` epochs. §4.8 sets that value to 26. **[IDN-102]** A client
  MUST apply the
  full object of entry 0 and then each delta in entry order. **[IDN-103]** A
  client MUST reject a root whose `sealed` field does not open, and it MUST
  treat that epoch as empty.

  > *Cause.* An earlier draft derived a handle and a write credential and gave
  > the backup no read credential, no content key, no structure, and no relay.
  > A relay stores an opaque chunk under a chunk identifier, thus a backup
  > needs the shape of a chunk. The root is one chunk, and `BACKUP_ROOT_ENTRIES`
  > of 31 holds one full object and the 30 daily deltas of one
  > `BACKUP_FULL_INTERVAL`. `BACKUP_DESC_REFS` of 7 keeps an entry inside 980
  > bytes. At level `0x01` one entry addresses 7 × 271 = 1 897 data chunks,
  > which is about 62 MB. That figure is the ceiling of one backup object, and
  > it bounds the opt-in media. Part 12 §12.3.2 gives the null reference that
  > the second `RelayRef` of a backup ref holds.
- **The backup object.** A backup object carries rows of the local store of
  Part 14 §14.6.4, each under its surrogate identifier and in its
  plaintext. `K_store` derives from the root seed (Part 5 §5.2), and the
  surrogate identifiers derive from `K_store`, thus a restore under the same
  seed puts each row at its place again.

  ```
  BackupObject {                        // the plaintext of the file, before §12.3
      version      u8                   // 0x01
      kind         u8                   // 0x01 a full object, 0x02 a delta object
      written_at   u64                  // Unix seconds of the writer
      base_at      u64                  // a delta: written_at of the object before it; a full object: 0
      count        u32
      rows         [count]BackupRow
  }

  BackupRow {
      op           u8                   // 0x01 put, 0x02 delete
      table        u8                   // the table of the store
      row_id       [16]u8               // the surrogate identifier
      // op 0x01 only:
      owner_flag   u8                   // 0x00 no owner, 0x01 an owner follows
      owner        [16]u8               // the owner column, when owner_flag is 0x01
      len          u32
      plain        [len]u8              // the plaintext of the row
  }
  ```

  **[IDN-178]** A client MUST write each backup object in the layout above.
  **[IDN-179]** A full object MUST hold each row that the restore needs and
  no delete. A delta MUST hold each such row that changed and each such row
  that left since the object before it. **[IDN-180]** A client MUST NOT put
  in a backup object a row that holds a state of this device alone: a push
  registration of Part 8, a push token, the ingress pin of Part 10, the
  dead-channel state of Part 3 §3.2.6, the device set and the sync channels
  of Part 7 (`DEV-291`), or the wrap of the store. A restored device makes
  each of them again. **[IDN-186]** A file stays on the device, and a backup
  object MUST carry the state of each file as one that waits for a tap
  (Part 14 `IMP-167`), or as one that failed when no descriptor names it. A
  restored device then fetches the file of a record, sent or received, from
  its descriptor while the chunks live. **[IDN-181]** A reader MUST reject an
  object with a `version` other than `0x01`, a `kind` other than the two
  values, a full object with a delete or a `base_at` other than 0, or bytes
  after the last row. **[IDN-182]** A restore MUST apply the full object
  and then each delta in the order of the root, each row in object order: a
  put replaces the row, and a delete removes it. **[IDN-183]** A restore
  MUST mark the channel of each restored contact stale under Part 3 rule
  `NET-325`, and the renewal of Part 3 §3.2.6 gives each one a new session.
- **[IDN-073]** A relay MUST hold a backup object for `BACKUP_TTL`. §4.8 sets
  that value to 180 days. **[IDN-074]** A revision MUST hold `BACKUP_LOOKBACK`
  weeks at or above `BACKUP_TTL`.

  > *Cause.* An earlier draft set `BACKUP_LOOKBACK` to 8 weekly epochs and gave
  > a backup object no retention value at all. A user that lost a device and
  > restored 10 weeks later then computed no handle that names a stored object,
  > and no rule made the relay hold that object. U10 needs 99 % of users to
  > recover the identity, the contacts, and the queue state. The two values
  > above give a user 180 days, and IDN-074 keeps them in agreement.

- **The backup travels on the chunk path of Part 12 §12.3.3.** **[IDN-075]** A
  client MUST divide a backup object into chunks of `CHUNK_SIZE`. **[IDN-117]**
  A client MUST write those chunks under the attachment commands of that
  section, with `BNEW` as the registration. **[IDN-076]** A client MUST write each chunk to
  `BACKUP_REPLICAS` relays under different operators. Part 3 rule `NET-344`
  relaxes that bound in a provisional directory. **[IDN-077]** A client
  MUST send a backup chunk on the separate connection of Part 12 §12.8.

  > *Cause.* An earlier draft put a backup write in a scheduled `B0` cover slot.
  > Part 3 §3.6.2 gives a 2 h foreground day about 360 such slots, and Part 6
  > §6.9 gives a `B0` slot 390 bytes at L6. That ceiling is about 140 KB each
  > day, and the acknowledgments and the receipts of Part 3 §3.5.4 take part of
  > it. This section holds 45 days of text history, thus a cover slot cannot
  > carry it. Part 3 §3.6.2 rule NET-133 states the prohibition, and Part 3
  > §3.12 holds the bandwidth row.

- **The write cadence is a clock, and it does not follow the user.**
  **[IDN-078]** A client MUST write a full backup object at each
  `BACKUP_FULL_INTERVAL`. **[IDN-079]** A client MUST write a delta object at
  each `BACKUP_INTERVAL`. **[IDN-048]** A client MUST NOT write on a change. A
  durable artifact for each user is a strong signal if its update time follows
  the activity of the user. Part 7 §7.1 makes this same objection against the
  ratchet-state-on-relay proposal of SimpleX, and the objection applies here
  also.
- **[IDN-184]** A client MUST write a delta object at its time when no row
  changed since the object before it. A delta that a change alone starts
  shows the relay the time of that change.
- **[IDN-080]** A client MUST write a backup in the foreground only.
  **[IDN-081]** A client MUST draw an independent delay for each backup write,
  from a uniform distribution over the write interval. Thus U4 does not measure
  a backup write, and the write time carries no user action.
- **[IDN-185]** For `BACKUP_EARLY_WINDOW` after its first backup write, a
  client MUST use `BACKUP_EARLY_INTERVAL` in the place of `BACKUP_INTERVAL`.
  That clock follows the age of the install, and not the acts of the user.

  > *Cause.* A new install writes its first full object at the first connect,
  > before the user adds a contact. With a delta each 24 h, a device that is
  > lost on its first day restores no contact. The first write already shows
  > the relay a new install, thus the early clock shows nothing more. Each
  > write is about 9 `B3` cells, thus the early clock costs about 1 MB for
  > each hour in the foreground, for two days.
- **[IDN-082]** A client MUST hold a full backup object no longer than
  `BACKUP_HISTORY_DAYS` of history. §4.8 sets that value to 45 days, which is
  the `MSG_TTL` of Part 3 §3.2.4 and the U10 target of §4.7.4.
- The relay holds ciphertext under a key that the nonprofit has not held and
  cannot derive. Legal process can compel the ciphertext blob and its random
  handle, but legal process cannot compel the Recovery Code.

### 4.7.3 Social recovery (optional)

Some users lose a written code. For those users, the client offers **k-of-n
social recovery**. The client makes Shamir shares of `C_social`, with a default
of 3-of-5, and delivers the shares over **existing pairwise queues**.

**The shares carry the social half only.** **[IDN-083]** A client MUST put
`C_social` in the shares. **[IDN-084]** A client MUST NOT put `C_user` in a
share. **[IDN-085]** A client MUST NOT put a value from which a party derives
`C_user` in a share.

> *Cause, and the goal that it protects.* An earlier draft split the full
> Recovery Code. §4.7.1 derives `BackupRootKey` from that code, and §4.7.2
> derives `backup_handle_epoch` from `BackupRootKey`. Thus three share holders
> reconstructed the code, computed the handle, fetched the object from the
> relay, and opened it. That object holds the `RootIdentity`, the local identity
> table, and the history. §5.2 of Part 5 states that the local identity table is
> the one object that links the pairwise salts and the group roster seeds of a
> user. Goal G9 of Part 2 §2.3 holds against
> **colluding contacts**, thus three contacts that take an account defeat a
> stated goal. The earlier text called the method graceful because the share
> holders are authenticated contacts. That is a usability statement and it is
> not a security argument.
>
> With the split, three share holders hold `C_social` and 128 bits of unknown
> `C_user`. A recovery needs the two halves together.

**Where `C_user` lives.** The user holds `C_user` as the `RecoveryDigits` of
§4.7.7. §4.7.1 IDN-042 also lets a mainstream build put `C_user` in
Android Block Store. **[IDN-086]** If a client puts
`C_user` in a platform-cloud item, that client MUST NOT put a share of
`C_social` in that same item.

> Thus neither set alone recovers the account. A platform account gives
> `C_user`, and three contacts give `C_social`. Part 15 §15.1 holds the two
> rows, and A5 has to reach two different parties in two different positions.

**[IDN-087]** The interface MUST state that the shares alone do not recover the
account. **[IDN-088]** The interface MUST state which half each share holder
receives.

**The share on the wire.** A share goes to its holder as an `AppMessage` of
kind `0x0D` (Part 6 §6.6) with this body.

```
RecoveryShare {
    version      u8          // 0x01
    set_id       [16]u8      // one split, from the CSPRNG
    threshold    u8          // k, 2 or more
    count        u8          // n, at or above k
    share        [17]u8      // the share index, 1 to n, and 16 bytes
}
```

The body is **36 bytes**. The `share` field is the payload of the
`RecoveryDigits` of type `0x0003` of §4.7.7.

- **[IDN-187]** A client MUST send each share on the pairwise channel of its
  holder, one share to each holder. **[IDN-188]** A client MUST NOT send a
  share on a group channel or to more than one holder.
- **[IDN-189]** A holder MUST keep the last share of each contact, and it MUST
  give a share back only as `RecoveryDigits` of type `0x0003` on its screen.
  **[IDN-190]** A holder MUST NOT send a share on any channel. The user that
  lost a device has no channel, and a channel that an attacker took gives the
  share to the attacker.
- **[IDN-191]** A restore with shares MUST take `C_user` as `RecoveryDigits`
  of type `0x0002` and `threshold` shares of type `0x0003`, and it MUST join
  the shares before the KDF of §4.7.1. **[IDN-192]** A new split MUST draw a
  new `set_id`, and the interface MUST show the holders of the current split
  alone.

> *Cause.* An earlier draft said that the shares go over pairwise queues and
> gave them no layout, thus no holder could tell a share from a message. The
> return path is the screen of the holder, because the device of the owner is
> the thing that was lost.

This method adds no dependency, no server, and no trusted party. It also
degrades gracefully, because the share holders are authenticated contacts.

### 4.7.4 Recovery targets (normative)

| Target | Value |
| --- | --- |
| Users that lose a device and recover the identity, the contacts, and the queue state | ≥ 99 % |
| Users that also recover 45 days or more of text history | ≥ 95 % |
| Median recovery time, from install to a restored inbox | ≤ 10 minutes |

**[IDN-049]** An implementation MUST measure these targets. **[IDN-050]** An
implementation MUST publish the results.

### 4.7.5 Explicitly rejected: enclave or HSM escrow

UMBRA does **not** implement Signal SVR3, the OPAQUE and HSM fleet of WhatsApp,
or a PIN-escrow scheme.

These schemes are good engineering. SVR3 recovers in 365 ms at $0.0025 for each
user each year, across three heterogeneous enclaves. But each scheme needs **one
logical account provider that can apply a rate limit**, **trusted hardware from
named vendors**, and **cloud accounts under one operator**. Those are three
central coercion targets. They contradict the infrastructure model and the KISS
constraint.

This document records the rejection here, thus no reader opens the decision
again.

### 4.7.6 Recovery UX rules (normative)

- **[IDN-051]** **A security-setup screen MUST NOT block the message list.** Signal #9632
  (2020) blocked users from the messages until the users made a PIN.
- **[IDN-052]** The client MUST let a user dismiss a recovery prompt. **[IDN-053]** After **two** dismissals
  the client MUST NOT prompt again, and only the settings screen offers the
  operation. Signal #14666 (2026) records weekly backup prompts that a user
  cannot dismiss. The reporter correctly predicted that users "eventually give
  in."
- Element #15416 records a related tension. Users that delay the recovery setup
  lose all their data, and then they "abandon and foreswear" the platform.
  Silent cloud escrow does not solve this tension. The solution has three parts.
  The parts are progressive prompts that a user can dismiss, optional
  platform-cloud backup for mainstream users, and social recovery. The social
  recovery serves the users that lose a written code.
- **[IDN-054]** Onboarding MUST NOT block on the confirmation of the recovery code if that
  block moves the time-to-first-message past the U1 target.

### 4.7.7 The recovery digits

A user holds four secrets as digits. The root seed of `IDN-003`, the Recovery Code of §4.7.1, the user
half `C_user` of §4.7.3, and a share of `C_social` of §4.7.3 are each a string
of decimal digits. An earlier draft let two of them take a word list, and no
value told a screen which secret the user typed. The encoding below tags each
one, and a checksum catches a transcription error before a 3-second KDF runs.

```
RecoveryDigits {
    type      u16          // 0x0001 the Recovery Code, 32 bytes
                           // 0x0002 C_user, 16 bytes
                           // 0x0003 a share of C_social, 17 bytes,
                           //        the share index first
                           // 0x0004 the root seed of IDN-003, 32 bytes
    payload   [n]u8
    check     u16          // SHA3-256( BE16(type) || payload )[0..2]
}

digits = the bytes of RecoveryDigits as one big-endian integer, in decimal,
         with leading zeros to the fixed width of the type, in groups of five
```

The Recovery Code is 36 bytes and 87 digits, and so is the root seed: its
`type` tells the two apart. `C_user` is 20 bytes and 49
digits. A share is 21 bytes and 51 digits. A screen reads the first digits,
decodes `type`, and knows the width.

- **[IDN-149]** A client MUST export each of the four secrets as
  `RecoveryDigits` in decimal, in groups of five digits. **[IDN-150]** A client
  MUST NOT export any of the four as a word list. Rule `IDN-041` keeps the
  hexadecimal form out on the same cause, which is the transcription error
  rate.
- **[IDN-151]** A client MUST verify `check` before it uses an entered secret.
  **[IDN-152]** If `check` fails, the client MUST say so and MUST NOT run the
  KDF.
- **[IDN-153]** If `type` differs from the type that the screen asks for, the
  client MUST name the type that the user entered and the type that the screen
  asks for. **[IDN-154]** A client MUST NOT use a payload of a type other than
  the one that the screen asks for.
- **[IDN-155]** If a restore yields an empty local identity table, the client
  MUST show a blocking screen that states that the restore recovered no
  identity. **[IDN-156]** That screen MUST offer the three recovery paths of
  §4.7 and no message list. A message list over an empty identity table is a
  new account that the user did not ask for. It looks like a restore that
  worked.

## 4.8 Parameters

| Parameter | Value |
| --- | --- |
| `RECOVERY_CODE_BITS` | 256, as `C_user` 128 and `C_social` 128 (§4.7.1) |
| `SOCIAL_RECOVERY_K_OF_N` | 3 of 5 by default (§4.7.3) |
| `BACKUP_INTERVAL` | 24 h, the delta write (§4.7.2) |
| `BACKUP_FULL_INTERVAL` | 30 days, the full write (§4.7.2) |
| `BACKUP_EARLY_INTERVAL` | 30 min, the delta write of a new install (§4.7.2) |
| `BACKUP_EARLY_WINDOW` | 48 h after the first backup write (§4.7.2) |
| `BACKUP_REPLICAS` | 2, on different operators (§4.7.2) |
| `BACKUP_HISTORY_DAYS` | 45 days, which equals `MSG_TTL` |
| `BACKUP_TTL` | 180 days, the relay retention of a backup object |
| `BACKUP_LOOKBACK` | 26 weekly epochs, which is 182 days |
| `BACKUP_ROOT_ENTRIES` | 31, which is one full object and 30 deltas (§4.7.2) |
| `BACKUP_DESC_REFS` | 7, the data chunk count above which a backup object uses level `0x01` (§4.7.2) |
| `HANDLE_KEY_LOOKAHEAD` | 64, the count of rotation counter values that a restore tries above the restored counter (§4.2.4) |
| `PALETTE_SIZE` | 12 (§4.2.5) |
| `INVITE_TTL` | 14 days, measured by the relay from the store of the blob, and by the client from the issue (§4.3.1) |
| `INVITE_RESERVE_TTL` | 600 s, the time that a relay holds a link identifier with no blob (Part 6 rule `WIR-508`) |
| Invitation host | One host that the nonprofit operates, named at the release tag of the client (§4.3.1) |

> *The cause of `BACKUP_REPLICAS` of 2.* Part 12 §12.4 sets `REPLICAS` to 3 for
> an attachment, because one relay outage then breaks a transfer that no party
> repeats. A backup object is different. The client rewrites it at each
> `BACKUP_FULL_INTERVAL`, thus a lost replica heals at the next full write. Part
> 3 §3.12 gives the bandwidth of this row, and a third replica adds about
> 246 KB each day for no reliability that the rewrite does not already give.

## 4.9 Rejected alternatives

| Alternative | Cause of the rejection |
| --- | --- |
| **Phone-number identity** | This is the worst available decision. A phone number is a state-issued identifier with universal cross-reference. It forces a contact-discovery service that leaks the social graph. Researchers have shown enumeration attacks against such services many times. |
| **No global identifier at all (pure SimpleX model)** | This model is stronger. But it removes the social layer that the owner needs, and it makes reconnection after the loss of a device almost impossible. UMBRA keeps this model as the *default* and adds the opt-in layer above it. |
| **One global account key (Session model)** | This model has the simplest UX. But the address becomes a permanent correlator across each contact and each relay. The address also selects deterministically which relays hold your inbox. |
| **Blockchain naming** | The 2026 public-names answer of SimpleX needs a fork of the Ethereum Name Service on an Ethereum network, a wallet, and a self-hosted node stack. This document has not verified the RAM figure of about 32 GB for each operator. This design disobeys the KISS constraint and the no-token-economics rule. Part 9 gives a signed-record directory with a transparency log in place of it. |
| **Provider-held key escrow or PIN recovery** | This design makes an account provider, a rate limiter, and a compellable recovery oracle. The relay-stored backup of UMBRA is different. The server holds only ciphertext under a Recovery Code that the user holds, and the handles rotate and stay unlinkable. |
