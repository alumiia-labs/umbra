# UMBRA Protocol Specification — Part 13: Anti-Abuse Without Identifiers

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 13.1 The strongest anti-spam property of UMBRA is structural

Before a token or a puzzle, this property applies. **A party cannot send a
message to a person unless that person gave a queue to that party.** The
pairwise sender credential *is* the authorization. There is no address space to
enumerate, and there is no directory of users to scrape. There is also no method
to send a message to a stranger that did not opt in.

Each mechanism in this part exists to protect the three locations that this
structural property does not reach.

## 13.2 What is gated, and what is deliberately not gated

The table below holds one row for each gated path. The verifier is the party
that checks the credential. The fallback is what the verifier accepts from a
client that holds no credential. The carrier is where the credential travels.

| Gated path | Verifier | Credential | Issuer | Fallback | Carrier |
| --- | --- | --- | --- | --- | --- |
| A queue creation, `NEW` of Part 6 §6.4 | Any relay | A token of §13.3, of the type that the relay advertises | The issuer of §13.9 | The proof of work of §13.8 | The `Admission` at the end of the payload |
| A group-queue creation, `GNEW` of Part 6 §6.4.5 | Any relay | A token of §13.3, of the type that the relay advertises | The issuer of §13.9 | The proof of work of §13.8 | The `Admission` at the end of the payload |
| An allocation of attachment storage, `CNEW` and `BNEW` of Part 12 §12.3.3 | An attachment relay | A token of §13.3 | The issuer of §13.9 | The proof of work of §13.8, at `POW_CHUNK_FLOOR` or above, and one solution for `POW_CHUNK_ALLOWANCE` registrations | The `Admission` at the end of the payload |
| A contact request at a Public Address or at a handle, by the hello of Part 9 §9.6 | The addressee client | A cross-relay token of §13.3.1 | The issuer of §13.9 | The proof of work of §13.8, at `HELLO_POW_EFFORT` | The `Admission` at the end of the hello, inside its AEAD |
| A handle registration, Part 9 §9.9 | The handle directory | One first-party token of §13.3.2 | The issuer of §13.9 | None | The registration request of Part 9 §9.9 |
| An OPRF evaluation of a lookup, Part 9 §9.4.1 | The handle directory | One first-party token of §13.3.2 | The issuer of §13.9 | The proof of work of §13.8, at `POW_LOOKUP_FLOOR` or above | The lookup request of Part 9 §9.4 |

A handle registration has no fallback. A proof of work prices a squat in
computation, and a squat is a purchase of a name and not a surge. Part 1
§1.8 records that the registration request and the lookup request have no
layout in this draft.

**Not gated:**

- **An ordinary message send.** The write credential of the queue (Part 3
  §3.2.2) authorizes such a send. A gate on a send puts a token cost on the
  fast path and damages the latency budget. It gives no security.
- **A group post.** A `GPOST` of Part 6 §6.4.5 is not gated, for the same
  cause. The relay applies `GROUP_POST_RATE` of Part 3 §3.2.7 for each group
  queue, and it answers a post above that rate with a `NACK` of reason
  `LIMIT`.

This design keeps the anti-abuse system fully off the critical path. Thus the
anti-abuse system does not change the chat latency.

**The carrier.** Four commands and the hello of Part 9 §9.6 end with one
`Admission`.

```
Admission {
    kind      u8      // 0x00 none
                      // 0x01 a token of §13.3
                      // 0x02 retired, §13.4 gives the cause
                      // 0x03 a PowSolution of §13.8
    len       u16
    body      [len]u8
}
```

The body of kind `0x01` is 354 bytes or 162 bytes, by the token type. The body
of kind `0x03` is 69 bytes. The body of kind `0x00` is empty, thus the trailer
costs 3 bytes in the steady state.

- **[ABU-044]** A client MUST end the payload of a `NEW`, a `GNEW`, a `CNEW`,
  and a `BNEW` with one `Admission`. **[ABU-045]** A parser MUST reject a `kind`
  that the table above does not hold. **[ABU-046]** A parser MUST reject a `len`
  that differs from the body length of its `kind`. **[ABU-089]** A parser MUST
  reject kind `0x02`, which an earlier draft gave to an ARC presentation.
- **[ABU-047]** A relay whose newest `PowChallenge` holds `effort` 0 MUST
  accept an `Admission` of kind `0x00` on `NEW` and `GNEW`.
  **[ABU-048]** If that `effort` is above 0, the relay MUST answer such a
  command with a `NACK` of reason `ADMISSION`. Part 6 §6.4.4 gives the reason.
  The client then fetches the challenge and sends the command again, thus a
  stale effort costs one retry.

> *Cause.* An earlier draft listed three gated paths in prose. It named no
> verifier, no issuer, and no carrier. It left a handle registration off the
> list, while Part 9 §9.9 priced it at one token of no named type. Part 9 §9.6
> spent an ARC presentation that no section issued. The `NEW` payload of Part 6
> §6.4 held no field for a token, thus `ABU-014` had no wire. The table and the
> trailer close each of those gaps, and the trailer of 3 bytes keeps the
> steady-state cost near zero.

### 13.2.1 A new install holds no token

U1 of Part 2 §2.4 gives a new install 90 seconds to the first message, with no
account screen and no server picker. That install has to create a queue, and the
list above gates a queue creation.

- A §13.2 row whose fallback names §13.8 gives the verifier a second path.
  **[ABU-014]** That verifier MUST accept a correct proof of work of §13.8 in
  place of the credential of the row. **[ABU-015]** A relay MUST NOT need a token for a queue creation.

  > *Cause.* An earlier form of `ABU-014` bound a relay and a queue creation
  > only. The rendezvous path and the handle directory then had no fallback,
  > and the two doors of §13.1 stayed locked for a new install. The rule now
  > binds each verifier that the table names.
- **[ABU-016]** An issuer MUST NOT need an identifier from a client to issue a
  token batch. **[ABU-017]** A deployment MUST publish the attestation that it
  uses for an issuance. **[ABU-018]** A deployment MUST NOT use a hardware
  attestation for that purpose, and §13.11 gives the cause.

**§13.8 sets the suggested effort at 0 in the steady state. Thus a new install
pays nothing, and it reaches U1.** Under load the effort rises, and a token then
buys the holder past the puzzle. That is the full function of a token in this
system: a token is a fast path and it is not an admission gate.

> *Cause.* An earlier draft gated a queue creation with a token and said, in
> §13.9, that a user "receives a grant by some method". That sentence was the
> only statement of issuance, and `ABU-001` forbids the three-party Attester
> that usually answers the question. A new install then had no path to a first
> queue. §13.1 already carries the anti-spam property alone, and this section
> states that plainly in place of an unstated gate.

## 13.3 Token architecture

UMBRA uses two token types. The `token_type` field of RFC 9578 gives the type.

### 13.3.1 Cross-relay token — `0x0002`, blind RSA-2048

This token uses RFC 9474 `RSABSSA-SHA384-PSS-Deterministic`. It is **354
bytes**, and a verifier checks it with one RSA public-exponent operation.

A third party can verify this token, and that property is the important one. **A
self-hosted third-party relay verifies the token offline with the public key of
the nonprofit alone.** Such a relay holds no shared secret, and it keeps its own
local set of spent nonces. A third-party operator does not trust the issuer,
does not contact the issuer, and does not need trust from the issuer.

### 13.3.2 First-party token — `0x0005`, VOPRF ristretto255-SHA512

This token comes from `draft-ietf-privacypass-batched-tokens`. It is **162
bytes**, and a verifier checks it with one scalar multiplication, at about 60
µs. UMBRA uses it for the relays that the nonprofit operates. For those relays,
batched issuance uses about 8 times less bandwidth and about 16 times less
issuer CPU.

A relay advertises the type that it accepts.

**The token layout.** Both types follow RFC 9578: `token_type u16 || nonce
[32]u8 || challenge_digest [32]u8 || token_key_id [32]u8 || authenticator`,
with an authenticator of 256 bytes for `0x0002` and 64 bytes for `0x0005`.
The client draws `nonce` from the device CSPRNG, and the issuer signs or
evaluates `token_input`, which is the four fields before the authenticator.

- **[ABU-093]** A party MUST compute `token_key_id` as `SHA3-256` over the
  issuer public key bytes: the 256-byte modulus of a `0x0002` key, or the
  32-byte ristretto255 element of a `0x0005` key.
- **[ABU-094]** A party MUST compute `challenge_digest` as `SHA3-256` over
  `TokenChallenge = token_type u16 || epoch u32 || redemption_context [32]u8`,
  where `epoch` is the epoch number of §13.6 and `redemption_context` is the
  `relay_id` of one relay under §13.7, or 32 zero bytes for any relay of the
  type. **[ABU-095]** A verifier MUST accept a token whose `challenge_digest`
  names the current epoch or the one before it, with its own `relay_id` or
  the zero context, and MUST reject each other digest.
- **[ABU-096]** The `0x0002` authenticator is the RFC 9474 signature over
  `token_input` with a 48-byte salt that the client draws at the blind, and
  the `0x0005` authenticator is the RFC 9497 output over `token_input` at the
  VOPRF mode. **[ABU-097]** An issuer MUST answer a batch of `0x0005` requests
  with one DLEQ proof over the batch, and a client MUST verify that proof
  before it finalizes a token of the batch.

### 13.3.3 Post-quantum status — state it accurately

**The token unlinkability is information-theoretic.** The blinding factor is
uniform. Thus a future quantum adversary that breaks the issuer key can forge
tokens *from that moment*, but that adversary **cannot deanonymize the past
redemptions**. This property is real and unusual. It means that tokens are
**not** a harvest-now-decrypt-later exposure.

Post-quantum *unforgeability* is not deployable today. The best 2026 result is
PoMFRIT (eprint 2026/109), at 6.7 KB for each signature. The zkDilithium Privacy
Pass of Cloudflare is 85–173 KB, with a proving time of 0.3–5 s. Lattice blind
signatures are 22–308 KB.

Thus UMBRA ships classical tokens in v1. UMBRA reserves `token_type` space, and
it sizes the wire format for an authenticator of 7 KB. PoMFRIT is the named
migration target.

## 13.4 Rate limiting the Public Address

A contact request to a Public Address or to a handle is the hello of Part 9
§9.6. The hello travels as an ordinary padded
message to a rendezvous queue, and any queue relay holds that queue. The queue
relay reads a padded message and nothing more. Thus the only party on the path
that can check a credential is the addressee. The addressee client is the
verifier of this path.

**[ABU-012]** An addressee client MUST verify the `Admission` at the end of a
hello before it shows the request. **[ABU-013]** A deployment MUST NOT put a
privately verifiable credential on a path whose verifier is not its issuer.

**The credential is the cross-relay token of §13.3.1.** A third party verifies
that token with the public key of the issuer alone, and the addressee is such
a party. The addressee holds the issuer keys from the log of §13.5 under
`ABU-002`, thus the check contacts no party.

- **[ABU-078]** An addressee client MUST verify a token of a hello against an
  issuer key of the log of §13.5. **[ABU-079]** An addressee client MUST NOT
  accept a token of a type other than `0x0002` in a hello. The first-party
  token of §13.3.2 needs the issuer secret, and the addressee does not hold it.
- **[ABU-080]** An addressee client MUST accept a token of the current epoch
  and a token of the epoch before it. **[ABU-081]** An addressee client MUST
  reject a token whose nonce it accepted before at the same Profile.
  **[ABU-056]** An addressee client MUST hold the spent-nonce set of an epoch
  until the end of the next epoch. The set has the scope of one Profile of Part
  4 §4.2.5, and the handle entry and the address entry of one Profile share it.

A token is one hello. A batch of 256 tokens of §13.9 is 256 hellos, at one
addressee or at many. The token is unlinkable, thus no rule links two hellos of
one stranger, and no limit for each sender exists at an addressee. The limits
of this path are the price of a token or of a solve, `HELLO_INBOUND_LIMIT`
below, and the one-tap rotation of Part 9 §9.9.

**The fallback is a proof of work with a derived challenge.** The addressee is
offline when a stranger sends, and it publishes no `PowChallenge` of §13.8. The
client derives the challenge from the entry that it looked up.

```
entry_pk     = HK_pub of a DirectoryEntry (Part 9 §9.3),
               or address_pk of an AddressEntry (Part 9 §9.3.3)
epoch_number = the epoch number of §13.6
verifier_id  = SHA3-256("umbra/v1/hello-verifier" || entry_pk)
seed         = SHA3-256("umbra/v1/hello-seed" || entry_pk
                        || BE32(epoch_number))
effort       = HELLO_POW_EFFORT
```

The client builds the challenge string of §13.8 from those values, and it puts
the `PowSolution` in the `Admission` as kind `0x03`. Part 5 §5.11 holds the two
labels.

- **[ABU-082]** A client that holds no token MUST compute the solution of a
  hello under the three values above.
- **[ABU-083]** An addressee client MUST verify a `PowSolution` of a hello
  against the seed of the current epoch and against the seed of the epoch
  before it. **[ABU-084]** An addressee client MUST apply `ABU-072` to
  `ABU-074` to that solution, with `HELLO_POW_EFFORT` as the effort of the
  challenge.
- **[ABU-085]** An addressee client MUST reject a hello whose `Admission` is of
  kind `0x00`. The addressee publishes no effort, thus the effort of this path
  never reaches 0, and the surge valve of §13.8 does not apply here.

`HELLO_POW_EFFORT` of 50 costs about 0.6 seconds on a phone, and about 0.2
seconds on a desktop. A token adds 357 bytes to the hello, and a solution adds
72 bytes. The verification of a token is one RSA public-exponent operation, and
the verification of a solution is about 50 µs. Part 2 §2.4 states the trade.

**The inbound limit.**

- **[ABU-086]** An addressee client MUST NOT show more than
  `HELLO_INBOUND_LIMIT` hellos for one published entry in one epoch.
  **[ABU-087]** If the client reaches that limit, it MUST offer the rotation of
  Part 9 §9.9.3 to the user. **[ABU-088]** The client MUST discard a hello
  above the limit after it acknowledges the record.

**The rate-limit state is at the addressee, and it is not at a third party.**
**[ABU-001]** UMBRA MUST NOT build a three-party Attester. The rate-limited Privacy Pass draft
of the IETF expired for this cause. The Attester holds a persistent identifier
for each client and learns the access patterns. Collusion between the Attester
and an Issuer shows which Origins a client visits.

> *Cause.* An earlier draft gave this path an ARC credential
> (`draft-ietf-privacypass-arc-crypto`) over ristretto255, and it named "the
> rendezvous service of the nonprofit" as the verifier. Part 9 §9.3 defines
> the rendezvous as a queue address on any relay, and no such service exists.
> ARC is privately verifiable, thus no addressee and no third-party relay could
> check a presentation, and the path had no verifier. The earlier draft also
> bound the presentation to the handle in Part 9 §9.6 and to the Public
> Address in this section. The cross-relay token needs the public key alone,
> and the addressee is the party that the spam reaches, thus the addressee is
> the verifier.
>
> The change removes ARC and its use of ristretto255 from this part.
> `ARC_PRESENTATIONS` retires with it. Rules `ABU-050` to `ABU-055` retire,
> because no ARC issuer exists. `ABU-012`, `ABU-013`, and `ABU-056` keep their
> numbers and name the addressee, because each one still states who verifies
> and what that party holds.

## 13.5 Key transparency for issuers — mandatory

Each issuer public key and its epoch go into an **append-only transparency
log**. **[ABU-002]** A client MUST refuse a token from a key that is not in the log. **[ABU-003]** A client
MUST also refuse to redeem against a relay that advertises a key that is not in
the log. The issuer publishes DLEQ evidence for privately-verifiable issuance.

**The log is the log of Part 9 §9.5.** The signers, the gossip, and the
lookup of that log serve an issuer key with no new mechanism.

```
IssuerKeyEntry {                  // the entry of one leaf, Part 9 §9.5.1
    token_type     u16            // §13.3
    epoch          u32            // §13.6
    key_len        u16
    public_key     [key_len]u8
}

label input = "umbra/v1/issuer-key" || BE16(token_type) || BE32(epoch)
```

- **[ABU-098]** An issuer MUST publish the key of each token type for each
  epoch as version 0 of the label above, before the epoch starts.
  **[ABU-099]** A client MUST look up that label under Part 9 §9.4, and it
  MUST verify the `LookupProof` of Part 9 §9.5.1 before it accepts the key.
- **[ABU-100]** A client MUST reject the label when its newest version is not
  0. A second version is a second key for one epoch, and the binary ladder of
  Part 9 §9.5.1 shows it to each client.
- **[ABU-101]** A client MUST reject an entry whose `token_type` or `epoch`
  differs from the label that it looked up.

> *Cause.* An earlier draft named a log and defined no object, no signer, and
> no lookup. A second log needs a second signer set and a second gossip
> source, and Part 9 §9.5.2 records how hard one funded set is to keep. The
> label input is public, and the client still blinds it, thus the directory
> serves one lookup shape.

> Without this log, a coerced or seized issuer performs the per-client-key
> attack of RFC 9576 with no difficulty. That issuer gives one user a unique
> key, and each redemption of that key is then attributable. The attack
> deanonymizes each user that accepted a personal key, and the client sees no
> signal.

## 13.6 Key rotation

The epoch number is the Unix seconds of the clock of a party divided by
604 800, rounded down. An epoch boundary is a multiple of 604 800 seconds.
§13.4 derives a seed from that number.

- **[ABU-004]** **An issuer MUST rotate each issuer key at one global 7-day epoch boundary.**
  **[ABU-005]** An issuer MUST NOT give one key or one relay a rotation of its own. Such a
  rotation divides the anonymity set (RFC 9576). RFC 9497 also makes the global
  rotation necessary, to limit the static-DH loss of log₂(Q)/2 bits on a VOPRF
  key.
- Batch issuance has a limit of **256 tokens for each attestation**. A
  stockpile costs money on path 1 of §13.9, and a grant on path 2. On path 3 it
  costs about 7 minutes of a phone for each batch. No rule caps the batch count
  of one party, because a party is anonymous, and Part 15 §15.3 states that
  residual.
- Each token has the scope of its epoch. Thus a stockpile becomes worthless in
  one week.

## 13.7 Spend checking is relay-local

Each relay keeps its **own** set of spent nonces. That set is a Bloom filter or
a hash set. Its scope is the current epoch, and its size matches the traffic of
that relay.

**[ABU-114]** A verifier MUST keep its set of spent nonces across a restart,
until the end of the epoch after the epoch of each nonce. A set that a restart
empties takes each token of two epochs one more time.

**[ABU-006]** **UMBRA MUST NOT build a global double-spend database.** Such a database is a
central linkage asset, a seizure target, and a scaling bottleneck. The cost is
that a party can spend a token one time *at each relay*. Where that cost
matters, give the token the scope of one relay or of a small relay set, with the
`redemption_context` of RFC 9577.

## 13.8 Proof of work — a surge valve, and not a baseline

UMBRA implements **Equi-X**, with the maintained Rust crates `hashx` and
`equix`. Arti uses those two crates. The constraints are these:

- The suggested effort is **0 in the steady state**.
- The effort increases only at a measured queue pressure at a relay.
- The effort has a hard limit, thus the slowest supported phone stays below
  **about 2 seconds**.
- A correct token **always avoids** the puzzle.
- **[ABU-007]** An implementation MUST NOT let an attacker influence the effort parameter.
- **[ABU-008]** The client MUST give the user visible feedback during the computation.

> Laurie and Clayton (2004) showed the effect of the difficulty that prices out
> abuse. That difficulty is 5.8–346 s for each message, and it breaks 0.13–13 %
> of the legitimate heavy senders.
>
> The EquiX deployment of Tor stays off by default. It has no published
> measurement of its effectiveness, and Tor is in a redesign of it. It is also
> regressive against phones. A phone gives 87 sol/s and a desktop gives 250
> sol/s. A target that is not x86 or ARM is 10–40 times worse. Its documented UX
> failure was that it gave no feedback to the user.

The verification takes about 50 µs. Thus one relay core absorbs about 20 000
puzzle checks each second.

**The challenge.** A verifier publishes its current effort in a signed object.
The `verifier_id` of a relay is its `relay_id` of Part 10 §10.5.3. The handle
directory holds an ML-DSA-65 identity key that the log of §13.5 lists, and its
`verifier_id` is the SHA3-256 of that key. `ABU-109` gives the `verifier_id` of
the issuer of §13.9. §13.4 derives the `verifier_id` of an addressee from its published key.

```
PowChallenge {
    version        u8          // 0x01
    verifier_id    [32]u8
    scheme         u8          // 0x01 Equi-X
    seed           [32]u8      // from the CSPRNG of the verifier
    effort         u32         // 0 to POW_EFFORT_MAX
    issued_at      u64         // Unix seconds, the clock of the verifier
    sig            [3309]u8    // ML-DSA-65, label "umbra/v1/pow-challenge"
}
```

The object is 3 387 bytes. The signature covers
`"umbra/v1/pow-challenge" || the bytes up to and not including sig`. Part 5
§5.11 holds the label.

- **[ABU-057]** A verifier MUST make a new `PowChallenge` with a fresh `seed`
  at each `POW_CHALLENGE_PERIOD`. **[ABU-058]** A verifier MUST accept a
  solution to its newest challenge and to the one before it. **[ABU-059]** A
  verifier MUST NOT accept a solution to an older challenge.
- **[ABU-060]** A relay MUST derive `effort` from the backlog of its own
  admission queue over the last `POW_CHALLENGE_PERIOD`. **[ABU-092]** That
  derivation MUST be `effort = min(POW_EFFORT_MAX, backlog / POW_BACKLOG_UNIT)`,
  raised to the floor of the verifier where one applies, with `backlog` the
  count of admissions pending in that period. **[ABU-061]** A
  verifier MUST NOT take an `effort` value from a client or from another
  party. **[ABU-062]** A verifier MUST NOT set `effort` above
  `POW_EFFORT_MAX`. These three rules give `ABU-007` its mechanism.
- **[ABU-063]** A relay MUST publish its newest challenge at each
  `POW_CHALLENGE_PERIOD`, under `ABU-102`. **[ABU-064]** A carrier of the
  relay manifest MUST serve the newest challenge of each relay that the
  manifest lists, beside the manifest, under `ABU-104`. Part 10 §10.5.5 gives
  the manifest. The challenge sits outside the relay-set tree, and the relay
  signs it, thus a consensus epoch does not bound it.
- **[ABU-065]** A client MUST fetch the challenge of a relay on the path of a
  descriptor fetch. **[ABU-066]** A client MUST NOT open a session for the only
  purpose of a challenge fetch. A challenge fetch shows the same fact as a
  descriptor fetch, which is the relay that the client selected.
- **[ABU-102]** A relay MUST send each challenge that it makes to each relay
  of the manifest with the ingress flag of Part 10 §10.5.3, the carriers of
  the manifest. It sends it as the value of one `UMBRA_CHALLENGE` capsule of
  Part 6 `WIR-529`. A carrier keeps its own challenge with no capsule.
- **[ABU-103]** A carrier MUST take a challenge only when `sig` verifies under
  the `identity_pk` of the entry of `verifier_id` in the manifest that it
  holds, and only when `issued_at` is less than two `POW_CHALLENGE_PERIOD`
  before its clock and at most one period after it. A carrier MUST keep only
  the newest challenge of each verifier, and it MUST drop a challenge that
  passes the two periods.
- **[ABU-104]** A carrier MUST serve the challenges that it keeps at the path
  `/.well-known/umbra/challenges`, on the transport of its manifest fetch. The
  body is the `PowChallenge` objects one after another, 3 387 bytes each, in
  ascending order of `verifier_id`.
- **[ABU-105]** A client MUST fetch the challenges from the carrier that it
  pinned for the manifest, and it MUST take each one under `ABU-068`, with the
  `identity_pk` of the entry of the verifier. That fetch meets `ABU-065`. A
  client MUST drop a body whose length is not a multiple of 3 387 bytes. It
  trusts the carrier with no challenge: a carrier can withhold one, and it
  cannot forge one.

> *Cause of the carrier.* An earlier draft had the relay publish its
> challenge to the directory authorities, and an authority serve it beside
> the descriptor. An authority of Part 10 signs a root once in an epoch, and
> it serves no fetch to a client: the manifest reaches a client from a
> carrier. A challenge lives for two periods, and an epoch is longer. The
> carrier already serves the manifest, thus a challenge at the carrier adds
> no path, and the signature of the relay makes the carrier a courier only.
> A carrier that withholds a challenge denies the admission of a proof of
> work at that relay; a token of §13.3 still admits.
- **[ABU-067]** A verifier other than a relay or an addressee client MUST
  return its newest challenge with each admission rejection. An admission
  rejection is a rejection of a request that carries no accepted `Admission`.
  An addressee client has no channel to the sender of a hello, and §13.4
  derives its challenge.
- **[ABU-068]** A client MUST verify `sig` against the identity key of the
  verifier before it computes a solution. **[ABU-069]** A client MUST NOT
  compute a solution to a challenge that it fetched more than
  `POW_CHALLENGE_PERIOD` before. The client measures that period from the
  fetch.
- **[ABU-070]** The handle directory MUST NOT set `effort` below
  `POW_LOOKUP_FLOOR`. Thus a lookup with no token is not free. A crawl of 10⁶
  handles costs about 2 × 10⁷ Equi-X solves, which is about 22 hours of one
  desktop.

**The solution.**

```
challenge  = "umbra/v1/pow" || verifier_id || seed || nonce || BE32(effort)
solution   = Equi-X(challenge)                  // 16 bytes, eight u16 indexes
R          = BE32( SHA3-256(challenge || solution)[0..4] )
pass       = R × effort ≤ 2^32 − 1

PowSolution {
    version    u8        // 0x01
    seed       [32]u8    // the seed of the challenge
    nonce      [16]u8
    effort     u32       // at or above the effort of the challenge
    solution   [16]u8
}
```

The object is 69 bytes. The client selects a `nonce`, runs Equi-X, and tests
`pass`. If `pass` does not hold, the client moves to the next `nonce`. The
expected count of Equi-X solves is `effort`. At 87 solves each second on a
phone, `POW_EFFORT_MAX` of 150 costs about 1.7 seconds, which is the bound of
the third constraint above. Part 5 §5.11 holds the label `"umbra/v1/pow"`.

- **[ABU-071]** A verifier MUST reject a `PowSolution` whose `seed` is not the
  seed of a challenge that `ABU-058` accepts. **[ABU-072]** A verifier MUST
  reject a `PowSolution` whose `effort` is below the `effort` of that
  challenge. **[ABU-073]** A verifier MUST reject a `PowSolution` that fails
  the Equi-X verification or the `pass` test.
- **[ABU-074]** A verifier MUST reject a `PowSolution` whose `nonce` it
  accepted before under the same `seed`. The set of accepted nonces has the
  scope of the two live seeds, thus §13.7 holds.
- **[ABU-075]** A client MUST set `effort` in a `PowSolution` at or above the
  `effort` of the challenge that it holds.

> *Cause.* An earlier draft named Equi-X and the `hashx` and `equix` crates,
> and no object carried a scheme, a seed, an effort, or an expiry. A client
> could not learn the effort, and it could not show progress against an
> unknown target under `ABU-008`. Tor publishes `pow-params` in the descriptor.
> UMBRA serves a separate signed object beside the descriptor. The effort is a
> fast-moving pressure signal, and the descriptor is bound to a consensus epoch
> of one hour. The relay signs the object, and each carrier of the manifest
> serves it under `ABU-064` and `ABU-104`. Thus one relay cannot give one
> client a private effort that no carrier holds.

### 13.8.1 The allocation of attachment storage

An allocation of attachment storage holds bytes at a relay for two weeks (Part 12
§12.7.1), thus a flood of it lasts longer than a flood of any other gated path.
It carries a solution even when the effort is 0.

- **[ABU-106]** A relay MUST reject a `CNEW` and a `BNEW` whose `Admission` is
  of kind `0x00`. It MUST reject a solution on those commands whose `effort` is
  below `POW_CHUNK_FLOOR` or below the effort of its challenge.
- **[ABU-107]** One solution MUST admit at most `POW_CHUNK_ALLOWANCE` `CNEW`
  and `BNEW` commands at its relay, while its challenge is live under
  `ABU-058`. Only its first use MUST count in the backlog of `ABU-060`, thus
  one large upload does not raise the effort for each other party.
- **[ABU-108]** A client SHOULD use one solution for each registration at one
  relay until its allowance ends or its challenge is no longer the newest.

> *Cause.* At an effort of 0 an allocation cost nothing, and the relay held one
> quota counter for each upload that carried no token (Part 12 `ATT-092`). One
> party spent that counter in minutes and stopped each attachment and each
> backup at the relay for the rest of the day. A floor of 8 costs a slow phone
> about 0.1 s for each 2 MiB of chunks, thus a photo costs about 0.3 s at its
> three replicas. A flood of 100 GiB costs about 51 200 solutions, and the
> effort of `ABU-060` rises under it.

## 13.9 Funding infrastructure without identifying users

UMBRA funds the relays by a **sale or a grant of blind-signed token batches**. A
user gets a batch of blind-RSA-signed relay-access tokens for one epoch by one
of the three paths below. §13.2.1 states that a token is a fast path and not an
admission gate, thus a user that takes no path still reaches U1.

1. A purchase.
2. A grant from a party that holds a batch, by a blind reissue.
3. The proof of work of §13.8, which costs time in place of money.

- **[ABU-076]** On path 3 the issuer MUST demand one `PowSolution` at
  `POW_EFFORT_MAX` for each token of the batch. **[ABU-077]** The issuer MUST
  NOT issue a token on path 3 for a solution at a lower effort.

**The issuance request.** A client asks for a batch of first-party tokens of
§13.3.2 with a `DirRequest` of kind `0x10` of Part 9 §9.10.

```
IssueRequest {
    token_type  u16               // 0x0005
    epoch       u32               // §13.6
    count       u8                // 1 to ISSUE_REQUEST_MAX
    items       [count]{ blinded [32]u8, solution PowSolution }
}

IssueResponse {
    count       u8
    elements    [count][32]u8
    proof       [64]u8            // one DLEQ proof over the batch, ABU-097
}
```

- **[ABU-109]** The seed of each solution MUST be `SHA3-256("umbra/v1/issue-pow"
  || BE32(epoch) || blinded)`, and its `verifier_id` MUST be
  `SHA3-256("umbra/v1/issue-pow-verifier" || pk)`, where `pk` is the issuer key of
  that epoch. **[ABU-110]** An issuer MUST answer the epoch of its clock and
  the next one only, and the next one only after its key is in the log under
  `ABU-098`. A solution thus serves one blinded element. A second request
  with that element gets the same element back, and the token is the same
  token, which a verifier spends once.

> *Cause.* Part 1 §1.8 gave the issuance of a token no layout and no carrier.
> Path 3 needs no interaction beyond one request: the blinded element fixes
> the seed, thus the issuer holds no challenge state and no replay set.

**The cross-relay form.** A request for `token_type` `0x0002` holds items of
`blinded [256]u8` and a `PowSolution`, and the answer holds `count u8` and
`count` blind signatures of 256 bytes each, with no batch proof.

- **[ABU-111]** An issuer MUST take the RSA key of `0x0002` for an epoch from
  the log under `ABU-098`, and it MUST answer an epoch whose key the log does
  not hold as stale. `ABU-076`, `ABU-077`, `ABU-109`, and `ABU-110` hold for
  that form as for `0x0005`, with the modulus of the key as `pk`.
  **[ABU-112]** A client MUST verify each token of the answer under that key
  before it keeps the token. The signature of one blinded message is one
  value, thus a second request with that message gives the same token, which a
  verifier spends once.
- **[ABU-113]** A client MUST hold the cross-relay keys of its epoch and of
  the next one from the log, thus it verifies a hello of Part 9 `DIS-182`
  with no lookup at its arrival. A client SHOULD keep a few cross-relay tokens
  of its epoch, and it spends one on each hello that it sends; with none it
  sends the proof of work of §13.8. A token of an older epoch goes.

A batch of 256 tokens costs about 7 minutes of a phone under that rule. Thus a
token that a user buys with time costs what the puzzle of one relay costs at
its maximum. Path 3 does not undercut the valve of §13.8.

- **[ABU-090]** The nonprofit MUST publish the price of a token batch with the
  cost model of Part 15 §15.6.1. **[ABU-091]** The nonprofit MUST NOT set that
  price above the recovery of the relay cost. A sale at cost recovery is a
  payment for relay capacity and not for the software. Part 15 §15.6 rests the
  CRA position on that fact.

This method gives the same unlinkability between the payer and the traffic as
Chaumian ecash. It also gives **no custody, no token economics, and no
money-transmitter exposure**. It uses one cryptographic dependency that UMBRA
holds for other functions.

**Explicitly rejected:**

- **Cashu and Chaumian ecash mints.** The FAQ of Cashu states that "ecash
  wallets are always custodial". It also states "don't put any money into Cashu
  mints that you're not willing to lose."
- **GNU Taler.** It needs a licensed exchange operator.
- **A blockchain token.** The owner decided that this is out of scope. Such a
  token also couples the protocol to a chain and to the regulatory exposure of
  that chain.

## 13.10 Abuse reporting

UMBRA does **not** frank a 1:1 message or a private group message. The
protocol has no report on the wire.

**[ABU-010]** **UMBRA MUST NOT build a global moderator key**, and **[ABU-011]** UMBRA MUST NOT frank a 1:1
message. A report about a private conversation is a screenshot. A cryptographic
accountability rail is the item that a government later demands access to. To
build one voluntarily is the easiest method to lose G13.

## 13.11 Rejected

| Idea | Cause of the rejection |
| --- | --- |
| **Blind Schnorr on ristretto255** | The 64-byte signatures and the simplicity of one curve are attractive. But the ROS attack (EUROCRYPT 2021) breaks the scheme under concurrent sessions. The safe Clause Blind Schnorr variant needs one more round trip with help from the exchange. That round trip is the incorrect trade on an unstable mobile network. |
| **Hardware attestation** | Quarkslab (2026-08-11) relayed a genuine attestation chain from a clean oracle device, with a Frida hook and no compromise of the secure hardware. Hardware attestation also excludes rooted devices, de-Googled devices, and older devices. Those users need UMBRA most. |
| **Phone-number or email verification** | This method returns the identifier that the full design exists to prevent. |
| **Global reputation for senders** | This method needs a stable sender identifier. By design, UMBRA has none. |
| **CAPTCHA** | A CAPTCHA fails on accessibility, sends user data to a third party, and an attacker defeats it at a low cost. |

## 13.12 Blocking a contact

§13.10 refuses to frank a 1:1 message, and it gives the cause. That decision
leaves harassment inside a pairwise conversation with no answer, and this
section gives one. The answer is local, and it needs no relay and no report.

**A block is a client state, and it is not a protocol message.**

- **[ABU-021]** A client MUST hold the block state as mutable state of Part 7
  §7.5.3. **[ABU-022]** A client MUST converge that state across the device set.
- **[ABU-023]** A client MUST NOT send a record to the blocked party that names
  the block. **[ABU-024]** A client MUST NOT change the queue set of that
  contact at the block.

**The queue stays alive, and the block makes no signal.**

- **[ABU-025]** A client MUST NOT send `DEL` on the queue of a blocked contact.
  Part 6 §6.4.3 gives `DEL`, and a deleted queue makes the next send of that
  contact fail. That failure is the signal that this section removes.
- **[ABU-026]** A client MUST continue to send `ACK` for the records of a
  blocked contact. Thus the relay drains the queue on the ordinary schedule, and
  `QUEUE_QUOTA` of Part 3 §3.2.4 does not fill.
- **[ABU-027]** A client MUST discard a record of a blocked contact after it
  acknowledges that record. **[ABU-028]** A client MUST NOT render such a
  record. **[ABU-029]** A client MUST NOT raise a notification for such a
  record.
- **[ABU-030]** A client MUST continue to emit a delivery receipt of Part 6
  §6.6 kind `0x06` at the rate that held before the block. **[ABU-031]** A
  client MUST NOT emit a read receipt of kind `0x07` for a blocked contact.

> *Cause of the two receipt rules.* A delivery receipt states that a device
> holds the record, and that statement stays true. A read receipt states that
> the user read the record, and that statement becomes false. A client that
> stopped the delivery receipts would also name the moment of the block. Part 3
> rule `NET-059` keeps each receipt off by default for a new contact, thus the
> common case emits neither.

**A block does not end the ratchet.**

- **[ABU-032]** A client MUST continue to advance the ratchet of a blocked
  contact. **[ABU-033]** A client MUST NOT let the skipped-key store of Part 5
  §5.5.4 grow past `MAX_STORED` for that session.
- **[ABU-034]** A client MUST restore the ordinary behavior at an unblock.
  **[ABU-035]** A client MUST NOT deliver a record that it discarded under
  ABU-027 to the user at an unblock.

**A block inside a group.** A member blocks another member, and that block does
not remove the blocked member from the group. The group records of the blocked
member still arrive on the group queue of Part 11 §11.2, because every member
reads the same queue; the client applies ABU-027 to ABU-029 to them after the
tag check of Part 11 §11.3.5, and no relay learns the block.

- **[ABU-036]** A client MUST discard a record of a blocked member of a group.
  **[ABU-037]** A client MUST NOT emit a group record that names the block.
  **[ABU-038]** A client MUST show the count of the records that it discarded,
  thus a user knows that the conversation has a gap.
- **[ABU-039]** A client MUST offer the removal of Part 11 §11.9.2 to a member
  that holds a role of `admin` or above, beside the block. A block protects one
  member, and a removal protects the group.

**What a block does not do.**

- **[ABU-040]** The interface MUST state that a blocked party can still send.
  The records reach the relay and the device of the user, and the client
  discards them.
- **[ABU-041]** The interface MUST state that a block does not tell the blocked
  party. **[ABU-042]** The interface MUST NOT claim that a block stops a
  message.

> *Why the block is not a queue teardown.* A teardown is the cheap
> implementation, and it is the wrong one. Part 3 §3.2.4 rotates a queue on a
> schedule, thus a rotation is normal traffic. A `DEL` that follows a harassing
> message is not normal traffic. It names the moment that a user blocked, and a
> hostile party then makes a fresh contact request from a new identity, at the
> moment that it knows the block landed. The rules above cost the bytes of a
> live queue, and Part 2 §2.4 states that trade.

## 13.13 Parameters

| Parameter | Value |
| --- | --- |
| `HELLO_POW_EFFORT` | 50 expected Equi-X solves for a hello with no token (§13.4) |
| `HELLO_INBOUND_LIMIT` | 64 hellos for one published entry in each epoch (§13.4) |
| `POW_CHALLENGE_PERIOD` | 10 min, measured by the verifier from the issue of the last challenge (§13.8) |
| `POW_EFFORT_MAX` | 150 expected Equi-X solves (§13.8) |
| `POW_CHUNK_FLOOR` | 8, the lowest effort of a solution that admits a `CNEW` or a `BNEW` (`ABU-106`) |
| `POW_CHUNK_ALLOWANCE` | 64 registrations, about 2 MiB of chunks, for one solution at one relay (`ABU-107`) |
| `POW_LOOKUP_FLOOR` | 20 expected Equi-X solves (§13.8) |
| `ISSUE_REQUEST_MAX` | 16 tokens in one issuance request (§13.9) |
| `POW_BACKLOG_UNIT` | 64 pending admissions in one `POW_CHALLENGE_PERIOD` raise the effort by one (§13.8) |
