# UMBRA Protocol Specification — Part 5: Cryptographic Core

**Status:** Draft
**Version:** 0.20.0
**Date:** 2026-10-11

---

## 5.1 Primitive inventory

Here KISS is a security property, and not an aesthetic. Each primitive is one
more implementation to audit, one more constant-time discipline to enforce, and
one more location for an error. The **message core** carries **six primitive
families** and no more. The message core holds the pairwise handshakes, the
ratchets, the queue encryption, the group content, and the onion cell
protection. **[CRY-001]** A proposal to add a seventh primitive to the message core MUST give
its cause against this list.

| # | Primitive | Parameters | Used for |
| --- | --- | --- | --- |
| 1 | **X25519** | RFC 7748 | Classical half of each key agreement |
| 2 | **ML-KEM-768** | FIPS 203, Category 3 | Post-quantum half of each key agreement |
| 3 | **ML-DSA-65** | FIPS 204, Category 3 | *Only* objects that a third party verifies |
| 4 | **ChaCha20-Poly1305** | RFC 8439 | All record and message AEAD |
| 5 | **AES-256 + POLYVAL** | UIV+ / GCM-UIV+ | Onion per-hop wide-block layer only |
| 6 | **Keccak**: SHA3-256, SHAKE256 | FIPS 202 | Hash, XOF, and all KDFs through HMAC and HKDF |

This count applies to the message core only. Discovery, anti-abuse, notification
delivery, platform storage, and release signing are outside the message core.
Those systems need more standards, and the **auxiliary register** below holds
them. That register is separate from the table above. It is closed in the same
manner, and it carries a dependency cap of its own.

| # | Primitive | Parameters | Used for | Refer to |
| --- | --- | --- | --- | --- |
| AUX-1 | **Blind RSA-2048** | RFC 9474, `RSABSSA-SHA384-PSS-Deterministic` | Cross-relay token that a third party verifies | Part 13 §13.3.1 |
| AUX-2 | **ristretto255 with SHA512** | RFC 9497 VOPRF | First-party token and blind directory lookup | Part 13 §13.3.2, Part 9 §9.4 |
| AUX-3 | **ECVRF-Edwards25519-SHA512-TAI** | RFC 9381, classically secure only | Index blinding for handle key transparency, and the probe selection that a relay MUST NOT predict | Part 9 §9.5, Part 10 §10.4.1 |
| AUX-4 | **Argon2id** | about 3 s for each try on a mid-range device | Human recovery code, and the at-rest passphrase | Part 14 §14.6.4 |
| AUX-5 | **A keyed function inside the secure element** | HMAC-SHA256 in StrongBox | Entanglement of the at-rest key with the secure element | Part 14 §14.6.4 |
| AUX-6 | **HPKE under OHTTP** | RFC 9180 and RFC 9458, with `UMBRA-KEM`; the suite is `UMBRA-KEM`, HKDF-SHA3-256, and ChaCha20-Poly1305 under the identifiers of §5.10, and the labels of RFC 9180 §4 hold (CRY-151) | The notification boundary, and the one-time `k_ntf_root` | Part 8 §8.2.3 |
| AUX-7 | **XChaCha20-Poly1305** | 24-byte random nonce | Storage master key wrap, and each database record | Part 14 §14.6.4 |
| AUX-8 | **Equi-X** | the `hashx` and `equix` crates, with the JIT off | Proof of work as a surge valve | Part 13 §13.8 |
| AUX-9 | **Two-aggregator additive secret sharing with Laplace noise** | PrivEx-S2, `b = σ/ε` | The relay statistic that a directory publishes | Part 10 §10.8 |

A per-record storage key has no counter, thus AUX-7 needs a 24-byte random
nonce.

The relay layer assignment of Part 3 §3.4.1 does **not** use AUX-3. Part 10
§10.5.4 computes it with Keccak, which is primitive 6 of the message core. That
assignment has no secret and no prover, thus a VRF would add a primitive and
carry no information.

**[CRY-002]** Those primitives MUST be in isolated crates or in platform adapters. **[CRY-003]** Those
primitives MUST NOT protect ordinary message content. **[CRY-004]** Those primitives MUST NOT
be on the path of a send on a pairwise channel that exists.

Part 14 §14.2 gives the dependency register R1 for the message core, and the
dependency register R2 for the auxiliary primitives above. Each register carries
a cap of its own. `DEPENDENCIES.md` holds the measured counts.

**[CRY-005]** An implementation MUST NOT use a cryptographic primitive that this section does
not list. To add an auxiliary primitive, add a row to the auxiliary register and
give its cause. To add a primitive to the message core, give its cause against
the table above.

**Exclusions and their causes:**

- **UMBRA does not use Ed25519.** The removal of Ed25519 removes the full SHA-2
  family from the core, because ML-KEM and ML-DSA put Keccak in the binary. The
  result is one hash family and not two. The removal also removes an API shape.
  CVE-2022-50237 records the full extraction of a private key from two
  signatures. The cause was an API that let a caller give a public key that did
  not match.

  > **The hybrid-signature question, answered explicitly.** A reasonable
  > argument says that long-lived objects that a third party verifies have to
  > carry a *concatenated hybrid* Ed25519 and ML-DSA-65 signature. Those objects are
  > the directory roots and the transparency tree heads. The argument is that
  > a lattice break lets an attacker rewrite
  > archived state retroactively. The argument also says that Ed25519 limits the
  > cryptanalytic risk in a much younger scheme.
  >
  > UMBRA declines, thus the protocol does not carry a seventh primitive.
  > `sig_id` (§5.10) is a wire field that the two parties negotiate. Thus a
  > deployment can add a hybrid without a flag day if the cryptanalysis
  > of ML-DSA moves. This is a real residual risk, and Part 15 §15.7 records it.
- **The core does not use SHA-2.** TLS in the transport layer (Part 3 §3.8)
  brings its own SHA-2, and that is outside the TCB of the cryptographic core.
- **UMBRA does not use sntrup761**, and this decision differs from SimpleX.
  sntrup761 has no FIPS validation and no maintained pure-Rust implementation.
  Thus its adoption puts `unsafe` C FFI and a C supply chain in the most
  security-critical path. That result conflicts directly with the
  minimal-dependency constraint. SimpleX objects to ML-KEM because NIST removed
  a hashing step that mitigated an RNG compromise. §5.3 and §5.9 answer that
  objection, and this document does not ignore it.
- **UMBRA bans Classic McEliece.** Grubbs, Maram, and Paterson (eprint 2021/708)
  show that its KEM-DEM construction is **not robust**. For a message *m*, a
  party can build one hybrid ciphertext. That ciphertext decrypts to *m* under
  *each* private key. Relays handle ciphertexts addressed to unknown recipients,
  thus this property is fatal in UMBRA. The public keys are also 524 KB, and a
  mobile device cannot use them.
- **UMBRA bans FN-DSA and Falcon.** In August 2026 FIPS 206 was not published.
  Its provisional design makes a bit-exact IEEE-754 binary64 signing path
  mandatory, with an operation order that NIST specifies. That design is the
  opposite of portable. Falcon key generation measures about 42 ms on a
  Cortex-A72. "Do Not Disturb a Sleeping Falcon" (Eurocrypt 2025) also defeats
  each derandomized variant.
- **UMBRA does not use HQC in v1.** For hqc-192 the public key is 4 522 B and
  the ciphertext is 9 042 B. But the KEM identifier is a wire field that the two
  parties negotiate. Thus a deployment can ship HQC as an emergency answer to an
  ML-KEM break, and without a flag day. Refer to §5.10.

### 5.1.1 Why UMBRA selects ML-KEM-768

FIPS 203 is not the only cause. Maram and Xagawa (eprint 2022/1696, PKC 2023)
proved that ML-KEM-768 is **ANO-CCA and robust in the QROM**. IND-CCA security
does *not* give ciphertext anonymity. The Tamarin identity-hiding proof of
PQ-WireGuard silently assumed a key-hiding property, and the standard
assumptions do not give that property. Each ciphertext that UMBRA puts on a
relay has to be unlinkable to a public key. Thus anonymity is a **first-class
selection criterion** and not a detail.

**[CRY-006]** A future KEM substitution MUST verify the anonymity and the robustness again,
and not only IND-CCA.

## 5.2 Key hierarchy

```
RootIdentity (256-bit seed, device-local, NEVER on the network and NEVER to a
              relay. The device-link channel of Part 7 §7.4 is the one path,
              and IDN-002 makes it the only one)
│
├── K_rng_harden = Expand("umbra/v1/rng-harden", 32)    RFC 8937 hardening secret
├── K_store      = Expand("umbra/v1/storage", 32)       at-rest master (Part 14)
├── K_devset     = Expand("umbra/v1/device-set", 32)    device-set membership (Part 7)
│
├── DeviceKey_i       per device: X25519 + ML-KEM-768, generated ON that device
│                     (the Root seed is transferred once at link time, Part 7)
│
├── PairwiseIdentity_c   per contact c: X25519 + ML-KEM-768 (the KEM half is reserved, Part 4 §4.5.1)
│                        = Hybrid( Expand("umbra/v1/pairwise" || salt_c, 96) )
│                        salt_c is 16 random bytes for each contact
│
├── PublicAddressKey_j   optional, j = 0,1,2…
│                        = Hybrid( Expand("umbra/v1/public-address" || BE32(j), 96) )
│                        X25519 + ML-KEM-768, and Part 4 gives the rules
│
└── HandleKey_{j,r}      optional, the handle key of PublicAddressKey_j
                         = Hybrid( Expand("umbra/v1/handle-key" || BE32(j) || BE32(r), 96) )
                         X25519 + ML-KEM-768, and Part 4 §4.2.4 gives the rules

Expand(info, L):
    return HKDF-SHA3-256( salt = "", ikm = RootIdentity, info = info, L = L )

Hybrid(t):                                  // t is 96 bytes
    x25519_sk  <- clamp( t[0..32] )         // RFC 7748 §5
    x25519_pk  <- X25519( x25519_sk, 9 )
    (ek, dk)   <- ML-KEM-768.KeyGen_internal( d = t[32..64], z = t[64..96] )
    return (x25519_sk, x25519_pk, ek, dk)
```

The function `Expand` is one HKDF-SHA3-256 call with a zero-length salt, which
RFC 5869 maps to 32 zero bytes. The function `Hybrid` splits a 96-byte output
into the two private keys. The function `ML-KEM-768.KeyGen_internal` is
Algorithm 16 of FIPS 203, and it takes the two 32-byte seeds `d` and `z`.

1. **[CRY-118]** An implementation MUST derive each key of the diagram with
   the `Expand` function and the `Hybrid` function above.
2. **[CRY-119]** An implementation MUST take the X25519 scalar from
   `t[0..32]`, `d` from `t[32..64]`, and `z` from `t[64..96]`.
3. **[CRY-120]** An implementation MUST clamp the X25519 scalar as RFC 7748 §5
   states, before the first use.
4. **[CRY-121]** The test vectors of Part 6 §6.8 MUST hold one key-hierarchy
   vector from one fixed `RootIdentity`. That vector gives each key of the
   diagram.

> *Cause.* A line of the form `KDF(Root, label)` gives no salt, no output
> length, and no split of the output into the two keypairs. Two clients can
> then restore one root seed to two different identities, and the user reaches
> no contact after a restore. Part 9 §9.9.1 and Part 12 §12.3.3 write the full
> call, and CRY-034 to CRY-037 pin the `UMBRA-KEM` encoding to the byte. This
> section holds the same rigor.

Each key in the diagram above comes from one 256-bit `RootIdentity` seed. The
one-way KDF gives the unlinkability, and separate generation does not. An
observer that holds `PairwiseIdentity_c` and `PublicAddressKey_j` sees two
unrelated public keys. That observer cannot correlate the two keys without the
`RootIdentity`. An adversary that holds the `RootIdentity` has won against each
other measure.

Two classes of key are **not** in this hierarchy. The device makes each one
directly from its CSPRNG.

- Queue keys (Part 3 §3.2.2), one for each queue. **[CRY-007]** A device MUST NOT derive a
  queue key from a long-term secret. Thus a seized relay cannot collect the
  queues of one user.
- `GroupRosterSeed_g` (Part 11 §11.9.1), one for each group. The roster key,
  the pair key, and the KEM key of Part 11 §11.3.3 derive from that seed under
  the labels of §5.11.

The client stores each `GroupRosterSeed_g` in the **local identity table**, together
with the pairwise salts of Part 4 §4.2.2. The root seed restores the
hierarchy in the diagram above. The encrypted backup of Part 4 §4.7.2 restores
the local identity table. Thus the Recovery Code restores the full account, and
the root seed alone does not.

## 5.3 The hybrid KEM: `UMBRA-KEM`

UMBRA defines its own combiner. UMBRA does not make a normative reference to a
draft that no body has ratified.

```
UMBRA-KEM.Gen():
    (pk_X, sk_X) <- X25519.Gen()
    (pk_M, sk_M) <- MLKEM768.Gen()
    return (pk = pk_X || pk_M, sk = sk_X || sk_M)          // pk = 1216 B

UMBRA-KEM.Encap(pk):
    (ek_X, pub_X) <- X25519.Gen()
    ss_X          <- X25519(ek_X, pk_X)
    (ct_M, ss_M)  <- MLKEM768.Encap(pk_M)
    ct            <- pub_X || ct_M                          // ct  = 1120 B
    ss            <- SHA3-256( "umbra/v1/kem-combine"
                             || ss_M || ss_X
                             || ct_M || pub_X
                             || pk_M || pk_X )
    return (ct, ss)                                         // ss  = 32 B

UMBRA-KEM.Decap(sk, pk, ct):
    parse sk as sk_X (32 B) || sk_M (2400 B)                // sk  = 2432 B
    parse pk as pk_X (32 B) || pk_M (1184 B)                // pk  = 1216 B
    parse ct as pub_X (32 B) || ct_M (1088 B)               // ct  = 1120 B
    ss_X          <- X25519(sk_X, pub_X)
    if ss_X = 0^32: abort                                   // §5.4.7
    ss_M          <- MLKEM768.Decap(sk_M, ct_M)
    ss            <- SHA3-256( "umbra/v1/kem-combine"
                             || ss_M || ss_X
                             || ct_M || pub_X
                             || pk_M || pk_X )
    return ss                                               // ss  = 32 B
```

**The encoding is fixed.** **[CRY-034]** An implementation MUST encode `pk_X` and `pub_X` as
the 32-byte little-endian u-coordinate of RFC 7748. **[CRY-035]** An implementation MUST
encode `pk_M`, `sk_M`, and `ct_M` in the byte encoding of FIPS 203. **[CRY-036]** An
implementation MUST concatenate in the order that the two algorithms above give.
The order of the concatenation in `pk`, in `sk`, and in `ct` is the classical
part and then the post-quantum part. The order inside the hash is the
post-quantum part and then the classical part, and those two orders differ
deliberately. **[CRY-037]** An implementation MUST NOT change either order.

**The decapsulator holds `pk`.** A device that holds `sk` also holds the matching
`pk`, because `pk` is public and local. **[CRY-038]** An implementation MUST NOT rebuild
`pk_M` from `sk_M` at each decapsulation, because that step is not constant-time
in each ML-KEM implementation. **[CRY-039]** An implementation MUST store `pk` beside `sk`.

**The failure behavior.** The two halves fail in two different manners, and the
three paragraphs below separate them.

**The classical half.** **[CRY-040]** `Decap` MUST abort on an all-zero `ss_X`,
and §5.4.7 gives the cause. That abort is a validation failure on a public input.
The caller supplies `pub_X`, thus the abort gives that caller no fact that the
caller does not hold already.

**The post-quantum half.** **[CRY-041]** `MLKEM768.Decap` MUST use the implicit
rejection of FIPS 203, thus a malformed `ct_M` gives a pseudorandom `ss_M` and it
does not give an error. A malformed `ct_M` therefore gives a shared secret, and
the mismatch appears later as an AEAD tag failure.

**The error value.** **[CRY-042]** An implementation MUST give one error value for
each failure of `Decap`. Thus the validation abort of CRY-040 is the only failure
that `Decap` signals, and no error value names the half that failed.
**[CRY-043]** An implementation MUST perform the re-encapsulation check of §5.12.

**[CRY-044]** `Encap` and `Decap` MUST give the same `ss` for one `(pk, sk)` pair and one
`ct`. **[CRY-045]** The test vectors of Part 6 §6.8 MUST hold that equality.
**[CRY-046]** Those test vectors MUST hold a negative vector for an all-zero
`pub_X`.

### 5.3.1 Why this combiner and not X-Wing

X-Wing (draft-connolly-cfrg-xwing-kem-10) deliberately **omits** `ct_M` from the
hash, as an optimization for performance. Its own text gives a warning. The text
says that this choice "relies crucially on the specifics of the Fujisaki-Okamoto
transformation used in ML-KEM-768". The text also says that "the X-Wing combiner
cannot be assumed to be secure when used with different KEMs."

UMBRA hashes each input, which is the two shared secrets, the two ciphertexts,
and the two public keys. This method follows the conservative Chempat method.
There are three causes:

1. **Crypto-agility.** UMBRA keeps the right to change ML-KEM for HQC at short
   notice (§5.10). A combiner with a security argument that depends on the FO
   transform of ML-KEM cannot survive that change. This combiner can survive it.
2. **Binding by construction.** The hash of `ct_M`, `pk_M`, and `pk_X` gives the
   binding properties directly. The combiner does not inherit those properties
   from the KEM. Fiedler and Günther (PKC 2025) show that this method removes
   the dependence on the `LEAK+r-BIND-SS-{CT,PK}` assumptions that broke PQXDH.
3. **The cost is zero.** The method adds one SHA3-256 absorption of about 2.2
   KB. ML-KEM-768 decapsulation takes 12–16 µs, thus the hash cost is
   negligible.

X-Wing is a good construction. UMBRA does not need its optimization, and UMBRA
cannot accept its non-genericity.

### 5.3.2 A bare concatenation is prohibited

One of the two components can have no IND-CCA2 security. A KEM combiner that
does not preserve security then gives a hybrid with **no** IND-CCA2 security
(Giacon, Heuer, Poettering, eprint 2018/024). **[CRY-008]** Implementations MUST NOT
concatenate shared secrets and give them to an AEAD or to a raw hash without
domain separation. SHA-2 and CMAC are also unsuitable as key combiners. SHA-2
permits a length-extension attack. The two constructions also do not keep
collision resistance when the secret is known and not uniform.

## 5.4 Handshake: `UMBRA-XKhfs`

The handshake has three flows and 1.5 RTT. It is hybrid, and the authentication
is classical. UMBRA has a second handshake, `UMBRA-NKhfs`, and §5.4.9 gives it.
A circuit hop of Part 3 §3.4.3 runs that one.

### 5.4.1 Pre-shared material

The out-of-band invitation link or the QR code (Part 4) carries these fields:

```
responder_static_x25519      32 B
responder_kem_ek             1184 B   (ML-KEM-768 encapsulation key, one-time)
version_range                2 B      min and max, Part 6 §6.7
queue_address                129 B    QueueAddress, Part 6 §6.6.10, the first queue of the responder
bundle_len                   2 B      the length of relay_bundle, u16
relay_bundle                 var      signed, for bootstrapping
```

**[CRY-151]** An HPKE of AUX-6 MUST build its `suite_id` as `"HPKE" ||
kem_id || kdf_id || aead_id` from the identifiers of §5.10, which are `0x0001`
each, and it MUST use `UMBRA-KEM` as the KEM with `Nsecret` of 32, `Nenc` of
1 120, and `Npk` of 1 216, HKDF-SHA3-256 as the KDF, and ChaCha20-Poly1305 as
the AEAD, with the labeled extract and expand of RFC 9180 §4 unchanged.

**[CRY-150]** A client MUST write the six fields in the order above, with
`bundle_len` before `relay_bundle`, and a reader MUST reject a bundle with
bytes after `relay_bundle`. Part 6 §6.1.1 rule 2 gives each variable field a
length before it.

The field `queue_address` is the queue that carries flight 1, and Part 3 rule
`NET-172` requires it. The initiator answers with its own first queue in
`app_1`, and Part 3 rule `NET-173` requires that.

The field `responder_kem_ek` is the one-time prekey `s1` of §5.4.5. The field
`version_range` is the advertised range of the responder. §5.4.8 binds that
range into the prologue, and Part 6 §6.7 rule WIR-093 requires that binding.

**No party signs a prekey.** The link moves on a side channel that carries its
own authentication. The blob of Part 4 §4.3.1 seals the fields above under a
key that the relay does not hold. The hello of Part 9 §9.6 seals them to
`HK_pub`. A relay that substitutes a prekey fails that AEAD, and the protection
costs nothing in deniability.

> *Cause.* The fields above hold no commitment to `responder_kem_ek`. The AEAD
> of the blob already protects that field, thus a commitment adds no
> protection.

> *This decision has the largest effect on deniability in UMBRA.* A signature on
> a prekey bundle is the cause that breaks the offline deniability of PQXDH.
> Eprint 2024/741 (PoPETs 2024(4), v1.1 June 2025) proves that PQXDH is
> **undeniable** against a malicious receiver with a quantum distinguisher. The
> cause is "the signature on the ephemeral key." The specification of Signal
> itself says that post-quantum deniable mutual authentication is "an open
> research problem."

### 5.4.2 Message flow

```
Pre-message:  <- s, s1                        (from the invitation link)

(1) I -> R:   range_i, mode, pid, e, e1, es, skem1   2339 B + payload
              range_i  the advertised range of I        2 B
              mode   the handshake mode, §5.4.8          1 B
              pid    one-time prekey identifier          16 B
              e      X25519 ephemeral                     32 B
              e1     ML-KEM-768 ephemeral ek            1184 B
              es     X25519(e, s)              -> MixKey
              skem1  ML-KEM-768.Encap(s1)               1088 B + flight tag 16 B

(2) R -> I:   e, ee, ekem1                     1136 B + payload
              e      X25519 ephemeral                     32 B
              ee     X25519(e, e)              -> MixKey
              ekem1  ML-KEM-768.Encap(e1)               1088 B + flight tag 16 B

(3) I -> R:   s, se                              64 B + payload
              s      AEAD-sealed initiator static     32 + 16 B
              se     X25519(s, e)              -> MixKey (computed, not transmitted)
                     flight tag                              16 B

Total: 3539 B
```

Each flight carries one 16-byte flight tag, and §5.4.8 gives that tag. The
totals are these:

| Flight | Fields | Flight tag | Total |
| --- | --- | --- | --- |
| (1) | `range_i` 2, `mode` 1, `pid` 16, `e` 32, `e1` 1184, `skem1` 1088 | 16 | 2 339 |
| (2) | `e` 32, `ekem1` 1088 | 16 | 1 136 |
| (3) | `s` 32 with a 16-byte AEAD tag | 16 | 64 |
| **Sum** | | | **3 539** |

**[CRY-047]** A revision MUST make the three flight rows and the sum agree.

The field `range_i` is the `version_range` of Part 6 §6.7 that the initiator
advertises, as two cleartext bytes. The responder learns `range_r` from its own
invitation, and it has no other source for `range_i`. §5.4.8 puts the two
ranges in the prologue, thus the transcript binds `range_i` at the two parties.
A change to those two bytes in transit makes the flight tag fail.

The field `mode` is the `handshake_mode` of the prologue, as one cleartext
byte. Version 1 defines the one value `0x01`, and §5.4.8 gives the rules.

`UMBRA-KEM` (§5.3) is the generic hybrid KEM. A party uses it when an object has
a hybrid public key. `UMBRA-XKhfs` is a transcript with a Noise shape. Its
classical contributions are the DH tokens `es`, `ee`, and `se`. Its post-quantum
contributions are the two ML-KEM ciphertexts above.

**[CRY-009]** Implementations MUST bind these items into the transcript KDF:

- each transmitted field
- the two AEAD flight tags
- the two static identities
- the version range
- the handshake mode
- the address type

The table lists only the handshake bytes that the cryptography needs. Part 6
bucket sizing accounts for the application payload ciphertext and the padding.

### 5.4.3 Identity-hiding rationale

Noise rev34 gives identity-hiding grades. Under those grades this pattern gives
the **initiator grade 8**, which is "encrypted with forward secrecy to
authenticated party". The pattern also gives *post-quantum* forward secrecy. The
initiator shows its static key only in message 3. That message moves under a
chaining key that has absorbed the X25519 `ee` secret and the ML-KEM `ekem1`
secret.

The **responder gets grade 3**, because no party transmits the responder static
key. The invitation link carried that key before the handshake.

**Patterns that UMBRA rejects, and the causes:**

| Pattern | Initiator grade | Cause of the rejection |
| --- | --- | --- |
| `IK` | 4 | The initiator static key is encrypted to the responder static key with **no forward secrecy**. A state that archives relay traffic today, and seizes the device of the responder in five years, deanonymizes each past conversation initiation. This is the most common available error, because WireGuard and WhatsApp use IK. |
| `IN`, `IX`, `IK1` | 0 | The static key is in cleartext. |
| `XX` | 8 | Permitted, but it wastes the responder key that UMBRA has out of band, and it gives the responder grade 1 only. |

### 5.4.4 Authentication is classical in v1, and that is deliberate

Authentication uses X25519, with the tokens `es` and `se`. UMBRA does **not**
give post-quantum authentication, and the threat model says so. The group pair
key of Part 11 §11.3.3, which authenticates a group record to each member, is
classical under the same posture.

Signal and Apple reached the same conclusion in production. To forge the
authentication, an attacker needs a *contemporaneous* quantum computer at the
moment of the handshake. That is not the harvest-now-decrypt-later threat.
Post-quantum *confidentiality* and *identity-hiding* are the parts that count
for archived traffic, and this design gives the two of them.

The measured cost of the alternative decides the question. PQNoise (CCS 2022)
shows that KEM-only mutual authentication forces a **fourth flow**. At a 31.1 ms
RTT, pqXX measures 31.83 ms and XX measures 16.02 ms. At a 195.6 ms RTT, pqXX
measures 199.31 ms and XX measures 98.47 ms. UMBRA multiplies each RTT by three
onion hops, thus a fourth flight is too expensive.

The wire format carries a version byte and a reserved auth-suite field. Thus a
deployment can add a `skem`-authenticated flow without a flag day.

### 5.4.5 One-time prekeys

A one-time prekey travels inside an invitation only. The one-time invitation of
Part 4 §4.3.1 carries it in the blob. The rendezvous hello of Part 9 §9.6
carries it in the fields of §5.4.1. No relay holds a prekey pool, thus no pool
empties, and no fallback handshake exists.

- One-time prekeys are **mandatory**. **[CRY-122]** A client MUST make a fresh
  one-time prekey for each invitation that it issues.
- There is **no reusable last-resort prekey.** **[CRY-010]** A client MUST NOT
  use one one-time prekey in a second invitation. The X3DH specification
  records that the fallback makes the initial messages replayable. The fallback
  also gives the *same* derived key across runs. X3DH calls this "catastrophic
  key reuse", and a deployment survives it only because the ratchet randomizes
  the material afterward.
- Flight 1 names the prekey with `pid`, and §5.4.8 gives that field. Thus a
  responder resolves one prekey and it runs no trial. **[CRY-011]** That
  resolution MUST be constant-time with respect to the position of the prekey in
  the set of outstanding prekeys. A leak of *which* prekey a lookup touched
  breaks the construction.
- **[CRY-089]** A responder MUST erase the private half of a one-time prekey
  when it consumes that prekey. **[CRY-123]** If the user deletes an invitation
  that no party consumed, the responder MUST erase the private half of its
  prekey. Part 4 rule `IDN-127` deletes an invitation at `INVITE_TTL`, and
  CRY-123 then applies.

> *Cause.* The alternative is a pool of prekeys that a relay serves. A served
> pool needs a fetch, an enforcement of the consumption at the relay, and a
> fallback handshake for an empty pool. §5.7 records the prekey-exhaustion
> denial of service that a served pool carries. A prekey that travels inside
> its own invitation has no pool and no exhaustion. The cost is that a stranger
> reaches a Public Address through a request that the user accepts. Part 4
> §4.2.3 already makes the public layer a doorbell.

> *Cause of the prekey identifier.* Without an identifier, a responder runs
> the schedule of §5.4.8 for each outstanding prekey. A trial that stops when
> `tag1` verifies is an early exit, and it is not constant-time across the
> candidates.
>
> That trial also has no cost bound. No party authenticates flight 1 before
> the work, and Part 13 §13.2 does not gate a send. Thus one unauthenticated
> record costs a phone one ML-KEM decapsulation for each outstanding prekey.
> The identifier removes the trial and that amplification together. It costs
> 16 bytes on flight 1.

### 5.4.6 No wall-clock anywhere in the handshake

**[CRY-012]** Implementations MUST NOT use a timestamp for replay protection. The TAI64N
mechanism of WireGuard has a documented compromise-amplification failure. With
one of the two static keys, an attacker forges an initiation that carries a
maximum timestamp. That initiation **blocks all the future handshakes
permanently** for that peer. Mobile clients have unreliable clocks, and a
relay set of the project is an attractive target.

Replay protection binds to the consumption of a one-time prekey. It also binds
to a 16-byte random nonce with queue scope, which message 2 echoes. The KDF
mixes in the ephemeral contribution of the responder. **[CRY-013]** Before that step, a 0-RTT
payload MUST NOT make the final session state.

### 5.4.7 Public-key validation

**[CRY-014]** Implementations MUST reject an all-zero X25519 output. The Noise specification
discourages the rejection of an invalid public key, and that guidance leaves the
KXS-class attack reachable. A malicious initiator sends `e = 0`, which forces
`ee = 0`. The key of the responder then depends only on static-static material.
That key is the same across sessions, and the responder uses it with nonce 0.
The nonce reuse then permits a forgery.

**[CRY-015]** **UMBRA MUST NOT derive an AEAD key from static-static material alone.** **[CRY-016]** A
client MUST put an ephemeral contribution from the two parties in each key
derivation. The one-time prekey `s1` is the ephemeral contribution of the
responder in flight 1, and §5.4.5 makes that prekey mandatory.

### 5.4.8 The handshake key schedule

§5.4.2 gives the flights. This section gives the exact state, the exact KDF
steps, the exact nonce values, and the payload protection. **[CRY-048]** An implementation
MUST follow this section step by step.

**The state.** A handshake holds four values.

```
ck   [32]u8    the chaining key
h    [32]u8    the transcript hash
k    [32]u8    the current AEAD key, or the value "none"
n    u64       the AEAD counter under k
```

**The four operations.**

```
MixHash(data):
    h  <- SHA3-256( h || data )

MixKey(ikm):
    t  <- HKDF-SHA3-256( salt = ck, ikm = ikm,
                         info = "umbra/v1/handshake-ck", L = 64 )
    ck <- t[0..32]
    k  <- t[32..64]
    n  <- 0

Seal(pt):
    ct <- ChaCha20-Poly1305( key = k, nonce = 0x00000000 || BE64(n),
                             ad = h, plaintext = pt )
    n  <- n + 1
    MixHash(ct)
    return ct

Open(ct):
    pt <- ChaCha20-Poly1305-Open( key = k, nonce = 0x00000000 || BE64(n),
                                  ad = h, ciphertext = ct )
    if the tag does not verify: abort
    n  <- n + 1
    MixHash(ct)
    return pt
```

1. **[CRY-049]** An implementation MUST encode the ChaCha20-Poly1305 nonce as four zero
   bytes and then `n` in big-endian order, which gives 12 bytes. Part 6 §6.1.1
   rule 1 makes each integer of this specification big-endian.
2. **[CRY-050]** An implementation MUST set `n` to 0 at each `MixKey`. Each `MixKey` gives a
   new `k`, thus no nonce repeats under one key.
3. **[CRY-051]** An implementation MUST abort if `n` reaches 2⁶⁴ − 1.
4. **[CRY-052]** An implementation MUST `MixHash` a ciphertext after the tag check and not
   before it.
5. **[CRY-053]** An implementation MUST use `h` as the associated data of each `Seal` and each
   `Open`. Thus each flight binds the full transcript before it.
6. The counter of this section is a handshake counter under a one-use key. Part
   6 §6.4.2 rule 3 forbids a counter for the L6 nonce, and that rule names a
   different layer and a long-lived key.

**Initialization.** The two parties run these steps before flight 1.

```
ck <- SHA3-256( "umbra/v1/handshake-ck" || "UMBRA-XKhfs/v1" )
h  <- ck
k  <- none
n  <- 0
MixHash( prologue )
MixHash( s )        // the responder static X25519 public key, §5.4.1
MixHash( s1 )       // the one-time ML-KEM-768 prekey, §5.4.1 and §5.4.5

prologue = suite_version || handshake_mode
        || kem_id || sig_id || aead_id || kdf_id
        || range_i.min || range_i.max || range_r.min || range_r.max
        || address_type
```

§5.10 gives the five suite identifiers. The value `handshake_mode` is one byte.
Version 1 defines the one value `0x01`, which is `UMBRA-XKhfs` with a one-time
prekey. Part 6 §6.7 gives the two version ranges. The address type is one
byte: `0x01` for a pairwise identity of Part 4 §4.2.2, and `0x02` for a
published address of Part 4 §4.2.3. **[CRY-135]** A party MUST put that byte
in the prologue, and it MUST abort a handshake whose peer holds the other
value, because the two prologues then differ and each flight tag fails.

**Flight 1, from the initiator to the responder.** The initiator writes
`range_i` as the first two bytes of the flight, and `mode` as the third byte.
The prologue holds the three bytes, thus no step below hashes them again.

```
0.  pid          <- SHA3-256( "umbra/v1/prekey-id" || s1 )[0..16]
                                                MixHash(pid)
1.  (e,  e_sk)   <- X25519.Gen()                MixHash(e)
2.  es           <- X25519(e_sk, s)             MixKey(es)
3.  (e1, e1_sk)  <- MLKEM768.Gen()              MixHash(e1)
4.  (skem1, ss1) <- MLKEM768.Encap(s1)          MixHash(skem1)   MixKey(ss1)
5.  tag1         <- Seal( "" )                  // 16 B, the flight tag
6.  payload1     <- Seal( n_hs || app_1 )
```

**The prekey identifier.** **[CRY-084]** An initiator MUST set `pid` to the
first 16 bytes of `SHA3-256( "umbra/v1/prekey-id" || s1 )`, where `s1` is the
1 184-byte one-time prekey of §5.4.1. §5.11 holds that label.

**[CRY-085]** A responder MUST select the one-time prekey that `pid` names.
**[CRY-086]** A responder MUST abort when `pid` names no prekey that it holds.
**[CRY-087]** A responder MUST abort when `pid` names a prekey that it consumed.
**[CRY-088]** A responder MUST NOT run more than one `MLKEM768.Decap` for one
flight 1.

> *What `pid` shows, stated.* The value is a hash of a public key that the
> responder published. A party that holds the invitation bundle of §5.4.1
> computes the same value. Thus `pid` names no new fact to that party. Flight 1
> travels inside the queue end-to-end layer of
> Part 6 §6.4.2, thus a relay on the path reads ciphertext only.

The value `n_hs` is 16 bytes from the device CSPRNG, and §5.4.6 gives its
function. The value `app_1` is the application payload. Part 3 rule `NET-173`
puts the `QueueAddress` of the first queue of the initiator in it. The values
`app_2` of flight 2 and `app_3` of flight 3 are the application payloads of
those flights. Version 1 defines no content for either, and a party
sends each one empty. Thus `payload2` seals `n_hs` alone, and `payload3`
seals an empty string.
**[CRY-054]** A responder MUST NOT make the final session state from `payload1`. CRY-013
of §5.4.6 states the same rule.

**The responder side of flight 1.** The responder runs the same schedule with
`MLKEM768.Decap` in place of `MLKEM768.Encap`, and with `Open` in place of
`Seal`.

**[CRY-100]** A responder MUST fill `range_i` of the prologue from the first
two bytes of flight 1. **[CRY-101]** A responder MUST read those two bytes
before it runs `MixHash(prologue)`. **[CRY-102]** A responder MUST apply Part 6
§6.7 rule `WIR-092` to `range_i` and `range_r` before it runs `MixHash(prologue)`.
A responder that aborts under that rule sends no flight 2.

**[CRY-124]** An initiator MUST write `0x01` in the `mode` byte of flight 1.
**[CRY-125]** A responder MUST fill `handshake_mode` of the prologue from the
third byte of flight 1. **[CRY-126]** A responder MUST abort when that byte
holds a value that this section does not define. A responder that aborts under
that rule runs no `MixHash` and sends no flight 2.

**[CRY-055]** A responder MUST resolve `pid` against its outstanding prekeys
before it runs `MixHash(s1)`. **[CRY-056]** That resolution MUST be constant-time with
respect to the prekey position, and CRY-011 states that rule.
The initialization before `MixHash(s1)` does not depend on the prekey, thus a
responder computes that prefix one time.

**Flight 2, from the responder to the initiator.**

```
1.  (er, er_sk)  <- X25519.Gen()                MixHash(er)
2.  ee           <- X25519(er_sk, e)            MixKey(ee)
3.  (ekem1, ss2) <- MLKEM768.Encap(e1)          MixHash(ekem1)   MixKey(ss2)
4.  tag2         <- Seal( "" )                  // 16 B, the flight tag
5.  payload2     <- Seal( n_hs || app_2 )
```

**[CRY-057]** An initiator MUST check that the `n_hs` of flight 2 equals the `n_hs` that it
sent. **[CRY-058]** An initiator MUST abort if the two values differ.

**Flight 3, from the initiator to the responder.**

```
1.  s_ct  <- Seal( s_i )                        // 32 B key + 16 B tag = 48 B
2.  se    <- X25519(s_i_sk, er)                 MixKey(se)
3.  tag3  <- Seal( "" )                         // 16 B, the flight tag
4.  payload3 <- Seal( app_3 )
5.  Split()
```

The value `s_i` is the 32-byte static X25519 public key of the initiator. That
key is the X25519 public key of the `PairwiseIdentity_c` of §5.2 or of the
`PublicAddressKey_j`. No flight carries the ML-KEM-768 half of either, thus
a party holds the 32-byte key of its peer and no static KEM key (Part 4
§4.5). Flight 3 carries it under a key that has absorbed `ee` and `ss2`,
and §5.4.3 gives the identity-hiding grade that this order produces.

**The split.**

```
Split():
    RK     <- HKDF-SHA3-256( salt = ck, ikm = "",
                             info = "umbra/v1/ratchet-root", L = 32 )
    HK_i2r <- HKDF-SHA3-256( salt = ck, ikm = "",
                             info = "umbra/v1/header-key" || 0x01, L = 32 )
    HK_r2i <- HKDF-SHA3-256( salt = ck, ikm = "",
                             info = "umbra/v1/header-key" || 0x02, L = 32 )
```

The value `RK` is the initial root key of §5.5.1. The two header keys protect
the `hdr_ct` field of Part 6 §6.5, one for each direction. **[CRY-059]** An implementation
MUST erase `ck`, `h`, `k`, and each ephemeral private key after the split, with
the one exception of the next rule. Part 14 §14.4 gives the erasure rule. Part
7 §7.4 step 3 takes its 6-digit confirmation code from `h`, and it takes that
code before the erasure.

**The first ratchet key.** The ephemeral `er` of flight 2 is the first DH
ratchet key of the responder in §5.5.1. The initiator holds its public half
from flight 2, and the responder holds its private half. **[CRY-136]** The
responder MUST keep `er_sk` as its first DH ratchet private key until the
first DH ratchet step of §5.5.1 replaces it, and it MUST erase it at that
step. **[CRY-137]** The initiator MUST use `er` as the ratchet public key of
the responder at the start of the session. **[CRY-152]** The relay handshake
of §5.4.9 has one exception of the same kind: the last hop of a circuit MUST
keep its `er_sk` as `RelaySession_sk` under Part 3 rule `NET-285`, and it
MUST erase it when the circuit ends.

> *Cause.* The split gives `RK` and the two header keys, and the Double
> Ratchet needs an initial DH key as well. The two other candidates are the
> responder static key, which gives the first chain no forward secrecy, and
> a fresh key in a payload, which adds a field. The flight-2 ephemeral is
> fresh, both parties hold it, and the first ratchet step erases it.

**The transcript binding of CRY-009 maps onto this schedule as follows.**

| The item that CRY-009 binds | Where this schedule binds it |
| --- | --- |
| Each transmitted field | `MixHash` at each step above |
| The two AEAD flight tags | `Seal` calls `MixHash` on `tag1`, on `tag2`, and on `tag3` |
| The two static identities | `MixHash(s)` at the initialization, and `Seal(s_i)` in flight 3 |
| The version range | The prologue |
| The handshake mode | The prologue |
| The address type | The prologue |

**[CRY-060]** The test vectors of Part 6 §6.8 MUST hold one complete handshake transcript.
**[CRY-061]** That vector MUST give `ck`, `h`, and `n` after each numbered step. **[CRY-062]** That vector
MUST give `RK`, `HK_i2r`, and `HK_r2i`. **[CRY-103]** Those vectors MUST hold a
second transcript in which `range_i` is (1, 1) and `range_r` is (1, 2).
**[CRY-104]** That vector MUST assert one `h` at the two parties after flight 1.
**[CRY-127]** Those vectors MUST hold a flight 1 whose `mode` byte is `0x02`,
and the responder aborts before `MixHash(prologue)`.

> *Cause.* Flight 1 carries `range_i`, because the prologue holds it. With
> `range_i` in the prologue and in no flight, the two parties derive one `h`
> only while each party advertises the same range. An implementation that
> advertises a wider range then fails each handshake, and `WIR-093` binds a
> value that does not travel.
>
> *Cause of the mode byte.* `CRY-033` binds a handshake mode, thus a field
> carries it. One byte in flight 1 and in the
> prologue separates a later mode from this one at the first hash. §5.11
> records the PQXDH precedent, which is a confusion between a full mode and a
> reduced mode.

### 5.4.9 `UMBRA-NKhfs`, the circuit-hop handshake

Part 3 §3.4.3 builds a circuit one hop at a time, and each hop runs the
handshake of this section. The pattern is Noise `NK` with the hybrid
forward-secrecy extension of §5.4.2. The initiator is the client, and it has no
static key. The responder is a relay, and its static key `s` is the `ntor_pk`
of its `RelayDescriptor` (Part 10 §10.5.3). The handshake has two flights and
no payload. It gives the two parties one secret, `ss_hop`, and Part 3 §3.4.4
rule `NET-106` derives the hop key material from that secret.

```
Pre-message:  <- s                             (ntor_pk, from the RelayDescriptor)

(1) I -> R:   e, es, e1                        1232 B
              e      X25519 ephemeral                     32 B
              es     X25519(e, s)              -> MixKey
              e1     ML-KEM-768 ephemeral ek            1184 B
                     flight tag                              16 B

(2) R -> I:   e, ee, ekem1                     1136 B
              e      X25519 ephemeral                     32 B
              ee     X25519(e, e)              -> MixKey
              ekem1  ML-KEM-768.Encap(e1)               1088 B
                     flight tag                              16 B

Total: 2368 B
```

| Flight | Fields | Flight tag | Total |
| --- | --- | --- | --- |
| (1) | `e` 32, `e1` 1184 | 16 | 1 232 |
| (2) | `e` 32, `ekem1` 1088 | 16 | 1 136 |
| **Sum** | | | **2 368** |

**[CRY-105]** A revision MUST make the two flight rows and the sum agree. Part
3 §3.4.3 carries flight 1 in `HopHello` and flight 2 in `HopReply`, and Part 3
§3.12 quotes the sum.

**What the handshake gives.** The secret `ss_hop` absorbs `es`, `ee`, and the
ML-KEM shared secret of `ekem1`. The token `es` authenticates the relay, and
that authentication is classical under §5.4.4. The token `ee` and the ML-KEM
secret give forward secrecy, and the ML-KEM secret gives post-quantum
confidentiality. The relay learns no identity of the client, because the client
sends no static key. The identity-hiding grade of the relay is 3 under §5.4.3.
A passive attacker with the private key of `s` can confirm that `s` was used.

**The state, the operations, and the flights.** The handshake uses the state
and the four operations of §5.4.8 without a change. **[CRY-106]** An
implementation MUST apply rules `CRY-049` to `CRY-053` to this handshake. The
two parties run these steps before flight 1.

```
ck <- SHA3-256( "umbra/v1/handshake-ck" || "UMBRA-NKhfs/v1" )
h  <- ck
k  <- none
n  <- 0
MixHash( prologue )
MixHash( s )        // ntor_pk of the responder

prologue = suite_version || kem_id || sig_id || aead_id || kdf_id || relay_id
```

§5.10 gives the five suite identifiers. The value `relay_id` is the 32-byte
field of the `RelayDescriptor` that holds `s`. Version 1 has one suite, thus
this handshake carries no version range. **[CRY-107]** A revision that adds a
second suite MUST add a range field to flight 1 and to the prologue.

**Flight 1, from the client to the relay.**

```
1.  (e,  e_sk)   <- X25519.Gen()                MixHash(e)
2.  es           <- X25519(e_sk, s)             MixKey(es)
3.  (e1, e1_sk)  <- MLKEM768.Gen()              MixHash(e1)
4.  tag1         <- Seal( "" )                  // 16 B, the flight tag
```

The relay runs the same schedule with `Open` in place of `Seal`.

**Flight 2, from the relay to the client.**

```
1.  (er, er_sk)  <- X25519.Gen()                MixHash(er)
2.  ee           <- X25519(er_sk, e)            MixKey(ee)
3.  (ekem1, ss2) <- MLKEM768.Encap(e1)          MixHash(ekem1)   MixKey(ss2)
4.  tag2         <- Seal( "" )                  // 16 B, the flight tag
5.  Split()
```

The client runs the same schedule with `MLKEM768.Decap` in place of
`MLKEM768.Encap`, and with `Open` in place of `Seal`.

**The split.**

```
Split():
    ss_hop <- HKDF-SHA3-256( salt = ck, ikm = "",
                             info = "umbra/v1/onion-hop", L = 32 )
```

The label `"umbra/v1/onion-hop"` names the hop key material, and §5.11 holds
it. This split makes `ss_hop` under that label, and `NET-106` expands `ss_hop`
under the same label with the hop index. The two steps make one object type,
thus `CRY-031` permits the shared label.

**The rules.**

1. **[CRY-108]** A client MUST take `s` and `relay_id` from one
   `RelayDescriptor` that passed Part 10 rules `REL-051` and `REL-057`.
2. **[CRY-109]** A relay MUST abort when `tag1` does not verify. **[CRY-110]**
   A client MUST abort when `tag2` does not verify. **[CRY-111]** A party that
   aborts MUST NOT send a later flight of that handshake. `CRY-014` makes each
   party reject an all-zero `es` and an all-zero `ee`.
3. **[CRY-112]** A flight of this handshake MUST NOT carry a payload. The
   client has nothing to send before the hop holds a key, and a payload in
   flight 1 would be replayable.
4. **[CRY-113]** A party MUST derive the hop key material from `ss_hop` of the
   split and from no other value.
5. **[CRY-114]** An implementation MUST erase `ck`, `h`, `k`, `e_sk`, `e1_sk`,
   and `er_sk` after the split. Part 14 §14.4 gives the erasure rule.
6. **[CRY-115]** A relay MUST accept flight 1 under each `ntor_pk` that a valid
   consensus lists for that relay. A consensus is valid inside
   `CONSENSUS_VALIDITY`. A client builds from the consensus that it holds, and
   Part 10 §10.11 gives `CONSENSUS_VALIDITY`.
7. **[CRY-116]** The test vectors of Part 6 §6.8 MUST hold one complete
   `UMBRA-NKhfs` transcript. **[CRY-117]** That vector MUST give `ck`, `h`,
   and `n` after each numbered step, and it MUST give `ss_hop`.

> *Cause.* Part 3 and Part 10 name `NKhfs`, and each message crosses that
> layer. Thus this section defines the handshake to the byte. Without a
> definition, two implementations cannot interoperate at the transport layer,
> and no security argument covers that layer. A relay holds no static ML-KEM
> key (Part 10 §10.5.3). An encapsulation to such a key would add 1 088 bytes
> to flight 1. The `EXTEND` cell of Part 3 §3.4.3 would then leave bucket `B1`.

## 5.5 The ratchet

UMBRA uses three ratchets together, and mixes them through one KDF.

### 5.5.1 Classical Double Ratchet, header-encrypted

- DH ratchet: X25519. §5.4.8 gives the initial `RK`, `HK_i2r`, and `HK_r2i`,
  and rules `CRY-136` and `CRY-137` give the first ratchet key of the
  responder.
- `KDF_RK`: HKDF-SHA3-256. A DH ratchet step runs this derivation:

  ```
  t     <- HKDF-SHA3-256( salt = RK, ikm = X25519(dh_sk, dh_pk),
                          info = "umbra/v1/ratchet-root", L = 96 )
  RK    <- t[0..32]
  CK    <- t[32..64]
  NHK   <- t[64..96]        // the next header key for that direction
  ```

- `KDF_CK`: HMAC-SHA3-256 with the constants `0x01` for the message key and
  `0x02` for the chain key:

  ```
  MK    <- HMAC-SHA3-256( CK, "umbra/v1/ratchet-chain" || 0x01 )
  CK    <- HMAC-SHA3-256( CK, "umbra/v1/ratchet-chain" || 0x02 )
  ```

- **[CRY-063]** An implementation MUST use the labels above. Part 5 §5.11 holds
  `"umbra/v1/ratchet-root"`, `"umbra/v1/ratchet-chain"`, and
  `"umbra/v1/header-key"`. One HKDF invocation gives `RK`, `CK`, and `NHK`
  together. The label names that invocation, and it does not name each of the
  three outputs. Thus §5.11 rule CRY-031 holds.
- Record AEAD: ChaCha20-Poly1305 for the header and for the body. UMBRA rejects
  AES-256-CBC with HMAC explicitly. The rejection gives one primitive fewer,
  constant-time operation on each ARM target, and no separate IV derivation.
  The field names below are those of `RatchetRecord` in Part 6 §6.5.
  - The header AEAD runs under the header key `HK` of the direction. Its
    nonce is `hdr_nonce`, its associated data is `version || ctx` (5 bytes),
    and its plaintext is `dh_pk || BE32(pn) || BE32(n)` (40 bytes). The
    field `hdr_ct` is the ciphertext and then the 16-byte tag.
  - The body AEAD runs under the message key `MK` of the record. Its nonce is
    `body_nonce`, and its associated data is each byte of the record before
    `body_nonce`: `version || ctx || hdr_nonce || hdr_ct || pq_frame_len ||
    pq_frame`. Thus a braid frame cannot move to another record. The field
    `body_ct` is the ciphertext and then the 16-byte tag.
  - The sender takes `hdr_nonce` and `body_nonce` from the randomness
    function of §5.9, 12 bytes each, new for each record. A message key
    seals one body. A header key seals each header of one chain, and the
    random nonce separates them.

**[CRY-017]** **A client MUST use the header-encrypted variant of the Double Ratchet.**
Cleartext `dh`, `pn`, and `n` fields let a relay link messages into sessions and
profile the cadence of a conversation. That result defeats the full function of
pairwise queues.

### 5.5.2 Post-quantum ratchet: chunked ML-KEM braid

UMBRA adopts the SPQR and ML-KEM Braid construction of Signal (spec Revision 1,
2025-02-21, deployed 2025-10-02). It renews a post-quantum secret inside each
session on a continuing schedule.

**What one braid epoch carries.** In one direction, one epoch carries two
objects. The first object is the **new encapsulation key of the sender**. The
second object is the **encapsulation of the sender against the key that the
last completed epoch of the peer gave**. The two objects are 2 304 bytes
together:

```
ML-KEM-768 material, split:
    header      = rho (32 B) || SHA3-256(ek_vector || rho) (32 B)   =   64 B
    ek_vector   = ByteEncode12(t_hat), the vector part of ek        = 1152 B
    ct1         = c1 of the ciphertext                              =  960 B
    ct2         = c2 of the ciphertext                              =  128 B
```

FIPS 203 encodes an ML-KEM-768 encapsulation key as
`ek = ByteEncode12(t_hat) || rho`. The value `rho` is the 32-byte public seed
that expands to the matrix `A`. The value `ek_vector` is the 1 152-byte encoded
vector `t_hat`. Thus `ek_vector || rho` is `ek`, and the hash in `header` is
the `H(ek)` of FIPS 203, because that function is SHA3-256 as well. The
`header` and `ek_vector` together are 1 216 bytes, which is `ek` and its hash.

The values `ct1` and `ct2` are the two parts of the 1 088-byte ML-KEM-768
ciphertext, which FIPS 203 writes as `c1 || c2`. The part `c1` depends on `rho`
and on the encapsulation coin only. The part `c2` depends on `t_hat` as well.
The coin is secret, and §5.9 gives it.

**[CRY-093]** A sender MUST make the seed `d` of its encapsulation key with the
randomness function of §5.9. **[CRY-128]** A sender MUST NOT put `d`, `z`, or
the decapsulation key in a field of the codeword. **[CRY-138]** A sender MUST
make the ciphertext of an epoch against the encapsulation key that §5.5.5
names for that epoch, and against no other key. No field names the target.

**[CRY-091]** A receiver that rebuilt the material MUST compare
`SHA3-256(ek_vector || rho)` against the hash in `header`. **[CRY-092]** That
receiver MUST reject the braid epoch when the two values differ. The
rejection is of the epoch and not of a record. The body of the record that
carried the last chunk opened under its message key, thus the receiver
delivers that record and each later one. It takes no encapsulation key from
that epoch, and it makes no ciphertext against it. The receiver ignores a
frame with another fault in the same way, and it delivers the record of that
frame.

> *Cause.* The `header` does not hold the FIPS 203 seed `d`. The seed `d`
> fixes the decapsulation key. Thus a codeword that holds `d` publishes the
> private half of the key that it announces. A quantum adversary that holds
> the session state then reads each later `ss_pq`, and the post-quantum half
> of G5 is void.
>
> The header above holds the public seed `rho` and `H(ek)`, which is the
> header of the ML-KEM Braid of Signal. The `ek_vector` travels as coded
> data. A header that holds `d` gives a heal window of 18 records at the
> default width. The window here is 36 records, and that is the price of a
> key that stays private.
>
> A receiver cannot compute `ct1` from the header alone, because `ct1` is a
> function of the peer key and of the secret coin. The party that can compute
> `c1` from a header is the peer, as the encapsulator of its own next epoch.
> FIPS 203 derives the coin from `m` and `H(ek)`. Version 1 does not use that
> property, because §5.5.5 fixes each target by epoch number. A later version
> can add it as a pipelining step.

At the close of a PQ epoch, the two parties mix the ML-KEM shared secret into
the root key:

```
RK <- HKDF-SHA3-256( salt = RK, ikm = ss_pq,
                     info = "umbra/v1/pq-epoch" || BE32(epoch), L = 32 )
```

**[CRY-064]** An implementation MUST use the label `"umbra/v1/pq-epoch"` for that step. **[CRY-065]** An
implementation MUST NOT apply that step before it rebuilt the full ML-KEM
material from the chunks.

A **systematic Reed–Solomon erasure code** over GF(2¹⁶) encodes the four parts
above, which are 2 304 bytes together. Thus *k* chunks of *n* rebuild the
material, and the order does not matter. This code is not an optimization. It is
the mechanism that lets the PQ ratchet survive the reordering and the loss that
one-direction relay queues cause. The queues of UMBRA lose more than the direct
delivery of Signal, thus this code counts *more* here and not less.

**The code parameters.**

**[CRY-067]** An implementation MUST use GF(2¹⁶) with the primitive polynomial
`p(x) = x¹⁶ + x¹² + x³ + x + 1`, which is `0x1100B`. **[CRY-068]** An
implementation MUST use `0x0002` as the generator element.

**[CRY-069]** An implementation MUST read a field symbol as two bytes in
big-endian order. Part 6 §6.1.1 rule 1 gives that order for each integer.
**[CRY-070]** An implementation MUST use a chunk width that is a whole number of
symbols. The three widths of the table below are 32, 64, and 128 bytes, and each
one is even.

**[CRY-071]** An implementation MUST place the *k* data chunks first and in
order, because the code is systematic. **[CRY-072]** An implementation MUST
encode each symbol position across the chunks, and it MUST NOT encode along one
chunk. Thus symbol *j* of each chunk makes one codeword, and a lost chunk costs
one symbol of each codeword.

**[CRY-073]** An implementation MUST use a Vandermonde generator matrix in
systematic form. **[CRY-139]** An implementation MUST take the evaluation
points `x_i = g^i` for `i` in `0..n`, where `g` is the generator element of
`CRY-068`, build `V[i][j] = x_i^j`, and use `G = V · (V[0..k])⁻¹`. Two
implementations that take other points give two different parity chunks,
and `CRY-075` then fails.

**The codeword and the redundancy schedule.**

**[CRY-074]** An implementation MUST build one codeword over the concatenation
`header || ek_vector || ct1 || ct2`, in that order. That concatenation is 2 304
bytes. **[CRY-076]** An implementation MUST NOT code a part alone.

**[CRY-077]** An implementation MUST set the data chunk count *k* to 2 304
divided by the width *w*. **[CRY-078]** An implementation MUST set the parity
chunk count *r* to *k* divided by 8, rounded up. Thus *n* is *k* plus *r*:

| Width *w* | Data *k* | Parity *r* | Total *n* | Overhead | Heals in |
| --- | --- | --- | --- | --- | --- |
| 128 B | 18 | 3 | 21 | 16.7 % | 18 to 21 records |
| 64 B (default) | 36 | 5 | 41 | 13.9 % | 36 to 41 records |
| 32 B | 72 | 9 | 81 | 12.5 % | 72 to 81 records |

Each width divides 2 304 exactly, thus no part of the material needs padding.
The Overhead column is *r* divided by *k*. The heal window is *k* records when
no chunk is lost, and it is *n* records when *r* chunks are lost.

**[CRY-079]** A receiver MUST rebuild the material when it holds any *k*
positions of the *n*. **[CRY-080]** A receiver MUST NOT wait for a chunk of a
specific index. **[CRY-097]** A receiver MAY discard a later chunk of a
position that it holds.

**[CRY-081]** A sender MUST set the `index` field of Part 6 §6.5 to the position
of the chunk in the codeword, and that position counts from zero.
**[CRY-082]** A sender MUST set `kind` of a data chunk to the part that holds
the first byte of that chunk. **[CRY-129]** A sender MUST set `kind` of a
chunk at index *k* or above to the parity value. Part 6 §6.5 gives that value.
The `kind` field is a receiver optimization, and it is not an input to the
code.

> *Where each part starts.* At the default width of 64 bytes the four parts
> start at the positions 0, 1, 19, and 34. The parity chunks are the positions
> 36 to 40. At the width of 32 bytes the parts start at the positions 0, 2,
> 38, and 68. The parity chunks are 72 to 80. At the width of 128 bytes the
> `header` is the first half of position 0. The parts then start at the
> positions 0, 0, 9, and 17, and the parity chunks are 18 to 20.

> *The cause of the rate.* Part 3 §3.7 measures about 5 % loss on a deployed
> relay-chained network. A parity of *r* over *k*, which is 12.5 % or more,
> absorbs that rate with margin. At the default width that cost is 5 chunks of
> 71 bytes, which is 355 bytes for each epoch.
>
> The ARQ of Part 3 §3.7 recovers a lost record separately. This code covers the
> residual, which is a chunk that arrives after the epoch needs it, or a chunk
> that the ARQ has not yet recovered. The code turns a wait into a rebuild.
>
> **[CRY-075]** Two implementations MUST produce byte-identical chunks for one
> material and one schedule. Part 14 §14.5 gives the cross-backend rule that
> covers that requirement. **[CRY-083]** The test suite MUST hold a vector for
> each of the three widths, and each vector MUST hold a loss pattern that drops
> *r* chunks.

**The chunk size is adaptive:**

| Condition | Chunk `w` | Chunks/epoch | Heals in | Cost for each message | `B0` text |
| --- | --- | --- | --- | --- | --- |
| Active conversation, unmetered | 128 B | 21 | 18 to 21 records | 135 B | 91 B |
| Default | 64 B | 41 | 36 to 41 records | 71 B | 155 B |
| Metered / roaming | 32 B | 81 | 72 to 81 records | 39 B | 187 B |

The PQ braid frame is 7 bytes plus the chunk width (Part 6 §6.5). Thus the width
128 costs 135 bytes, the width 64 costs 71 bytes, and the width 32 costs 39
bytes. The width 128 gives 91 bytes of `B0` text, the width 64 gives 155 bytes,
and the width 32 gives 187 bytes. **[CRY-018]** A client MUST select the chunk width so that
the record fits the smallest bucket that holds the message. **[CRY-019]** If no permitted
width gives a fit, the client MUST send the record with `pq_frame_len = 0`. **[CRY-020]** The
client MUST then send the chunk on a later record.

**[CRY-021]** **UMBRA MUST NOT use the retransmit-until-acknowledged strategy of Apple PQ3.**
A conversation is unbalanced when a phone or a linked desktop is offline for
hours, and that condition is normal for UMBRA. In such a conversation, that
strategy costs 48 680 expected bytes to reach post-compromise security. The
chunked design costs 10 010 bytes, thus the penalty is 4.9× (eprint 2025/078,
Eurocrypt 2025).

**[CRY-022]** **UMBRA MUST NOT make future KEM keypairs in advance.** Signal measured that
parallel epoch generation heals faster but collects unused decapsulation keys.
Those keys expose more messages to one device seizure, which is the incorrect
trade under adversary A6 of Part 2.

### 5.5.3 Rekey cadence

The client starts a new PQ epoch after **`N = 100` records OR `T = 7` days**.
The first limit to occur applies. The sending client measures the two limits
from the first chunk of its last epoch, and it computes them fully on the
client side.

The hard bound of 7 days protects the low-volume users. Without that bound, a
user that sends two messages each month does not heal. The client-side
computation also stops a hostile relay from a delay of the post-compromise
healing through a withholding of the delivery.

**The incomplete epoch.** An epoch of a sender is **incomplete** from its first
chunk. It becomes **complete** when the sender holds a ciphertext of the peer
against the encapsulation key of that epoch. §5.5.5 uses the word complete in
the same sense. Five rules govern the incomplete epoch.

1. **[CRY-130]** A sender MUST carry one chunk of its incomplete epoch on each
   `RatchetRecord`, except where CRY-019 applies.
2. **[CRY-131]** After the chunk at index *n* − 1, a sender MUST continue with
   the chunk at index 0. Thus a lost chunk returns on a later record, and
   CRY-097 lets the receiver discard a duplicate.
3. **[CRY-132]** A client MUST NOT start a new epoch while an epoch of its own
   is incomplete.
4. **[CRY-140]** If a limit occurs during an incomplete epoch, the client MUST
   start the next epoch at the first DH chain start of §5.5.1 after the epoch
   is complete. §5.5.5 gives the cause.
5. **[CRY-134]** The test vectors of Part 6 §6.8 MUST hold a schedule in which
   `T` occurs during an incomplete epoch. In that schedule the epoch continues
   under one epoch number.

> *Cause.* A limit `T` that starts a new epoch during an incomplete epoch
> stops a quiet conversation from healing. A user that sends a few records
> each month then completes no epoch of 41 chunks, because each 7 days the
> timer starts a new one.
> Apple PQ3 completes a quiet rekey with encrypted delivery receipts, and
> CRY-021 bans the retransmission that PQ3 pairs with them. The rules above
> carry a chunk on each record, and a receipt of Part 6 §6.6.9 is a record.
> Part 3 §3.6 rule `NET-064` carries a queued receipt in a cover slot. Thus a
> quiet conversation completes an epoch on the records that it sends in any
> case.

### 5.5.4 Skipped-message keys — hard limits, not advice

The Double Ratchet specification gives a mitigation as a non-normative
suggestion, which is "e.g. 1000". UMBRA makes the limits enforced constants,
because the store is an allocation that an attacker controls and that a sender
can reach:

| Constant | Value |
| --- | --- |
| `MAX_SKIP` (per chain) | 1 000 |
| `MAX_STORED` (per session) | 2 000 |
| `MAX_BYTES` (per session) | 80 KiB, which is 1 077 keys of 76 bytes |
| `SKIP_TTL` | **45 days**, which equals `MSG_TTL` |
| `MAX_STORED_DEVICE` (global) | 200 000 keys / 8 MiB |

**The two session limits.** A session holds one skipped key as 76 bytes: the
header key of 32 bytes, the message key of 32 bytes, the index of 4 bytes,
and the time of 8 bytes. `MAX_BYTES` of 80 KiB is 81 920 bytes, thus it
holds 1 077 such keys. That count is below `MAX_STORED`, thus `MAX_BYTES` is
the limit that binds, and a session holds at most 1 077 skipped keys.
`MAX_STORED` stays as the count bound of a stored form that a later
version makes smaller, and `CRY-153` applies the lower of the two.

The device-global limit exists to stop a device with many held sessions from
an allocation of the per-session maximum by each of its peers. A group holds no
pairwise session among its members (Part 11 §11.3), thus the contact count and
the device-set size bound the session count. The 8 MiB of `MAX_STORED_DEVICE`
are 8 388 608 bytes, thus they hold 110 376 keys of 76 bytes. That count is
below 200 000, thus the bytes are the limit that binds. A device that passes
the limit after a skip drops the oldest skipped keys first, whatever session
holds them, in the manner of `CRY-153`.

**[CRY-098]** `SKIP_TTL` MUST NOT be below the `MSG_TTL` of Part 3 §3.2.4.
**[CRY-099]** A revision MUST hold the two values equal, and a revision MUST NOT
raise `MSG_TTL` alone.

> *Cause.* A relay holds an undelivered message for 45 days. With a `SKIP_TTL`
> of 14 days, a receiver that skipped the key of that message discards that
> key on day 14, thus the message arrives and it does not decrypt. U9 of Part 2 §2.4 sets the undecryptable rate
> below 1 in 10⁵, and that window is 31 days wide on the ordinary path. Part 12
> §12.7.1 does not hold the same relation for `CHUNK_TTL`. It sets a chunk
> at 14 days, below `MSG_TTL`, on purpose: a record that arrives after its
> chunks left opens, and its file does not. Part 2 §2.4 holds that trade in
> its table, and rules `ATT-050` and `ATT-051` give the relation that Part 12
> does keep.
>
> **This is a trade, and Part 2 §2.4 requires the text to state it.** A skipped
> key lives 45 days and not 14. A seized device therefore gives A6 a
> wider set of message keys. `MAX_SKIP`, `MAX_STORED`, `MAX_BYTES`, and
> `MAX_STORED_DEVICE` bound the count of that set, and only the age differs.
> Part 15 §15.3 records the residual.

**[CRY-153]** A session MUST drop each skipped key older than `SKIP_TTL` at
each skip, and a skip that would pass `MAX_STORED` or `MAX_BYTES` MUST drop the
oldest keys first. A session that refused a skip at the limit would open no
later record of that peer, and the contact would end.

`MAX_SKIP` bounds the keys that one chain leaves in two cases. Inside a chain,
a session refuses a record whose `n` is more than `MAX_SKIP` above the next
position of that chain, and the refusal holds for that record alone. At a DH
ratchet step, the `pn` of the header names the length of the chain that ends.
If `pn` is more than `MAX_SKIP` above the next position of that chain, the
session stores the first `MAX_SKIP` keys of the chain, stores no key past
them, and takes the step. A refusal at the step would repeat at each later
chain, because each of them carries that `pn`, and the direction would end.
The peer alone writes a header that opens, thus `MAX_SKIP` keys stay the cost
of one step.

The age of a skipped key is a duration of Part 1 §1.9, and it starts when the
session stores the key. At a clock movement the session starts the age of each
key that it holds again (Part 1 rule `SCP-019`). Thus a movement of the device
clock deletes no key (rule `SCP-021`) and adds one `SKIP_TTL` at most to the
life of a key.

**[CRY-023]** An implementation MUST store the skipped keys encrypted at rest under `K_store`.
The specification records that these keys are a long-tailed hole in the forward
secrecy. An attacker that recorded the dropped ciphertexts, and later
compromises the device, decrypts those ciphertexts.

### 5.5.5 The interlock of the two strands

Each party runs one strand of epochs. The two strands interlock under the
four rules below, thus the two parties derive one root key sequence with no
field that names a target, an epoch, or a mix.

1. **The target is implicit.** **[CRY-141]** The initiator's epoch `e` MUST
   encapsulate to the responder's key of epoch `e − 1`. **[CRY-142]** The
   responder's epoch `e` MUST encapsulate to the initiator's key of epoch `e`.
   Thus the strands alternate: the initiator's epoch 1, the responder's epoch
   1, the initiator's epoch 2, and so on, and each epoch needs the one before
   it.
2. **The first epoch.** **[CRY-143]** The initiator's epoch 1 MUST carry
   1 088 zero bytes in the place of `ct1 || ct2`, because no responder key
   exists yet. **[CRY-144]** The responder MUST start its epoch 1 at the first
   chain start after it rebuilt the initiator's epoch 1, and it MUST carry no
   braid frame before that.
3. **An epoch advances at a chain start only.** **[CRY-145]** A party MUST
   start an epoch at the first record of a DH sending chain and at no other
   record. Thus every record of one chain carries one epoch number, and any
   record of the chain shows it. **[CRY-146]** The first record of a chain
   MUST carry a braid frame; rule `CRY-019` does not apply to that record, and
   a client selects a bucket that holds the frame.
4. **The mix.** Let party P own epoch `e`, and let `ss_e` be the shared secret
   of the ciphertext that the peer made against the key of that epoch.
   **[CRY-147]** P MUST apply the mix of `CRY-064` for epoch `e` immediately
   before it derives the sending chain of its first DH ratchet step whose
   chain carries an epoch above `e`. **[CRY-148]** The peer MUST apply the
   same mix immediately before it derives the receiving chain of the step that
   the same chain starts, which it recognizes by the epoch number in the
   frame of any record of that chain. **[CRY-149]** A party MUST retain
   `ss_e` from the moment it computes it, by encapsulation or by
   decapsulation, until the mix consumes it.

An epoch of P is **complete** when P rebuilt the peer's codeword that carries
the ciphertext against the key of that epoch (§5.5.3). Under rule 1 that
codeword also carries the peer's next key, thus a party that completed an
epoch holds the target of its next one.

> *Cause.* The codeword does not show which key a ciphertext targets, when a
> shared secret enters the root key, or how the first epoch starts with no
> peer key. A receiver that guesses a target runs implicit rejection on the
> wrong key and desynchronizes the root key without an error. The rules above make the target a function of the epoch
> number, tie every advance to a DH chain start so that one record reveals
> the epoch, and bind each mix to a DH step that both parties identify from
> the same chain. The test vectors of Part 6 §6.8 hold the schedule of
> `CRY-134` under these rules.

## 5.6 Steady-state overhead budget

| Layer | Component | Bytes |
| --- | --- | --- |
| L3 | Cell: `circ_id` 16 and `tag` 16 | 32 |
| L3 | Cell command byte and padding marker | 2 |
| L5 | Command header (Part 6 §6.4) | 84 |
| L5 | `seq` on a `MSG` | 4 |
| L6 | Queue end-to-end record (Part 6 §6.4.2) | 32 |
| L7 | Ratchet record less the body, with the 4-byte `ctx` | 86 |
| L7 | PQ braid frame at the default 64-byte chunk | 71 |
| L7 | Body AEAD tag | 16 |
| L8 | `AppMessage` header (Part 6 §6.6) | 30 |
| **Total** | **From the cell to the text, at the default chunk** | **357** |

The L6 row holds 1 byte of version, a 12-byte nonce, and a 16-byte tag. It also
holds the 2-byte true length that Part 6 §6.4.2 rule 5 puts inside the
ciphertext. Part 6 §6.9 gives the same figure.

Bucket `B0` is 512 bytes. Thus `B0` carries 155 bytes of text at the default
chunk, 187 bytes at the 32-byte chunk, and 226 bytes with no chunk. A text above
that limit goes to bucket `B1`.

## 5.7 Deniability posture

UMBRA targets **offline (participation) deniability**. It claims no more than
that.

**What UMBRA gives:**

- A party can forge a transcript between two parties with their public keys
  only. No message carries an individual signature under a long-term key. Queue
  commands use a deniable authenticator (Part 3 §3.2.3), thus the logs of a
  seized relay hold no proof of authorship. This property follows at no cost
  from implicit authentication with a KEM or a DH only, and with unsigned
  prekeys. A group record of Part 11 §11.3 carries one pairwise MAC tag for
  each member and no signature, thus each receiver can forge its own tag and
  the record proves authorship to no third party.

**What UMBRA does not give:**

- **Online deniability.** A party that speaks to you can convince a third party
  in real time, *while* that party speaks to you. Online deniability needs
  DAKEZ-style ring signatures of about 464 B at about 1 ms classically, and no
  post-quantum instantiation of those signatures is QROM-secure. The alternative
  is the LWE construction of K-Waay, with prekeys of 22–24 KB and a documented
  prekey-exhaustion DoS.
- **Post-quantum authentication** (§5.4.4).

The threat model states the limit in plain language. A transcript proves nothing
to a court. But a party that speaks to you at this moment can convince a third
party in real time.

The DAKEZ literature gives a coercion frame that is important here. KCI
resistance is **not** an unqualified benefit for a contact handshake. A user can
claim to cooperate with a judge. That user can refuse to show a long-term secret
with good cause, because that disclosure exposes the user to key-compromise
impersonation.

## 5.8 Group keys

Part 11 gives the details. This section gives the cryptographic rule:

**[CRY-024]** **Group content MUST have post-quantum protection in transit.**
At rest, `K_store` of §5.2 covers each record.
SimpleX excludes groups and files from its PQ layer explicitly. Archived group
traffic is the harvest-now-decrypt-later target with the highest value. The v1
scope of UMBRA holds groups of 2 to 500 members.

The mechanism is cheap. A group epoch key `K_e` travels to each member in an
`UMBRA-KEM` slot of the epoch-key record (Part 11 §11.4), or at a join over the
PQ-protected pairwise channel of the inviting admin. The slot chain of Part 11
§11.3.1 derives the per-record key from `K_e`, thus each group record inherits
post-quantum confidentiality **without a KEM header for each record**. The
pair key and the tag vector of Part 11 §11.3.3 give attribution, and that
authentication is classical under §5.4.4. The codebase holds one KEM and one
AEAD for this, and it does not hold a second ratchet. A file-encryption key
travels inside a group record, thus it inherits the same protection.

> *Cause.* The alternative moves a symmetric sender key to each member over
> the PQ ratchet of a pairwise channel, and a group of N members then holds
> N × (N − 1) such channels. The group queue of Part 11 §11.2 holds no pairwise channel
> among members, thus the epoch key needs a carrier of its own, and the
> `UMBRA-KEM` of §5.3 is that carrier.

## 5.9 Randomness

**[CRY-025]** Implementations MUST implement RFC 8937 randomness hardening
**unconditionally**:

```
randomness(context) = HMAC-SHA3-256( K_rng_harden,
                                     CSPRNG(32) || context || call || BE32(block) )
```

`call` is 16 bytes that no other draw under `K_rng_harden` carries. Those
bytes are the number of the draw in the process as a `u64`, then the wall time in
nanoseconds as a `u64`, each big-endian. `block` counts the 32-byte blocks of
one draw from zero. A platform generator that gives the same 32 bytes twice
thus gives two different values (RFC 8937 §4, `tag2`). No value of this
function goes on the wire as it is, thus the layout is local to an
implementation.

An implementation uses this function for each KEM encapsulation coin, each
ephemeral key, and each signature nonce.

This function is about fifteen lines of code, and it removes a full class of
catastrophic failure. ML-KEM encapsulation shows raw RNG output. The security
considerations of draft-ietf-tls-mlkem-09 were amended for this cause. The text
says that "the disclosure of output(s) of an insecure random number generator
... can be used in an attack to compromise the state of the insecure RNG
itself." This function is also the substantive answer of UMBRA to the objection
of SimpleX to ML-KEM.

**[CRY-026]** Implementations MUST enforce one encapsulation for each ephemeral key **at the
type level**. In Rust, `encapsulate` consumes `self`.

## 5.10 Crypto-agility, done cheaply

Each algorithm is a wire identifier that the two parties negotiate, behind an
explicit version byte. This holds although v1 offers one of each:

```
suite_version   u8      = 0x01
kem_id          u16     = 0x0001  (X25519 + ML-KEM-768)
sig_id          u16     = 0x0001  (ML-DSA-65)
aead_id         u16     = 0x0001  (ChaCha20-Poly1305)
kdf_id          u16     = 0x0001  (HKDF-SHA3-256)
```

**There is one suite. There is no pure-PQ codepoint and no classical-only
codepoint.** An offer of the two codepoints is a downgrade surface, and UMBRA
has no FIPS-validation cause to want a pure mode. The IETF spent three Working
Group Last Calls and did not reach a consensus that pure ML-KEM in TLS gives a
benefit. The blocking objection says that pure ML-KEM "discards compositional
security under component compromise", and that objection describes the adversary
of UMBRA. ANSSI and BSI each make hybridization *mandatory*.

The identifiers are present to let a deployment answer an ML-KEM break with a
shipment of HQC, and without a break in the wire format. That is the full cost
of agility, and a deployment pays it one time.

## 5.11 Domain separation

**[CRY-027]** Each KDF invocation and each signature MUST carry a label prefix. The label
names the object type and its lifetime:

```
"umbra/v1/rng-harden"
"umbra/v1/storage"
"umbra/v1/device-set"
"umbra/v1/pairwise"
"umbra/v1/public-address"
"umbra/v1/handle-key"
"umbra/v1/invite-blob"
"umbra/v1/profile-blob"
"umbra/v1/kem-combine"
"umbra/v1/handshake-ck"
"umbra/v1/prekey-id"
"umbra/v1/onion-hop"
"umbra/v1/onion-hop-update"
"umbra/v1/ratchet-root"
"umbra/v1/ratchet-chain"
"umbra/v1/header-key"
"umbra/v1/pq-epoch"
"umbra/v1/cmd-auth"
"umbra/v1/queue-e2e"
"umbra/v1/ntf"
"umbra/v1/backup-handle"
"umbra/v1/backup-write"
"umbra/v1/directory-root"
"umbra/v1/directory-keyset"
"umbra/v1/relay-descriptor"
"umbra/v1/relay-layer"
"umbra/v1/relay-family"
"umbra/v1/relayref"
"umbra/v1/link-receipt"
"umbra/v1/report-queue"
"umbra/v1/link-fault-seal"
"umbra/v1/relay-hello"
"umbra/v1/receipt-query"
"umbra/v1/stat-query"
"umbra/v1/link-removal"
"umbra/v1/measurer-cert"
"umbra/v1/measurer-open"
"umbra/v1/device-roster"
"umbra/v1/device-claim"
"umbra/v1/group-grant"
"umbra/v1/group-moderation"
"umbra/v1/group-slot"
"umbra/v1/group-slot-next"
"umbra/v1/group-record-key"
"umbra/v1/group-record"
"umbra/v1/group-read"
"umbra/v1/group-write"
"umbra/v1/group-pair"
"umbra/v1/group-kem"
"umbra/v1/group-tag"
"umbra/v1/group-epoch-slot"
"umbra/v1/group-epoch-tag"
"umbra/v1/group-rekey"
"umbra/v1/mention"
"umbra/v1/handle-renew"
"umbra/v1/file-manifest"
"umbra/v1/file-commit"
"umbra/v1/chunk-read"
"umbra/v1/avatar-color"
"umbra/v1/session-tag"
"umbra/v1/session-resume"
"umbra/v1/dead-channel"
"umbra/v1/chunk-place"
"umbra/v1/backup-read"
"umbra/v1/backup-key"
"umbra/v1/tree-head"
"umbra/v1/tree-head-keyset"
"umbra/v1/pow-challenge"
"umbra/v1/pow"
"umbra/v1/hello-verifier"
"umbra/v1/hello-seed"
"umbra/v1/sas-commit"
"umbra/v1/sas"
"umbra/v1/record-key"
"umbra/v1/at-rest-wrap"
"umbra/v1/table-mac"
"umbra/v1/sync-seed"
"umbra/v1/link-offer"
"umbra/v1/link-hello"
"umbra/v1/link-transcript"
"umbra/v1/link-code"
"umbra/v1/link-provision"
"umbra/v1/handle-write"
"umbra/v1/address-index"
"umbra/v1/hello"
"umbra/v1/log-commit"
"umbra/v1/issuer-key"
"umbra/v1/lookup-pow"
"umbra/v1/issue-pow"
"umbra/v1/row-id"
"umbra/v1/rotate-jitter"
"umbra/v1/backup-salt"
"umbra/v1/handle-blob"
"umbra/v1/issuer-rsa"
"umbra/v1/lookup-pow-verifier"
"umbra/v1/issue-pow-verifier"
"umbra/v1/relay-ntf"
"umbra/v1/ndr"
"umbra/v1/directory"
"umbra/v1/client-rng"
"umbra/v1/quota-holder"
"umbra/v1/ndr-removal"
"umbra/v1/renewal-guard"
```

> *The cause of the last nine labels.* The two verifier labels take the
> `verifier_id` of Part 9 `DIS-165` and Part 13 `ABU-109` apart from the seed
> of the same proof of work, as `hello-seed` and `hello-verifier` are apart
> (`CRY-031`). `relay-ntf`, `ndr`, and `directory` derive the key pair of a
> relay notifier, of the NDR gateway, and of the directory gateway from the
> seed of its operator. `client-rng` keys the hardening of the device
> CSPRNG of `CRY-025` in a client runtime before its store opens.
> `quota-holder` names the holder of a chunk quota at a relay (Part 12).
> `ndr-removal` gives the removal secret of the next registration of a
> handle from the one before it, thus each registration takes a fresh secret
> and a lost answer can be sent again (Part 8 `NTF-124`). `renewal-guard`
> is the prefix of the commitment of Part 3 rule `NET-354`. Thus no other
> hash of this specification over a 32-byte value opens a renewal guard.
>
> *The construction under six labels.* No other part gives these, thus
> this note gives each one in full.
>
> - `"umbra/v1/relay-ntf"`, `"umbra/v1/ndr"`, and `"umbra/v1/directory"` each
>   derive one `UMBRA-KEM` key pair from a 32-byte seed. With `label` as one
>   of the three: `x = SHA3-256(label || "/x" || seed)` is the X25519 seed,
>   and `d = SHA3-256(label || "/d" || seed)` and
>   `z = SHA3-256(label || "/z" || seed)` are the two ML-KEM-768 seeds of
>   FIPS 203 key generation, in that order. The seed of a queue relay is its
>   static secret (Part 8 rule `NTF-129`). The seed of the NDR gateway
>   and of the directory gateway is a secret of its operator.
> - `"umbra/v1/client-rng"` is the `context` of `randomness(context)` of
>   `CRY-025` for each draw of a client runtime, in each state of its store.
> - `"umbra/v1/quota-holder"` names the holder of an upload quota at a relay:
>   `holder = SHA3-256(label || kind || value)`. For an admission by token,
>   `kind` is the ASCII string `token` and `value` is the nonce of the token.
>   For an admission by proof of work, `kind` is the ASCII string `pow` and
>   `value` is the seed and then the nonce of the solution.
> - `"umbra/v1/handle-blob"` is the salt of the blob challenge of Part 9
>   §9.9.3, which that section gives.

**The list above is closed.** **[CRY-028]** An implementation MUST NOT use a label that this
list does not hold. **[CRY-029]** A revision that needs a new label MUST add that label to
this list. **[CRY-030]** That revision MUST give the cause. §5.1 closes the
primitive register in the same manner.

> *The cause of the five link labels.* Part 7 §7.4 links a device over
> handle-addressed chunks. The offer and the hello each need a slot of their
> own, the transcript and the code each need a hash of their own, and the
> provision needs a slot and a seal key that only the two devices derive.

> *The cause of `"umbra/v1/issuer-rsa"`.* An issuer of the cross-relay token
> of Part 13 §13.3.1 derives the RSA key of each epoch from one secret seed
> under this label and the epoch, thus a restart of the issuer finds the key
> that the log already holds. The primes come from
> `HMAC-SHA3-256(HMAC-SHA3-256(seed, label || BE32(epoch)), BE64(counter))`,
> and no other derivation takes that input.

> *The cause of `"umbra/v1/handle-blob"`.* Part 9 rule `DIS-175` writes the
> profile blob under a challenge of its own. Its answer binds the blob, as the
> write answer binds the entry, and a label of its own keeps a blob answer from
> passing as a write answer or a renewal answer.

> *The cause of the two blob labels.* Part 4 §4.3.1 derives the key of the
> invitation blob from a link fragment. Part 9 §9.3.1 derives the key of the
> profile blob from a handle and a fragment. The two derivations take different
> input and protect different objects, thus each one needs a label of its own.
> Without a label the two keys share one KDF namespace with each derivation
> above.

> *The cause of the mention label and the manifest label.* Part 6 §6.6.5
> derives a mention identifier under `"umbra/v1/mention"`, and Part 12 §12.3.4
> derives a manifest key under `"umbra/v1/file-manifest"`.
>
> *The cause of the eleven group-queue labels.* A group uses the group queue
> of Part 11 and no sender key, thus the list holds no
> `"umbra/v1/sender-key"` and no `"umbra/v1/group-member"` (the member
> identifier is a member index, which no KDF makes). Part 11 §11.3.1
> derives the first slot key of an epoch from `K_e` under
> `"umbra/v1/group-slot"`, each later slot key from the previous one under
> `"umbra/v1/group-slot-next"`, and the record key of a slot under
> `"umbra/v1/group-record-key"`; each of the three lives for one epoch or one
> slot. `"umbra/v1/group-record"` is the associated data of a group record and
> not a KDF label; it binds the ciphertext to the group, the epoch, and the
> slot. Part 11 §11.3.1 derives the reader credential and the writer credential
> of a group queue from `K_e` under `"umbra/v1/group-read"` and
> `"umbra/v1/group-write"`, one pair for each epoch. Part 11 §11.3.3 derives
> the pair key and the KEM key of a member from `GroupRosterSeed_g` under
> `"umbra/v1/group-pair"` and `"umbra/v1/group-kem"`, for the life of the
> membership, and it derives the pair MAC key of two members and computes each
> tag under `"umbra/v1/group-tag"`. Part 11 §11.4.2 derives the slot key of an
> epoch-key record under `"umbra/v1/group-epoch-slot"`, and it computes the
> rotator's tag inside a slot under `"umbra/v1/group-epoch-tag"`; each lives
> for one rotation. Part 11 §11.12 signs a `RekeyRecord` under
> `"umbra/v1/group-rekey"`, and it lives for one re-key. Each label names one
> object type, and CRY-031 holds.
>
> *The cause of seven more labels.* Part 5 §5.4.8 hashes a
> one-time prekey under `"umbra/v1/prekey-id"`. Part 10 §10.5.4 computes the
> relay layer under `"umbra/v1/relay-layer"`, and Part 10 §10.6.3 signs a family
> certificate under `"umbra/v1/relay-family"`. Part 10 §10.4.2 signs a link
> receipt under `"umbra/v1/link-receipt"`, and Part 10 §10.3.1 signs a measurer
> certificate under `"umbra/v1/measurer-cert"`. Part 7 §7.3.1 signs an ownership
> claim record under `"umbra/v1/device-claim"`. Part 9 §9.9.1 derives a
> renewal challenge under `"umbra/v1/handle-renew"`. Each one names one object
> type, and CRY-031 keeps them apart.
>
> *The cause of the measurer-open label.* Part 10 §10.3.1 signs the open of
> a measurement session under `"umbra/v1/measurer-open"`, with the key of the
> measurer. The certificate of that key is another object under another key,
> thus `CRY-031` gives the open a label of its own.
>
> *The cause of the two wire labels.* Part 6 §6.5 derives the session tag of
> a ratchet record from the initial root key under `"umbra/v1/session-tag"`.
> Part 6 §6.2.3 computes the authenticator of a session resume under
> `"umbra/v1/session-resume"`. Its input is the label, the session
> identifier, the resume count, and the two frame counts of the record.
> Each label names one object type.

> *The cause of the four storage labels.* Part 3 §3.2.6 extracts the
> dead-channel secret under `"umbra/v1/dead-channel"`, and its three expansions
> differ in the first info byte. Part 12 §12.4.2 ranks a relay for a
> handle-addressed chunk under `"umbra/v1/chunk-place"`. Part 4 §4.7.2 derives
> the read credential of the backup root under `"umbra/v1/backup-read"` and its
> content key under `"umbra/v1/backup-key"`. The two backup labels sit beside
> `"umbra/v1/backup-handle"` and `"umbra/v1/backup-write"`, and each of the four
> names one object type.

> *The cause of the two tree-head labels.* Part 9 §9.5.2 signs a
> `SignedTreeHead` under `"umbra/v1/tree-head"` and a `LogKeySet` under
> `"umbra/v1/tree-head-keyset"`. The two objects follow the `DirectoryRoot`
> pattern of Part 10 §10.5.2. A shared label with that pattern would put a
> tree head and a directory root under one signing domain. CRY-031 forbids that.

> *The cause of the two proof-of-work labels.* Part 13 §13.8 signs a
> `PowChallenge` under `"umbra/v1/pow-challenge"`, and it builds the Equi-X
> challenge string under `"umbra/v1/pow"`. The first names a signature and the
> second names a hash input, which are two object types.

> *The cause of the two verification labels.* Part 4 §4.5.2 commits to a
> nonce under `"umbra/v1/sas-commit"`, and it derives the six-digit code
> under `"umbra/v1/sas"`. The first names a hash of one nonce and the second
> names a hash of two keys and two nonces, which are two object types.

> *The cause of the two hello labels.* Part 13 §13.4 derives the proof-of-work
> challenge of a hello from the published key of the addressee, because the
> addressee publishes no `PowChallenge`. The label `"umbra/v1/hello-verifier"`
> makes the `verifier_id`, and `"umbra/v1/hello-seed"` makes the `seed`. The
> two values enter the challenge string at two positions, thus CRY-031 keeps
> them apart.

> *The cause of the hello label.* Part 9 §9.6 rule `DIS-143` encapsulates the
> hello to the entry key and seals it under a key that only that encapsulation
> gives. The label `"umbra/v1/hello"` keeps that key apart from the challenge
> keys of §9.9.1 and §9.9.3, which take the same shared-secret shape.

> *The cause of the row label.* Part 14 §14.6.4 derives the key of the
> surrogate row identifiers from `K_store` under `"umbra/v1/row-id"`. The
> table MAC key and each record key derive from the same master key, thus the
> surrogate key needs a label of its own.

> *The cause of the two log labels.* Part 9 §9.5.1 commits a leaf of the
> transparency log to its entry under `"umbra/v1/log-commit"`, with the
> opening as the HMAC key. Part 13 §13.5 names the label input of an issuer
> key under `"umbra/v1/issuer-key"`, which keeps that input apart from a
> handle and an address in the one VOPRF of Part 9 §9.4.

> *The cause of the hop-update label.* Part 3 §3.4.4 rule `NET-204` replaces
> the key set of the hop 3 layer after each cell under
> `"umbra/v1/onion-hop-update"`. The label `"umbra/v1/onion-hop"` derives the
> first key set from `ss_hop`, and the update derives the next key set from
> the current one. The two derivations take different input, thus CRY-031
> gives them two labels.

> *The cause of the handle-key label.* Part 9 §9.3 names the handle key
> `HK_pub`. Part 4 §4.2.4 derives that key from the root identity with a
> rotation counter, thus a restored client recovers the private half. The label separates the handle key from
> `"umbra/v1/public-address"`, and a directory crawl does not link the two.

> *The cause of the relay-layer label.* The label
> `"umbra/v1/relay-descriptor"` names the descriptor signature. CRY-031
> forbids two object types under one label, thus the layer assignment has a
> label of its own. Part 10 §10.5.3 gives the leaf hash and the node hash no
> label at all.

> *The cause of six labels of Part 7, Part 11, and Part 12.* Part 7 §7.3.1 signs a
> `Roster` under `"umbra/v1/device-roster"`. Part 11 §11.9.2 signs a granting
> epoch under `"umbra/v1/group-grant"`, and Part 11 §11.9.6 signs a moderation
> epoch under `"umbra/v1/group-moderation"`. Part 12 §12.3.2 hashes a relay
> identity under `"umbra/v1/relayref"`. Part 12 §12.3.1 commits an attachment key
> under `"umbra/v1/file-commit"`, and Part 12 §12.3.3 derives a chunk read
> credential under `"umbra/v1/chunk-read"`. Each of the six names one object
> type.

> *The cause of the three platform-surface labels.* Part 14 §14.6.4 derives a
> record key under `"umbra/v1/record-key"`, and `"umbra/v1/storage"` names the
> master key above it. Part 7 §7.7 derives a sync channel seed after a
> revocation under `"umbra/v1/sync-seed"`, and `"umbra/v1/device-set"` names
> the membership key. Part 9 §9.9.3 derives a write authorization under
> `"umbra/v1/handle-write"`, and `"umbra/v1/handle-renew"` names the renewal.
> Each of the three names one object type.

> *The cause of the two at-rest labels.* Part 14 §14.6.4 derives the wrap key
> of `K_store` from the secure-element secret under `"umbra/v1/at-rest-wrap"`.
> Part 4 §4.6 derives the table MAC key from `K_store` under
> `"umbra/v1/table-mac"`. The first sits above `K_store` and the second sits
> below it, thus CRY-031 keeps them apart.

> *The cause of the address label.* Part 9 §9.3.3 puts an address
> entry in the tree of the handle directory under one VOPRF key. The label
> `"umbra/v1/address-index"` in front of the address keeps that label space
> apart from the handle label space.

One label names one object type. **[CRY-031]** Two object types MUST NOT share one label.
Part 11 §11.9.2 signs a granting epoch of a group, and Part 11 §11.9.6 signs a
moderation epoch of a group. The two objects use two labels of their own.

**[CRY-032]** The label `"umbra/v1/group-roster"` is not used, and an
implementation MUST NOT add it. Part 11 §11.9.1 makes `GroupRosterSeed_g` from the device
CSPRNG. That value does not come from a KDF, thus it needs no derivation
label. The pair key and the KEM key that Part 11 §11.3.3 derives from
`GroupRosterSeed_g` use `"umbra/v1/group-pair"` and `"umbra/v1/group-kem"`. **[CRY-066]** A group signature MUST use
`"umbra/v1/group-grant"` or `"umbra/v1/group-moderation"`, and it MUST NOT use a
label that names a seed.

PQXDH did not domain-separate its signed ephemeral KEM public key from its
semi-static KEM public key. That omission made a trivial key-confusion attack,
and the two published analyses had to model around it (Fiedler and Günther, PKC
2025). Bhargavan and others separately marked the risk of a confusion between
X3DH-full and PQXDH-reduced, for the same cause. Domain separation is free, and
there is no cause for an error here.

**[CRY-033]** Implementations MUST bind the **full handshake transcript** into the KDF. The
transcript holds the two identity keys, the KEM encapsulation key, the KEM
ciphertext, the protocol version, the handshake mode, and the address type. The
address type is pairwise or published. This binding is the mechanism that lets
the security argument survive a future KEM change.

## 5.12 Explicitly out of scope

**Physical fault injection and power or EM side channels are outside the v1
threat model.** "Mind the Faulty Keccak" (eprint 2024/1522) breaks ML-KEM and
ML-DSA at each phase with low-cost EM injection, at a success rate of 89.5 % on
ARM. Single-bit faults are also sufficient against Kyber (SAC 2025). But the
rejection-sampling countermeasure costs 2–3 retries on a decapsulation with no
fault, and masking adds more cost. That is a large KISS expenditure against an
adversary that has the phone of the user on a probe station. Part 2 §A6 puts
that adversary out of scope.

Two cheap defenses ARE mandatory, because they cost almost nothing:

- **Verify-after-sign** for ML-DSA.
- **Re-encapsulation checking** in the FO transform.
