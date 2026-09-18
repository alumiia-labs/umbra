# UMBRA Protocol Specification — Part 15: Implementation Requirements and Assurance

**Status:** Draft
**Version:** 0.2.0-draft
**Date:** 2026-09-11

---

## 15.1 Workspace layout

```
umbra/
├── crates/
│   ├── umbra-crypto/     primitives, UMBRA-KEM, handshake, ratchet   → no in-workspace deps
│   ├── umbra-wire/       fixed-layout codecs, padding, buckets       → umbra-crypto
│   ├── umbra-onion/      cell construction, per-hop UIV+, replay     → umbra-wire
│   ├── umbra-queue/      queue commands, subscriptions, ARQ          → umbra-wire
│   ├── umbra-transport/  TLS/QUIC, session layer, pluggable wire     → umbra-wire
│   ├── umbra-core/       orchestration, state machine, storage       → all above
│   ├── umbra-ffi/        UniFFI surface, coarse-grained only         → umbra-core
│   ├── umbra-web/        wasm-bindgen surface, browser socket, store → umbra-core
│   ├── umbra-relay/      relay server binary                         → queue, onion
│   └── umbra-simd/       the ONLY crate permitted `unsafe`           → nothing
├── spec/
├── tests/vectors/        vendored KATs + PROVENANCE.md
└── scripts/
```

The dependency direction is strictly downward. A cycle is a build failure.

> *Cause.* An earlier draft held an `umbra-nse` crate for the notification
> extension of a platform that this revision defers, and §15.6.3 records what
> an iOS revision revisits.

## 15.2 Dependency policy

**UMBRA holds three dependency registers. Two registers carry a numeric cap, and
the third register carries a rule.**

| Register | Content | Cap |
| --- | --- | --- |
| **R1** message core | The six primitives of Part 5 §5.1 | **40** transitive crates on a target triple |
| **R2** auxiliary | The nine auxiliary primitives of Part 5 §5.1 | **30** more transitive crates above the R1 graph |
| **R3** platform | Transport, storage, async runtime, FFI, and build tooling | No number in v1. §15.2.3 gives the rule |

The combined cap for R1 and R2 is **70** transitive crates. **[IMP-002]** A change MUST name
the register that it charges. **[IMP-003]** A claim that a change costs no crate MUST name
that register too.

> *The cause for two caps, and not for one raised cap.* One cap over a graph
> near 70 hides which register grew. The value of the message-core cap is that
> one person reads the whole R1 graph in a day. A single raised number retires
> that property, and it makes each auxiliary addition look free. Two caps keep
> the audit unit small, and they put each new standard against a limit that a
> reader sees.

### 15.2.1 Register R1: the message core

The trial figure is **37 crates** on `aarch64-linux-android`. It is 35 crates
on `no_std` and on `wasm32`. That graph is
about 65k LOC, and it has no open OSV or RustSec advisory at the pinned
versions.

**The figure of 37 comes from a trial resolution outside this repository.** The
reference implementation holds no workspace `Cargo.toml` file at the date of
this draft. Thus 37 is not a measurement of this repository. §15.2.4 names the
party that measures the count, and it names the time.

| Crate | Configuration |
| --- | --- |
| `ml-kem` 0.3 | `default-features = false` |
| `ml-dsa` 0.1 | `default-features = false`, `features = ["rand_core"]`. **[IMP-004]** An implementation **MUST** turn the `pkcs8` default off. If it stays on, the build inherits `der`, `spki`, `pkcs8`, and `const-oid` |
| `x25519-dalek` 3 | `default-features = false`, `features = ["static_secrets"]` |
| `chacha20poly1305` 0.11 | `default-features = false` |
| `aes` + `polyval` | for the onion UIV+ layer only |
| `sha3` 0.11 | pin to 0.11 to match `ml-kem` and to prevent a duplicate `sha3` 0.12 |
| `hkdf` 0.13, `hmac` 0.13 | generic over `Sha3_256` |
| `subtle` 2, `zeroize` 1 | |

### 15.2.2 Register R2: the auxiliary primitives

Part 5 §5.1 registers nine auxiliary primitives. The table below gives the
likely pure-Rust crate for each one. **Each count in the last column is an
estimate. No party has measured these numbers.** A count is the number of
crates that the row adds above the R1 graph. A crate that two rows share counts
one time.

| # | Primitive | Likely pure-Rust crate | New crates (estimate) |
| --- | --- | --- | --- |
| AUX-1 | Blind RSA-2048 | `blind-rsa-signatures` over `rsa` 0.10 | **14–18** |
| AUX-2 | ristretto255 with SHA512 | `curve25519-dalek`, which R1 holds already, plus `sha2` | **1–3** |
| AUX-3 | ECVRF-Edwards25519-SHA512-TAI | a vendored module, and no crate (Part 9 §9.11) | **0–1** |
| AUX-4 | Argon2id | `argon2`, `blake2`, `base64ct` | **3–5** |
| AUX-5 | A keyed function in the secure element | a platform adapter, and no crate. Android uses the HMAC-SHA256 key of StrongBox | **0** |
| AUX-6 | HPKE under OHTTP | in-workspace, over `UMBRA-KEM` | **0–2** |
| AUX-7 | XChaCha20-Poly1305 | `chacha20poly1305`, which R1 holds already | **0** |
| AUX-8 | Equi-X | `equix` and `hashx`, with the JIT feature off | **4–6** |
| AUX-9 | Additive secret sharing with Laplace noise | in-workspace, PrivEx-S2 | **0–1** |
| AUX-10 | The `UsernameCaseMapped` profile of RFC 8265 (Part 9 §9.3.2) | `precis-profiles`, `precis-core`, `unicode-normalization`, `tinyvec`; the table generator `precis-tools` and its parsers are build-only | **4** |

The low column sums to 26, and the high column sums to 40. Thus the estimate for
R1 and R2 together is 63 to 77 crates, against the combined cap of 70.
`DEPENDENCIES.md` holds the measured count, which is below both estimates. AUX-1
alone takes half of the R2 cap.

The cap of 30 is a real limit, and four decisions make it reachable. Each
decision is already in another Part:

1. **Write the HPKE and OHTTP layer in the workspace.** Part 8 §8.2.3 puts
   `UMBRA-KEM` in HPKE, and the `hpke` crate does not hold `UMBRA-KEM`. The
   `hpke`, `ohttp`, and `bhttp` crates together cost an estimated 10 to 18
   crates.
2. **Vendor the ECVRF module.** Part 9 §9.11 states this decision. The full
   `akd` crate costs an estimated 10 crates or more.
3. **Turn the JIT feature of `equix` off.** That feature carries `unsafe`, and
   §15.3 forbids `unsafe` outside `umbra-simd`.
4. **Write the PrivEx-S2 construction directly.** Part 10 §10.8 states this
   decision, and it prohibits a `draft-ietf-ppm-dap` dependency.

**[IMP-005]** If the measured R2 count is more than 30, the maintainers MUST NOT tag a
release. **[IMP-006]** Those maintainers MUST first remove a primitive, or MUST first revise
this section with a written cause. §15.2.5 gives the removal candidates.

### 15.2.3 Register R3: the platform subsystems

R3 holds the transport stack, the storage stack, the async runtime, the UniFFI
surface, and the build tooling. §15.2.8 names the transport stack. No party has
measured R3, and this section gives it no number. A cap on an unmeasured graph
is a guess. A guess in this position is the error that §15.2.4 corrects, thus
this section does not write one.

One rule applies until the first measurement. **[IMP-007]** **One subsystem in
R3 MUST NOT add more transitive crates than its row in the table below.** No
single platform part costs more than the whole message core. Part 3 §3.8
rejects a WebRTC stack under this rule. Each cap is an estimate until §15.2.4
measures the subsystem, and `IMP-009` sets the measured cap.

| Subsystem | Cap (estimate) |
| --- | --- |
| Transport, §15.2.8 | 40 |
| Storage, §15.6.4 | 25 |
| Async runtime | 20 |
| UniFFI surface, §15.6.1 | 15 |
| Web surface, §15.7 | 15 |
| Build tooling | No cap, because a build tool is not linked |

**[IMP-008]** At the first measurement, the maintainers MUST publish the R3 count. **[IMP-009]** Those
maintainers MUST set the R3 cap in the same change.

### 15.2.4 Measurement: the party, the trigger, and the artifact

**This section publishes no measured count of this repository.** This repository
holds no `Cargo.toml` file and no `crates/` directory, thus no party measures a
transitive crate count today. Each figure outside the R1 table is an estimate,
and this section marks each one as an estimate.

**The maintainers of the reference implementation measure the three counts.**
The trigger is the first commit that adds the workspace `Cargo.toml` file. **[IMP-010]** That
commit MUST also add a `DEPENDENCIES.md` file at the root of the repository. A
build script generates that file, and no person maintains it by hand.
**[IMP-011]** `DEPENDENCIES.md` MUST hold five items:

1. The R1 count, the R2 count, and the R3 count, for each target triple.
2. The crate list of each register, with the version of each crate.
3. The cap of each register, and the result PASS or FAIL against that cap.
4. The commit hash and the date of the measurement.
5. The `rustc` version that §15.5.1 pins, and the exact `cargo` version.

The three target triples are `aarch64-linux-android`,
`x86_64-unknown-linux-gnu`, and `wasm32-unknown-unknown`.

**[IMP-012]** The maintainers MUST publish `DEPENDENCIES.md` before the first tagged release.
**[IMP-013]** The maintainers MUST NOT tag a release without that file. **[IMP-014]** A CI job MUST generate
that file again at each commit. **[IMP-015]** That job MUST fail the build on a difference
against the committed file.

### 15.2.5 Removal candidates

The rule of this project is to prefer a removal to an addition. **This section
removes no primitive.** Part 5 §5.1 holds the two registers, and a removal needs
a change to that section. The table below gives each candidate and the cost of
its removal.

| Candidate | Saving (estimate) | The cost of the removal |
| --- | --- | --- |
| **AUX-1** blind RSA-2048 | 14–18 crates | This is the largest saving, and it is the most expensive one. Part 14 §14.3.1 gives a third-party relay offline verification with the public key of the nonprofit alone. Without AUX-1, that relay verifies the first-party token of §14.3.2. That token is privately verifiable, thus the relay needs a shared secret with the issuer. A self-hosted operator then has to trust the issuer, and the self-hosting position of Part 14 fails |
| **AUX-8** Equi-X | 4–6 crates | Part 14 §14.8 loses the surge valve at a relay under queue pressure. Argon2id (AUX-4) holds the puzzle in place of Equi-X. But Argon2id gives no asymmetry against an ASIC and against a GPU. It also costs more RAM on the slowest supported phone |
| **AUX-4** Argon2id | 3–5 crates | §15.6.4 loses the memory-hard step of the at-rest construction. The secure-element entanglement stays, thus a brute force attack still runs on the seized device. But the cost for each try falls from about 3 s to the cost of one secure-element operation. Of the three primitive removals with a real saving, this one costs the most protection |
| **AUX-3** ECVRF | 0–1 crate | Part 9 §9.11 vendors the module already, thus the saving is close to zero. The removal costs the blind directory index of Part 9 §9.5. This candidate gives no saving that pays for its cost |
| Runtime SIMD detection | 2 crates | This is not a primitive. §15.3 gives the full analysis. The removal drops `cpufeatures` and `libc`. It gives a uniform R1 graph of 35 crates on the three target triples |

An estimated **10 to 18 crates** come off R2 with no primitive removal. That
saving needs the four decisions of §15.2.2. Take those four decisions first, and
examine a primitive removal after them.

### 15.2.6 Crates that UMBRA does not adopt

- **`libcrux`** — its formal-verification claim does not cover the ARM64 and
  NEON backend. That backend is 792 LOC, and it is 100 % admitted. It "needs
  proofs" for the runtime safety and for the correctness. UMBRA ships Android
  first, thus the target is ARM64. If a deployment needs a
  verified ML-KEM later, that deployment forces the portable backend on mobile.
- **`liboqs-rust`** — the maintainers state that it is not for production use.
  Its only public audit excluded the algorithm implementations deliberately.
- **`ring`** as the rustls provider — it gives no `X25519MLKEM768` key share
  and no ECH, thus it cannot send the ClientHello of Part 3 §3.8. An earlier
  draft called the crate unmaintained under RUSTSEC-2025-0007. That advisory
  is withdrawn, and the cause above stands alone.
- **`boring` and `boring2`** — BoringSSL shapes a ClientHello as Chrome, and
  Part 3 §3.8 does not need that shape. The cost is a C++ toolchain in the
  Android NDK, above the C toolchain of `aws-lc-rs`.
- **`openssl`** — it links a C library that UMBRA holds for no other function.
  §15.6.4 rejects the SQLCipher build on the same cause.
- **`akd`** — Part 9 §9.11 takes the ECVRF module of that crate, and not the
  crate. The crate carries SEEMless, Parakeet, and a MySQL shape that an opt-in
  directory does not need.
- **`ohttp` and `bhttp`** — §15.2.2 decision 1 gives the cause.

### 15.2.7 Enforcement

- `cargo-deny` with an explicit allowlist and `multiple-versions = "warn"`,
  with a `skip` list in which each entry carries a date and a cause. A CI job
  fails the build on a skip entry older than 90 days. Each of R1 and R2
  carries a separate allowlist. Thus a new transitive crate **fails the
  build**, and a duplicate version is a dated debt and not a silent one.
- The repository holds `Cargo.lock`.
- A CI job makes an OSV and RustSec query for each crate and version. `cargo
  audit` alone is not sufficient.
- A CI job generates `DEPENDENCIES.md` again, and compares it against the
  committed file. A difference **fails the build**.
- **A cooling-off window of 14 to 30 days** for an update that is not a security
  update. The release builds are network-isolated, from a committed `cargo
  vendor` tree.

> In August 2026 the `arrayref`, `internment`, and `append-only-vec` compromise
> injected a typosquatted `proc-macro1`. The `build.rs` of that crate executed a
> remote payload. Those releases were live for **86–107 minutes**. A cooling-off
> window with offline vendored builds gives UMBRA immunity to that attack.
> `cargo-vet` does not, because the median audit lag is 29 days and 40 % of the
> RustSec fix-versions get no audit.

### 15.2.8 The transport stack

R3 holds the transport stack, and §15.2.3 gives it no number. This section
names the crates, thus an implementer can build the L1 layer of Part 3 §3.8.

| Function | Crate | Note |
| --- | --- | --- |
| TLS 1.3 | `rustls` 0.23 | with `aws-lc-rs` as the provider, and the `tls12` feature off |
| TLS provider | `aws-lc-rs` 1 | the default provider of `rustls`. It holds `X25519MLKEM768`, and it holds the HPKE that ECH needs |
| QUIC | `quinn` 0.11 | over the same `rustls` configuration |
| HTTP/1.1 Upgrade, and the WebSocket frame | in-workspace | Part 6 §6.2.1 puts one capsule in one frame, and no crate is needed |
| TLS on the runtime | `tokio-rustls` 0.26 | the adapter between `rustls` and `tokio`, and no other function |
| CA roots | `webpki-roots` 1 | the Mozilla root set, for the certificate check of Part 3 rule `NET-282` |
| Async runtime | `tokio` 1 | the `rt-multi-thread`, `net`, `time`, `sync`, `io-util`, and `macros` features only |

- **[IMP-066]** The L1 stack MUST use `rustls` with the `aws-lc-rs` provider.
  **[IMP-067]** An implementation MUST NOT use the `ring` provider for L1.
  **[IMP-068]** The `rustls` build MUST turn the `tls12` feature off.
- **[IMP-069]** A build MUST pin an `aws-lc-rs` version that ships the
  bindings for `aarch64-linux-android`. Thus the build needs no bindgen on the
  v1 mobile target, and CMake stays.
- The transport stack of this table has no wasm32 build, and the web client
  of §15.7 needs none. The browser gives the TLS stack and the WebSocket
  frame, and the `umbra-web` crate puts that socket behind the transport
  trait. `tokio` does not build for the browser, thus the web surface runs
  the core on the event loop of the browser through `wasm-bindgen-futures`.

The count of this table is an estimate until §15.2.4 measures it, and
`IMP-007` bounds it at 40 transitive crates. A relay operator with a FIPS
requirement selects the `fips` feature of the same provider crate, and the
client build does not.

> *Cause.* An earlier draft rejected `aws-lc-rs` because its advantage was
> FIPS validation, which UMBRA does not need. That statement inverted the
> advantage. The crate is the default provider of `rustls`, and it is the
> provider that holds the post-quantum key share and the HPKE of ECH. The C
> toolchain is the cost, and that cost buys the L1 flight of Part 3 §3.8. With
> both providers rejected, no client could open a connection, and Part 3
> §3.12 priced a handshake that no stack sent.

## 15.3 Unsafe and panic policy

- Each crate root that UMBRA writes carries `#![forbid(unsafe_code)]`. The
  workspace also carries `unsafe_code = "forbid"` in `[workspace.lints.rust]`.
  This is the real enforcement. It is a compiler error and not a suggestion.
- The one exception is `umbra-simd`. That crate uses `#![deny(unsafe_code)]`
  with explicit `#[allow]` sites. **[IMP-016]** That crate MUST give byte-identical output to
  the portable path.
- Examine a full removal of runtime SIMD detection on mobile. That removal drops
  `cpufeatures` and `libc`. It removes 672 `unsafe` tokens, and it gives a
  uniform graph of 35 crates across the three targets. Keep the detection only if
  a benchmark on a mid-range Android device shows that the portable ML-KEM-768
  is too slow. That benchmark does not show this, because ML-KEM-768 takes
  71–104 µs on a Cortex-A76.
- No `unwrap()`, no `expect()`, and no index that can panic, on data that a
  parser produced or that an attacker can influence.

## 15.4 Secret handling

- Each secret is a newtype with `ZeroizeOnDrop`. Each secret has **no** `Debug`,
  `Display`, `Serialize`, or `Clone`, unless a written cause permits one.
- Prefer heap storage in a `Box`. The guidance of `zeroize` itself warns about
  move semantics and about stack spills.
- A security-critical pair is one unit at the type level. A keypair is one type,
  and it is not two parameters. The `ed25519-dalek` CVE-2022-50237 permitted the
  full extraction of a private key from two signatures. The cause was an API
  that let a caller give a public key that did not match. The layered identity
  of UMBRA is the exact shape where such a mismatch is easy to write.
- `encapsulate` consumes `self`.
- **[IMP-017]** **Key material, a passphrase, and message plaintext MUST NOT be a Kotlin
  `String` or `ByteArray`.** Each of these is an opaque UniFFI handle. The one
  exception is passphrase entry. Take a `CharArray` and not a `String`, because
  a `String` is immutable and the JVM can intern it. Copy the array into Rust
  immediately, and then overwrite the array.

## 15.5 Assurance

### 15.5.1 Constant time — three layers

No one tool is sufficient. Trail of Bits measured that Valgrind detects
Clangover but **does not detect** KyberSlash. Trail of Bits also measured that
the `dudect` results were not reproducible across machines.

1. **Valgrind and ctgrind secret-tainting against the release binary**, for each
   target triple, at each commit. This layer finds the Clangover class, which is
   a branch that the compiler inserts.
2. **A source-level ban** on `/`, on `%`, and on a secret-indexed access, in a
   function that touches key material. This layer finds the KyberSlash class,
   which is a variable-time instruction that layer 1 provably does not find.
3. **`dudect-bencher` each night. It is a signal, and it is not a gate.**

The web client of §15.7 runs code that the browser compiles, thus layer 1 and
layer 3 measure the native binary only, and layer 2 is the one layer that
binds the web client. Part 16 §16.3 holds the row.

**The toolchain is part of the cryptographic TCB.** Pin the exact `rustc`
version, the target triples, the opt-level, and the codegen-units for the
release builds. Run layer 1 again at each change to one of these.

LLVM has defeated hand-written constant-time Rust in shipped code two times. The
first case was the `jns` branch on a mask in `curve25519-dalek`
(RUSTSEC-2024-0344 and CVE-2024-58262). The second case was Clangover. In the
two cases the source did not change.

### 15.5.2 Test vectors and differential testing

- **[IMP-034]** The repository MUST vendor the NIST ACVP and CAVP corpora and the C2SP
  `testvectors_v1` corpus at `tests/vectors/`. **[IMP-035]** The repository MUST hold a
  `tests/vectors/PROVENANCE.md` file that records the upstream commit of each
  corpus. **[IMP-036]** A test MUST NOT fetch a vector at test time.

  **This repository holds no corpus today.** It holds the specification only,
  and `tests/vectors/` is empty. That path is frozen, thus the first commit that
  adds a corpus also runs the unfreeze procedure. §15.1 gives the target layout,
  and the crates of that layout do not exist today either.
- A test cross-tests each primitive against one independent implementation, **on
  the two endiannesses**.
- **Cross-backend byte-equality is a CI invariant.** **[IMP-019]** The portable build, the
  AVX2 build, and the NEON build MUST serialize each cryptographic object
  identically, at each commit.
- A canonical re-encode check runs on each parsed signature and on each parsed
  ciphertext.
- Prefer a one-shot ML-KEM API over an incremental or stateful API.

> Four of the thirteen reported vulnerabilities in libcrux were errors in the
> specification or in the proof. Formal verification structurally cannot find
> such an error. A cross-backend endianness bug in unverified libcrux code
> caused real decryption failures in the post-quantum ratchet of Signal, across
> libsignal v0.76.3 to v0.86.9.

### 15.5.3 Fuzzing and bounded model checking

- `cargo-fuzz` with a structured input from `arbitrary`, for each wire parser.
  Prefer the `fuzz_mutator!` mutation method over pure `Arbitrary` generation.
- `proptest` for the algebraic round-trip properties. Those properties are
  encode and decode, encrypt and decrypt, and ratchet advance and recover.
- **Kani** for panic-freedom and overflow-freedom. The scope is the wire
  parsers, the sequence and counter arithmetic, and the ratchet state
  transitions.

Fuzzing and bounded model checking are complements and not substitutes. Kani
found an encoding-boundary bug in s2n-quic in **20 seconds**. 16.7 M fuzzing
iterations did not find that bug.

### 15.5.4 Formal verification — scope it honestly

**Kani is the only formal-methods investment of UMBRA for v1.** The budget is 2
to 6 engineer-weeks. s2n-quic runs 102 harnesses in 23 minutes of CI.

UMBRA **rejects Verus, Creusot, Prusti, and hax for v1**. Verus measures about 5
proof-lines for each implementation-line. At that rate, the verification of a
protocol core is a commitment of multiple engineer-years. libcrux spent that
effort and reached only 58.4 % checked coverage.

**[IMP-020]** **An implementation MUST hold a `SOUNDNESS.md` file.** The build system
generates that file, and no person maintains it by hand. For each property and
each target triple, it states that the property is PROVED, TESTED, or ASSUMED.
For PROVED it names the tool and the exact coverage. For TESTED it names the
vectors. This practice is the cheapest method to separate credible assurance
from an unsupported claim, and the users of libcrux paid for its absence.

## 15.6 Platform delivery

### 15.6.1 FFI

UMBRA uses **UniFFI 0.32.x**, with a deliberately narrow surface:

```
init(config) -> Handle

// Plaintext never crosses as ByteArray. The platform builds a Draft on the
// Rust side, writes into it, and sends the handle.
new_draft(handle, conv) -> Draft
draft_set_text(draft, CharArray)          // Android: CharArray, not String
draft_attach(draft, FileRef)
send_draft(handle, Draft) -> MsgId
cancel_send(handle, MsgId)

// A received message is a handle. The platform reads it into a view that
// the renderer owns for the frame, and does not copy it into a String.
next_event(handle) -> Event               // Event carries a MsgRef, not bytes
msg_render(MsgRef, Sink)

lock()
unlock(CharArray)                         // 15.4 gives the passphrase exception
```

Each network, ratchet, queue, and onion function stays on the Rust side.

The web client of §15.7 crosses no UniFFI surface. The `umbra-web` crate gives
it a `wasm-bindgen` surface of the same shape, and `IMP-037` to `IMP-039`
bind that surface in the same manner, with a JavaScript string and an
`ArrayBuffer` in the place of the Kotlin types, and with the passphrase
exception of §15.4.

**[IMP-037]** The FFI surface MUST NOT carry message plaintext, key material, or
a passphrase as a Kotlin `ByteArray` or a Kotlin `String`. §15.4 rule `IMP-017`
gives that rule, and this section gives the surface that obeys it.

**[IMP-038]** `Draft` and `MsgRef` MUST be opaque UniFFI object handles.
**[IMP-039]** An implementation MUST zeroize the buffer behind a `Draft` when
that draft is dropped, and it MUST do that whether the send succeeded or failed.

> *Cause.* An earlier draft of this section gave `send(handle, conv, bytes)`.
> UniFFI maps a `bytes` parameter onto a Kotlin `ByteArray`, thus that one
> signature broke `IMP-017` at the one point where each message passes. A
> `ByteArray` on the JVM heap moves under a compacting collector, thus no party
> overwrites each copy of it.
>
> The passphrase keeps its stated exception, because a keyboard gives characters
> and no platform lets Rust own that buffer. `CharArray` is mutable, thus the
> caller overwrites it after the copy. §15.4 gives that rule already.

**Nothing crosses the FFI for each packet.** The direction from Rust to the
foreign language is one long-lived event stream. One thread drains that stream,
and that thread calls `AttachCurrentThread` one time, through the
`on_thread_start` hook of Tokio. The Kotlin path runs over JNA. JNA attaches and
detaches a JVM thread at each callback, and the documentation of UniFFI itself
calls that "a heavy operation."

Pin the exact UniFFI version. Treat an increment as a change that blocks a
release. Run a full Kotlin regression after an increment. UniFFI is before 1.0, and it shipped breaking changes across 0.29 to
0.32.

### 15.6.2 Android

- Pin NDK **r28 or newer** in CI. Thus the 16 KB page alignment is automatic.
- Ship `arm64-v8a` only for v1.
- CI has two hard gates. **[IMP-021]** `llvm-objdump -p libumbra.so | grep LOAD` MUST show
  `align 2**14` or higher. **[IMP-022]** `zipalign -v -c -P 16 4` MUST pass.
- If a build has to use NDK r27 or older, inject `-Wl,-z,max-page-size=16384
  -Wl,-z,common-page-size=16384` through RUSTFLAGS explicitly. `cargo-ndk` does
  not do this for you.
- The UI uses Kotlin with Jetpack Compose.

### 15.6.3 Deferred platforms

iOS and a native desktop shell are outside the v1 scope. Android and the web
client of §15.7 are the v1 client platforms, and the web client serves the
desktop in v1. The core keeps the UniFFI annotations and holds no platform
assumption, thus a later platform adds a shell and no core change. An iOS
revision has to revisit four items: the notification extension of Part 8, the
secure-element entanglement of §15.6.4, the file protection and the backup
exclusion of §15.6.6, and the reproducible-build attestation of a static
library under §15.8. A native desktop shell reuses the extension bundle of
§15.7 in a thin native window, with a code signature of its platform.

### 15.6.4 Storage and keys

**At rest**, UMBRA follows the shipped construction of Molly with three
changes. The secure element computes a keyed function. The AEAD is
**XChaCha20-Poly1305**, and not CBC with HMAC. The
record layer below encrypts each record on its own.

- Argon2id, calibrated to **about 3 s for each try** on a mid-range device,
  turns the passphrase into the 32-byte value `a`.
- The secure element entangles `a` with a key that it holds. The device makes
  that key **in StrongBox**, and the key never leaves it. Thus a brute force attack has to run on the seized device, at the speed
  of the secure element.
- The result wraps the storage master key `K_store` of Part 5 §5.2.
- The client holds `K_store` in RAM after the unlock. Thus the client pays the
  3-second cost at each unlock, and not at each launch.
- The client wipes `K_store` from RAM at a lock. The auto-lock default is 15 to
  30 minutes of idle time.

**The entanglement.** StrongBox holds an HMAC-SHA256 key. The platform adapter
computes the secure-element step, and the core reads one 32-byte secret `S`.

```
a        <- Argon2id( passphrase, salt_pw )                 // 32 bytes

S        <- HMAC-SHA256( k_se, "umbra/v1/at-rest-wrap" || a )
                                                            // k_se in StrongBox

K_wrap   <- HKDF-SHA3-256( salt = a, ikm = S,
                           info = "umbra/v1/at-rest-wrap", L = 32 )
nonce_w  <- 24 bytes from the CSPRNG, stored beside the wrap
wrapped  <- XChaCha20-Poly1305( K_wrap, nonce_w, K_store,
                                ad = "umbra/v1/at-rest-wrap" )
```

Each try of a passphrase needs one secure-element operation, because `S` is a
function of `a` and of a key that the attacker cannot read. Part 5 §5.11 holds
the label.

- **[IMP-061]** A client MUST derive `K_wrap` with the block above, and with no
  other input. **[IMP-062]** A client MUST make the secure-element key with no
  export path.
- **[IMP-065]** A client MUST NOT demand a user authentication for each use of
  the secure-element key. The passphrase is the authentication of this step.

> *Cause.* An earlier draft gave this block a second branch for the secure
> element of a platform that this revision defers, and §15.6.3 records that an
> iOS revision revisits this step.

**The database** uses `rusqlite` with the `bundled` feature, which is plain
SQLite. The application adds XChaCha20-Poly1305 for each record, with a key for
each record from HKDF-SHA3-256. UMBRA does **not** use
`bundled-sqlcipher-vendored-openssl`. That feature brings in OpenSSL to give
cryptography that UMBRA links for other functions.

Encryption at the application level leaks structure. Compensate for that leak.
Move each metadata-sensitive column into the encrypted blob. Those columns are
the timestamps, the conversation identifiers, and the contact identifiers. Index
only on keyed-hash surrogate IDs.

**The record key.** `K_store` is the at-rest master key of Part 5 §5.2, and
the passphrase construction above wraps it. `table_id` is the table identifier,
and `row_id` is the keyed-hash surrogate ID above.

```
record_salt <- 16 bytes from the CSPRNG, stored beside the record
K_rec       <- HKDF-SHA3-256( salt = record_salt, ikm = K_store,
                              info = "umbra/v1/record-key" || table_id || row_id,
                              L = 32 )
nonce       <- 24 bytes from the CSPRNG, stored beside the record
ct || tag   <- XChaCha20-Poly1305( K_rec, nonce, plaintext,
                                   ad = table_id || row_id )
```

- **[IMP-023]** A client MUST derive the record key with the input set of the
  block above, and with no other input. Part 5 §5.11 holds the label.
  **[IMP-040]** A client MUST make a fresh `record_salt` and a fresh `nonce`
  from the CSPRNG at each write of a record.
- Part 4 rule `IDN-029` puts `table_id` and `row_id` in the associated data.
  Thus a party cannot move a record from one row into another row. Part 4 §4.6
  states the table MAC that rests on this binding.
- **[IMP-041]** A client that discards a record key under Part 7 MUST overwrite
  `record_salt` with zero bytes. Rules `DEV-099` and `DEV-210` of Part 7
  discard that key. Thus no party derives the key again from `K_store`.
- A **deletion batch** is a tombstone batch of Part 7 §7.5.6, a retention purge
  of §7.5.2, or a timer expiry of §7.5.8. **[IMP-042]** A client
  MUST open the database with `PRAGMA secure_delete=ON`. **[IMP-043]** After a
  client applies a deletion batch, it MUST run `PRAGMA wal_checkpoint(TRUNCATE)`.
  Part 6 §6.8 rule `WIR-356` gives the test that checks the raw file.

> *Cause.* An earlier draft derived the record key from `K_store`, the table
> identifier, and the row identifier only. Part 7 rule `DEV-099` told a device
> to discard that key. A key that a client derives again from a master key that
> it still holds is not discarded. The random salt beside the record makes the
> key of one record a value that an overwrite destroys. `secure_delete`
> overwrites a freed page with zero bytes. The checkpoint moves each frame out
> of the write-ahead log and truncates that log. Without the two, a deleted
> record stays in a free page or in the log until SQLite reuses the space.

**[IMP-024]** A client MUST store the keyed form of `msg_id` that Part 6 §6.6 gives. **[IMP-025]** A client
MUST NOT store the raw value. Part 6 §6.6 gives the derivation and the cause.

**A hardware keystore is a wrapping oracle and a keyed-function oracle. It is
not a home for the keys of UMBRA.** StrongBox supports RSA-2048, AES, ECDSA and
ECDH P-256, HMAC-SHA256, and 3DES only. It has no X25519 and no ML-KEM.

**Set the file protection explicitly:**

- Set `setUnlockedDeviceRequired(true)` and
  `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG |
  AUTH_DEVICE_CREDENTIAL)` on the wrapping key. Set `setIsStrongBoxBacked(true)`
  when `android.hardware.strongbox_keystore` is present. If it is not present,
  fall back to the TEE gracefully. A wrapping key in the keystore has no export
  path, thus it does not go into the platform backup of §15.6.6.
- The user can opt in separately to a cloud backup of the Recovery Code (Part 4
  §4.7.1) through the Block Store of the platform, with its end-to-end
  encryption on. **[IMP-026]** That item MUST sit under a Block Store key of
  its own, apart from each local wrapping key. **[IMP-027]** An implementation
  MUST let the user export it and delete it from the UMBRA settings.
  **[IMP-028]** That operation MUST NOT change a local storage key.

> The dominant forensic variable is the **AFU state against the BFU state**.
> Amnesty documented a Cellebrite chain of CVE-2024-53104, CVE-2024-53197, and
> CVE-2024-50302. That chain gets kernel code execution over USB on a locked
> Android device in the AFU state. A short auto-lock is not a convenience.

### 15.6.5 No hardware attestation for anti-abuse

**[IMP-029]** Relay reputation MUST come from measured behavior only. That behavior is the
uptime probes that a client observes, the latency percentiles, the acknowledged
message deliveries, and the sustained bandwidth. A client signs those
observations as attestations. **[IMP-030]** Relay reputation MUST NOT come from device
attestation. **[IMP-031]** Relay reputation MUST NOT come from a "genuine device"
proof.

Quarkslab (2026-08-11) showed a Frida-hooked relay of a genuine attestation
chain, from a clean oracle device, with no compromise of the secure hardware. If
UMBRA validates an Android attestation chain for a function, a check of
`attestationApplicationId` is mandatory. That field holds the package name and
the digest of the signing certificate. The omission of that check is the hole
that the attack used.

### 15.6.6 Platform egress

Part 2 §2.2 gives adversary A7, which is the platform of an honest device and
the software that shares that device. Each rule below names one platform
interface, and it states what the client gives to that interface. A **platform
store** is a location that the client does not encrypt under §15.6.4. The
platform media store, the platform backup, the task snapshot, and the clipboard
are platform stores.

**Each social affordance stays.** A user can save a file, copy a message, and
take a screenshot. Each of those is an explicit user action, and no rule below
removes one. Part 2 rule `THR-013` names those actions as its one exception.

**The decrypted attachment.**

- **[IMP-044]** A client MUST write a decrypted attachment inside the encrypted
  store of §15.6.4. **[IMP-045]** A client MUST NOT write a decrypted attachment
  to the platform media store without an explicit user action. That action
  names one file.
- **[IMP-046]** Before the first such action, a client MUST show a one-time
  warning. **[IMP-047]** That warning MUST state that the file leaves the
  encrypted store, and that each platform service then reads it.

**The platform backup.**

- **[IMP-048]** An Android client MUST set `android:allowBackup="false"` on the
  `<application>` element, with `tools:replace="android:allowBackup"`. Thus a
  merged library manifest cannot set it again.
- **[IMP-050]** The settings of a client MUST state that the platform backup
  carries no UMBRA data. The backup of Part 4 §4.7.2 carries that data.

> *Cause.* Android sets `allowBackup` to true when no manifest states a value,
> and a library manifest can set it. A restored container on a new handset is
> a store that no key opens. §15.6.4 entangles the storage master key with a
> secure-element key that never leaves the device. Thus the platform
> backup gives a copy to a party that Part 16 §16.1 did not list, and it gives
> the user nothing.

**The task snapshot.**

- **[IMP-055]** A client MUST draw a cover view over each conversation surface
  before the application leaves the foreground. Thus the task snapshot of the
  platform holds the cover and not the conversation. On Android 13 or newer a
  client also calls `setRecentsScreenshotEnabled(false)`.

**The clipboard and the input method.**

- **[IMP-056]** An Android client MUST mark a copied message as sensitive with
  `ClipDescription.EXTRA_IS_SENSITIVE`.
- **[IMP-057]** An Android client MUST set `IME_FLAG_NO_PERSONALIZED_LEARNING`
  on each composer and on the passphrase field.

**The screenshot and the accessibility tree.**

- **[IMP-058]** A client MUST offer a screenshot block as a setting of one
  conversation, and not as a global setting. On Android that block is
  `FLAG_SECURE` on the window of that conversation.
- **[IMP-059]** A client MUST NOT block a screenshot in a conversation by
  default. Part 14 §14.10 makes a report about a private conversation a
  screenshot.
- **[IMP-060]** A client MUST NOT hide a message from the accessibility tree.
  An accessibility service serves a user that cannot see the screen, and a
  hidden message is a hidden conversation for that user.

> *Cause.* The rules of §15.4 and §15.6.1 constrain the representation that
> crosses the FFI, and they stop no export. The input method that fills a
> composer is a separate process, and it reads the passphrase that feeds
> Argon2id. The task snapshot is a rendered bitmap that the platform writes at
> each background transition, and no key protects it. The auto-lock of §15.6.4
> wipes the master key, and a bitmap needs no key. A rule about where data goes
> is cheaper than a lost feature. Thus each social affordance stays, and each
> rule names an interface.

## 15.7 The web client

The web client is the second v1 client platform (Part 1 §1.1). It is the same
Rust core, compiled to `wasm32-unknown-unknown`, in a browser extension. This
section gives its form, its role in the device set, its transport, its
storage, its randomness and notifications, and its build. Each rule of this
specification binds the web client, except where a rule below names an
exemption and its cause. The performance question is not a cause: the measured
mean slowdown of WebAssembly is 1.45 to 1.55 times, and ML-KEM-768
encapsulation takes 29 µs natively.

### 15.7.1 The form: an extension, and not a hosted page

Three properties of the browser shape the web client. An earlier draft named
them as the causes that kept the browser out of v1, and this revision gives
each one a form that holds, or it states the residual.

1. **Code delivery.** A browser fetches a hosted page again at each load, thus
   the host can give one user a different build, and no party can check trust
   assumption 4 of Part 2 §2.6 for that user. An extension is a signed and
   versioned bundle. The browser installs it one time, and it fetches no code
   at a page load. **[IMP-094]** The web client MUST ship as a browser
   extension bundle. **[IMP-095]** A deployment MUST NOT serve the web client
   as a hosted page, as a progressive web application, or as a script that a
   page loads. **[IMP-096]** The bundle MUST hold each byte of code that the
   web client runs, and the web client MUST NOT load a script, a module, or a
   WebAssembly binary from a network location.
2. **Storage eviction.** A browser can delete the script-writable storage of an
   origin, and one browser does that after 7 days with no interaction. §15.7.2
   makes the web client a linked device, thus an eviction costs one link and
   no identity.
3. **Sockets.** A browser gives WebSocket, WebTransport, and `fetch` only.
   §15.7.3 gives the transport, and it states what the ingress relay learns.

**This is a trade, and Part 2 §2.4 requires the text to state it.** Each
browser vendor operates the one store that its browser installs from, thus
each vendor is a gatekeeper of the web client, and Part 16 §16.2.11 records
that. A user without the extension has no web client, and a link in a message
does not give one.

> *Cause.* An earlier draft ruled the browser out of v1 on the three causes
> above, and it named an extension as the form for a later revision. The owner
> put the web in the v1 scope. The core builds for `wasm32` under §15.2.4
> already, the extension form holds trust assumption 4, and the linked-device
> role removes the identity from the evictable store. The third cause stays as
> a property of the transport, and §15.7.3 states it.

### 15.7.2 The role: a linked device

- **[IMP-097]** A web client MUST be a linked device of a device set under
  Part 7, and it MUST NOT make a `RootIdentity`. **[IMP-098]** A web client
  MUST NOT hold a Recovery Code of Part 4 §4.7.1, a `C_social` share, or a
  backup key of Part 4 §4.7.2. Part 7 rule `DEV-264` states the same role from
  the device set, and rule `DEV-266` lets the web client show the link QR
  code.
- **[IMP-099]** A web client that finds its store absent or unreadable at
  start MUST return to the link flow of Part 7 §7.4, and it MUST show the
  line "This browser is no longer linked. Link it again from your phone."
  **[IMP-100]** The existing device MUST revoke the old entry under Part 7
  §7.7 before it links the same browser again, and Part 7 rule `DEV-265`
  gives that step.

Thus an eviction of the store costs one link and the history that the owner
device does not hold. A linked device accepts that cost under Part 7 §7.2
already.

### 15.7.3 The transport

The web client sends the L1 stream of Part 3 §3.8 through the WebSocket API of
its browser, over the TLS 1.3 stack of its browser, to port 443 of a pinned
ingress relay. Each layer from L2 up is the Rust core, unchanged.

- **[IMP-101]** A web client MUST use the WebSocket API of the browser over
  TLS to port 443, and it MUST NOT use WebTransport or `fetch` for the L1
  stream in v1. Part 3 rule `NET-275` states the same rule from the transport.
- The browser owns the ClientHello, the key share, the TLS record layout, and
  the WebSocket mask. Thus Part 3 rules `NET-214`, `NET-215`, and `NET-073`,
  and Part 6 rules `WIR-225` to `WIR-228`, bind the native client and the
  relay, and not the web client. Part 3 rule `NET-276` makes the relay refuse
  early data, and Part 6 rule `WIR-485` makes it refuse compression. Thus the
  properties that those client rules give hold at the relay for a web client.
- **[IMP-102]** A web client MUST NOT open a connection to a host other than
  its two pinned ingress relays of Part 10 §10.6.1 and the bootstrap carriers
  of Part 3 §3.10. **[IMP-103]** The extension manifest MUST request no host
  permission on any site, no content script, and no access to the browsing
  data of the user.

What the ingress relay learns changes in one way. The ClientHello of a web
client is the ClientHello of its browser, thus a classifier tells a web client
from a native client. Part 3 §3.8.1 states that trade, and Part 16 §16.3 holds
the row.

### 15.7.4 Storage and keys

The web client holds its store in the IndexedDB of the extension origin, under
the record construction of §15.6.4.

- **[IMP-104]** A web client MUST encrypt each record with the record key of
  §15.6.4, and it MUST keep each metadata-sensitive column inside the encrypted
  blob. **[IMP-105]** A web client MUST store in the IndexedDB of the extension
  origin only, and it MUST NOT use the sync storage area of the browser, the
  local storage area, or a cookie. A sync storage area copies to the account of
  the user at the browser vendor.
- **The wrap.** A browser has no secure element. **[IMP-106]** A web client
  MUST make `k_se` of §15.6.4 as a non-extractable HMAC-SHA256 key of the Web
  Cryptography API, and it MUST compute `S` with that key. The key has no
  export path, thus a copy of the store opens with the passphrase and that
  browser profile only. The key gives no rate limit against a party that runs
  script inside the profile, and Part 16 §16.3 holds the row.
- **[IMP-107]** A web client MUST calibrate Argon2id to about 3 s for each try
  in the browser, in the manner of §15.6.4.
- **Deletion.** IndexedDB has no `secure_delete`. **[IMP-108]** A web client
  that applies a deletion batch of §15.6.4 MUST overwrite `record_salt` and the
  ciphertext of each record with zero bytes, and then delete the record. The
  storage engine of the browser can hold the earlier bytes until it compacts,
  and Part 16 §16.3 holds the row. Rules `IMP-042` and `IMP-043` bind the
  SQLite store of the Android client only.
- **[IMP-109]** A web client MUST call `navigator.storage.persist()` at the
  first launch, and it MUST treat a refusal as no error.

### 15.7.5 Randomness, notifications, and the interface

- Rule `IMP-090` names `crypto.getRandomValues` as the platform source of the
  web client, and rule `IMP-093` applies the hardening of Part 5 §5.9 to it.
- The web client holds a live session while the browser runs, and it registers
  no push token. Part 8 §8.6 gives that rule. A message that arrives while the
  browser does not run waits at the queue relay, and the phone of the user
  gets its notification under Part 8. **[IMP-110]** The settings of a web
  client MUST state that the browser receives messages while it runs, and that
  the phone receives each notification.
- The platform egress rules of §15.6.6 name Android interfaces. On the web
  client the platform stores are the clipboard, the download location, and the
  browser profile. **[IMP-111]** A web client MUST apply `IMP-044` to
  `IMP-047` with the download location as the platform media store.
  **[IMP-112]** A web client MUST state that the screenshot block of `IMP-058`
  is not available in the browser, because a browser gives no equivalent of
  `FLAG_SECURE`.
- Part 2 §2.4 goals U5 and U8 name an Android device, and they do not measure
  the web client. §15.9 binds the web client in full.

### 15.7.6 The build and the crate

- The web surface is the `umbra-web` crate of §15.1. It holds the
  `wasm-bindgen` bindings, the WebSocket transport behind the transport trait,
  and the IndexedDB adapter behind the storage trait. It uses no UniFFI, and
  the `wasm-unstable-single-threaded` feature of UniFFI stays off.
  **[IMP-113]** The `umbra-web` crate MUST NOT add more transitive crates than
  its row in §15.2.3.
- **[IMP-114]** The extension bundle MUST be reproducible under §15.8, and
  Part 16 rule `SEC-005` names it. **[IMP-115]** The web client MUST verify
  the inclusion proof of Part 16 rule `SEC-006` for its own bundle at each
  start, and it MUST refuse to unlock the store while that proof is absent.
  The browser applies an extension update before the client runs, thus the
  check at start is the one point where the client sees the new bundle.
- **Constant time.** The browser compiles the WebAssembly binary, thus layer 1
  of §15.5.1 does not run against the code that executes, and layer 2 is the
  one layer under the control of the project. Part 16 §16.3 holds the row.

## 15.8 Build reproducibility and binary transparency

Trust assumption 4 of Part 2 §2.6 says that *the client binary that the user
runs is the binary that the auditor examined*. Without this section, no party
can check that assumption. If that assumption fails, each other guarantee
becomes void.

- The Rust core, the Android application binary, and the web extension
  bundle use reproducible builds. **[IMP-032]** Two independent builds of the
  Rust core, of the Android application, and of the extension bundle MUST
  give the same hash. §15.6.3 records that a platform with a
  signed and encrypted bundle needs a rule for the static library, and this
  revision defers that platform.
- The project runs a binary transparency log with Sigstore support. The
  application holds a verification path.
- **Two or more independent rebuilders** rebuild each release from the source.
  Those rebuilders publish signed attestations that their bytes match the
  published artifact. **[IMP-033]** A minimum of one rebuilder MUST be outside the control of
  the nonprofit. A reproducible build that no independent party reproduces
  proves nothing.
- The release builds are network-isolated, from a committed `cargo vendor` tree.

## 15.9 Degraded states and the interface

Part 2 §2.4 sets goals that assume an interface. U1 assumes a first launch
with no security screen. U6 assumes that a user sees a record that no relay
accepted. Part 14 rule `ABU-008` assumes a progress indicator. This section
gives those assumptions a closed set of states and a rule for each one.

### 15.9.1 The delivery states

Each outbound record is in one state of the table below, and the table is
closed. Part 7 §7.5.3 converges the state across the device set.

| State | Condition | The client shows |
| --- | --- | --- |
| `queued` | The client holds the record, and no relay acknowledged the `SEND` | One mark for a queued record |
| `accepted` | A relay acknowledged the `SEND` under Part 3 §3.7 | One mark for an accepted record |
| `delivered` | A delivery receipt of Part 6 §6.6.9 arrived. Part 3 rule `NET-059` keeps receipts off by default, thus this state is reachable only when the peer sends them | One mark for a delivered record |
| `read` | A read receipt arrived, under the same default | One mark for a read record |
| `failed` | Part 3 §3.7 stopped the ARQ, at a permanent rejection, at `SEND_MAX_ATTEMPTS`, or at `SEND_GIVE_UP` | The record, the cause in words, and a resend affordance |

- **[IMP-072]** A client MUST hold each outbound record in one state of the
  table above. **[IMP-073]** A client MUST NOT add a state to the table.
- **[IMP-074]** A client MUST show a `failed` record with its cause and with a
  resend affordance. **[IMP-075]** A client MUST NOT resend a `failed` record
  without a user action. Part 3 §3.7 gives the cause, which is that a resend
  loop is a signature and a dead channel needs the probe of Part 3 §3.2.6.
- **[IMP-076]** A client MUST NOT show a `queued` record as a failure. A queued
  record waits for a connection, and U6 counts it as deliverable.

### 15.9.2 The seven degraded states

A client is in one or more of the states below, or in none. Each state names
its condition, its end, and the one line that the client shows.

| State | Condition | The state ends when | The client shows |
| --- | --- | --- | --- |
| `offline` | The device holds no network route | A route returns | "No connection. Messages wait." |
| `ingress unreachable` | Both pinned ingress relays of Part 10 §10.6.1 refuse or time out, with a route present | One ingress accepts a connection | "The relays do not answer. Messages wait." |
| `provisional directory` | The client holds a `DirectoryRoot` below `AUTHORITY_FLOOR`, under Part 10 rule `REL-126` | A root at or above the floor arrives | "The relay directory is provisional." |
| `admission surge` | The newest `PowChallenge` of a relay in use holds `effort` above 0, under Part 14 §14.8 | The effort returns to 0, or the client spends a token | A progress indicator during each solve, under `ABU-008` |
| `recipient queue full` | A `QUOTA` of Part 3 rule `NET-017` names the queue of a contact | The relay stops the signal | "This contact has not collected messages for a while." |
| `notification carrier absent` | The build holds no carrier of Part 8 rule `NTF-040` for the selected mode | The user selects a mode that the build carries | The line of `NTF-040` |
| `clock` | `NTF_FAIL_MAX` consecutive notification blobs failed to open inside the window of Part 8 rule `NTF-075` | One blob opens after a fresh `k_ntf_root` | "The device clock may be wrong. Notifications show no preview until it is checked." |

- **[IMP-077]** A client MUST show each current degraded state in one line at
  the top of the message list. **[IMP-078]** A client MUST NOT show a degraded
  state as a security failure. **[IMP-079]** A client MUST NOT block the
  message list, the composer, or a send in a degraded state.
- **[IMP-080]** A client MUST leave a degraded state without a user action when
  its condition ends. **[IMP-081]** A client MUST NOT add a degraded state to
  the table without a row in Part 2 §2.4.
- **[IMP-082]** In the `recipient queue full` state, a client MUST keep the
  record `queued`. The relay holds `QUEUE_QUOTA` records of Part 3 §3.2.4, and
  the sender holds the rest.

> *Cause.* An earlier draft named a degraded read in Part 9, a provisional
> directory in Part 10, a missing carrier in Part 8, and a progress indicator
> in Part 14. No section listed the states, thus two implementations showed two
> different sets. A user that sees "connecting" for an hour deletes the
> application, and a user that sees a red banner for a provisional directory
> reads it as a compromise. The one line for each state and the rule against a
> block keep U1 and U6 honest.

### 15.9.3 The interface strings

Rules of this specification require the interface to show a string. Examples
are `NTF-009`, `COM-001`, `ABU-040`, `IMP-050`, and the lines of the table
above. A translation that drops such a string breaks the rule in that locale,
and no test caught that before this section.

- **[IMP-083]** Each string that a rule of this specification requires the
  interface to show MUST carry a stable message identifier. **[IMP-084]** That
  identifier MUST be `umbra.ui.` followed by the rule identifier in lower
  case. **[IMP-085]** A revision MUST NOT change an identifier.
- **[IMP-086]** A test MUST check that each identifier resolves to a non-empty
  string in each shipped locale. **[IMP-087]** A release MUST NOT ship a locale
  that fails that test.

### 15.9.4 Accessibility

- **[IMP-088]** The interface MUST meet WCAG 2.2 at level AA. **[IMP-089]** Text
  MUST hold a contrast ratio of 4.5:1 or more against its background. Part 4
  rule `IDN-016` states the same bound for the identicon palette, and rule
  `IMP-060` keeps the accessibility tree whole.

## 15.10 Randomness

Part 5 §5.9 hardens each random value under RFC 8937, and trust assumption 2
of Part 2 §2.6 rests on the source below that hardening. This section names
the platform half.

- **[IMP-090]** A client MUST take each CSPRNG output from the platform source,
  which is `getrandom` on Android and `crypto.getRandomValues` on the web
  client of §15.7.
  **[IMP-091]** A client MUST NOT hold a userspace generator that it seeds one
  time. **[IMP-092]** A relay MUST take each CSPRNG output from `getrandom` of
  its kernel.
- **[IMP-093]** A client MUST apply the hardening of Part 5 §5.9 to each value
  that the platform source gives. The hardening secret `K_rng_harden` of Part 5
  §5.2 lives in the encrypted store of §15.6.4. Thus a platform generator that
  fails after the first launch shows no raw output on the wire.
