# UMBRA Protocol Specification — Part 14: Implementation Requirements and Assurance

**Status:** Draft
**Version:** 0.13.0
**Date:** 2026-10-09

---

## 14.1 Workspace layout

```
umbra/
├── crates/
│   ├── umbra-crypto/     primitives, UMBRA-KEM, handshake, ratchet   → no in-workspace deps
│   ├── umbra-wire/       fixed-layout codecs, padding, buckets       → umbra-crypto
│   ├── umbra-onion/      cell construction, per-hop UIV+, replay     → umbra-wire
│   ├── umbra-queue/      queue commands, subscriptions, ARQ          → umbra-wire
│   ├── umbra-transport/  TLS (QUIC deferred), session layer, wire    → umbra-wire
│   ├── umbra-core/       orchestration, state machine, storage       → all above
│   ├── umbra-ffi/        UniFFI surface, coarse-grained only         → umbra-core
│   ├── umbra-web/        wasm-bindgen surface, browser socket, store → umbra-core
│   ├── umbra-relay/      relay node and server binary                → umbra-core
│   └── umbra-simd/       the ONLY crate permitted `unsafe`           → nothing
├── spec/
├── tests/vectors/        vendored KATs + PROVENANCE.md
└── scripts/
```

The dependency direction is strictly downward. A cycle is a build failure.

Two crates of the layout do not exist in the reference implementation today.
`umbra-web` waits for the web client, which is deferred (Part 1 §1.1), and `umbra-simd` waits
for a SIMD path, which no crate needs yet. Thus each crate of the workspace
forbids `unsafe` today, and the exception below has no crate to apply to.

## 14.2 Dependency policy

**UMBRA holds three dependency registers. Two registers carry a numeric cap, and
the third register carries a rule.**

| Register | Content | Cap |
| --- | --- | --- |
| **R1** message core | The six primitives of Part 5 §5.1 | **40** transitive crates on a target triple |
| **R2** auxiliary | The nine auxiliary primitives of Part 5 §5.1 | **30** more transitive crates above the R1 graph |
| **R3** platform | Transport, storage, async runtime, FFI, and build tooling | No number in v1. §14.2.3 gives the rule |

The combined cap for R1 and R2 is **70** transitive crates. **[IMP-002]** A change MUST name
the register that it charges. **[IMP-003]** A claim that a change costs no crate MUST name
that register too.

> *The cause for two caps, and not for one raised cap.* One cap over a graph
> near 70 hides which register grew. The value of the message-core cap is that
> one person reads the whole R1 graph in a day. A single raised number retires
> that property, and it makes each auxiliary addition look free. Two caps keep
> the audit unit small, and they put each new standard against a limit that a
> reader sees.

### 14.2.1 Register R1: the message core

The trial figure is **37 crates** on `aarch64-linux-android`. It is 35 crates
on `no_std` and on `wasm32`. That graph is
about 65k LOC, and it has no open OSV or RustSec advisory at the pinned
versions.

**The figure of 37 comes from a trial resolution outside this repository.**
`DEPENDENCIES.md` holds the measurement of this repository, which the script
of §14.2.4 writes.

| Crate | Configuration |
| --- | --- |
| `ml-kem` 0.3 | `default-features = false`, `features = ["zeroize"]` |
| `ml-dsa` 0.1 | `default-features = false`, `features = ["rand_core", "zeroize"]`. **[IMP-004]** An implementation **MUST** turn the `pkcs8` default off. If it stays on, the build inherits `der`, `spki`, `pkcs8`, and `const-oid` |
| `x25519-dalek` 3 | `default-features = false`, `features = ["static_secrets", "reusable_secrets", "zeroize"]`. **[IMP-174]** An implementation **MUST** turn `zeroize` on: with it off, a secret scalar and a shared secret stay in memory after a drop (Part 5 `CRY-059`). |
| `chacha20poly1305` 0.11 | `default-features = false` |
| `aes` + `polyval` | for the onion UIV+ layer only |
| `sha3` 0.11 | pin to 0.11 to match `ml-kem` and to prevent a duplicate `sha3` 0.12; `features = ["zeroize"]` |
| `hkdf` 0.13, `hmac` 0.13 | generic over `Sha3_256`; `hmac` with `features = ["zeroize"]`, thus a keyed state is wiped |
| `subtle` 2, `zeroize` 1 | |

### 14.2.2 Register R2: the auxiliary primitives

Part 5 §5.1 registers nine auxiliary primitives. The table below gives the
likely pure-Rust crate for each one. **Each count in the last column is an
estimate.** `DEPENDENCIES.md` holds the measured counts. A count is the number of
crates that the row adds above the R1 graph. A crate that two rows share counts
one time.

| # | Primitive | Likely pure-Rust crate | New crates (estimate) |
| --- | --- | --- | --- |
| AUX-1 | Blind RSA-2048 | in-workspace over `crypto-bigint`, which gives the modular arithmetic and nothing else; no `rsa` crate, and no key generation in the client | **1** |
| AUX-2 | ristretto255 with SHA512 | `curve25519-dalek`, which R1 holds already, plus `sha2` | **1–3** |
| AUX-3 | ECVRF-Edwards25519-SHA512-TAI | a vendored module, and no crate (Part 9 §9.12) | **0–1** |
| AUX-4 | Argon2id | `argon2`, `blake2`, `base64ct` | **3–5** |
| AUX-5 | A keyed function in the secure element | a platform adapter, and no crate. Android uses the HMAC-SHA256 key of StrongBox | **0** |
| AUX-6 | HPKE under OHTTP | in-workspace, over `UMBRA-KEM` | **0–2** |
| AUX-7 | XChaCha20-Poly1305 | `chacha20poly1305`, which R1 holds already | **0** |
| AUX-8 | Equi-X | `equix` over `hashx`, with the JIT feature off; the interpreter needs std, thus a default feature of `umbra-crypto` carries it | **4–8** |
| AUX-9 | Additive secret sharing with Laplace noise | in-workspace, PrivEx-S2 | **0–1** |
| AUX-10 | The `UsernameCaseMapped` profile of RFC 8265 (Part 9 §9.3.2) | `precis-profiles`, `precis-core`, `unicode-normalization`, `tinyvec`; the table generator `precis-tools` and its parsers are build-only | **4** |

The low column sums to 13, and the high column sums to 25. Thus the estimate for
R1 and R2 together is 50 to 62 crates, against the combined cap of 70.
`DEPENDENCIES.md` holds the measured count. AUX-1
alone takes half of the R2 cap.

The cap of 30 is a real limit, and four decisions make it reachable. Each
decision is already in another Part:

1. **Write the HPKE and OHTTP layer in the workspace.** Part 8 §8.2.3 puts
   `UMBRA-KEM` in HPKE, and the `hpke` crate does not hold `UMBRA-KEM`. The
   `hpke`, `ohttp`, and `bhttp` crates together cost an estimated 10 to 18
   crates.
2. **Vendor the ECVRF module.** Part 9 §9.12 states this decision. The full
   `akd` crate costs an estimated 10 crates or more.
3. **Turn the JIT feature of `equix` off.** That feature carries `unsafe`, and
   §14.3 forbids `unsafe` outside `umbra-simd`.
4. **Write the PrivEx-S2 construction directly.** Part 10 §10.8 states this
   decision, and it prohibits a `draft-ietf-ppm-dap` dependency.

**[IMP-005]** If the measured R2 count is more than 30, the maintainers MUST NOT tag a
release. **[IMP-006]** Those maintainers MUST first remove a primitive, or MUST first revise
this section with a written cause. §14.2.5 gives the removal candidates.

### 14.2.3 Register R3: the platform subsystems

R3 holds the transport stack, the storage stack, the async runtime, the UniFFI
surface, and the build tooling. §14.2.8 names the transport stack. Each of
them sits behind a feature that is off by default, thus the default graph
holds no R3 crate, and `DEPENDENCIES.md` measures R3 on the two platform
builds: the Android library with `bindings`, and the relay server with
`native`.

**[IMP-007]** **One subsystem in R3 MUST NOT add more transitive crates than
its row in the table below.** No single platform part costs more than the
whole message core. Part 3 §3.8 rejects a WebRTC stack under this rule. A crate
that two subsystems reach charges to one of them, in the order of the table.

| Subsystem | Cap | Measured, Android library | Measured, relay server |
| --- | --- | --- | --- |
| Async runtime | 20 | 5 | 5 |
| Transport, §14.2.8 | 40 | 20 | 20 |
| Storage, §14.6.4 | 25 | 6 | 6 |
| UniFFI surface, §14.6.1 | 15 | 14 | 0 |
| Web surface, §14.7 | 15 | not built | not built |
| Build tooling | No cap, because a build tool is not linked | | |

**The first measurement (2026-09-22).** The Android library links 45 R3
crates, and the relay server links 31. The R3 cap is **50** for the Android
library and **35** for the relay server. The UniFFI surface sits one crate
below its cap: a UniFFI upgrade that adds two crates fails the build, and the
maintainers then remove a crate or revise this section with a written cause,
as `IMP-006` asks of R2.

> *The licences of R3.* The platform graph adds three licences to the allow
> list of the core: MPL-2.0 for the six `uniffi` crates, ISC for the rustls
> verifier and `aws-lc`, and CDLA-Permissive-2.0 for the root data of
> `webpki-roots`. MPL-2.0 is file-level copyleft, UMBRA changes no file of
> it, and MPL-2.0 §3.3 permits the combination with AGPL-3.0. `deny.toml`
> allows each of them for the named crates alone.

**[IMP-008]** At the first measurement, the maintainers MUST publish the R3 count. **[IMP-009]** Those
maintainers MUST set the R3 cap in the same change.

### 14.2.4 Measurement: the party, the trigger, and the artifact

`DEPENDENCIES.md` at the root of the repository holds the measured counts.
The figures of §14.2.2 and §14.2.5 are estimates of changes that the
repository has not made, and those sections mark each one as an estimate.

**The maintainers of the reference implementation measure the three counts.**
The trigger is the first commit that adds the workspace `Cargo.toml` file. **[IMP-010]** That
commit MUST also add a `DEPENDENCIES.md` file at the root of the repository. A
build script generates that file, and no person maintains it by hand.
**[IMP-011]** `DEPENDENCIES.md` MUST hold five items:

1. The R1 count, the R2 count, and the R3 count, for each target triple.
2. The crate list of each register, with the version of each crate.
3. The cap of each register, and the result PASS or FAIL against that cap.
4. The commit hash and the date of the measurement.
5. The `rustc` version that §14.5.1 pins, and the exact `cargo` version.

The three target triples are `aarch64-linux-android`,
`x86_64-unknown-linux-gnu`, and `wasm32-unknown-unknown`.

**[IMP-012]** The maintainers MUST publish `DEPENDENCIES.md` before the first tagged release.
**[IMP-013]** The maintainers MUST NOT tag a release without that file. **[IMP-014]** A CI job MUST generate
that file again at each commit. **[IMP-015]** That job MUST fail the build on a difference
against the committed file.

### 14.2.5 Removal candidates

The rule of this project is to prefer a removal to an addition. **This section
removes no primitive.** Part 5 §5.1 holds the two registers, and a removal needs
a change to that section. The table below gives each candidate and the cost of
its removal.

| Candidate | Saving (estimate) | The cost of the removal |
| --- | --- | --- |
| **AUX-1** blind RSA-2048 | 14–18 crates | This is the largest saving, and it is the most expensive one. Part 13 §13.3.1 gives a third-party relay offline verification with the public key of the project alone. Without AUX-1, that relay verifies the first-party token of §13.3.2. That token is privately verifiable, thus the relay needs a shared secret with the issuer. A self-hosted operator then has to trust the issuer, and the self-hosting position of Part 13 fails |
| **AUX-8** Equi-X | 4–6 crates | Part 13 §13.8 loses the surge valve at a relay under queue pressure. Argon2id (AUX-4) holds the puzzle in place of Equi-X. But Argon2id gives no asymmetry against an ASIC and against a GPU. It also costs more RAM on the slowest supported phone |
| **AUX-4** Argon2id | 3–5 crates | §14.6.4 loses the memory-hard step of the at-rest construction. The secure-element entanglement stays, thus a brute force attack still runs on the seized device. But the cost for each try falls from about 3 s to the cost of one secure-element operation. Of the three primitive removals with a real saving, this one costs the most protection |
| **AUX-3** ECVRF | 0–1 crate | Part 9 §9.12 vendors the module already, thus the saving is close to zero. The removal costs the blind directory index of Part 9 §9.5. This candidate gives no saving that pays for its cost |
| Runtime SIMD detection | 2 crates | This is not a primitive. §14.3 gives the full analysis. The removal drops `cpufeatures` and `libc`. It gives a uniform R1 graph of 35 crates on the three target triples |

An estimated **10 to 18 crates** come off R2 with no primitive removal. That
saving needs the four decisions of §14.2.2. Take those four decisions first, and
examine a primitive removal after them.

### 14.2.6 Crates that UMBRA does not adopt

- **`libcrux`** — its formal-verification claim does not cover the ARM64 and
  NEON backend. That backend is 792 LOC, and it is 100 % admitted. It "needs
  proofs" for the runtime safety and for the correctness. UMBRA ships Android
  first, thus the target is ARM64. If a deployment needs a
  verified ML-KEM later, that deployment forces the portable backend on mobile.
- **`liboqs-rust`** — the maintainers state that it is not for production use.
  Its only public audit excluded the algorithm implementations deliberately.
- **`ring`** as the rustls provider — it gives no `X25519MLKEM768` key share
  and no ECH, thus it cannot send the ClientHello of Part 3 §3.8. The
  advisory RUSTSEC-2025-0007 called the crate unmaintained. That advisory
  is withdrawn, and the cause above stands alone.
- **`boring` and `boring2`** — BoringSSL shapes a ClientHello as Chrome, and
  Part 3 §3.8 does not need that shape. The cost is a C++ toolchain in the
  Android NDK, above the C toolchain of `aws-lc-rs`.
- **`openssl`** — it links a C library that UMBRA holds for no other function.
  §14.6.4 rejects the SQLCipher build on the same cause.
- **`akd`** — Part 9 §9.12 takes the ECVRF module of that crate, and not the
  crate. The crate carries SEEMless, Parakeet, and a MySQL shape that an opt-in
  directory does not need.
- **`ohttp` and `bhttp`** — §14.2.2 decision 1 gives the cause.

### 14.2.7 Enforcement

- `cargo-deny` with an explicit allowlist and `multiple-versions = "warn"`,
  with a `skip` list in which each entry carries a date and a cause. A CI job
  fails the build on a skip entry older than 90 days. Each of R1 and R2
  carries a separate allowlist. Thus a new transitive crate **fails the
  build**, and a duplicate version is a dated debt and not a silent one.
- The repository holds `Cargo.lock`.
- `cargo-deny` checks each crate and version against the RustSec advisory
  database.
- A CI job generates `DEPENDENCIES.md` again, and compares it against the
  committed file. A difference **fails the build**.
- **A cooling-off window of 14 to 30 days** for an update that is not a security
  update.

> In August 2026 the `arrayref`, `internment`, and `append-only-vec` compromise
> injected a typosquatted `proc-macro1`. The `build.rs` of that crate executed a
> remote payload. Those releases were live for **86–107 minutes**. A cooling-off
> window with offline vendored builds gives UMBRA immunity to that attack.
> `cargo-vet` does not, because the median audit lag is 29 days and 40 % of the
> RustSec fix-versions get no audit.

### 14.2.8 The transport stack

R3 holds the transport stack, and §14.2.3 gives it no number. This section
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
  of §14.7 needs none. The browser gives the TLS stack and the WebSocket
  frame, and the `umbra-web` crate puts that socket behind the transport
  trait. `tokio` does not build for the browser, thus the web surface runs
  the core on the event loop of the browser through `wasm-bindgen-futures`.

The count of this table is an estimate until §14.2.4 measures it, and
`IMP-007` bounds it at 40 transitive crates. A relay operator with a FIPS
requirement selects the `fips` feature of the same provider crate, and the
client build does not.

> *Cause.* The advantage of `aws-lc-rs` is not its FIPS validation, which
> UMBRA does not need. The crate is the default provider of `rustls`, and it
> is the provider that holds the post-quantum key share and the HPKE of ECH.
> The C toolchain is the cost, and that cost buys the L1 flight of Part 3
> §3.8. With both providers rejected, no client opens a connection, and no
> stack sends the handshake that Part 3 §3.12 prices.

## 14.3 Unsafe and panic policy

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

## 14.4 Secret handling

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

## 14.5 Assurance

### 14.5.1 Constant time — three layers

The control of v1 is at the source. A function that touches key material uses
no `/`, no `%`, and no secret-indexed access. This ban finds the KyberSlash
class, which is a variable-time instruction.

The ban does not find a branch that the compiler inserts. LLVM has defeated
hand-written constant-time Rust in shipped code two times. The first case was
the `jns` branch on a mask in `curve25519-dalek` (RUSTSEC-2024-0344 and
CVE-2024-58262). The second case was Clangover. In the two cases the source did
not change. v1 runs no test against the release binary for that class.

**The toolchain is part of the cryptographic TCB.** Pin the exact `rustc`
version, the target triples, the opt-level, and the codegen-units for the
release builds.

### 14.5.2 Test vectors and differential testing

- **[IMP-034]** The repository MUST vendor the NIST ACVP corpora of ML-KEM
  and ML-DSA, the C2SP CCTV vectors of ML-KEM, and the RFC 9180 and RFC 9474
  vectors at `tests/vectors/`. **[IMP-035]** The repository MUST hold a
  `tests/vectors/PROVENANCE.md` file that records the upstream commit of each
  corpus. **[IMP-036]** A test MUST NOT fetch a vector at test time.
- A canonical re-encode check runs on each parsed signature and on each parsed
  ciphertext.
- Prefer a one-shot ML-KEM API over an incremental or stateful API.
- The rule number `IMP-019` is retired, and no rule uses it.

> Four of the thirteen reported vulnerabilities in libcrux were errors in the
> specification or in the proof. Formal verification structurally cannot find
> such an error. A cross-backend endianness bug in unverified libcrux code
> caused real decryption failures in the post-quantum ratchet of Signal, across
> libsignal v0.76.3 to v0.86.9.

### 14.5.3 Fuzzing and bounded model checking

v1 runs no fuzzer and no bounded model checker.

### 14.5.4 Formal verification — scope it honestly

UMBRA **rejects Verus, Creusot, Prusti, and hax for v1**. Verus measures about 5
proof-lines for each implementation-line. At that rate, the verification of a
protocol core is a commitment of multiple engineer-years. libcrux spent that
effort and reached only 58.4 % checked coverage.

The rule number `IMP-020` is retired, and no rule uses it.

## 14.6 Platform delivery

### 14.6.1 FFI

UMBRA uses **UniFFI 0.32.x**, with a deliberately narrow surface:

```
init(config, SecureElement, CharArray) -> Handle   // the passphrase, at the first launch

// Plaintext never crosses as ByteArray. The platform builds a Draft on the
// Rust side, writes into it, and sends the handle.
new_draft(handle, conv) -> Draft
draft_set_text(draft, CharArray)          // Android: CharArray, not String
draft_attach(draft, path, class, w, h, seconds)   // one file, and no text beside it
send_draft(handle, Draft) -> MsgId
cancel_send(handle, MsgId)

// A received message is a handle. The platform reads it into a view that
// the renderer owns for the frame, and does not copy it into a String.
next_event(handle) -> Event               // Event carries a MsgRef, not bytes
wait_event(handle, timeout_ms) -> Event   // the same, and the call waits
msg_render(MsgRef, Sink)
msg_info(handle, MsgRef) -> MsgInfo       // the direction, the delivery state, two times, the file state
fetch_file(handle, MsgRef)                // a second attempt for a file that did not arrive
msg_file(handle, MsgRef, FileSink)        // the bytes of a file, one time for one decode (IMP-166)
messages(handle, conv) -> [MsgRef]        // the handles of one conversation

// The network. The relay directory of Part 10 replaces the Network record.
connect(handle, Network)                  // the three relays of the path
connection(handle) -> Connection          // the circuits and their relays, for the view of the link
disconnect(handle)
invite(handle)                            // an Invitation event follows
accept(handle, bundle)                    // a Contact event follows

lock()
unlock(CharArray)                         // 14.4 gives the passphrase exception
tick(handle)                              // the clock of the platform, for the auto-lock
measure_argon2_floor_ms() -> u64          // one try at the floor cost, for init
```

Each network, ratchet, queue, and onion function stays on the Rust side.

The web client of §14.7 crosses no UniFFI surface. The `umbra-web` crate gives
it a `wasm-bindgen` surface of the same shape, and `IMP-037` to `IMP-039`
bind that surface in the same manner, with a JavaScript string and an
`ArrayBuffer` in the place of the Kotlin types, and with the passphrase
exception of §14.4.

**[IMP-037]** The FFI surface MUST NOT carry message plaintext, key material, or
a passphrase as a Kotlin `ByteArray` or a Kotlin `String`. §14.4 rule `IMP-017`
gives that rule, and this section gives the surface that obeys it.

**The stated exceptions.** The values below cross the surface as a Kotlin
`String` or as bytes, and no other value of the three classes does. Each one
has a cause, and Part 15 §15.3 holds one row for the set.

| The value | The cause |
| --- | --- |
| A name that a user typed to be shown: the name of a group, the name of a file, the name and the note of a contact request, the names of an introduction, and the name and the welcome text of a profile | A view of the platform draws it as text, thus the platform holds it in each design |
| The verification code of Part 4 §4.5.2, and the ticket and the short code of a device link of Part 7 §7.4 | Each one exists for a person to read or for a camera to scan |
| The bundle of an invitation, as the paragraph below states | The platform shows it as a link or as a QR code |
| The question and the options of a poll | **This one is a limit and not a design.** A poll is message text, and in v1 it crosses as a string in each direction. A later version moves it behind a `Draft` and a `TextSink`, and it removes this row |
| The wake table of Part 8 rule `NTF-135`, as bytes | The platform seals it under a keystore key that needs no unlock, and the core cannot reach that key |
| The bytes of a file and of a preview, under `IMP-166` | The decoder and the player of the platform read bytes |

**[IMP-165]** The file of a draft MUST cross the surface as a path that the
core reads, and not as its bytes. On Android the path names an open descriptor
of the process, `/proc/self/fd/<n>`, which the platform got from the content
resolver or from a pipe that carries the re-encode of Part 12 rule `ATT-155`.
Thus the surface carries no byte of the file on its way in, and the device
holds no copy of it outside the store (`IMP-160`).

**[IMP-166]** The bytes of a file that the store holds MAY cross the surface
one time for each decode, into a sink of the platform. This is an exception to
`IMP-037`, and it has a cause: the image decoder and the media player of the
platform read a byte array or a stream, and a decoder inside the core would
hand over pixels, which are the same plaintext. The core MUST overwrite its
copy after the call. A media player reads a video in ranges, thus the core
MAY hold one copy of the file in its memory for the time that the player is
open, and give each range that the player asks for. The core MUST overwrite
that copy when the player closes, and MUST refuse each range after a lock.
A picture that a peer made is a profile picture of Part 9 rule `DIS-176` or a
picture of a contact request. The platform MUST decode such a picture to at
most 1 024 pixels on each side. It MUST read the size of the picture
before it decodes one pixel. A JPEG of a few kilobytes can name a very large
canvas, and a decode of that canvas ends the process.
The preview of Part 6 rule `WIR-533` MAY cross the surface as bytes in both
directions, under the same terms: it is a picture, as the file is. The platform MUST overwrite the array when the decode
ends, MUST NOT write the bytes to a file or to a platform cache, and MUST drop
each decoded image at a lock. The exception covers a file alone: a text, a
passphrase and key material stay under `IMP-037`.

**[IMP-038]** `Draft` and `MsgRef` MUST be opaque UniFFI object handles.
**[IMP-039]** An implementation MUST zeroize the buffer behind a `Draft` when
that draft is dropped, and it MUST do that whether the send succeeded or failed.

**Three points where the platform shapes the surface.**

- **[IMP-124]** Text and the passphrase MUST cross as UTF-16 code units, and
  the Rust side MUST overwrite its copy after the use. UniFFI 0.32 has no
  `CharArray` type, thus the generated Kotlin takes a list of code units. The
  Kotlin wrapper of the app MUST fill that list from a `CharArray`, and it
  MUST overwrite the `CharArray` after the call. The list is an object on the
  JVM heap for the length of the call, and so is the buffer that UniFFI
  lowers each value through in either direction; Part 15 §15.3 holds that
  residual.
- **[IMP-125]** The secure-element step of §14.6.4 MUST cross as one callback
  that takes the input of the keyed function and returns its 32 bytes. The
  Android keystore has a Java interface only, thus this one value crosses as
  bytes. The Rust side MUST overwrite the returned value after it derives
  `K_wrap`.
- **[IMP-126]** A record that waits for the send path MUST sit in the store
  under the record encryption of §14.6.4, in a table of its own. A lock MUST
  clear the queue in RAM, and an unlock MUST fill it again from that table.
  The row leaves the table when a relay accepts the record, when the ARQ of
  Part 3 §3.7 stops, or when the user cancels the send.

**The network behind the surface.**

- **[IMP-127]** A lock MUST stop the network runtime, and the runtime MUST
  drop its state at that stop. That state holds ratchet keys, queue keys, and
  circuit keys, and a locked client holds no key in RAM. The hardening
  secret `K_rng_harden` of `IMP-093` is a key of the store too, and it
  leaves RAM at the lock with each other key.
- **[IMP-128]** A client MUST order a conversation view by the time of its own
  store of each message. It MUST NOT order the view by `sent_at`, because that
  value comes from the peer, and a peer could thus put a message before an
  earlier one. `msg_info` gives the two times, and it gives no content.
- **[IMP-129]** A conversation identifier on the surface MUST be the surrogate
  of §14.6.4 under the store key, and it MUST NOT be a queue identifier. Thus
  the owner column of a message row names no queue to a party that reads the
  file and holds no `K_store`.
- **[IMP-138]** The name that a user gives a contact MUST stay on the devices
  of that user, and a client MUST NOT send it to a peer or to a relay. It is a
  label of the user and no message text, thus it crosses the surface as a
  string. The preview of a conversation list is message text, thus it goes
  into a sink under `IMP-037`. `summaries` gives the handle of the newest
  message and no text.
- **[IMP-139]** A client MUST count a received message as not seen while its
  store time is above the read marker of its conversation, and it MUST move
  that marker when the user looks at the conversation and at no other time.
  The marker sends nothing: a read receipt is a record of Part 6 §6.6.9 with
  its own setting.
- **[IMP-146]** A client MUST hold a receipt in table `0x0B` from the commit
  of the message that it reports, or from the move of the read marker of
  `IMP-139`, to the slot that carries it (`NET-053`). It MUST erase the rows
  of a batch after a relay answered the record of the slot that carried
  that batch, and not at the moment it made the batch or wrote its cell. A slot
  that an acknowledgment took, and a run that ends before the `QUOTA`
  of that record, leave the batch in the store. A relay that refuses the
  record with `REJECTED` or `VERSION` ends the batch too, because that
  record goes no more (`NET-217`). A kind that the user turns off MUST erase each held receipt of that
  kind for that contact. The move of the read marker is the one source of a
  read receipt, thus a notification gives none (`NET-043`).
- **[IMP-147]** A receipt is no message of a conversation, and a client MUST
  NOT store it as one. A receipt MUST change the delivery state of a message
  only when this device sent that message in the conversation of the peer
  that sent the receipt, and only upward in the order Accepted, Delivered,
  Read. A receipt whose body does not parse MUST change nothing, and it MUST
  NOT end the batch of the records that arrived with it.
- **[IMP-156]** A client MUST reject a reaction whose `emoji` holds a code
  point that no emoji sequence uses, from a contact and from its own
  surface. Part 6 §6.6.9 checks UTF-8 and a length, thus 64 bytes of a
  reaction could carry a text that no view treats as a message, no edit
  window covers, and no deletion reaches. The permitted code points are the
  emoji blocks, the arrows, the symbols, the joiner U+200D, the selector
  U+FE0F, and the tag characters of a flag. A letter of a script and a digit
  are not among them. An emoji that passes is no message text under
  `IMP-037`, and it crosses the surface as a string.
- **[IMP-157]** A client MUST take a reaction only for a message that it
  holds in the conversation of the sender (`WIR-282`), and it MUST drop each
  other one. One party holds at most 16 emoji on one message, and a client
  MUST drop an addition above that count. Thus a contact cannot grow table
  `0x0E` past a bound that the messages of the conversation set. A message
  that a deletion takes MUST lose its reactions in the same batch. A reaction
  of this device is a waiting record under the rules of `IMP-152`, and the
  event of a reaction raises no alert.
- **[IMP-154]** An edit MUST change the row of its target in place, under a
  new record key, and the client MUST keep no earlier text. The count of the
  revisions sits in table `0x0D`, and a count above zero is the edited mark
  of `DEV-090`, which a view MUST show beside the time of the message. The
  new text crosses the surface in a draft, as each message text does
  (`IMP-037`). An edit request of this device is a waiting record under the
  rules of `IMP-152`. A sender MUST refuse its own edit after `EDIT_WINDOW`
  of its own store time of the target and after `EDIT_MAX` revisions: the
  contact would discard that edit, and the two devices would then show two
  texts.
- **[IMP-155]** An edit that arrives before its target MUST wait in table
  `0x0C` with its new text, and the target takes that text and the edited
  mark in the batch that stores it. A deletion that waits for the same target
  MUST stay, and a later edit MUST NOT replace it.
- **[IMP-151]** The placeholder of Part 7 §7.5.6 MUST be the row of the
  deleted message itself: the client overwrites the content of that row with
  a record of kind `0x05` that names the `msg_id` of the row, under a new
  record key (`DEV-099`, `DEV-100`). The row keeps its direction, its
  conversation, and its store time, thus the placeholder stands at the
  position of the message. A deletion for the devices of one user, on a
  device set of one device, erases the row and sends nothing.
- **[IMP-152]** A deletion request of this device is a record that waits for
  the send path as each other record does (`DEV-112`). It holds a raw
  `msg_id` under `WIR-070`. A client MUST show it in no view and in no
  summary, and it MUST erase it in the batch that records that a relay took
  it (`WIR-071`). A client MUST keep the time of the last request of each
  conversation in the store, and it MUST refuse a request inside
  `DELETE_RATE_LIMIT` with no change to the store. A lock and a new run do
  not reset that time.
- **[IMP-153]** The surface MUST give a deleted state of a message and no
  text for it, and the event of a deletion MUST carry the conversation and
  no content. The platform MUST NOT raise an alert for that event: a
  deletion is no arrival.
- **[IMP-149]** A stored record MUST hold its `reply_target` as the `msg_ref`
  of Part 6 §6.6 (`WIR-170`). A client MUST make that replacement in the batch
  that stores a received record. A record of this device that waits for a
  relay holds the raw value under `WIR-070`, because the send needs it again,
  and the client MUST make the replacement in the batch that records the
  first delivery state above Queued (`WIR-071`). The raw `msg_id` of a record
  stays in the header of its own row and in no other row (`WIR-073`): a reply,
  a receipt, and a deletion each need it for the wire.
- **[IMP-150]** The surface MUST give the target of a reply as a handle of a
  message of the same conversation, or as absent (`WIR-173`), and it MUST NOT
  give a `msg_id` or a `msg_ref`. The text of the target is message text, thus
  the platform renders it through a sink under `IMP-037`. A draft takes its
  target as a handle, and a client MUST refuse a target of another
  conversation (`WIR-171`).
- **[IMP-148]** A conversation view MUST show the read state as one mark of
  the contact at the newest message that the contact saw, and it MUST NOT
  write a word for that state on each message. The states Queued, Accepted,
  Delivered and Failed stay a word on their message, because each is a fact
  of that one message.
- **[IMP-142]** The short code and the safety number of Part 4 §4.5 are
  public values of the two devices, and they cross the surface as strings. The
  surface MUST give the safety number with no network, from the stored
  channel alone. The confirmation of a short code MUST be a call of its own
  that follows an act of the user, and the event that carries the code MUST
  set no state (`IDN-148`).
- **[IMP-144]** A client MUST ask for the camera of the platform at the moment
  the user opens a scanner, and at no other time. It MUST read a code from a
  frame on the device, and it MUST NOT store a frame or send one. A scanner
  serves the link of an invitation (Part 4 §4.3) and the safety number of
  `IDN-140`, and a device with no camera keeps the pasted link and the short
  code.
- The bundle of an invitation crosses as bytes in an event and in `accept`.
  The bundle holds the send key and the end-to-end key of one queue (Part 6
  §6.6.10), thus this is an exception to `IMP-037`. The platform shows the
  bundle as a link or as a QR code, thus the platform holds it in each
  design. A holder of the bundle can open the queue layer of that one queue,
  and it can send to that queue. The ratchet of Part 5 protects each record
  under that layer.

> *Cause.* The alternative is a signature `send(handle, conv, bytes)`.
> UniFFI maps a `bytes` parameter onto a Kotlin `ByteArray`, thus that one
> signature breaks `IMP-017` at the one point where each message passes. A
> `ByteArray` on the JVM heap moves under a compacting collector, thus no party
> overwrites each copy of it.
>
> The passphrase keeps its stated exception, because a keyboard gives characters
> and no platform lets Rust own that buffer. `CharArray` is mutable, thus the
> caller overwrites it after the copy. §14.4 gives that rule already.

**Nothing crosses the FFI for each packet.** The direction from Rust to the
foreign language is one long-lived event stream. One thread drains that stream,
and that thread calls `AttachCurrentThread` one time, through the
`on_thread_start` hook of Tokio. The Kotlin path runs over JNA. JNA attaches and
detaches a JVM thread at each callback, and the documentation of UniFFI itself
calls that "a heavy operation."

Pin the exact UniFFI version. Treat an increment as a change that blocks a
release. Run a full Kotlin regression after an increment. UniFFI is before 1.0, and it shipped breaking changes across 0.29 to
0.32.

### 14.6.2 Android

- Pin NDK **r28 or newer** in CI. Thus the 16 KB page alignment is automatic.
- Ship `arm64-v8a` only for v1.
- CI has two hard gates. **[IMP-021]** `llvm-objdump -p libumbra.so | grep LOAD` MUST show
  `align 2**14` or higher. **[IMP-022]** `zipalign -v -c -P 16 4` MUST pass.
- If a build has to use NDK r27 or older, inject `-Wl,-z,max-page-size=16384
  -Wl,-z,common-page-size=16384` through RUSTFLAGS explicitly. `cargo-ndk` does
  not do this for you.
- The UI uses Kotlin with Jetpack Compose.

### 14.6.3 Deferred platforms

iOS, the web client of §14.7, and a native desktop shell are outside the v1
scope. Android is the v1 client platform (Part 1 §1.1), and v1 has no
desktop client. §14.7 stays in this part as the design of the web client. Each
rule of it binds that client when it ships and binds no v1
conformance claim. The core keeps the UniFFI annotations and holds no platform
assumption, thus a later platform adds a shell and no core change. An iOS
version has to revisit four items: the notification extension of Part 8, the
secure-element entanglement of §14.6.4, the file protection and the backup
exclusion of §14.6.6, and the reproducible build of a static library. A native desktop shell reuses the extension bundle of
§14.7 in a thin native window, with a code signature of its platform.

### 14.6.4 Storage and keys

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
- The client wipes `K_store` from RAM at a lock. The auto-lock default is 15
  minutes of idle time, and the user can set it up to 30 minutes
  (`IMP-119`).

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

**The stored header.** The client holds the values that open `K_store` again
in one record beside the database. The record holds no secret.

```
WrapHeader {                      // 97 bytes
    version        u8             // 0x01
    m_kib          u32            // the Argon2id memory, in KiB
    t              u32            // the Argon2id passes
    salt_pw        [16]u8         // from the CSPRNG
    nonce_w        [24]u8
    wrapped        [32]u8
    tag            [16]u8
}
```

- **[IMP-116]** A client MUST run Argon2id with one lane, a memory of 64 MiB or
  more, and 3 passes or more. **[IMP-117]** At the creation of the store, a
  client MUST measure one try at that floor on the device, and it MUST raise
  the passes until one try takes about 3 s. A device that needs more than 3 s
  at the floor keeps the floor. The header carries the two values, thus a
  restore on a faster device opens the store and the next passphrase change
  calibrates again. **[IMP-175]** A client MUST refuse a header whose memory
  is above four times the floor, or whose passes are above 3 000, before it
  runs Argon2id: a party with the file that raises the two values would
  otherwise make each unlock allocate without bound.
- **[IMP-118]** A passphrase change MUST wrap the same `K_store` under a new
  `salt_pw` and a new `nonce_w`. It MUST NOT change `K_store`, because each
  record key derives from it.
- **[IMP-119]** A client MUST NOT let the user set an auto-lock above 30
  minutes of idle time, and the default MUST be 15 minutes. The idle time
  is a duration of Part 1 rule `SCP-018`. A client MUST count it from the
  last action of the user on a monotonic source that counts the sleep of the
  device. The device clock MUST have no part in it. A change of the device
  clock neither shortens nor lengthens the idle time. A client MUST NOT lock
  because the device clock moved. Thus no step of the
  device clock keeps a store open above its limit. No such step asks the user
  for the passphrase in the middle of use. The reference client reads the
  time since boot, which counts the sleep, at the last action and at each
  tick. On a platform where it cannot read that time it counts on a
  monotonic source that stops in a sleep. The client then locks late by the
  length of each sleep, and never early.
  **[IMP-140]** A client MUST keep that setting in the store, under the record
  encryption of this section. A client MAY offer a lock at the moment the
  application leaves the screen, and it MUST then keep an idle limit too, for
  a device that stays on the screen with no action.
- **[IMP-141]** A client MUST ask for the current passphrase before a
  passphrase change. It MUST write the new header beside the database before
  it uses that header, because a client that holds a header which the file
  does not hold locks the user out at the next launch.

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
K_row   <- HKDF-SHA3-256( salt = empty, ikm = K_store,
                          info = "umbra/v1/row-id", L = 32 )
row_id  <- HMAC-SHA3-256( K_row, table_id || natural_key )[0..16]
```

- **[IMP-120]** `table_id` MUST be one byte, and `row_id` MUST be the 16 bytes
  of the block above. Both lengths are fixed, thus the `info` and the `ad` of
  the record key parse in one way. `natural_key` is the value that names the
  row in the protocol, such as a contact identifier with a `msg_ref`. Part 5
  §5.11 holds the label.
- **[IMP-121]** A row MAY carry one more indexed column, which is the `row_id`
  of the row that owns it, such as the conversation of a message. A client
  MUST NOT index on another value. From record version `0x02` on, the
  associated data of a record holds the owner column, as the block below
  gives it. A client MUST open each record under the owner that its column
  names. A read of the rows of one owner MUST open each row under that
  owner. Thus a row that a party with the file moved to another owner does not
  open. No caller of the store reads it as a row of that owner. The
  row tag of Part 4 `IDN-033` reads the owner column too, thus the scan of
  `IDN-162` finds a row that a party hid from each owner. A row whose
  plaintext holds no owner, such as a row of table `0x15`, has its owner
  from this binding alone. The owner column of record version `0x01` sat
  outside the associated data. Thus the plaintext of a row that names its
  owner MUST still name it. A client MUST reject a row whose plaintext names
  another owner. That check is the one that covers a row which a
  party moved before the pass of `IMP-130`.

```
record_salt <- 16 bytes from the CSPRNG, stored beside the record
K_rec       <- HKDF-SHA3-256( salt = record_salt, ikm = K_store,
                              info = "umbra/v1/record-key" || table_id || row_id,
                              L = 32 )
nonce       <- 24 bytes from the CSPRNG, stored beside the record
ad          <- 0x02 || table_id || row_id || owner_flag || owner
ct || tag   <- XChaCha20-Poly1305( K_rec, nonce, plaintext, ad )
```

The first byte of `ad` is the record version. `owner_flag` is `0x01` and
`owner` is the 16 bytes of the owner column of `IMP-121`, or `owner_flag` is
`0x00` and `owner` is empty for a row with no owner. The flag fixes each
length, thus `ad` parses in one way. Record version `0x01` had
`ad = table_id || row_id`, which is 17 bytes, and no form of version `0x02`
has that length. The stored record is `record_salt || nonce || ct || tag`
in the two versions, and `K_rec` is the same.

- **[IMP-023]** A client MUST derive the record key with the input set of the
  block above, and with no other input. Part 5 §5.11 holds the label.
  **[IMP-040]** A client MUST make a fresh `record_salt` and a fresh `nonce`
  from the CSPRNG at each write of a record.
- Part 4 rule `IDN-029` puts the version, `table_id`, `row_id`, and the owner
  in the associated data. Thus a party cannot move a record from one row into
  another row, or a row from one owner to another. Part 4 §4.6 states the
  table MAC that rests on this binding. In a store of record version `0x02`
  the row tag of that MAC reads the owner column. In such a store the set MAC
  of Part 4 `IDN-193` reads the first 16 bytes of the MAC of each table. Thus
  one table that a party puts back to an earlier state fails at the unlock.
- **[IMP-041]** A client that discards a record key under Part 7 MUST overwrite
  `record_salt` with zero bytes. Rules `DEV-099` and `DEV-210` of Part 7
  discard that key. Thus no party derives the key again from `K_store`.
  **[IMP-122]** A client MUST NOT open a record whose `record_salt` is zero
  bytes. The record tag stays in the row. The table MAC of Part 4 §4.6 reads
  that tag with each bit inverted for a record with a zero salt. Thus the MAC
  changes at a discard, and the client writes it in the deletion batch
  of the discard. A zero salt that the client did not write then fails the scan
  of `IDN-162`. Without the inversion a party with the file would hide
  a row from each view with no change of a MAC.
- **[IMP-123]** A client MUST write the rows of a commit batch and the table
  MAC of each table that the batch changed in one transaction of the
  database. A crash between the two would leave a table that fails its MAC
  with no attacker.
- A **deletion batch** is a tombstone batch of Part 7 §7.5.6, a retention purge
  of §7.5.2, or a timer expiry of §7.5.8. **[IMP-042]** A client
  MUST open the database with `PRAGMA secure_delete=ON`. **[IMP-043]** After a
  client applies a deletion batch, it MUST run `PRAGMA wal_checkpoint(TRUNCATE)`.
  Part 6 §6.8 rule `WIR-356` gives the test that checks the raw file.

> *Cause.* Part 7 rule `DEV-099` tells a device to discard the record key. A
> record key from `K_store`, the table identifier, and the row identifier
> only does not permit that. A key that a client derives again from a master
> key that it still holds is not discarded. The random salt beside the record makes the
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

- Set `setUnlockedDeviceRequired(true)` on the wrapping key, and no user
  authentication for each use (`IMP-065`). Set `setIsStrongBoxBacked(true)`
  when `android.hardware.strongbox_keystore` is present. If it is not present,
  fall back to the TEE gracefully. A wrapping key in the keystore has no export
  path, thus it does not go into the platform backup of §14.6.6.
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

**The state of the client between two runs.** A platform ends a run of the
network with no notice. Android closes the sockets of an application a short
time after it leaves the screen. Thus the store holds the state that a run
needs to continue each contact: the two queue ends of each channel, the
cursor of the inbound queue, the Double Ratchet session with its skipped
keys, and the braid. It also holds each invitation that waits for its
flight 1, with its one-time prekey.

**[IMP-169]** A client MUST keep a handshake of Part 5 §5.4 that waits for its
next flight in the store: the invitee from flight 1 to flight 2, with its
flight 1, and the inviter from flight 2 to flight 3. **[IMP-170]** The client
MUST erase that state when the handshake ends or fails. An invitee that
starts a run from that state sends its flight 1 again, and an inviter that
read flight 1 already drops the copy (Part 6 `WIR-503`).

> *Cause.* A platform ends a run with no notice, and an application can start
> a second run while the first one runs. A handshake held in RAM alone then
> ends with that run, and the invitation of the other party is spent.

| `table_id` | Table | One row |
| --- | --- | --- |
| `0x00` | Set of tables | No row. Its MAC counts each table of the store (Part 4 `IDN-193`) |
| `0x01` | Messages | One message, under its conversation and its `msg_ref` |
| `0x02` | Tombstones | One deleted message |
| `0x03` | Contacts | One contact: the `RecipientId` of its inbound queue, and the stored channel |
| `0x04` | Queues | Reserved for the queues of the path selection of Part 3 §3.4.6 |
| `0x05` | Verifications | One verification of Part 4 §4.5 |
| `0x06` | Local identity | The root seed, the Recovery Code, the seed of each group, and the mark of `IDN-193`. The row `discovery-roots` holds each identity root from before a reset that still gives the key of a published entry. For each root it holds its seed, a count, and the name of each entry that the root serves. A name leaves the row when the log shows a later rotation of its entry or when its entry goes. A root leaves the row with its last name (`DEV-306`). Part 4 calls these rows, the pairwise salts of the rows of `0x03`, and the rotation counters of the rows of `0x28` together the local identity table |
| `0x07` | Send queue | One record that waits for the send path (`IMP-126`) |
| `0x08` | Invitations | One invitation that waits: the `RecipientId` of its queue, the fragment of its link or its bundle, the queue end, and the prekey seed. A handshake between two flights has its row here too, with its state (`IMP-169`). A queue end that owes its `DEL` has its row here too, in the form `0x08`. Such a queue is one that a rotation, a renewal, or an ended invitation left. The client keeps it until that `DEL` left under Part 3 rule `NET-178`. The form of a queue that a rotation replaced ends with the identifier of its contact. The client reads that queue under the ratchet of that contact until the `DEL` (Part 3 rule `NET-177`). A form with no such tail names a queue that the client reads no more |
| `0x09` | Conversations | What this device alone knows of one conversation: the time up to which the user saw its messages, and the name that the user gave the contact |
| `0x0A` | Settings | One setting of this device under its name, such as the idle time of the auto-lock, the receipts of one conversation, the highest directory epoch (`IMP-159`), or the ingress pins (`REL-153`). Six names hold protocol state. `unanswered/<conversation>` holds the time, in milliseconds, of the first relay acknowledgment of that conversation that no record of the peer followed yet (Part 3 §3.2.6). A record of the peer erases it. `rotation-owed` holds the conversation of each contact whose queue rotation a revocation still owes (Part 7 §7.7 step 2c). `leaving-channels` holds the sync channel and the `device_id` of each revoked device that still waits for the notice of `DEV-313`. `revocation-notice/<device_id>` holds the time of that revocation, in seconds, and the epoch that revokes the device. `key-served/<conversation>` holds the start of the 24 hours and the count of the key requests of that peer that this device answered (`WIR-338`). `held/<message>` holds the wait of one record that a full queue refused (`IMP-082`). It holds the time from which `HOLD_RETRY` counts to its next send and the time of its first `LIMIT`, both in seconds. It also holds the count of its `LIMIT` answers. A relay that takes the record erases it, and the failure of the record at a bound erases it too |
| `0x0B` | Held receipts | One receipt that waits for a slot: the conversation, the kind, the `msg_id` of its target, and the time that it reports (Part 3 §3.5.4) |
| `0x0C` | Pending references | One deletion or one edit whose target did not arrive yet: the conversation, the `msg_ref` of the target, the time of the record, and the new text of an edit. An entry with no text is a deletion (Part 7 §7.5.6). The key of a row is the conversation, the target, and the direction of the record that waits (`DEV-093`). A row of an earlier build has a key with no direction, and it came from the contact |
| `0x0D` | Revisions | How many times the sender of a message changed its text, under the row of that message, in one byte. After a revision that a sync channel gave, the source device and its causal counter follow. They are the high-water mark of `DEV-034` for the copies of that source. A message with no row here shows no edited mark |
| `0x0E` | Reactions | One reaction: the conversation, the `msg_ref` of its target, the direction, and the emoji. One party holds one row for one emoji on one message (Part 6 §6.6.9) |
| `0x0F` | File states | The file of one message, under the row of that message: whether this device uploads it, wants it, holds it, or failed at its transfer, and the media fields of its descriptor (Part 12 §12.3) |
| `0x10` | Files | The plaintext of the file of one message, under the row of that message |
| `0x11` | Chunk credentials | For a file that this device uploaded: the `chunk_id`, the `cred_sk`, and the relays of each chunk, until the erase (Part 12 rules `ATT-160` and `ATT-161`) |
| `0x12` | Group | The stored form of a group: its roster, its epochs, and its replicas. |
| `0x13` | Group Queue | The group queues that a creator asked for and that no relay named yet. A row holds the `group_id`, the replica index, and the relay. |
| `0x14` | Group Join | The offers that this device got and that the user did not answer, and the join records that an admin of this device did not act on. A row holds the `group_id` and then the `JoinRecord`, or nothing for an offer. The owner column names the pairwise conversation. |
| `0x15` | Group Member | The contact behind a member index, for each member that an admin of this device brought in. The roster names no contact, thus a member that another admin added has no row here and the view shows its index alone. A row holds the pairwise conversation, and its owner column names the group. |
| `0x16` | Group Presence | The activity clocks of §11.9.7: for each member that an admin of this device watches, the time of its last record or presence record, and for each group, the time of the last record of this device. The row `watch` of a group holds the time up to which an admin of this device watched that group. A gap of 10 minutes or more in it moves the clock of each member forward by that gap (`GRP-396`). A row holds a `BE64` of seconds, and its owner column names the group. |
| `0x17` | Group Owners | For each group, the member indices that held the owner credentials of this device when it last took or drew them (`GRP-401`). A member that leaves that set leaves with credentials that the relay still takes, thus its departure calls for new ones. The row `gkey` of a group holds what this device knows of its `GKEY` commands, after a version byte: for each replica the `write_pk` of the epoch whose `GKEY` arrived there, and each owner credential that the current one replaced and whose `GKEY` did not arrive yet, the oldest first (`GRP-361`, `GRP-363`, `GRP-401`). The owner column names the group. |
| `0x18` | Group Grants | The granting epochs on the authority path to a current role (`GRP-068`). A row holds one `GroupControl`, under the group and the `epoch_index` of the grant, and its owner column names the group. A grant on no path leaves when the next snapshot is built (`GRP-069`). |
| `0x19` | Notify Relay | The root of each queue relay: `relay_id`, `k_ntf_root`, `relay_idx`. |
| `0x1A` | Notify Group | Each handle group: `handle`, `relay_id`, `k_tok`, the removal secret, the registration state, and the count of its queues. |
| `0x1B` | Notify Queue | Each queue with a binding: `recipient_id`, `handle`, `queue_alias`, and whether its `NBIND` left. |
| `0x1C` | Group Notify | The notify queue of each group of Part 8 §8.5.2: its `RecipientId`, its encoded `QueueAddress`, the time of the last `GNREG` at each of the two replicas, the time the queue was made, and the queue that it replaces until that one leaves (`NTF-105`). |
| `0x1D` | Notify State | The stored form of each notify queue of Part 8 §8.5.2, under its `RecipientId`. |
| `0x1E` | Dead Channel | The dead-channel state of each contact, by conversation: whether the channel is dead and since when, the address of the new queue of this device, the week, the credential and the relays of the blob that this device wrote, and the week and the time of the next fetch. A row MAY end with a tail of one byte `0x01` and one `QueueAddress`. That address is the candidate address of the peer of Part 3 rule `NET-190`. Behind the candidate the tail holds one byte that says whether the record of `NET-191` left for it. Then come the time in seconds at which the client first held it, and the week of the blob that gave it. A row with no candidate, and a row of an earlier build, hold no tail. A row of an earlier build that holds a candidate ends behind its `QueueAddress`. It reads as a candidate that took no record, and its time starts at the next check. |
| `0x1F` | Backup Index | The hash of each row that the last backup object carried, by the table and the surrogate identifier of the row: a delta holds the rows whose hash moved and the rows that left (`IDN-179`). |
| `0x20` | Backup State | The state of the backup of this device: the schedule and the entries of the root with the credentials of their chunks. A backup carries neither. |
| `0x21` | Device Self | The identity of this device, with the flag of its channels. |
| `0x22` | Device Roster | The current roster epoch of the set, and under its index each of the 8 epochs before it that Part 7 `DEV-229` keeps for a peer that missed one. |
| `0x23` | Device Peers | The sync channel of each other device, by its conversation. |
| `0x24` | Sync State | The stored form of the sync engine. |
| `0x25` | Sync Sent | The body of each published record, by its counter, until each peer acknowledged it. |
| `0x26` | Ended Channels | Each sync channel that a revocation ended, by its conversation. The node of the run that ended it still holds it, and the store takes no state of it again. |
| `0x27` | Rendezvous State | The stored form of each rendezvous queue, under its `RecipientId`. |
| `0x28` | Published | Each entry that this device publishes, under its identifier. |
| `0x29` | Requests | Each contact request that waits for the user, under its identifier. |
| `0x2A` | Epoch Held | The epoch-key records that a device that does not own the channels read before the roster object that calls for them (`DEV-303`), under the group and the epoch. The owner column names the group. |
| `0x2B` | Group Records Held | The synced records of a group that this device does not hold yet, by their order of arrival: the subject of the group, then the record (`DEV-299`). |
| `0x2C` | Group State Due | The groups whose state waits to go to the other devices of the set, by their conversation. A row stays until the descriptor went out, thus an app that ends before the upload sends it at its next run. |
| `0x2D` | Directory Heads | Each head of the log that this device accepted, under its `tree_size` (`DIS-063`): the size, the root, the timestamp, and the time of the acceptance. |
| `0x2E` | Blocked | Each block of this device: a contact under its conversation, a member under the group and the index. The value is one byte of the kind, and the count of the records that a block of a group discarded. |
| `0x2F` | Own Epoch | The last roster object that this device posted to a group, under the group conversation. An epoch of another member can take its place under the order of `GRP-117`, and this device then posts it again against the new head (`GRP-119`). |
| `0x30` | Tokens | Each token that this device holds, under its nonce: the epoch, then the encoded token. |
| `0x31` | Token State | Each key of the cross-relay issuer that the log gave, under the epoch: the modulus. Each spent nonce of a token that a hello carried, under the nonce with a leading byte: the epoch. Each proof of work that a hello carried, under its seed and nonce with a leading byte: the epoch. |
| `0x32` | Held Handles | Each held key, under the canonical label input of its handle: the version, then `HK_pub`. |
| `0x33` | Gossip | The gossip state. Each value starts with its kind byte, thus a listing tells the rows apart. |
| `0x34` | Timers | The setting of each conversation: the seconds, the time of the change, and whether the user made it. |
| `0x35` | Deadlines | The deadline of each timed record, under the row of its message: the conversation and the time of the erasure in seconds. |
| `0x36` | Polls | The close time of each poll, under the row of its message: the conversation and the time in seconds, or 0 for no close. |
| `0x37` | Votes | The last vote of each voter on each poll. |
| `0x38` | Mentioned | The mark of each message of a group that names this member (Part 11 §11.11), under the row of the message. The mention list itself stays in the record, and no view shows it (`GRP-141`). |
| `0x39` | Moderated | The moderation state of each message of a group, under the row of the message: the conversation, the action, and the role of the actor. A target that did not arrive yet takes its state at its arrival. |
| `0x3A` | Mod Notes | One row for each moderation epoch that this device applied: the conversation, the time, the role of the actor, and the count of each act (`GRP-089`). |
| `0x3B` | Group Sender | The member index that sent each message of a group that arrived, under the row of the message: the conversation and the index. |
| `0x3C` | Roster Notes | One row for each change of a roster that this device applied: the conversation, the time, the kind, the member index, and the role. |
| `0x3D` | Key Changes | The notice that waits for the answer of the user in each conversation, under the row of the conversation: the conversation, the new X25519 key, the new ML-KEM key, and the time of its arrival. |
| `0x3E` | Reset Notices | The key-change notices that no relay took yet: the conversation, the time at which the notice goes, and the record. A row stays until a relay accepted its notice. The row of a notice on the send path holds the time `2^64 - 1`. A notice that reached no relay takes a new delay of `IDN-064` in the commit of its failure. |
| `0x3F` | Shares Held | The last share that each contact gave to this user, under the row of the conversation: the conversation, the time, and the `RecoveryShare` body. |
| `0x40` | Shares Given | The share of the current split that each holder took, under the row of the conversation: the conversation, the time, and the index, the threshold, and the count. |
| `0x41` | Group Unsent | Each record of this device that no replica accepted yet, as it was sealed, with its credentials, its message, and its place in the order of the posts. The next session sends the same bytes (`GRP-392`). A roster object moves the group of this device at its seal, thus a lost one splits the group. A presence is no such record. |
| `0x42` | Intros | One row for each introduction that waits: the kind, the conversation of the other party of the record, the third conversation of a request of this device, the two names, and the invitation of an offer. |
| `0x43` | Send Index | The message of this device that each `send_index` of a conversation named, under the row of the conversation and the index. The index wraps at 65 536, and a later record takes the place of an earlier one. |
| `0x44` | Key Asked | Each key request of this device, under the conversation and the index, with the time of the request for its rate (`WIR-337`, `WIR-347`), and a mark of one byte beside it when its supply came. A request older than 24 hours names another record, since the index wraps. |
| `0x45` | Roster Hashes | The SHA3-256 of each roster epoch that this device applied, by its index (`DEV-228`). |
| `0x46` | Roster Parent | The `Parent` of the head, in one row. |
| `0x47` | Roster Forks | Each fork that the view shows, by its index, its signer and its kind. |
| `0x48` | Sync Holes | Each hole of a source device, by the device: the device, the first and the last counter, the time that this device first saw it, and the label. |
| `0x49` | Drafts | The draft of each conversation, as UTF-8, by the conversation. |
| `0x4A` | Recovery | The state of the recovery of each group: `WANTED` and the time of the request, or `NOTICED`, the roster epoch and the descriptor. |
| `0x4B` | Catchup In | The descriptor of each catch-up object that a peer sent, by the conversation of its sync channel. |
| `0x4C` | Sync Origin | The source device and the causal counter of each message that a peer synced, by the row of the message. |
| `0x4D` | Held Deletions | Each message that a deletion of another device names after a restore, by its row, with its conversation. It waits for the user (`DEV-118`). |
| `0x4E` | Rekey Held | The re-key items of `DEV-301` that did not apply yet, under the subject of the group: the time of arrival in seconds, the subject, then the item. The group can come later on the chunk path, and the roster epoch before the re-key on the sync channel. |
| `0x4F` | Failure | The cause of each failed message of this device, under the row of the message: a relay refused it, no path took it, its file did not upload, no replica of the group took it, or the queue of the contact was full (`IMP-074`) |
| `0x50` | Publish Pending | The copy of each record of a contact that goes to the other devices of the set, written in the commit of the record: its place, as the time of the commit in milliseconds and its index in the batch, the conversation, then the record (`DEV-293`). The publish sends the copies in the order of their places and drops each one. A copy that a crash left goes with the next commit. A row of an earlier build holds no place, and it goes first. |
| `0x51` | Pairwise Held | Each synced record of a conversation whose identity entry did not come yet, under a random row: the subject, the order of its arrival, its deadline or 0, whether the user wrote it, then the record (`DEV-294`). The entry replays them. |
| `0x52` | Sync Inbox | Each record that the sync engine took and the store did not take yet, written in the commit of the engine (`DEV-013`). |
| `0x53` | Add Seq | The add of each joiner whose admit waits, under the row of the kept record of the add: the row of the join, the joiner, the group, the index, the replicas that returned a `GSEQ` and the `seq` at each, then the descriptor of the snapshot once it uploaded (`GRP-311`, `GRP-424`). |
| `0x55` | Erase Due | The erase of each object that this device put on the chunk path, until each relay answered its `CDEL` or `CHUNK_LIFE_MAX` of Part 12 passed (`ATT-160`, `ATT-161`). A row of kind `0x01` holds the chunks of one uploaded file, under the row of its message. It holds the kind, the time of the upload in seconds, then the credentials as a row of `0x11` holds them. A second row of one byte `0x00` beside it is its hold. The upload writes the two, and the deletion of the message takes the hold away in the batch that takes the row of `0x11`. Thus the first row is due from then on (`IMP-164`). A message leaves with no erase of its chunks at the end of the history period, at a removal by a moderator, or with its conversation. Such a message takes the two rows along. A hold with no row of `0x11` is such a message, and the client deletes the two rows at the next start with no `CDEL`. A row of kind `0x02` holds one object of a device link of Part 7 `DEV-003`, under its `chunk_id`. It holds the kind, the time of the write, then the credential. It has no hold, and it is due when its link runs no more. No row names a conversation in its owner column. A backup of Part 4 §4.7.2 does not carry this table. The identifier `0x54` names no table. |

The stored form of a row is local to one device, and no peer reads it. This
part gives it no byte layout. **[IMP-130]** A stored object MUST start with a
version byte, and a client MUST reject a row whose version it does not read.

The record layer has a version of its own, which is the first byte of the
associated data above. The store holds one record version. The present
version is `0x02`. A new store starts at it. A store of version `0x01` is
one whose set MAC verifies in the first form of Part 4 `IDN-033`, or one
with a table and no set MAC. Under `IMP-130` a client MUST move such a
store to version `0x02` in one pass, in the unlocked session that first
writes a record, before that write:

1. For each table, the client opens each record of version `0x01` and seals
   it again under version `0x02`. The new seal uses a fresh `record_salt`, a
   fresh `nonce` (`IMP-040`), and the owner that the column of the record
   names. It leaves a
   record that is of version `0x02` already, and a record with a zero salt.
   It commits the records of one table in one batch or more, each with the
   table MAC of the first form (`IMP-123`). Thus a pass that a platform ends
   leaves a store of version `0x01` that verifies at the unlock, with some
   records of version `0x02`. The next pass takes the rest. The client
   MUST read one row at a time. It MUST NOT hold a table in RAM, because one
   row of table `0x10` is a whole file. A batch holds at most 4 MiB of
   sealed records and at most 256 records. A record above 4 MiB is a
   batch of its own. The client holds one record in the clear for the time
   of its seal, and it overwrites that plaintext when the seal ends.
2. In one last transaction the client writes the MAC of each table and the
   set MAC in the second form of Part 4 `IDN-033` and `IDN-193`. That
   transaction is the mark of version `0x02`.

Before the mark a client MUST read a record of each of the two versions. After
the mark a client MUST NOT open a record of version `0x01`. Such a record
is a fault of the file, and the client reports it in the manner of Part 4
`IDN-039`. No path leads back. A set MAC of the first form does not verify the
table MACs of the second form. A table MAC of the first form does
not cover a record that the pass sealed again. A table that did not match
its `accum` before the pass MUST NOT match it after. The client carries the
difference into the `accum` of the second form. Thus the scan of `IDN-162`
reports after the pass what it would have reported before. The pass reads
each row, thus it sees that difference itself. A client that runs the pass
at the unlock MUST report a table that did not match in the manner of
`IDN-039` when the pass ends, and not only at the later scan. A party can put
back the MACs of the first form, to pass a record of version `0x01` with a
changed owner column through the pass. That party shows in this way, unless it
puts back the full file. Part 4 §4.6 states that one residual, which is a
full file of version `0x01` that a party puts back.

A pass that a fault of the storage ends, such as a full disk, is no sign of a
party with the file. The client MUST NOT report it in the manner of
`IDN-039`. The client MUST NOT run the pass a second time in that unlocked
session. Each write of the session fails with the fault of the pass, and
the next unlock runs the pass again. The commit counter of a table goes up
through each batch of the pass and through the mark (`IDN-068`).

- **[IMP-158]** The stored form of a contact and of an invitation MUST name
  the relay that holds its inbound queue, because a new run builds a circuit
  to that relay before it subscribes (`NET-308`). The stored channel names the
  relay of the outbound queue. Version `0x01` of the two forms named no
  relay of the inbound queue. A client MUST read that version and MUST write
  the present version at the next commit of the row. A store of that version
  came from a network with one queue relay. Thus the client MUST take the
  relay of the outbound queue as the relay of the inbound queue of a
  contact, and the relay that the stored bundle names as the relay of the
  queue of an invitation.
- **[IMP-160]** The plaintext of a file MUST sit in the at-rest store and
  in no other place on the device: no cache file, no temporary file, and no
  platform media store. A client MUST put the file of a draft into the store
  at the send, before the first chunk leaves. Thus an upload continues after
  a new start with no second read of the source, which the platform can
  take away. **[IMP-161]** A lock MUST take each file job out of the memory,
  because a job holds its file in the clear, and an unlock MUST make the jobs
  again from the store.
- **[IMP-162]** The record of a file holds its descriptor (Part 6 §6.6 kind
  `0x02`), and the descriptor exists when the relays hold each chunk. Thus a
  client MUST store the message with no descriptor at the send, MUST NOT
  give that record to the send path, and MUST write the descriptor into the
  row and queue the record when the upload ends. An upload that fails MUST
  give the message the delivery state `failed`.
- **[IMP-163]** A client MUST start a download for each received record of
  kind `0x02` whose descriptor it can read and whose `padded_size` is at most
  the automatic download limit of `IMP-167`. A descriptor that does not
  parse, or that has a level that the client does not build, MUST show as a
  file whose transfer failed, and the message MUST stay. A client MUST let
  the user start a failed download again.
- **[IMP-167]** A client MUST let the user set an automatic download limit
  for the device: off, or a size. With no choice of the user the limit is
  `AUTO_DOWNLOAD_DEFAULT` of Part 12 §12.7. The limit applies to each class
  of file. A file above it MUST show its class, its size, its name, and its
  preview of Part 6 rule `WIR-533` with no chunk fetched, and its download
  MUST start at a tap of the user. The limit is a setting of the device, and
  the backup of Part 4 §4.7.2 does not carry it.

  > *Cause.* A user on a metered plan or a slow link cannot stop a download
  > that starts at arrival, and a video of `MAX_FILE_SIZE` costs about
  > 253 MiB at one replica (Part 12 §12.7.2). A download at a tap has a
  > cost too: it shows the chunk relays of the file when the user opened the
  > conversation. A download at arrival shows them the arrival alone. The
  > default keeps each photo and each document at arrival, and a large video
  > waits.
- **[IMP-168]** A client MUST let the user limit the automatic download to a
  network that the platform does not mark as metered. With that limit on, a
  file that arrives on a metered network MUST wait as a file above the limit
  of `IMP-167` does. When the device moves to a network with no such mark,
  the client MUST start the download of each file that waits and whose
  `padded_size` is at most the limit. That choice is a setting of the
  device, as the limit is.
- **[IMP-171]** A client MUST record a voice object of Part 12 into the
  memory alone. The recording MUST NOT sit in a file, as `IMP-160` states
  for each file. **[IMP-172]** A client MUST end a recording at
  `VOICE_MAX_SECONDS` (`ATT-071`), and it MUST drop a recording that the
  user leaves: a close of the conversation, or a lock. **[IMP-173]** The
  encode of a recording MUST carry no comment field and no time of the
  capture (`ATT-155`). An Opus stream in OGG holds its vendor string in its
  comment header, and that string names the encoder library alone.

  > *Cause.* A recorder of the platform writes to a file by default, and a
  > file under the cache of the app outlives a crash. A recording that stays
  > after a lock is a plaintext that the lock of `IMP-161` does not reach.
- **[IMP-164]** A deletion of a message MUST erase its rows in the tables
  `0x0F`, `0x10` and `0x11` in the batch that takes the message, and for a
  file that this device uploaded it MUST then send the `CDEL` of `ATT-161`
  for each chunk to each relay of that chunk. The credentials of those
  chunks outlive the message for that purpose alone. The copy in table `0x55`
  stays after the batch, across each lock and each new start. It stays until
  each relay answered the `CDEL` or until `CHUNK_LIFE_MAX` of Part 12
  passed since the upload, and the client then erases it. That copy holds
  `chunk_id`, `cred_sk` and the relays of each chunk, and neither the file
  key nor a name of the conversation. A `CDEL` whose answer a lock or a new
  start lost goes again in the next run.
- **[IMP-159]** A client MUST keep the highest epoch of a `DirectoryRoot`
  that it verified in the settings table, and it MUST give the larger of
  that value and the shipped epoch of `REL-045` to the consensus at each
  start. Rule `REL-034` of Part 10 binds nothing in a run that forgot the
  last one. The stored value MUST NOT go down.
- **[IMP-131]** A client MUST commit each change of a channel to the store
  before it writes a byte of that call to the link. A ratchet record that
  left the device under a state that the store does not hold lets a restart
  seal a second record under the same message key and the same nonce.
- **[IMP-132]** A client MUST commit a received record and the channel state
  that opened it in one batch of `IMP-123`. A state without its record loses
  the record, because the message key is gone. `WIR-115` puts the `ACK`
  after that batch.
- **[IMP-133]** A client MUST replace the row of a channel at each commit,
  and it MUST NOT keep an earlier state of a channel. An earlier state holds
  chain keys that the forward secrecy of Part 5 §5.5 erased. The
  `secure_delete` setting and the truncation of the write-ahead log of this
  section apply to that row. The truncation follows a commit that replaced
  the row of a channel, once for the commit whatever the count of its rows.
  The first row of a channel replaces no state, and it asks for none.
- **[IMP-134]** At the start of a run a client MUST send a `SUB` for each
  stored queue. It MUST then send an `ACK` at the last sequence number that
  it acknowledged, when that number is above zero. The `ACK` of the last run
  can be lost with its link, and a relay would deliver those records at each
  later `SUB`. A relay takes an `ACK` at or below its cursor as no change.
- **[IMP-135]** A record that arrives a second time at or below the stored
  cursor, or at a stored sequence number above it, MUST NOT reach the
  ratchet. The cursor drops it, and the `ACK` covers it.
- **[IMP-143]** A record that the client uses itself gives no message: a
  queue address, a record of a ceremony. The cursor of its queue covers it,
  thus its `ACK` follows the commit of the channel state that it moved, in
  the same slot and under the same floor as the `ACK` of a message (Part 3
  §3.5.4).
- **[IMP-145]** The surface MUST take the state of the app, on the screen or
  not, from the platform layer, and the runtime MUST select the cover tier of
  Part 3 §3.6.2 from that state alone. A lock, a privacy mode, and a setting
  of the user MUST NOT change the tier (`NET-061`).
- **[IMP-136]** A client MUST delete the row of an invitation in the batch
  that follows the flight 1 that consumed its prekey, before flight 2
  leaves. Part 5 rule `CRY-089` erases the prekey at that point.
- **[IMP-137]** A record that waits in the send queue at the start of a run
  MUST go again under its `msg_id`. The receiver drops the second copy by
  that `msg_id`.

The high-water mark of `DEV-089` rests on the sender-chain position of a
record. The v1 node gives the store a record and no position,
thus the store applies each edit in the order of its arrival. Each queue
delivers in order, and the one device that reads a pairwise queue publishes
each edit on the sync channels in the order that it took it, thus the order
holds but for a late resend of an earlier edit.

`IMP-169` and `IMP-170` keep a handshake between its flight 1 and its flight 3
in the store, thus a run that ends inside that window loses no handshake.

### 14.6.5 No hardware attestation for anti-abuse

**[IMP-029]** Relay reputation MUST come from the mechanisms of Part 10 §10.3
and Part 10 §10.4 only. Those sections give the class tests of the
authorities and the negative link reputation, and Part 10 rule `REL-077`
keeps a client from signing a report. **[IMP-030]** Relay reputation MUST NOT come from device
attestation. **[IMP-031]** Relay reputation MUST NOT come from a "genuine device"
proof.

Quarkslab (2026-08-11) showed a Frida-hooked relay of a genuine attestation
chain, from a clean oracle device, with no compromise of the secure hardware. If
UMBRA validates an Android attestation chain for a function, a check of
`attestationApplicationId` is mandatory. That field holds the package name and
the digest of the signing certificate. The omission of that check is the hole
that the attack used.

### 14.6.6 Platform egress

Part 2 §2.2 gives adversary A7, which is the platform of an honest device and
the software that shares that device. Each rule below names one platform
interface, and it states what the client gives to that interface. A **platform
store** is a location that the client does not encrypt under §14.6.4. The
platform media store, the platform backup, the task snapshot, and the clipboard
are platform stores.

**Each social affordance stays.** A user can save a file, copy a message, and
take a screenshot. Each of those is an explicit user action, and no rule below
removes one. Part 2 rule `THR-013` names those actions as its one exception.

**The decrypted attachment.**

- **[IMP-044]** A client MUST write a decrypted attachment inside the encrypted
  store of §14.6.4. **[IMP-045]** A client MUST NOT write a decrypted attachment
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
> a store that no key opens. §14.6.4 entangles the storage master key with a
> secure-element key that never leaves the device. Thus the platform
> backup gives a copy to a party that Part 15 §15.1 did not list, and it gives
> the user nothing.

**The task snapshot.**

- **[IMP-055]** A client MUST draw a cover view over each conversation surface
  before the application leaves the foreground. Thus the task snapshot of the
  platform holds the cover and not the conversation. On Android 13 or newer a
  client also calls `setRecentsScreenshotEnabled(false)`. Before Android 13
  a sheet is a window of its own above the cover, thus it takes
  `FLAG_SECURE`; the conversation under it keeps its screenshot of
  `IMP-059`.

**The clipboard and the input method.**

- **[IMP-056]** An Android client MUST mark a copied message as sensitive with
  `ClipDescription.EXTRA_IS_SENSITIVE`.
- **[IMP-057]** An Android client MUST set `IME_FLAG_NO_PERSONALIZED_LEARNING`
  on each composer and on the passphrase field. It MUST also keep each
  passphrase field, and each view under it, out of the autofill of the
  platform and out of its content capture
  (`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS` and
  `IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS`). An autofill
  service that saves the passphrase holds it outside the device, and a
  content-capture service reads each text of a view. The reference client
  sets the two on the root view, thus on each view of the application.

**The screenshot and the accessibility tree.**

- **[IMP-058]** A client MUST offer a screenshot block as a setting of one
  conversation, and not as a global setting. On Android that block is
  `FLAG_SECURE` on the window of that conversation.
- **[IMP-059]** A client MUST NOT block a screenshot in a conversation by
  default. Part 13 §13.10 makes a report about a private conversation a
  screenshot.
- **[IMP-060]** A client MUST NOT hide a message from the accessibility tree.
  An accessibility service serves a user that cannot see the screen, and a
  hidden message is a hidden conversation for that user.

> *Cause.* The rules of §14.4 and §14.6.1 constrain the representation that
> crosses the FFI, and they stop no export. The input method that fills a
> composer is a separate process, and it reads the passphrase that feeds
> Argon2id. The task snapshot is a rendered bitmap that the platform writes at
> each background transition, and no key protects it. The auto-lock of §14.6.4
> wipes the master key, and a bitmap needs no key. A rule about where data goes
> is cheaper than a lost feature. Thus each social affordance stays, and each
> rule names an interface.

## 14.7 The web client

**The web client is deferred.** Part 1 §1.1 puts it outside v1, as it puts
iOS, and no v1 build holds it. This section keeps the design,
and each rule of it binds the web client when it ships. The web client is
the same
Rust core, compiled to `wasm32-unknown-unknown`, in a browser extension. This
section gives its form, its role in the device set, its transport, its
storage, its randomness and notifications, and its build. Each rule of this
specification binds the web client, except where a rule below names an
exemption and its cause. The performance question is not a cause: the measured
mean slowdown of WebAssembly is 1.45 to 1.55 times, and ML-KEM-768
encapsulation takes 29 µs natively.

### 14.7.1 The form: an extension, and not a hosted page

Three properties of the browser shape the web client. This section gives
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
   origin, and one browser does that after 7 days with no interaction. §14.7.2
   makes the web client a linked device, thus an eviction costs one link and
   no identity.
3. **Sockets.** A browser gives WebSocket, WebTransport, and `fetch` only.
   §14.7.3 gives the transport, and it states what the ingress relay learns.

**This is a trade, and Part 2 §2.4 requires the text to state it.** Each
browser vendor operates the one store that its browser installs from, thus
each vendor is a gatekeeper of the web client, and Part 15 §15.2.11 records
that. A user without the extension has no web client, and a link in a message
does not give one.

> *Cause.* The core builds for `wasm32` under §14.2.4, the extension form
> holds trust assumption 4, and the linked-device role removes the identity
> from the evictable store. The third property stays as a property of the
> transport, and §14.7.3 states it.

### 14.7.2 The role: a linked device

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

### 14.7.3 The transport

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
from a native client. Part 3 §3.8.1 states that trade, and Part 15 §15.3 holds
the row.

### 14.7.4 Storage and keys

The web client holds its store in the IndexedDB of the extension origin, under
the record construction of §14.6.4.

- **[IMP-104]** A web client MUST encrypt each record with the record key of
  §14.6.4, and it MUST keep each metadata-sensitive column inside the encrypted
  blob. **[IMP-105]** A web client MUST store in the IndexedDB of the extension
  origin only, and it MUST NOT use the sync storage area of the browser, the
  local storage area, or a cookie. A sync storage area copies to the account of
  the user at the browser vendor.
- **The wrap.** A browser has no secure element. **[IMP-106]** A web client
  MUST make `k_se` of §14.6.4 as a non-extractable HMAC-SHA256 key of the Web
  Cryptography API, and it MUST compute `S` with that key. The key has no
  export path, thus a copy of the store opens with the passphrase and that
  browser profile only. The key gives no rate limit against a party that runs
  script inside the profile, and Part 15 §15.3 holds the row.
- **[IMP-107]** A web client MUST calibrate Argon2id to about 3 s for each try
  in the browser, in the manner of §14.6.4.
- **Deletion.** IndexedDB has no `secure_delete`. **[IMP-108]** A web client
  that applies a deletion batch of §14.6.4 MUST overwrite `record_salt` and the
  ciphertext of each record with zero bytes, and then delete the record. The
  storage engine of the browser can hold the earlier bytes until it compacts,
  and Part 15 §15.3 holds the row. Rules `IMP-042` and `IMP-043` bind the
  SQLite store of the Android client only.
- **[IMP-109]** A web client MUST call `navigator.storage.persist()` at the
  first launch, and it MUST treat a refusal as no error.

### 14.7.5 Randomness, notifications, and the interface

- Rule `IMP-090` names `crypto.getRandomValues` as the platform source of the
  web client, and rule `IMP-093` applies the hardening of Part 5 §5.9 to it.
- The web client holds a live session while the browser runs, and it registers
  no push token. Part 8 §8.6 gives that rule. A message that arrives while the
  browser does not run waits at the queue relay, and the phone of the user
  gets its notification under Part 8. **[IMP-110]** The settings of a web
  client MUST state that the browser receives messages while it runs, and that
  the phone receives each notification.
- The platform egress rules of §14.6.6 name Android interfaces. On the web
  client the platform stores are the clipboard, the download location, and the
  browser profile. **[IMP-111]** A web client MUST apply `IMP-044` to
  `IMP-047` with the download location as the platform media store.
  **[IMP-112]** A web client MUST state that the screenshot block of `IMP-058`
  is not available in the browser, because a browser gives no equivalent of
  `FLAG_SECURE`.
- Part 2 §2.4 goals U5 and U8 name an Android device, and they do not measure
  the web client. §14.9 binds the web client in full.

### 14.7.6 The build and the crate

- The web surface is the `umbra-web` crate of §14.1. It holds the
  `wasm-bindgen` bindings, the WebSocket transport behind the transport trait,
  and the IndexedDB adapter behind the storage trait. It uses no UniFFI, and
  the `wasm-unstable-single-threaded` feature of UniFFI stays off.
  **[IMP-113]** The `umbra-web` crate MUST NOT add more transitive crates than
  its row in §14.2.3.
- The rule numbers `IMP-114` and `IMP-115` are retired, and no rule uses them.
- **Constant time.** The browser compiles the WebAssembly binary, thus the
  source-level ban of §14.5.1 is the one control of the project. Part 15 §15.3
  holds the row.

## 14.8 Build reproducibility and binary transparency

Trust assumption 4 of Part 2 §2.6 says that *the client binary that the user
runs is the binary that the auditor examined*. v1 gives no method to check
that assumption. The release build pins its toolchain (§14.5.1) and holds
`Cargo.lock`. No independent party rebuilds a release, and the project runs
no binary transparency log. Part 15 §15.5 states the result.

The rule numbers `IMP-032` and `IMP-033` are retired, and no rule uses them.

## 14.9 Degraded states and the interface

Part 2 §2.4 sets goals that assume an interface. U1 assumes a first launch
with no security screen. U6 assumes that a user sees a record that no relay
accepted. Part 13 rule `ABU-008` assumes a progress indicator. This section
gives those assumptions a closed set of states and a rule for each one.

### 14.9.1 The delivery states

Each outbound record is in one state of the table below, and the table is
closed. Part 7 §7.5.3 converges the state across the device set.

| State | Condition | The client shows |
| --- | --- | --- |
| `queued` | The client holds the record, and no relay acknowledged the `SEND` | One mark for a queued record |
| `accepted` | A relay acknowledged the `SEND` under Part 3 §3.7 | One mark for an accepted record |
| `delivered` | A delivery receipt of Part 6 §6.6.9 arrived. Part 3 rule `NET-059` keeps receipts off by default and `NET-041` makes a client emit one only with the setting on. Thus this state is reachable only when the peer turned them on. No rule of Part 3 needs this state: a silent channel of Part 3 §3.2.6 rests on `accepted` and on the records of the peer | One mark for a delivered record |
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

### 14.9.2 The eight degraded states

A client is in one or more of the states below, or in none. Each state names
its condition, its end, and the one line that the client shows.

| State | Condition | The state ends when | The client shows |
| --- | --- | --- | --- |
| `offline` | The device holds no network route | A route returns | "No connection. Messages wait." |
| `ingress unreachable` | Both pinned ingress relays of Part 10 §10.6.1 refuse or time out, with a route present | One ingress accepts a connection | "The relays do not answer. Messages wait." |
| `provisional directory` | The client holds a `DirectoryRoot` below `AUTHORITY_FLOOR`, under Part 10 rule `REL-126` | A root at or above the floor arrives | "The relay directory is provisional." |
| `admission surge` | The newest `PowChallenge` of a relay in use holds `effort` above 0, under Part 13 §13.8 | The effort returns to 0, or the client spends a token | A progress indicator during each solve, under `ABU-008` |
| `recipient queue full` | A `QUOTA` of Part 3 rule `NET-017` names the queue of a contact | The relay stops the signal | "This contact has not collected messages for a while." |
| `notification carrier absent` | The build holds no carrier of Part 8 rule `NTF-040` for the selected mode | The user selects a mode that the build carries | The line of `NTF-040` |
| `corrected clock` | The clock state of Part 10 §10.5.2 is `corrected` (`REL-116`) | A root gives a correction at or below `CLOCK_SKEW`, or a clock movement discards the correction | "The clock of this device differs from the network time by more than one hour." |
| `clock` | `NTF_FAIL_MAX` consecutive notification blobs failed to open inside the window of Part 8 rule `NTF-075`, or a held group record names a slot above the window of Part 11 rule `GRP-229` | One blob opens after a fresh `k_ntf_root`, or no held group record names such a slot | "The device clock may be wrong. Notifications show no preview until it is checked." |

**The route view.** Part 3 rules `NET-201`, `NET-343` and `NET-350` require a
display of each circuit, and this paragraph gives it. The client holds a
connection view that the user reaches from the settings. The view lists the
pinned ingress relay and the standby relay, each with its host and its country.
It then lists one row for each circuit that the client holds. The row
of a circuit names the country code of each hop in the order of the chain,
as "DE → NL → SE". A row gains one of the two strings below after the
countries, with a separator.

| Rule | Identifier | The string | The condition |
| --- | --- | --- | --- |
| `NET-343` | `umbra.ui.net-343` | "one operator" | Two hops of the circuit share an operator or a family |
| `NET-201` | `umbra.ui.net-201` | "one jurisdiction" | Two hops of the circuit share a jurisdiction bloc, under `NET-200` or under `NET-350`, and the row does not already carry the string of `NET-343` |

The line of the `provisional directory` state above names the state. The string
of `NET-343` on each row names what it means for a circuit: one
operator runs two ends of it. A circuit of one autonomous system, one prefix
or one server under `NET-350` and `NET-351` exists only in a provisional
network. There the row carries "one operator" already. The route view shows
no relay identity beyond the host of the two pins, and it is a display and
no control.

- **[IMP-077]** A client MUST show each current degraded state in one line at
  the top of the message list. **[IMP-078]** A client MUST NOT show a degraded
  state as a security failure. **[IMP-079]** A client MUST NOT block the
  message list, the composer, or a send in a degraded state.
- **[IMP-080]** A client MUST leave a degraded state without a user action when
  its condition ends. **[IMP-081]** A client MUST NOT add a degraded state to
  the table without a row in Part 2 §2.4.
- **[IMP-082]** In the `recipient queue full` state, a client MUST keep the
  record `queued`. The relay holds `QUEUE_QUOTA` records of Part 3 §3.2.4, and
  the sender holds the rest. The record goes again after `HOLD_RETRY` of 15
  minutes, and each later wait is twice the wait before it. The bounds of
  Part 3 rules `NET-219` and `NET-220` apply. At the bound the record
  goes to `failed` with the full queue as its cause, and the state of this
  rule ends for it. A `QUOTA` that names room ends the state, and each held
  record goes at once. The full state of a conversation is the memory of
  one run. The wait of a held record and the two counts of its bounds are
  in the store (table `0x0A`). Thus a new run, an unlock, and a new process
  send no held record before its time. Part 3 §3.7 states the v1
  limits beside `NET-222`.

> *Cause.* Part 9 names a degraded read, Part 10 names a provisional
> directory, Part 8 names a missing carrier, and Part 13 names a progress
> indicator. Without one list of the states, two implementations show two
> different sets. A user that sees "connecting" for an hour deletes the
> application, and a user that sees a red banner for a provisional directory
> reads it as a compromise. The one line for each state and the rule against a
> block keep U1 and U6 honest.

### 14.9.3 The interface strings

Rules of this specification require the interface to show a string. Examples
are `NTF-009`, `ABU-040`, `IMP-050`, and the lines of the table
above. A translation that drops such a string breaks the rule in that locale.
The test of `IMP-086` finds that fault.

- **[IMP-083]** Each string that a rule of this specification requires the
  interface to show MUST carry a stable message identifier. **[IMP-084]** That
  identifier MUST be `umbra.ui.` followed by the rule identifier in lower
  case. **[IMP-085]** A revision MUST NOT change an identifier.
- **[IMP-086]** A test MUST check that each identifier resolves to a non-empty
  string in each shipped locale. **[IMP-087]** A release MUST NOT ship a locale
  that fails that test.

### 14.9.4 Accessibility

- **[IMP-088]** The interface MUST meet WCAG 2.2 at level AA. **[IMP-089]** Text
  MUST hold a contrast ratio of 4.5:1 or more against its background. Part 4
  rule `IDN-016` states the same bound for the identicon palette, and rule
  `IMP-060` keeps the accessibility tree whole.

## 14.10 Randomness

Part 5 §5.9 hardens each random value under RFC 8937, and trust assumption 2
of Part 2 §2.6 rests on the source below that hardening. This section names
the platform half.

- **[IMP-090]** A client MUST take each CSPRNG output from the platform source,
  which is `getrandom` on Android and `crypto.getRandomValues` on the web
  client of §14.7.
  **[IMP-091]** A client MUST NOT hold a userspace generator that it seeds one
  time. **[IMP-092]** A relay MUST take each CSPRNG output from `getrandom` of
  its kernel.
- **[IMP-093]** A client MUST apply the hardening of Part 5 §5.9 to each value
  that the platform source gives. The hardening secret `K_rng_harden` of Part 5
  §5.2 lives in the encrypted store of §14.6.4. Thus a platform generator that
  fails after the first launch shows no raw output on the wire. A client
  holds `K_rng_harden` in RAM from the unlock to the lock and at no other
  time (`IMP-127`). Thus a locked client, and a client before its first
  unlock, draws each value from the platform source alone. A locked client
  runs no network runtime, thus it makes no key of a session and no
  identifier of a queue in that state.
