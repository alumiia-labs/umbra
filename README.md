# UMBRA

UMBRA is a messenger protocol with a reference implementation. It gives
private, post-quantum, metadata-resistant communication between persons.

- **Content.** Only the intended recipients can read a message. This holds
  after a quantum computer becomes available.
- **Metadata.** No one party can rebuild who speaks to whom, at what time,
  and from which location. This applies to the relay operators too.
- **Usability.** An account needs no phone number and no email address.

**Status: draft, version 0.x.** No independent party has audited the
protocol or the code. Do not use UMBRA where a failure puts a person at risk.

## The repository

| Folder | Content |
| --- | --- |
| `spec/` | The specification, in 15 parts. `spec/req-index.md` lists each rule. |
| `crates/` | The Rust core, the relay, and the FFI layer. |
| `android/` | The Android app, in Kotlin and Compose. |
| `deploy/` | The Ansible playbooks for a relay network. |
| `site/` | The web site of the invitation links. |
| `brand/` | The logo files. |
| `scripts/` | The build scripts and the check scripts. |
| `tests/` | The test vectors and the fixtures. |

Start with `spec/01-scope-and-conventions.md` and `spec/02-threat-model.md`.
Part 15 lists what UMBRA does not protect against.

## Build and check

The pinned Rust toolchain is in `rust-toolchain.toml`.

```sh
cargo test --workspace
bash scripts/check.sh           # the full check set of each commit
```

`android/README.md` gives the build of the app. `deploy/ansible/README.md`
gives the deployment of a network.

## Security

`SECURITY.md` gives the procedure for a vulnerability report.

## License

AGPL-3.0-only. Refer to `LICENSE`. The icons of
`android/app/src/main/assets/fa` are Font Awesome Free, under CC BY 4.0. The
fonts are under the SIL Open Font License 1.1.
