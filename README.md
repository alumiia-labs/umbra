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
| `deploy/` | One relay of your own (`deploy/relay`, `deploy/helm/umbra-relay`), and the Ansible playbooks of the servers of the network. |
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

`android/README.md` gives the build of the app.

**Run a relay.** You can run one relay of the public network on your own
machine, as a home server or a homelab, with `compose.yaml` or the Helm
chart in `deploy/helm/umbra-relay`. `deploy/relay/README.md` gives the
steps and the join request.

The servers of the network itself run from `deploy/ansible`.

**The test network.** This command runs a test network of seven relays on
this machine, with no Rust toolchain:

```sh
docker compose -f compose.devnet.yaml up --build
```

Its seeds are in the repository, thus it protects nothing.
`android/README.md` gives its use.

## Contribute

`CONTRIBUTING.md` gives the rules for an issue and for a pull request.
`CODE_OF_CONDUCT.md` applies to each person in this project.

## Security

`SECURITY.md` gives the procedure for a vulnerability report.

## License

AGPL-3.0-only. Refer to `LICENSE`.

- The icons of `android/app/src/main/assets/fa` are Font Awesome Free, under
  CC BY 4.0.
- The fonts are under the SIL Open Font License 1.1.
