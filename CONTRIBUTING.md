# Contribute to UMBRA

Thank you for your help. This file gives the rules for an issue and for a
pull request.

`CODE_OF_CONDUCT.md` applies to each person in this project.

## Before you start

- Report a vulnerability in private. `SECURITY.md` gives the procedure. Do not
  open a public issue for it.
- Open an issue before a large change. Agree on the design first.
- Read `spec/01-scope-and-conventions.md` and `spec/02-threat-model.md`.
- Read `AGENTS.md`. It gives the language rules, the comment rules, and the
  version rules.

## What the project accepts

| Change | Condition |
| --- | --- |
| A correction of the code | The pull request names the specification rule that the code did not obey. |
| A correction of the specification | The pull request gives the fault and its effect. |
| A new specification rule | An issue agrees on the rule first. |
| A new dependency | The pull request gives the reason. `deny.toml` must permit the license. |
| A translation | Not at this time. The app has one locale. |

The project does not accept these changes:

- Analytics, attribution, or other measurement in the app.
- A change that makes a rule of the threat model weaker with no agreed issue.
- A test with a wider bound that hides a fault. Find the cause of the fault.

## The specification comes first

The specification in `spec/` is the source of truth. Each rule has an
identifier, for example `NET-360`.

- Change the rule and the code in the same pull request.
- Cite the rule identifier in the code that obeys it.
- Run `python scripts/reqindex.py` after a change to a rule.

## Build and check

`rust-toolchain.toml` pins the Rust toolchain. `android/README.md` gives the
build of the app.

```sh
cargo test --workspace
bash scripts/check.sh
```

`scripts/check.sh` is the full check set. It takes about 25 minutes. The
`check` workflow runs it on each push and on each pull request.

- Make sure that the check set passes before you ask for a review.
- Add a test for each correction. Make sure that the test fails without the
  correction.
- Do not make a time bound of a test longer to make the test pass.

## Language

Write the code, the comments, the commit messages, and the documents in
ASD-STE100 Simplified Technical English. `AGENTS.md` gives the rules.

- Use American English spelling.
- Write a comment to give a reason. Do not write a comment that repeats the
  code.

## Versions

One version applies to the app, the crates, the specification, and the web
site. `AGENTS.md` lists each place.

- Increase the version in the commit that makes the change.
- Run `cargo check` after the change. This command updates `Cargo.lock`.

A maintainer can set the final version number at the merge.

## Commits

Write one subject line in this form:

```text
area: what is true after the change; version
```

Example:

```text
relay, core: an answer of a file command waits for no tick; 0.24.0
```

- Name the changed areas first, for example `core`, `relay`, `ffi`,
  `android`, `spec`, `site`, `ci`.
- Give the reason in the body when the subject line does not show it.
- Keep one topic in one pull request.

## Pull requests

- Fill in the pull request template.
- Keep the change small. A small change gets a fast review.
- Do not include secrets, keys, or the real settings of a network.

## License

UMBRA is under AGPL-3.0-only. You agree that your contribution is under the
same license. Make sure that you have the right to give the contribution.
