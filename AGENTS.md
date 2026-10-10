## Language

Use ASD-STE100 (Simplified Technical English) in all code, comments, commit messages, and responses.

- Write short sentences. Use a maximum of 20 words in an instruction and 25 words in a description.
- Give one instruction per sentence.
- Use the active voice and the present tense.
- Use the imperative mood for instructions ("Set the value", not "The value should be set").
- Use one approved word for one meaning. Do not use synonyms for the same thing.
- Do not use slang, idioms, or contractions.

Use American English spelling in all text (color, behavior, initialize, center).

## Comments

- Write comments to explain why, not what. The code shows what it does.
- Keep comments sparse. Add a comment only when the reason is not clear from the code.
- Keep comments brief. Use one short sentence when possible.

## Versions

One semantic version applies to the Android app, the Rust crates, the specification, and the web site.

- Increase the version in the commit that makes the change.
- Increase the patch number for a correction or an internal change.
- Increase the minor number for a new feature.
- Increase the minor number for a change to the wire format, the store, the FFI surface, or a specification rule.
- Keep the major number at 0 until the public release.
- Change the version in each place below in the same commit.

| Item | Place |
| --- | --- |
| Android app | `appVersion` in `android/app/build.gradle.kts`. The build calculates the version code. |
| Rust crates | `version` of `[workspace.package]` in `Cargo.toml`. |
| Rust crates | `version` of each path dependency in each `crates/*/Cargo.toml`. |
| Specification | The `**Version:**` line and the `**Date:**` line of each `spec/NN-*.md` part. |
| Web site | `version` in `site/package.json`. |

- Run `cargo check` after the change. This command updates `Cargo.lock`.
- Run `python scripts/reqindex.py` after a change to a specification rule.
- Add a new item to the table when the item gets a version number.
