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

## Readability

Write code and text that a new reader understands on the first read.

- Put a blank line between the steps of a function: a check, a lookup, a change, a result.
- Do not put a blank line between each statement. A group of lines that do one step stays together.
- Put one statement on a line. Do not chain commands on one line when separate lines are clearer.
- Give a value a name that says what it holds. Use a short name only in a small scope.
- Move a deep nesting or a long function into named parts when each part has one clear job.
- Use a list or a table for steps and for sets of values, not a long paragraph.
- Keep each paragraph of text to one topic.

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
| Helm chart | `version` and `appVersion` in `deploy/helm/umbra-relay/Chart.yaml`. |
| Relay image | The image tag of `UMBRA_IMAGE` in `compose.yaml`. |

- Run `cargo check` after the change. This command updates `Cargo.lock`.
- Run `python scripts/reqindex.py` after a change to a specification rule.
- Add a new item to the table when the item gets a version number.
