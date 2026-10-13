<!-- Do not open a public pull request for a vulnerability. SECURITY.md gives the procedure. -->

## Change

<!-- Tell what is true after this change. -->

## Reason

<!-- Give the issue number, or the specification rule that the code did not obey. -->

## Test

<!-- Tell how you made sure that the change is correct. Name each new test. -->

## Checklist

- [ ] `bash scripts/check.sh` passes.
- [ ] A new test fails without the correction.
- [ ] The specification and the code agree. The code cites each rule identifier.
- [ ] `python scripts/reqindex.py` ran after a change to a rule.
- [ ] The version is the same in each place that `AGENTS.md` lists.
- [ ] The text obeys the language rules of `AGENTS.md`.
- [ ] The change contains no secret, no key, and no real network setting.
- [ ] The change adds no dependency, or `deny.toml` permits its license.
