# UMBRA Protocol Specification — Part 12: Withdrawn

**Status:** Withdrawn
**Version:** 0.2.0-draft
**Date:** 2026-09-25

---

## 12.1 The withdrawal

This part gave public communities: open conversations of 1000 members or
more, which a party joined with a link and read with pulls from relays that
held a cache. The owner withdrew the feature from UMBRA on 2026-09-25, and
this part holds no requirement.

The part keeps its number. The other parts of this specification name
Part 13 to Part 16 by number, and a gap costs less than a renumbering.

The codes that this part gave stay reserved, and no party gives them a new
meaning in version 1:

- the commands `0x80` to `0x85` of Part 6 §6.4;
- the kinds `0x0D`, `0x0E`, `0x11`, and `0x38` of an `AppMessage` of Part 6
  §6.6;
- the L6 kind `0x03` of Part 6 §6.4.2;
- the labels of Part 5 §5.11 that start with `"umbra/v1/community-"`.

Part 6 gives the rule that rejects each of them.

> *Cause.* A private group of Part 11 serves a conversation of known people
> up to 500 members. A public space of pseudonymous authors adds a second
> product with its own moderation, its own abuse surface, and its own
> relay role, and the owner did not want that product in UMBRA.
