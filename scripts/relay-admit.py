"""Turns the join request of a relay of deploy/relay into the input of the
signer: the descriptor file and the line of the outside relay.

    python scripts/relay-admit.py <request file> [<descriptor directory>]

The request file holds the text from BEGIN to END, as the relay request on
GitHub shows it. The descriptor goes to deploy/ansible/build/descriptors
when the command names no directory. Check the dossier before you run it
(Part 10 REL-012). The signer verifies the signature of the descriptor.
"""

import base64
import binascii
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEGIN = "-----BEGIN UMBRA RELAY REQUEST-----"
END = "-----END UMBRA RELAY REQUEST-----"
FACTS = ["name", "role", "class", "public", "operator", "contact", "country", "asn", "family", "relay_id"]


def parse(text):
    if BEGIN not in text or END not in text:
        raise ValueError("the file holds no request from BEGIN to END")

    body = text.split(BEGIN, 1)[1].split(END, 1)[0]
    facts = {}
    lines = [line.strip() for line in body.strip().splitlines()]
    for index, line in enumerate(lines):
        if line == "descriptor=":
            facts["descriptor"] = base64.b64decode("".join(lines[index + 1 :]), validate=True)
            break
        name, _, value = line.partition("=")
        facts[name] = value

    missing = [name for name in FACTS + ["descriptor"] if not facts.get(name)]
    if missing:
        raise ValueError("the request holds no " + ", ".join(missing))
    return facts


def check(facts):
    checks = {
        "name": r"[a-z0-9-]+",
        "role": r"entry|middle|exit",
        "class": r"[0-3]",
        "public": r"[A-Za-z0-9.-]+,\d+\.\d+\.\d+\.\d+,\d+",
        # The signer reads a relay line split at commas, and the entry
        # script splits the list at spaces.
        "operator": r"[^,\s]+",
        "country": r"[A-Z]{2}",
        "asn": r"\d+",
        "family": r"[0-9a-f]{64}",
        "relay_id": r"[0-9a-f]{64}",
    }
    for name, pattern in checks.items():
        if not re.fullmatch(pattern, facts[name]):
            raise ValueError(f"{name}={facts[name]} is not valid")

    if facts["role"] == "entry" and (facts["class"] == "0" or not facts["public"].endswith(",443")):
        raise ValueError("an entry relay takes port 443 and class 1 or more")


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2

    try:
        facts = parse(Path(sys.argv[1]).read_text(encoding="utf-8"))
        check(facts)
    except (ValueError, binascii.Error) as fault:
        print(f"the request does not read: {fault}", file=sys.stderr)
        return 1

    out = Path(sys.argv[2]) if len(sys.argv) == 3 else ROOT / "deploy/ansible/build/descriptors"
    out.mkdir(parents=True, exist_ok=True)
    descriptor = out / f"{facts['name']}.desc"
    descriptor.write_bytes(facts["descriptor"])

    address = facts["public"].split(",")[1]
    print(f"wrote {descriptor}")
    print(f"relay_id {facts['relay_id']}, contact {facts['contact']}")
    print("\nAnsible, umbra_outside_relays of group_vars/all.yml:")
    line = f"  - {{ name: {facts['name']}, role: {facts['role']}, class: {facts['class']}, operator: {facts['operator']}"
    if facts["role"] == "entry":
        line += f", address: {address}"
    print(line + " }")
    print("\nDocker, an item of UMBRA_RELAYS on the signer server:")
    print(f"  {facts['name']},{facts['role']},{facts['class']},{facts['operator']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
