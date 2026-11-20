"""Turns the join request of a relay of deploy/relay into the input of the
signer: the descriptor file and the line of the outside relay.

    python scripts/relay-admit.py <request file> [<descriptor directory>]
    python scripts/relay-admit.py --self-test

The request file holds the text from BEGIN to END, as the relay request on
GitHub shows it. The descriptor goes to deploy/ansible/build/descriptors
when the command names no directory. Check the dossier before you run it
(Part 10 REL-012). The script compares the descriptor with the facts of the
request, and the signer verifies the signature of the descriptor.

The script refuses these requests:

- a request that names the operator of the network (umbra_operator);
- a name that a relay of the inventory holds;
- a name of the directory that holds another relay, and a relay_id that a
  descriptor of another name holds.

A request with the name and the relay_id of an admitted relay replaces its
descriptor when the new one is not older. That is a new address of the same
relay.

A middle relay or an exit relay can have no host: its `public` line starts
with a comma, and its descriptor holds the pin of its link certificate in
the place of a host name (Part 10 REL-143). An entry relay has a host.

The script stops on a relay name of the settings that does not read, and on
a name that two relays of the settings hold.

--self-test runs the checks on the sample settings and requests below. The
check set runs it.
"""

import base64
import binascii
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE = ROOT / "deploy/ansible"
BEGIN = "-----BEGIN UMBRA RELAY REQUEST-----"
END = "-----END UMBRA RELAY REQUEST-----"
FACTS = ["name", "role", "class", "public", "operator", "contact", "country", "asn", "family", "relay_id"]

# The descriptor of Part 10 §10.5.3: the offset and the width of each field.
DESCRIPTOR_LEN = 5464
FIELDS = {
    "version": (0, 1),
    "relay_id": (1, 32),
    "identity_pk": (33, 1952),
    "addr_v4": (2017, 4),
    "port": (2037, 2),
    "host": (2039, 64),
    "asn": (2103, 4),
    "jurisdiction": (2107, 2),
    "family_id": (2109, 32),
    "capacity_class": (2141, 1),
    "roles": (2142, 1),
    "valid_after": (2147, 8),
}
QUEUE, CHAIN, INGRESS = 0x01, 0x02, 0x04
# The pin form of `host` (Part 10 REL-143): a zero byte, the SHA3-256 of the
# link certificate, and zero bytes.
PIN_LEN = 32
# The role bits that each role needs, and those that it must not have. A
# relay that offers the ingress role takes no layer 3 (Part 10 REL-060),
# thus an exit relay must not offer it, and an entry relay takes no queue.
ROLE_BITS = {
    "entry": (CHAIN | INGRESS, QUEUE),
    "middle": (CHAIN, 0),
    "exit": (QUEUE | CHAIN, INGRESS),
}
# A line of the settings that names a relay, and its name and operator. The
# name runs to the end of its value, thus "home_1" does not read as "home".
NAMED = re.compile(r"\bname:")
NAME = re.compile(r"\bname:\s*[\"']?([a-z0-9-]+)[\"']?\s*(?:[,}]|$)")
OPERATOR = re.compile(r"\boperator:\s*[\"']?([^,\s}\"']+)")


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


def shown(text):
    """The text with each control character as an escape. A request is not
    trusted, and an escape sequence can write over the terminal of the owner."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def check(facts):
    checks = {
        "name": r"[a-z0-9-]+",
        "role": r"entry|middle|exit",
        "class": r"[0-3]",
        # `[0-9]` and not `\d`, which takes each number character of Unicode.
        # An empty host is the pin form of the descriptor (Part 10 REL-143).
        "public": r"[A-Za-z0-9.-]*,[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3},[0-9]{1,5}",
        # The signer reads a relay line split at commas, and the entry
        # script splits the list at spaces. The owner pastes the value into
        # a YAML line, thus it holds no character that YAML reads as syntax.
        "operator": r"[A-Za-z0-9._-]+",
        "country": r"[A-Z]{2}",
        "asn": r"[0-9]{1,10}",
        "family": r"[0-9a-f]{64}",
        "relay_id": r"[0-9a-f]{64}",
    }
    for name, pattern in checks.items():
        if not re.fullmatch(pattern, facts[name]):
            raise ValueError(f"{name}={facts[name]} is not valid")

    host, address, port = facts["public"].split(",")
    if any(int(part) > 255 for part in address.split(".")):
        raise ValueError(f"public={facts['public']} holds no IPv4 address")
    if not 1 <= int(port) <= 65_535:
        raise ValueError(f"public={facts['public']} holds no port")
    if int(facts["asn"]) >= 2**32:
        raise ValueError(f"asn={facts['asn']} is above 32 bits")

    if facts["role"] == "entry" and (facts["class"] == "0" or not facts["public"].endswith(",443")):
        raise ValueError("an entry relay takes port 443 and class 1 or more")
    # Part 10 REL-226: a phone verifies the certificate of an entry relay
    # against its host name.
    if facts["role"] == "entry" and not host:
        raise ValueError("an entry relay takes a host name")


def read_descriptor(raw):
    if len(raw) != DESCRIPTOR_LEN or raw[0] != 0x01:
        raise ValueError("the descriptor is not one of Part 10 §10.5.3")

    fields = {name: raw[at : at + width] for name, (at, width) in FIELDS.items()}
    if hashlib.sha3_256(fields["identity_pk"]).digest() != fields["relay_id"]:
        raise ValueError("the relay_id of the descriptor is not the hash of its key")
    return fields


def pin_host(pin):
    """The `host` field of a descriptor in pin form."""
    return b"\0" + pin + bytes(64 - 1 - PIN_LEN)


def link_pin(host):
    """The pin of a `host` field in pin form, or None for each other field.
    A pin of zero bytes is no pin."""
    pin, pad = host[1 : 1 + PIN_LEN], host[1 + PIN_LEN :]
    if host[0] == 0 and any(pin) and not any(pad):
        return pin
    return None


def stated_fields(facts):
    """The fields of the descriptor that the facts of a request state. A
    request with no host states no `host` field: the pin of the descriptor
    comes from the certificate of the relay."""
    host, address, port = facts["public"].split(",")
    named = {"host": host.encode().ljust(64, b"\0")} if host else {}
    return {
        "relay_id": bytes.fromhex(facts["relay_id"]),
        **named,
        "addr_v4": bytes(int(part) for part in address.split(".")),
        "port": int(port).to_bytes(2, "big"),
        "asn": int(facts["asn"]).to_bytes(4, "big"),
        "jurisdiction": facts["country"].encode(),
        "family_id": bytes.fromhex(facts["family"]),
        "capacity_class": bytes([int(facts["class"])]),
    }


def compare(facts, descriptor):
    """The facts that the owner checks are the facts that the signer lists."""
    stated = stated_fields(facts)
    differ = [name for name, value in stated.items() if descriptor[name] != value]
    if differ:
        raise ValueError("the descriptor states another " + ", ".join(differ) + " than the request")

    roles = descriptor["roles"][0]
    if "host" not in stated:
        if link_pin(descriptor["host"]) is None:
            raise ValueError("the request states no host, and the descriptor holds no pin of a link certificate")
        # Part 10 REL-227: each client rejects such a descriptor.
        if roles & INGRESS:
            raise ValueError("a descriptor in pin form offers the ingress role")

    needed, refused = ROLE_BITS[facts["role"]]
    if roles & needed != needed or roles & refused:
        raise ValueError(f"the roles of the descriptor do not fit the role {facts['role']}")


def file_text(path):
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def uncommented(text):
    # YAML starts a comment at a "#" after a space alone, thus the operator
    # "a#b" is one value.
    return [re.split(r"(?:^|\s)#", line, maxsplit=1)[0] for line in text.splitlines()]


def named_mappings(text, where):
    """Each flow mapping that names a relay, with the name. A flow list can
    hold the mappings of more relays on one line. The checks of admit() do
    not see a name that the scan skips, thus a name that does not read stops
    the script."""
    found = []
    for line in uncommented(text):
        for mapping in line.split("{"):
            names = NAME.findall(mapping)
            if len(names) != len(NAMED.findall(mapping)):
                raise ValueError(f"{where}: no relay name reads from '{mapping.strip()}'")
            found += [(name, mapping) for name in names]
    return found


def read_settings(group_vars, inventory):
    """The own operator, the relay names of the inventory, and the name and
    the operator of each outside relay, from the text of group_vars/all.yml
    and of inventory.yml. A plain scan reads these flat lines, thus the
    script needs no YAML library."""
    own = None
    for line in uncommented(group_vars):
        operator = re.match(r"umbra_operator:\s*[\"']?([^\"'\s]+)", line)
        if operator:
            own = operator.group(1)
    if own is None:
        raise ValueError("group_vars/all.yml holds no umbra_operator")

    outside = []
    for name, mapping in named_mappings(group_vars, "group_vars/all.yml"):
        operator = OPERATOR.search(mapping)
        outside.append((name, operator.group(1) if operator else ""))
    relays = [name for name, _ in named_mappings(inventory, "inventory.yml")]

    # The playbook stops on such a name too (roles/common).
    names = relays + [name for name, _ in outside]
    twice = sorted({name for name in names if names.count(name) > 1})
    if twice:
        raise ValueError("the settings hold these names two times: " + " ".join(twice))
    return own, relays, outside


def held_descriptor(path):
    try:
        return read_descriptor(path.read_bytes())
    except (OSError, ValueError):
        return None


def admit(facts, descriptor, out, settings):
    """Checks the name and the relay_id against the network, and gives the
    file of the descriptor and whether it is new."""
    own, inventory, outside = settings

    # Part 10 REL-128: the owner sets the operator from the dossier. A relay
    # of another operator under the own name would skip its admission.
    if facts["operator"] == own:
        raise ValueError(f"the request names the operator of the network, {own}")
    if facts["name"] in inventory:
        raise ValueError(f"a relay of the inventory holds the name {facts['name']}")

    target = out / f"{facts['name']}.desc"
    for other in sorted(out.glob("*.desc")):
        held = held_descriptor(other)
        if other != target and held and held["relay_id"] == descriptor["relay_id"]:
            raise ValueError(f"{other} holds this relay_id under another name")

    if not target.exists():
        if any(name == facts["name"] for name, _ in outside):
            raise ValueError(f"umbra_outside_relays holds {facts['name']}, and {target} is not there to compare")
        return target, True

    held = held_descriptor(target)
    if held is None or held["relay_id"] != descriptor["relay_id"]:
        raise ValueError(f"{target} holds another relay; a new relay takes a name of its own")

    # A copy of an older descriptor would take the relay back to an old
    # address.
    if int.from_bytes(descriptor["valid_after"], "big") < int.from_bytes(held["valid_after"], "big"):
        raise ValueError(f"{target} holds a newer descriptor of this relay")
    return target, target.read_bytes() != facts["descriptor"]


def review(text, out, settings):
    """All checks of one request. Gives the facts, the file of the
    descriptor, and whether the file changes."""
    facts = parse(text)
    check(facts)
    descriptor = read_descriptor(facts["descriptor"])
    compare(facts, descriptor)
    out.mkdir(parents=True, exist_ok=True)
    target, changed = admit(facts, descriptor, out, settings)
    return facts, target, changed


SAMPLE_GROUP_VARS = """\
umbra_operator: umbra-project
umbra_outside_relays:
  # - { name: home-7, role: middle, class: 0, operator: erin }
  - { name: home-1, role: exit, class: 0, operator: alice }
  - { name: "home-6", role: middle, class: 0, operator: 'carol' }
"""
SAMPLE_INVENTORY = """\
all:
  children:
    relays:
      hosts:
        east-1:
          ansible_host: 203.0.113.10
          relays:
            - { name: entry-east, role: entry, port: 443, class: 1 }
            - { name: exit-1, role: exit, port: 9443, class: 1 }
"""


def sample_request(seed, name, valid_after=1, stated=None, pin=None, roles=None, **changes):
    """A join request as entry.sh writes it, with a descriptor of the same
    facts. `changes` go into the facts of both, and `stated` into the
    request alone. A request with no host gets a descriptor in pin form,
    with `pin` or a pin from the seed. `roles` are the role bits of the
    descriptor in the place of those of the role. The signature stays zero:
    the signer checks it, and this script does not."""
    identity = hashlib.shake_256(seed.encode()).digest(FIELDS["identity_pk"][1])
    facts = {
        "name": name,
        "role": "exit",
        "class": "1",
        "public": "relay.example.org,198.51.100.7,443",
        "operator": "bob",
        "contact": "bob@example.org",
        "country": "DE",
        "asn": "64496",
        "family": "ab" * 32,
        "relay_id": hashlib.sha3_256(identity).hexdigest(),
        **changes,
    }

    raw = bytearray(DESCRIPTOR_LEN)
    if pin is None:
        pin = hashlib.sha3_256(f"link {seed}".encode()).digest()
    if roles is None:
        roles = ROLE_BITS[facts["role"]][0]
    fields = {
        "host": pin_host(pin),
        **stated_fields(facts),
        "version": b"\x01",
        "identity_pk": identity,
        "roles": bytes([roles]),
        "valid_after": valid_after.to_bytes(8, "big"),
    }
    for field, value in fields.items():
        at, width = FIELDS[field]
        raw[at : at + width] = value

    facts.update(stated or {})
    encoded = base64.b64encode(bytes(raw)).decode()
    lines = [BEGIN] + [f"{fact}={facts[fact]}" for fact in FACTS] + ["descriptor="]
    lines += [encoded[at : at + 76] for at in range(0, len(encoded), 76)] + [END]
    return "\n".join(lines) + "\n"


def self_test():
    faults = []

    def expect(label, want, action, *args):
        """`want` is a part of the result, or of the cause of a refusal."""
        try:
            got = str(action(*args))
        except (ValueError, binascii.Error) as fault:
            got = f"refused: {fault}"
        if want not in got:
            faults.append(f"{label}: gives '{got}', and the case wants '{want}'")

    bad = "  - { name: Home_5, role: exit, class: 0, operator: dave }\n"
    again = "  - { name: exit-1, role: exit, class: 0, operator: dave }\n"
    hashed = "  - { operator: d#ve, name: exit-1, role: exit, class: 0 }\n"
    flow = (
        "umbra_operator: umbra-project\n"
        "umbra_outside_relays: [{ name: home-1, role: exit, class: 0, operator: alice },"
        " { name: {}, role: exit, class: 0, operator: dave }]\n"
    )
    read = "('umbra-project', ['entry-east', 'exit-1'], [('home-1', 'alice'), ('home-6', 'carol')])"
    read_flow = "[('home-1', 'alice'), ('home-8', 'dave')])"
    settings_cases = [
        ("the sample settings", SAMPLE_GROUP_VARS, read),
        ("a name that does not read", SAMPLE_GROUP_VARS + bad, "no relay name reads"),
        ("a name of the inventory again", SAMPLE_GROUP_VARS + again, "two times: exit-1"),
        ("a name after a # in a value", SAMPLE_GROUP_VARS + hashed, "two times: exit-1"),
        ("a flow list on one line", flow.replace("{}", "home-8"), read_flow),
        ("a name of the inventory in a flow list", flow.replace("{}", "exit-1"), "two times: exit-1"),
        ("no own operator", "umbra_outside_relays: []\n", "no umbra_operator"),
    ]
    for label, group_vars, want in settings_cases:
        expect(label, want, read_settings, group_vars, SAMPLE_INVENTORY)

    # The cases run in this order against one descriptor directory.
    moved = "relay.example.org,198.51.100.8,443"
    other_port = "relay.example.org,198.51.100.7,9443"
    named = "relay.example.org,198.51.100.9,9443"
    no_host = ",198.51.100.9,9443"
    no_host_443 = ",198.51.100.9,443"
    request_cases = [
        ("a new relay", sample_request("a", "home-2"), "wrote home-2.desc"),
        ("the same request again", sample_request("a", "home-2"), "held home-2.desc"),
        ("a new address of the relay", sample_request("a", "home-2", 2, public=moved), "wrote home-2.desc"),
        ("an older descriptor of the relay", sample_request("a", "home-2", 1), "holds a newer descriptor"),
        ("its relay_id under another name", sample_request("a", "home-3"), "under another name"),
        ("another relay under its name", sample_request("b", "home-2"), "holds another relay"),
        ("the own operator", sample_request("c", "home-4", operator="umbra-project"), "the operator of the network"),
        ("a name of the inventory", sample_request("c", "exit-1"), "a relay of the inventory"),
        ("a name of umbra_outside_relays", sample_request("c", "home-1"), "umbra_outside_relays holds home-1"),
        ("a quoted name of umbra_outside_relays", sample_request("c", "home-6"), "umbra_outside_relays holds home-6"),
        ("another class than the descriptor", sample_request("c", "home-4", stated={"class": "2"}), "capacity_class"),
        ("roles that do not fit the role", sample_request("c", "home-4", stated={"role": "entry"}), "the role entry"),
        ("an entry relay on another port", sample_request("c", "home-4", role="entry", public=other_port), "port 443"),
        ("no descriptor", sample_request("c", "home-4").split("descriptor=")[0] + END, "holds no descriptor"),
        ("the own operator in quotes", sample_request("c", "home-4", stated={"operator": '"umbra-project"'}), "operator="),
        ("a port above 16 bits", sample_request("c", "home-4", stated={"public": "relay.example.org,198.51.100.7,70000"}), "holds no port"),
        ("an ASN above 32 bits", sample_request("c", "home-4", stated={"asn": "4294967296"}), "above 32 bits"),
        # The pin form of Part 10 REL-143.
        ("a middle relay in pin form", sample_request("d", "home-5", role="middle", public=no_host), "wrote home-5.desc"),
        ("an exit relay in pin form", sample_request("e", "home-7", public=no_host), "wrote home-7.desc"),
        ("an entry relay with no host", sample_request("f", "home-8", role="entry", public=no_host_443), "takes a host name"),
        ("no host, and a name in the descriptor", sample_request("f", "home-8", public=named, stated={"public": no_host}), "holds no pin"),
        ("a host, and a pin in the descriptor", sample_request("f", "home-8", public=no_host, stated={"public": named}), "another host"),
        ("a pin of zero bytes", sample_request("f", "home-8", public=no_host, pin=bytes(PIN_LEN)), "holds no pin"),
        ("a pin form with the ingress offer", sample_request("f", "home-8", role="middle", public=no_host, roles=CHAIN | INGRESS), "offers the ingress role"),
    ]
    settings = read_settings(SAMPLE_GROUP_VARS, SAMPLE_INVENTORY)

    def submit(text, out):
        facts, target, changed = review(text, out, settings)
        if changed:
            target.write_bytes(facts["descriptor"])
        return f"{'wrote' if changed else 'held'} {target.name}"

    with tempfile.TemporaryDirectory() as folder:
        for label, text, want in request_cases:
            expect(label, want, submit, text, Path(folder))

    print(f"cases: {len(settings_cases) + len(request_cases)}  faults: {len(faults)}")
    for line in faults:
        print("  " + line)
    return 1 if faults else 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2

    out = Path(sys.argv[2]) if len(sys.argv) == 3 else ANSIBLE / "build/descriptors"
    try:
        settings = read_settings(file_text(ANSIBLE / "group_vars/all.yml"), file_text(ANSIBLE / "inventory.yml"))
        facts, target, changed = review(Path(sys.argv[1]).read_text(encoding="utf-8"), out, settings)
    except (ValueError, OverflowError, binascii.Error) as fault:
        print(f"the request is refused: {shown(str(fault))}", file=sys.stderr)
        return 1

    if changed:
        target.write_bytes(facts["descriptor"])
        print(f"wrote {target}")
    else:
        print(f"{target} holds this descriptor already")

    address = facts["public"].split(",")[1]
    print(f"relay_id {facts['relay_id']}, contact {shown(facts['contact'])}")
    _, _, outside = settings
    same = [name for name, operator in outside if operator == facts["operator"] and name != facts["name"]]
    if same:
        print(f"the operator {facts['operator']} has these relays already: {' '.join(same)}")

    print("\nAnsible, umbra_outside_relays of group_vars/all.yml:")
    # The quotes keep a name as `true` or `123` a string in YAML.
    line = (
        f"  - {{ name: {json.dumps(facts['name'])}, role: {facts['role']}, class: {facts['class']}, "
        f"operator: {json.dumps(facts['operator'])}"
    )
    if facts["role"] == "entry":
        line += f", address: {address}"
    print(line + " }")
    print(
        "\nThe signer lists the relay as pending at class 0 until a test passes, and then at the"
        "\nclass that a passed test verified (Part 10 REL-210). The class of the line is the upper bound."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
