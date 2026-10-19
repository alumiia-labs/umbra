"""Checks that deploy/relay/network.env holds the keys that the release app
pins. A relay image with other keys pushes to no notification server.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "android/app/src/release/assets"
NETWORK_ENV = ROOT / "deploy/relay/network.env"


def env_values(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name] = value
    return values


def main():
    faults = []

    values = env_values(NETWORK_ENV)
    pinned = {
        "UMBRA_NDR_KEY_CONFIG": ASSETS / "umbra-ndr-key.bin",
        "UMBRA_DIRECTORY_PINS": ASSETS / "umbra-directory-pins.bin",
    }
    for name, asset in pinned.items():
        if values.get(name, "").lower() != asset.read_bytes().hex():
            faults.append(f"{NETWORK_ENV.name}: {name} is not {asset.name}; run scripts/release-network.sh")

    for fault in faults:
        print(fault, file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
