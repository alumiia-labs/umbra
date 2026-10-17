# Deploying the UMBRA network on Docker

`compose.yaml` in the root of the repository runs the services of
`deploy/ansible` in containers: the same launch network of four servers, the
same settings, and the same order of the first run. Each server runs the
file with its own `.env`. `deploy/ansible/README.md` explains the network
itself: why each service sits where it does, what the signer does each hour,
and the limits of a network of one operator. Read it first.

| Server | `COMPOSE_PROFILES` |
|---|---|
| `east-1` | `tls,relay1,relay2,ndr` |
| `east-2` | `tls,relay1,relay2` |
| `west-1` | `tls,relay1,relay2,directory` |
| `signer-west-1` | `tls,signer` |

One image holds each server binary and `umbra-entry`, which does the work of
the Ansible roles at the start of a container:

- It makes each secret one time, in the state directory of its service. A
  secret never leaves that directory.
- It writes the settings file of the service from the environment, into a
  file system in memory.
- A relay signs its descriptor when it has none, or when a line that the
  descriptor states changed (Part 10 `REL-160`).
- A service starts again when certbot writes a new certificate.
- The signer signs a manifest at two minutes past each hour, with no network.
  It issues a measurer certificate when the measurer asks for one.
- The measurer runs the class tests one time in each 7 days (`REL-097`).

Each service runs under the network of the host, as its own user, with a
read-only file system, no capability, and a memory limit. The signer has no
network at all.

## What each server needs

- Linux with Docker Engine 24 or newer and the compose plugin. Debian 12 or
  13 on the OVH VPS-1 serves each.
- An A record for its name, as `east-1.umbrachat.app`.
- A clock that follows the network time: chrony or systemd-timesyncd on the
  host. A root lives three hours, and a wrong clock rejects it.
- Port 443 for a user with no root. Docker gives such a user no capability,
  thus the host permits the port:

  ```sh
  echo net.ipv4.ip_unprivileged_port_start=443 | sudo tee /etc/sysctl.d/60-umbra.conf
  sudo sysctl --system
  ```

  A server holds the services of the network alone, thus no other user
  takes the port. A service that cannot take its port says so at its start.
- A firewall on the host. Each service uses the network of the host, thus
  the firewall applies to it as to a systemd service:
  - each server: 22 (from your addresses), and 80 for certbot;
  - a relay server: the port of each relay (443, 9443);
  - the signer: 443;
  - the notification server and the directory: `UMBRA_SERVICE_PORT` (8443),
    to the addresses of the relay servers alone.

  The `common` and `hardening` roles of `deploy/ansible` give the same host
  settings: SSH by key alone, fail2ban, the kernel settings, no crash dumps,
  updates on their own, and the firewall.

## The first run

The order is the one of `site.yml`: each step needs the one before.

1. **Each server.** Clone the repository, then:

   ```sh
   cp deploy/docker/server.env.example .env    # fill it in for this server
   docker compose build                        # or pull UMBRA_IMAGE
   sudo docker compose run --rm init           # the directories under UMBRA_ROOT
   docker compose up -d certbot                # the certificate of the server
   ```

   `UMBRA_FAMILY` is the same on each server: make it one time with
   `openssl rand -hex 32`.

2. **The notification server and the directory.** On `east-1`, put the
   Firebase service account file at `<UMBRA_ROOT>/secrets/fcm.json`. Run
   `init` again, which gives it to the service alone. Then:

   ```sh
   docker compose up -d ndr                                    # on east-1
   docker compose run --rm -T ndr ndr key-config               # prints the key
   docker compose up -d directory                              # on west-1
   docker compose run --rm -T directory directory pins         # prints the pins
   ```

   Put the key in `UMBRA_NDR_KEY_CONFIG` and the pins in
   `UMBRA_DIRECTORY_PINS` of the `.env` of each relay server. Keep both in
   `deploy/ansible/build/` as `ndr-key-config.hex` and `directory-pins.hex`
   for the release app.

3. **Each relay.** On each relay server:

   ```sh
   docker compose up -d relay1 relay2
   ```

   Each relay makes its identity, signs its descriptor, and then waits for
   the key set. Copy `<UMBRA_ROOT>/relay1/relay.desc` and
   `<UMBRA_ROOT>/relay2/relay.desc` of each server to
   `<UMBRA_ROOT>/descriptors/<relay name>.desc` on the signer.

4. **The signer.** On `signer-west-1`, with each descriptor in place:

   ```sh
   docker compose up -d
   ```

   The signer makes the seven authority keys one time and signs the first
   manifest. nginx serves it at
   `https://signer-west-1.<domain>/.well-known/umbra/manifest`. The
   authority tool and the measurer start after the keys.

   **Back up `<UMBRA_ROOT>/signer` offline now:** each key directory and the
   key chain. Without them no new manifest verifies under the key set that
   the app ships.

5. **The key set to each relay.** Copy `<UMBRA_ROOT>/www/keyset.bin` of the
   signer to `<UMBRA_ROOT>/network/keyset.bin` on each relay server. Each
   relay then fetches the manifest and starts. Later manifests arrive on
   their own.

6. **The release app.** Copy `keyset.bin` and `manifest` of
   `<UMBRA_ROOT>/www` on the signer to `deploy/ansible/build/`. Write
   `deploy/ansible/build/network.properties` as the template
   `deploy/ansible/templates/network.properties.j2` gives it, then run
   `bash scripts/release-network.sh` ("After the first run" in
   `deploy/ansible/README.md`).

## Checks

```sh
docker compose ps
docker compose logs --tail 20 relay1 relay2
docker compose logs --tail 20 signer authority measurer    # on the signer
curl -sI https://signer-west-1.<domain>/.well-known/umbra/manifest
```

A line with `ALERT` names a failure that needs the operator: a signer that
signed no manifest, a renewal that failed, or a relay with no class test
result. Give the log of the signer to a monitor that sends you each such
line. A failed signer leaves the old manifest, and the network stops when
that one ends, three hours later.

## Later runs

- **A new binary.** On one server at a time:

  ```sh
  git pull && docker compose build && docker compose up -d
  ```

  Tag each build (`UMBRA_IMAGE=umbra-servers:<version>`) to go back to the
  one before with a change of `.env`.
- **A changed class, or a relay more or less.** Change the `.env` of the
  relay server and `UMBRA_RELAYS` on the signer. A relay whose descriptor
  lines changed signs a new descriptor at `docker compose up -d`: copy it to
  the signer again. Then `docker compose up -d signer` on the signer. An
  hour takes one manifest (`REL-160`), thus the new relay set takes effect
  at the next hour. Restart each relay of each server after that manifest,
  one at a time (`docker compose restart relay1`, then `relay2`).
- **A second manifest in this hour,** to take a relay out at once:

  ```sh
  docker compose run --rm signer signer sign --force
  ```

- **A rotation of the authority keys.** Run the two commands of "Rotating the
  directory keys" in `deploy/ansible/README.md` in the signer container:

  ```sh
  docker compose run --rm --entrypoint umbra-signer signer keygen /var/lib/umbra-signer/keys-2 2
  docker compose run --rm --entrypoint umbra-signer signer rotate \
      /var/lib/umbra-signer/keys /var/lib/umbra-signer/keys-2 /var/lib/umbra-signer/keychain
  ```

  Then set `UMBRA_SIGNER_KEYS_DIR=keys-2` and run `docker compose up -d`.
- **A revoked measurer.** Add `<measurer_id>,<not_after>` from
  `docker compose logs signer` to `UMBRA_REVOKED_MEASURERS`, delete the two
  files of `<UMBRA_ROOT>/measurer/keys`, and run `docker compose up -d`.
- **The class tests now:**

  ```sh
  docker compose exec measurer umbra-entry measurer now
  ```

## Taking a relay out

Delete the relay from `UMBRA_RELAYS` on the signer, then run
`docker compose up -d signer` there. On the server of the relay, take its
profile out of `COMPOSE_PROFILES` and remove its container:

```sh
docker compose rm --stop --force relay2
```

The seed and the store of the relay stay in `<UMBRA_ROOT>/relay2`, in case
it comes back with the same identity. Delete that directory to end it.
