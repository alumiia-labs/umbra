# Deploying the UMBRA network

These playbooks install the launch network on Debian: four servers at
OVHcloud US, over two sites. A server can run two relays; the inventory
lists the relays of each server.

| Server | Site | Runs |
|---|---|---|
| `east-1` | Vint Hill, Virginia | Entry relay `entry-east` (port 443), exit relay `exit-1` (port 9443), and the notification server (`umbra-ndr`, port 8443) |
| `east-2` | Vint Hill, Virginia | Middle relay (port 443) and exit relay `exit-3` (port 9443) |
| `west-1` | Hillsboro, Oregon | Entry relay `entry-west` (port 443), exit relay `exit-2` (port 9443), and the directory (`umbra-directory`, port 8443) |
| `signer-west` | Hillsboro, Oregon | The directory signer; it signs the relay list each hour, and nginx serves it |

Three exit relays hold the two replicas of a group and the three copies of
a file. An entry relay takes port 443, since phones reach it. Each relay
runs as `umbra-relay@<name>`, with its files in `/etc/umbra/relays/<name>`
and `/var/lib/umbra-relay/<name>`.

The trade of two relays on one server: a chain whose entry and exit relay
share a server shows that server both ends. The operator runs every server
during the launch anyway; the trade is against one who breaks into one
server. The app avoids such a chain when it has another (Part 3 `NET-351`).

With one operator, the directory is *provisional* (Part 10 `REL-126`). The
app shows that, and the rules of Part 3 `NET-340` and `NET-350` let one
operator, one provider, and one country carry the traffic.

## What you need

- Four Debian 12 or 13 servers. OVH's VPS-1 (500 Mbit/s) serves each.
  - A server with two relays states the share of each: class 1 (250 Mbit/s)
    for each on a 500 Mbit/s plan. An entry relay needs class 1 or more.
- A domain. Give each server an A record: `east-1.<domain>`, `east-2.<domain>`,
  `west-1.<domain>`, and `signer-west.<domain>`.
- SSH with a key, as root or as a user with sudo, to each server, from this
  machine. OVH's Debian images log in as `debian`, which the example
  inventory sets. The run turns off password logins, and it stops first if
  that user holds no key.
- The Firebase service account JSON of the app's project, for pushes.
- Ansible 2.15 or newer and Docker, on this machine. WSL works: run the
  playbooks from Debian in WSL.
  - Clone the repository inside the WSL file system (`~/umbra`), not under
    `/mnt/c`. Ansible ignores the `ansible.cfg` of a folder that anyone may
    write, and every folder under `/mnt/c` looks that way. It would then
    find no inventory.
  - From `/mnt/c` all the same, run
    `ANSIBLE_CONFIG=$PWD/ansible.cfg ansible-playbook -i inventory.yml site.yml`.

## One-time values

In `group_vars/all.yml`:

| Value | How to get it |
|---|---|
| `umbra_domain` | Your domain |
| `umbra_acme_email` | The address for Let's Encrypt |
| `umbra_asn` | `whois <address of a server>` prints the AS number of OVHcloud |
| `umbra_family` | `openssl rand -hex 32`, made once and kept |
| `umbra_fcm_credentials` | The path of the Firebase JSON on this machine |
| `umbra_ssh_from` | Your own IP addresses, to close SSH to everyone else. Optional |

Copy `inventory.example.yml` to `inventory.yml`. In `inventory.yml`:

- Put each server's address in `ansible_host`.
- Each relay under `relays` has a name, a role (`entry`, `middle`, or
  `exit`), a port, and a class: 0, 1, 2 or 3 for 100, 250, 500 or
  1 000 Mbit/s, in both directions. State only what the plan holds, split
  between the relays of one server.
- An entry relay takes port 443 and class 1 or more.

## Run

```sh
bash scripts/build-linux.sh             # from the repo root, builds target/deploy/bin
cd deploy/ansible
ansible-playbook site.yml
```

The first run does this, in order:

1. Each server:
   - takes the updates, a clock, a firewall, and a certificate for its name;
   - makes its own secrets, which never leave it.
2. The notification server and the directory start. Their public keys come back to `build/`.
3. Each relay signs its descriptor. It comes back to `build/descriptors/`.
4. The signer makes the seven authority keys and signs the first manifest.
   The key set and the manifest come back to `build/`.
5. Each relay takes the key set and the manifest, then starts.

A later run changes nothing that is already in place. It makes no key again.
Run it again after:

- a new binary;
- a new relay in the inventory;
- a changed class.

## After the first run

- **Back up the signer keys.** Copy `/var/lib/umbra-signer` from
  `signer-west` to an offline place: each key directory and the key chain.
  Without the chain, an app that ships an older key set cannot reach the
  new one. Without those keys, no new manifest
  verifies under the key set that the app ships. The network then stops
  within three hours of the last manifest.
- **Give the release app its network.** Run `bash scripts/release-network.sh`
  from the repo root, then build the release app. The script turns `build/`
  into the assets of the release build:
  - the directory key set;
  - the key of the notification server;
  - the pins of the directory;
  - the carriers, the entry relays and the signer, that the app fetches the
    manifest from.

  Each value is public, so commit the assets. A build without them has no
  network.
- **Keep `build/`.** It holds no secret, and git ignores it.

## How it runs

- **Hardening.** Each server gets the following:
  - SSH by key alone, with no forwarding. fail2ban bans an address after 5
    SSH failures in 10 minutes.
  - The kernel settings of a server that routes nothing: no forged source,
    no redirects, SYN cookies, and no process that reads another's memory.
  - No crash dumps, since a dump of a service could hold its keys.
  - A journal that keeps 7 days, because a relay sees client addresses.
- **Services.** Each service runs as its own user, in a systemd sandbox:
  - a read-only system, and write access to its own folder alone;
  - a syscall filter and no new privileges;
  - no capabilities beyond the low port of a relay.

- **The manifest.** The signer signs a manifest at two minutes past each
  hour; a root lives three hours. Each relay fetches the manifest from
  `https://signer-west.<domain>/.well-known/umbra/manifest` every five
  minutes. It replaces its copy only with a manifest that verifies and still
  lists it.
- **Certificates** renew on their own. A renewal restarts the service that
  uses the certificate.
- **The firewall** opens 22, 80, and the port of each relay of the server
  (443, 9443). It opens 443 on the signer, and 8443 on the notification
  server and the directory, to the relay servers alone.

## Rotating the directory keys

Rotate the keys when a signer key leaks or is lost, or when an independent
authority joins (Part 10 `REL-036`). The old keys sign the new set. Each
relay and each installed app then walks the chain to the new set by itself
(`REL-200`), so no app update is needed.

On `signer-west`:

```sh
sudo -u umbra-signer umbra-signer keygen /var/lib/umbra-signer/keys-2 2
sudo -u umbra-signer umbra-signer rotate /var/lib/umbra-signer/keys     /var/lib/umbra-signer/keys-2 /var/lib/umbra-signer/keychain
```

The second argument of `keygen` is the epoch of the new set: one above the
current one. Then:

1. Set `umbra_signer_keys: /var/lib/umbra-signer/keys-2` in
   `group_vars/all.yml`.
2. Run `ansible-playbook site.yml`. The signer then signs under the new keys
   and publishes the chain at `/.well-known/umbra/keychain`.
3. Run `scripts/release-network.sh`, so that the next app build ships the new
   set. An app takes the newer of the set it ships and the set it reached
   through the chain.
4. Back up `keys-2` and `/var/lib/umbra-signer/keychain` offline, as above.
5. Move the old key directory offline. Keep it until no build that ships the
   old set is still in use.

The signer refuses to sign under keys that the chain does not end at, thus
a mistyped `umbra_signer_keys` stops the hourly manifest rather than every
app.

## Checks

```sh
ansible all -m command -a 'systemctl --failed'
ansible relays -m command -a 'journalctl -u umbra-relay -n 20 --no-pager'
curl -sI https://signer-west.<domain>/.well-known/umbra/manifest
```
