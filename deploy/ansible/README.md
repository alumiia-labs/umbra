# Deploying the UMBRA network

These playbooks install the launch network on Debian: seven servers at
OVHcloud US, over two sites.

| Server | Site | Runs |
|---|---|---|
| `entry-east` | Vint Hill, Virginia | Entry relay (the two gateways' OHTTP relay) |
| `entry-west` | Hillsboro, Oregon | Entry relay |
| `middle-east` | Virginia | Middle relay |
| `exit-east` | Virginia | Exit relay and the notification server (`umbra-ndr`, port 8443) |
| `exit-west-1` | Oregon | Exit relay and the directory (`umbra-directory`, port 8443) |
| `exit-west-2` | Oregon | Exit relay |
| `signer-west` | Oregon | The directory signer; it signs the relay list each hour, and nginx serves it |

With one operator, the directory is *provisional* (Part 10 `REL-126`). The
app shows that, and the rules of Part 3 `NET-340` and `NET-350` let one
operator, one provider, and one country carry the traffic.

## What you need

- Seven Debian 12 or 13 servers.
  - An entry relay needs a plan with 250 Mbit/s or more. Each other relay
    needs 100 Mbit/s or more.
  - The signer takes the smallest plan.
- A domain. Give each server an A record: `entry-east.<domain>`, and so on.
- SSH as root, or as a user with sudo, to each server, from this machine.
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
- Put each relay's class in `class`: 0, 1, 2 or 3 for 100, 250, 500 or
  1 000 Mbit/s, in both directions. State only what the plan holds.
- An entry relay needs class 1 or more.

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

- **Back up the signer keys.** Copy `/var/lib/umbra-signer/keys` from
  `signer-west` to an offline place. Without those keys, no new manifest
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

- **The manifest.** The signer signs a manifest at two minutes past each
  hour; a root lives three hours. Each relay fetches the manifest from
  `https://signer-west.<domain>/.well-known/umbra/manifest` every five
  minutes. It replaces its copy only with a manifest that verifies and still
  lists it.
- **Certificates** renew on their own. A renewal restarts the service that
  uses the certificate.
- **The firewall** opens 22, 80 and 443. It opens 8443 on the notification
  server and the directory, to the relays alone.

## Checks

```sh
ansible all -m command -a 'systemctl --failed'
ansible relays -m command -a 'journalctl -u umbra-relay -n 20 --no-pager'
curl -sI https://signer-west.<domain>/.well-known/umbra/manifest
```
