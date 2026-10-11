# Deploying the UMBRA network

These playbooks install the launch network on Debian: four servers at
OVHcloud US, over two sites. A server can run two relays; the inventory
lists the relays of each server.

| Server | Site | Runs |
|---|---|---|
| `east-1` | Vint Hill, Virginia | Entry relay `entry-east` (port 443), exit relay `exit-1` (port 9443), and the notification server (`umbra-ndr`, port 8443) |
| `east-2` | Vint Hill, Virginia | Middle relay (port 443) and exit relay `exit-3` (port 9443) |
| `west-1` | Hillsboro, Oregon | Entry relay `entry-west` (port 443), exit relay `exit-2` (port 9443), and the directory (`umbra-directory`, port 8443) |
| `signer-west-1` | Hillsboro, Oregon | The directory signer; it signs the relay list each hour, and nginx serves it. The authority tool (`umbra-authority`) and the measurer (`umbra-measurer`) run beside it |

Three exit relays hold the two replicas of a group and the three copies of
a file. An entry relay takes port 443, since phones reach it. Each relay
runs as `umbra-relay@<name>`, with its files in `/etc/umbra/relays/<name>`
and `/var/lib/umbra-relay/<name>`.

The trade of two relays on one server: a chain whose entry and exit relay
share a server shows that server both ends. The operator runs every server
during the launch anyway; the trade is against one who breaks into one
server. The app avoids such a chain when it has another (Part 3 `NET-351`).

The app reaches the notification server and the directory through an
entry relay, which forwards the request and sees the address of the app
(OHTTP). That entry relay and the server that it forwards to sit on two
servers (Part 8 `NTF-002`). `entry-west` forwards to the notification
server on `east-1`, and `entry-east` forwards to the directory on `west-1`.
One who breaks into one server thus links no address to a push
registration. The run fails for an inventory with no entry relay on another
server than one of the two.

With one operator, the directory is *provisional* (Part 10 `REL-126`). The
app shows that, and the rules of Part 3 `NET-340` and `NET-350` let one
operator, one provider, and one country carry the traffic.

## What you need

- Four Debian 12 or 13 servers. OVH's VPS-1 (500 Mbit/s) serves each.
  - A server with two relays states the share of each: class 1 (250 Mbit/s)
    for each on a 500 Mbit/s plan. An entry relay needs class 1 or more.
  - The measurer on the signer tests class 0 alone on a 500 Mbit/s plan
    ("Measurement" below). The class of each relay above class 0 stays the
    one that the inventory states.
  - A relay server needs 4 GB of memory or more. An exit relay holds the
    bytes of each file chunk in memory, thus `umbra_chunk_capacity` is 1 GiB
    and not a part of the disk. See "Memory" below before you raise it.
- A domain. Give each server an A record: `east-1.<domain>`, `east-2.<domain>`,
  `west-1.<domain>`, and `signer-west-1.<domain>`.
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
| `umbra_asn` | `whois <address of a server>` prints the AS number of OVHcloud |
| `umbra_family` | `openssl rand -hex 32`, made once and kept |
| `umbra_fcm_credentials` | The path of the Firebase JSON on this machine |
| `umbra_ssh_from` | Your own IP addresses, IPv4 or IPv6, to close SSH to everyone else. It needs an address of the family of `ansible_host` (IPv4), or the run stops. Optional |
| `umbra_alert_command` | A command that tells you when the signer fails. Optional |
| `umbra_reboot_hour` | The hour at which the first server restarts after an update that needs it. Optional |

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
   The key set and the manifest come back to `build/`. The authority tool
   starts on the same server, and the measurer gets its key and its timer.
5. Each relay takes the key set and the manifest, then starts.

A later run changes nothing that is already in place. It makes no key again,
and a relay signs its descriptor again only when its settings changed.
Run it again after:

- a new binary;
- a new relay in the inventory;
- a changed class.

A run goes through the relay servers one at a time, and the relays of one
server restart one after the other. A relay that does not come back stops
the run before the next server.

An hour takes one manifest (Part 10 `REL-160`): an app that holds the
manifest of an hour rejects a second one for it. Thus:

- A run that changes nothing leaves the manifest of the hour in its place.
- A run that changes the relay set, a class, or a descriptor waits at the
  signer for the next hour and signs then. The wait is 60 minutes at most.
  Start such a run late in the hour for a short wait.
- `ansible-playbook site.yml -e umbra_sign_force=true` signs a second
  manifest for the hour at once. Each app that holds the first one keeps
  the old relay set until the next hour. It can show a warning about the
  directory (`REL-161`). Use it to take a relay out without a wait.
- To make a relay sign a new descriptor with no changed setting, delete
  `/var/lib/umbra-relay/<name>/relay.desc` on its server. Then run again.

## After the first run

- **Back up the signer keys.** Copy `/var/lib/umbra-signer` from
  `signer-west-1` to an offline place: each key directory and the key chain.
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
    manifest from;
  - `shipped_epoch`, the epoch of the manifest that the last run brought
    back (Part 10 `REL-045`). The app refuses each older manifest, thus run
    the script again before each release build.

  Each value is public, so commit the assets. A build without them has no
  network.

  A release build holds `ndr_relay` and `directory_relay` of
  `umbra-network.properties` as they were at its build. They name the entry
  relays that forward to the notification server and to the directory. An
  installed build keeps calling those two servers. Before a run that moves
  an entry relay to another server, ship an app release with the new file.
  Do the same before a run that changes which relay forwards to which
  server. An older build loses its push registration and its directory
  calls at that run.
- **Keep `build/`.** It holds no secret, and git ignores it.

## How it runs

- **Hardening.** Each server gets the following:
  - SSH by key alone, with no forwarding. fail2ban bans an address after 5
    SSH failures in 10 minutes.
  - The kernel settings of a server that routes nothing: no forged source,
    no redirects, SYN cookies, and no process that reads another's memory.
  - No crash dumps, since a dump of a service could hold its keys.
  - A journal that keeps 7 days, because a relay sees client addresses.
  - Security updates install by themselves. An update that needs a restart
    restarts the server at `umbra_reboot_hour`:30 by the clock of the
    server. Each next server of the inventory restarts one hour later, thus
    no two servers are down together.
- **Services.** Each service runs as its own user, in a systemd sandbox:
  - a read-only system, and write access to its own folder alone;
  - a syscall filter and no new privileges;
  - no capabilities beyond the low port of a relay;
  - a memory limit ("Memory" below).

  The relays of one server share the user `umbra-relay`. The unit of each
  relay hides the settings and the store of the other one. That stops a
  plain read of the files. It does not stop each path between two processes
  of one user. A user for each relay would, and the playbook makes none yet.
- **Memory.** `MemoryMax` stops a service that grows past its limit, and
  systemd starts it again; the other services of the server keep their
  memory. The values are in `group_vars/all.yml`:

  | Service | Slows at | Stops at |
  |---|---|---|
  | Entry or middle relay | `umbra_relay_memory_high`, 1200M | `umbra_relay_memory_max`, 1400M |
  | Exit relay | `umbra_exit_memory_high`, 2300M | `umbra_exit_memory_max`, 2500M |
  | Notification server, directory, authority tool, one run of the measurer | `umbra_service_memory_high`, 448M | `umbra_service_memory_max`, 512M |
  | Signer, one run; one measurer certificate | `umbra_signer_memory_high`, 448M | `umbra_signer_memory_max`, 512M |

  An exit relay holds the bytes of each file chunk in memory, and it reads
  them two times at its start. Its limit is thus two times
  `umbra_chunk_capacity` and room for its queues. With a lower limit, a full
  store stops the relay at each start. The three limits of a relay server
  add up to more than 4 GB. Only the exit relay comes near its limit, and
  only while it starts with a full store. Raise `umbra_chunk_capacity` only
  on a server with more memory. Raise `umbra_exit_memory_max` with it.
  The three exit relays then declare 1 GiB each, which Part 12 `ATT-086`
  permits under the provisional directory alone.
- **The clock.** A manifest lives three hours. Thus each service starts
  after chrony has set the clock (`umbra-clock.service`), and the signer
  waits for it before each run.
- **The manifest.** The signer signs a manifest at two minutes past each
  hour; a root lives three hours. Each relay fetches the manifest from
  `https://signer-west-1.<domain>/.well-known/umbra/manifest` every five
  minutes. It replaces its copy only with a manifest that verifies and still
  lists it. nginx on the signer keeps no log of a request, neither of one
  that it served nor of one that failed.
- **The authority tool.** `umbra-authority` holds the report queue of
  authority 0 at an exit relay, as an app holds a queue. The manifest names
  that queue, and each app sends its link-fault reports there (Part 10
  `REL-166`). The tool counts the reports of each hour. For a relay above
  the fault rate it runs the isolation query (`REL-080`), and it writes
  each verdict to `/var/lib/umbra-authority/verdicts`. The signer reads
  that file each hour: a relay with an `expel` line leaves the manifest,
  and a link with a `link` line takes a removal for 7 days.
  - The tool runs as the user `umbra-signer`, because it reads the seed
    files of that user. Its unit hides the seeds of the authorities 2 to 6.
    Its settings file, `/etc/umbra-authority/authority.conf`, holds no
    secret.
  - The tool makes the two secrets of its report queue in
    `/var/lib/umbra-authority/secrets` at its first start, each readable by
    its owner alone. It refuses a seed file or a secret file that a group
    or each other user can read.
  - One operator holds each key, thus the tool is both aggregators of the
    chain count (Part 10 §10.8).
- **Measurement.** `umbra-measurer` runs the class test of each relay one
  time in each 7 days (Part 10 `REL-097`): the timer starts it at a random
  time in the 12 hours after Monday 02:20. A test sends echo cells to one
  relay for 30 seconds at 2.25 times the rate of the class, and the relay
  passes when the echoes reach the rate of the class.
  - Each run takes a new certificate first (`umbra-measurer-cert`). The
    signer issues it under the keys of the authorities 5 and 6, for
    `umbra_measurer_cert_epochs` hours. The measurer runs as its own user
    and reads no authority key.
  - Each test is one line of `/var/lib/umbra-measurer/results`:
    `<relay_id> <class> <pass|fail> <epoch>`. The signer reads the file
    each hour. A failed test at a class lists the relay below that class
    in the next manifest. A failed test at class 0 takes the relay out of
    the manifest. A later pass lists it again, and its class then rises by
    one step in each 7 days at most (`REL-001`);
    `/var/lib/umbra-signer/state/class_state` holds the class and the
    epoch of the last step of each relay. An entry relay below class 1
    stays in the manifest as a middle relay, and it takes no phone.
  - **What this measurer cannot test.** A test needs 225 Mbit/s for
    class 0, 562.5 for class 1, 1 125 for class 2, and 2 250 for class 3.
    The signer server has 500 Mbit/s (`umbra_measurer_capacity`). It thus
    tests class 0 alone, two relays in one slot. No test of this
    deployment verifies class 1 or above, and each relay keeps the class
    of the inventory above class 0. Part 10 §10.2 permits that under the
    provisional directory alone.
  - The six relays share one network (one ASN), thus they are one cluster
    of Part 10 §10.3. The rule puts 4 relays of such a cluster in one
    slot. The capacity holds 2, thus a run takes 3 slots, and the measurer
    says so in its log. Which relays share a slot comes from the random
    generator of the server at each run.
  - A relay gives a measurer that it refuses no sign. A relay that opened
    no session thus gets no result line, the run ends with a failure, and
    `umbra-alert@umbra-measurer` tells you. Such a relay keeps its class.
  - To revoke a certificate, take its `measurer_id` and its `not_after`
    from `journalctl -u umbra-measurer-cert`, add them to
    `umbra_revoked_measurers`, and run the playbook. The root of the next
    manifest names the measurer, and each relay then refuses it
    (`REL-104`, `REL-105`). Delete the two files of
    `/var/lib/umbra-measurer/keys` before that run, and it makes a new key.
- **A failed signer run** leaves the old manifest in place, and the network
  stops when that one ends. The unit `umbra-alert@umbra-signer` then writes a
  line of the highest priority to the journal and to each open terminal.
  It also runs `umbra_alert_command` with the name of the unit when you set
  one, as a script that sends a mail.
- **Certificates** renew by themselves. A renewal restarts the services that
  use the certificate, one at a time.
- **The firewall** opens 22, 80, and the port of each relay of the server
  (443, 9443). It opens 443 on the signer, and 8443 on the notification
  server and the directory, to the relay servers alone. A change of the
  rules keeps the SSH bans of fail2ban.

## Rotating the directory keys

Rotate the keys when a signer key leaks or is lost, or when an independent
authority joins (Part 10 `REL-036`). The old keys sign the new set. Each
relay and each installed app then walks the chain to the new set by itself
(`REL-200`), so no app update is needed.

On `signer-west-1`:

```sh
sudo -u umbra-signer umbra-signer keygen /var/lib/umbra-signer/keys-2 2
sudo -u umbra-signer umbra-signer rotate /var/lib/umbra-signer/keys     /var/lib/umbra-signer/keys-2 /var/lib/umbra-signer/keychain
```

The second argument of `keygen` is the epoch of the new set: one above the
current one, and `rotate` refuses each other value (`REL-037`). A new set
that is not provisional takes a fourth argument of `rotate`, the published
manifest file. The tool refuses the set while an ingress relay of that
manifest has no chain of different operators (`REL-142`). Then:

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

The playbook makes keys on a signer that holds none, and never after that.
A signer with a key chain, a key directory, or a published key set gets no
new keys. When `umbra_signer_keys` then names a directory with no key set,
the run stops and says so.

The signer refuses to sign under keys that the chain does not end at, thus
a mistyped `umbra_signer_keys` stops the hourly manifest rather than every
app.

## Limits of this deployment

- **The invitation host.** An invitation link is
  `https://<umbra_invitation_host>/i#<fragment>`, and the host is the domain
  itself unless `umbra_invitation_host` names another. No role of this
  playbook serves it. The web site of that host has to serve two static
  files before a release. The first is `/.well-known/assetlinks.json` with
  the package `com.alumiialabs.umbra` and the SHA-256 of the release signing
  certificate (`IDN-122`). The second is the landing document at `/i`, which
  holds no script and no third-party resource (`IDN-120`, `IDN-121`). Without
  the first file Android does not verify the App Link, and a tap on a link
  opens the browser and not the app. The folder `site/` of this repository
  holds those files and the way to deploy them.

- **One measurer, class 0 alone.** Part 10 §10.5.1 accepts a class from 3
  measurers in 2 networks. This deployment has one measurer on one server
  of 500 Mbit/s, which tests class 0 alone ("Measurement" above).
- **The keys of the authority tool.** The tool holds the keys of the
  authorities 0 and 1 while it runs, on a server that reaches the network.
  The signer run and the certificate run hold each key with no network.
- **A user for each relay.** The relays of one server share one user
  ("How it runs").
- **The key chain before a rotation.** The signer publishes no key chain
  before the first rotation, as `REL-199` says; nginx answers 404 and logs
  nothing.

## Checks

```sh
ansible all -m command -a 'systemctl --failed'
ansible relays -m command -a "journalctl -u 'umbra-relay@*' -n 20 --no-pager"
ansible signer -m command -a 'journalctl -u umbra-signer -n 20 --no-pager'
curl -sI https://signer-west-1.<domain>/.well-known/umbra/manifest
ansible signer -m command -a 'journalctl -u umbra-authority -n 20 --no-pager'
ansible signer -m command -a 'systemctl list-timers umbra-measurer.timer --no-pager'
ansible signer -m command -a 'journalctl -u umbra-measurer -u umbra-measurer-cert -n 40 --no-pager'
ansible signer -m command -a 'tail -n 12 /var/lib/umbra-measurer/results'
```

The log of the signer shows one line for each run. A new manifest gives
`epoch=<hour>` with the count of the relays and `report_queues=1` once the
authority tool made its queue. An hour that had a manifest already gives
`kept=same` or `kept=other`. Each relay has a line with its `class=`.

The log of the authority tool shows `authority online` and, one time,
`report queue made`. Each report of an app is one line.

To run the measurer now, and not at its timer:

```sh
ansible signer -b -m command -a 'systemctl start umbra-measurer'
```

The run takes about two minutes for six relays. Its log holds one result
line for each relay and the rate of the echoes. A line `gave no result`
names a relay that opened no measurement session.
