# Run an UMBRA relay at home

`compose.yaml` in the root of the repository runs one UMBRA relay on your
own machine: a home server, a homelab, or a VPS. The relay joins the public UMBRA network after the owner
of the network admits it. It carries encrypted cells only. It never sees a
message, a contact, or a name.

For Kubernetes or k3s, use the Helm chart `deploy/helm/umbra-relay`. The
steps below are the same, and its `values.yaml` holds the settings.

## What your machine needs

| Need | Why |
| --- | --- |
| Linux with Docker Engine 24 or newer and the compose plugin | The relay uses the network of the host. Docker Desktop on Windows or macOS gives it another address. An x86-64 or ARM64 machine works. |
| A public IPv4 address that reaches this machine | Phones and other relays dial the address in the descriptor. Carrier-grade NAT (CGNAT) does not work. |
| A DNS name with an A record to that address | The relay shows a certificate for this name. A dynamic DNS name works. |
| Port 80 and the relay port, forwarded on your router | certbot uses port 80 for the certificate. |
| 100 Mbit/s or more in both directions | The network lists no relay below class 0 (Part 10 `REL-197`). Upload counts too. |
| A clock that follows the network time | chrony or systemd-timesyncd. A root of the directory lives three hours, and a wrong clock rejects it. |
| 2 GB of memory for a middle relay, 3 GB for an exit relay | An exit relay holds its file chunks in memory. |

## Select a role

| Role | What it does | What it needs |
| --- | --- | --- |
| `middle` | The middle of a chain. It sees no client address and no queue. | The least. Start with this role. |
| `exit` | The last relay of a chain. It holds message queues and file chunks, and it pushes alerts to phones. | A machine that stays on, and memory for the chunks. |
| `entry` | The first relay, which phones reach. | Port 443 and class 1 (250 Mbit/s) or more. |

## Steps

1. Clone the repository.

   ```sh
   git clone https://github.com/alumiia-labs/umbra.git
   cd umbra
   ```

2. Copy the settings file, and fill it in. Each line of `relay.env.example`
   has its explanation.

   ```sh
   cp deploy/relay/relay.env.example .env
   ```

3. Get the image. `pull` takes the release image. `build` compiles it from
   this clone, which takes about 20 minutes.

   ```sh
   docker compose pull    # or: docker compose build
   ```

4. Start the relay.

   ```sh
   docker compose up -d
   docker compose logs -f relay
   ```

   The relay makes its keys one time, gets its certificate, and signs its
   descriptor. Until the network admits it, the log says that no manifest
   gives this relay a place. That is correct.

5. Make the join request.

   ```sh
   docker compose run --rm relay join
   ```

   The command prints a block of text. Open a
   [relay request](https://github.com/alumiia-labs/umbra/issues/new?template=relay.yml)
   on GitHub, and paste the block into it. The request holds your descriptor
   and the facts of the dossier of Part 10 §10.6.

## After the request

The owner of the network checks the request (Part 10 `REL-012`), and adds
the relay to the signer. Then the relay goes through the admission of Part
10 §10.5.4 and §10.7.1:

| Time | State |
| --- | --- |
| The first hour | The manifest lists the relay as pending. Your relay sees its own entry, and no client uses it. |
| 4 days | The directory places the relay at its layer from a hash. You do not select the layer. |
| 14 days | An entry relay gets the ingress flag. Phones then reach it. |

The network tests the class of the relay. A relay that fails the test of
its class goes to a lower class. A relay that fails class 0 leaves the
manifest.

## Keep it running

- **Updates.** `git pull`, then `docker compose pull` and `docker compose up -d`.
- **A new address.** A new IPv4 address, name, port, class, or role makes a
  new descriptor. The relay signs it at its next start. Run `join` again,
  and put the new block in a comment on your request. Until the signer has
  it, clients dial the old address.
- **Backups.** Back up `data/relay`. It holds the keys of the relay. A
  lost key makes a new relay, which waits 4 days again.
- **Your own certificate.** Set `COMPOSE_PROFILES=` in `.env`. Put
  `cert.pem` (the full chain) and `key.pem` in `data/tls`. Give them the
  group 10000, and mode 0640 for the key. The relay starts again when the
  files change.
- **Stop.** `docker compose down`, and tell the owner on your request.

## A port below 1024

Docker gives the relay user no capability, thus port 443 needs a setting of
the host:

```sh
echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/90-umbra.conf
sudo sysctl --system
```

An entry relay needs this setting. A middle or exit relay can take a port
above 1024, as 9443, and needs no setting.

## Two relays or more

Give each relay its own directory and its own `UMBRA_ROOT`. Give each the
same `UMBRA_FAMILY`, which you make one time with `openssl rand -hex 32`. A
client then puts no two of your relays in one chain (Part 10 `REL-011`).
Two relays on one machine need two ports, and each one states its share of
the link as its class.

## What the relay keeps

The relay keeps its keys, the queues of its clients when it is an exit
relay, and a small log. The log holds no message. It can hold client
addresses for a short time, thus Docker keeps at most 60 MB of it.
