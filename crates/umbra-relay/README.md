# umbra-relay

The relay of the UMBRA protocol: the circuit hops of Part 3 §3.4, the pairwise
queues of Part 3 §3.2, the invitations of Part 4 §4.3.1, the community cache
of Part 12, the chunk store of Part 13, and the group queues of Part 3 §3.2.7.
The node is a plain state machine. The binary puts TLS 1.3, the WebSocket
framing of Part 6 §6.2.1, a pacing clock, and an SQLite store around it.

This revision serves a test network. It has no push path, and the issuer key
of its settings admits nothing.
It reads a signed relay manifest of Part 10, and section 7 shows that form.
No real directory authority exists yet, thus one process holds the seven test
keys.

## A test network of three relays

A client builds a circuit of three hops, thus a network needs one relay of
each layer. Use three machines of three operators for a test that means
something. One machine with three ports shows that the software runs, and it
hides nothing from its one operator.

### 1. Build

```sh
cargo build --release -p umbra-relay --features native
```

The binary is `target/release/umbra-relay`. The build needs a C compiler and
CMake for the TLS library and for SQLite.

### 2. An identity for each relay

```sh
umbra-relay keygen
```

It prints a `relay_id` line and a `static_secret` line. The secret shows one
time. Put the two lines into the settings file of that relay, and keep that
file readable for the service user alone.

### 3. A certificate for each relay

A client checks the certificate against the web roots. Get one for the host
name of the relay from a public authority, for example with `certbot certonly
--standalone -d relay1.example.org`. The relay reads the chain and the key at
its start, thus a renewal needs a restart. The queues outlive that restart.

### 4. The settings file

```text
listen=0.0.0.0:443
layer=1
relay_id=<from keygen>
static_secret=<from keygen>
cert=/etc/letsencrypt/live/relay1.example.org/fullchain.pem
key=/etc/letsencrypt/live/relay1.example.org/privkey.pem
issuer_modulus=<512 hex characters; a test network uses ff repeated 256 times>
community_capacity=67108864
store=/var/lib/umbra/relay.db
public=relay1.example.org,203.0.113.7,443
next=<relay_id of the layer 2 relay>,relay2.example.org,203.0.113.8,443
```

- `layer` is 1 for the guard, 2 for the middle relay, and 3 for the queue
  relay.
- A relay of layer 1 or 2 has one `next` line for each relay of the next
  layer. A relay of layer 3 has none.
- `store` names the SQLite file of the queues. With no such line the queues
  sit in RAM, and a restart ends each contact that the relay served.
- `public` is the host name of the certificate, the IPv4 address, and the
  port that a client dials.
- `trust` names one test authority in place of the web roots. A deployed
  relay has no such line.

### 5. A service

```ini
[Unit]
Description=UMBRA relay
After=network-online.target
Wants=network-online.target

[Service]
User=umbra
ExecStart=/usr/local/bin/umbra-relay /etc/umbra/relay.conf
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=umbra
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The relay stops when its store takes no commit, because it can acknowledge
nothing then (`NET-299`). `Restart=on-failure` brings it back.

### 6. The descriptor for a tester

```sh
umbra-relay descriptor /etc/umbra/relay.conf
```

Each relay prints one `relay` line with its facts. The settings file of a
relay declares them:

```text
operator=<a name for the party that runs this relay>
country=<the two letters of its jurisdiction>
asn=<the number of its autonomous system>
```

A client puts no two relays of one operator, of one jurisdiction bloc, of one
autonomous system, or of one IPv4 /16 into one chain (Part 3 §3.4.6), and it
builds no chain when the set permits none. Thus a useful network holds one or
more relays of each layer, under operators and in places that differ. Two
relays of layer 2 and two of layer 3 let the circuits of one client take
chains that differ. A `prefix=<a.b>` line names the /16 for a test network on
one machine, where each relay has one address.

Put the lines under a header, and add the invitation host:

```text
umbra-network 2
relay relay1.example.org 203.0.113.7 443 <static key> <relay id> layer=1 operator=north country=SE asn=64501
relay relay2.example.org 198.51.100.8 443 <static key> <relay id> layer=2 operator=alps country=CH asn=64502
relay relay3.example.org 192.0.2.9 443 <static key> <relay id> layer=3 operator=geyser country=IS asn=64503
invite invite.example.org
```

The first relay of layer 1 is the ingress that a client dials. A header
`umbra-network 1` with three lines and no facts still reads, as one path.

A tester pastes that text into the panel "Test network" on the unlock view of
a debug build of the Android app. The invitation host is a name inside each
link. No party has to serve it for a test, because a client never opens it
(`IDN-124`).

### 7. A network under a signed manifest

The descriptor of section 6 is a text that no party signs. The relay
directory of Part 10 replaces it: each relay signs a descriptor, and the
directory authorities sign a manifest over the relay set.

A relay of that form has an identity key, and its `relay_id` is the hash of
that key. Its settings file holds these lines in the place of `relay_id`,
`layer` and `next`:

```text
identity_seed=<from umbra-relay keygen>
family=<64 hex characters, one value for each family of relays>
class=<0 to 3>
roles=<queue,chain for a chain relay; chain,ingress for an ingress relay>
manifest=/var/lib/umbra/manifest.bin
keyset=/etc/umbra/keyset.bin
```

```sh
umbra-relay sign-descriptor /etc/umbra/relay.conf relay.desc
```

The operator gives `relay.desc` to the authority. The test authority takes
each descriptor and the facts that a real authority verifies:

```text
seed=<64 hex characters>
relay=relay1.desc,north,2,ingress
relay=relay2.desc,alps,2,chain
```

```sh
umbra-test-authority authority.conf /var/lib/umbra
```

It writes `manifest.bin` and `keyset.bin`. The layer of a chain relay with
the queue role comes from a hash that no operator selects (`REL-060`), thus a
small network can come out with no relay in one layer. The program prints the
layer of each relay. A relay reads its own layer and the relays of the next
layer from the manifest at its start. A client verifies the manifest under
the key set, which its build ships.

The address of a descriptor serves the clients and the relays of the layer
before, and the /16 of that address is the network that a client tests. Thus
two relays on one machine need two loopback networks, as `127.2.0.1` and
`127.3.0.1`. `scripts/devnet.sh` runs such a network of seven relays, with two ingress
relays for the two pins of a client.

A relay that reads a manifest also gives it to a client that asks over HTTPS
at `/.well-known/umbra/manifest` (Part 3 rule `NET-316`). The debug build of
the Android app reads it there from the ingress relay of the devnet. In a
deployment the co-tenant site of the relay serves that path as a file.

## What the store file holds

Queue identifiers, the public authorization keys, sequence numbers, the
ciphertext of each record that no `ACK` covers, and each invitation blob. Each
time is a multiple of one hour (`NET-301`). It holds no circuit, no session, no
subscription, and no address of a client (`NET-300`). The file runs under
`secure_delete`, and the relay truncates the write-ahead log after each commit
that deletes, thus an acknowledged record leaves no bytes behind (`NET-302`).

Do not copy the file of a live relay. Stop the relay, or use the backup
command of SQLite.

The chunks of Part 13 and the records of a group queue sit in memory alone.
A restart drops them, and each client finds them gone. The store of the
pairwise queues holds neither.
