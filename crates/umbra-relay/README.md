# umbra-relay

The relay of the UMBRA protocol: the circuit hops of Part 3 §3.4, the pairwise
queues of Part 3 §3.2, the invitations of Part 4 §4.3.1, and the community
cache of Part 12. The node is a plain state machine. The binary puts TLS 1.3,
the WebSocket framing of Part 6 §6.2.1, a pacing clock, and an SQLite store
around it.

This revision serves a test network. It has no relay directory, no attachment
service, no group queue, and no push path, and the issuer key of its settings
admits nothing.

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

Each relay prints one `relay` line. Put the three lines under a header, the
guard first, and add the invitation host:

```text
umbra-network 1
relay relay1.example.org 203.0.113.7 443 <static key> <relay id>
relay relay2.example.org 203.0.113.8 443 <static key> <relay id>
relay relay3.example.org 203.0.113.9 443 <static key> <relay id>
invite invite.example.org
```

A tester pastes that text into the panel "Test network" on the unlock view of
a debug build of the Android app. The invitation host is a name inside each
link. No party has to serve it for a test, because a client never opens it
(`IDN-124`).

## What the store file holds

Queue identifiers, the public authorization keys, sequence numbers, the
ciphertext of each record that no `ACK` covers, and each invitation blob. Each
time is a multiple of one hour (`NET-301`). It holds no circuit, no session, no
subscription, and no address of a client (`NET-300`). The file runs under
`secure_delete`, and the relay truncates the write-ahead log after each commit
that deletes, thus an acknowledged record leaves no bytes behind (`NET-302`).

Do not copy the file of a live relay. Stop the relay, or use the backup
command of SQLite.
