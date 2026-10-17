# Deploying the UMBRA network on Kubernetes

The Helm chart `umbra/` runs the services of `deploy/ansible` on a cluster:
one node for each server of the launch network, each service on the node of
its server. `deploy/ansible/README.md` explains the network itself; read it
first. `deploy/docker/README.md` gives the same deployment with Docker
Compose, and the chart uses the same image, the same entry, and the same
directories.

A relay states the address of its server, and a client dials that address.
Thus each relay, the notification server, the directory, the manifest
carrier, and the measurer use the network of their node (`hostNetwork`).
The firewall of the node applies to them. The signer has a pod network,
and a NetworkPolicy closes it to each connection. The state of each service
stays on its node, under `root` (`/srv/umbra`).

## What the cluster needs

- One node for each server, with the public address of that server. k3s
  joins four VPS into one cluster:

  ```sh
  curl -sfL https://get.k3s.io | sh -s - --disable traefik --disable servicelb   # signer-west-1
  curl -sfL https://get.k3s.io | K3S_URL=https://<signer>:6443 K3S_TOKEN=<token> sh -   # each other
  ```

  The token is in `/var/lib/rancher/k3s/server/node-token` on the first
  node. Keep port 6443 and the ports of the cluster network (k3s: 8472/udp
  and 10250) open between the nodes alone.
- A controller that applies a NetworkPolicy. k3s holds one.
- The node names of `servers` (or set `node` of each server to its name).
- The image on each node, or in a registry that the nodes read:

  ```sh
  docker compose build                                      # in the root of the repository
  docker save umbra-servers | sudo k3s ctr images import -   # on each node
  ```

- A namespace that permits the network and the files of a node. The pods
  need the `privileged` level of pod security for `hostNetwork`,
  `hostPath`, and the init container that sets the owners. Each service
  itself runs with no root, a read-only file system, and no capability.
- The host settings of `deploy/docker/README.md`: a clock that follows the
  network time, port 443 for a user with no root
  (`net.ipv4.ip_unprivileged_port_start=443`), and the firewall of each
  server.

## The first install

1. Fill in a values file of your own from `umbra/values.yaml`: the domain,
   `family` (`openssl rand -hex 32`, one time), `asn`, and each server with
   its address and its relays.

2. Give the notification server its Firebase service account:

   ```sh
   kubectl create namespace umbra
   kubectl -n umbra create secret generic umbra-fcm --from-file=fcm.json=<the JSON file>
   ```

3. Install:

   ```sh
   helm install umbra deploy/helm/umbra -n umbra -f <your values>
   ```

   certbot gets the certificate of each server. The notification server
   and the directory start and make their keys. Each relay signs its
   descriptor and waits for the key set. The signer makes the seven
   authority keys. Back up `<root>/signer` on the signer node offline now.

4. Collect the public values, and give them to the network:

   ```sh
   bash deploy/helm/collect.sh umbra
   helm upgrade umbra deploy/helm/umbra -n umbra \
       -f <your values> -f deploy/helm/build/network-values.yaml
   ```

   The exit relays get the key of the notification server and the pins of
   the directory, each relay gets the key set, and the signer gets each
   descriptor. The signer then signs the first manifest, and each relay
   fetches it and starts.

5. The release app:

   ```sh
   bash deploy/helm/collect.sh umbra      # now with the manifest
   bash scripts/release-network.sh deploy/helm/build
   ```

## Checks

```sh
kubectl -n umbra get pods -o wide
kubectl -n umbra logs deploy/signer
kubectl -n umbra logs deploy/relay-entry-east
curl -sI https://signer-west-1.<domain>/.well-known/umbra/manifest
```

A line with `ALERT` names a failure that needs the operator. A failed
signer leaves the old manifest, and the network stops when that one ends,
three hours later.

## Later changes

- **A new image:** give one server the new tag in `imageTag` and run
  `helm upgrade`. Check its pods, then do the next server. Set `image.tag`
  and delete each `imageTag` at the end. One server at a time keeps the
  others up, as the serial runs of `deploy/ansible` do.
- **A changed class, or a relay more or less:** change `servers` and run
  `helm upgrade`. A relay whose descriptor lines changed signs a new
  descriptor. Run `collect.sh` and `helm upgrade` again to give it to the
  signer. An hour takes one manifest (`REL-160`), thus the new set takes
  effect at the next hour. Then restart each relay one at a time
  (`kubectl -n umbra rollout restart deploy/relay-<name>`).
- **A second manifest in this hour:**

  ```sh
  kubectl -n umbra exec deploy/signer -- umbra-entry signer sign --force
  ```

- **A rotation of the authority keys:** run `umbra-signer keygen` and
  `umbra-signer rotate` of `deploy/ansible/README.md` with
  `kubectl exec deploy/signer --`, then set `signer.keysDir` and upgrade.
- **The class tests now:**

  ```sh
  kubectl -n umbra exec deploy/measurer -- umbra-entry measurer now
  ```

## Taking a relay out

Delete the relay from `servers` and run `helm upgrade`. Its pod stops. Its
seed and its store stay in `<root>/relays/<name>` on its node, in case it comes
back with the same identity.
