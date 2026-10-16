# The test network on Kubernetes and k3s

The Helm chart `umbra-devnet/` runs the test network of `scripts/devnet.sh`
on a cluster: seven relays, the NDR, the directory, the authority, and the
measurer in one pod. The seeds of that network are in the repository, thus
it protects nothing. Run it on a test cluster alone.

A real network does not run here. Each of its relays needs a public address
of its own, port 443 on the host, and a certificate of its name, and the
signer keeps its keys off the network. `deploy/ansible/README.md` gives that
deployment.

## Steps on k3s

1. Build the image in the root of the repository:

   ```sh
   docker compose build
   ```

2. Give the image to the cluster. k3s pulls no local image, thus import it
   on each node:

   ```sh
   docker save umbra-devnet:latest | sudo k3s ctr images import -
   ```

   On another cluster, push the image to a registry that the cluster reads,
   and set `image.repository` and `image.tag` to it.

3. Start the network. `host` is the address that clients dial, and it goes
   into the descriptors of the two ingress relays. The default 10.0.2.2
   serves an emulator on the machine of the node. A phone or another
   machine needs the address of the node:

   ```sh
   helm install umbra-devnet deploy/helm/umbra-devnet \
       --namespace umbra-devnet --create-namespace \
       --set host=192.168.1.254
   kubectl label namespace umbra-devnet \
       pod-security.kubernetes.io/enforce=restricted
   kubectl -n umbra-devnet logs -f deploy/umbra-devnet
   ```

   The pod meets the `restricted` pod security level, thus the label is
   optional. The log shows "the manifest names the report queue" when the
   network is ready. The load balancer of k3s opens the ports 7441 and 7446
   on each node. The debug build of the app dials them (`android/README.md`).

4. Stop it. The command also deletes the volume, thus the queues of the
   relays:

   ```sh
   helm uninstall umbra-devnet --namespace umbra-devnet
   ```

A new value of `host` (`helm upgrade --set host=...`) takes a new pod. The
relays sign new descriptors at each start, and the volume keeps the queues.
`values.yaml` gives the other settings: the service type, the volume, and
the resources.
