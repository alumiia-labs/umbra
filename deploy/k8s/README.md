# The test network on Kubernetes and k3s

`devnet/` runs the test network of `scripts/devnet.sh` on a cluster: seven
relays, the NDR, the directory, the authority, and the measurer in one pod.
The seeds of that network are in the repository, thus it protects nothing.
Run it on a test cluster alone.

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
   and set `image` in `devnet/deployment.yaml` to it.

3. Set the address that clients dial. It goes into the descriptors of the
   two ingress relays. 10.0.2.2 serves an emulator on the machine of the
   node. A phone or another machine needs the address of the node:

   ```sh
   cd deploy/k8s/devnet
   kustomize edit add configmap devnet --behavior=replace \
       --from-literal=UMBRA_DEVNET_HOST=192.168.1.254
   ```

   `kubectl kustomize` has no `edit`. Change the literal in
   `kustomization.yaml` in its place.

4. Start the network:

   ```sh
   kubectl apply -k deploy/k8s/devnet
   kubectl -n umbra-devnet logs -f deploy/devnet
   ```

   The log shows "the manifest names the report queue" when the network is
   ready. The load balancer of k3s opens the ports 7441 and 7446 on each
   node. The debug build of the app dials them (`android/README.md`).

5. Stop it. The command also deletes the volume, thus the queues of the
   relays:

   ```sh
   kubectl delete -k deploy/k8s/devnet
   ```

A new value of `UMBRA_DEVNET_HOST` takes a new pod. The relays sign new
descriptors at each start, and the volume keeps the queues.
