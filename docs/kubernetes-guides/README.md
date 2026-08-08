---
title: "Kubernetes integration guides"
weight: 60
---

How to make a cluster's `kube-apiserver` encrypt its Secrets through a running
`k8s-kms-plugin`. One page per distribution, covering the `EncryptionConfiguration`, how the
apiserver reaches the plugin's unix socket, and how to prove encryption is actually happening.

Do the [HSM & TPM](../hsm-guides/README.md) side first: these guides assume a `k8s-kms-plugin serve`
already running against a PKCS #11 provider.

| Distribution | Tested with | Runs where | Also covers |
|--------------|-------------|------------|-------------|
| [`KinD`](./kind-kubernetes.md) — **recommended for testing** | `kind v0.32.0` (Kubernetes v1.36.1) | In a Podman or Docker container | The two-hop socket mount, rootless Podman, and a troubleshooting table |
| [`k3s`](./k3s-kubernetes.md) | `v1.33.1+k3s1` | On the host | Key rotation with `serve rotation`, and HA with three server nodes |

Both need Kubernetes **v1.29 or newer** — `k8s-kms-plugin` serves only
[KMS v2](https://pkg.go.dev/k8s.io/kms/apis/v2), and KMS v1 is disabled by default from v1.29.

Both use the reference
[`EncryptionConfiguration`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml)
from [`deployments/k8s/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/deployments/k8s/).
The one field to get right is `resources.providers.kms.endpoint`: it must name the same unix socket
the plugin is listening on, as seen *from inside the apiserver*. That is what makes `KinD` more work
than `k3s` — the socket has to cross two boundaries rather than none.

## Which distribution to pick

`KinD` if you are evaluating or developing: the cluster is created and deleted in one command each,
and nothing is installed on the host. `k3s` if you want the plugin exercised on a host-installed
cluster, or if you are testing key rotation or high availability — those are only documented there.

Any distribution that supports KMS v2 and lets you pass
`--encryption-provider-config` to the apiserver will work; these two are simply the ones tested and
written up. Contributions covering another distribution are welcome.
