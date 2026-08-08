## Test `k8s-kms-plugin serve` with a `KinD` cluster

The script in this directory prepares the local environment needed to run
`k8s-kms-plugin` as a KMS v2 provider for a [`KinD`](https://kind.sigs.k8s.io/)
cluster (Podman or Docker).

**Prerequisites**: `kind` and `kubectl` in your `PATH`, plus `podman` (≥ 3.0) or
`docker`. See [`docs/kind-kubernetes.md`](../../docs/kind-kubernetes.md) for the
full walkthrough and the troubleshooting table.

---

### `rebuild-kms-dev.sh`

Creates the staging area shared between the host and the `KinD` node, and
generates the two configuration files that wire the plugin socket through to
`kube-apiserver`:

```
$KMS_DEV_ROOT/run/                                     <- the plugin unix socket lives here
$KMS_DEV_ROOT/config/encryption-conf-kmsv2-unix-socket.yaml
$KMS_DEV_ROOT/config/kind.config.yaml
```

```bash
./rebuild-kms-dev.sh
KMS_DEV_ROOT="$HOME/.kms-dev" ./rebuild-kms-dev.sh
./rebuild-kms-dev.sh --help
```

The script is **idempotent**: re-running it overwrites the two generated config
files and removes a stale socket left behind by a dead plugin. It does **not**
start the plugin, create the cluster, or modify an existing one — it prints the
commands to do so as next steps, adapted to the container runtime it detects.

> An existing cluster keeps the mounts it was created with. After changing
> `KMS_DEV_ROOT`, delete and recreate it: `kind delete cluster --name kms-dev`.

#### Configuration

Everything is overridable via environment variables:

| Variable        | Default                                   | Purpose                                          |
|-----------------|-------------------------------------------|--------------------------------------------------|
| `KMS_DEV_ROOT`  | `/tmp/kms-dev`                            | staging root (use `$HOME/.kms-dev` to persist)    |
| `CLUSTER_NAME`  | `kms-dev`                                 | `KinD` cluster name (context: `kind-kms-dev`)     |
| `PROVIDER_NAME` | `kms-server`                              | KMS provider name — appears in the etcd prefix    |
| `SOCKET_NAME`   | `k8s-kms-plugin-dev.sock`                 | unix socket file name                             |
| `KMS_TIMEOUT`   | `3s`                                      | KMS provider timeout                              |
| `PKCS11_MODULE` | `/usr/local/lib/softhsm/libsofthsm3.so`   | PKCS #11 library, printed in the next-steps hints |
| `P11_LABEL`     | `k8s-kms-plugin-dev`                      | token label                                       |
| `P11_PIN`       | `1234`                                    | token user PIN                                    |
| `P11_KEY_LABEL` | `dev-rsa-2048-oaep`                       | KEK label                                         |
| `ALGORITHM`     | `rsa-oaep`                                | `--algorithm-family` value                        |

The PKCS #11 defaults match the development token created by
[`create-dev-token`](../../tools/create-dev-token/) — see
[`docs/softhsm-v3.md`](../../docs/hsm-guides/softhsm-v3.md).

#### Typical session

```bash
# 1. stage the config files
./scripts/k8s-kind/rebuild-kms-dev.sh

# 2. start the plugin -- --log-level trace shows every KMS v2 request
k8s-kms-plugin serve \
    --log-level trace \
    --socket /tmp/kms-dev/run/k8s-kms-plugin-dev.sock \
    --p11-lib   /usr/local/lib/softhsm/libsofthsm3.so \
    --p11-label k8s-kms-plugin-dev \
    --p11-pin   1234 \
    --p11-key-label dev-rsa-2048-oaep \
    --algorithm-family rsa-oaep &

# 3. create the cluster
export KIND_EXPERIMENTAL_PROVIDER=podman
kind create cluster --config /tmp/kms-dev/config/kind.config.yaml

# 4. write a secret -- the plugin logs an EncryptRequest
kubectl --context kind-kms-dev create secret generic probe --from-literal=foo=bar
```

The plugin must be running **before** the cluster is created, otherwise
`kube-apiserver` starts with a temporarily unhealthy `/healthz` and noisy KMS
connection errors.
