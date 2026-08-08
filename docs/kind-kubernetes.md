---
title: "KinD"
weight: 61
---

This guide explains how to run a [`KinD`](https://kind.sigs.k8s.io/) (Kubernetes **in D**ocker or Podman) cluster against a
local `k8s-kms-plugin serve` instance listening on a unix socket, with **Podman** as the container provider
(the Docker variant is given as well — only the cluster creation step differs).

⚠️ **This guide is for testing purposes only. Do not use it in a production environment.**

- [Why `KinD` needs more wiring than `k3s`](#why-kind-needs-more-wiring-than-k3s)
- [Prerequisites](#prerequisites)
- [Stage the environment with `rebuild-kms-dev.sh`](#stage-the-environment-with-rebuild-kms-devsh)
- [The same, by hand](#the-same-by-hand)
  - [Staging directories](#staging-directories)
  - [The `EncryptionConfiguration`](#the-encryptionconfiguration)
  - [The `KinD` cluster config](#the-kind-cluster-config)
- [Start `k8s-kms-plugin serve`](#start-k8s-kms-plugin-serve)
- [Create the cluster](#create-the-cluster)
  - [Podman](#podman)
  - [Docker](#docker)
- [Verify the wiring](#verify-the-wiring)
- [Confirm that encryption really happens](#confirm-that-encryption-really-happens)
- [Cleanup](#cleanup)
- [Troubleshooting summary](#troubleshooting-summary)

## Why `KinD` needs more wiring than `k3s`

With [`k3s`](./k3s-kubernetes.md), `kube-apiserver` runs as a normal process directly on the host, so any host path —
including the plugin's unix socket — is already visible to it.

`KinD` is different: each "node" is itself a container, and inside that container `kube-apiserver` runs as a *second*,
nested container (a static pod managed by `kubelet`). The host filesystem is therefore **two hops** away from the
process that needs to reach the KMS socket:

```
┌─ Host machine ────────────────────────────────────────────────────────────────┐
│                                                                               │
│   k8s-kms-plugin serve                                                        │
│   socket: /tmp/kms-dev/run/k8s-kms-plugin-dev.sock                            │
│                                                                               │
│   (1) KinD extraMounts:  /tmp/kms-dev/run  ->  /kms-socket                    │
│                                                                               │
│   ┌─ KinD node (container) ───────────────────────────────────────────────┐   │
│   │                                                                       │   │
│   │   /kms-socket/k8s-kms-plugin-dev.sock                                 │   │
│   │                                                                       │   │
│   │   (2) kubeadm apiServer.extraVolumes:  /kms-socket  ->  /kms-socket   │   │
│   │                                                                       │   │
│   │   ┌─ kube-apiserver (static pod) ────────────────────────────┐        │   │
│   │   │                                                          │        │   │
│   │   │   endpoint: unix:///kms-socket/k8s-kms-plugin-dev.sock   │        │   │
│   │   │                                                          │        │   │
│   │   └──────────────────────────────────────────────────────────┘        │   │
│   │                                                                       │   │
│   └───────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

Each nesting level re-exposes the socket one hop deeper: **(1)** `extraMounts` carries the host directory into the
node container, **(2)** `apiServer.extraVolumes` carries it from the node into the static pod.

Both mounts have to be wired through explicitly, and the `endpoint:` of the `EncryptionConfiguration` must reference
the socket path **as seen from inside the apiserver container**, not the host path.

## Prerequisites

- `kubectl`
- `kind` — this guide was written with `kind v0.32.0`, which defaults to Kubernetes `v1.36.1`
- **Podman ≥ 3.0** (this guide) or Docker ≥ 20.10
- A `k8s-kms-plugin` binary and a PKCS #11 token — see [`SoftHSMv3`](./hsm-guides/softhsm-v3.md) for the recommended
  development setup, or [`Thales eToken Fusion`](./hsm-guides/thales-etoken-fusion.md) / [`Yubico YubiHSM 2`](./hsm-guides/yubico-yubihsm2.md)
  for real hardware

```sh
kind version
kubectl version --client
podman info | grep cgroupVersion
```

`k8s-kms-plugin` implements the [KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2) only, so the cluster must be
Kubernetes v1.29 or higher. Any recent `KinD` node image satisfies this.

## Stage the environment with `rebuild-kms-dev.sh`

The script only **prepares files**. Starting the plugin and creating the cluster stay in your hands — deliberately,
since both are stateful and long-lived:

| Step                                        | Done by                                       | Section                                          |
|---------------------------------------------|-----------------------------------------------|--------------------------------------------------|
| Staging directories `run/` + `config/`      | 🤖 script                                     | [Stage the environment with `rebuild-kms-dev.sh`](#stage-the-environment-with-rebuild-kms-devsh) / [Staging directories](#staging-directories) |
| `encryption-conf-kmsv2-unix-socket.yaml`    | 🤖 script                                     | [Stage the environment with `rebuild-kms-dev.sh`](#stage-the-environment-with-rebuild-kms-devsh) / [The `EncryptionConfiguration`](#the-encryptionconfiguration) |
| `kind.config.yaml`                          | 🤖 script                                     | [Stage the environment with `rebuild-kms-dev.sh`](#stage-the-environment-with-rebuild-kms-devsh) / [The `KinD` cluster config](#the-kind-cluster-config) |
| Removing a stale socket from a dead plugin  | 🤖 script                                     | [Stage the environment with `rebuild-kms-dev.sh`](#stage-the-environment-with-rebuild-kms-devsh) |
| `k8s-kms-plugin serve`                      | 🙋 you — the script only prints the command   | [Start `k8s-kms-plugin serve`](#start-k8s-kms-plugin-serve)               |
| `kind create cluster --config …`            | 🙋 you — **using the generated `kind.config.yaml`** | [Create the cluster](#create-the-cluster)                  |
| Verifying the wiring and the etcd ciphertext | 🙋 you                                       | [Verify the wiring](#verify-the-wiring), [Confirm that encryption really happens](#confirm-that-encryption-really-happens) |
| Deleting the cluster and the staging area   | 🙋 you                                        | [Cleanup](#cleanup)                                  |

[`scripts/k8s-kind/rebuild-kms-dev.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/k8s-kind/rebuild-kms-dev.sh) creates the staging directories and
generates both configuration files. Run it from the repository root:

```sh
./scripts/k8s-kind/rebuild-kms-dev.sh
```

`/tmp` does not survive a reboot — use `KMS_DEV_ROOT` for a persistent staging area:

```sh
KMS_DEV_ROOT="$HOME/.kms-dev" ./scripts/k8s-kind/rebuild-kms-dev.sh
```

It reports the three paths it wrote — the socket directory, and the two config files consumed later by
`kind create cluster`:

```
recreated:
  /tmp/kms-dev/run/
  /tmp/kms-dev/config/encryption-conf-kmsv2-unix-socket.yaml
  /tmp/kms-dev/config/kind.config.yaml
```

Everything after that in its output is a **printed hint**, not something it executed: the `serve` command, the
`kind create cluster` command adapted to the container runtime it detected, and the verification commands — all
pre-filled with your paths. The script is idempotent, so re-running it refreshes the two config files and clears a
stale socket left behind by a dead plugin.

Every default — cluster name, socket name, PKCS #11 library, KEK label, algorithm family — is overridable through
environment variables; run `./scripts/k8s-kind/rebuild-kms-dev.sh --help` or see
[`scripts/k8s-kind/README.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/k8s-kind/README.md) for the full list.

> An existing cluster keeps the mounts it was created with. After changing `KMS_DEV_ROOT`, delete and recreate it:
> `kind delete cluster --name kms-dev`.

**Continue at [section 5](#start-k8s-kms-plugin-serve)** to start the plugin. The next section explains what those
generated files contain and why — read it if you prefer doing it by hand, or when something needs adapting.

## The same, by hand

Skip this section if you ran the script. It covers exactly what `rebuild-kms-dev.sh` writes, using the default
`/tmp/kms-dev` staging root.

### Staging directories

Use a dedicated location rather than the plugin's usual socket path (e.g. `/run/user/1000`). Two separate
directories are mounted into the node: one holding the socket, one holding the configuration.

```sh
mkdir -p /tmp/kms-dev/run /tmp/kms-dev/config
```

> The socket directory must be mounted as a **directory**, never as a single file: when the plugin restarts, the
> socket inode is recreated, and a single-file bind mount would keep pointing at the stale, deleted inode.

### The `EncryptionConfiguration`

Start from [`encryption-conf-kmsv2-unix-socket.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml) and
change `endpoint:` to the in-container path:

```sh
cp deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml /tmp/kms-dev/config/
```

```yaml
# /tmp/kms-dev/config/encryption-conf-kmsv2-unix-socket.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: kms-server
          endpoint: unix:///kms-socket/k8s-kms-plugin-dev.sock   # in-container path, NOT the host path
          timeout: 3s
      - identity: {}
```

### The `KinD` cluster config

Save the following as `/tmp/kms-dev/config/kind.config.yaml`. It lands in the same directory that is mounted into the
node at `/etc/kubernetes/kms` — harmless, since `kube-apiserver` only reads the file named by
`encryption-provider-config` and ignores the rest.

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: kms-dev
nodes:
  - role: control-plane
    extraMounts:                                    # (1) host -> node container
      - hostPath: /tmp/kms-dev/run
        containerPath: /kms-socket
      - hostPath: /tmp/kms-dev/config
        containerPath: /etc/kubernetes/kms
        readOnly: true
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            encryption-provider-config: "/etc/kubernetes/kms/encryption-conf-kmsv2-unix-socket.yaml"
          extraVolumes:                             # (2) node container -> apiserver static pod
            - name: kms-socket
              hostPath: /kms-socket
              mountPath: /kms-socket
              pathType: DirectoryOrCreate
            - name: kms-config
              hostPath: /etc/kubernetes/kms
              mountPath: /etc/kubernetes/kms
              readOnly: true
              pathType: DirectoryOrCreate
```

> **On the missing `apiVersion:` in the kubeadm patch:** it is deliberately omitted. The kubeadm config format
> changed from `v1beta3` to `v1beta4` starting with Kubernetes v1.36, and `v1beta4` expects `extraArgs` as a list of
> `{name, value}` pairs instead of a map. Pinning the wrong `apiVersion` for your `kind` / node-image combination
> makes the patch **silently dropped** — no error, the flag simply never reaches `kube-apiserver`. Leaving
> `apiVersion` out of this map-style block lets `kind` auto-detect and convert it.

## Start `k8s-kms-plugin serve`

> 🙋 **Manual step.** The script prints this command pre-filled with your paths, but never runs it.

Point `--socket` at the staging `run` directory:

```sh
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket /tmp/kms-dev/run/k8s-kms-plugin-dev.sock \
    --p11-lib   "$PKCS11_MODULE" \
    --p11-label k8s-kms-plugin-dev \
    --p11-pin   1234 \
    --p11-key-label dev-rsa-2048-oaep \
    --algorithm-family rsa-oaep &
```

Start the plugin **before** creating the cluster. `kube-apiserver` does retry its KMS connection on a background
loop, but a missing plugin produces noisy startup errors and a temporarily unhealthy `/healthz`.

> **On the algorithm family:** everything in this guide is algorithm-agnostic — nothing below depends on which
> family the plugin serves, and all four families work against a **stock** `kube-apiserver`. `rsa-oaep` is used
> here simply as a bootstrap, so that an early failure can be attributed to the `KinD` wiring rather than to the
> KEK. Once the cluster is up and encrypting, restart the plugin with `--algorithm-family aes-gcm`, `aes-cbc` or
> `ml-kem` (see [`SoftHSMv3`](./hsm-guides/softhsm-v3.md#start-k8s-kms-plugin-serve)) to exercise the other families.

## Create the cluster

> 🙋 **Manual step.** `kind create cluster` is never run by the script — it only generates the
> `kind.config.yaml` passed to `--config` below. Creating the cluster is what actually applies the two mounts, so
> a cluster created *before* the config existed will not have them.

### Podman

`KinD`'s Podman support is still experimental and requires an opt-in environment variable:

```sh
export KIND_EXPERIMENTAL_PROVIDER=podman
kind create cluster --config /tmp/kms-dev/config/kind.config.yaml
```

Requirements for rootless Podman (see the [`KinD` rootless docs](https://kind.sigs.k8s.io/docs/user/rootless/)):

- Podman ≥ 3.0
- cgroup v2 — `podman info | grep cgroupVersion`
- cgroup delegation enabled for user services (automatic with `systemd` ≥ 252; on older `systemd` a
  `Delegate=yes` drop-in under `/etc/systemd/system/user@.service.d/` is required)

If `kind` complains that it *requires setting systemd property "Delegate=yes"*, wrap the command into its own
delegated scope:

```sh
systemd-run --user --scope --property=Delegate=yes \
  kind create cluster --config /tmp/kms-dev/config/kind.config.yaml
```

If cluster creation hangs or fails with `could not find a log line that matches "Reached target .*Multi-User
System.*"` while the node container itself looks healthy, this is a known rootless-Podman log-relay race. Switch the
Podman log driver, then delete and recreate the cluster:

```sh
mkdir -p ~/.config/containers
cat >> ~/.config/containers/containers.conf <<EOF
[containers]
log_driver = "k8s-file"
EOF
```

### Docker

```sh
kind create cluster --config /tmp/kms-dev/config/kind.config.yaml
```

## Verify the wiring

```sh
kind get clusters
kubectl config get-contexts
```

The context is named after the cluster: `kind-kms-dev` — **not** `kind-kind`. Using the wrong context is by far the
most common cause of `dial tcp 127.0.0.1:PORT: connect: connection refused` at this stage, as `kubectl` then dials a
port nothing is listening on.

```sh
kubectl --context kind-kms-dev get pods -A
```

All `kube-system` pods should be `Running`, including `kube-apiserver-kms-dev-control-plane`.

Confirm that the flag actually reached `kube-apiserver`:

```sh
kubectl --context kind-kms-dev -n kube-system get pod kube-apiserver-kms-dev-control-plane \
  -o jsonpath='{.spec.containers[0].command}' | tr ' ' '\n' | grep -i encrypt
```

If the output is empty, the `kubeadmConfigPatches` block was dropped — inspect the rendered kubeadm config and the
manifest kubeadm actually wrote:

```sh
kubectl --context kind-kms-dev -n kube-system get cm kubeadm-config -o jsonpath='{.data.ClusterConfiguration}'

podman exec -it kms-dev-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml
# Docker: docker exec -it kms-dev-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml
```

Confirm that mount (1) delivered the files into the node:

```sh
podman exec -it kms-dev-control-plane ls -la /etc/kubernetes/kms/ /kms-socket/
# Docker: docker exec -it kms-dev-control-plane ls -la /etc/kubernetes/kms/ /kms-socket/
```

The first directory must contain `encryption-conf-kmsv2-unix-socket.yaml`, the second the live socket file (mode
`srwx...`).

## Confirm that encryption really happens

Watch the `k8s-kms-plugin` logs while running the commands below. The apiserver health loop sends periodic
[`StatusRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#StatusRequest)s, and writing a secret triggers an
[`EncryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#EncryptRequest):

```
TRAC[0031] UnaryInterceptor kms v2 StatusRequest         line="providers/p11.go:969"
DEBU[0031] StatusResponse                                Healthz=ok KeyId=dev-rsa-2048-oaep Version=v2 line="providers/p11.go:1027"
TRAC[0031] UnaryInterceptor kms v2 EncryptRequest        line="providers/p11.go:973"
```

Create a secret:

```sh
kubectl --context kind-kms-dev create secret generic probe --from-literal=foo=bar
```

To read the raw `etcd` value, exec into the **etcd pod through `kubectl`**, not into the node container: `etcdctl`
only ships inside the etcd image. Recent `registry.k8s.io/etcd` images are distroless with no shell, so invoke the
binary directly instead of going through `sh -c`:

```sh
kubectl --context kind-kms-dev -n kube-system exec etcd-kms-dev-control-plane -- \
  etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt \
          --cert=/etc/kubernetes/pki/etcd/server.crt \
          --key=/etc/kubernetes/pki/etcd/server.key \
          get /registry/secrets/default/probe | strings
```

The value must start with the `k8s:enc:kms:v2:kms-server:` prefix, followed by binary ciphertext — the proof that
the secret is stored encrypted and not as plaintext `bar`:

```
/registry/secrets/default/probe
k8s:enc:kms:v2:kms-server:
```

## Cleanup

```sh
kind delete cluster --name kms-dev
rm -rf /tmp/kms-dev
```

Then stop the `k8s-kms-plugin serve` process.

## Troubleshooting summary

| Symptom | Cause | Fix |
|---|---|---|
| `dial tcp 127.0.0.1:PORT: connect: connection refused` | Wrong `kubectl` context (`kind-kind` instead of `kind-kms-dev`) | `kubectl config get-contexts`, then use `kind-<cluster name>` |
| No KMS traffic at all on the plugin | `encryption-provider-config` never reached `kube-apiserver` — usually a `kubeadmConfigPatches` `apiVersion` mismatch causing a silent drop | Check `.spec.containers[0].command` of the apiserver pod; use the unversioned, map-style `extraArgs` block |
| `/kms-socket/` or `/etc/kubernetes/kms/` empty inside the node | `extraMounts` `hostPath` does not match the real host directory | `podman exec … ls -la` to confirm, fix `kind.config.yaml`, recreate the cluster |
| apiserver dials a dead socket after a plugin restart | The socket was bind-mounted as a single file, so the mount points at the stale inode | Mount the **directory** that contains the socket |
| `etcdctl: not found` | Ran against the node container instead of the etcd pod | `kubectl exec` into `etcd-<node>`, not `podman/docker exec` into the node |
| `exec: "sh": executable file not found` | Recent etcd images ship no shell | Call `etcdctl` directly, without `sh -c` |
| `running kind with rootless provider requires setting systemd property "Delegate=yes"` | cgroup delegation not active for the user scope | `systemd-run --user --scope --property=Delegate=yes kind create cluster …` |
| `kind` hangs waiting for `Reached target … Multi-User System` | Rootless Podman's log relay races `kind`'s log watcher | Set `log_driver = "k8s-file"` in `~/.config/containers/containers.conf`, recreate the cluster |
