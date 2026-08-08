---
title: "SoftHSMv3 (pqctoday-hsm)"
weight: 10
---

This guide describes how to set up [`SoftHSMv3`](https://github.com/pqctoday-org/pqctoday-hsm) (`pqctoday-hsm`) and make it
work with the `k8s-kms-plugin` in a **non production environment**.

`SoftHSMv3` is a software HSM that implements [PKCS #11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/pkcs11-base-v3.2.html),
including post-quantum mechanisms (`CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`). It is the **recommended** software HSM for
development and integration testing of `k8s-kms-plugin` as it supports all four algorithm families:

| Algorithm family    | `--algorithm-family` | Support        |
|---------------------|----------------------|----------------|
| AES-GCM             | `aes-gcm`            | ✅ Supported   |
| AES-CBC + HMAC      | `aes-cbc`            | ✅ Supported   |
| RSA-OAEP            | `rsa-oaep`           | ✅ Supported   |
| ML-KEM (FIPS 203)   | `ml-kem`             | ✅ Supported   |

- [Install `SoftHSMv3`](#install-softhsmv3)
- [Bootstrap a development token with `create-dev-token`](#bootstrap-a-development-token-with-create-dev-token)
  - [Get `create-dev-token`](#get-create-dev-token)
  - [Run `create-dev-token`](#run-create-dev-token)
  - [Inspect the token](#inspect-the-token)
- [Start `k8s-kms-plugin serve`](#start-k8s-kms-plugin-serve)
  - [AES-GCM](#aes-gcm)
  - [AES-CBC + HMAC](#aes-cbc--hmac)
  - [RSA-OAEP](#rsa-oaep)
  - [ML-KEM](#ml-kem)
- [Validate with grpcurl](#validate-with-grpcurl)
- [Configure a Kubernetes cluster](#configure-a-kubernetes-cluster)


## Install `SoftHSMv3`

Build and install from source following the instructions at https://github.com/pqctoday-org/pqctoday-hsm.

After installation, locate the shared library. Common paths:

```sh
# Debian / Ubuntu
export PKCS11_MODULE="/usr/local/lib/softhsm/libsofthsm3.so"

# or if installed to the default prefix
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm3.so"
```

Verify the library loads correctly:

```sh
pkcs11-tool --module "$PKCS11_MODULE" --show-info
```


## Bootstrap a development token with `create-dev-token`

[`create-dev-token`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/tools/create-dev-token/) is a helper tool that bootstraps a **persistent** SoftHSMv3 token
with one ready-to-use key per algorithm family. It eliminates the need for manual `pkcs11-tool` commands.

Keys provisioned:

| CKA_LABEL             | Algorithm family | Key type                  |
|-----------------------|------------------|---------------------------|
| `dev-aes-gcm-kek`     | `aes-gcm`        | AES-256-GCM symmetric key |
| `dev-aes-cbc-kek`     | `aes-cbc`        | AES-256-CBC symmetric key |
| `dev-hmac-sha256`     | `aes-cbc`        | Generic-256 HMAC key (paired with CBC) |
| `dev-rsa-2048-oaep`   | `rsa-oaep`       | RSA-2048 key pair                          |
| `dev-rsa-3072-oaep`   | `rsa-oaep`       | RSA-3072 key pair                          |
| `dev-rsa-4096-oaep`   | `rsa-oaep`       | RSA-4096 key pair                          |
| `dev-ml-kem-512`      | `ml-kem`         | ML-KEM-512 key pair (skipped on SoftHSMv2) |
| `dev-ml-kem-768`      | `ml-kem`         | ML-KEM-768 key pair (skipped on SoftHSMv2) |
| `dev-ml-kem-1024`     | `ml-kem`         | ML-KEM-1024 key pair (skipped on SoftHSMv2)|

### Get `create-dev-token`

**From GitHub releases** (recommended — no Go toolchain required):

Download `create-dev-token_testing-only_linux_<arch>_<version>` from the
[releases page](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases) and rename it:

```sh
mv create-dev-token_testing-only_linux_amd64_v1.2.3 create-dev-token
chmod +x create-dev-token
./create-dev-token --version
```

**Build from source** (version-stamped from `git describe`):

```sh
cd tools/create-dev-token
make build
```

**No build** (Go ≥ 1.22 required):

```sh
go run ./tools/create-dev-token --help
```

### Run `create-dev-token`

Use `eval` (or `source <(...)`) to create the token **and** export `SOFTHSM2_CONF` into the current shell in one step:

```sh
# Pre-built binary
eval "$(create-dev-token --lib "$PKCS11_MODULE")"

# Or with go run (from the repo root):
eval "$(go run ./tools/create-dev-token --lib "$PKCS11_MODULE")"
```

All progress output and the ready-to-paste `k8s-kms-plugin serve` commands go to **stderr** (visible in the terminal). Only `export SOFTHSM2_CONF=…` goes to **stdout** so that `eval`/`source` captures it cleanly. Pass `--no-env-export` to suppress the stdout export line.

`SOFTHSM2_CONF` is now set in the current session. For new terminal sessions:

```sh
export SOFTHSM2_CONF=/tmp/k8s-kms-plugin-devtoken/softhsm2.conf
```

To start fresh, delete the directory and re-run:

```sh
rm -rf /tmp/k8s-kms-plugin-devtoken
```

### Inspect the token

With `pkcs11-tool` (from the `opensc` package):

```sh
pkcs11-tool \
  --module "$PKCS11_MODULE" \
  --login --pin 1234 \
  --token-label k8s-kms-plugin-dev \
  --list-objects
```

With `p11tool` (from the `gnutls-bin` package):

```sh
GNUTLS_SO_PIN="0000" GNUTLS_PIN="1234" p11tool \
  --provider "$PKCS11_MODULE" \
  --login \
  --list-all "pkcs11:token=k8s-kms-plugin-dev"
```


## Start `k8s-kms-plugin serve`

> The token created by `create-dev-token` uses label `k8s-kms-plugin-dev` and PIN `1234`.
> Adjust `--p11-lib`, `--p11-label`, `--p11-pin` to match your environment.

Every example below identifies its key with `--p11-key-label`; `--p11-key-id` (PKCS #11 `CKA_ID`)
works the same way. See [`CKA_ID` vs `CKA_LABEL`](../cli-user-interface/cka-id-vs-cka-label.md) for
how the two are resolved.

The four commands differ only in the key they select and the family they announce — those are the
highlighted lines.

### AES-GCM

```sh {hl_lines=[9,10]}
SOCKET="/run/user/$(id -u)/k8s-kms-plugin.sock"
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket "$SOCKET" \
    --p11-lib   "$PKCS11_MODULE" \
    --p11-label k8s-kms-plugin-dev \
    --p11-pin   1234 \
    --p11-key-label dev-aes-gcm-kek \
    --algorithm-family aes-gcm
```

### AES-CBC + HMAC

```sh {hl_lines=[9,10,11]}
SOCKET="/run/user/$(id -u)/k8s-kms-plugin.sock"
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket "$SOCKET" \
    --p11-lib        "$PKCS11_MODULE" \
    --p11-label      k8s-kms-plugin-dev \
    --p11-pin        1234 \
    --p11-key-label  dev-aes-cbc-kek \
    --p11-hmac-label dev-hmac-sha256 \
    --algorithm-family aes-cbc
```

### RSA-OAEP

```sh {hl_lines=[9,10]}
SOCKET="/run/user/$(id -u)/k8s-kms-plugin.sock"
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket "$SOCKET" \
    --p11-lib   "$PKCS11_MODULE" \
    --p11-label k8s-kms-plugin-dev \
    --p11-pin   1234 \
    --p11-key-label dev-rsa-2048-oaep \
    --algorithm-family rsa-oaep
```

Swap `--p11-key-label` to `dev-rsa-3072-oaep` or `dev-rsa-4096-oaep` to use the RSA-3072 / RSA-4096 key pairs instead.

### ML-KEM

```sh {hl_lines=[9,10]}
SOCKET="/run/user/$(id -u)/k8s-kms-plugin.sock"
k8s-kms-plugin \
  serve \
    --log-level=trace \
    --socket "$SOCKET" \
    --p11-lib   "$PKCS11_MODULE" \
    --p11-label k8s-kms-plugin-dev \
    --p11-pin   1234 \
    --p11-key-label dev-ml-kem-768 \
    --algorithm-family ml-kem
```

The specific ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024) is derived at runtime from the key's
`ParameterSet` attribute — you only specify the family via `--algorithm-family ml-kem`.


## Validate with grpcurl

With the plugin running, test encrypt → decrypt from a second terminal:

```sh
./scripts/grpcurl/grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

Expected output:

```
🔐 Input plaintext: hello world
🧾 key_id from Status: dev-ml-kem-768
🔓 Decrypted text: hello world
✅ Round-trip encryption/decryption successful!
```


## Configure a Kubernetes cluster

Review [`encryption-conf-kmsv2-unix-socket.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml) and make sure
`resources.providers.kms.endpoint` matches the socket path used by the running `k8s-kms-plugin`.

Then point a cluster at it. Either
[Kubernetes integration guide](../kubernetes-guides/README.md) works from here — pick whichever suits
what you are doing:

| Guide | Why you might pick it |
|-------|-----------------------|
| [`KinD`](../kubernetes-guides/kind-kubernetes.md) | Nothing installed on the host; the cluster is created and deleted in one command each. Usually the quickest way to see the plugin working end to end |
| [`k3s`](../kubernetes-guides/k3s-kubernetes.md) | A host-installed cluster. Also the guide that covers key rotation and high availability |

Each guide has the full walkthrough — the socket path the apiserver needs, and how to confirm your
Secrets really are encrypted in `etcd`. As a one-liner, `k3s` takes the config directly on the
install command — the highlighted line is the one that wires `kube-apiserver` to the plugin:

```sh {hl_lines=[3]}
curl -sfL https://get.k3s.io | K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=$HOME/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

`KinD` needs the socket mounted into the node container instead, which is what its guide walks
through.
