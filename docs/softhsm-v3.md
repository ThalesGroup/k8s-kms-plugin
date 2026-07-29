# [`SoftHSMv3` (`pqctoday-hsm`)](https://github.com/pqctoday-org/pqctoday-hsm)

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

- [1. Install `SoftHSMv3`](#1-install-softhsmv3)
- [2. Bootstrap a development token with `create-dev-token`](#2-bootstrap-a-development-token-with-create-dev-token)
  - [2.1. Get `create-dev-token`](#21-get-create-dev-token)
  - [2.2. Run `create-dev-token`](#22-run-create-dev-token)
  - [2.3. Inspect the token](#23-inspect-the-token)
- [3. Start `k8s-kms-plugin serve`](#3-start-k8s-kms-plugin-serve)
  - [3.1. AES-GCM](#31-aes-gcm)
  - [3.2. AES-CBC + HMAC](#32-aes-cbc--hmac)
  - [3.3. RSA-OAEP](#33-rsa-oaep)
  - [3.4. ML-KEM](#34-ml-kem)
- [4. Validate with grpcurl](#4-validate-with-grpcurl)
- [5. Configure a Kubernetes cluster](#5-configure-a-kubernetes-cluster)


## 1. Install `SoftHSMv3`

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


## 2. Bootstrap a development token with `create-dev-token`

[`create-dev-token`](../tools/create-dev-token/) is a helper tool that bootstraps a **persistent** SoftHSMv3 token
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

### 2.1. Get `create-dev-token`

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

### 2.2. Run `create-dev-token`

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

### 2.3. Inspect the token

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


## 3. Start `k8s-kms-plugin serve`

> The token created by `create-dev-token` uses label `k8s-kms-plugin-dev` and PIN `1234`.
> Adjust `--p11-lib`, `--p11-label`, `--p11-pin` to match your environment.

### 3.1. AES-GCM

```sh
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

### 3.2. AES-CBC + HMAC

```sh
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

### 3.3. RSA-OAEP

```sh
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

### 3.4. ML-KEM

```sh
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


## 4. Validate with grpcurl

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


## 5. Configure a Kubernetes cluster

Review [`encryption-conf-kmsv2-unix-socket.yaml`](../deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml) and make sure
`resources.providers.kms.endpoint` matches the socket path used by the running `k8s-kms-plugin`.

Then install a Kubernetes cluster like `k3s`:

```sh
curl -sfL https://get.k3s.io | K3S_DEBUG=true INSTALL_K3S_VERSION=v1.33.1+k3s1 sh -s - \
  --write-kubeconfig-mode 660 \
  --kube-apiserver-arg=encryption-provider-config=$HOME/k8s-kms-plugin/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml
```

See also [`k3s-kubernetes.md`](./k3s-kubernetes.md) for a more complete Kubernetes setup guide.
