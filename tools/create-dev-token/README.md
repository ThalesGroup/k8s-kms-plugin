# create-dev-token

`create-dev-token` bootstraps a **persistent** SoftHSMv3 token with one key of every algorithm family supported by `k8s-kms-plugin`:

| Label | Algorithm | Key type |
|---|---|---|
| `dev-aes-gcm-kek` | `aes-gcm` | AES-256-GCM symmetric key |
| `dev-aes-cbc-kek` | `aes-cbc` | AES-256-CBC symmetric key |
| `dev-hmac-sha256` | `aes-cbc` | Generic-256 HMAC key (paired with CBC) |
| `dev-rsa-2048-oaep` | `rsa-oaep` | RSA-2048 key pair |
| `dev-ml-kem-768` | `ml-kem` | ML-KEM-768 key pair (skipped on SoftHSMv2) |

The store survives across runs and is intended for interactive testing with `p11tool`, `pkcs11-tool`, and `k8s-kms-plugin serve`.

## Prerequisites

| Tool | Purpose |
|---|---|
| Go ≥ 1.22 | `go run ./tools/create-dev-token` |
| SoftHSMv3 | `libsofthsmv3.so` — build from [pqctoday-org/pqctoday-hsm](https://github.com/pqctoday-org/pqctoday-hsm) |
| `pkcs11-tool` | Inspect the token (optional, from `opensc` package) |
| `p11tool` | Inspect the token (optional, from `gnutls-bin` package) |

SoftHSMv2 migth also works for aes-gcm / aes-cbc / rsa-oaep. ML-KEM-768 requires SoftHSMv3.

## Create the token

```bash
P11_LIBRARY=/path/to/libsofthsmv3.so \
  go run ./tools/create-dev-token \
    --dir /tmp/k8s-kms-plugin-devtoken
```

All flags are optional except `--lib` (or `P11_LIBRARY`):

| Flag | Default | Description |
|---|---|---|
| `--lib` | `$P11_LIBRARY` | Path to the SoftHSMv3 shared library |
| `--dir` | `/tmp/k8s-kms-plugin-devtoken` | Directory to create the token store in |
| `--pin` | `1234` | User PIN to set on the token |

The program creates `--dir`, writes a `softhsm2.conf` inside it, initialises the PKCS\#11 token, and generates all keys. It exits with an error if `--dir` already exists, so there is no risk of silently overwriting an existing store.

On success it prints `export SOFTHSM2_CONF=…` and ready-to-paste commands for every tool.

## Inspect the token

Set the config path in every terminal session that needs to access the token:

```bash
export SOFTHSM2_CONF=/tmp/k8s-kms-plugin-devtoken/softhsm2.conf
```

### p11tool

```bash
GNUTLS_SO_PIN="0000" GNUTLS_PIN="1234" p11tool \
  --provider /path/to/libsofthsmv3.so \
  --login \
  --list-all "pkcs11:token=k8s-kms-plugin-dev"
```

### pkcs11-tool

```bash
pkcs11-tool \
  --module /path/to/libsofthsmv3.so \
  --login --pin 1234 \
  --token-label k8s-kms-plugin-dev \
  --list-objects
```

## Run k8s-kms-plugin against the token

Start the plugin, then test it with `grpcurl-roundtrip-test.sh` from another terminal.

### AES-GCM

```bash
k8s-kms-plugin serve \
  --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
  --p11-lib   /path/to/libsofthsmv3.so \
  --p11-label k8s-kms-plugin-dev \
  --p11-pin   1234 \
  --p11-key-label dev-aes-gcm-kek \
  --algorithm-family aes-gcm
```

### AES-CBC + HMAC

```bash
k8s-kms-plugin serve \
  --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
  --p11-lib        /path/to/libsofthsmv3.so \
  --p11-label      k8s-kms-plugin-dev \
  --p11-pin        1234 \
  --p11-key-label  dev-aes-cbc-kek \
  --p11-hmac-label dev-hmac-sha256 \
  --algorithm-family aes-cbc
```

### RSA-OAEP

```bash
k8s-kms-plugin serve \
  --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
  --p11-lib   /path/to/libsofthsmv3.so \
  --p11-label k8s-kms-plugin-dev \
  --p11-pin   1234 \
  --p11-key-label dev-rsa-2048-oaep \
  --algorithm-family rsa-oaep
```

### ML-KEM-768

```bash
k8s-kms-plugin serve \
  --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
  --p11-lib   /path/to/libsofthsmv3.so \
  --p11-label k8s-kms-plugin-dev \
  --p11-pin   1234 \
  --p11-key-label dev-ml-kem-768 \
  --algorithm-family ml-kem
```

## Round-trip test with grpcurl

With the plugin running on the socket above:

```bash
cd scripts/grpcurl
./grpcurl-roundtrip-test.sh "hello dev token" \
  /run/user/$(id -u)/k8s-kms-plugin-dev.sock
```

## Delete the token

```bash
rm -rf /tmp/k8s-kms-plugin-devtoken
```
