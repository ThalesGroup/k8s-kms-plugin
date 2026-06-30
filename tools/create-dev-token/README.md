# create-dev-token

> [!WARNING]
> ⚠️ **Development / testing helper — not part of the `k8s-kms-plugin` deployable.** ⚠️
> It provisions a throwaway token with **well-known PINs** and **fixed key IDs**.
> Do **not** run it against a production HSM, and do **not** use the keys it
> creates to protect real data. It ships as a pre-built convenience binary on the
> GitHub releases page (named `create-dev-token_testing-only_…`), separate from the
> plugin packages and container image.

`create-dev-token` bootstraps a **persistent** SoftHSMv3 token with one key of every algorithm family supported by `k8s-kms-plugin`:

| Label               | Algorithm  | Key type                                   |
|---------------------|------------|--------------------------------------------|
| `dev-aes-gcm-kek`   | `aes-gcm`  | AES-256-GCM symmetric key                  |
| `dev-aes-cbc-kek`   | `aes-cbc`  | AES-256-CBC symmetric key                  |
| `dev-hmac-sha256`   | `aes-cbc`  | Generic-256 HMAC key (paired with CBC)     |
| `dev-rsa-2048-oaep` | `rsa-oaep` | RSA-2048 key pair                          |
| `dev-ml-kem-768`    | `ml-kem`   | ML-KEM-768 key pair (skipped on SoftHSMv2) |

The store survives across runs and is intended for interactive testing with `p11tool`, `pkcs11-tool`, and `k8s-kms-plugin serve`.

## Prerequisites

| Tool          | Purpose                                                                                                  |
|---------------|----------------------------------------------------------------------------------------------------------|
| SoftHSMv3     | `libsofthsmv3.so` — build from [pqctoday-org/pqctoday-hsm](https://github.com/pqctoday-org/pqctoday-hsm) |
| `pkcs11-tool` | Inspect the token (optional, from `opensc` package)                                                      |
| `p11tool`     | Inspect the token (optional, from `gnutls-bin` package)                                                  |
| Go ≥ 1.22     | Only needed if building from source or using `go run`                                                    |

SoftHSMv2 might also work for aes-gcm / aes-cbc / rsa-oaep. ML-KEM-768 requires SoftHSMv3.

## Get the binary

**From GitHub releases** (recommended — no Go toolchain required):

Download `create-dev-token_testing-only_linux_<arch>_<version>` from the
[releases page](https://github.com/ThalesGroup/k8s-kms-plugin/releases) and rename it:

```bash
mv create-dev-token_testing-only_linux_amd64_v1.2.3 create-dev-token
chmod +x create-dev-token
./create-dev-token --version
```

**Build from source** (version-stamped from `git describe`):

```bash
# From the repo root
make -C tools/create-dev-token build
# Binary is placed at tools/create-dev-token/create-dev-token
```

**No build** (Go ≥ 1.22 required):

```bash
go run ./tools/create-dev-token --help
```

## Create the token

Use `eval` (or `source <(...)`) to create the token **and** export `SOFTHSM2_CONF` into the current shell in one step:

```bash
# Pre-built binary
eval "$(create-dev-token --lib /path/to/libsofthsmv3.so)"

# Or with go run (from the repo root, no build step)
eval "$(go run ./tools/create-dev-token --lib /path/to/libsofthsmv3.so)"
```

All progress output and the ready-to-paste command list go to **stderr** (visible in the terminal).
Only `export SOFTHSM2_CONF=…` goes to **stdout** so that `eval`/`source` captures it cleanly.

All flags are optional except `--lib` (or `PKCS11_MODULE`):

| Flag              | Default                        | Description                                      |
|-------------------|--------------------------------|--------------------------------------------------|
| `--lib`           | `$PKCS11_MODULE`               | Path to the SoftHSMv3 shared library             |
| `--dir`           | `/tmp/k8s-kms-plugin-devtoken` | Directory to create the token store in           |
| `--pin`           | `1234`                         | User PIN to set on the token                     |
| `--no-env-export` | `false`                        | Do not print `export SOFTHSM2_CONF=…` to stdout  |
| `--version`       |                                | Print version and exit                           |

The program creates `--dir`, writes a `softhsm2.conf` inside it, initialises the PKCS\#11 token, and generates all keys. It exits with an error if `--dir` already exists, so there is no risk of silently overwriting an existing store.

## Inspect the token

`SOFTHSM2_CONF` is already set in the session where `eval` ran. For any new terminal session:

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
./grpcurl-roundtrip-test.sh "this is a secret" \
  /run/user/$(id -u)/k8s-kms-plugin-dev.sock
```

## Key rotation test

The dev token contains all keys needed to exercise a full rotation scenario
without any extra setup. The example below rotates from **AES-CBC** (old KEK)
to **RSA-OAEP** (new active KEK).

**Step 1** — start the plugin with the **old** KEK and capture an `EncryptResponse`:

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

In another terminal, run the roundtrip test in **verbose** mode — the output
includes a ready-to-paste `serve rotation` test command:

```bash
cd scripts/grpcurl
VERBOSE=true ./grpcurl-roundtrip-test.sh "hello rotation" \
  /run/user/$(id -u)/k8s-kms-plugin-dev.sock
```

Copy the command block printed under `⬇️ Run key rotation test with the old KEK data from this run`.

**Step 2** — stop the plugin from Step 1, then start `serve rotation` with the
**new (ACTIVE)** RSA-OAEP KEK and the old AES-CBC KEK as decryption fallback:

```bash
k8s-kms-plugin serve \
  --socket /run/user/$(id -u)/k8s-kms-plugin-dev.sock \
  --p11-lib        /path/to/libsofthsmv3.so \
  --p11-label      k8s-kms-plugin-dev \
  --p11-pin        1234 \
  --p11-key-label  dev-rsa-2048-oaep \
  --algorithm-family rsa-oaep \
  rotation \
    --old-p11-lib        /path/to/libsofthsmv3.so \
    --old-p11-label      k8s-kms-plugin-dev \
    --old-p11-pin        1234 \
    --old-p11-key-label  dev-aes-cbc-kek \
    --old-p11-hmac-label dev-hmac-sha256 \
    --old-algorithm-family aes-cbc
```

**Step 3** — paste and run the command copied in Step 1. A successful run prints:

```
✅ Round-trip encryption/decryption successful!   ← new ACTIVE KEK encrypted & decrypted
✅ Rotation decryption successful!                ← old KEK ciphertext decrypted by rotation server
```

## Delete the token

```bash
rm -rf /tmp/k8s-kms-plugin-devtoken
```
