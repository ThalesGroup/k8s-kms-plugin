---
title: "grpcurl round-trip scripts"
weight: 20
---

The scripts in this directory let you manually exercise the KMS v2 gRPC API
(`Status`, `Encrypt`, `Decrypt`) against a running `k8s-kms-plugin` instance,
without needing a Kubernetes cluster.

**Prerequisites**: `grpcurl`, `jq`, `base64` must be in your `PATH`.

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

> [`grpcurl`](https://github.com/fullstorydev/grpcurl) is also required by the **end-to-end test suite**
> ([`test/e2e/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/test/e2e/)), which drives the same RPCs from Go — see
> [Running the Tests](../development.md#running-the-tests).

**`api.proto`**: these scripts resolve the KMS v2 service definition themselves, at the `k8s.io/kms`
version `go.mod` selects — from the Go module cache when it is populated, otherwise downloaded to a
temp file. Nothing is written into this directory. See [`lib-api-proto.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/grpcurl/lib-api-proto.sh).

Set `KMS_PROTO_VERSION` to pin a different release (for example `KMS_PROTO_VERSION=v0.34.1`) when
testing against a version the repository does not build against yet.

---

### `grpcurl-roundtrip-test.sh`

Performs a full **Status → Encrypt → Decrypt** round-trip and verifies the
decrypted output matches the original plaintext.

```bash
./grpcurl-roundtrip-test.sh <plaintext> <unix-socket-path>
VERBOSE=true ./grpcurl-roundtrip-test.sh <plaintext> <unix-socket-path>
```

Set `VERBOSE=true` to print full JSON requests and responses for each RPC call.

#### Default output

```bash
./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```

```markdown
# 🔐 KMS v2 Round-Trip Test

🔇 Verbose: disabled — set `VERBOSE=true` to see full JSON requests and responses

🔐 Input plaintext: `Hello world`
🔐 Base64 encoded: `SGVsbG8gd29ybGQ=`

---

## 1️⃣ Status

🧾 key_id: `05`

---

## 2️⃣ Encrypt

🔑 JWE Header:
```json
{
  "alg": "dir",
  "kid": "05",
  "enc": "A256GCM"
}
```

---

## 3️⃣ Decrypt

🔓 Decrypted text: `Hello world`

---

## 4️⃣ Summary

✅ Round-trip encryption/decryption successful!
```

`grpcurl-roundtrip-test.sh` prints a JWE header for the classical algorithm
families (`aes-gcm`, `aes-cbc`, `rsa-oaep`) as shown above. For `ml-kem`, the
plugin's `EncryptResponse` carries no JWE at all — the script detects this
from the `algorithm-family` annotation the plugin attaches to every
`EncryptResponse`, and prints the binary envelope's size breakdown instead:

```markdown
## 2️⃣ Encrypt

🧬 ML-KEM envelope (no JWE):
```
ciphertext:                  60 B  (nonce || AES-256-GCM-sealed DEK seed)
kem-ciphertext annotation: 1088 B  (raw ML-KEM encapsulation ciphertext)
```
```

ML-KEM is a Key Encapsulation Mechanism, not a public-key encryption scheme: it
always produces two artifacts (the KEM ciphertext and the AEAD-wrapped seed)
where JWE has only one slot, and the KEM ciphertext alone exceeds the KMS v2
1 kB `ciphertext` limit for ML-KEM-768/1024. So the plugin splits them across
the two fields KMS v2 already provides: the AEAD-wrapped seed stays in
`ciphertext`, and the KEM ciphertext travels in
`annotations["kem-ciphertext.k8s-kms-plugin.keysealer.eclipse.org"]`, which the
apiserver round-trips verbatim to the matching `Decrypt` call.

#### Verbose output

```bash
VERBOSE=true ./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```

```markdown
# 🔐 KMS v2 Round-Trip Test

🔍 Verbose: enabled

🔐 Input plaintext: `Hello world`
🔐 Base64 encoded: `SGVsbG8gd29ybGQ=`

---

## 1️⃣ Status

📤 StatusRequest:
```json
{}
```

📥 StatusResponse:
```json
{
  "version": "v2",
  "healthz": "ok",
  "keyId": "05"
}
```

🧾 key_id: `05`

---

## 2️⃣ Encrypt

📤 EncryptRequest:
```json
{
  "plaintext": "SGVsbG8gd29ybGQ=",
  "uid": "test-enc-1"
}
```

📥 EncryptResponse:
```json
{
  "ciphertext": "ZXlKaGJHY2l...",
  "keyId": "05"
}
```

🗄️ Ciphertext (base64):
```
ZXlKaGJHY2lPaUpOVEMx...
```

🔑 JWE Header:
```json
{
  "alg": "dir",
  "kid": "05",
  "enc": "A256GCM"
}
```

(For `ml-kem`, this section instead prints a `🧬 ML-KEM envelope (no JWE):`
block — see the note under "Default output" above.)

> ⬇️ Run key rotation test with the old KEK data from this run:
```bash
VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh \
  '<plaintext for ACTIVE KEK>' \
  'Hello world' \
  'eyJjaXBoZXJ0ZXh0Ij...' \
  '/run/user/1000/k8s-kms-plugin.sock'
```

---

## 3️⃣ Decrypt

📤 DecryptRequest:
```json
{
  "ciphertext": "ZXlKaGJHY2l...",
  "uid": "test-dec-1",
  "key_id": "05"
}
```

📥 DecryptResponse:
```json
{
  "plaintext": "SGVsbG8gd29ybGQ="
}
```

🔓 Decrypted text: `Hello world`

---

## 4️⃣ Summary

✅ Round-trip encryption/decryption successful!
```

---

### `grpcurl-roundtrip-key-rotation.sh`

Verifies that after a key rotation, the plugin using the **new (ACTIVE) KEK**
can still decrypt data that was encrypted with the **old KEK**.

```bash
VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh \
  '<plaintext for ACTIVE KEK>' \
  '<plaintext for OLD KEK>' \
  '<base64 EncryptResponse old kek>' \
  '<unix-socket-path>'
```

The `<base64 EncryptResponse old kek>` value is printed by
`grpcurl-roundtrip-test.sh` when run with `VERBOSE=true` (see the
`> ⬇️ Run key rotation test` block in the verbose output above).

#### Workflow

**Step 1** — Start `k8s-kms-plugin serve` with the **old** KEK and run the
roundtrip test in verbose mode to capture the `EncryptResponse`:

```bash
k8s-kms-plugin serve \
  --log-level=trace \
  --socket /run/user/1000/k8s-kms-plugin.sock \
  --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --p11-label mylabel \
  --p11-pin mypin \
  --p11-key-id 64636138353931326363356537313264 \
  --p11-hmac-id 30663536623936326235663530363234 \
  --algorithm-family aes-cbc
```

```bash
VERBOSE=true ./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```

Copy the ready-to-run command from the `> ⬇️ Run key rotation test` block
in the output.

**Step 2** — Stop the plugin, then restart with `serve rotation` using the
**new (ACTIVE)** KEK and the **old** KEK for decryption fallback. The highlighted lines are the
`rotation` subcommand and its `--old-*` flags added on top of the Step 1 command:

```bash {linenos=table,hl_lines=["9-15"]}
k8s-kms-plugin serve \
  --log-level=trace \
  --socket /run/user/1000/k8s-kms-plugin.sock \
  --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --p11-label mylabel \
  --p11-pin mypin \
  --p11-key-label rsa0 \
  --algorithm-family rsa-oaep \
  rotation \
    --old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --old-p11-label mylabel \
    --old-p11-pin mypin \
    --old-p11-key-id 64636138353931326363356537313264 \
    --old-p11-hmac-id 30663536623936326235663530363234 \
    --old-algorithm-family aes-cbc
```

**Step 3** — Paste and run the command copied from step 1:

```bash
VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh \
  'hello world active KEK' \
  'Hello world' \
  'eyJjaXBoZXJ0ZXh0Ij...' \
  '/run/user/1000/k8s-kms-plugin.sock'
```

A successful run prints `✅ Round-trip encryption/decryption successful!` for
the ACTIVE KEK section, and `✅ Rotation decryption successful!` for the OLD
KEK section, confirming that the rotation server can decrypt data encrypted
under the previous key.

### Collect envelope size samples

The script [`collect-jwe-samples.sh`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/scripts/grpcurl/collect-jwe-samples.sh) drives every
supported algorithm family through a Status → Encrypt → Decrypt round-trip and
reports the size of `EncryptResponse.ciphertext`, which KMS v2 caps at < 1 kB.
For `aes-gcm` / `aes-cbc` / `rsa-oaep` this is a JWE Compact Serialization; for
`ml-kem` it is a plain binary envelope (`nonce || AES-256-GCM-sealed seed`,
~60 B) with the raw ML-KEM encapsulation ciphertext carried separately in a
`kem-ciphertext` annotation — the split that keeps ML-KEM under the 1 kB limit in the
first place. See [ML-KEM](../hsm-guides/softhsm-v3.md#ml-kem) for how
to provision an ML-KEM key to exercise that case.

Unlike the round-trip scripts above, this one starts and stops the plugin
itself — one plugin per case, since the plugin serves exactly one KEK and one
algorithm family per socket. It only needs a `create-dev-token` SoftHSM store:

```bash
export SOFTHSM2_CONF=/tmp/k8s-kms-plugin-devtoken/softhsm2.conf
./collect-jwe-samples.sh --lib /path/to/libsofthsmv3.so
```

Results land in `jwe-samples/` — a git-ignored directory — plus a
`jwe-samples.zip` bundling the whole tree, ready to drop onto a GitHub issue:

```
jwe-samples/summary.md                    table of sizes
jwe-samples/summary.csv                   same data, machine-readable
jwe-samples/summary.json                  same, plus the per-segment breakdown
jwe-samples/messages.md                   every EncryptResponse / DecryptRequest
jwe-samples/<case>/*.json                 full per-case messages
jwe-samples/<case>/jwe.compact.txt        aes-gcm / aes-cbc / rsa-oaep
jwe-samples/<case>/envelope.bin           ml-kem
jwe-samples/<case>/plugin.log             that case's plugin output
```

Useful flags — `--help` lists them all:

| Flag | Effect |
|---|---|
| `--only REGEX` | run just the matching cases, e.g. `--only 'ml-kem'` |
| `--keep-going` | carry on after a failing case instead of stopping |
| `--log-level trace` | capture the plugin's own `ciphertextLen`, cross-checked against the measured size in the *Plugin log* column |
| `--format FMT` | `zip` (default), `tgz`, or `tar.zst` |
| `--no-archive` | skip the archive, and its `zip`/`bsdtar` dependency |

`tar.zst` compresses best, but GitHub only accepts `.zip`, `.gz` and `.tgz` as
issue attachments — which is why `zip` is the default.

