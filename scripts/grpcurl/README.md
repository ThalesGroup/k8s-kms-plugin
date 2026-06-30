## Test `k8s-kms-plugin serve` with `grpcurl`

The scripts in this directory let you manually exercise the KMS v2 gRPC API
(`Status`, `Encrypt`, `Decrypt`) against a running `k8s-kms-plugin` instance,
without needing a Kubernetes cluster.

**Prerequisites**: `grpcurl`, `jq`, `base64` must be in your `PATH`.

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
  "alg": "ML-KEM-768",
  "kid": "05",
  "enc": "A256GCM",
  "cty": "JWK",
  "ek": "..."
}
```

---

## 3️⃣ Decrypt

🔓 Decrypted text: `Hello world`

---

## 4️⃣ Summary

✅ Round-trip encryption/decryption successful!
```

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

🗄️ Ciphertext JWE (base64):
```
ZXlKaGJHY2lPaUpOVEMx...
```

🔑 JWE Header:
```json
{
  "alg": "ML-KEM-768",
  "kid": "05",
  "enc": "A256GCM",
  "cty": "JWK",
  "ek": "..."
}
```

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
  --kek-id 64636138353931326363356537313264 \
  --hmac-id 30663536623936326235663530363234 \
  --algorithm aes-cbc
```

```bash
VERBOSE=true ./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```

Copy the ready-to-run command from the `> ⬇️ Run key rotation test` block
in the output.

**Step 2** — Stop the plugin, then restart with `serve rotation` using the
**new (ACTIVE)** KEK and the **old** KEK for decryption fallback:

```bash
k8s-kms-plugin serve \
  --log-level=trace \
  --socket /run/user/1000/k8s-kms-plugin.sock \
  --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --p11-label mylabel \
  --p11-pin mypin \
  --p11-key-label rsa0 \
  --algorithm rsa-oaep \
  rotation \
    --old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --old-p11-label mylabel \
    --old-p11-pin mypin \
    --old-kek-id 64636138353931326363356537313264 \
    --old-hmac-id 30663536623936326235663530363234 \
    --old-algorithm aes-cbc
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
