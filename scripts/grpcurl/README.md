## Test `k8s-kms-plugin serve` with `grpcurl`

The `grpcurl-roundtrip-test.sh` script allows you to mimic and test the
communication between the `k8s-kms-plugin` and the `kubernetes` KMS API server.

The script tests a [`StatusRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#StatusRequest), then an [`EncryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#EncryptRequest) and finally a [`DecryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#DecryptRequest).

This assume a `k8s-kms-plugin serve` is running without errors and listening
on this unix socket `/run/user/1000/k8s-kms-plugin.sock`.

```bash
./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```
```
Using existing api.proto. If you want to update it, please remove this file.
🔐 Input plaintext: Hello world
🔐 Base64 encoded: SGVsbG8gd29ybGQ=

1️⃣ ℹ️ Status Request & Response

🧾 key_id from Status: 64636138353931326363356537313264

2️⃣ ℹ️ Encrypt Request & Response

🗄️  Ciphertext JWE only (base64): ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li50eXhEb1RpdWd5cTdTTWY3RjBYVFpRLkt3Ny1POHNkWWdYbHo4ZFhuM3FvTWcuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==

⬇️ Full EncryptResponse JSON base64 encoded: use this as <base64 EncryptResponse old kek> in the grpcurl-roundtrip-key-rotation.sh script:
eyJjaXBoZXJ0ZXh0IjoiWlhsS2FHSkhZMmxQYVVwQ1RXcFZNbEV3U2tSSmFYZHBZVEpzYTBscWIybE9hbEV5VFhwWmVFMTZaM3BPVkUwMVRYcEZlazFxV1hwT2FrMTZUbFJaTVUxNlkzcE5WRTE1VG1wUmFVeERTakJsV0VGcFQybEtTMVl4VVdsTVEwcHFaRWhyYVU5cFNrdFdNVkZwVEVOS1ptUkhhR2hpUjFaNldESkdhRnBEU1RaSmEwWkNVVlZHUWxGVlJrSlJWVVo2U1dsM2FWcFhOV3BKYW05cFVWUkpNVTVyVGtOUmVVbzVMaTUwZVhoRWIxUnBkV2Q1Y1RkVFRXWTNSakJZVkZwUkxrdDNOeTFQT0hOa1dXZFliSG80WkZodU0zRnZUV2N1Um5sT1UxWnRNbGwxU0d0U09EQnNSR2xFTlVkRFJYUTJjRVphU2pWU2VGaE9jek53WW1KVWVYcFBOQT09Iiwia2V5SWQiOiI2NDYzNjEzODM1MzkzMTMyNjM2MzM1NjUzNzMxMzI2NCJ9Cg==

3️⃣ ℹ️ Decrypt Request & Response

🔓 Decrypted text: Hello world

4️⃣ ℹ️ Summary
✅ Round-trip encryption/decryption successful!
```

If the script is successful, it means that the `k8s-kms-plugin` and encrypt and
decrypt operations are working correctly.

You can also add the env var `VERBOSE=true` to see the JSON content of the KMS v2 Status, Encrypt and Decrypt responses.

```bash
VERBOSE=true ./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

```json
Using existing api.proto. If you want to update it, please remove this file.
🔐 Input plaintext: hello world
🔐 Base64 encoded: aGVsbG8gd29ybGQ=

1️⃣ ℹ️ Status Request & Response
📦 Full StatusResponse JSON:
{
  "version": "v2",
  "healthz": "ok",
  "keyId": "64636138353931326363356537313264"
}

🧾 key_id from Status: 64636138353931326363356537313264

2️⃣ ℹ️ Encrypt Request & Response
📦 Full EncryptResponse JSON:
{
  "ciphertext": "ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li5UZ05Yamt3ZTBnU0tVb0xaV3hvNExRLlozZmgyV3R5UG5GWlAtQnV0TEhEaUEuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==",
  "keyId": "64636138353931326363356537313264"
}

🗄️  Ciphertext JWE only (base64): ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li5UZ05Yamt3ZTBnU0tVb0xaV3hvNExRLlozZmgyV3R5UG5GWlAtQnV0TEhEaUEuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==

⬇️ Full EncryptResponse JSON base64 encoded: use this as <base64 EncryptResponse old kek> in the grpcurl-roundtrip-key-rotation.sh script:
eyJjaXBoZXJ0ZXh0IjoiWlhsS2FHSkhZMmxQYVVwQ1RXcFZNbEV3U2tSSmFYZHBZVEpzYTBscWIybE9hbEV5VFhwWmVFMTZaM3BPVkUwMVRYcEZlazFxV1hwT2FrMTZUbFJaTVUxNlkzcE5WRTE1VG1wUmFVeERTakJsV0VGcFQybEtTMVl4VVdsTVEwcHFaRWhyYVU5cFNrdFdNVkZwVEVOS1ptUkhhR2hpUjFaNldESkdhRnBEU1RaSmEwWkNVVlZHUWxGVlJrSlJWVVo2U1dsM2FWcFhOV3BKYW05cFVWUkpNVTVyVGtOUmVVbzVMaTVVWjA1WWFtdDNaVEJuVTB0VmIweGFWM2h2TkV4Ukxsb3pabWd5VjNSNVVHNUdXbEF0UW5WMFRFaEVhVUV1Um5sT1UxWnRNbGwxU0d0U09EQnNSR2xFTlVkRFJYUTJjRVphU2pWU2VGaE9jek53WW1KVWVYcFBOQT09Iiwia2V5SWQiOiI2NDYzNjEzODM1MzkzMTMyNjM2MzM1NjUzNzMxMzI2NCJ9Cg==

3️⃣ ℹ️ Decrypt Request & Response
📦 Full DecryptResponse JSON:
{
  "plaintext": "aGVsbG8gd29ybGQ="
}

🔓 Decrypted text: hello world

4️⃣ ℹ️ Summary
✅ Round-trip encryption/decryption successful!
```

## Test `k8s-kms-plugin serve rotation` with `grpcurl`

Principle is the same, expect the purpose here is also to verify if the decryption of content encrypted with the old KEK works.

### First run `k8s-kms-plugin serve` with `grpcurl-roundtrip-test.sh` and get the content of an `EncryptResponse`

In this situation, key ID `64636138353931326363356537313264` will be later rotated and replaced by a new key.

```bash
./k8s-kms-plugin \
  serve \
    --log-level=trace \
    --p11-lib  /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  \
    --p11-label mylabel  \
    --p11-pin  mypin  \
    --kek-id  64636138353931326363356537313264 \
    --hmac-id 30663536623936326235663530363234 \
    --algorithm aes-cbc \
    --socket /run/user/1000/k8s-kms-plugin.sock
```

Then run `./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock`.

Retrieve this field:
```
⬇️ Full EncryptResponse JSON base64 encoded: use this as <base64 EncryptResponse old kek> in the grpcurl-roundtrip-key-rotation.sh script:
eyJjaXBoZXJ0ZXh0IjoiWlhsS2FHSkhZMmxQYVVwQ1RXcFZNbEV3U2tSSmFYZHBZVEpzYTBscWIybE9hbEV5VFhwWmVFMTZaM3BPVkUwMVRYcEZlazFxV1hwT2FrMTZUbFJaTVUxNlkzcE5WRTE1VG1wUmFVeERTakJsV0VGcFQybEtTMVl4VVdsTVEwcHFaRWhyYVU5cFNrdFdNVkZwVEVOS1ptUkhhR2hpUjFaNldESkdhRnBEU1RaSmEwWkNVVlZHUWxGVlJrSlJWVVo2U1dsM2FWcFhOV3BKYW05cFVWUkpNVTVyVGtOUmVVbzVMaTVwVVZVemFsTk5hV2hLUTNkT1YyWXpPVk4xYUdwQkxtMUVjM0JyUVdSNVQweEpTa2hLWmtsR1FqVTBWV2N1Um5sT1UxWnRNbGwxU0d0U09EQnNSR2xFTlVkRFJYUTJjRVphU2pWU2VGaE9jek53WW1KVWVYcFBOQT09Iiwia2V5SWQiOiI2NDYzNjEzODM1MzkzMTMyNjM2MzM1NjUzNzMxMzI2NCJ9Cg==
```

You will use it in the `grpcurl-roundtrip-key-rotation.sh` script.

### Now run `k8s-kms-plugin serve rotation`

Key with ID `64636138353931326363356537313264` is rotated by a new key with label `rsa0` and ID `123abc`.

```
k8s-kms-plugin \
  serve \
  --log-level=trace \
  --socket /run/user/1000/k8s-kms-plugin.sock \
  --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
  --p11-label mylabel \
  --p11-pin mypin \
  --p11-key-label rsa0 \
  --algorithm rsa-oaep \
  --config grpc-network.yaml \
  rotation \
    --old-p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --old-p11-label mylabel \
    --old-p11-pin mypin \
    --old-kek-id 64636138353931326363356537313264 \
    --old-hmac-id 30663536623936326235663530363234 \
    --old-algorithm aes-cbc
```

Then run

```bash
VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh 'hello world active KEK' 'Hello world' 'eyJjaXBoZXJ0ZXh0IjoiWlhsS2FHSkhZMmxQYVVwQ1RXcFZNbEV3U2tSSmFYZHBZVEpzYTBscWIybE9hbEV5VFhwWmVFMTZaM3BPVkUwMVRYcEZlazFxV1hwT2FrMTZUbFJaTVUxNlkzcE5WRTE1VG1wUmFVeERTakJsV0VGcFQybEtTMVl4VVdsTVEwcHFaRWhyYVU5cFNrdFdNVkZwVEVOS1ptUkhhR2hpUjFaNldESkdhRnBEU1RaSmEwWkNVVlZHUWxGVlJrSlJWVVo2U1dsM2FWcFhOV3BKYW05cFVWUkpNVTVyVGtOUmVVbzVMaTVwVVZVemFsTk5hV2hLUTNkT1YyWXpPVk4xYUdwQkxtMUVjM0JyUVdSNVQweEpTa2hLWmtsR1FqVTBWV2N1Um5sT1UxWnRNbGwxU0d0U09EQnNSR2xFTlVkRFJYUTJjRVphU2pWU2VGaE9jek53WW1KVWVYcFBOQT09Iiwia2V5SWQiOiI2NDYzNjEzODM1MzkzMTMyNjM2MzM1NjUzNzMxMzI2NCJ9Cg==' /run/user/1000/k8s-kms-plugin.sock
```

You should get

```json
Using existing api.proto. If you want to update it, please remove this file.

==========================================================
▶️ Testing ACTIVE KEK Status, Encrypt and Decrypt requests
🔐 Input plaintext ACTIVE KEK: hello world active KEK
🔐 Base64 encoded: aGVsbG8gd29ybGQgYWN0aXZlIEtFSw==

1️⃣ ℹ️ Status Request & Response ACTIVE KEK

📦 Full Status response:
{
  "version": "v2",
  "healthz": "ok",
  "keyId": "123abc"
}
🧾 key_id from Status: 123abc

2️⃣ ℹ️ Encrypt Request & Response
📦 Full Encrypt response:
{
  "ciphertext": "ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW10cFpDSTZJalE1T1dZMFltWmhZbVppT1dFME5qazNNbVl4TUdNeFl6RmxNamcwTmpjNFpEbG1ZbUk1WWpZeVpHWmhObUk1TURVNFpEUmpPV0kwWm1RME1qSmxNV1FpTENKMGVYQWlPaUpLVjFRaUxDSmpkSGtpT2lKS1YxUWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC5MVkE0NmlJYW9OaXpjOWRXTjJoNXBoVjEyOF9Kc2tpRFhpMWROTjFKaWx4cGoyQjdjVmdLanZhMW1XdXQ5S1kxc3VMYmZLS2I5TVBPSWFwdVNJTk1YMEF5c2VwZzAyM2VGS19aSDByT2lQbm1kVENKd2RyUHlwTkZkcXpWc0FUSUJYTHRxamRycVdQN21KN0NvdXBHR19ScEN1NjB5N1dqVmVKa2RmbmI1eUxRbWZBTnp2XzlnQXJZOEFpYUo4NDI4SnEzQk1CeFE2blBOTW9FMUdLNUNoODlNSWVGbEJWQWdEQjg0T19OcGs3NlpadHYzclFDUUY0cFZLQmV2Y1FDRmVFVldEbFpZbVpIZ2tpMlNOY3hSZF9MUWtRd0xPTEVycTJXeXdybDU5aUVkYnNuM0pOU2I5aTdTY2dLVEFETUR3WXhwOWMwR05HeEY1THp0VEdmbWcuVzdOTVRzOFFZMjJ2WENxci5zNjdmRGUtT0RBNmxlblBfQThnWEFEeEJRcm90VEEuVlRfZkJpbTRYV1FLLU85di13TEl2Zw==",
  "keyId": "123abc"
}
🗄️  Ciphertext (base64): ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW10cFpDSTZJalE1T1dZMFltWmhZbVppT1dFME5qazNNbVl4TUdNeFl6RmxNamcwTmpjNFpEbG1ZbUk1WWpZeVpHWmhObUk1TURVNFpEUmpPV0kwWm1RME1qSmxNV1FpTENKMGVYQWlPaUpLVjFRaUxDSmpkSGtpT2lKS1YxUWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC5MVkE0NmlJYW9OaXpjOWRXTjJoNXBoVjEyOF9Kc2tpRFhpMWROTjFKaWx4cGoyQjdjVmdLanZhMW1XdXQ5S1kxc3VMYmZLS2I5TVBPSWFwdVNJTk1YMEF5c2VwZzAyM2VGS19aSDByT2lQbm1kVENKd2RyUHlwTkZkcXpWc0FUSUJYTHRxamRycVdQN21KN0NvdXBHR19ScEN1NjB5N1dqVmVKa2RmbmI1eUxRbWZBTnp2XzlnQXJZOEFpYUo4NDI4SnEzQk1CeFE2blBOTW9FMUdLNUNoODlNSWVGbEJWQWdEQjg0T19OcGs3NlpadHYzclFDUUY0cFZLQmV2Y1FDRmVFVldEbFpZbVpIZ2tpMlNOY3hSZF9MUWtRd0xPTEVycTJXeXdybDU5aUVkYnNuM0pOU2I5aTdTY2dLVEFETUR3WXhwOWMwR05HeEY1THp0VEdmbWcuVzdOTVRzOFFZMjJ2WENxci5zNjdmRGUtT0RBNmxlblBfQThnWEFEeEJRcm90VEEuVlRfZkJpbTRYV1FLLU85di13TEl2Zw==

3️⃣ ℹ️ Decrypt Request & Response
📦 Full Decrypt response:
{
  "plaintext": "aGVsbG8gd29ybGQgYWN0aXZlIEtFSw=="
}
🔓 Decrypted text: hello world active KEK

4️⃣ ℹ️ Summary for ACTIVE KEK
✅ Round-trip encryption/decryption successful!

==========================================================
▶️ Testing OLD ROTATED KEK DecryptRequest
OLD EncryptResponse JSON
{
  "ciphertext": "ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li5pUVUzalNNaWhKQ3dOV2YzOVN1aGpBLm1Ec3BrQWR5T0xJSkhKZklGQjU0VWcuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==",
  "keyId": "64636138353931326363356537313264"
}
ℹ️ Decrypt Request & Response
📦 Full DecryptResponse JSON:
{
  "plaintext": "SGVsbG8gd29ybGQ="
}

ℹ️ Summary for OLD KEK
✅ Rotation decryption successful!
```