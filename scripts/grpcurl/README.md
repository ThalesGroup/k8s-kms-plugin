# Unix Socket

The [`grpcurl-unix-roundtrip-test.sh`](./grpcurl-unix-roundtrip-test.sh) script allows you to mimic and test the
communication between the `k8s-kms-plugin` and the `kubernetes` KMS v2 API server.

The script tests a [`StatusRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#StatusRequest), then an [`EncryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#EncryptRequest) and finally a [`DecryptRequest`](https://pkg.go.dev/k8s.io/kms/apis/v2#DecryptRequest).

This assume a `k8s-kms-plugin serve` is running without errors and listening
on this unix socket `/run/user/1000/k8s-kms-plugin.sock`.

```bash
./grpcurl-roundtrip-test.sh "Hello world" /run/user/1000/k8s-kms-plugin.sock
```
```
🔐 Input plaintext: Hello world
🔐 Base64 encoded: SGVsbG8gd29ybGQ=
🧾 key_id from Status: abcd
🗄️  Ciphertext (base64): ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW10cFpDSTZJamd3TkRFME1qQTFaR05qT1dKbU9XUTRaV1prWkdRMk5XUmpPVE15TWpnM1lURm1aamRsTUdZd1pUTmlNRGxqTldWaE1UWmpPVEU1TW1FMU1HVXdOellpTENKMGVYQWlPaUpLVjFRaUxDSmpkSGtpT2lKS1YxUWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC5wUktUOHJVTWF3bER4eTItR3h2TTVUVHR4aDA3TTg2dWpNZUdPR3VWeXR5LVp2bGdjMmRIRVVnOXFEUnQwWFE4NkZwTE8yR3FTOTFqMVlNYk1NcTc2bkJYVUFjRnlBS3Bhb240eVhSS2U2eTF6NFY5YmZQaTNYNzhQaDlTMlhuTnJBaTdCSDVsRXlMNDJqbjBpSlFGVU05U3EzMkl3TmtYLWNlSnlwckdmQTVhcTJ3Y3VBd1Uxc1MzU2hPc1FwY2xaVE9DYnZnem5tYWw2bHdnTlNOa21ad2xWaGxhaU56YVF5SzFndWpZeU05eExmZEVza2Zaa01GMVB5U1F6VnNRT0tWckplM2Y4a3NWeGE5MmZRb0FDRGtzczF1aVVYR0NRRXVZR0puQV8wUm1TMEhzSEVmNGhDdG1jRmdTcEduajlVWjZaMkxscGVabUEyYlIzWXpsUU90T0hqWmZWVkROOHRNMUV1OEpBdXlobE05X1VNeWRZNlJBVkk1LUdRUmJ6QVpKQUkyX0h4Vlk2YU0zODVLVjJaaVp0VlZnSFQ5bkhIOHFvMVRyWlYweElDTjJ2VzJIRlJfX2M0LVpzR21JSHJXMWZycHhYeDlSVkRhSTEwRWJwMlRXR3R5Rkx6M21OTExNdlBmcXVuVWZjTVdhMFFNSVFYcHdZclJQZ3RFUmpPdktFMkwta3o0ZUxzWjhyd1J6Q2F4TlV2YnY2Yy12Q3JETnlFb0lKSWlyX1NaeGR4em91UTRfcFFFd2pVVHBwZ0hLQnBETTRFeTNTdzNXT2VkMnZlVU1rNXIzQk5zajNfRUhRVEM3cTB3Qjdpd0tTMW1CaGItMDRWODhBQ1gtWFZfRXp1cW1lQnRrSGlIWXlVUGVILU16R2o2X3JGcVF5STJFVXEzZGJycy5UUnF5ZlNyQVN2eXhhRGNsLllRZWplMGFTYTk0TnRxUS5ZSzc5MUY3b0JaLUt4SGZmMFhMNXpB
🔓 Decrypted text: Hello world
✅ Round-trip encryption/decryption successful!
```

If the script is successful, it means that the `k8s-kms-plugin` and encrypt and
decrypt operations are working correctly.

You can also add the env var `VERBOSE=true` to see the JSON content of the KMS v2 Status, Encrypt and Decrypt responses.

```bash
VERBOSE=true ./grpcurl-roundtrip-test.sh 'hello world' /run/user/1000/k8s-kms-plugin.sock
```

```json
🔐 Input plaintext: hello world
🔐 Base64 encoded: aGVsbG8gd29ybGQ=
📦 Full Status response:
{
  "version": "v2",
  "healthz": "ok",
  "keyId": "abcd"
}
🧾 key_id from Status: abcd
📦 Full Encrypt response:
{
  "ciphertext": "ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW10cFpDSTZJamd3TkRFME1qQTFaR05qT1dKbU9XUTRaV1prWkdRMk5XUmpPVE15TWpnM1lURm1aamRsTUdZd1pUTmlNRGxqTldWaE1UWmpPVEU1TW1FMU1HVXdOellpTENKMGVYQWlPaUpLVjFRaUxDSmpkSGtpT2lKS1YxUWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC5iTHgydWdCckhhWnBXSFhkTzI1SHV5LWZHdGgxY19GcGQzV19sTkMwR25GM0FrSm1Ja0JmVG53Si1LME1Hc1N1R0I1UjRoMlpRaTllVS11V09yS0dwREVSX3dfbkh6NDRmWHdKb2pmR1JFUksxM2FXZm1GWU93V2dNZGdQcFhEQVVsYzFsRVZYYUdoc002N0xSTDNTc0o5b3I3dG96Q1NLVUdyY2NFYXdrcmEwSUxXVmEzNlF6RFRTM1BpX0liQk4wMVRiQkhFdmYycE1SMmhZU0RPYVBHX01va1oxWUZNdWxfaFgxTk9wT0p0TFRlRE1tQnlScjI1c0ZSc1htX24zdTBua0RNbi1JWG1rMTlEaXhaNlhvRDJTUW5vVS1vYUxtcHBXZGYxX3dSQjB2MWZjMnpiemZGYmt1UFFFY1dSUTlOWGFvZ2gweDBiQmswZS0xam5SVndMWk9PeFc5RFoybUVESDhudnE5elRZc0RhTGtJMHhkYWFiME4yNFJJXzVqM2pGY0FhdVFkMUVaSUFpQXF5UWFfeWNQWEF6UzB6VkJpMkhPRzk2ZFlDai1ETWtfa3ZHbng5Z2ZXSHJvU0pkSm1rbXpBMEVVZkk3R3BJSjZ2bDNWU0h2dER5QkowRUo1cWlqb1ZMZkN2Z3h5dEtDdWgtTW1FbVBLZzdzQTNNMDYzUktPUllrUjY3YWZPWUFFMWl1eFFIczgwc3dLMTJUMVVkY3Vsc2R4a0NJbURmMFdoekpoc1lZbkJneWV3Z0t6R3ZDTFZsQWFOVVdBbmNYUUpJbVZDbThDb05GdS1VSEhnN1YxMVR4SkhfNExNbVFOeUg3dG5GTHdEbExMMGQxdUtRYlMwWF9WSXZpTms5aXExLWQ0RmNKLThNdDZuakFFdG81RFN0V0VEYy5Hd0psTkc0dGdFT2R4U2djLi1fMkhkODBkdFlWc2hONC5jbWhFWnlreTd6amRsM1JaMEpfUGd3",
  "keyId": "abcd"
}
🗄️  Ciphertext (base64): ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW10cFpDSTZJamd3TkRFME1qQTFaR05qT1dKbU9XUTRaV1prWkdRMk5XUmpPVE15TWpnM1lURm1aamRsTUdZd1pUTmlNRGxqTldWaE1UWmpPVEU1TW1FMU1HVXdOellpTENKMGVYQWlPaUpLVjFRaUxDSmpkSGtpT2lKS1YxUWlMQ0psYm1NaU9pSkJNalUyUjBOTkluMC5iTHgydWdCckhhWnBXSFhkTzI1SHV5LWZHdGgxY19GcGQzV19sTkMwR25GM0FrSm1Ja0JmVG53Si1LME1Hc1N1R0I1UjRoMlpRaTllVS11V09yS0dwREVSX3dfbkh6NDRmWHdKb2pmR1JFUksxM2FXZm1GWU93V2dNZGdQcFhEQVVsYzFsRVZYYUdoc002N0xSTDNTc0o5b3I3dG96Q1NLVUdyY2NFYXdrcmEwSUxXVmEzNlF6RFRTM1BpX0liQk4wMVRiQkhFdmYycE1SMmhZU0RPYVBHX01va1oxWUZNdWxfaFgxTk9wT0p0TFRlRE1tQnlScjI1c0ZSc1htX24zdTBua0RNbi1JWG1rMTlEaXhaNlhvRDJTUW5vVS1vYUxtcHBXZGYxX3dSQjB2MWZjMnpiemZGYmt1UFFFY1dSUTlOWGFvZ2gweDBiQmswZS0xam5SVndMWk9PeFc5RFoybUVESDhudnE5elRZc0RhTGtJMHhkYWFiME4yNFJJXzVqM2pGY0FhdVFkMUVaSUFpQXF5UWFfeWNQWEF6UzB6VkJpMkhPRzk2ZFlDai1ETWtfa3ZHbng5Z2ZXSHJvU0pkSm1rbXpBMEVVZkk3R3BJSjZ2bDNWU0h2dER5QkowRUo1cWlqb1ZMZkN2Z3h5dEtDdWgtTW1FbVBLZzdzQTNNMDYzUktPUllrUjY3YWZPWUFFMWl1eFFIczgwc3dLMTJUMVVkY3Vsc2R4a0NJbURmMFdoekpoc1lZbkJneWV3Z0t6R3ZDTFZsQWFOVVdBbmNYUUpJbVZDbThDb05GdS1VSEhnN1YxMVR4SkhfNExNbVFOeUg3dG5GTHdEbExMMGQxdUtRYlMwWF9WSXZpTms5aXExLWQ0RmNKLThNdDZuakFFdG81RFN0V0VEYy5Hd0psTkc0dGdFT2R4U2djLi1fMkhkODBkdFlWc2hONC5jbWhFWnlreTd6amRsM1JaMEpfUGd3
📦 Full Decrypt response:
{
  "plaintext": "aGVsbG8gd29ybGQ="
}
🔓 Decrypted text: hello world
✅ Round-trip encryption/decryption successful!
```

# [experimental feature] TCP gRPC API

As of Kubernetes `v1.33.1` and KMS `v0.33.3`, the KMSv2 API implementation from Kubernetes **only supports unix socket gRPC** as network connection endpoint:
* official documentation https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#configuring-the-kms-provider-kms-v2
* method `ParseEndpoint` from `k8s.io/kms/pkg/util` in version `v0.33.3` only supports `unix`: see
  * https://pkg.go.dev/k8s.io/kms@v0.33.3/pkg/util#ParseEndpoint
  * [kms v0.33.3 /pkg/util/util.go#L26](https://github.com/kubernetes/kms/blob/b8a79480db40eda7916f633621690b1ca9993373/pkg/util/util.go#L26)

The KMSv2 API does not support TCP and TLS.

However, the `k8s-kms-plugin` gRPC API can be expose as plaintext TCP or TLS. This is an experimental feature since k8s does not support for now. But maybe in the future, the GRPC API KMS will support TCP and TLS. When this hapens, the `k8s-kms-plugin`  will be ready.

## Test with dummy certificates

If you do not have certificates available for testing this experimental feature, use this script [`generate-self-signed-cert.sh`](../tls/generate-self-signed-cert.sh) to generate a dummy self-signed root CA, client and server certificates and corresponding private keys.

[`generate-self-signed-cert.sh`](../tls/generate-self-signed-cert.sh) will generate the following files:

```
./generate-self-signed-cert.sh 

🔧 Generating root CA...
🔧 Generating server TLS certificate...
Certificate request self-signature ok
subject=CN = kms-server.local
🔧 Generating client TLS certificate for mTLS...
Certificate request self-signature ok
subject=CN = kms-client
✅ All certificates generated in ./certs:
ca.crt
ca.key
ca.srl
client.cnf
client.crt
client.csr
client.key
server.cnf
tls.crt
tls.csr
tls.key
```

## Run `k8s-kms-plugin serve` with TCP gRPC API & TLS (no mutual TLS)

We use the dummy certificates generated at the previous step.

```bash
k8s-kms-plugin \
  serve  \
    --log-level=trace  \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mylabel  \
    --p11-pin mypin  \
    --kek-id  64636138353931326363356537313264 \
    --hmac-id 30663536623936326235663530363234 \
    --algorithm aes-cbc \
    --grpc-network tcp4 \
    --host 127.0.0.1 \
    --port 8842 \
    --enable-tls \
    --tls-key ~/certs/tls.key \
    --tls-certificate ~/certs/tls.crt \
    --tls-ca ~/certs/ca.crt
```

### StatusRequest

TCP + insecure TLS

```bash
grpcurl \
  -insecure \
  -proto api.proto \
  -d '{}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Status
```

Answer:

```json
{
  "version": "v2",
  "healthz": "ok",
  "keyId": "64636138353931326363356537313264"
}
```

If you have the root CA certificate, you can use it with `grpcurl` to verify the server:

```bash
grpcurl \
  -cacert ~/certs/ca.crt \
  -proto api.proto \
  -d '{}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Status
```

### EncryptRequest

TCP + insecure TLS

```bash
grpcurl \
  -insecure \
  -proto api.proto \
  -d '{"plaintext": "aGVsbG8gd29ybGQ=", "uid": "mock-123"}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Encrypt
```

answer:

```json
{
  "ciphertext": "ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li5vWFE1bjJkb1B3QnpEVkJkY1pRTDlnLjF5RWpxZTFxM0JwZnFjR2RTNlFVVGcuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==",
  "keyId": "64636138353931326363356537313264"
}
```

Instead of using `grpcurl -insecure`, you can also use `grpcurl` with the root CA certificate to verify the server with `-cacert ~/certs/ca.crt`, similar to the `StatusRequest` example.

### DecryptRequest

TCP + insecure TLS

```bash
grpcurl \
  -insecure \
  -proto api.proto \
  -d '{"ciphertext": "ZXlKaGJHY2lPaUpCTWpVMlEwSkRJaXdpYTJsa0lqb2lOalEyTXpZeE16Z3pOVE01TXpFek1qWXpOak16TlRZMU16Y3pNVE15TmpRaUxDSjBlWEFpT2lKS1YxUWlMQ0pqZEhraU9pSktWMVFpTENKZmRHaGhiR1Z6WDJGaFpDSTZJa0ZCUVVGQlFVRkJRVUZ6SWl3aVpXNWpJam9pUVRJMU5rTkNReUo5Li5vWFE1bjJkb1B3QnpEVkJkY1pRTDlnLjF5RWpxZTFxM0JwZnFjR2RTNlFVVGcuRnlOU1ZtMll1SGtSODBsRGlENUdDRXQ2cEZaSjVSeFhOczNwYmJUeXpPNA==", "uid": "test-dec-1", "key_id":"64636138353931326363356537313264"}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Decrypt
```

answer:

```json
{
  "plaintext": "aGVsbG8gd29ybGQ="
}
```

Instead of using `grpcurl -insecure`, you can also use `grpcurl` with the root CA certificate to verify the server with `-cacert ~/certs/ca.crt`, similar to the `StatusRequest` example.

## Run `k8s-kms-plugin serve` with TCP gRPC API & mutual TLS Enabled

```bash
k8s-kms-plugin \
  serve  \
    --log-level=trace  \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mylabel  \
    --p11-pin mypin  \
    --kek-id  64636138353931326363356537313264 \
    --hmac-id 30663536623936326235663530363234 \
    --algorithm aes-cbc \
    --grpc-network tcp4 \
    --host 127.0.0.1 \
    --port 8842 \
    --enable-tls \
    --tls-key ~/certs/tls.key \
    --tls-certificate ~/certs/tls.crt \
    --tls-ca ~/certs/ca.crt \
    --require-client-cert true \
    --tls-client-ca ~/certs/ca.crt
```

### StatusRequest

TCP + mutual TLS

```bash
grpcurl \
  -cacert ~/certs/ca.crt \
  -cert ~/certs/client.crt \
  -key ~/certs/client.key \
  -proto api.proto \
  -d '{}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Status
```

The EncryptRequest and DecryptRequest examples are the same as the previous sections. Only you need to add to `grpcurl` the client certieficate and key.

## Run `k8s-kms-plugin serve` with TCP gRPC API but no TLS

The principle is the same as the previous section, but without the `--enable-tls` flag. So the gRPC API is plaintext TCP.

```bash
k8s-kms-plugin \
  serve  \
    --log-level=trace  \
    --p11-lib /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --p11-label mylabel  \
    --p11-pin mypin  \
    --kek-id  64636138353931326363356537313264 \
    --hmac-id 30663536623936326235663530363234 \
    --algorithm aes-cbc \
    --grpc-network tcp4 \
    --host 127.0.0.1 \
    --port 8842
```

### StatusRequest

TCP plaintext (no TLS): principally the same as the previous section, only you use grpcurl with `-plaintext` option.

```bash
grpcurl \
  -plaintext \
  -proto api.proto \
  -d '{}' \
  127.0.0.1:8842 \
  v2.KeyManagementService.Status
```