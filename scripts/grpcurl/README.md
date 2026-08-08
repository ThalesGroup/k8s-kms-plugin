# `grpcurl` round-trip scripts

Exercise the KMS v2 gRPC API (`Status`, `Encrypt`, `Decrypt`) against a running
`k8s-kms-plugin`, with no Kubernetes cluster involved.

| Script | Purpose |
|--------|---------|
| `grpcurl-roundtrip-test.sh` | Full Status → Encrypt → Decrypt round trip |
| `grpcurl-roundtrip-key-rotation.sh` | Checks the new KEK still decrypts data written under the old one |
| `collect-jwe-samples.sh` | Collects JWE / ML-KEM envelope samples across algorithm families |
| `lib-api-proto.sh` | Shared helper: resolves the KMS v2 `api.proto` at the `k8s.io/kms` version `go.mod` selects |

**Requires** `grpcurl`, `jq` and `base64` on `PATH`.

📖 **Documentation: [`docs/tools-and-scripts/grpcurl-scripts.md`](../../docs/tools-and-scripts/grpcurl-scripts.md)**
— every script's arguments, annotated example output, and the key-rotation workflow.
