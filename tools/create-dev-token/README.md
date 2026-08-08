# create-dev-token

> ⚠️ **Development / testing helper — not part of the `k8s-kms-plugin` deployable.**
> It uses well-known PINs and fixed `CKA_ID`s. Never run it against a production HSM.

Provisions a persistent SoftHSM token with one key per algorithm family (AES-GCM, AES-CBC+HMAC,
RSA-OAEP, ML-KEM), ready to drive `k8s-kms-plugin serve` by hand.

📖 **Documentation: [`docs/tools-and-scripts/create-dev-token.md`](../../docs/tools-and-scripts/create-dev-token.md)**
— usage, flags, what it creates on the token, and how to point `serve` at it.

```sh
cd tools/create-dev-token && make       # or: go run . --help
```
