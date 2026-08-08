---
title: "HSM & TPM guides"
weight: 50
---

How to set up a PKCS #11 provider and point `k8s-kms-plugin serve` at it. One page per device,
covering installation, creating the keys for each algorithm family, and the matching `serve`
invocation.

`k8s-kms-plugin` talks to every one of these through the same PKCS #11 interface, so the plugin
configuration differs only in `--p11-lib`, the token label and which key you point it at.

## Software providers

Use these to try the plugin, and in CI — no hardware required.

| Guide | Notes |
|-------|-------|
| [SoftHSMv3 (`pqctoday-hsm`)](./softhsm-v3.md) | **Recommended** for development and integration testing — the only provider here that supports every algorithm family, including ML-KEM |
| [SoftHSMv2](./softhsm-v2.md) | Legacy reference. AES and RSA only; no ML-KEM |
| [Software TPM Emulator](./software-tpm-emulator.md) | Legacy reference, emulates a TPM 2.0 via `swtpm`. No ML-KEM |

## Hardware providers

| Guide | Form factor | Notes |
|-------|-------------|-------|
| [Thales eToken Fusion](./thales-etoken-fusion.md) | USB token | RSA-OAEP tested at 2048 bits |
| [Yubico YubiHSM 2](./yubico-yubihsm2.md) | USB HSM | RSA-OAEP tested at 4096 bits; usable over USB or the network connector |

## Which algorithm families work where

The table of what has actually been *tested* on each device — key sizes and ML-KEM parameter sets
included — is in the usage guide:
[HSM & TPM Supported Platforms](../usage.md#hsm--tpm-supported-platforms).

A ❔ there does not mean broken: the plugin derives the key size and parameter set from the key on
the token at runtime, so untested sizes are simply untested. Contributions covering another device,
or another size on a device already listed, are welcome.

## Choosing keys on the token

Every guide selects a key with either `--p11-key-id` (PKCS #11 `CKA_ID`) or `--p11-key-label`
(`CKA_LABEL`) — they are mutually exclusive, and one is required. See
[`CKA_ID` vs `CKA_LABEL`](../cli-user-interface/cka-id-vs-cka-label.md) for how each is resolved
against the token.

Once a provider is working, point a cluster at it with one of the
[Kubernetes integration guides](../README.md#kubernetes-integration-guides).
