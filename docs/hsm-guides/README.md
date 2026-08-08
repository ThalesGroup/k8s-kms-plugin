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

## HSM & TPM Supported Platforms

> [!NOTE]
> This section will improve with reference to specific `k8s-kms-plugin` version once
> the release & CICD are set up.

The following table sums up the HSMs or TPMs that has been _officially_ tested & confirmed to work
with the `k8s-kms-plugin`. This list is not exhaustive: you can contribute to it, as other HSM
devices or virtual HSM might work with the `k8s-kms-plugin`.

Each ✅ cell lists the **key sizes / parameter sets actually tested** on that device. Other sizes are not known to
fail — the plugin derives the key size at runtime from the HSM key — they have simply not been exercised yet.

| [`k8s-kms-plugin` version `XX`]()                                                                  | HSM or TPM   | Form factor  | AES GCM             | AES CBC HMAC        | RSA OAEP                     | ML-KEM                       | Comment                                                                    | Docs Details                            |
|----------------------------------------------------------------------------------------------------|--------------|--------------|---------------------|---------------------|------------------------------|------------------------------|----------------------------------------------------------------------------|-----------------------------------------|
| [`SoftHSMv3` (`pqctoday-hsm`)](https://github.com/pqctoday-org/pqctoday-hsm)                       | HSM PKCS #11 | Software     | ✅ 256-bit          | ✅ 256-bit          | ✅ 2048, 3072, 4096          | ✅ 512, 768, 1024            | Recommended for dev & integration testing; supports all algorithm families | [Link](./softhsm-v3.md)            |
| [`SoftHSMv2`](https://github.com/softhsm/SoftHSMv2)                                                | HSM PKCS #11 | Software     | ❔Not Tested        | ❔Not Tested        | ❔Not Tested                 | 🚫not supported              | Legacy reference; ML-KEM requires SoftHSMv3                                | [Link](./softhsm-v2.md)            |
| [`Software TPM Emulator`](https://github.com/stefanberger/swtpm)                                   | TPM PKCS #11 | Software     | ❔Not Tested        | ❔Not Tested        | ❔Not Tested                 | 🚫not supported              | Legacy reference; ML-KEM requires SoftHSMv3                                | [Link](./software-tpm-emulator.md) |
| [Thales eToken Fusion](https://cpl.thalesgroup.com/access-management/authenticators/etoken-fusion) | HSM PKCS #11 | Hardware USB | ❔Not Tested        | ❔Not Tested        | ✅ 2048                      | ❔Not Tested                 |                                                                            | [Link](./thales-etoken-fusion.md)  |
| [yubico YubiHSM 2](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/index.html)         | HSM PKCS #11 | Hardware USB | ❔Not Tested        | ❔Not Tested        | ✅ 4096                      | ❔Not Tested                 |                                                                            | [Link](./yubico-yubihsm2.md)       |

> **Units**: AES sizes are key lengths in bits; RSA sizes are modulus lengths in bits; ML-KEM values are FIPS 203
> parameter sets (ML-KEM-512 / 768 / 1024).

## Choosing keys on the token

Every guide selects a key with either `--p11-key-id` (PKCS #11 `CKA_ID`) or `--p11-key-label`
(`CKA_LABEL`) — they are mutually exclusive, and one is required. See
[`CKA_ID` vs `CKA_LABEL`](../cli-user-interface/cka-id-vs-cka-label.md) for how each is resolved
against the token.

Once a provider is working, point a cluster at it with one of the
[Kubernetes integration guides](../README.md#kubernetes-integration-guides).
