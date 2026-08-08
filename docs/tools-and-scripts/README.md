---
title: "Helper tools & scripts"
weight: 65
---

Development and testing helpers that ship with the repository. None of them is part of the
deployable: they exist to get a token, a cluster or a gRPC call in front of you quickly.

| Helper | What it does | Lives in |
|--------|--------------|----------|
| [`create-dev-token`](./create-dev-token.md) | Provisions a persistent SoftHSM token with one key per algorithm family — AES-GCM, AES-CBC+HMAC, RSA-OAEP and ML-KEM — ready for `serve` | [`tools/create-dev-token/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/tools/create-dev-token/) |
| [`grpcurl` round-trip scripts](./grpcurl-scripts.md) | Drive the KMS v2 API (`Status`, `Encrypt`, `Decrypt`) against a running plugin with no cluster involved, including a key-rotation round trip and a JWE sample collector | [`scripts/grpcurl/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/grpcurl/) |
| [`KinD` staging script](./k8s-kind-scripts.md) | Stages the directories, `EncryptionConfiguration` and `kind.config.yaml` a `KinD` cluster needs, and prints the `serve` command to run | [`scripts/k8s-kind/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/k8s-kind/) |

> [!CAUTION]
> **Development only.** `create-dev-token` uses well-known PINs and fixed `CKA_ID`s, and the
> staging script writes throwaway configuration. Never point either at a production HSM or cluster.

## A typical loop

These compose, and each step is independent of the next:

1. **[`create-dev-token`](./create-dev-token.md)** — get a token with keys for every algorithm
   family, without touching hardware. (Or follow [SoftHSMv3](../hsm-guides/softhsm-v3.md) to build
   one by hand and understand what it contains.)
2. **[`grpcurl` scripts](./grpcurl-scripts.md)** — confirm the plugin encrypts and decrypts before a
   cluster is anywhere near it. Much faster to iterate on than a cluster, and the failure messages
   point at the plugin rather than at Kubernetes.
3. **[`KinD` staging script](./k8s-kind-scripts.md)** — stage a cluster's configuration, then follow
   the [`KinD` guide](../kubernetes-guides/kind-kubernetes.md) to create it.

## Where the source lives

Each page here documents scripts that stay in `tools/` and `scripts/`; only the documentation moved
into `docs/`, so it is indexed and published with everything else. The directories keep a short
`README.md` pointing back at these pages.

The e2e test suite drives the same RPCs as the `grpcurl` scripts, from Go — see
[Running the Tests](../development.md#running-the-tests).
