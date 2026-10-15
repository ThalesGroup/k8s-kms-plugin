---
title: "Quick start"
weight: 15
---

See `k8s-kms-plugin` encrypt a Kubernetes cluster's Secrets end to end, in two steps, with no
hardware: a software HSM, then a throwaway cluster that is deleted again in one command.

> [!TIP]
> The quick start is for **trying** the plugin, not for understanding it. To learn what it does
> first — where it sits in the KMS v2 envelope scheme, why the KEK never leaves the device, how it is
> deployed — get started with [Concepts & Architecture](./overview.md) instead.

## Two steps, in order

| Step | Guide | What you get |
|------|-------|--------------|
| 1 | [SoftHSMv3 (`pqctoday-hsm`)](./hsm-guides/softhsm-v3.md) | A software PKCS #11 provider with a key per algorithm family, and `k8s-kms-plugin serve` running against it — including ML-KEM |
| 2 | [`KinD`](./kubernetes-guides/kind-kubernetes.md) | A single-node Kubernetes cluster encrypting its Secrets through that plugin, deleted again in one command |

SoftHSMv3 is the software HSM to use here because it is the only one covering all four algorithm
families. `KinD` runs the whole cluster in Podman or Docker, so nothing is installed on the host.
Each guide lists its own prerequisites. Step 2 reuses the token step 1 created, and restarts the
plugin on a socket the cluster can reach.

## After the quick start

| Page | Why |
|------|-----|
| [Concepts & Architecture](./overview.md) | What you just ran: the envelope scheme, deployment topologies, key rotation |
| [HSM & TPM guides](./hsm-guides/README.md) | Moving from the software HSM to a TPM or a hardware HSM |
| [`k3s`](./kubernetes-guides/k3s-kubernetes.md) | A host-installed cluster, with key rotation and high availability worked through |
| [Installation](./installation.md) | Packages, container images, and verifying a download before you trust it |
