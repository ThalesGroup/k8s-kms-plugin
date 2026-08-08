# `k8s-kms-plugin` 🔐

[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/eclipse-keysealer/k8s-kms-plugin.svg)](https://pkg.go.dev/github.com/eclipse-keysealer/k8s-kms-plugin)
[![Build](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/ci.yml)
[![Lint](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/lint.yml/badge.svg)](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/lint.yml)
[![Secret Scan](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/secret-scan.yml)
[![Release](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/release.yml/badge.svg)](https://github.com/eclipse-keysealer/k8s-kms-plugin/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eclipse-keysealer/k8s-kms-plugin/badge)](https://scorecard.dev/viewer/?uri=github.com/eclipse-keysealer/k8s-kms-plugin)
[![GitHub release](https://img.shields.io/github/v/release/eclipse-keysealer/k8s-kms-plugin)](https://github.com/eclipse-keysealer/k8s-kms-plugin/releases/latest)
[![Changelog](https://img.shields.io/badge/changelog-v1.0.0-blue)](./CHANGELOG.md)

`k8s-kms-plugin serve` implements the [Kubernetes KMS v2 API](https://pkg.go.dev/k8s.io/kms/apis/v2) protocol as a gRPC service that leverages a remote or local HSM via PKCS11.
`k8s-kms-plugin serve rotation` supports key rotation operations.

Supported `--algorithm-family` values (key size / parameter set is derived at runtime from the HSM key):

- `aes-gcm` — AES-GCM symmetric encryption (128 / 192 / 256-bit)
- `aes-cbc` — AES-CBC symmetric encryption with HMAC-SHA256 authentication
- `rsa-oaep` — RSA-OAEP asymmetric encryption
- `ml-kem` — post-quantum ML-KEM hybrid encryption (CRYSTALS-Kyber / FIPS 203; ML-KEM-512, ML-KEM-768, ML-KEM-1024)

For what each family actually does to the data — keys used, primitives composed, wire format, and which
operations run inside the HSM — see [Cryptographic Schemes](./docs/cryptographic-schemes.md).

This plugin will also run in proxy mode which can connect to a remote plugin service running in a secure network device (Key Managers)

> ⚠️ **Droping support of KMS v1**: Newer (after 2025) version of the `k8s-kms-plugin` droped support for [Kubernetes KMSv1](https://pkg.go.dev/k8s.io/kms@v0.34.1/apis/v1beta1),
> as KMSv1 is deprecated in Kubernetes v1.28 and disabled by default since Kubernetes v1.29.

> 🚧 **Note**: This documentation is under construction and needs to be updated to remove/archive references to KMS v1 and
> document KMS v2 operations.

# Part of Eclipse KeySealer

`k8s-kms-plugin` is part of [Eclipse KeySealer](https://projects.eclipse.org/projects/technology.keysealer),
which brings HSM-backed key management to Kubernetes. It relies on [crypto11](https://github.com/eclipse-keypont/crypto11), [gose](https://github.com/eclipse-keypont/gose)
and [pkcs11-go](https://github.com/eclipse-keypont/pkcs11-go) from the related
[Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont) project for its PKCS#11 bindings. _"Pont"_ is french for "bridge"

# 🚤 Quick Start 🚀

**TL;DR**: For a quick start experience, try the `k8s-kms-plugin` with a software (virtual) HSM, then plug it into a
throwaway Kubernetes cluster:

1. [SoftHSMv3 (`pqctoday-hsm`) & `k8s-kms-plugin`](./docs/hsm-guides/softhsm-v3.md) — **recommended** HSM: supports all algorithm families including ML-KEM
2. [`KinD` & `k8s-kms-plugin`](./docs/kubernetes-guides/kind-kubernetes.md) — **recommended** cluster: single-node Kubernetes on Podman or Docker, deleted in one command

Other HSMs and TPMs (Thales eToken Fusion, YubiHSM 2, SoftHSMv2, TPM emulator), and the other
Kubernetes distribution guide (`k3s`), are indexed in [`docs/README.md`](./docs/README.md).

# Documentation 📚

The full documentation lives in [`docs/`](./docs/README.md). Start here:

| Guide | What it covers |
|-------|----------------|
| [Concepts & Architecture](./docs/overview.md) | Terminology, where the plugin sits in the KMS v2 envelope scheme, deployment topologies (single node and HA), key rotation |
| [Cryptographic Schemes](./docs/cryptographic-schemes.md) | What each `--algorithm-family` does to the data: keys, primitives, wire format, and which operations stay inside the HSM |
| [Installation](./docs/installation.md) | Getting a release binary or package, verifying its signature and provenance, `go install`, building from source, container images |
| [HSM & TPM guides](./docs/hsm-guides/README.md) | One page per PKCS #11 provider — software and hardware — plus the matrix of which algorithm families and key sizes were tested on each |
| [Kubernetes integration guides](./docs/kubernetes-guides/README.md) | Making a cluster's `kube-apiserver` encrypt Secrets through the plugin: `KinD` and `k3s` |
| [CLI reference](./docs/cli-user-interface/README.md) | Help output, shell completion, configuration precedence, and the generated [per-command reference](./docs/cli-user-interface/markdown/README.md) and [flag / environment variable / config key table](./docs/cli-user-interface/markdown/cli-env-var-table.md) |
| [Helper tools & scripts](./docs/tools-and-scripts/README.md) | `create-dev-token` for a ready-made SoftHSM token, `grpcurl` scripts to drive the API without a cluster, and the `KinD` staging script |
| [Development & Debugging](./docs/development.md) | Repository layout, running the three test suites, building against `crypto11`/`gose` branches, `delve` and `vscode` debugging |
| [Supply Chain Security](./docs/supply-chain-security.md) | Vulnerability scanning, release signing, and verifying artifacts, container images and SLSA provenance |

Release notes and the KMS v1 → v2 migration record are in [`CHANGELOG.md`](./CHANGELOG.md).

# Contributing

Contributions are welcome. Before opening a pull request, please run:

```sh
make lint            # golangci-lint
make test            # unit tests, race detector enabled
make check-doc-links # relative links and #anchors in the documentation
```

If you changed a CLI flag or command, regenerate the CLI reference with `make doc`; if you changed
dependencies, refresh [`NOTICES.md`](./NOTICES.md) with `make notices`. Both write tracked files.

See [Development & Debugging](./docs/development.md) for the full development setup, and
[`CONTRIBUTORS`](./CONTRIBUTORS) for the list of contributors.

# Licence

[MIT](./LICENSE) — see [`NOTICES.md`](./NOTICES.md) for third-party dependency licences.
