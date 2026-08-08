---
title: "Documentation"
---

This folder is the documentation index for [`k8s-kms-plugin`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/README.md). Start here when looking for a guide;
the main [`README.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/README.md) is a short front door that links back here.

> 📄 **Rendering**: these pages are rendered both by GitHub and by the documentation site
> ([Hugo + Hextra](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/website)), which publishes `docs/` and nothing else. Three link
> conventions keep them working in both places:
>
> - **between documentation pages** — always **relative** to the `.md` file (`./installation.md`).
>   A render hook rewrites these to page URLs on the site.
> - **to repository files outside `docs/`** (`scripts/`, `deployments/`, `tools/`, `Makefile`, Go source) —
>   always **absolute** (`https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/…`), because a
>   relative `../` link would leave the published site and 404.
> - **to non-page files inside `docs/`** (`.puml`, `.txt`, and directory listings) — also **absolute**.
>   A page becomes a *directory* URL on the site, so a relative link to a plain file beside it
>   resolves one level too deep. Images are the exception: keep those relative, since Hugo's image
>   render hook resolves them.
>
> Headings carry **no manual section numbers**: a generator derives ordering and the table of contents from the
> document tree, and hand-written numbers drift out of sync with the anchors pointing at them. Run
> `make check-doc-links` after moving or renaming anything here, and `make site` (which runs
> `make check-site`) to confirm the published output still resolves.

- [Getting started](#getting-started)
- [Concepts & architecture](#concepts--architecture)
- [Cryptographic reference](#cryptographic-reference)
- [HSM \& TPM guides](#hsm--tpm-guides)
- [Kubernetes integration guides](#kubernetes-integration-guides)
- [CLI reference](#cli-reference)
- [Development](#development)
- [Helper tools \& scripts](#helper-tools--scripts)
- [Diagrams \& images](#diagrams--images)

## Getting started

**Quick start** — two steps, no hardware needed. Do them in order:

| Step | Guide | What you get |
|------|-------|--------------|
| 1 | [SoftHSMv3 (`pqctoday-hsm`)](./hsm-guides/softhsm-v3.md) | A software PKCS #11 provider with a key per algorithm family, and `k8s-kms-plugin serve` running against it — including ML-KEM |
| 2 | [`KinD`](./kind-kubernetes.md) | A single-node Kubernetes cluster encrypting its Secrets through that plugin, deleted again in one command |

Then, as you need them:

| Page | What it covers |
|------|----------------|
| [Installation](./installation.md) | Getting a release binary or package, verifying it, `go install`, building from source, container images |
| [Usage & User Guides](./usage.md) | CLI help, shell completion, the generated CLI reference, configuration precedence, and the HSM/TPM support matrix |
| [`CHANGELOG.md`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/CHANGELOG.md) | Release history |

## Concepts & architecture

| Page | What it covers |
|------|----------------|
| [Concepts & Architecture](./overview.md) | Terminology, where the plugin sits in the KMS v2 envelope scheme, deployment topologies (single node and HA), and key rotation |

## Cryptographic reference

| Page | What it covers |
|------|----------------|
| [Cryptographic Schemes](./cryptographic-schemes.md) | What each `--algorithm-family` does to the data: keys used, primitives composed, wire format, and which operations run inside the HSM. Includes the ML-KEM / FIPS 203 envelope in detail |

## HSM & TPM guides

One page per PKCS #11 provider, grouped in **[`hsm-guides/`](./hsm-guides/README.md)** — software
providers first, then hardware. New devices are added there.

| Software | Hardware |
|----------|----------|
| [SoftHSMv3 (`pqctoday-hsm`)](./hsm-guides/softhsm-v3.md) — **recommended**, all algorithm families including ML-KEM | [Thales eToken Fusion](./hsm-guides/thales-etoken-fusion.md) — USB token |
| [SoftHSMv2](./hsm-guides/softhsm-v2.md) — legacy, no ML-KEM | [Yubico YubiHSM 2](./hsm-guides/yubico-yubihsm2.md) — USB HSM |
| [Software TPM Emulator](./hsm-guides/software-tpm-emulator.md) — legacy, no ML-KEM | |

The matrix of which algorithm families have been *tested* on each device lives in the usage guide:
[HSM & TPM Supported Platforms](./usage.md#hsm--tpm-supported-platforms).

## Kubernetes integration guides

How to make a cluster's `kube-apiserver` use a running `k8s-kms-plugin` as its KMS v2 provider.

| Guide | Notes |
|-------|-------|
| [`KinD`](./kind-kubernetes.md) | **Recommended** for testing — single-node cluster on Podman or Docker, deleted in one command. Covers the two-hop socket mount, rootless Podman, and a troubleshooting table |
| [`k3s`](./k3s-kubernetes.md) | Installs on the host. Also covers key rotation and HA (3 server nodes) |

Both guides use the reference [`EncryptionConfiguration`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/deployments/k8s/encryption-conf-kmsv2-unix-socket.yaml)
from [`deployments/k8s/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/deployments/k8s/).

## CLI reference

| Page | What it covers |
|------|----------------|
| [CLI documentation index](./cli-user-interface/markdown/README.md) | One page per command, generated from the Cobra definitions |
| [`k8s-kms-plugin serve`](./cli-user-interface/markdown/k8s-kms-plugin_serve.md) | The main command: serves the KMS v2 gRPC API |
| [`k8s-kms-plugin serve rotation`](./cli-user-interface/markdown/k8s-kms-plugin_serve_rotation.md) | Key rotation mode (active + old KEK) |
| [Flags ↔ environment variables](./cli-user-interface/markdown/cli-env-var-table.md) | Recap of every subcommand, flag and env var ([txt version](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/txt/cli-env-var-table.txt)) |
| [`CKA_ID` vs `CKA_LABEL`](./cli-user-interface/cka-id-vs-cka-label.md) | How `--p11-key-id`/`--p11-key-label` (and their `--p11-hmac-*`/`--old-*` counterparts) are resolved — hand-written, not regenerated by `make doc` |

_Auto generated_ files carry a footer such as `###### Auto generated by spf13/cobra on 31-Jul-2025`. Do not edit them
by hand — regenerate with `make doc`. See
[CLI Auto Generated Documentation](./usage.md#cli-auto-generated-documentation).

## Development

| Page | What it covers |
|------|----------------|
| [Development & Debugging](./development.md) | Repository layout, the three test suites and what each needs, building against `crypto11`/`gose` development branches, `delve` and `vscode` debugging |
| [Supply Chain Security](./supply-chain-security.md) | The reference for release signing and provenance: vulnerability scanning locally and in CI, how releases are signed and attested, and the full commands to verify artifacts, container images and SLSA provenance |

## Helper tools & scripts

| Tool | Purpose |
|------|---------|
| [`tools/create-dev-token/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/tools/create-dev-token/) | Bootstraps a SoftHSM token with one ready-to-use key per algorithm family |
| [`scripts/k8s-kind/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/k8s-kind/) | Stages the `KinD` cluster config and `EncryptionConfiguration` |
| [`scripts/grpcurl/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/scripts/grpcurl/) | Exercises the KMS v2 API (`Status`, `Encrypt`, `Decrypt`) without a cluster |

## Diagrams & images

- [`puml-diagrams/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/docs/puml-diagrams/) — PlantUML sources (`.puml`) and their rendered `.svg`
  (`overview.png`/`.svg` are exported from `overview.drawio` instead, not from PlantUML)
- [`images/`](https://github.com/eclipse-keysealer/k8s-kms-plugin/tree/master/docs/images/) — deployment scenarios, key rotation sequences, dependency graphs

Two diagram formats are used on purpose:

| Format | Used for | Lives in |
|---|---|---|
| **Mermaid** | short overview diagrams, written inline in the Markdown and rendered by GitHub — nothing to regenerate | the `.md` files themselves |
| **PlantUML** | the detailed KMS v2 sequences (legend, `alt` branches, per-family payloads) | `.puml` sources + committed `.svg` |

The KMS v2 sequence diagrams are embedded under
[Deployment Scenarios Examples](./overview.md#deployment-scenarios-examples); the envelope overview
is the Mermaid diagram in [Architecture](./overview.md#architecture) and in
[Cryptographic Schemes](./cryptographic-schemes.md#what-the-plugin-actually-encrypts).

**Regenerating the PlantUML `.svg`** after editing a `.puml` — the `.svg` files are committed, so they must be
refreshed in the same commit:

```bash
podman run --rm -v "$PWD/docs/puml-diagrams:/data:z" -w /data \
  docker.io/plantuml/plantuml:latest -tsvg 'kmsv2-*.puml'
```

⚠️ PlantUML names its output after the `@startuml "<name>"` title, **not** after the source file, so rename the
results back to the tracked `kmsv2-*.sqce-diag.svg` names (or use the VS Code PlantUML extension, which keeps the
source file name). The class diagrams (`cbc-class.puml`, `gcm-class.puml`, `rsa-class.puml`,
`ml-kem-class.puml`) use an unnamed `@startuml`, so PlantUML already names their output after the source
file and no renaming is needed.
