---
title: "Thales Luna HSM"
weight: 60
---

Thales publishes its own integration guide for Luna HSMs, and that guide documents **this plugin** —
it installs `k8s-kms-plugin` from the Eclipse KeySealer releases and configures `kube-apiserver`
against it. Rather than restate it here and let the copy drift out of step with the vendor's, this
page points at the original.

> [!IMPORTANT]
> **[Kubernetes Secret Encryption Using KMS v2](https://thalesdocs.com/gphsm/integrations/guides/kubernetes_secrets_encryption/kubernetes_secrets_encryption_using_kms_v2/)**
> — the authoritative guide, maintained by Thales.

It applies to all Luna HSMs provided a supported Luna Client is used, which covers the network
appliance and Luna Cloud HSM as well. The Luna Client supplies the PKCS #11 library that
`--p11-lib` points at; everything above that line is the same plugin configuration as any other
provider in this section.

The vendor guide covers the prerequisites, generating the KEK on the HSM, configuring and deploying
the plugin, verifying that Secrets are encrypted, key rotation, and migrating an existing cluster
from a local encryption provider to HSM-backed keys.

> [!NOTE]
> Luna is not yet exercised by this repository's integration or e2e suites, so it is absent from the
> [supported platforms table](./README.md#hsm--tpm-supported-platforms). That table records what has
> been tested here, not what is known to work.

Once the HSM is reachable, the plugin flags and the choice between `--p11-key-id` and
`--p11-key-label` follow the section index — see [`CKA_ID` vs `CKA_LABEL`](../cli-user-interface/cka-id-vs-cka-label.md).
