---
title: "k8s-kms-plugin"
layout: hextra-home
---

{{< hextra/hero-badge link="https://projects.eclipse.org/projects/technology.keysealer" >}}
  <span>Part of Eclipse KeySealer</span>
  {{< icon name="arrow-circle-right" attributes="height=14" >}}
{{< /hextra/hero-badge >}}

<div class="hx:mt-6 hx:mb-6">
{{< hextra/hero-headline >}}
  Encrypt Kubernetes secrets&nbsp;<br class="hx:sm:block hx:hidden" />with a TPM or HSM
{{< /hextra/hero-headline >}}
</div>

<div class="hx:mb-12">
{{< hextra/hero-subtitle >}}
  A gRPC service implementing the Kubernetes KMS v2 API,&nbsp;<br class="hx:sm:block hx:hidden" />backed by a PKCS #11 device — including post-quantum ML-KEM.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-6">
{{< hextra/hero-button text="Get started" link="docs/" >}}
</div>

<div class="hx:mt-6"></div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="Your keys never leave the device"
    subtitle="The plugin sees only the 32-byte DEK seed that kube-apiserver asks it to wrap. The KEK stays on the TPM or HSM, and every wrap and unwrap happens there."
    link="docs/overview/"
  >}}
  {{< hextra/feature-card
    title="Post-quantum ready"
    subtitle="ML-KEM-512, 768 and 1024 (FIPS 203) alongside AES-GCM, AES-CBC+HMAC and RSA-OAEP. The parameter set is derived from the key on the device, not configured by hand."
    link="docs/cryptographic-schemes/"
  >}}
  {{< hextra/feature-card
    title="KMS v2, with key rotation"
    subtitle="Serves the current Kubernetes KMS v2 API over a local unix socket. serve rotation decrypts under the previous KEK while the new one takes over — the two may even live on different HSMs."
    link="docs/overview/#key-rotation-support"
  >}}
  {{< hextra/feature-card
    title="Signed, attested releases"
    subtitle="Keyless Sigstore signatures, SBOMs, and SLSA3 provenance for both binaries and the container image. The release pipeline verifies its own output before it finishes."
    link="docs/supply-chain-security/"
  >}}
  {{< hextra/feature-card
    title="Try it in minutes"
    subtitle="A software HSM and a throwaway KinD cluster, deleted in one command. No hardware needed to see the whole path end to end."
    link="docs/hsm-guides/softhsm-v3/"
  >}}
  {{< hextra/feature-card
    title="Runs where your cluster runs"
    subtitle="linux/amd64, arm64 and riscv64 binaries and packages, plus a container image on ghcr.io. Tested against SoftHSMv3, SoftHSMv2, a TPM emulator, Thales eToken Fusion and YubiHSM 2."
    link="docs/installation/"
  >}}
{{< /hextra/feature-grid >}}
