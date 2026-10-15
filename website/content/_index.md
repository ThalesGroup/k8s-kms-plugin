---
title: "k8s-kms-plugin"
layout: hextra-home
---

<div class="hx:flex hx:flex-wrap hx:gap-2">
{{< hextra/hero-badge link="https://projects.eclipse.org/projects/technology.keysealer" >}}
  <span>Part of Eclipse KeySealer</span>
  {{< icon name="arrow-circle-right" attributes="height=14" >}}
{{< /hextra/hero-badge >}}
{{< hextra/hero-badge link="https://projects.eclipse.org/projects/technology.keypont" >}}
  <span>Relying on Eclipse KeyPont</span>
  {{< icon name="arrow-circle-right" attributes="height=14" >}}
{{< /hextra/hero-badge >}}
</div>

<!-- The hero text and the "where it fits" diagram sit side by side on wide screens and stack on
     narrow ones; the layout rules are in website/assets/css/custom.css. The same diagram is in the
     main README.md, so change both together. -->
<div class="kms-hero">
<div class="kms-hero-text">

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
{{< hextra/hero-button text="Get started" link="docs/overview/" >}}
</div>

</div>
<div class="kms-hero-figure">

```mermaid
%%{init: {"flowchart": {"nodeSpacing": 16, "rankSpacing": 32, "padding": 8}}}%%
flowchart TB
    K8S["kube-apiserver"]
    PLG(["k8s-kms-plugin"])
    DRV["vendor PKCS #11 driver"]
    HSM{{"TPM / HSM · KEK"}}
    K8S <-->|"KMS v2 API<br/>gRPC over a plaintext<br/>unix socket"| PLG
    PLG <-->|"PKCS #11 C API<br/>up to v3.2"| DRV
    DRV <-->|"USB · network · TPM"| HSM
    classDef main fill:#1f6feb,stroke:#1f6feb,color:#fff,font-weight:bold,font-size:18px
    class PLG main
```

</div>
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
    title="Quick start, in minutes"
    subtitle="A SoftHSMv3 software HSM, then a throwaway KinD cluster deleted in one command. No hardware needed to see the whole path end to end."
    link="docs/quick-start/"
  >}}
  {{< hextra/feature-card
    title="Runs where your cluster runs"
    subtitle="linux/amd64, arm64 and riscv64 binaries and packages, plus a container image on ghcr.io. Tested against SoftHSMv3, SoftHSMv2, a TPM emulator, Thales eToken Fusion and YubiHSM 2."
    link="docs/installation/"
  >}}
{{< /hextra/feature-grid >}}
