<!--
SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and k8s-kms-plugin Authors
SPDX-License-Identifier: MIT
-->

# Security Policy

k8s-kms-plugin is a Kubernetes KMS v2 plugin: it sits between the API server and a PKCS #11 token
or HSM, and it is the component that wraps and unwraps the data-encryption keys protecting every
secret in the cluster. A defect here can mean key material leaking, a key that is not what it
claims to be, or a cluster that cannot decrypt its own data. We take reports seriously and would
rather hear about a suspected issue than not.

This project is an Eclipse Foundation project and adheres to the
[Eclipse Foundation Vulnerability Reporting Policy](https://www.eclipse.org/security/policy/).

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull
requests.**

Report privately through any of these channels:

- **[GitHub private vulnerability reporting](https://github.com/eclipse-keysealer/k8s-kms-plugin/security/advisories/new)**
  — preferred. It keeps the report, the fix and the advisory in one place.
- **The Eclipse Foundation Vulnerability Reporting Tracker**, by creating a
  [confidential issue](https://gitlab.eclipse.org/security/vulnerability-reports/-/issues/new?issuable_template=new_vulnerability).
  This is the Foundation-level channel and the right one if the issue spans several Eclipse KeySealer
  or KeyPont projects.
- **The Eclipse Foundation security team**, at <security@eclipse-foundation.org>. See the
  [Eclipse Foundation Security Policy](https://www.eclipse.org/security/policy/) for the
  Foundation-level process. Use this channel if you would rather not report through GitHub or GitLab.

### What to include

The more of this you can supply, the faster we can confirm and fix:

- A description of the issue and why you believe it has security impact, including the type of
  issue (for example a key-confusion, a plaintext leak, or an authentication bypass).
- The affected version or commit, and whether `master` is affected.
- The deployment shape: the KMS v2 protocol version, the transport (Unix socket or TCP), and the
  PKCS #11 module or HSM involved (vendor, product, library/firmware version), if the issue depends
  on one.
- Step-by-step instructions to reproduce the issue, and the location of the affected source code
  (tag/branch/commit or direct URL), with full paths of the source files involved.
- Any configuration required to reproduce the issue (a redacted `config.yaml` is fine), and related
  log files if you have them.
- A minimal reproducer — a `grpcurl` transcript or a short Go snippet that triggers the bug is often
  the clearest one. Proof-of-concept or exploit code is welcome if you have it.
- Whether you intend to disclose publicly, and on what timeline.

Reports in any language are fine, and a partial report is better than none.

## What to expect

We will tell you when we have confirmed the issue, when a fix lands, and when the advisory is
published. If we conclude the report is not a vulnerability we will explain why, and you are
welcome to push back. This is a modest project; we do our best to respond promptly.

We work on a best-effort basis, but a strong security CI/CD pipeline backs every change: linting,
static analysis, vulnerability scanning and signed, provenance-attested releases. It reduces the
odds of a defect reaching a release, and it is why we would rather hear about a suspected issue
than not.

## Disclosure

We follow coordinated disclosure. We ask that you give us a reasonable opportunity to release a fix
before disclosing publicly — as a default, 90 days from acknowledgement, or until a fix is
released, whichever comes first. When a fix is released we publish a
[GitHub Security Advisory](https://github.com/eclipse-keysealer/k8s-kms-plugin/security/advisories),
with a CVE where one is warranted; for Eclipse projects CVEs are assigned through the Eclipse
Foundation security team. Reporters are credited by name unless they ask not to be.

## Supported versions

| Version  | Supported                        |
|----------|----------------------------------|
| `v1.x`   | Yes — active development         |
| Older    | No                               |

Fixes land on `master` first and ship in the next tagged release.

## Scope

**In scope** — anything in this repository that could compromise key material or the integrity of a
KMS v2 operation, including:

- Plaintext, data-encryption keys or KEK material leaking through logs, error messages, returned
  buffers or memory that is not cleared.
- Key confusion: unwrapping with the wrong key, returning a key that does not match the one that
  was wrapped, or a key ID that is not bound to the key it names.
- Authentication or authorization that can be bypassed on the KMS v2 gRPC surface, including the
  status and health endpoints.
- Mechanism, parameter or attribute handling that silently weakens an operation — for example
  accepting a padding scheme or key size the caller did not ask for, or failing to enforce an
  attribute the caller set.
- Missing or incorrect validation of data returned by the token, where a malicious or malfunctioning
  token could induce unsafe behaviour in the plugin.
- Supply-chain integrity of the release pipeline: the signed tags, SBOM, container image signatures
  and SLSA provenance.

**Out of scope:**

- Vulnerabilities in the PKCS #11 module, token or HSM itself. Report those to the vendor. We do
  want to know if the plugin can defend against them, so tell us anyway if there is something we
  could do.
- Vulnerabilities in a dependency, unless the plugin's use of the dependency is what makes them
  exploitable. Report those upstream; `govulncheck` and Dependabot cover us for the rest.
- Insecure configuration chosen by the operator — for example a world-readable `config.yaml`, a PIN
  on the command line, or a socket reachable by untrusted users. If our documentation encourages an
  insecure pattern, that *is* worth reporting.
- Test-only code, example configuration, and the throwaway tokens and PINs used by the test suites.

## Verifying what you run

Every tagged release ships a signed binary, a keyless cosign signature, a CycloneDX SBOM and SLSA3
build provenance, and the container images are signed too. If you need to confirm that the artifact
you are running is what we published, see
[Supply Chain Security](./docs/supply-chain-security.md) and
[Installation](./docs/installation.md) in the documentation.

## Security posture

Every push and pull request runs golangci-lint, `go vet`, govulncheck, gosec, CodeQL, Trivy, native
GitHub secret scanning, dependency review and an
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/eclipse-keysealer/k8s-kms-plugin)
evaluation. These reduce the odds of a defect reaching a release; they do not replace your report.
