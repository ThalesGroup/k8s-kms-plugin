---
title: "CLI reference"
weight: 90
---

How every `k8s-kms-plugin` command, flag, environment variable and config file key is spelled, and
how the PKCS #11 key selectors are resolved.

| Page | What it covers |
|------|----------------|
| [Generated command reference](./markdown/README.md) | One page per command, generated from the Cobra definitions by `make doc` |
| [Flags ↔ environment variables ↔ config keys](./markdown/cli-env-var-table.md) | Every subcommand and flag with its environment variable, config key, type and default ([plain text version](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/cli-user-interface/txt/cli-env-var-table.txt)) |
| [`CKA_ID` vs `CKA_LABEL`](./cka-id-vs-cka-label.md) | How `--p11-key-id` / `--p11-key-label` and their `--p11-hmac-*` and `--old-*` counterparts are resolved against the token |

Everything under [`markdown/`](./markdown/) is **generated** — do not edit it by hand. Change the
Cobra command and run `make doc`. The output is reproducible, so a diff there is a real CLI change.

Configuration precedence is **CLI flags > environment variables > config file > defaults**; see
[User Input Priority](../usage.md#user-input-priority-cli--env-vars--config-file--default).
