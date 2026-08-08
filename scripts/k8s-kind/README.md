# `KinD` staging script

`rebuild-kms-dev.sh` stages everything a [`KinD`](https://kind.sigs.k8s.io/) cluster needs to use
`k8s-kms-plugin` as its KMS v2 provider: the `run/` and `config/` directories, the
`EncryptionConfiguration`, and a `kind.config.yaml` that mounts the plugin's unix socket into the
node container. It then prints the `serve` command to run.

📖 **Documentation: [`docs/tools-and-scripts/k8s-kind-scripts.md`](../../docs/tools-and-scripts/k8s-kind-scripts.md)**
— what it writes, what you still do by hand, and the step-by-step split.

Creating the cluster itself is covered by the
[`KinD` integration guide](../../docs/kubernetes-guides/kind-kubernetes.md).
