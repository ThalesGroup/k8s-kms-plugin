#!/usr/bin/env bash
#
# Prepare a local environment for testing k8s-kms-plugin with a KinD cluster.
#
# Creates the staging area shared between the host and the KinD node:
#
#   $KMS_DEV_ROOT/run/       <- the plugin's unix socket lives here (mounted as a
#                               DIRECTORY so a plugin restart does not leave the
#                               apiserver bound to a stale socket inode)
#   $KMS_DEV_ROOT/config/    <- EncryptionConfiguration + KinD cluster config
#
# Idempotent: safe to re-run, overwrites the two generated config files.
#
# Does NOT: start the plugin, create the cluster, or touch an existing cluster.
#
# See ../../docs/kind-kubernetes.md for the full walkthrough.
#
# Override defaults via env, e.g.:
#   KMS_DEV_ROOT="$HOME/.kms-dev" ./rebuild-kms-dev.sh
#
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./rebuild-kms-dev.sh [-h|--help]

Recreates the KinD + KMSv2 staging directories and config files.

Environment variables:
  KMS_DEV_ROOT    staging root                     (default: /tmp/kms-dev)
  CLUSTER_NAME    KinD cluster name                (default: kms-dev)
  PROVIDER_NAME   KMS provider name in etcd prefix (default: kms-server)
  SOCKET_NAME     unix socket file name            (default: k8s-kms-plugin-dev.sock)
  KMS_TIMEOUT     KMS provider timeout             (default: 3s)
  PKCS11_MODULE   PKCS #11 library, printed in the next-steps hints
                                                   (default: /usr/local/lib/softhsm/libsofthsm3.so)
  P11_LABEL       token label                      (default: k8s-kms-plugin-dev)
  P11_PIN         token user PIN                   (default: 1234)
  P11_KEY_LABEL   KEK label                        (default: dev-rsa-2048-oaep)
  ALGORITHM       --algorithm-family value         (default: rsa-oaep)
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) echo "error: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
esac

KMS_DEV_ROOT="${KMS_DEV_ROOT:-/tmp/kms-dev}"
CLUSTER_NAME="${CLUSTER_NAME:-kms-dev}"
PROVIDER_NAME="${PROVIDER_NAME:-kms-server}"
SOCKET_NAME="${SOCKET_NAME:-k8s-kms-plugin-dev.sock}"
KMS_TIMEOUT="${KMS_TIMEOUT:-3s}"
ENC_CONF_NAME="encryption-conf-kmsv2-unix-socket.yaml"

# Only used to print copy-pasteable next steps; nothing below reads the token.
PKCS11_MODULE="${PKCS11_MODULE:-/usr/local/lib/softhsm/libsofthsm3.so}"
P11_LABEL="${P11_LABEL:-k8s-kms-plugin-dev}"
P11_PIN="${P11_PIN:-1234}"
P11_KEY_LABEL="${P11_KEY_LABEL:-dev-rsa-2048-oaep}"
ALGORITHM="${ALGORITHM:-rsa-oaep}"

RUN_DIR="$KMS_DEV_ROOT/run"
CONF_DIR="$KMS_DEV_ROOT/config"

# --- preflight --------------------------------------------------------------
# Missing tools are reported, not fatal: the staging area is still worth writing.
for tool in kind kubectl; do
  command -v "$tool" >/dev/null 2>&1 || echo "warning: '$tool' not found in PATH"
done

# The container runtime decides whether KIND_EXPERIMENTAL_PROVIDER is needed.
if command -v podman >/dev/null 2>&1; then
  RUNTIME="podman"
elif command -v docker >/dev/null 2>&1; then
  RUNTIME="docker"
else
  RUNTIME="podman"
  echo "warning: neither podman nor docker found in PATH"
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "note: cluster '$CLUSTER_NAME' already exists."
  echo "      it keeps the mounts it was created with -- delete and recreate it"
  echo "      if you change KMS_DEV_ROOT: kind delete cluster --name $CLUSTER_NAME"
fi

# --- directories ------------------------------------------------------------
mkdir -p "$RUN_DIR" "$CONF_DIR"

# A leftover socket from a dead plugin will make the apiserver dial a dead file.
if [[ -S "$RUN_DIR/$SOCKET_NAME" ]]; then
  echo "note: stale socket found, removing -> $RUN_DIR/$SOCKET_NAME"
  rm -f "$RUN_DIR/$SOCKET_NAME"
fi

# --- EncryptionConfiguration ------------------------------------------------
# endpoint is the path INSIDE the apiserver container, not the host path.
cat > "$CONF_DIR/$ENC_CONF_NAME" <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: $PROVIDER_NAME
          endpoint: unix:///kms-socket/$SOCKET_NAME
          timeout: $KMS_TIMEOUT
      - identity: {}
EOF

# --- kind cluster config ----------------------------------------------------
# extraMounts  = hop 1: host          -> node container
# extraVolumes = hop 2: node container -> kube-apiserver static pod
# No apiVersion on the kubeadm patch: lets kind pick v1beta3/v1beta4 itself.
# Pinning the wrong one makes the patch silently dropped.
cat > "$CONF_DIR/kind.config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $CLUSTER_NAME
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $RUN_DIR
        containerPath: /kms-socket
      - hostPath: $CONF_DIR
        containerPath: /etc/kubernetes/kms
        readOnly: true
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            encryption-provider-config: "/etc/kubernetes/kms/$ENC_CONF_NAME"
          extraVolumes:
            - name: kms-socket
              hostPath: /kms-socket
              mountPath: /kms-socket
              pathType: DirectoryOrCreate
            - name: kms-config
              hostPath: /etc/kubernetes/kms
              mountPath: /etc/kubernetes/kms
              readOnly: true
              pathType: DirectoryOrCreate
EOF

# --- report -----------------------------------------------------------------
echo "recreated:"
echo "  $RUN_DIR/"
echo "  $CONF_DIR/$ENC_CONF_NAME"
echo "  $CONF_DIR/kind.config.yaml"

if [[ "$KMS_DEV_ROOT" == /tmp/* ]]; then
  echo
  echo "warning: $KMS_DEV_ROOT is under /tmp and will not survive a reboot."
  echo "         re-run with KMS_DEV_ROOT=\$HOME/.kms-dev to make it persistent."
fi

# Podman is experimental in kind and needs the opt-in env var; docker does not.
if [[ "$RUNTIME" == "podman" ]]; then
  CREATE_CMD="   export KIND_EXPERIMENTAL_PROVIDER=podman
   systemd-run --user --scope --property=Delegate=yes \\
     kind create cluster --config $CONF_DIR/kind.config.yaml"
else
  CREATE_CMD="   kind create cluster --config $CONF_DIR/kind.config.yaml"
fi

cat <<EOF

next steps  (details: docs/kind-kubernetes.md)
---------------------------------------------
1. start the plugin -- before creating the cluster

   k8s-kms-plugin serve \\
       --log-level trace \\
       --socket "$RUN_DIR/$SOCKET_NAME" \\
       --p11-lib   "$PKCS11_MODULE" \\
       --p11-label "$P11_LABEL" \\
       --p11-pin   "$P11_PIN" \\
       --p11-key-label $P11_KEY_LABEL \\
       --algorithm-family $ALGORITHM &

   (no token yet? bootstrap one with: eval "\$(go run ./tools/create-dev-token --lib $PKCS11_MODULE)")

2. create the cluster ($RUNTIME detected)

$CREATE_CMD

3. verify the flag reached the apiserver -- empty output means the patch was dropped

   kubectl --context kind-$CLUSTER_NAME -n kube-system \\
     get pod kube-apiserver-$CLUSTER_NAME-control-plane \\
     -o jsonpath='{.spec.containers[0].command}' | tr ' ' '\\n' | grep -i encrypt

4. confirm secrets are encrypted in etcd -- look for the k8s:enc:kms:v2:$PROVIDER_NAME: prefix

   kubectl --context kind-$CLUSTER_NAME create secret generic probe --from-literal=foo=bar
   kubectl --context kind-$CLUSTER_NAME -n kube-system exec etcd-$CLUSTER_NAME-control-plane -- \\
     etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt \\
             --cert=/etc/kubernetes/pki/etcd/server.crt \\
             --key=/etc/kubernetes/pki/etcd/server.key \\
             get /registry/secrets/default/probe | strings

cleanup
-------
   kind delete cluster --name $CLUSTER_NAME
   rm -rf $KMS_DEV_ROOT
EOF
