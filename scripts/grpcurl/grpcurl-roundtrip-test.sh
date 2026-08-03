#!/usr/bin/env bash
set -euo pipefail

# ---- Check for required tools ----
# Probe by *running* each tool, not with `command -v` — the same rule the Makefile
# applies (see `define require`). A goenv/asdf/pyenv shim stays on PATH even when
# the tool is not installed for the active version, so `command -v grpcurl` says
# yes and the shim only fails once called, with
# `goenv: 'grpcurl' command not found` — an error that surfaces far from its cause.
#
# Exit 127 — missing binary, or a shim with nothing behind it — is the only status
# treated as missing; tools that reject --version exit 1 or 2 and pass.
MISSING=()
require_tool() {   # require_tool <binary> <how to install it>
  local rc=0
  "$1" --version >/dev/null 2>&1 || rc=$?
  (( rc != 127 )) || MISSING+=("$1|$2")
}

require_tool grpcurl "go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
require_tool jq      "sudo apt-get install jq"
require_tool base64  "sudo apt-get install coreutils"
require_tool curl    "sudo apt-get install curl"

if (( ${#MISSING[@]} > 0 )); then
  echo "❌ Required tools are not installed:" >&2
  for m in "${MISSING[@]}"; do
    IFS='|' read -r _tool _hint <<<"$m"
    echo "   • $_tool — install it with:" >&2
    echo "       $_hint" >&2
  done
  exit 1
fi

print_jwe_header() {
  local jwe b64
  jwe=$(printf '%s' "$1" | base64 -d)
  b64=$(printf '%s' "$jwe" | cut -d. -f1 | tr -- '-_' '+/')
  case $((${#b64} % 4)) in
    2) b64="${b64}==" ;;
    3) b64="${b64}=" ;;
  esac
  echo "🔑 JWE Header:"
  echo '```json'
  printf '%s' "$b64" | base64 -d | jq
  echo '```'
}

# print_mlkem_envelope shows the size of the AEAD-wrapped seed (ciphertext) and the raw
# ML-KEM encapsulation ciphertext (the kem-ct annotation). ML-KEM has no JWE header to
# print — the KEM ciphertext travels as a plain KMS v2 annotation instead (see
# ml-kem-kmsv2-implementation-spec.md).
print_mlkem_envelope() {
  local ciphertext_b64="$1" encrypt_response="$2"
  local ct_len kemct_b64 kemct_len

  ct_len=$(printf '%s' "$ciphertext_b64" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')
  kemct_b64=$(printf '%s' "$encrypt_response" | jq -r '(.annotations // {})["kem-ct.k8s-kms-plugin.keysealer.eclipse.org"] // empty')
  kemct_len=0
  [[ -n "$kemct_b64" ]] && kemct_len=$(printf '%s' "$kemct_b64" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')

  echo "🧬 ML-KEM envelope (no JWE):"
  echo '```'
  echo "ciphertext:        ${ct_len} B  (nonce || AES-256-GCM-sealed DEK seed)"
  echo "kem-ct annotation: ${kemct_len} B  (raw ML-KEM encapsulation ciphertext)"
  echo '```'
}

# print_ciphertext_info prints either the JWE protected header (AES-GCM / AES-CBC+HMAC /
# RSA-OAEP) or the ML-KEM binary envelope's size breakdown, depending on the
# "algorithm-family" annotation the plugin attaches to every EncryptResponse — so this
# reports what the plugin actually produced, not an assumption baked into the script.
print_ciphertext_info() {
  local ciphertext_b64="$1" encrypt_response="$2"
  local family_b64 family

  family_b64=$(printf '%s' "$encrypt_response" | jq -r '(.annotations // {})["algorithm-family.k8s-kms-plugin.keysealer.eclipse.org"] // empty')
  family=""
  [[ -n "$family_b64" ]] && family=$(printf '%s' "$family_b64" | base64 -d 2>/dev/null || true)

  if [[ "$family" == "ml-kem" ]]; then
    print_mlkem_envelope "$ciphertext_b64" "$encrypt_response"
  else
    print_jwe_header "$ciphertext_b64"
  fi
}

API_PROTO_URL="https://raw.githubusercontent.com/kubernetes/kms/refs/tags/v0.34.1/apis/v2/api.proto"
if [[ ! -f api.proto ]]; then
  echo "api.proto file not found. Downloading protobufer API file from ${API_PROTO_URL}..."
  curl -sSL -o api.proto "${API_PROTO_URL}"
else
  echo "Using existing api.proto. If you want to update it, please remove this file."
fi

# ---- Parse user input ----
PLAINTEXT="${1:-}"
SOCKET="${2:-}"
VERBOSE="${VERBOSE:-false}"

if [[ -z "$PLAINTEXT" || -z "$SOCKET" ]]; then
  echo "Usage: $0 <plaintext> <unix-socket-path>"
  echo "Example: $0 'hello world' /run/user/1000/k8s-kms-plugin.sock"
  echo "         VERBOSE=true $0 'hello world' /run/user/1000/k8s-kms-plugin.sock"
  echo ""
  echo "This script performs a KMSv2 StatusRequest to get a key_id."
  echo "Then does an EncryptRequest using the user input plaintext and the key_id."
  echo "Then does a DecryptRequest and verifies the decrypted ciphertext matches the user provided plaintext."
  echo ""
  echo "Set VERBOSE=true to dump full JSON requests and responses."
  exit 1
fi

echo "# 🔐 KMS v2 Round-Trip Test"
echo ""
[[ "$VERBOSE" == true ]] && echo "🔍 Verbose: enabled" || echo "🔇 Verbose: disabled — set \`VERBOSE=true\` to see full JSON requests and responses"
echo ""

# ---- Base64-encode plaintext ----
PLAINTEXT_BASE64=$(echo -n "$PLAINTEXT" | base64)
echo "🔐 Input plaintext: \`$PLAINTEXT\`"
echo "🔐 Base64 encoded: \`$PLAINTEXT_BASE64\`"

echo ""
echo "---"
echo ""
echo "## 1️⃣ Status"
echo ""

# ---- Get key_id from Status ----
STATUS_REQUEST='{}'
[[ "$VERBOSE" == true ]] && { echo "📤 StatusRequest:"; echo '```json'; echo "$STATUS_REQUEST" | jq; echo '```'; echo ""; }

STATUS_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$STATUS_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Status)

[[ "$VERBOSE" == true ]] && { echo "📥 StatusResponse:"; echo '```json'; echo "$STATUS_RESPONSE" | jq; echo '```'; echo ""; }

KEY_ID=$(echo "$STATUS_RESPONSE" | jq -r .keyId)
echo "🧾 key_id: \`$KEY_ID\`"

echo ""
echo "---"
echo ""
echo "## 2️⃣ Encrypt"
echo ""

# ---- Encrypt ----
ENCRYPT_REQUEST="{\"plaintext\": \"$PLAINTEXT_BASE64\", \"uid\": \"test-enc-1\"}"
[[ "$VERBOSE" == true ]] && { echo "📤 EncryptRequest:"; echo '```json'; echo "$ENCRYPT_REQUEST" | jq; echo '```'; echo ""; }

ENCRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$ENCRYPT_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Encrypt)

[[ "$VERBOSE" == true ]] && { echo "📥 EncryptResponse:"; echo '```json'; echo "$ENCRYPT_RESPONSE" | jq; echo '```'; echo ""; }

CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r .ciphertext)
[[ "$VERBOSE" == true ]] && { echo "🗄️ Ciphertext (base64):"; echo '```'; echo "$CIPHERTEXT"; echo '```'; echo ""; }
print_ciphertext_info "$CIPHERTEXT" "$ENCRYPT_RESPONSE"
echo ""

if [[ "$VERBOSE" == true ]]; then
  ENCRYPT_RESPONSE_B64=$(echo "$ENCRYPT_RESPONSE" | jq -c | base64 -w 0)
  echo "> ⬇️ Run key rotation test with the old KEK data from this run:"
  echo '```bash'
  printf 'VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh \\\n'
  printf '  '"'"'<plaintext for ACTIVE KEK>'"'"' \\\n'
  printf '  '"'"'%s'"'"' \\\n' "$PLAINTEXT"
  printf '  '"'"'%s'"'"' \\\n' "$ENCRYPT_RESPONSE_B64"
  printf '  '"'"'%s'"'"'\n' "$SOCKET"
  echo '```'
fi

echo ""
echo "---"
echo ""
echo "## 3️⃣ Decrypt"
echo ""

# ---- Decrypt ----
# Annotations are forwarded from EncryptResponse, mirroring the apiserver's round-trip
# guarantee — required for ML-KEM, whose kem-ct annotation the plugin needs back to decrypt.
DECRYPT_REQUEST=$(echo "$ENCRYPT_RESPONSE" | jq -c --arg uid "test-dec-1" --arg kid "$KEY_ID" \
  '{ciphertext: .ciphertext, uid: $uid, key_id: $kid} + (if (.annotations // {}) == {} then {} else {annotations: .annotations} end)')
[[ "$VERBOSE" == true ]] && { echo "📤 DecryptRequest:"; echo '```json'; echo "$DECRYPT_REQUEST" | jq; echo '```'; echo ""; }

DECRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$DECRYPT_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Decrypt)

[[ "$VERBOSE" == true ]] && { echo "📥 DecryptResponse:"; echo '```json'; echo "$DECRYPT_RESPONSE" | jq; echo '```'; echo ""; }

DECRYPTED_BASE64=$(echo "$DECRYPT_RESPONSE" | jq -r .plaintext)
DECRYPTED_TEXT=$(echo "$DECRYPTED_BASE64" | base64 -d)
echo "🔓 Decrypted text: \`$DECRYPTED_TEXT\`"

echo ""
echo "---"
echo ""
echo "## 4️⃣ Summary"
echo ""

# ---- Compare ----
if [[ "$DECRYPTED_TEXT" == "$PLAINTEXT" ]]; then
  echo "✅ Round-trip encryption/decryption successful!"
else
  echo "❌ Decryption mismatch! Expected \`$PLAINTEXT\` but got \`$DECRYPTED_TEXT\`"
  exit 1
fi
