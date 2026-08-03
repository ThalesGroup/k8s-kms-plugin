#!/usr/bin/env bash
#
# collect-jwe-samples.sh
#
# Drives k8s-kms-plugin through every key in a create-dev-token SoftHSM store,
# performs a KMS v2 Status/Encrypt/Decrypt round-trip against each, and saves
# the raw JSON messages plus a byte-level size breakdown of the envelope:
# the JWE Compact Serialization for aes-gcm/aes-cbc/rsa-oaep, or the plain
# binary envelope (nonce || AES-256-GCM-sealed seed) plus the separate
# kem-ct annotation for ml-kem — detected per case from the algorithm-family
# annotation the plugin actually returned, not assumed from the case name.
#
# The plugin serves exactly one KEK + one algorithm family per socket, so this
# script starts and stops the plugin once per case.
#
# Usage:
#   export SOFTHSM2_CONF=/tmp/k8s-kms-plugin-devtoken/softhsm2.conf
#   ./collect-jwe-samples.sh --lib /path/to/libsofthsmv3.so
#
# Output tree (jwe-samples/ is git-ignored — see .gitignore):
#   jwe-samples/<case>/{status,encrypt,decrypt}-*.json
#   jwe-samples/<case>/sizes.json
#   jwe-samples/<case>/jwe.compact.txt, jwe.protected-header.json  (aes-gcm/aes-cbc/rsa-oaep only)
#   jwe-samples/<case>/envelope.bin                                (ml-kem only)
#   jwe-samples/summary.md, summary.csv, summary.json
#
set -euo pipefail

# --------------------------------------------------------------------------
# Defaults (override via flags or environment)
# --------------------------------------------------------------------------
PLUGIN_BIN="${PLUGIN_BIN:-k8s-kms-plugin}"
P11_LIB="${PKCS11_MODULE:-}"
P11_LABEL="${P11_LABEL:-k8s-kms-plugin-dev}"
P11_PIN="${P11_PIN:-1234}"
OUT_DIR="${OUT_DIR:-jwe-samples}"   # git-ignored; see .gitignore
PLAINTEXT="${PLAINTEXT:-kms-v2-dek-seed-0123456789abcdef}"
LIMIT="${LIMIT:-1024}"          # apiserver ciphertext ceiling; try 1000 to compare
PROTO_TAG="${PROTO_TAG:-v0.34.1}"
ONLY=""
KEEP_GOING=false
FULL_CIPHERTEXT=false
ARCHIVE_ENABLED=true
# zip by default because the archive's job is to be attached to an issue, and
# GitHub accepts only .zip, .gz and .tgz there — .tar.zst is rejected on upload.
ARCHIVE_FORMAT="${ARCHIVE_FORMAT:-zip}"
LOG_FORMAT="${LOG_FORMAT:-json}"
LOG_LEVEL="${LOG_LEVEL:-info}"
LOG_FLAG_POSITION=""      # discovered on first successful start, then reused
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-20}"

API_PROTO_URL="https://raw.githubusercontent.com/kubernetes/kms/refs/tags/${PROTO_TAG}/apis/v2/api.proto"

usage() {
  cat <<EOF
Usage: $0 [options]

  --lib PATH          PKCS#11 module (default: \$PKCS11_MODULE)
  --plugin PATH       k8s-kms-plugin binary (default: k8s-kms-plugin)
  --label LABEL       PKCS#11 token label (default: k8s-kms-plugin-dev)
  --pin PIN           PKCS#11 user PIN (default: 1234)
  --out DIR           output directory (default: jwe-samples, git-ignored)
  --plaintext STR     payload to encrypt (default: a 32-byte DEK-sized string)
  --limit N           KMS v2 ciphertext ceiling for the report (default: 1024)
  --only REGEX        run only cases whose name matches REGEX
  --keep-going        continue after a failing case (e.g. ML-KEM on SoftHSMv2)
  --full-ciphertext   do not elide long base64 values in messages.md
                      (per-case JSON files are always written in full)
  --format FMT        archive format: zip (default), tgz, tar.zst
                      zip and tgz can be attached to a GitHub issue; tar.zst
                      compresses far better but GitHub rejects it on upload
  --no-archive        do not bundle the output tree at all
                      (skips the archiver dependency entirely)
  --log-format FMT    plugin --log-format (default: json)
  --log-level LVL     plugin --log-level (default: info; use trace to capture
                      the plugin's own ciphertextLen instrumentation)
  -h, --help          this text

SOFTHSM2_CONF must point at the create-dev-token store.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lib)        P11_LIB="$2";     shift 2 ;;
    --plugin)     PLUGIN_BIN="$2";  shift 2 ;;
    --label)      P11_LABEL="$2";   shift 2 ;;
    --pin)        P11_PIN="$2";     shift 2 ;;
    --out)        OUT_DIR="$2";     shift 2 ;;
    --plaintext)  PLAINTEXT="$2";   shift 2 ;;
    --limit)      LIMIT="$2";       shift 2 ;;
    --only)       ONLY="$2";        shift 2 ;;
    --keep-going) KEEP_GOING=true;  shift   ;;
    --full-ciphertext) FULL_CIPHERTEXT=true; shift ;;
    --format)     ARCHIVE_FORMAT="$2"; shift 2 ;;
    --no-archive) ARCHIVE_ENABLED=false; shift ;;
    --log-format) LOG_FORMAT="$2"; shift 2 ;;
    --log-level)  LOG_LEVEL="$2";  shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "❌ Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
# Probe by *running* each tool, not with `command -v` — the same rule the
# Makefile applies (see `define require`). A goenv/asdf/pyenv shim stays on PATH
# even when the tool is not installed for the active version, so `command -v
# grpcurl` says yes and the shim only fails when called, with
# `goenv: 'grpcurl' command not found`. That is not a theoretical concern here:
# the plugin readiness probe *is* a grpcurl call, so a dead shim made every
# probe fail and the script blamed the plugin ("plugin failed to start") for a
# missing client.
#
# Exit 127 — missing binary, or a shim with nothing behind it — is the only
# status treated as missing; tools that reject --version exit 1 or 2 and pass.
MISSING=()
have_tool() {   # have_tool <binary> -> 0 if it is actually runnable
  local rc=0
  "$1" --version >/dev/null 2>&1 || rc=$?
  (( rc != 127 ))
}
require_tool() {   # require_tool <binary> <how to install it>
  have_tool "$1" || MISSING+=("$1|$2")
}

require_tool grpcurl "go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
require_tool jq      "sudo apt-get install jq"
require_tool base64  "sudo apt-get install coreutils"
require_tool curl    "sudo apt-get install curl"
require_tool "$PLUGIN_BIN" "go install ./cmd/k8s-kms-plugin   (or set --plugin / PLUGIN_BIN)"

# The archiver is only a dependency when we are actually going to build an
# archive, so --no-archive keeps the script runnable without one.
ARCHIVER=""
if $ARCHIVE_ENABLED; then
  case "$ARCHIVE_FORMAT" in
    zip)
      # Either tool will do: bsdtar (libarchive) writes zip natively and ships on
      # Arch and macOS, where `zip` frequently is not installed.
      if   have_tool zip;    then ARCHIVER=zip
      elif have_tool bsdtar; then ARCHIVER=bsdtar
      else
        MISSING+=("zip|sudo apt-get install zip / sudo pacman -S zip   (or --format tgz, or --no-archive)")
      fi ;;
    tgz)
      have_tool tar && ARCHIVER=tar || MISSING+=("tar|sudo apt-get install tar") ;;
    tar.zst)
      have_tool tar  || MISSING+=("tar|sudo apt-get install tar")
      have_tool zstd && ARCHIVER=tar-zstd \
        || MISSING+=("zstd|sudo apt-get install zstd / sudo pacman -S zstd") ;;
    *)
      echo "❌ Unknown --format: $ARCHIVE_FORMAT (want: zip, tgz, tar.zst)" >&2; exit 1 ;;
  esac
fi

if (( ${#MISSING[@]} > 0 )); then
  echo "❌ Required tools are not installed:" >&2
  for m in "${MISSING[@]}"; do
    IFS='|' read -r _tool _hint <<<"$m"
    echo "   • $_tool — install it with:" >&2
    echo "       $_hint" >&2
  done
  exit 1
fi
[[ -n "$P11_LIB" ]] || { echo "❌ No PKCS#11 module. Pass --lib or set PKCS11_MODULE." >&2; exit 1; }
[[ -f "$P11_LIB" ]] || { echo "❌ PKCS#11 module not found: $P11_LIB" >&2; exit 1; }
[[ -n "${SOFTHSM2_CONF:-}" ]] || { echo "❌ SOFTHSM2_CONF is not set." >&2; exit 1; }
[[ -f "$SOFTHSM2_CONF" ]] || { echo "❌ SOFTHSM2_CONF points at a missing file: $SOFTHSM2_CONF" >&2; exit 1; }

mkdir -p "$OUT_DIR"
PROTO_FILE="api.proto"
if [[ ! -f "$PROTO_FILE" ]]; then
  echo "⬇️  Fetching KMS v2 api.proto (${PROTO_TAG})"
  curl -sSL -o "$PROTO_FILE" "$API_PROTO_URL"
fi

SOCKET_DIR="$(mktemp -d /tmp/kms-jwe-samples.XXXXXX)"
SOCKET="$SOCKET_DIR/plugin.sock"
PLUGIN_PID=""

cleanup() {
  stop_plugin || true
  rm -rf "$SOCKET_DIR"
}
trap cleanup EXIT INT TERM

# Without this, a command that trips `set -e` aborts with no output at all,
# which is very hard to diagnose mid-loop.
trap 'rc=$?; echo "" >&2; echo "❌ aborted at line $LINENO (exit $rc)" >&2' ERR

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

# base64url -> raw bytes on stdout. Never fails the caller under `set -e`;
# emits nothing on malformed input.
b64url_decode() {
  local s="${1//-/+}"
  s="${s//_/\/}"
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;;
    3) s="${s}="  ;;
    1) return 0   ;;
  esac
  printf '%s' "$s" | base64 -d 2>/dev/null || true
}

# base64url -> raw bytes into a file. Use this, not `$(b64url_decode ...)`,
# whenever the payload may be binary: command substitution strips trailing
# newlines and a bash string cannot hold a NUL byte, so round-tripping the
# ml-kem envelope through a variable silently loses bytes.
b64url_decode_to_file() {   # b64url_decode_to_file <b64url> <path>
  local s="${1//-/+}"
  s="${s//_/\/}"
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;;
    3) s="${s}="  ;;
    1) : >"$2"; return 0 ;;
  esac
  printf '%s' "$s" | base64 -d >"$2" 2>/dev/null || : >"$2"
}

# decoded byte length of a base64url string ("0" for empty/invalid)
b64url_len() {
  local s="${1:-}" n
  [[ -z "$s" ]] && { echo 0; return 0; }
  n=$( { b64url_decode "$s" | wc -c | tr -d '[:space:]'; } 2>/dev/null || echo 0 )
  echo "${n:-0}"
}

stop_plugin() {
  [[ -n "$PLUGIN_PID" ]] || return 0
  if kill -0 "$PLUGIN_PID" 2>/dev/null; then
    kill "$PLUGIN_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$PLUGIN_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -0 "$PLUGIN_PID" 2>/dev/null && kill -9 "$PLUGIN_PID" 2>/dev/null || true
  fi
  wait "$PLUGIN_PID" 2>/dev/null || true
  PLUGIN_PID=""
  rm -f "$SOCKET"
}

kms_call() {   # kms_call <Method> <json>
  grpcurl -plaintext -proto "$PROTO_FILE" -d "$2" \
          -unix unix://"$SOCKET" "v2.KeyManagementService.$1"
}

# Poll Status until the plugin answers, so we never race the socket.
#
# Records why it gave up in PROBE_ERR. Without that, a client-side failure (a
# broken grpcurl, a bad -proto) is indistinguishable from a plugin that never
# came up, and the caller reports "plugin failed to start" against a plugin
# whose own log says it is serving happily.
PROBE_ERR=""
wait_until_ready() {
  local deadline=$(( SECONDS + STARTUP_TIMEOUT ))
  PROBE_ERR=""
  while (( SECONDS < deadline )); do
    if [[ -S "$SOCKET" ]]; then
      if PROBE_ERR=$(kms_call Status '{}' 2>&1 >/dev/null); then
        return 0
      fi
    fi
    if ! kill -0 "$PLUGIN_PID" 2>/dev/null; then   # plugin died during startup
      PROBE_ERR="plugin process exited during startup"
      return 1
    fi
    sleep 0.2
  done
  [[ -n "$PROBE_ERR" ]] || \
    PROBE_ERR="socket $SOCKET never appeared within ${STARTUP_TIMEOUT}s"
  return 1
}

start_plugin() {   # start_plugin <key_label> <family> <hmac_label|""> <logfile>
  local key_label="$1" family="$2" hmac_label="$3" logfile="$4"
  local -a common=(
    --socket        "$SOCKET"
    --p11-lib       "$P11_LIB"
    --p11-label     "$P11_LABEL"
    --p11-pin       "$P11_PIN"
    --p11-key-label "$key_label"
    --algorithm-family "$family"
  )
  [[ -n "$hmac_label" ]] && common+=(--p11-hmac-label "$hmac_label")

  local -a logflags=()
  [[ -n "$LOG_FORMAT" ]] && logflags+=("--log-format=$LOG_FORMAT")
  [[ -n "$LOG_LEVEL"  ]] && logflags+=("--log-level=$LOG_LEVEL")

  # Log flags may be subcommand-local or global depending on the CLI
  # framework. Try after `serve` first, fall back to before it, then
  # remember whichever placement worked for the remaining cases.
  local -a attempts
  if [[ -n "$LOG_FLAG_POSITION" ]]; then
    attempts=("$LOG_FLAG_POSITION")
  else
    attempts=(after before none)
  fi

  local pos
  for pos in "${attempts[@]}"; do
    case "$pos" in
      after)  "$PLUGIN_BIN" serve "${logflags[@]}" "${common[@]}" >"$logfile" 2>&1 & ;;
      before) "$PLUGIN_BIN" "${logflags[@]}" serve "${common[@]}" >"$logfile" 2>&1 & ;;
      none)   "$PLUGIN_BIN" serve "${common[@]}"                  >"$logfile" 2>&1 & ;;
    esac
    PLUGIN_PID=$!
    if wait_until_ready; then
      if [[ -z "$LOG_FLAG_POSITION" ]]; then
        LOG_FLAG_POSITION="$pos"
        [[ "$pos" == "none" ]] && \
          echo "ℹ️  plugin rejected --log-format/--log-level; continuing without them" >&2
      fi
      return 0
    fi
    cp "$logfile" "$logfile.failed-$pos" 2>/dev/null || true
    stop_plugin
  done
  return 1
}

# --------------------------------------------------------------------------
# Cases: name | key label | algorithm family | hmac label
# --------------------------------------------------------------------------
CASES=(
  "01-aes-gcm|dev-aes-gcm-kek|aes-gcm|"
  "02-aes-cbc-hmac|dev-aes-cbc-kek|aes-cbc|dev-hmac-sha256"
  "03-rsa-oaep-2048|dev-rsa-2048-oaep|rsa-oaep|"
  "04-rsa-oaep-3072|dev-rsa-3072-oaep|rsa-oaep|"
  "05-rsa-oaep-4096|dev-rsa-4096-oaep|rsa-oaep|"
  "06-ml-kem-512|dev-ml-kem-512|ml-kem|"
  "07-ml-kem-768|dev-ml-kem-768|ml-kem|"
  "08-ml-kem-1024|dev-ml-kem-1024|ml-kem|"
)

PLAINTEXT_B64=$(printf '%s' "$PLAINTEXT" | base64 -w 0)
FAILED=()

# Column widths for aligned progress output. The "(family / key-label)"
# descriptor varies in width, so pad it to the widest of the selected cases.
NAME_W=0
DESC_W=0
for entry in "${CASES[@]}"; do
  IFS='|' read -r _n _kl _f _h <<<"$entry"
  if [[ -n "$ONLY" && ! "$_n" =~ $ONLY ]]; then continue; fi
  _d="($_f / $_kl)"
  if (( ${#_n} > NAME_W )); then NAME_W=${#_n}; fi
  if (( ${#_d} > DESC_W )); then DESC_W=${#_d}; fi
done
unset _n _kl _f _h _d

echo "🔐 KMS v2 JWE sample collection"
echo "   token=$P11_LABEL  module=$P11_LIB"
echo "   plaintext=${#PLAINTEXT} B  limit=${LIMIT} B  out=$OUT_DIR"
echo "   plugin logs: format=${LOG_FORMAT:-default} level=${LOG_LEVEL:-default}"
echo ""

# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
for entry in "${CASES[@]}"; do
  IFS='|' read -r NAME KEY_LABEL FAMILY HMAC_LABEL <<<"$entry"
  [[ -n "$ONLY" && ! "$NAME" =~ $ONLY ]] && continue

  CASE_DIR="$OUT_DIR/$NAME"
  mkdir -p "$CASE_DIR"
  LOG="$CASE_DIR/plugin.log"

  printf '▶️  %-*s  %-*s ... ' "$NAME_W" "$NAME" "$DESC_W" "($FAMILY / $KEY_LABEL)"

  if ! start_plugin "$KEY_LABEL" "$FAMILY" "$HMAC_LABEL" "$LOG"; then
    echo "❌ plugin not reachable"
    echo "     ↳ ${PROBE_ERR:-unknown failure}" >&2
    echo "     ↳ plugin log: $LOG" >&2
    stop_plugin
    FAILED+=("$NAME")
    jq -n --arg case "$NAME" \
          --arg reason "plugin not reachable: ${PROBE_ERR:-unknown failure}" \
      '{case:$case, ok:false, reason:$reason}' >"$CASE_DIR/sizes.json"
    $KEEP_GOING && continue || exit 1
  fi

  # ---- 1. Status -------------------------------------------------------
  STATUS_RESPONSE=$(kms_call Status '{}')
  printf '%s' "$STATUS_RESPONSE" >"$CASE_DIR/status-response.raw.json"
  echo "$STATUS_RESPONSE" | jq . >"$CASE_DIR/status-response.json"
  STATUS_KEY_ID=$(jq -r '.keyId // .key_id // ""' <<<"$STATUS_RESPONSE" 2>/dev/null || echo "")
  KEY_ID="$STATUS_KEY_ID"

  # ---- 2. Encrypt ------------------------------------------------------
  ENCRYPT_REQUEST=$(jq -nc --arg pt "$PLAINTEXT_B64" --arg uid "sample-enc-$NAME" \
    '{plaintext:$pt, uid:$uid}')
  echo "$ENCRYPT_REQUEST" | jq . >"$CASE_DIR/encrypt-request.json"

  if ! ENCRYPT_RESPONSE=$(kms_call Encrypt "$ENCRYPT_REQUEST" 2>"$CASE_DIR/encrypt.err"); then
    echo "❌ Encrypt failed (see $CASE_DIR/encrypt.err)"
    stop_plugin; FAILED+=("$NAME")
    jq -n --arg case "$NAME" --arg reason "encrypt failed" \
      '{case:$case, ok:false, reason:$reason}' >"$CASE_DIR/sizes.json"
    $KEEP_GOING && continue || exit 1
  fi
  printf '%s' "$ENCRYPT_RESPONSE" >"$CASE_DIR/encrypt-response.raw.json"
  echo "$ENCRYPT_RESPONSE" | jq . >"$CASE_DIR/encrypt-response.json"

  CIPHERTEXT_B64=$(jq -r '.ciphertext // ""' <<<"$ENCRYPT_RESPONSE" 2>/dev/null || echo "")
  ENC_KEY_ID=$(jq -r '.keyId // .key_id // empty' <<<"$ENCRYPT_RESPONSE" 2>/dev/null || echo "")
  [[ -n "$ENC_KEY_ID" ]] && KEY_ID="$ENC_KEY_ID"

  # ---- 3. Decrypt (echo annotations back, per the KMS v2 contract) ------
  DECRYPT_REQUEST=$(jq -nc \
    --argjson enc "$ENCRYPT_RESPONSE" \
    --arg uid "sample-dec-$NAME" \
    --arg kid "$KEY_ID" \
    '{ciphertext: $enc.ciphertext, uid: $uid, key_id: $kid}
     + (if ($enc.annotations // {}) == {} then {} else {annotations: $enc.annotations} end)')
  printf '%s' "$DECRYPT_REQUEST" >"$CASE_DIR/decrypt-request.raw.json"
  echo "$DECRYPT_REQUEST" | jq . >"$CASE_DIR/decrypt-request.json"

  if ! DECRYPT_RESPONSE=$(kms_call Decrypt "$DECRYPT_REQUEST" 2>"$CASE_DIR/decrypt.err"); then
    echo "❌ Decrypt failed (see $CASE_DIR/decrypt.err)"
    stop_plugin; FAILED+=("$NAME")
    jq -n --arg case "$NAME" --arg reason "decrypt failed" \
      '{case:$case, ok:false, reason:$reason}' >"$CASE_DIR/sizes.json"
    $KEEP_GOING && continue || exit 1
  fi
  printf '%s' "$DECRYPT_RESPONSE" >"$CASE_DIR/decrypt-response.raw.json"
  echo "$DECRYPT_RESPONSE" | jq . >"$CASE_DIR/decrypt-response.json"

  ROUNDTRIP_OK=false
  [[ "$(jq -r '.plaintext' <<<"$DECRYPT_RESPONSE")" == "$PLAINTEXT_B64" ]] && ROUNDTRIP_OK=true

  stop_plugin

  # ---- 4. Dissect the envelope ------------------------------------------
  # EncryptResponse.ciphertext is protobuf `bytes`, so grpcurl renders it as
  # base64. For aes-gcm/aes-cbc/rsa-oaep it's a JWE Compact Serialization;
  # for ml-kem it's a flat binary envelope (nonce || AES-256-GCM-sealed seed)
  # with the KEM ciphertext carried separately in an annotation — there is no
  # JWE to dissect for that case. Branch on the algorithm-family annotation
  # the plugin actually returned (not $FAMILY, what we asked it to run as),
  # so this reports what was actually produced.
  ALGO_FAMILY_ANNOT_B64=$(jq -r '(.annotations // {})["algorithm-family.k8s-kms-plugin.keysealer.eclipse.org"] // empty' <<<"$ENCRYPT_RESPONSE" 2>/dev/null || true)
  ALGO_FAMILY_ANNOT=$(b64url_decode "$ALGO_FAMILY_ANNOT_B64")

  # Decode to a file and measure with `wc -c`. The ml-kem envelope is raw binary,
  # so measuring it as ${#ENVELOPE} undercounted it (stripped trailing newlines,
  # truncation at the first NUL) and disagreed with the plugin's own
  # ciphertextLen — and envelope.bin was written corrupted for the same reason.
  ENVELOPE_FILE="$CASE_DIR/.envelope.tmp"
  b64url_decode_to_file "$CIPHERTEXT_B64" "$ENVELOPE_FILE"
  # kept as the "jwe_compact_bytes" field below for report continuity
  JWE_LEN=$(wc -c <"$ENVELOPE_FILE" | tr -d '[:space:]')

  if [[ "$ALGO_FAMILY_ANNOT" == "ml-kem" ]]; then
    mv -f "$ENVELOPE_FILE" "$CASE_DIR/envelope.bin"
    rm -f "$CASE_DIR/jwe.compact.txt" "$CASE_DIR/jwe.protected-header.json"

    ALG="$KEY_LABEL"
    ENC="AES-256-GCM (binary envelope, not JWE)"
    HEADER_JSON="{}"
    SEG_HDR="" SEG_EKEY="" SEG_IV="" SEG_CT="" SEG_TAG=""

    KEMCT_B64=$(jq -r '(.annotations // {})["kem-ct.k8s-kms-plugin.keysealer.eclipse.org"] // empty' <<<"$ENCRYPT_RESPONSE" 2>/dev/null || true)
    CRYPTOGRAM_RAW=$(b64url_len "$KEMCT_B64")
    CRYPTOGRAM_SRC="annotations.kem-ct"
    ENCODING_FACTOR="1.000"   # raw protobuf bytes on the actual wire — no JWE base64 layering
    CRYPTOGRAM_ON_WIRE=$CRYPTOGRAM_RAW

    # The cryptogram no longer lives inside ciphertext at all (that's the whole
    # point of the split), so "framing" here is just the AEAD overhead — the
    # nonce + GCM tag wrapped around the DEK seed — not "ciphertext minus cryptogram".
    FRAMING=$(( JWE_LEN - ${#PLAINTEXT} ))
  else
    mv -f "$ENVELOPE_FILE" "$CASE_DIR/jwe.compact.txt"
    # Safe to hold in a variable: a JWE Compact Serialization is base64url + '.'
    ENVELOPE=$(cat "$CASE_DIR/jwe.compact.txt")

    IFS='.' read -r SEG_HDR SEG_EKEY SEG_IV SEG_CT SEG_TAG <<<"$ENVELOPE"

    HEADER_JSON=$(b64url_decode "$SEG_HDR")
    printf '%s' "$HEADER_JSON" | jq . >"$CASE_DIR/jwe.protected-header.json" 2>/dev/null \
      || printf '%s' "$HEADER_JSON" >"$CASE_DIR/jwe.protected-header.json"

    ALG=$(jq -r '.alg // "?"' <<<"$HEADER_JSON" 2>/dev/null || echo "?")
    ENC=$(jq -r '.enc // "?"' <<<"$HEADER_JSON" 2>/dev/null || echo "?")

    # Locate the asymmetric cryptogram: the JWE Encrypted Key segment — the
    # only shape any currently-supported classical family produces. ML-KEM
    # never reaches this branch, so there is no `ek`/`kem-ct` header case here
    # any more.
    if [[ -n "${SEG_EKEY:-}" ]]; then
      CRYPTOGRAM_RAW=$(b64url_len "$SEG_EKEY")
      CRYPTOGRAM_SRC="jwe.encrypted-key"
      ENCODING_FACTOR=$(awk -v r="$CRYPTOGRAM_RAW" -v w="${#SEG_EKEY}" 'BEGIN{if(r>0) printf "%.3f", w/r; else print "0"}')
      CRYPTOGRAM_ON_WIRE=${#SEG_EKEY}
    else
      CRYPTOGRAM_RAW=0
      CRYPTOGRAM_SRC="none (direct)"
      ENCODING_FACTOR="0"
      CRYPTOGRAM_ON_WIRE=0
    fi

    FRAMING=$(( JWE_LEN - CRYPTOGRAM_ON_WIRE ))
  fi

  PCT=$(awk -v j="$JWE_LEN" -v l="$LIMIT" 'BEGIN{printf "%d", (100*j/l)+0.5}')
  OVER=$(( JWE_LEN - LIMIT ))
  (( OVER < 0 )) && OVER=0

  ANNOT_BYTES=$(jq -r '
    (.annotations // {}) | to_entries
    | map((.key|length) + ((.value // "")|length)) | add // 0' <<<"$ENCRYPT_RESPONSE" 2>/dev/null || echo 0)
  ANNOT_BYTES=${ANNOT_BYTES:-0}

  STATUS_KEY_ID_LEN=${#STATUS_KEY_ID}
  KEY_ID_LEN=${#KEY_ID}

  # Independent cross-check: the plugin logs its own ciphertextLen. Tolerates
  # `ciphertextLen=2093`, `"ciphertextLen":2093` and `ciphertextLen: 2093`.
  # The trailing `|| true` matters: grep exits 1 on no-match, and with
  # `pipefail` + `set -e` that would abort the whole script.
  PLUGIN_LEN=$(grep -oE '"?ciphertextLen"?[[:space:]]*[=:][[:space:]]*[0-9]+' "$LOG" 2>/dev/null \
                 | tail -1 | grep -oE '[0-9]+$' || true)
  if [[ -n "$PLUGIN_LEN" ]]; then
    if [[ "$PLUGIN_LEN" == "$JWE_LEN" ]]; then
      CROSS_CHECK="match"
    else
      CROSS_CHECK="MISMATCH"
      FAILED+=("$NAME (plugin reported ${PLUGIN_LEN} B, measured ${JWE_LEN} B)")
    fi
  else
    PLUGIN_LEN=0
    CROSS_CHECK="unavailable"
  fi

  jq -n \
    --arg  case            "$NAME" \
    --arg  family          "$FAMILY" \
    --arg  key_label       "$KEY_LABEL" \
    --arg  alg             "$ALG" \
    --arg  enc             "$ENC" \
    --arg  cryptogram_src  "$CRYPTOGRAM_SRC" \
    --arg  encoding_factor "$ENCODING_FACTOR" \
    --argjson ok           "$ROUNDTRIP_OK" \
    --argjson jwe_len      "$JWE_LEN" \
    --argjson hdr_b64      "${#SEG_HDR}" \
    --argjson hdr_raw      "${#HEADER_JSON}" \
    --argjson ekey_b64     "${#SEG_EKEY}" \
    --argjson iv_b64       "${#SEG_IV}" \
    --argjson ct_b64       "${#SEG_CT}" \
    --argjson tag_b64      "${#SEG_TAG}" \
    --argjson cg_raw       "$CRYPTOGRAM_RAW" \
    --argjson cg_wire      "$CRYPTOGRAM_ON_WIRE" \
    --argjson framing      "$FRAMING" \
    --argjson limit        "$LIMIT" \
    --argjson pct          "$PCT" \
    --argjson over         "$OVER" \
    --argjson annot        "$ANNOT_BYTES" \
    --arg  key_id          "$KEY_ID" \
    --argjson key_id_bytes "$KEY_ID_LEN" \
    --argjson status_key_id_bytes "$STATUS_KEY_ID_LEN" \
    --argjson plugin_len   "$PLUGIN_LEN" \
    --arg  cross_check     "$CROSS_CHECK" \
    --arg  log_format      "$LOG_FORMAT" \
    --arg  log_level       "$LOG_LEVEL" \
    '{
       case: $case, ok: $ok, family: $family, key_label: $key_label,
       alg: $alg, enc: $enc,
       key_id: $key_id,
       key_id_bytes: $key_id_bytes,
       status_key_id_bytes: $status_key_id_bytes,
       plugin_reported_ciphertext_bytes: $plugin_len,
       cross_check: $cross_check,
       log: { format: $log_format, level: $log_level },
       jwe_compact_bytes: $jwe_len,
       segments: {
         protected_header_b64: $hdr_b64,
         protected_header_json: $hdr_raw,
         encrypted_key_b64: $ekey_b64,
         iv_b64: $iv_b64,
         ciphertext_b64: $ct_b64,
         tag_b64: $tag_b64
       },
       cryptogram: {
         source: $cryptogram_src,
         raw_bytes: $cg_raw,
         on_wire_bytes: $cg_wire,
         encoding_expansion: ($encoding_factor|tonumber)
       },
       residual_framing_bytes: $framing,
       kms_annotations_bytes: $annot,
       limit_bytes: $limit,
       pct_of_limit: $pct,
       over_by_bytes: $over
     }' >"$CASE_DIR/sizes.json"

  if $ROUNDTRIP_OK; then
    case "$CROSS_CHECK" in
      match)       XC="  ✓ plugin agrees" ;;
      MISMATCH)    XC="  ✗ plugin says ${PLUGIN_LEN} B" ;;
      *)           XC="" ;;
    esac
    printf '✅ %-12s JWE=%5s B (%3s%% of limit)%s\n' "$ALG" "$JWE_LEN" "$PCT" "$XC"
  else
    printf '⚠️  %-12s JWE=%5s B — ROUND-TRIP MISMATCH\n' "$ALG" "$JWE_LEN"
    FAILED+=("$NAME (roundtrip mismatch)")
  fi
done

# --------------------------------------------------------------------------
# Aggregate report
# --------------------------------------------------------------------------
shopt -s nullglob
SIZE_FILES=( "$OUT_DIR"/*/sizes.json )
shopt -u nullglob
if (( ${#SIZE_FILES[@]} == 0 )); then
  echo "" >&2
  echo "⚠️  No cases produced results — nothing to summarise." >&2
  exit 1
fi
jq -s 'map(select(type == "object"))' "${SIZE_FILES[@]}" >"$OUT_DIR/summary.json"

jq -r '
  ["case","alg","enc","cryptogram_raw_bytes","jwe_compact_bytes",
   "pct_of_limit","over_by_bytes","encoding_expansion","residual_framing_bytes",
   "key_id","key_id_bytes","kms_annotations_bytes"],
  (.[] | select(.ok == true) |
    [.case, .alg, .enc, .cryptogram.raw_bytes, .jwe_compact_bytes,
     .pct_of_limit, .over_by_bytes, .cryptogram.encoding_expansion,
     .residual_framing_bytes, .key_id, .key_id_bytes, .kms_annotations_bytes])
  | @csv' "$OUT_DIR/summary.json" >"$OUT_DIR/summary.csv"

{
  echo "# KMS v2 \`EncryptResponse.ciphertext\` size by wrap mechanism"
  echo
  echo "Payload: ${#PLAINTEXT} B. Limit assumed: ${LIMIT} B."
  echo "Generated by \`collect-jwe-samples.sh\` against a create-dev-token SoftHSM store."
  echo
  echo "| Wrap mechanism | \`alg\` | Raw cryptogram | JWE compact | % of limit | Over by | Plugin log |"
  echo "|---|---|---:|---:|---:|---:|---|"
  jq -r '
    .[] | select(.ok == true) |
    "| \(.case) | `\(.alg)` | \(if .cryptogram.raw_bytes > 0 then "\(.cryptogram.raw_bytes) B" else "—" end) " +
    "| \(.jwe_compact_bytes) B | \(.pct_of_limit)% " +
    "| \(if .over_by_bytes > 0 then "+\(.over_by_bytes) B" else "—" end) " +
    "| \(if .cross_check == "match" then "✓ \(.plugin_reported_ciphertext_bytes) B"
         elif .cross_check == "MISMATCH" then "✗ \(.plugin_reported_ciphertext_bytes) B"
         else "—" end) |"
  ' "$OUT_DIR/summary.json"
  echo
  echo "The *Plugin log* column is the \`ciphertextLen\` the plugin itself reported,"
  echo "parsed from its structured logs — an independent confirmation of the"
  echo "\`EncryptResponse.ciphertext\` length measured from the gRPC response."
  echo
  echo "## Encoding cost of the cryptogram"
  echo
  echo "| Case | Carrier | Raw | On wire | Expansion | Residual framing |"
  echo "|---|---|---:|---:|---:|---:|"
  jq -r '
    .[] | select(.ok == true and .cryptogram.raw_bytes > 0) |
    "| \(.case) | \(.cryptogram.source) | \(.cryptogram.raw_bytes) B | \(.cryptogram.on_wire_bytes) B " +
    "| \(.cryptogram.encoding_expansion)× | \(.residual_framing_bytes) B |"
  ' "$OUT_DIR/summary.json"
  echo
  echo "A cryptogram carried in the JWE Encrypted Key segment (rsa-oaep) is"
  echo "base64url-encoded once (≈1.333×). ML-KEM's cryptogram — the raw"
  echo "encapsulation ciphertext — travels in the \`kem-ct\` annotation as plain"
  echo "protobuf \`bytes\`, so it has no encoding expansion at all (1.000×); an"
  echo "earlier JWE-based ML-KEM design carried it base64url-encoded inside the"
  echo "protected header (double-encoded, (4/3)² ≈ 1.778×) and was dropped"
  echo "specifically because that pushed \`ciphertext\` over the KMS v2 1 kB limit."
  echo
  echo "## Other size-constrained KMS v2 fields"
  echo
  echo "\`key_id\` carries its own < 1 kB ceiling (\`StatusResponse.key_id\` and"
  echo "\`EncryptResponse.key_id\`), and annotation keys + values are bounded at 32 kB."
  echo
  echo "| Case | \`key_id\` | \`key_id\` bytes | % of ${LIMIT} B | Annotations bytes | % of 32 kB |"
  echo "|---|---|---:|---:|---:|---:|"
  jq -r --argjson limit "$LIMIT" '
    .[] | select(.ok == true) |
    "| \(.case) | `\(.key_id)` | \(.key_id_bytes) B " +
    "| \((.key_id_bytes * 100 / $limit) | floor)% " +
    "| \(.kms_annotations_bytes) B " +
    "| \((.kms_annotations_bytes * 100 / 32768) | floor)% |"
  ' "$OUT_DIR/summary.json"
  echo
  echo "Unlike \`ciphertext\`, these fields are not under pressure from the"
  echo "post-quantum transition: \`key_id\` is a plugin-chosen identifier whose"
  echo "length is independent of the KEK algorithm."
} >"$OUT_DIR/summary.md"

# --------------------------------------------------------------------------
# Consolidated KMS v2 message document (ready to paste into an issue)
# --------------------------------------------------------------------------
if $FULL_CIPHERTEXT; then
  ELIDE_FILTER='.'
else
  # Shorten long base64 blobs so the document stays readable; the per-case
  # JSON files always keep the full values.
  ELIDE_FILTER='def el: if (type=="string" and (length>96))
                        then (.[0:32] + "…<" + (length|tostring) + " chars elided>… " + .[-16:])
                        else . end; walk(el)'
fi

{
  echo "# KMS v2 message samples"
  echo
  echo "\`EncryptResponse\` and \`DecryptRequest\` messages captured from"
  echo "\`k8s-kms-plugin\` for each supported KEK algorithm, as rendered by"
  echo "\`grpcurl\` against the KMS v2 gRPC API (\`api.proto\` ${PROTO_TAG})."
  echo
  echo "Payload: ${#PLAINTEXT} B. Assumed \`EncryptResponse.ciphertext\` limit: ${LIMIT} B."
  if $FULL_CIPHERTEXT; then
    echo "Values are shown in full."
  else
    echo "Long base64 values are elided for readability — the complete messages are in"
    echo "\`<case>/encrypt-response.json\` and \`<case>/decrypt-request.json\`."
  fi
  echo
  echo "> Note: \`EncryptResponse.ciphertext\` is protobuf \`bytes\`, so grpcurl renders"
  echo "> it base64-encoded. Decoding it once yields the JWE Compact Serialization for"
  echo "> aes-gcm/aes-cbc/rsa-oaep — ml-kem is a plain binary envelope instead, with the"
  echo "> KEM ciphertext carried separately in the \`kem-ct\` annotation."
  echo

  for entry in "${CASES[@]}"; do
    IFS='|' read -r NAME KEY_LABEL FAMILY HMAC_LABEL <<<"$entry"
    CASE_DIR="$OUT_DIR/$NAME"
    [[ -f "$CASE_DIR/encrypt-response.json" ]] || continue

    CASE_ALG=$(jq -r '.alg // "?"'  "$CASE_DIR/sizes.json" 2>/dev/null || echo "?")
    CASE_LEN=$(jq -r '.jwe_compact_bytes // 0' "$CASE_DIR/sizes.json" 2>/dev/null || echo 0)
    CASE_PCT=$(jq -r '.pct_of_limit // 0'      "$CASE_DIR/sizes.json" 2>/dev/null || echo 0)
    CASE_KID=$(jq -r '.key_id_bytes // 0'      "$CASE_DIR/sizes.json" 2>/dev/null || echo 0)

    echo "## $NAME"
    echo
    echo "- Algorithm family: \`$FAMILY\` (PKCS#11 key \`$KEY_LABEL\`)"
    if [[ "$FAMILY" == "ml-kem" ]]; then
      echo "- ML-KEM key: \`$CASE_ALG\`"
    else
      echo "- JWE \`alg\`: \`$CASE_ALG\`"
    fi
    echo "- \`EncryptResponse.ciphertext\`: **${CASE_LEN} B** (${CASE_PCT}% of the ${LIMIT} B limit)"
    echo "- \`key_id\`: ${CASE_KID} B (own ${LIMIT} B limit)"
    echo
    echo "### StatusResponse"
    echo
    echo '```json'
    jq "$ELIDE_FILTER" "$CASE_DIR/status-response.json"
    echo '```'
    echo
    if [[ "$FAMILY" == "ml-kem" ]]; then
      echo "### ML-KEM envelope (no JWE)"
      echo
      echo "The KEM ciphertext travels in the \`kem-ct\` annotation, not inside"
      echo "\`ciphertext\` — see the \`cryptogram\` / \`kms_annotations_bytes\` fields below."
      echo
      echo '```json'
      jq "$ELIDE_FILTER" "$CASE_DIR/sizes.json"
      echo '```'
    else
      echo "### JWE protected header"
      echo
      echo '```json'
      cat "$CASE_DIR/jwe.protected-header.json" 2>/dev/null \
        | jq "$ELIDE_FILTER" 2>/dev/null \
        || cat "$CASE_DIR/jwe.protected-header.json"
      echo '```'
    fi
    echo
    echo "### EncryptResponse"
    echo
    echo '```json'
    jq "$ELIDE_FILTER" "$CASE_DIR/encrypt-response.json"
    echo '```'
    echo
    echo "### DecryptRequest"
    echo
    echo '```json'
    jq "$ELIDE_FILTER" "$CASE_DIR/decrypt-request.json"
    echo '```'
    echo
  done
} >"$OUT_DIR/messages.md"

echo ""
echo "📄 Reports"
echo "   $OUT_DIR/summary.md      table of sizes"
echo "   $OUT_DIR/summary.csv     same data, machine-readable"
echo "   $OUT_DIR/summary.json    same data, plus per-segment breakdown"
echo "   $OUT_DIR/messages.md     all EncryptResponse / DecryptRequest JSON, ready to paste"
echo ""
echo "📂 Per-case messages (full, un-elided)"
for entry in "${CASES[@]}"; do
  IFS='|' read -r NAME _ _ _ <<<"$entry"
  [[ -f "$OUT_DIR/$NAME/encrypt-response.json" ]] || continue
  echo "   $OUT_DIR/$NAME/"
  echo "      status-response.json      encrypt-request.json"
  echo "      encrypt-response.json     decrypt-request.json"
  echo "      decrypt-response.json     jwe.protected-header.json"
  echo "      jwe.compact.txt           sizes.json"
  echo "      (*.raw.json = verbatim grpcurl output, unformatted)"
done

# --------------------------------------------------------------------------
# Archive — one file to attach to an issue
# --------------------------------------------------------------------------
# Built even when cases failed: a partial tree plus its plugin.log is exactly
# what a bug report needs.
#
# `zip` merges into an existing archive rather than replacing it, so a stale
# jwe-samples.zip has to be removed first — otherwise cases dropped since the
# last run (or narrowed away by --only) would linger inside it.
#
# Archiving from the parent directory keeps the paths inside relative
# ("jwe-samples/01-aes-gcm/..."), instead of burying them under the absolute
# path when --out is absolute.
if [[ -n "$ARCHIVER" ]]; then
  ARCHIVE="${OUT_DIR%/}.$ARCHIVE_FORMAT"
  ARCHIVE_PARENT="$(dirname "${OUT_DIR%/}")"
  ARCHIVE_BASE="$(basename "${OUT_DIR%/}")"
  ARCHIVE_NAME="$ARCHIVE_BASE.$ARCHIVE_FORMAT"
  rm -f "$ARCHIVE"
  case "$ARCHIVER" in
    zip)      ( cd "$ARCHIVE_PARENT" && zip -qr "$ARCHIVE_NAME" "$ARCHIVE_BASE" ) ;;
    bsdtar)   ( cd "$ARCHIVE_PARENT" && bsdtar --format=zip -cf "$ARCHIVE_NAME" "$ARCHIVE_BASE" ) ;;
    tar)      ( cd "$ARCHIVE_PARENT" && tar -czf "$ARCHIVE_NAME" "$ARCHIVE_BASE" ) ;;
    tar-zstd) ( cd "$ARCHIVE_PARENT" && tar --zstd -cf "$ARCHIVE_NAME" "$ARCHIVE_BASE" ) ;;
  esac
  echo ""
  echo "🗜️  Archive  ($ARCHIVE_FORMAT via $ARCHIVER)"
  echo "   $ARCHIVE  ($(du -h "$ARCHIVE" | cut -f1))"
  # `&& ... || true`: a bare `&&` as the last statement would make the whole
  # `if` block exit non-zero for every other format, which `set -e` treats as fatal.
  [[ "$ARCHIVE_FORMAT" == "tar.zst" ]] && \
    echo "   ⚠️  GitHub rejects .zst attachments — use --format zip or tgz for an issue" || true
fi

if (( ${#FAILED[@]} > 0 )); then
  echo ""
  echo "⚠️  Cases with problems: ${FAILED[*]}"
  echo "   (ML-KEM cases require SoftHSMv3; they are skipped on SoftHSMv2.)"
  exit 1
fi