# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT
#
# shellcheck shell=bash
#
# resolve_api_proto — locate the KMS v2 api.proto that matches the k8s.io/kms version this
# repository builds against, and export it for grpcurl.
#
# Sets two variables:
#   API_PROTO          absolute path to api.proto, for `grpcurl -proto "$API_PROTO"`
#   API_PROTO_VERSION  the k8s.io/kms version it came from, e.g. v0.36.3
#
# Why not a hardcoded URL: grpcurl uses this file as the service definition, so a proto from a
# different release than the plugin implements makes the script exercise a contract the binary does
# not serve — quietly, for every field that still happens to line up. These scripts pinned v0.34.1
# by hand while go.mod had moved on to v0.36.3, which is exactly the drift this avoids.
#
# Resolution order matches test/e2e/main_test.go:
#
#   1. The Go module cache, located with `go list -m`. Authoritative — it is the very copy the
#      plugin compiles against — needs no network, honours any replace directive, and cannot drift.
#   2. An HTTPS fetch from the kubernetes/kms tag matching the resolved version, for a checkout
#      with no populated module cache.
#
# Nothing is written into the repository: the cached file is read in place and a download goes to a
# temp file. The git-ignored scripts/grpcurl/api.proto some older instructions mention is no longer
# used or created.

# repo_root prints the repository root, so `go list -m` runs inside the module regardless of the
# directory the caller invoked the script from.
repo_root() {
  git rev-parse --show-toplevel 2>/dev/null && return 0
  # Fall back to this file's location when git is unavailable (a tarball export, for instance).
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd
}

# kms_version_from_gomod parses the version out of go.mod. Used only when the go tool is not
# runnable; `go list -m` is preferred because it resolves replace directives and module graph
# selection rather than trusting the literal require line.
kms_version_from_gomod() {
  local gomod="$1/go.mod"
  [[ -r "$gomod" ]] || return 1
  awk '$1 == "k8s.io/kms" { print $2; found = 1; exit } END { exit !found }' "$gomod"
}

resolve_api_proto() {
  local root proto_rel="apis/v2/api.proto"
  root="$(repo_root)"

  local version="" dir=""

  # Escape hatch: pin a version explicitly to test against a release the repo does not build
  # against yet. Skips the module cache, since that only ever holds the selected version.
  if [[ -n "${KMS_PROTO_VERSION:-}" ]]; then
    version="$KMS_PROTO_VERSION"
    echo "ℹ️  KMS_PROTO_VERSION is set — using k8s.io/kms ${version} instead of the version in go.mod" >&2
  elif go version >/dev/null 2>&1; then
    # Tab-separated so an empty Dir (module known but not extracted) still parses.
    local listed
    if listed="$(cd "$root" && go list -m -f '{{.Version}}	{{.Dir}}' k8s.io/kms 2>/dev/null)"; then
      version="${listed%%$'\t'*}"
      dir="${listed#*$'\t'}"
      [[ "$dir" == "$version" ]] && dir=""
    fi
  fi
  [[ -n "$version" ]] || version="$(kms_version_from_gomod "$root")" || {
    echo "resolve_api_proto: cannot determine the k8s.io/kms version" >&2
    echo "  neither 'go list -m k8s.io/kms' nor $root/go.mod could be read" >&2
    return 1
  }

  # 1. Module cache.
  if [[ -n "$dir" && -r "$dir/$proto_rel" ]]; then
    API_PROTO="$dir/$proto_rel"
    API_PROTO_VERSION="$version"
    echo "✅ api.proto: k8s.io/kms ${version} (Go module cache)" >&2
    return 0
  fi

  # 2. Download the matching tag.
  local url="https://raw.githubusercontent.com/kubernetes/kms/refs/tags/${version}/${proto_rel}"
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/k8s-kms-plugin-proto-XXXXXX")"
  echo "⬇️  api.proto not in the module cache, fetching ${url}" >&2
  if ! curl -sSLf -o "$tmp/api.proto" "$url"; then
    rm -rf "$tmp"
    echo "resolve_api_proto: failed to download api.proto for k8s.io/kms ${version}" >&2
    echo "  run 'go mod download k8s.io/kms' to populate the module cache instead" >&2
    return 1
  fi
  # A proxy error page would otherwise surface much later as a confusing grpcurl parse failure.
  if ! grep -q "service KeyManagementService" "$tmp/api.proto"; then
    rm -rf "$tmp"
    echo "resolve_api_proto: ${url} does not look like the KMS v2 api.proto" >&2
    return 1
  fi

  API_PROTO="$tmp/api.proto"
  API_PROTO_VERSION="$version"
  echo "✅ api.proto: k8s.io/kms ${version} (downloaded)" >&2
}
