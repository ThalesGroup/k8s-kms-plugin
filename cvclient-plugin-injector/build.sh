#!/bin/bash
# This script builds a container image to inject the Thales Luna HSM
# PKCS11 driver and related utilties into a specified target directory.
# See thales-injector/README.md for background.

set -euxo pipefail

script_dir="$(dirname $(readlink -f "$0"))"

fatal() {
  >&2 echo "fatal: $*"
  exit 1
}

verify_checksum() {
  calc_sum="$(sha256sum "$1"|cut -d' ' -f1)"
  expected_sum="${2}"

  if [ "$calc_sum" != "$expected_sum" ]
  then
    fatal "checksum mismatch for ${1}"
  fi
  return 0
}

###
### Obtain package tarball.
###

#Contents of cvclient-bin.tar.gz
cvclient_payload="gs://hsm-cvclient-bin/cvclient-min-10.1-sha256sum@1b2faa327c32a674e395e697d2e7f65c447847ce393b12354a3d82962a76ee87.tar.gz"

cvclient_version="10.1"
cvclient_sha256sum="1b2faa327c32a674e395e697d2e7f65c447847ce393b12354a3d82962a76ee87"
cvclient_path="${script_dir}/cvclient-min.tar.gz"

rm -v -f "${cvclient_path}"

gsutil cp "${cvclient_payload}" "${cvclient_path}"

verify_checksum "${cvclient_path}" "${cvclient_sha256sum}"

###
### Build Image.
###

image_repo="gcr.io/thales-hsm-driver-injector"
image_name="thaleslunahsm-plugin-injector"
image_tag="${cvclient_version}-1" # append local version.

# fully qualified image reference
image_fullname="${image_repo}/${image_name}:${image_tag}"

docker build -t "${image_fullname}" "${script_dir}"
docker push "${image_fullname}"
