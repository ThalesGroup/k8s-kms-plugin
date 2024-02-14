#!/bin/bash -eu
# Injects the driver plugin into a shared volume.
# See README.md for background.

destdir=${1:-}

err_exit() {
  >&2 echo "E: $*"
  exit 1
}

if [ ! -n "${destdir}" ]
then
  err_exit "usage: $0 directory"
fi

if [ ! -d "${destdir}" ]
then
  err_exit "${destdir} is not a directory"
fi

cp -a -v /opt/cvclient "${destdir}"
