#!/usr/bin/env bash
mkdir -p /var/lib/softhsm/tokens/
softhsm2-util --init-token --slot 0 --label default --so-pin changeme --pin changeme
/k8s-kms-plugin serve
#  Wait for a few seconds to let logs settle.
sleep 2s