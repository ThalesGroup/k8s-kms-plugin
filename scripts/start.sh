#!/usr/bin/env bash
/usr/sbin/rsyslogd &
mkdir -p /var/lib/softhsm/tokens/
sed -i -e "s/INFO/DEBUG/g" /etc/softhsm2.conf
softhsm2-util --init-token --slot 0 --label default --so-pin changeme --pin changeme
sleep 2s
/k8s-kms-plugin serve
sleep 2ss