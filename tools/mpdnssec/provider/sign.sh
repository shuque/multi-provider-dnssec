#!/bin/sh

set -x -e

cat unsigned.db dnskeys.db | \
dnssec-signzone -P -x -o example.test. -O full -f signed.db /dev/stdin zsk
