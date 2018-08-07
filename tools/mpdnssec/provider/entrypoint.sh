#!/bin/sh

set -e -x

# generate zone signing key
keyname=`dnssec-keygen -a 13 example.test.`
mv ${keyname}.key zsk.key
mv ${keyname}.private zsk.private

# create the signatures for the first time
cp zsk.key dnskeys.db
./sign.sh

# run knot on the background
knotd -c knot.conf &

# run provider
exec ./provider
