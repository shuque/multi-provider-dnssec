#!/bin/sh

set -x -e

./sign.sh && knotc -c knot.conf zone-reload example.test.
