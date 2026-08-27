#!/bin/sh
set -e
# safe.directory first — git refuses mounted-repo operations otherwise and the
# error is confusing cold (spec §7.3).
git config --global --add safe.directory /workspace
# Scratch for checkout-index staging and SARIF output — the container holds no
# unique state, so restarts are free (engine-spec §6.1).
mkdir -p /reports /scan
exec "$@"
