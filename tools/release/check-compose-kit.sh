#!/bin/sh
# The release's Compose kit gate: every key and value the
# deployment forbids is absent from compose.yaml in tools/release/compose-kit/.
# Fails on the first hit found.
set -u
cd "$(dirname "$0")/compose-kit" || exit 1

for forbidden in container_name network_mode privileged devices docker.sock \
  0.0.0.0 'published: 0' latest; do
  if grep -q -e "$forbidden" compose.yaml; then
    echo "compose.yaml: forbidden pattern found: $forbidden" >&2
    exit 1
  fi
done
echo "compose.yaml: no forbidden pattern found"
