#!/bin/sh
# Remove this machine's client installation through the installed binary's
# `uninstall` verb; nothing is touched when there is none.
set -eu
bin="$HOME/Library/Application Support/Jaynshare/bin/jaynshare"
[ -x "$bin" ] || { echo "uninstall-macos.sh: no client installation at $bin" >&2; exit 11; }
exec "$bin" uninstall "$@"
