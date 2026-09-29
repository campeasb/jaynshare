#!/bin/sh
# The macOS client installer: OS-shipped tools only, no
# administrator rights, no PATH edit. It selects the one payload for this
# machine, checks it against SHA256SUMS, and runs that payload's
# `enrol --bundle <dir>` exactly once — the binary verifies the release
# signature and every member digest again, shows the
# facts, asks, and reads the code at its own hidden prompt; this
# script never sees the code.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "install-macos.sh: this installer is for macOS only" >&2; exit 18
fi
major="$(sw_vers -productVersion | cut -d. -f1)"
if [ "$major" -lt 13 ]; then
  echo "install-macos.sh: macOS 13 or later is required" >&2; exit 18
fi
if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ] && [ -z "${JAYNSHARE_TARGET:-}" ]; then
  echo "install-macos.sh: running under Rosetta; set JAYNSHARE_TARGET=macos-x86_64 to install the translated payload on purpose" >&2; exit 18
fi
case "${JAYNSHARE_TARGET:-$(uname -m)}" in
  arm64|aarch64|macos-aarch64) payload="payload/macos-aarch64/jaynshare" ;;
  x86_64|macos-x86_64)         payload="payload/macos-x86_64/jaynshare" ;;
  *) echo "install-macos.sh: unsupported architecture $(uname -m)" >&2; exit 18 ;;
esac

[ -f "$here/$payload" ] || { echo "install-macos.sh: $payload is missing from the bundle" >&2; exit 17; }
expected="$(awk -v m="$payload" '$2 == m { print $1 }' "$here/SHA256SUMS")"
actual="$(shasum -a 256 "$here/$payload" | awk '{ print $1 }')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "install-macos.sh: $payload does not match SHA256SUMS" >&2; exit 17
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/jaynshare-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

cp "$here/$payload" "$tmp/jaynshare" && chmod 700 "$tmp/jaynshare"
# A bundle that came through a browser, mail or chat carries the
# quarantine mark, and Gatekeeper blocks a quarantined executable that has
# no Developer ID notarization. Only this digest-checked copy loses the mark;
# the bundle keeps it, and the copy verifies the release manifest, its
# signature and its sums before anything durable is written.
if xattr -p com.apple.quarantine "$tmp/jaynshare" >/dev/null 2>&1 \
   && ! xattr -d com.apple.quarantine "$tmp/jaynshare" 2>"$tmp/xattr.err"; then
  # A platform refusal is exit 18; the bundle itself is left as it is.
  echo "install-macos.sh: xattr -d com.apple.quarantine $tmp/jaynshare (the staged payload copy) failed: $(head -n 1 "$tmp/xattr.err")" >&2
  exit 18
fi
# Not `exec`: the EXIT trap must remove the payload copy afterwards.
status=0
"$tmp/jaynshare" enrol --bundle "$here" "$@" || status=$?
exit "$status"
