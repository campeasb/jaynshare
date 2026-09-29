#!/usr/bin/env bash
# Cross-build the five targets, package and sign the release set, push the OCI
# index, and publish a GitHub release.
#
# Usage: tools/release/publish.sh <semver> --key <seed file> \
#            --image-repository <repo> [--release-notes <file>]
#
# The signing seed must sit outside the repository and never enters a
# build workspace or a log; only its path is passed to build.py.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"

die() { echo "publish.sh: $1" >&2; exit 2; }
usage="usage: tools/release/publish.sh <semver> --key <seed file> --image-repository <repo> [--release-notes <file>]"

version=${1:-}
shift || true
[ -n "$version" ] || die "$usage"
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?'
printf '%s' "$version" | grep -Eqx "$semver" ||
    die "$version is not a SemVer 2.0.0 version"

key=
repository=
notes=
while [ $# -gt 0 ]; do
    case $1 in
    --key)
        [ $# -ge 2 ] || die "$usage"
        key=$2
        shift 2
        ;;
    --image-repository)
        [ $# -ge 2 ] || die "$usage"
        repository=$2
        shift 2
        ;;
    --release-notes)
        [ $# -ge 2 ] || die "$usage"
        notes=$2
        shift 2
        ;;
    *) die "$usage" ;;
esac
done
[ -n "$key" ] || die "$usage"
[ -n "$repository" ] || die "$usage"

# The seed lives outside the repository.
case $key in
    "$REPO"/*) die "--key <seed> must be outside the repository" ;;
esac
case $(cd "$(dirname "$key")" && pwd)/ in
    "$REPO"/*) die "--key <seed> must be outside the repository" ;;
esac
[ -f "$key" ] || die "--key $key: no such seed file"

command -v gh >/dev/null || die "gh is not on PATH (https://cli.github.com)"
command -v python3 >/dev/null || die "python3 is not on PATH"
[ -f tools/release/build.py ] || die "tools/release/build.py is missing"

# The work happens outside the tree; cross.sh refuses a dirty tracked tree
# and stamps HEAD's commit into the binaries itself.
work=$(mktemp -d /tmp/jaynshare-publish.XXXXXX)
trap 'rm -rf "$work"' EXIT
bins=$work/bins
out=$work/out

echo "==> cross.sh: the five binaries into $bins"
# JAYNSHARE_CROSS: the acceptance scenario's fake (not set by an operator).
cross=${JAYNSHARE_CROSS:-tools/release/cross.sh}
"$cross" --out "$bins" | tee "$work/bins.log"

echo "==> build.py: the release set into $out"
commit=$(git rev-parse HEAD)
# shellcheck disable=SC2086
python3 tools/release/build.py \
    --version "$version" \
    --commit "$commit" \
    --key "$key" \
    --out "$out" \
    --image-repository "$repository" \
    --image-out "$work/image" \
    --image-push \
    $(sed -n 's/^--bin /--bin /p' "$work/bins.log")

echo "==> gh release create v$version"
assets=("$out"/*)
notes_args=()
if [ -n "$notes" ]; then
    notes_args=(--notes-file "$notes")
else
    notes_args=(--generate-notes)
fi
gh release create "v$version" "${assets[@]}" "${notes_args[@]}" \
    --title "jaynshare $version" \
    --target "$commit"

echo "published v$version: $(git rev-parse HEAD)"
