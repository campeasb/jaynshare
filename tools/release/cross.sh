#!/usr/bin/env bash
# Build the five release executables (musl Linux x2, macOS x2, Windows).
# It does not sign, archive or read any key;
# `build.py --bin <target>=<path>` packages what this prints.
set -euo pipefail

TARGETS=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-pc-windows-msvc
)
ALLOWED=" ${TARGETS[*]} "

die2() { echo "$1" >&2; exit 2; }
die3() { echo "$1" >&2; exit 3; }

usage=$(
    cat <<'EOF'
usage: tools/release/cross.sh --out <dir> [--target <triple>]... [--commit <40 hex>] [--allow-dirty]
EOF
)

out=
commit=
allow_dirty=false
want=()

while [ $# -gt 0 ]; do
    case $1 in
    --out)
        [ $# -ge 2 ] || die2 "$usage"
        out=$2
        shift 2
        ;;
    --target)
        [ $# -ge 2 ] || die2 "$usage"
        case " $ALLOWED " in
        *" $2 "*) ;;
        *) die2 "unknown target $2 (expected one of:${ALLOWED% })" ;;
        esac
        want+=("$2")
        shift 2
        ;;
    --commit)
        [ $# -ge 2 ] || die2 "$usage"
        commit=$2
        shift 2
        ;;
    --allow-dirty) allow_dirty=true; shift ;;
    *) die2 "$usage" ;;
    esac
done

[ -n "$out" ] || die2 "$usage"
[ ${#want[@]} -gt 0 ] || want=("${TARGETS[@]}")

if [ -z "$commit" ]; then
    commit=$(git rev-parse HEAD)
fi
[ "$commit" = "$(echo "$commit" | tr -cd '0-9a-f')" ] || die2 "--commit: expected 40 lowercase hex digits"
[ ${#commit} -eq 40 ] || die2 "--commit: expected 40 lowercase hex digits"

if ! $allow_dirty && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    die2 "refusing: the working tree has modified tracked files (use --allow-dirty to override)"
fi

[ "$(uname)" = Darwin ] || APPLE_HOST=false || APPLE_HOST=true
APPLE_HOST=false
[ "$(uname)" = Darwin ] && APPLE_HOST=true

mkdir -p "$out"
out=$(cd "$out" && pwd)

env_no_proxy=(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy JAYNSHARE_COMMIT="$commit")

build_native() {
    local t=$1
    if ! "${env_no_proxy[@]}" cargo build --release --locked --target "$t" --target-dir "target/cross/$t"; then
        die3 "$t: cargo build failed"
    fi
}

build_musl() {
    local t=$1
    local plat
    case $t in
    aarch64-*) plat=linux/arm64 ;;
    x86_64-*) plat=linux/amd64 ;;
    esac
    mkdir -p "target/cross/$t"
    if ! docker run --rm --platform "$plat" \
        -v "$PWD":/src:ro -w /src \
        -v "$PWD/target/cross/$t":/target \
        -v jaynshare-cross-cargo:/usr/local/cargo/registry \
        -e JAYNSHARE_COMMIT="$commit" \
        rust:1.95-alpine sh -c \
        'apk add --no-cache musl-dev >/dev/null && env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy cargo build --release --locked --target '"$t"' --target-dir /target'; then
        die3 "$t: docker build failed"
    fi
}

# cargo xwin links with llvm-lib and lld-link; llvm-tools carries both
# as llvm-ar and rust-lld, which pick their mode from the name.
build_msvc() {
    if ! "${env_no_proxy[@]}" cargo xwin --version >/dev/null 2>&1; then
        die3 "x86_64-pc-windows-msvc: cargo xwin is not installed; run: cargo install --locked cargo-xwin"
    fi
    local llvm="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
    [ -x "$llvm/llvm-ar" ] ||
        die3 "x86_64-pc-windows-msvc: llvm-tools is not installed; run: rustup component add llvm-tools"
    local tools=$PWD/target/cross/xwin-bin
    mkdir -p "$tools"
    ln -sf "$llvm/llvm-ar" "$tools/llvm-lib"
    ln -sf "$llvm/rust-lld" "$tools/lld-link"
    if ! PATH="$tools:$PATH" "${env_no_proxy[@]}" cargo xwin build --release --locked --target x86_64-pc-windows-msvc --target-dir target/cross/x86_64-pc-windows-msvc; then
        die3 "x86_64-pc-windows-msvc: cargo xwin build failed"
    fi
}

bin_name() {
    case $1 in
    *windows-msvc) echo jaynshare.exe ;;
    *) echo jaynshare ;;
    esac
}

# Runs the binary's `version --json` where this machine can, echoes the JSON.
run_version() {
    local t=$1
    local bin="$out/$1/$(bin_name "$1")"
    case $t in
    aarch64-apple-darwin)
        "$bin" version --json
        ;;
    x86_64-apple-darwin)
        if arch -x86_64 true 2>/dev/null; then
            arch -x86_64 "$bin" version --json
        else
            return 0
        fi
        ;;
    *-unknown-linux-musl)
        local plat
        case $t in
        aarch64-*) plat=linux/arm64 ;;
        x86_64-*) plat=linux/amd64 ;;
        esac
        docker run --rm --platform "$plat" -v "$out/$t":/b:ro alpine:3 "/b/$(bin_name "$t")" version --json
        ;;
    *) # msvc: not runnable on this host
        return 0
        ;;
    esac
}

check_version() {
    local t=$1 json
    if ! json=$(run_version "$t"); then
        echo "$t: version --json failed" >&2
        exit 1
    fi
    [ -n "$json" ] || return 0
    if ! python3 -c '
import json, sys
d = json.loads(sys.argv[1]); r = d["result"]
if r["commit"] != sys.argv[2]:
    print(f"{sys.argv[3]}: result.commit mismatch", file=sys.stderr); sys.exit(1)
if r["target"] != sys.argv[3]:
    print(f"{sys.argv[3]}: result.target mismatch", file=sys.stderr); sys.exit(1)
' "$json" "$commit" "$t"; then
        exit 1
    fi
}

for t in "${want[@]}"; do
    bin="$out/$t/$(bin_name "$t")"
    case $t in
    *-apple-darwin)
        $APPLE_HOST || die3 "$t: not on macOS"
        if ! rustup target list --installed | grep -qx "$t"; then
            die3 "$t: rustup target not installed; run: rustup target add $t"
        fi
        build_native "$t"
        ;;
    *-unknown-linux-musl) build_musl "$t" ;;
    *-windows-msvc) build_msvc ;;
    esac

    mkdir -p "$out/$t"
    cp "target/cross/$t/$t/release/$(bin_name "$t")" "$bin"

    [ -s "$bin" ] || { echo "$t: missing or empty: $bin" >&2; exit 1; }

    case $t in
    aarch64-apple-darwin) pattern="Mach-O.*arm64" ;;
    x86_64-apple-darwin) pattern="Mach-O.*x86_64" ;;
    aarch64-unknown-linux-musl) pattern="ELF.*ARM aarch64.*static" ;;
    x86_64-unknown-linux-musl) pattern="ELF.*x86-64.*static" ;;
    x86_64-pc-windows-msvc) pattern="PE32[+] executable.*x86-64" ;;
    esac
    if ! file "$bin" | grep -q "$pattern"; then
        echo "$t: unexpected file format: $(file "$bin")" >&2
        exit 1
    fi

    check_version "$t"

    echo "--bin $t=$bin"
done
