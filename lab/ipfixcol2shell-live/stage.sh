#!/bin/sh
# Provision the pinned upstream TCP input sources into v280/ and v290/.
# Fetching source tarballs is provisioning; nothing here opens a socket to a
# target. Tarballs are cached locally and verified by sha256 on every run.
set -eu
cd "$(dirname "$0")"
mkdir -p tarballs

fetch() {
    url=$1
    path=$2
    expected=$3
    if [ ! -f "$path" ] || [ "$(sha256sum "$path" | cut -d' ' -f1)" != "$expected" ]; then
        curl -fsSL --max-time 60 -o "$path" "$url"
    fi
    actual=$(sha256sum "$path" | cut -d' ' -f1)
    if [ "$actual" != "$expected" ]; then
        printf 'sha256 mismatch for %s: %s\n' "$path" "$actual" >&2
        exit 1
    fi
}

fetch https://github.com/CESNET/ipfixcol2/archive/refs/tags/v2.8.0.tar.gz \
    tarballs/v2.8.0.tar.gz 460f1272fd1a857bf8788ae226adfcb83cf8ffcf40583386f207eb6bb4186e1c
fetch https://github.com/CESNET/ipfixcol2/archive/refs/tags/v2.9.0.tar.gz \
    tarballs/v2.9.0.tar.gz fa98b31c3a408d0ef04f2e99d1c9fc0a335ed4381c602fe65e8a481872625e7c

for tag in v280 v290; do
    rm -rf "$tag"
    mkdir -p "$tag"
done
tar xzf tarballs/v2.8.0.tar.gz -C v280 --strip-components=1
tar xzf tarballs/v2.9.0.tar.gz -C v290 --strip-components=1
cp v280/src/plugins/input/tcp/src/*.cpp v280/src/plugins/input/tcp/src/*.hpp v280/
cp v290/src/plugins/input/tcp/src/*.cpp v290/src/plugins/input/tcp/src/*.hpp v290/

# The two decoder files must match the frontier pins byte for byte.
for pair in \
    'v280/Lz4Decoder.cpp 3e618628ef0af35ad57f05afdb6a42cafe64403f846364d094f0381e7695fd10' \
    'v290/Lz4Decoder.cpp 46a0fc8b98ed9a0b5b31567610211a771c22a241981d2dbbd4237fec0dfbcd14'; do
    set -- $pair
    actual=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$actual" != "$2" ]; then
        printf 'sha256 mismatch for %s: %s\n' "$1" "$actual" >&2
        exit 1
    fi
done
