#!/bin/bash
# Reconstruct pinned source trees and both build configurations from tracked
# archives. No network access is used here.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"
for pair in 'pins/libevent-vuln-1b7cc9b5.tar.gz:src-vuln' 'pins/libevent-fixed-52057cb3.tar.gz:src-fixed'; do
    arc="${pair%%:*}"; dir="${pair##*:}"
    if [ ! -f "$dir/bufferevent_sock.c" ]; then
        mkdir -p "$dir"
        tar xzf "$arc" -C "$dir" --strip-components=1
    fi
done
bash build.sh src-vuln vuln
bash build.sh src-fixed fixed
