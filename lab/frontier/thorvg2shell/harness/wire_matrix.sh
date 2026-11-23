#!/bin/bash
# Loopback wire lane: real HTTP request bodies decoded through the public API.
# Only 127.0.0.1 is bound; no external network. Run from lab/frontier/thorvg2shell.
set -u
PORT=18081
OUT=harness/evidence/wire.tsv
: > "$OUT"
printf '# built %s\n' "$(date -u +%FT%TZ)" >> "$OUT"
printf '# vuln_lib %s\n' "$(sha256sum /tmp/thorvg-public-build/src/libthorvg-1.so.1.1.1 | cut -d' ' -f1)" >> "$OUT"
printf '# fixed_lib %s\n' "$(sha256sum /tmp/thorvg-public-fixed/src/libthorvg-1.so.1.1.2 | cut -d' ' -f1)" >> "$OUT"
printf 'build\tphase\thttp\tserver_rc\n' >> "$OUT"

run_build() {
    local tag="$1"
    local log="harness/evidence/wire-$tag.log"
    ./harness/bin/loopback-"$tag" "$PORT" > "$log" 2>&1 &
    local pid=$!
    sleep 1
    local health http
    health=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" 2>/dev/null)
    printf '%s\thealth\t%s\t-\n' "$tag" "$health" >> "$OUT"
    http=$(curl -s -m 60 -o /dev/null -w '%{http_code}' \
        --data-binary @poc/control_large.jpg \
        -H 'Content-Type: image/jpeg' "http://127.0.0.1:$PORT/decode" 2>/dev/null)
    printf '%s\tcontrol_large\t%s\t-\n' "$tag" "$http" >> "$OUT"
    http=$(curl -s -m 60 -o /dev/null -w '%{http_code}' \
        --data-binary @poc/dup4_large.jpg \
        -H 'Content-Type: image/jpeg' "http://127.0.0.1:$PORT/decode" 2>/dev/null)
    printf '%s\tdup4_large\t%s\t-\n' "$tag" "$http" >> "$OUT"
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        printf '%s\tserver_exit\talive_killed\t0\n' "$tag" >> "$OUT"
    else
        wait "$pid" 2>/dev/null
        printf '%s\tserver_exit\tdead\t%s\n' "$tag" "$?" >> "$OUT"
    fi
    printf '%s\tserver_log\t%s\n' "$tag" "$(tr '\n' '|' < "$log")" >> "$OUT"
}

run_build vuln
run_build fixed
cat "$OUT"
printf 'wire_sha256 %s\n' "$(sha256sum "$OUT" | cut -d' ' -f1)"
