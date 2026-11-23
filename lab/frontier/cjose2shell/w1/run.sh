#!/bin/bash
# Drive the loopback consumer with real HTTP requests. One server per case.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$HERE/evidence"
cd "$HERE" || exit 2

for bin in w1-plain-vuln w1-trace-vuln w1-asan-vuln w1-plain-fixed; do
    for scenario in valid wrapped wrappedN48 wrappedN56 wrappedbig probe undersized; do
        out="evidence/$bin.$scenario.log"
        : > "$out"
        ./"$bin" > "$out" 2>&1 &
        pid=$!
        port=""
        for _ in $(seq 1 200); do
            port=$(grep -m1 '^PORT=' "$out" 2>/dev/null | cut -d= -f2)
            [ -n "$port" ] && break
            sleep 0.05
        done
        if [ -z "$port" ]; then
            printf '%s %s NO_PORT\n' "$bin" "$scenario"
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            continue
        fi
        python3 client.py 127.0.0.1 "$port" "$scenario" >> "$out" 2>&1
        wait "$pid"
        rc=$?
        printf '%s %s SERVER_RC=%s\n' "$bin" "$scenario" "$rc"
    done
done
