#!/bin/bash
# unarr2shell lane 3: replay the crafted USTAR bytes over loopback TCP into
# unarr's public API via a synthetic consumer. NOT a real application caller
# and NOT rung 5: this only shows wire bytes can reach the tar_get_name sink.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/rung4/wire"
BUILD="$HERE/build"
EVID="$HERE/evidence"
mkdir -p "$BUILD" "$EVID"

SRC="$ROOT/unarr-1.1.0"
FIX="$ROOT/src-locally-fixed"
LIBV="$ROOT/build/vuln/libunarr.a"
LIBF="$ROOT/build/fixed/libunarr.a"

# The main harness builds both ASan libraries; rebuild it if they are absent.
if [ ! -f "$LIBV" ] || [ ! -f "$LIBF" ]; then
    bash "$ROOT/harness/run-all.sh" >/dev/null 2>&1 || exit 1
fi
for tree in "$SRC" "$FIX"; do
    [ -f "$tree/CMakeLists.txt" ] || exit 1
done
python3 "$ROOT/harness/make-poc.py" "$ROOT/evidence" >/dev/null || exit 1

cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I"$SRC" \
   "$HERE/wire_driver.c" "$LIBV" -o "$BUILD/wire-vuln" || exit 1
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I"$FIX" \
   "$HERE/wire_driver.c" "$LIBF" -o "$BUILD/wire-fixed" || exit 1

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; pass=$((pass+1))
    else echo "FAIL $1 (want $2, got $3)"; fail=$((fail+1)); fi
}

send_tar() {
    python3 -c '
import socket, sys, time
data = open(sys.argv[1], "rb").read()
port = int(sys.argv[2])
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
        break
    except OSError:
        time.sleep(0.05)
else:
    sys.exit(3)
s.sendall(data)
s.shutdown(socket.SHUT_WR)
s.close()
' "$1" "$2"
}
run_case() {
    local label="$1" bin="$2" tar="$3" port="$4"
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:halt_on_error=1 \
        "$bin" "$port" >"$EVID/$label.out" 2>&1 &
    local pid=$!
    send_tar "$tar" "$port"
    wait "$pid"
    echo $? >"$EVID/$label.rc"
    echo "  $label rc=$(cat "$EVID/$label.rc")"
    grep -m2 -E 'WIRE_BYTES=|entry name:|ERROR: AddressSanitizer|WRITE of size|tar_get_name' \
        "$EVID/$label.out" | sed 's/^/    /'
}

run_case vuln-attack "$BUILD/wire-vuln" "$ROOT/evidence/attack.tar" 19441
run_case vuln-safe-name "$BUILD/wire-vuln" "$ROOT/evidence/safe-short-name.tar" 19442
run_case vuln-safe-prefix "$BUILD/wire-vuln" "$ROOT/evidence/safe-short-prefix.tar" 19443
run_case fixed-attack "$BUILD/wire-fixed" "$ROOT/evidence/attack.tar" 19444

attack_out="$EVID/vuln-attack.out"
attack_rc=$(cat "$EVID/vuln-attack.rc")
grep -q '^WIRE_BYTES=[1-9]' "$attack_out" \
    && grep -q 'AddressSanitizer: heap-buffer-overflow' "$attack_out" \
    && grep -q 'WRITE of size 101' "$attack_out" \
    && grep -q 'tar_get_name' "$attack_out"
check wire-attack-asan 0 $([ $? -eq 0 ] && echo 0 || echo 1)
check wire-attack-rc 1 "$attack_rc"
for s in vuln-safe-name vuln-safe-prefix fixed-attack; do
    check "$s-rc" 0 "$(cat "$EVID/$s.rc")"
    grep -q 'entry name:' "$EVID/$s.out"
    check "$s-clean-name" 0 $([ $? -eq 0 ] && echo 0 || echo 1)
done

{
    echo "# unarr2shell wire-to-sink replay — $(date -u +%FT%TZ)"
    echo
    echo "Loopback-only synthetic consumer: 127.0.0.1 TCP body ->"
    echo "ar_open_memory -> ar_open_tar_archive -> ar_parse_entry ->"
    echo "ar_entry_get_name. No real application caller; no external target."
    echo "Libraries: ${LIBV#$ROOT/} (verbatim v1.1.0) and"
    echo "${LIBF#$ROOT/} (synthetic +1-byte control),"
    echo "both built by harness/run-all.sh with ASan."
    echo
    echo '## Observed'
    for s in vuln-attack vuln-safe-name vuln-safe-prefix fixed-attack; do
        echo "[$s] rc=$(cat "$EVID/$s.rc")"
        grep -E 'WIRE_BYTES=|entry name:|ERROR: AddressSanitizer|WRITE of size|#1 tar_get_name|#2 ar_entry_get_name' "$EVID/$s.out" | sed 's/^/  /'
    done
    echo
    echo "Interpretation: crafted tar bytes delivered on loopback reach the same"
    echo "tar_get_name overflow (WRITE of size 101) through the public API; safe"
    echo "inputs and the synthetic fixed build stay clean. This is rung-4 wire"
    echo "mechanics with a synthetic consumer: it establishes neither a real"
    echo "network-facing caller nor rung 5. Grade unchanged: rung 3 verbatim /"
    echo "rung 4 PARTIAL fixed NUL."
} > "$HERE/wire-evidence.md"
cat "$HERE/wire-evidence.md"
echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
