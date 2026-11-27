#!/bin/sh
# Run every pinned case and assert observed bytes/state. No case is inferred.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNS=$ROOT/runs
PASS=0
FAIL=0

run_case() {
    # run_case LABEL DIR
    label=$1; dir=$2
    (cd "$dir/harness" && ./mqtt_repro) >"$dir/out.txt" 2>&1
    echo $? >"$dir/rc.txt"
}

ok()   { echo "PASS $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

has()  { grep -q -- "$2" "$1"; }
none() { ! grep -q -- "$2" "$1"; }

# --- primary oracle: sanitizer-confirmed OOB at the raw pinned sink ---
for cc in gcc clang; do
    d=$RUNS/vuln-$cc-bounds
    run_case "vuln-$cc-bounds" "$d"
    rc=$(cat "$d/rc.txt")
    if [ "$rc" != 0 ] && has "$d/out.txt" "index 128 out of bounds" \
       && has "$d/out.txt" "mqtt.c:862"; then
        ok "vuln-$cc-bounds rc=$rc UBSan index-128 OOB at raw mqtt.c:862"
    else
        bad "vuln-$cc-bounds rc=$rc expected nonzero + index-128 + mqtt.c:862"
    fi
done

# --- fixed pin: same 200-byte input, bounds sanitizer clean ---
for cc in gcc clang; do
    d=$RUNS/fixed-$cc-bounds
    run_case "fixed-$cc-bounds" "$d"
    rc=$(cat "$d/rc.txt")
    if [ "$rc" = 0 ] && none "$d/out.txt" "runtime error" \
       && has "$d/out.txt" "msg_idx after parse = 128"; then
        ok "fixed-$cc-bounds rc=0 msg_idx=128 no sanitizer report"
    else
        bad "fixed-$cc-bounds rc=$rc expected clean msg_idx=128"
    fi
done

# --- safe-input control: vulnerable pin, 128 bytes, no OOB ---
d=$RUNS/vuln-gcc-bounds-safe
run_case "vuln-gcc-bounds-safe" "$d"
rc=$(cat "$d/rc.txt")
if [ "$rc" = 0 ] && none "$d/out.txt" "runtime error" \
   && has "$d/out.txt" "msg_idx after parse = 128"; then
    ok "vuln-gcc-bounds-safe rc=0 msg_idx=128 no sanitizer report"
else
    bad "vuln-gcc-bounds-safe rc=$rc expected clean msg_idx=128"
fi

# --- ASan negative preserved: intra-object overflow is NOT heap ASan-visible ---
for cc in gcc clang; do
    d=$RUNS/vuln-$cc-asan
    run_case "vuln-$cc-asan" "$d"
    rc=$(cat "$d/rc.txt")
    if [ "$rc" = 0 ] && has "$d/out.txt" "msg_idx after parse = 200" \
       && none "$d/out.txt" "AddressSanitizer"; then
        ok "vuln-$cc-asan rc=0 msg_idx=200 ASan silent (intra-object)"
    else
        bad "vuln-$cc-asan rc=$rc expected msg_idx=200 ASan-silent"
    fi
done

# --- plain state differential ---
for pin in vuln fixed; do
    d=$RUNS/$pin-gcc-plain
    run_case "$pin-gcc-plain" "$d"
    rc=$(cat "$d/rc.txt")
    want=200; [ "$pin" = fixed ] && want=128
    if [ "$rc" = 0 ] && has "$d/out.txt" "msg_idx after parse = $want"; then
        ok "$pin-gcc-plain rc=0 msg_idx=$want"
    else
        bad "$pin-gcc-plain rc=$rc expected msg_idx=$want"
    fi
done

# --- rung-4 canary: chosen continuation byte lands at chosen adjacent offsets ---
canary_case() {
    label=$1; dir=$2; want=$3
    run_case "$label" "$dir"
    rc=$(cat "$dir/rc.txt")
    if [ "$rc" = 0 ] && has "$dir/out.txt" "$want"; then
        ok "$label rc=0 $want"
    else
        bad "$label rc=$rc expected $want"
    fi
}
canary_case canary-vuln-ff  "$RUNS/vuln-gcc-canary-ff" \
    "CANARY changed=68/256 put=65535 get=65535 first=ff ff ff ff"
canary_case canary-vuln-80  "$RUNS/vuln-gcc-canary-80" \
    "CANARY changed=68/256 put=32896 get=32896 first=80 80 80 80"
canary_case canary-fixed-ff "$RUNS/fixed-gcc-canary-fixed" \
    "CANARY changed=0/256 put=0 get=0 first=ee ee ee ee"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
