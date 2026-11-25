#!/usr/bin/env bash
# W25: ONE witness command for the shipped-3.20b Synchronet claim.
# Runs the four existing, unmodified drivers W21/W22/W23/W24 in order and
# asserts the raw-byte chain: 40-byte control clean, 64-byte chosen pointer
# pair written over loopback SSH, pinned fixed-form control clean, three-run
# determinism, and a faulting load that reads the wire-chosen pointer.
#
# Precondition: the ignored src-tree/320b worktree is the exact pinned
# db9c5d6f release. All clients connect only to 127.0.0.1 loopback ports.
# Each driver restores src/sbbs3/answer.cpp on exit; this wrapper also
# snapshots and restores the committed evidence files it overwrites, so the
# live tree's receipts stay byte-exact.
set -uo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
D=$HERE/release-label/term320b
REAL=$D/real320b
FIXED=$D/fixed320b
TREE=$HERE/src-tree/320b
OUT=${1:-$D/witness-out-$$}
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d

CTRL='REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000 first=(nil) last=(nil)'
CHOSEN='REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154'
FIXEDLINE='FIXED_320B_PROBE sizeof=41 wire=64 len=40 off41=00 cv=00000000 first=(nil) last=(nil)'
PAYLOAD='REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154'

pass=0
fail=0
ck() {
    if [ "$1" = 0 ]; then echo "PASS $2"; pass=$((pass + 1));
    else echo "FAIL $2"; fail=$((fail + 1)); fi
}
need() {
    # need FILE PATTERN LABEL -- grep a raw transcript (fixed strings).
    local file=$1 pattern=$2 label=$3
    grep -qF -- "$pattern" "$file"; ck $? "$label"
}
absent() {
    local file=$1 pattern=$2 label=$3
    if grep -qF -- "$pattern" "$file"; then ck 1 "$label"; else ck 0 "$label"; fi
}

test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || {
    echo "TREE_HEAD_MISMATCH"; exit 2;
}
mkdir -p "$OUT" || exit 2

# Snapshot committed evidence the drivers overwrite. The drivers' outputs are
# copied into $OUT; the originals are restored byte-for-byte on exit.
SNAP=$OUT/snapshot
mkdir -p "$SNAP/real" "$SNAP/fixed" "$SNAP/determinism" || exit 2
for f in server-control40.log server-vuln.log server-vuln-final.log \
         client-control40.log client-vuln-chosen64.log client-gdb.log \
         client-faultaddr.log gdb-vuln-final.log gdb-faultaddr.log run-final.log; do
    cp -p "$REAL/evidence/$f" "$SNAP/real/$f" 2>/dev/null || true
done
for f in server-vuln.log server-fixed.log client-vuln-chosen64.log \
         client-fixed-chosen64.log pinned-hunk.log run.log; do
    cp -p "$FIXED/evidence/$f" "$SNAP/fixed/$f" 2>/dev/null || true
done
for f in "$REAL"/evidence/determinism/run-*.log; do
    [ -e "$f" ] && cp -p "$f" "$SNAP/determinism/$(basename "$f")"
done

restore() {
    local f
    git -C "$TREE" checkout -- src/sbbs3/answer.cpp 2>/dev/null || true
    for f in "$SNAP/real"/*; do [ -e "$f" ] && cp -p "$f" "$REAL/evidence/$(basename "$f")"; done
    for f in "$SNAP/fixed"/*; do [ -e "$f" ] && cp -p "$f" "$FIXED/evidence/$(basename "$f")"; done
    for f in "$SNAP/determinism"/*; do [ -e "$f" ] && cp -p "$f" "$REAL/evidence/determinism/$(basename "$f")"; done
}
trap restore EXIT

# W21: one real 3.20b build, two fresh loopback servers, 40-byte then chosen.
echo "=== W21 real320b (one run) $(date -u +%FT%TZ) ==="
bash "$REAL/run-real320b.sh" > "$OUT/w21.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && grep -q 'RESULT: PASS=4 FAIL=0' "$OUT/w21.log" && echo 0 || echo 1) "W21 driver rc=0 and RESULT 4 PASS / 0 FAIL"
need "$REAL/evidence/server-control40.log" "$CTRL" "W21 40-byte control leaves fields nil/zero"
need "$REAL/evidence/server-vuln.log" "$CHOSEN" "W21 64-byte chosen TERM writes pointer pair"
need "$REAL/evidence/server-vuln.log" 'Node 1 destructor begin' "W21 chosen session reaches teardown"
absent "$REAL/evidence/server-vuln.log" 'Node 1 destructor end' "W21 chosen session never completes teardown"

# W22: same release and wire TERM, pinned cb6d77dbca fixed-form copy.
echo "=== W22 fixed320b $(date -u +%FT%TZ) ==="
bash "$FIXED/run-fixed320b.sh" > "$OUT/w22.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && grep -q 'RESULT: PASS=5 FAIL=0' "$OUT/w22.log" && echo 0 || echo 1) "W22 driver rc=0 and RESULT 5 PASS / 0 FAIL"
need "$FIXED/evidence/pinned-hunk.log" 'FIXED_HUNK_PINNED_OK' "W22 fixed statements byte-exact from pinned hunk"
need "$FIXED/evidence/server-fixed.log" "$FIXEDLINE" "W22 fixed copy bounds 64-byte wire TERM to 40"
need "$FIXED/evidence/server-fixed.log" 'Node 1 destructor end' "W22 fixed session completes teardown"

# W23: three fresh servers, same chosen bytes and teardown marker.
echo "=== W23 determinism $(date -u +%FT%TZ) ==="
bash "$REAL/run-determinism.sh" > "$OUT/w23.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && grep -q 'RESULT: PASS=13 FAIL=0' "$OUT/w23.log" && echo 0 || echo 1) "W23 driver rc=0 and RESULT 13 PASS / 0 FAIL"
for n in 1 2 3; do
    need "$REAL/evidence/determinism/run-$n-vuln.log" "$CHOSEN" "W23 run $n chosen pointer pair"
done
# Compare the probe+teardown payloads directly; only timestamps and trailing
# CR differ between runs, so normalize those and require all three normalized
# payload pairs to be byte-identical (no opaque hash recipe is needed).
norm1=$(grep -F "$PAYLOAD" "$REAL/evidence/determinism/run-1-vuln.log" | tr -d '\r' | sed -E 's/^[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} //')
norm2=$(grep -F "$PAYLOAD" "$REAL/evidence/determinism/run-2-vuln.log" | tr -d '\r' | sed -E 's/^[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} //')
norm3=$(grep -F "$PAYLOAD" "$REAL/evidence/determinism/run-3-vuln.log" | tr -d '\r' | sed -E 's/^[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} //')
ck $([ "$norm1" = "$norm2" ] && [ "$norm1" = "$norm3" ] && [ -n "$norm1" ] && echo 0 || echo 1) "W23 chosen probe payload byte-identical across 3 runs"
# W24: under gdb, the faulting load uses the wire-chosen pointer.
echo "=== W24 fault-address $(date -u +%FT%TZ) ==="
bash "$REAL/run-faultaddr320b.sh" > "$OUT/w24.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && grep -q 'RESULT: PASS=7 FAIL=0' "$OUT/w24.log" && echo 0 || echo 1) "W24 driver rc=0 and RESULT 7 PASS / 0 FAIL"
need "$REAL/evidence/gdb-faultaddr.log" "$CHOSEN" "W24 live answer() wrote chosen pointer"
need "$REAL/evidence/gdb-faultaddr.log" 'mov    0x20(%rax),%rax' "W24 fault instruction reads node->flags at +0x20(%rax)"
need "$REAL/evidence/gdb-faultaddr.log" 'rax            0x465541544f4f2d45' "W24 fault rax == wire-chosen savedlines.first"
need "$REAL/evidence/gdb-faultaddr.log" 'W24_LIST_FIRST=0x465541544f4f2d45' "W24 list->first at fault == chosen pointer"

# Preserve one copy of every raw transcript for an independent reviewer.
for f in server-control40.log server-vuln.log gdb-vuln-final.log gdb-faultaddr.log; do
    cp -p "$REAL/evidence/$f" "$OUT/real-$f" 2>/dev/null || true
done
for f in server-vuln.log server-fixed.log pinned-hunk.log; do
    cp -p "$FIXED/evidence/$f" "$OUT/fixed-$f" 2>/dev/null || true
done
for n in 1 2 3; do
    cp -p "$REAL/evidence/determinism/run-$n-vuln.log" "$OUT/w23-run-$n-vuln.log" 2>/dev/null || true
done

echo "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
