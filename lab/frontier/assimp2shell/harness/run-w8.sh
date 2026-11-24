#!/usr/bin/env bash
# W8: bounded live-aiMesh field scan after the ASan report callback lets the
# importer's own out-of-bounds MAT4/FLOAT copy complete. Question: do chosen
# OOB source bytes survive in any field of the aiMesh returned by
# ReadFileFromMemory? The driver only adds instrumentation; the pinned library
# and the documents are untouched. Author-measured, unwitnessed, no r5.
# Prerequisite: bash harness/run-w5.sh (builds the vulnerable and PR6860
# overlay libraries from the pinned tarball).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p w8/evidence harness/bin
log=w8/evidence/w8.log
: >"$log"
pass=0
fail=0

check() { # name, logfile, required substring (or empty), rejected substring (or empty)
    local name="$1" file="$2" need="${3-}" reject="${4-}"
    if [ -n "$need" ] && ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF "$reject" "$file"; then
        printf 'FAIL %s (found: %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
    -I pins/assimp-6.0.6/include -I build-min/include \
    harness/w8_field_driver.cpp -L build-min/bin -lassimp \
    -Wl,-rpath,"$PWD/build-min/bin" -o harness/bin/w8_field_vuln
g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
    -I pins/fixed-full-6.0.6/include -I build-min-fixed/include \
    harness/w8_field_driver.cpp -L build-min-fixed/bin -lassimp \
    -Wl,-rpath,"$PWD/build-min-fixed/bin" -o harness/bin/w8_field_fixed

run() { # driver, case, label
    local drv="$1" c="$2" label="$3" rc=0
    local out="w8/evidence/${c}-${label}.out"
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=0:symbolize=1 \
        "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$?
    printf '# %s case=%s label=%s rc=%s\n' "$(basename "$drv")" "$c" "$label" "$rc" >>"$log"
    [ "$rc" -eq 0 ] || { printf 'FAIL rc %s=%s\n' "$c" "$rc" | tee -a "$log"; fail=$((fail+1)); }
}

# Count=1: chosen marker at OOB source offsets 40..55; first OOB byte is
# dest+12. The OOB bytes appear after the callback, but no live aiMesh field
# contains the 16-byte marker.
run harness/bin/w8_field_vuln mat4pos-livefield cb
check c1-asan-callback w8/evidence/mat4pos-livefield-cb.out 'ASAN_CB addr='
check c1-import-completed w8/evidence/mat4pos-livefield-cb.out 'scene=ok'
check c1-oob-bytes-present w8/evidence/mat4pos-livefield-cb.out '54415546'
check c1-vertices-scanned w8/evidence/mat4pos-livefield-cb.out 'SCAN_CLEAN field=mesh0.mVertices'
check c1-no-live-hit w8/evidence/mat4pos-livefield-cb.out '' 'LIVE_HIT'

# Count=2 with a NORMAL array: the POSITION overflow range covers the address
# of mNormals, but NORMAL extraction overwrites those bytes with its own data
# (0000803f = 1.0f). No chosen marker survives in a live field.
run harness/bin/w8_field_vuln mat4pos2-norm-livefield cb
check c2-asan-callback w8/evidence/mat4pos2-norm-livefield-cb.out 'ASAN_CB addr='
check c2-import-completed w8/evidence/mat4pos2-norm-livefield-cb.out 'scene=ok'
check c2-normals-scanned w8/evidence/mat4pos2-norm-livefield-cb.out 'SCAN_CLEAN field=mesh0.mNormals'
check c2-normal-overwrite w8/evidence/mat4pos2-norm-livefield-cb.out '0000803f'
check c2-no-live-hit w8/evidence/mat4pos2-norm-livefield-cb.out '' 'LIVE_HIT'

# Positive control: a known marker in the returned mesh struct and mName must
# be found by the same scanner, so SCAN_CLEAN above is not a false negative.
run harness/bin/w8_field_vuln scanner-positive control
check scanner-positive-struct w8/evidence/scanner-positive-control.out 'LIVE_HIT field=mesh0.struct'
check scanner-positive-name w8/evidence/scanner-positive-control.out 'LIVE_HIT field=mesh0.mName'

# Safe input on the vulnerable build: no report, no hit.
run harness/bin/w8_field_vuln safe control
check safe-clean w8/evidence/safe-control.out 'scene=ok' 'ASAN_CB'
check safe-no-hit w8/evidence/safe-control.out '' 'LIVE_HIT'

# Proposed PR6860 hunk (open, unmerged) rejects the crafted document: no
# report, no hit. Never a released fixed-version claim.
run harness/bin/w8_field_fixed mat4pos-livefield fixed
check fixed-clean w8/evidence/mat4pos-livefield-fixed.out 'scene=ok' 'ERROR: AddressSanitizer'
check fixed-no-callback w8/evidence/mat4pos-livefield-fixed.out '' 'ASAN_CB'
check fixed-no-hit w8/evidence/mat4pos-livefield-fixed.out '' 'LIVE_HIT'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum w8/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
