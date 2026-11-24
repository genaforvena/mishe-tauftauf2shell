#!/usr/bin/env bash
# W7: the last unchecked accessor site enumerated in W6 — MAT4/FLOAT NORMAL
# extraction at glTFImporter.cpp:285-287 — through the real importer path.
# Reuses pinned libraries and drivers built by run-w5.sh.
# Author-measured only; no witness verdict and no rung-5 claim.
set -euo pipefail
cd "$(dirname "$0")/.."

for drv in harness/bin/w5_real_vuln harness/bin/w5_real_fixed \
           harness/bin/w5_cb_vuln harness/bin/w5_plain; do
    if [ ! -x "$drv" ]; then
        echo "missing $drv: run 'bash harness/run-w5.sh' first" >&2
        exit 2
    fi
done

mkdir -p w7/evidence
rm -f w7/evidence/*.out
log=w7/evidence/w7.log
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

run() { # driver, case, mode (asan|cb|plain), optional output label
    local drv="$1" c="$2" mode="$3" label="${4:-$3}" rc=0
    local out="w7/evidence/${c}-${label}.out"
    case "$mode" in
        cb) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        plain) "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        *) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
    esac
    printf '# %s case=%s mode=%s label=%s rc=%s\n' "$(basename "$drv")" "$c" "$mode" "$label" "$rc" >>"$log"
}

run harness/bin/w5_real_vuln mat4norm-count1 asan
check norm-write64 w7/evidence/mat4norm-count1-asan.out 'WRITE of size 64'
check norm-region12 w7/evidence/mat4norm-count1-asan.out '0 bytes after 12-byte region'
check norm-extract-frame w7/evidence/mat4norm-count1-asan.out "ExtractData<aiVector3t<float> >"
check norm-import-frame w7/evidence/mat4norm-count1-asan.out 'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)'
check norm-realpath-frame w7/evidence/mat4norm-count1-asan.out 'Importer::ReadFileFromMemory'

run harness/bin/w5_real_fixed mat4norm-count1 fixed
check norm-fixed-clean w7/evidence/mat4norm-count1-fixed.out 'scene=ok' 'ERROR: AddressSanitizer'

run harness/bin/w5_cb_vuln mat4norm-count1 cb
check norm-cb-addr w7/evidence/mat4norm-count1-cb.out 'ASAN_CB addr='
check norm-cb-scene-ok w7/evidence/mat4norm-count1-cb.out 'scene=ok'
check norm-cb-post-write w7/evidence/mat4norm-count1-cb.out 'POST_WRITE addr='
check norm-cb-chosen-bytes w7/evidence/mat4norm-count1-cb.out '54415546'

run harness/bin/w5_plain mat4norm-count1 plain
check norm-plain-fault w7/evidence/w7.log 'case=mat4norm-count1 mode=plain label=plain rc=139'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum w7/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
