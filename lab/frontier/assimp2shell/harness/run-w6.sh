#!/usr/bin/env bash
# W6: untested glTF 1.0 accessor sites found by source enumeration.
# (1) MAT4/FLOAT TEXCOORD_0 into aiVector3D: same unchecked ExtractData
#     primitive as POSITION, but a distinct ImportMeshes call site.
# (2) TEXCOORD count < POSITION count: the Y-flip loop indexes the texcoord
#     array with mNumVertices from POSITION (a separate missing count check,
#     NOT the element-size bug). Both are author-measured, unwitnessed.
# Prerequisite: bash harness/run-w5.sh once (builds the pinned ASan and plain
# libraries and the drivers reused here, from the pinned source tree).
set -euo pipefail
cd "$(dirname "$0")/.."

for drv in harness/bin/w5_real_vuln harness/bin/w5_real_fixed \
           harness/bin/w5_cb_vuln harness/bin/w5_plain; do
    if [ ! -x "$drv" ]; then
        echo "missing $drv: run 'bash harness/run-w5.sh' first" >&2
        exit 2
    fi
done

mkdir -p w6/evidence
rm -f w6/evidence/*.out
log=w6/evidence/w6.log
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
    local out="w6/evidence/${c}-${label}.out"
    case "$mode" in
        cb) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        plain) "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        *) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
    esac
    printf '# %s case=%s mode=%s label=%s rc=%s\n' "$(basename "$drv")" "$c" "$mode" "$label" "$rc" >>"$log"
}

run harness/bin/w5_real_vuln mat4tex-count1 asan
check mat4tex-write64 w6/evidence/mat4tex-count1-asan.out 'WRITE of size 64'
check mat4tex-region12 w6/evidence/mat4tex-count1-asan.out '0 bytes after 12-byte region'
check mat4tex-extract-frame w6/evidence/mat4tex-count1-asan.out "ExtractData<aiVector3t<float> >"
check mat4tex-import-frame w6/evidence/mat4tex-count1-asan.out 'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)'
check mat4tex-realpath-frame w6/evidence/mat4tex-count1-asan.out 'Importer::ReadFileFromMemory'


run harness/bin/w5_real_fixed mat4tex-count1 fixed
check mat4tex-fixed-no-asan w6/evidence/mat4tex-count1-fixed.out 'scene=null' 'ERROR: AddressSanitizer'
check mat4tex-fixed-message w6/evidence/mat4tex-count1-fixed.out 'failed to extract data for texcoord 0'

run harness/bin/w5_cb_vuln mat4tex-count1 cb
check mat4tex-cb-addr w6/evidence/mat4tex-count1-cb.out 'ASAN_CB addr='
check mat4tex-cb-scene-ok w6/evidence/mat4tex-count1-cb.out 'scene=ok'
check mat4tex-cb-dump w6/evidence/mat4tex-count1-cb.out 'POST_WRITE addr='

run harness/bin/w5_plain mat4tex-count1 plain
check mat4tex-plain-fault w6/evidence/w6.log 'case=mat4tex-count1 mode=plain label=plain rc=139'

run harness/bin/w5_real_vuln texcount-mismatch asan
check texcount-read4 w6/evidence/texcount-mismatch-asan.out 'READ of size 4'
check texcount-import-frame w6/evidence/texcount-mismatch-asan.out 'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)'

run harness/bin/w5_real_fixed texcount-mismatch asan fixed
check texcount-fixed-still-read w6/evidence/texcount-mismatch-fixed.out 'READ of size 4'
check texcount-fixed-frame w6/evidence/texcount-mismatch-fixed.out 'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)'

run harness/bin/w5_plain texcount-mismatch plain
check texcount-plain-abort w6/evidence/texcount-mismatch-plain.out 'double free or corruption (out)'

run harness/bin/w5_real_vuln texsafe-count1 asan
check texsafe-vuln-clean w6/evidence/texsafe-count1-asan.out 'scene=ok' 'ERROR: AddressSanitizer'

run harness/bin/w5_real_fixed texsafe-count1 fixed
check texsafe-fixed-clean w6/evidence/texsafe-count1-fixed.out 'scene=ok' 'ERROR: AddressSanitizer'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum w6/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
