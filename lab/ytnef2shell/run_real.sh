#!/usr/bin/env bash
# Drive a real libytnef caller (ytnefprint -> MAPIPrint -> DecompressRTF) over
# upstream and crafted TNEF files. Local files only; no network, no mail.
set -u
cd "$(dirname "$0")" || exit 2
export ASAN_OPTIONS=detect_leaks=0
E=evidence
mkdir -p "$E"

INPUTS="rtf-safe.dat rtf-wrap16.dat rtf-wrap0.dat rtf-wrap206.dat rtf-mela.dat \
winmail-safe.dat winmail-wrap16.dat winmail-wrap0.dat winmail-wrap206.dat winmail-mela.dat"

run() {
    local build=$1 input=$2 tag="${1}-${2%.dat}"
    local dir="build/$build"
    ( cd "$dir" && LD_LIBRARY_PATH="$PWD/lib/.libs" \
        ./ytnefprint/ytnefprint "../../inputs/$input" ) \
        >"$E/$tag.out" 2>"$E/$tag.err"
    local rc=$?
    cat "$E/$tag.out" "$E/$tag.err" >"$E/$tag.log"
    local asan="none"
    grep -qF 'ERROR: AddressSanitizer' "$E/$tag.log" && asan="YES"
    local frame="-"
    frame=$(grep -m1 -F 'DecompressRTF' "$E/$tag.log" || true)
    frame=${frame:0:72}
    printf '%-24s rc=%-3s asan=%-4s frame=%s\n' "$tag" "$rc" "$asan" "$frame"
}

for build in v212-asan v213-asan; do
    echo "=== build $build ==="
    for input in $INPUTS; do
        run "$build" "$input"
    done
done
