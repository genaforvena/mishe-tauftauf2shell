#!/bin/sh
# Build and replay the live555 parseVorbisOrTheoraConfigStr() harness.
# All vectors are local base64 strings; no network, no RTSP server, no socket.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p runs

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has()  { grep -Fq -- "$2" "$1" 2>/dev/null; }

# A: first memmove, identSize=65535 with 2 decoded bytes left.
# B: second memmove, commentSize=65534 after a 1-byte ident copy.
# C: third memmove, setupSize=98 after two 1-byte copies.
# SAFE: 8 header bytes for 8 declared header sizes; all copies in bounds.
A='AAAAAQAAAP//AKq7'
B='AAAAAQAAAP//AQHM'
C='AAAAAQAAAABkAgEB3d3d'
SAFE='AAAAAQAAAAAIAQIDQUJDREVGR0hJ'

if (cd pins && sha256sum -c PIN_HASHES.txt) >runs/pins.log 2>&1; then
    ok 'three pins sha256-match manifest'
else
    bad 'pin hashes'
fi
python3 gen_sink.py >runs/generate.log 2>&1 || bad 'generate sinks'
python3 -c '
from pathlib import Path
for out, pin, first, last in (
    ("h/sink_vuln.cpp", "pins/VorbisAudioRTPSource.cpp.vuln", 119, 197),
    ("h/sink_fixed.cpp", "pins/VorbisAudioRTPSource.cpp.fixed", 119, 200),
):
    body = "\n".join(Path(pin).read_text().splitlines()[first-1:last]) + "\n"
    assert body in Path(out).read_text(), out
print("verbatim sink slices match pinned lines")
' >runs/verbatim.log 2>&1 && ok 'verbatim sink slices' || bad 'verbatim sink slices'

CXX=${CXX:-g++}
build() { # compiler output-suffix
    "$1" -O0 -g -fno-exceptions -fno-rtti h/driver.cpp "h/sink_$2.cpp" -o "h/plain-$2" >>runs/build.log 2>&1 || bad "build plain-$2"
    "$1" -fsanitize=address -O0 -g -fno-exceptions -fno-rtti h/driver.cpp "h/sink_$2.cpp" -o "h/asan-$2" >>runs/build.log 2>&1 || bad "build asan-$2"
}
build "$CXX" vuln
build "$CXX" fixed
if command -v clang++ >/dev/null 2>&1; then
    clang++ -fsanitize=address -O0 -g -fno-exceptions -fno-rtti h/driver.cpp h/sink_vuln.cpp -o h/clang-asan-vuln >>runs/build.log 2>&1 || bad 'build clang-asan-vuln'
fi

run() { # binary tag vector
    "h/$1" "$3" >"runs/$2.out" 2>&1
    printf '%s\n' "$?" >"runs/$2.rc"
}

run asan-vuln    asan-vuln-a       "$A"
run asan-vuln    asan-vuln-b       "$B"
run asan-vuln    asan-vuln-c       "$C"
run asan-vuln    asan-vuln-safe    "$SAFE"
run asan-fixed   asan-fixed-a      "$A"
run asan-fixed   asan-fixed-b      "$B"
run asan-fixed   asan-fixed-c      "$C"
run plain-vuln   plain-vuln-a      "$A"
run plain-fixed  plain-fixed-a     "$A"
if [ -x h/clang-asan-vuln ]; then run clang-asan-vuln clang-asan-vuln-a "$A"; fi

trap_check() { # tag size raw-line
    t=$1; size=$2; line=$3
    if [ "$(cat "runs/$t.rc")" != "0" ] &&
       has "runs/$t.out" 'heap-buffer-overflow' &&
       has "runs/$t.out" "READ of size $size" &&
       has "runs/$t.out" "liveMedia/VorbisAudioRTPSource.cpp:$line"; then
        ok "$t READ-$size at pinned line $line"
    else
        bad "$t expected READ-$size at line $line"
    fi
}
trap_check asan-vuln-a  65535 186
trap_check asan-vuln-b  65534 188
trap_check asan-vuln-c  98    190

if [ -f runs/clang-asan-vuln-a.rc ] &&
   [ "$(cat runs/clang-asan-vuln-a.rc)" != "0" ] &&
   has runs/clang-asan-vuln-a.out 'heap-buffer-overflow'; then
    ok 'clang ASan reproduces first memmove OOB read'
else
    bad 'clang ASan vulnerable vector'
fi

clean=1
for t in asan-vuln-safe asan-fixed-a asan-fixed-b asan-fixed-c; do
    if [ ! -f "runs/$t.rc" ] || [ "$(cat "runs/$t.rc")" != "0" ] || has "runs/$t.out" 'AddressSanitizer'; then clean=0; fi
done
if [ "$clean" = 1 ]; then ok 'safe vector and fixed pin clean under ASan'; else bad 'safe/fixed controls'; fi

if [ -f runs/plain-vuln-a.rc ]; then ok 'plain vulnerable outcome recorded'; else bad 'plain vulnerable run'; fi
if [ "$(cat runs/plain-fixed-a.rc)" = "0" ]; then ok 'plain fixed pin exits 0'; else bad 'plain fixed pin'; fi

printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
