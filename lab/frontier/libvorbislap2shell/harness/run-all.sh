#!/bin/sh
# Pinned-sink differential for CVE-2026-137079 (_ov_getlap negative memcpy).
# No network, no media file, no live service: the pinned sink body runs with a
# stand-in vorbis_synthesis_lapout() that returns the requested sample count.
set -eu
cd "$(dirname "$0")/.."
PASS=0
FAIL=0
check() {
    if [ "$1" = 0 ]; then PASS=$((PASS + 1)); else
        FAIL=$((FAIL + 1)); echo "FAIL: $2"; fi
}
note() { echo "CHECK $1 $2"; }
mkdir -p evidence
(cd src && sha256sum -c SHA256SUMS) > evidence/pins.out 2>&1
check $? "input pins"
rm -rf build generated bin
mkdir -p build/vuln build/fixed generated bin
tar xzf src/vorbis-v1.3.7.tar.gz -C build/vuln --strip-components=1
tar xzf src/vorbis-v1.3.7.tar.gz -C build/fixed --strip-components=1
(cd build/fixed && patch -s -p1 < ../../src/pr136.diff)
check $? "fixed patch applies"

sh harness/gen.sh build/vuln generated/vuln.c
sh harness/gen.sh build/fixed generated/fixed.c
grep -q 'samples==0' generated/vuln.c
check $? "vulnerable generated body has pinned ==0 guard"
grep -q 'samples<=0' generated/fixed.c
check $? "fixed generated body has PR136 <=0 guard"

gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o bin/vuln-asan generated/vuln.c
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o bin/fixed-asan generated/fixed.c
gcc -g -O0 -fno-stack-protector -o bin/vuln-plain generated/vuln.c
gcc -g -O0 -fno-stack-protector -o bin/fixed-plain generated/fixed.c
check $? "four builds"

set +e
./bin/vuln-asan -4 > evidence/vuln-asan-attack.raw 2>&1; VAA=$?
./bin/vuln-asan 0 > evidence/vuln-asan-safe.raw 2>&1; VAS=$?
./bin/fixed-asan 0 > evidence/fixed-asan-safe.raw 2>&1; FAS=$?
./bin/fixed-asan -4 > evidence/fixed-asan-attack.raw 2>&1; FAA=$?
./bin/vuln-plain -4 > evidence/vuln-plain-attack.raw 2>&1; VPA=$?
./bin/vuln-plain 0 > evidence/vuln-plain-safe.raw 2>&1; VPS=$?
./bin/fixed-plain -4 > evidence/fixed-plain-attack.raw 2>&1; FPA=$?
set -e

[ "$VAA" -ne 0 ]
check $? "vulnerable ASan attack faults"
grep -q 'AddressSanitizer' evidence/vuln-asan-attack.raw
check $? "ASan report present"
grep -q 'negative-size-param: (size=-16)' evidence/vuln-asan-attack.raw
check $? "ASan negative-size-param on pinned memcpy line"
grep -q 'vorbisfile.c:2250' evidence/vuln-asan-attack.raw
check $? "ASan pinned memcpy line"
grep -q 'dynamic-stack-buffer-overflow' evidence/vuln-asan-safe.raw
check $? "second pinned overflow via zero-sample memset"
grep -q 'vorbisfile.c:2245' evidence/vuln-asan-safe.raw
check $? "ASan pinned memset line"
[ "$FAA" -eq 0 ] && grep -q 'RETURN lapcount=64' evidence/fixed-asan-attack.raw
check $? "fixed ASan attack clean"
[ "$FAS" -eq 0 ] && grep -q 'RETURN lapcount=64' evidence/fixed-asan-safe.raw
check $? "fixed ASan safe clean"
[ "$VPA" -eq 0 ] && grep -q 'RETURN lapcount=4' evidence/vuln-plain-attack.raw
check $? "plain negative-count run completes (no crash, negative preserved)"
[ "$VPS" -eq 0 ] && grep -q 'RETURN lapcount=64' evidence/vuln-plain-safe.raw
check $? "vulnerable plain safe input completes (zero overwrite unmeasured)"
[ "$FPA" -eq 0 ] && grep -q 'RETURN lapcount=64' evidence/fixed-plain-attack.raw
check $? "fixed plain attack clean"

note RUN_ALL "$PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ] && echo RUN_ALL_OK "$PASS PASS / 0 FAIL"
[ "$FAIL" -eq 0 ]
