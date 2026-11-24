#!/bin/sh
# fontforge2shell W196 reproducible matrix. Never probes a network.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
: > evidence.log
run() {
    label=$1; shift
    printf '%-28s ' "$label" >> evidence.log
    "$@" >> evidence.log 2>&1
    printf 'rc=%s\n' "$?" >> evidence.log
}
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o asan-attack harness.c || exit 2
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -DFIXED -o asan-fixed harness.c || exit 2
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o asan-safe harness.c || exit 2
gcc -g -O0 -o plain-attack harness.c || exit 2
gcc -g -O0 -DFIXED -o plain-fixed harness.c || exit 2
./asan-attack > evidence/asan-attack.out 2>&1; a=$?
./asan-fixed > evidence/asan-fixed.out 2>&1; f=$?
./asan-safe safe > evidence/asan-safe.out 2>&1; s=$?
./plain-attack > evidence/plain-attack.out 2>&1; p=$?
./plain-fixed > evidence/plain-fixed.out 2>&1; pf=$?
gdb -q -batch -ex 'set pagination off' -ex 'break harness.c:131' \
    -ex 'run' -ex 'p/x encs[-1]' -ex 'x/4bx (char*)encs-4' \
    -ex 'p/x encs' ./plain-attack > evidence/gdb.txt 2>&1
printf 'asan-attack rc=%s (expect 1)\n' "$a" >> evidence.log
printf 'asan-fixed  rc=%s (expect 0)\n' "$f" >> evidence.log
printf 'asan-safe   rc=%s (expect 0)\n' "$s" >> evidence.log
printf 'plain-attack rc=%s (expect 134)\n' "$p" >> evidence.log
printf 'plain-fixed  rc=%s (expect 0)\n' "$pf" >> evidence.log
printf 'normalized gdb bytes: ' >> evidence.log
grep -E '^0x[0-9a-f]+:.*0x4d.*0x49.*0x53.*0x00' evidence/gdb.txt >> evidence.log || true
sha256sum harness.c pinned/* >> evidence.log
sha256sum evidence/* >> evidence.log
cat evidence.log
