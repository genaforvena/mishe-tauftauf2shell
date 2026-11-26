#!/bin/sh
# Build and replay the OpenSCAP ds_sds_mangle_filepath() harness.
# All inputs are local strings from the upstream advisory; no network, no service.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p runs

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has()  { grep -Fq -- "$2" "$1" 2>/dev/null; }

build() {
    "$1" -O0 -g harness/main.c harness/sink_vuln.c  -o harness/"$2"  >runs/build.log 2>&1 || bad "build $2"
    "$1" -O0 -g harness/main.c harness/sink_fixed.c -o harness/"$3"  >>runs/build.log 2>&1 || bad "build $3"
}

# Plain controls and ASan controls. clang ASan is a second compiler cross-check.
build gcc  plain-vuln  plain-fixed
gcc -fsanitize=address -O0 -g harness/main.c harness/sink_vuln.c  -o harness/asan-vuln  >>runs/build.log 2>&1 || bad "build asan-vuln"
gcc -fsanitize=address -O0 -g harness/main.c harness/sink_fixed.c -o harness/asan-fixed >>runs/build.log 2>&1 || bad "build asan-fixed"
if command -v clang >/dev/null 2>&1; then
    clang -fsanitize=address -O0 -g harness/main.c harness/sink_vuln.c  -o harness/clang-asan-vuln  >>runs/build.log 2>&1 || bad "build clang-asan-vuln"
    clang -fsanitize=address -O0 -g harness/main.c harness/sink_fixed.c -o harness/clang-asan-fixed >>runs/build.log 2>&1 || bad "build clang-asan-fixed"
fi

run() { # binary tag vector
    harness/"$1" "$3" >runs/"$2".out 2>&1
    printf '%s\n' "$?" >runs/"$2".rc
}

# Vulnerable pin, attack vectors.
run asan-vuln        asan-vuln-slashes        slashes
run asan-vuln        asan-vuln-empty          empty
if [ -x harness/clang-asan-vuln ]; then run clang-asan-vuln clang-asan-vuln-slashes slashes; fi
run plain-vuln       plain-vuln-slashes       slashes
run plain-vuln       plain-vuln-empty         empty
# Controls.
run asan-vuln        asan-vuln-safe           safe
run asan-fixed       asan-fixed-slashes       slashes
run asan-fixed       asan-fixed-empty         empty
if [ -x harness/clang-asan-fixed ]; then run clang-asan-fixed clang-asan-fixed-slashes slashes; fi
run plain-fixed      plain-fixed-slashes      slashes
run plain-fixed      plain-fixed-safe         safe

# Rung 3: observed one-byte heap write past the pinned allocation.
if [ "$(cat runs/asan-vuln-slashes.rc)" != "0" ] &&
   has runs/asan-vuln-slashes.out 'heap-buffer-overflow' &&
   has runs/asan-vuln-slashes.out 'WRITE of size 1' &&
   has runs/asan-vuln-slashes.out 'src/DS/sds.c:884'; then ok 'asan-vuln slashes WRITE-1 at pinned sink'; else bad 'asan-vuln slashes'; fi
if [ "$(cat runs/asan-vuln-empty.rc)" != "0" ] && has runs/asan-vuln-empty.out 'heap-buffer-overflow'; then
    ok 'asan-vuln empty vector also traps'
else
    printf 'OBS empty vector rc=%s, no ASan report (negative preserved)\n' "$(cat runs/asan-vuln-empty.rc)"
fi
if [ -f runs/clang-asan-vuln-slashes.rc ] &&
   [ "$(cat runs/clang-asan-vuln-slashes.rc)" != "0" ] &&
   has runs/clang-asan-vuln-slashes.out 'heap-buffer-overflow'; then ok 'clang-asan-vuln slashes reproduces'; else bad 'clang-asan-vuln slashes'; fi

# Fixed and safe controls must be clean.
clean=1
for t in asan-vuln-safe asan-fixed-slashes asan-fixed-empty clang-asan-fixed-slashes; do
    [ -f runs/$t.rc ] || continue
    if [ "$(cat runs/$t.rc)" != "0" ] || has runs/$t.out 'AddressSanitizer'; then clean=0; fi
done
if [ "$clean" = 1 ]; then ok 'fixed and safe vectors clean under ASan'; else bad 'fixed/safe controls'; fi

# Plain-build outcome is recorded, not assumed: no rung-1/2 claim if rc=0.
if [ -f runs/plain-vuln-slashes.rc ]; then ok 'plain-build attack outcome recorded'; else bad 'plain attack run'; fi
if has runs/plain-fixed-slashes.out 'out=[--------]'; then ok 'fixed plain output is 8 dashes'; else bad 'fixed plain output'; fi

printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
