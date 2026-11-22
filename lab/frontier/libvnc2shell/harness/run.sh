#!/usr/bin/env bash
# libvnc2shell replay (GHSA-v9pm-47h4-jcq8 / CVE-2026-50538).
# Builds the verbatim pinned Tight write path from vulnerable and fixed
# commits under gcc/clang ASan and plain, runs chosen-byte + safe controls,
# asserts each observation and records normalized replay hashes.
# Loopback-free: no process talks to a network; the RFB stream is in-process.
set -u
cd "$(dirname "$0")" || exit 1

VULN=73352b9de9c0
FIXED=540332be3e0acc566fa64da6f1b4680c72c724dd
(cd ../src && sha256sum --check PIN_HASHES.txt) || exit 1

python3 gen_fn.py ../src/tight-vuln.c tight-vuln_fn.inc || exit 1
python3 gen_fn.py ../src/tight-fixed.c tight-fixed_fn.inc || exit 1

pass=0; fail=0
ok() { echo "PASS $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }
assert_contains() { if grep -qF "$2" "$1"; then ok "$3"; else no "$3"; fi; }
assert_absent()   { if grep -qF "$2" "$1"; then no "$3"; else ok "$3"; fi; }

build() { # srcinc compiler mode defs out
    cp "$1" tight_fn.inc
    local cc="$2" mode="$3" defs="$4" out="$5"
    local args=(-O0 -g -fno-omit-frame-pointer $defs -o "$out" harness.c -lz)
    if [ "$mode" = asan ]; then args+=(-fsanitize=address); fi
    if [ "$cc" = clang ]; then clang "${args[@]}" || exit 1
    else gcc "${args[@]}" || exit 1; fi
}
run() { # binary defs out
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$1" $2 > "$3" 2>&1
    echo $? > "$3.rc"
}

# --- vulnerable pin, ASan, over-expanding zlib stream (32 rows into 16) ---
build tight-vuln_fn.inc gcc asan \
  "-DFB_ALLOC=1024 -DROWS=32 -DCHOSEN_BASE=0x41" v-asan
run ./v-asan "" raw-vuln-asan.log
assert_contains raw-vuln-asan.log "ERROR: AddressSanitizer: heap-buffer-overflow" "vuln-asan-fault"
assert_contains raw-vuln-asan.log "WRITE of size 64" "vuln-asan-write-size"
assert_contains raw-vuln-asan.log "0 bytes after 1024-byte region" "vuln-asan-offset"
assert_contains raw-vuln-asan.log "in FilterCopy32" "vuln-asan-filter-frame"
assert_contains raw-vuln-asan.log "in HandleTight32" "vuln-asan-handler-frame"

# --- fixed pin: clamp rejects before the write ---
build tight-fixed_fn.inc gcc asan \
  "-DFB_ALLOC=1024 -DROWS=32 -DCHOSEN_BASE=0x41" f-asan
run ./f-asan "" raw-fixed-asan.log
assert_contains raw-fixed-asan.log "Tight: too many scan lines after decompression." "fixed-asan-log"
assert_absent   raw-fixed-asan.log "ERROR: AddressSanitizer" "fixed-asan-clean"

# --- safe control: 16 rows into a 16-row framebuffer, both pins ---
build tight-vuln_fn.inc gcc asan \
  "-DFB_ALLOC=1024 -DROWS=16 -DCHOSEN_BASE=0x41" v-safe-asan
run ./v-safe-asan "" raw-vuln-safe-asan.log
assert_absent raw-vuln-safe-asan.log "ERROR: AddressSanitizer" "vuln-safe-asan-clean"
assert_contains raw-vuln-safe-asan.log "rc=1" "vuln-safe-returns-true"

build tight-fixed_fn.inc gcc asan \
  "-DFB_ALLOC=1024 -DROWS=16 -DCHOSEN_BASE=0x41" f-safe-asan
run ./f-safe-asan "" raw-fixed-safe-asan.log
assert_absent raw-fixed-safe-asan.log "ERROR: AddressSanitizer" "fixed-safe-asan-clean"
assert_contains raw-fixed-safe-asan.log "rc=1" "fixed-safe-returns-true"

# --- plain build: chosen bytes land in the adjacent heap region ---
build tight-vuln_fn.inc gcc plain \
  "-DFB_ALLOC=2048 -DROWS=32 -DCHOSEN_BASE=0x41" v-plain
run ./v-plain "" raw-vuln-plain.log
assert_contains raw-vuln-plain.log "oob16=4142434445464748494a4b4c4d4e4f50" "vuln-plain-chosen-41"
assert_contains raw-vuln-plain.log "Incorrect number of scan lines after decompression." "vuln-postloop-too-late"

build tight-vuln_fn.inc gcc plain \
  "-DFB_ALLOC=2048 -DROWS=32 -DCHOSEN_BASE=0x5a" v-plain-alt
run ./v-plain-alt "" raw-vuln-plain-alt.log
assert_contains raw-vuln-plain-alt.log "oob16=5a5b5c5d5e5f60616263646566676869" "vuln-plain-chosen-5a"

build tight-fixed_fn.inc gcc plain \
  "-DFB_ALLOC=2048 -DROWS=32 -DCHOSEN_BASE=0x41" f-plain
run ./f-plain "" raw-fixed-plain.log
assert_contains raw-fixed-plain.log "Tight: too many scan lines after decompression." "fixed-plain-log"
assert_contains raw-fixed-plain.log "oob16=00000000000000000000000000000000" "fixed-plain-no-write"

# --- clang ASan cross-check ---
if command -v clang >/dev/null 2>&1; then
    build tight-vuln_fn.inc clang asan \
      "-DFB_ALLOC=1024 -DROWS=32 -DCHOSEN_BASE=0x41" v-clang-asan
    run ./v-clang-asan "" raw-vuln-clang-asan.log
    assert_contains raw-vuln-clang-asan.log "ERROR: AddressSanitizer: heap-buffer-overflow" "vuln-clang-asan-fault"
    assert_contains raw-vuln-clang-asan.log "0 bytes after 1024-byte region" "vuln-clang-asan-offset"
    build tight-fixed_fn.inc clang asan \
      "-DFB_ALLOC=1024 -DROWS=32 -DCHOSEN_BASE=0x41" f-clang-asan
    run ./f-clang-asan "" raw-fixed-clang-asan.log
    assert_contains raw-fixed-clang-asan.log "Tight: too many scan lines after decompression." "fixed-clang-asan-log"
    assert_absent raw-fixed-clang-asan.log "ERROR: AddressSanitizer" "fixed-clang-asan-clean"
fi

# --- normalized replay hashes ---
mkdir -p ../evidence
: > ../EVIDENCE_HASHES.txt
for f in raw-*.log; do
    n="norm-${f#raw-}"
    python3 normalize.py "$f" > "../evidence/$n"
    printf '%s  %s\n' "$(sha256sum "../evidence/$n" | cut -d' ' -f1)" "$n" >> ../EVIDENCE_HASHES.txt
done
sort -o ../EVIDENCE_HASHES.txt ../EVIDENCE_HASHES.txt

cp tight-vuln_fn.inc tight_fn.inc
echo "TOTAL $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
