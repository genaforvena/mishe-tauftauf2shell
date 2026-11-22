#!/usr/bin/env bash
# libssh2 CVE-2026-66035 replay. Builds vuln/fixed pins under gcc and clang,
# ASan and plain, runs chosen-byte and safe controls, asserts each result and
# records normalized hashes. Loopback-only, no network or daemon involved.
set -u
cd "$(dirname "$0")" || exit 1

VULN=edec1cce27a309399a9d174b73fef9b997148fbb
FIXED=42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4
sha256sum --check ../pins/PIN_HASHES.txt || exit 1

python3 gen_fn.py ../pins/transport-vuln.c transport-vuln_fn.inc
python3 gen_fn.py ../pins/transport-fixed.c transport-fixed_fn.inc

pass=0; fail=0
ok() { echo "PASS $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }
assert_contains() { if grep -qF "$2" "$1"; then ok "$3"; else no "$3"; fi; }
assert_absent() { if grep -qF "$2" "$1"; then no "$3"; else ok "$3"; fi; }

build() { # srcinc compiler sanitizer extra-defines out
    cp "$1" transport_fn.inc
    local cc="$2" san="$3" defs="$4" out="$5"
    local args=(-O0 -g -fno-omit-frame-pointer $defs -o "$out" harness.c)
    if [ "$san" = asan ]; then args+=(-fsanitize=address); fi
    if [ "$cc" = clang ]; then
        clang "${args[@]}" || exit 1
    else
        gcc "${args[@]}" || exit 1
    fi
}

run() { # binary total_num chosen_base out
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$1" > "$4" 2>&1
    echo $? > "$4.rc"
}

export -f assert_contains assert_absent ok no

# gcc ASan, chosen small packet (total_num=28 -> decrypt_size=4, memcpy 15)
build transport-vuln_fn.inc gcc asan "-DTOTAL_NUM=28" v-asan
run ./v-asan 28 0x41 raw-vuln-asan.log
assert_contains raw-vuln-asan.log "ERROR: AddressSanitizer: heap-buffer-overflow" "vuln-asan-fault"
assert_contains raw-vuln-asan.log "WRITE of size 15" "vuln-asan-write-size"
assert_contains raw-vuln-asan.log "0 bytes after 4-byte region" "vuln-asan-offset"
assert_contains raw-vuln-asan.log "in transport_fullpacket" "vuln-asan-frame"

build transport-fixed_fn.inc gcc asan "-DTOTAL_NUM=28" f-asan
run ./f-asan 28 0x41 raw-fixed-asan.log
assert_contains raw-fixed-asan.log "rc=-18" "fixed-asan-reject"
assert_absent raw-fixed-asan.log "ERROR: AddressSanitizer" "fixed-asan-clean"

# gcc ASan safe input (total_num=64 -> decrypt_size=40, memcpy fits)
build transport-vuln_fn.inc gcc asan "-DTOTAL_NUM=64" v-safe-asan
run ./v-safe-asan 64 0x41 raw-vuln-safe-asan.log
assert_absent raw-vuln-safe-asan.log "ERROR: AddressSanitizer" "vuln-safe-asan-clean"
assert_contains raw-vuln-safe-asan.log "decrypt_size=40" "vuln-safe-size"

build transport-fixed_fn.inc gcc asan "-DTOTAL_NUM=64" f-safe-asan
run ./f-safe-asan 64 0x41 raw-fixed-safe-asan.log
assert_absent raw-fixed-safe-asan.log "ERROR: AddressSanitizer" "fixed-safe-asan-clean"

# gcc plain, chosen bytes in readback; alternate base proves chosen control
build transport-vuln_fn.inc gcc plain "-DTOTAL_NUM=28 -DCHOSEN_BASE=0x41" v-plain
run ./v-plain 28 0x41 raw-vuln-plain.log
assert_contains raw-vuln-plain.log "readback=4142434445464748494a4b4c4d4e4f" "vuln-plain-chosen"

build transport-vuln_fn.inc gcc plain "-DTOTAL_NUM=28 -DCHOSEN_BASE=0x5a" v-plain-alt
run ./v-plain-alt 28 0x5a raw-vuln-plain-alt.log
assert_contains raw-vuln-plain-alt.log "readback=5a5b5c5d5e5f606162636465666768" "vuln-plain-alt-chosen"

build transport-fixed_fn.inc gcc plain "-DTOTAL_NUM=28 -DCHOSEN_BASE=0x41" f-plain
run ./f-plain 28 0x41 raw-fixed-plain.log
assert_contains raw-fixed-plain.log "rc=-18" "fixed-plain-reject"
assert_absent raw-fixed-plain.log "readback=41" "fixed-plain-no-write"

# clang ASan cross-check
if command -v clang >/dev/null 2>&1; then
    build transport-vuln_fn.inc clang asan "-DTOTAL_NUM=28" v-clang-asan
    run ./v-clang-asan 28 0x41 raw-vuln-clang-asan.log
    assert_contains raw-vuln-clang-asan.log "ERROR: AddressSanitizer: heap-buffer-overflow" "vuln-clang-asan-fault"
    assert_contains raw-vuln-clang-asan.log "0 bytes after 4-byte region" "vuln-clang-asan-offset"
    build transport-fixed_fn.inc clang asan "-DTOTAL_NUM=28" f-clang-asan
    run ./f-clang-asan 28 0x41 raw-fixed-clang-asan.log
    assert_contains raw-fixed-clang-asan.log "rc=-18" "fixed-clang-asan-reject"
    assert_absent raw-fixed-clang-asan.log "ERROR: AddressSanitizer" "fixed-clang-asan-clean"
fi

mkdir -p ../evidence
: > ../EVIDENCE_HASHES.txt
for f in raw-*.log; do
    n="norm-${f#raw-}"
    python3 normalize.py "$f" > "../evidence/$n"
    printf '%s  %s\n' "$(sha256sum "../evidence/$n" | cut -d' ' -f1)" "$n" >> ../EVIDENCE_HASHES.txt
done
sort -o ../EVIDENCE_HASHES.txt ../EVIDENCE_HASHES.txt

cp transport-vuln_fn.inc transport_fn.inc
echo "TOTAL $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
