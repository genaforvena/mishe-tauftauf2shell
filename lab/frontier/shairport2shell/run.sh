#!/usr/bin/env bash
# Replay driver: bash lab/frontier/shairport2shell/run.sh <outdir>
# Extracts lines 4206-4221 of the VERBATIM pinned upstream rtsp.c at the fix
# commit's parent (a50f184, affected) and the fix commit (c1c41c4, fixed) into
# gen_block.h and compiles one driver that executes those exact upstream
# statements.  No production statement is reimplemented.  Loopback only;
# no daemon is built, started or contacted.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
needre() { if grep -qE -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
line_is() { # file needle lineno label
  got=$(grep -nF -- "$2" "$1" | head -1 | cut -d: -f1)
  if [ "$got" = "$3" ]; then pass "$4"; else bad "$4 (line=$got)"; fi
}

# --- pinned source bytes (raw.githubusercontent.com; see PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
7cc04130d403a16474e6541726062e4352d6fe0fe532555362d77205a9ba8883  vuln/rtsp.c
69b23114c7e90433a9bb49378444646e5b03b39ecc79bec5c5e254d34a35fea3  fixed/rtsp.c
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PINNED_SOURCE_BYTES
else
  bad PINNED_SOURCE_BYTES
  cat "$out/pinned.check"
  exit 2
fi

# --- verbatim source assertions: exact upstream lines, no reimplementation ---
need "$here/src/vuln/rtsp.c"  '            char obf[4096];' VULN_SMALL_BUFFER
need "$here/src/fixed/rtsp.c" \
  '            char obf[2 * 4096 + 1]; // two hex chars per input byte, plus a terminating nul' \
  FIXED_BUFFER_SIZE
needre "$here/src/vuln/rtsp.c" \
  'snprintf\(obfp, 3, "%02X", \(unsigned int\)\*p\);' VULN_HEX_LOOP
line_is "$here/src/vuln/rtsp.c" '            char obf[4096];' 4208 VULN_LINE_4208
line_is "$here/src/vuln/rtsp.c" \
  '              snprintf(obfp, 3, "%02X", (unsigned int)*p);' 4215 VULN_LINE_4215
line_is "$here/src/fixed/rtsp.c" \
  '            char obf[2 * 4096 + 1]; // two hex chars per input byte, plus a terminating nul' \
  4208 FIXED_LINE_4208

# --- generate the byte-exact block with real pinned line numbers in frames ---
gen_block() { # srcfile outdir
  mkdir -p "$2"
  printf '#line 4206 "rtsp.c"\n' >"$2/gen_block.h"
  sed -n '4206,4221p' "$1" >>"$2/gen_block.h"
}
gen_block "$here/src/vuln/rtsp.c"  "$out/vuln"
gen_block "$here/src/fixed/rtsp.c" "$out/fixed"
CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -I"$out/vuln"  -o "$out/vuln-bin"  "$here/driver.c" || exit 91
gcc $CFLAGS -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixed" -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

# --- rungs 1/2: length clamp to 4096 bytes, 2 hex chars per byte ---
"$out/vuln-bin" capture >"$out/vuln.out" 2>&1
need "$out/vuln.out" \
  'LAYOUT body=4096 victim_from_obf=' RUNG1_LAYOUT
needre "$out/vuln.out" 'LAYOUT body=4096 victim_from_obf=[0-9]+ debug_calls=1 obf_written=8193' \
  RUNG1_8193_BYTES
needre "$out/vuln.out" 'CAPTURE first_changed=[0-9]+ chosen_offset=[0-9]+' RUNG2_OVERFLOW_OBSERVED
needre "$out/vuln.out" 'VICTIM requested_offset=0 chosen_offset=[0-9]+ supplied=494E4449325348454C4C' \
  RUNG4_CHOSEN_BYTES_AT_OFFSET0
needre "$out/vuln.out" 'VICTIM requested_offset=64 chosen_offset=64 supplied=494E4449325348454C4C' \
  RUNG4_CHOSEN_BYTES_AT_OFFSET64
if grep -q 'DELTA_MISMATCH' "$out/vuln.out"; then bad STACK_DELTA_STABLE; else pass STACK_DELTA_STABLE; fi

# --- rung 3: ASan-confirmed stack corruption in the verbatim upstream loop ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
needre "$out/asan.out" 'WRITE of size [0-9]+' ASAN_WRITE
needre "$out/asan.out" 'hexdump_unrecognised.*rtsp.c:4215' ASAN_UPSTREAM_LINE
needre "$out/asan.out" 'snprintf' ASAN_UPSTREAM_CALL

# --- fixed control: 2*4096+1 buffer bounds the same loop ---
"$out/fixed-bin" capture >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'CAPTURE first_changed=-1 chosen_offset=-1' FIXED_NEIGHBOUR_CLEAN
needre "$out/fixed.out" 'obf_written=8193' FIXED_SAME_INPUT

# --- deterministic trace: emit canonical lines, never raw ASan PID/path text ---
{
  echo 'PINNED'; cat "$out/pinned.check"
  echo 'VULN'; cat "$out/vuln.out"
  echo 'ASAN'
  grep -qF 'stack-buffer-overflow' "$out/asan.out" && echo 'ASAN stack-buffer-overflow'
  grep -qE 'WRITE of size [0-9]+' "$out/asan.out" && echo 'ASAN WRITE of size 3'
  grep -qE 'hexdump_unrecognised.*rtsp.c:4215' "$out/asan.out" \
    && echo 'ASAN frame hexdump_unrecognised rtsp.c:4215'
  grep -qF "'obf'" "$out/asan.out" && echo 'ASAN victim obf'
  echo 'FIXED'; cat "$out/fixed.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASS rc 0'
  exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
