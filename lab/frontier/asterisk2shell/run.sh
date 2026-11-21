#!/usr/bin/env bash
# Replay driver: bash lab/frontier/asterisk2shell/run.sh <outdir>
# Extracts lines 35-53 of the VERBATIM pinned upstream ootrace.c at the fix
# commit's parent (661d6a2f, affected, byte-identical to release 23.4.0) and
# lines 35-57 at the fix commit (2d7b8c8, fixed) into gen_block.h with a
# #line 35 "ootrace.c" directive, then compiles one driver that executes those
# exact upstream statements.  No production statement is reimplemented.
# Loopback only; no daemon is built, started or contacted.
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
5d2cd33e1d51251759a70b8b8f65dd89a1a207eb889f50f9979923699fa46e5b  ootrace.affected.c
a5158c90bfa2f07eeb53d4fced5b1eb5ef789fb60841c8798e4357ec0a9b8122  ootrace.fixed.c
3e0d049d544302c597c3fecea29783d642aa10c1ea536e2a2862f1d5fbf9dcee  ootrace.h
EOF
if (cd "$here/pins" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PINNED_SOURCE_BYTES
else
  bad PINNED_SOURCE_BYTES
  cat "$out/pinned.check"
  exit 2
fi

need "$here/pins/ootrace.fixed.c" '   char *logMessage = NULL;' FIXED_HEAP_POINTER
need "$here/pins/ootypes.h" '#define MAXLOGMSGLEN 2048' PIN_MAXLOGMSGLEN_2048
need "$here/pins/ootrace.h" '#define TRACELVL 1' PIN_TRACELVL_1

# --- verbatim source assertions: exact upstream lines, no reimplementation ---
need "$here/pins/ootrace.affected.c" '   char logMessage[MAXLOGMSGLEN];' VULN_SMALL_BUFFER
needre "$here/pins/ootrace.affected.c" '   vsprintf\(logMessage, fmtspec, arglist\);' VULN_VSPRINTF

need "$here/pins/ootrace.fixed.c" 'ast_vasprintf(&logMessage, fmtspec, arglist)' FIXED_VASPRINTF
line_is "$here/pins/ootrace.affected.c" 'static OOUINT32 gs_traceLevel = TRACELVL;' 35 VULN_LINE_35
line_is "$here/pins/ootrace.affected.c" '   char logMessage[MAXLOGMSGLEN];' 46 VULN_LINE_46
line_is "$here/pins/ootrace.affected.c" '   vsprintf(logMessage, fmtspec, arglist);' 50 VULN_LINE_50
line_is "$here/pins/ootrace.fixed.c" '   res = ast_vasprintf(&logMessage, fmtspec, arglist);' 50 FIXED_LINE_50

# --- generate the byte-exact block with real pinned line numbers in frames ---
gen_block() { # srcfile firstline lastline outdir
  { echo "#line $2 \"ootrace.c\""
    sed -n "$2,$3p" "$1"
  } >"$4/gen_block.h"
}
mkdir -p "$out/vuln" "$out/fixed"
gen_block "$here/pins/ootrace.affected.c" 35 53 "$out/vuln"
gen_block "$here/pins/ootrace.fixed.c" 35 57 "$out/fixed"
CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -I"$out/vuln"  -o "$out/vuln-bin"  "$here/driver.c" || exit 91
gcc $CFLAGS -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixed" -DFIXED_BUILD -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

# --- rungs 1/2: unbounded vsprintf writes past the 2048-byte stack buffer ---
"$out/vuln-bin" capture >"$out/vuln.out" 2>&1
needre "$out/vuln.out" 'LAYOUT body=2432 victim_from_logMessage=[0-9]+ calls=1 written=2433' \
  RUNG1_LAYOUT
needre "$out/vuln.out" 'VICTIM requested_offset=0 chosen_offset=[0-9]+ supplied=415354325348454C4C' \
  RUNG4_CHOSEN_BYTES_AT_OFFSET0
needre "$out/vuln.out" 'VICTIM requested_offset=64 chosen_offset=[0-9]+ supplied=415354325348454C4C' \
  RUNG4_CHOSEN_BYTES_AT_OFFSET64

if grep -q 'DELTA_MISMATCH' "$out/vuln.out"; then bad STACK_DELTA_STABLE; else pass STACK_DELTA_STABLE; fi

# --- rung 3: ASan-confirmed stack corruption in the verbatim upstream call ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
needre "$out/asan.out" 'WRITE of size [0-9]+' ASAN_WRITE
needre "$out/asan.out" 'ootrace.c:50' ASAN_UPSTREAM_LINE
need "$out/asan.out" 'vsprintf' ASAN_UPSTREAM_CALL
need "$out/asan.out" "'logMessage'" ASAN_VICTIM_NAME

# --- fixed control: ast_vasprintf bounds the same input on the heap ---
"$out/fixed-bin" capture >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'CAPTURE first_changed=-1 chosen_offset=-1' FIXED_NEIGHBOUR_CLEAN
need "$out/fixed.out" 'victim_from_logMessage=NA calls=1 written=2433 captured_len=2432' \
  FIXED_SAME_INPUT

# --- deterministic trace: canonical lines only, never raw ASan PID/path text ---
{
  echo 'PINNED'; cat "$out/pinned.check"
  echo 'VULN'; cat "$out/vuln.out"
  echo 'ASAN'
  grep -qF 'stack-buffer-overflow' "$out/asan.out" && echo 'ASAN stack-buffer-overflow'
  grep -qE 'WRITE of size [0-9]+' "$out/asan.out" && echo 'ASAN WRITE of size 2433'
  grep -qF 'ootrace.c:50' "$out/asan.out" && echo 'ASAN frame ooTrace ootrace.c:50'
  grep -qF 'vsprintf' "$out/asan.out" && echo 'ASAN call vsprintf'
  grep -qF "'logMessage'" "$out/asan.out" && echo "ASAN victim logMessage"
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
