#!/usr/bin/env bash
# Replay driver: bash lab/frontier/iondtn2shell/run.sh <outdir>
# Extracts the VERBATIM pinned ui_str_from_ac() block from ION-DTN
# nm/mgr/nm_mgr_print.c at release 4.2.0 (affected) and 4.2.1-a.2 (fixed)
# into gen_block.h with #line directives, then compiles one driver that
# executes those exact upstream statements with stubbed collaborators.
# No production statement is reimplemented; no daemon or socket is created.
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
line_is() {
  got=$(grep -nF -- "$2" "$1" | head -1 | cut -d: -f1)
  if [ "$got" = "$3" ]; then pass "$4"; else bad "$4 (line=$got)"; fi
}

cat >"$out/pinned.sha256" <<'EOF'
31b9673ccc2573da71156cca7139bdf962d718044acb0cbe9bbac7077dd12127  nm_mgr_print.420.c
c2abf2d0ff0031bb191706bc1cebb35aa680379d779b301f7a25aef1ab06084d  nm_mgr_print.421a2.c
EOF
if (cd "$here/pins" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PINNED_SOURCE_BYTES
else
  bad PINNED_SOURCE_BYTES
  cat "$out/pinned.check"
  exit 2
fi

need "$here/pins/nm_mgr_print.420.c" 'char *str = STAKE(1024);' VULN_STAKE_1024
need "$here/pins/nm_mgr_print.420.c" 'strcat(str, (alt_str==NULL) ? "null" : alt_str);' VULN_STRCAT_VALUE
need "$here/pins/nm_mgr_print.421a2.c" 'if (len >= rem) {' FIXED_CAPACITY_CHECK
need "$here/pins/nm_mgr_print.421a2.c" 'istrcat(cursor, app_str, rem);' FIXED_ISTR_CAT
line_is "$here/pins/nm_mgr_print.420.c" 'char *ui_str_from_ac(ac_t *ac)' 548 VULN_LINE_548
line_is "$here/pins/nm_mgr_print.420.c" 'char *str = STAKE(1024);' 550 VULN_LINE_550
line_is "$here/pins/nm_mgr_print.420.c" 'strcat(str, (alt_str==NULL) ? "null" : alt_str);' 557 VULN_LINE_557
line_is "$here/pins/nm_mgr_print.420.c" 'strcat(str, " ");' 558 VULN_LINE_558
line_is "$here/pins/nm_mgr_print.421a2.c" 'char *ui_str_from_ac(ac_t *ac)' 543 FIXED_LINE_543
line_is "$here/pins/nm_mgr_print.421a2.c" 'if (len >= rem) {' 564 FIXED_LINE_564
line_is "$here/pins/nm_mgr_print.421a2.c" 'istrcat(cursor, app_str, rem);' 570 FIXED_LINE_570

gen_block() {
  { echo "#line $3 \"nm_mgr_print.c\""
    sed -n "$2" "$1"
  } >"$4/gen_block.h"
}
mkdir -p "$out/vuln" "$out/fixed"
gen_block "$here/pins/nm_mgr_print.420.c" '548,563p' 548 "$out/vuln"
gen_block "$here/pins/nm_mgr_print.421a2.c" '543,588p' 543 "$out/fixed"
CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixed" -DFIXED_BUILD -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

"$out/vuln-bin" capture >"$out/vuln.out" 2>&1
needre "$out/vuln.out" 'LAYOUT stake_len=1024 values=18 value_len=80 written=1458 overflow=434 calls=1' RUNG1_UNBOUNDED_STRCAT
need "$out/vuln.out" 'CAPTURE returned=nonnull result_is_arena=1 returned_len=1458 first_changed=0 state_failure=1' RUNG2_STATE_FAILURE
for off in 1024 1088 1152 1280 1408; do
  need "$out/vuln.out" "VICTIM requested_offset=$off chosen_offset=$off supplied=494f4e3253484c21 observed=494f4e3253484c21 equal=1" "RUNG4_CHOSEN_$off"
done

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'heap-buffer-overflow' ASAN_HEAP_OVERFLOW
needre "$out/asan.out" 'WRITE of size [0-9]+' ASAN_WRITE
needre "$out/asan.out" 'nm_mgr_print.c:55[78]' ASAN_UPSTREAM_LINE
need "$out/asan.out" 'strcat' ASAN_UPSTREAM_CALL

"$out/fixed-bin" capture >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'CAPTURE returned=NULL first_changed=18446744073709551615' FIXED_NO_CALL
need "$out/fixed.out" 'FIXED_NO_WRITE marker_never_reached=1 victim_unchanged=1' FIXED_NO_WRITE

{
  printf 'pinned_affected=31b9673ccc2573da71156cca7139bdf962d718044acb0cbe9bbac7077dd12127\n'
  printf 'pinned_fixed=c2abf2d0ff0031bb191706bc1cebb35aa680379d779b301f7a25aef1ab06084d\n'
  grep -E '^(LAYOUT|CAPTURE|VICTIM|FIXED_NO_WRITE)' "$out/vuln.out"
  grep -E '^(LAYOUT|CAPTURE|FIXED_NO_WRITE)' "$out/fixed.out"
  sed -E -e 's/^==[0-9]+==//' -e 's/0x[0-9a-f]+/0xADDR/g' "$out/asan.out" \
    | grep -E 'ERROR: AddressSanitizer: heap-buffer-overflow|WRITE of size' | head -3
  grep -oE 'nm_mgr_print.c:55[78]' "$out/asan.out" | head -2
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'
  exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
