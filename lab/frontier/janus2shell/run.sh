#!/usr/bin/env bash
# Replay: bash lab/frontier/janus2shell/run.sh <outdir>
# Executes VERBATIM pinned .mjr info-header parse blocks from Janus
# src/plugins/janus_recordplay.c at tag v1.4.2 (vulnerable) and v1.4.3
# (fixed by e55e2915a2801f18495c7f0d049af9274dd70065). Stubbed collaborators
# and an in-memory .mjr stream; no daemon, HTTP API, SDP parser, socket or
# network is used.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)
p="$here/pins"
fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
needre() { if grep -qE -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
line_has() {
  if [ "$(sed -n "${2}p" "$1")" = "$3" ]; then pass "$4"; else bad "$4"; fi
}
gen_block() { # file first last outdir #line-name
  {
    printf '#line %s "%s"\n' "$2" "$5"
    sed -n "${2},${3}p" "$1"
  } >>"$4"
}

cat >"$out/pinned.sha256" <<'EOF'
c06e9396b593f384b3ab9b65a3a4ec3be9dada397c1bec86d8c5b01db55c4a98  janus_recordplay.142.c
745c414595c874d961a220c3d194769a2172c9e57fbe809d9ee3dd2dca7bad6e  janus_recordplay.143.c
badbecd6dfc03d5a6e627c3882415045a4b1cfa585f8f3915a9ec42f39362827  janus_recordplay.0162.c
892746e3f6c608cd5c47935c3dacdc7fc21a745a165abff4ff4bebdf6187222a  janus_recordplay.0163.c
bc7e951fef14dfd1d98b099f253c1549aa211d855bbed710d02108569d26ae62  fix.1.4.patch
EOF
if (cd "$p" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PIN_SHA256
else
  bad PIN_SHA256
fi

v="$p/janus_recordplay.142.c"
f="$p/janus_recordplay.143.c"
line_has "$v" 664 '	char prebuffer[1500];' VULN_BUFFER_PIN
line_has "$v" 670 '		bytes = fread(prebuffer, sizeof(char), 8, file);' VULN_MAGIC_PIN
line_has "$v" 701 '			offset += 8;' VULN_OFFSET_PIN
line_has "$v" 703 '			len = ntohs(len);' VULN_LEN_PIN
line_has "$v" 707 '				bytes = fread(prebuffer, sizeof(char), len, file);' VULN_SINK_PIN
line_has "$v" 714 '				prebuffer[len] = '"'"'\0'"'"';' VULN_TERMINATOR_PIN
line_has "$f" 707 '				if(len >= sizeof(prebuffer)) {' FIXED_GUARD_PIN
line_has "$f" 708 '					JANUS_LOG(LOG_ERR, "Info header too big (%"SCNu16" bytes), invalid recording\n", len);' FIXED_GUARD_LOG_PIN
line_has "$f" 712 '				bytes = fread(prebuffer, sizeof(char), len, file);' FIXED_SINK_PIN
line_has "$f" 719 '				prebuffer[len] = '"'"'\0'"'"';' FIXED_TERMINATOR_PIN
line_has "$p/janus_recordplay.0162.c" 712 '				prebuffer[len] = '"'"'\0'"'"';' LEGACY_VULN_PIN
line_has "$p/janus_recordplay.0163.c" 705 '				if(len >= sizeof(prebuffer)) {' LEGACY_FIXED_PIN

mkdir -p "$out/vuln" "$out/fixed"
: >"$out/vuln/gen_sink.h"
gen_block "$v" 669 670 "$out/vuln/gen_sink.h" "src/plugins/janus_recordplay.c"
gen_block "$v" 701 707 "$out/vuln/gen_sink.h" "src/plugins/janus_recordplay.c"
cat >>"$out/vuln/gen_sink.h" <<'OBS'
/* INSTRUMENTATION — not upstream source: observe chosen bytes immediately
 * after the pinned fread, before this lab frame's epilogue. The non-ASan
 * run can fault at return when the write reaches saved frame state. */
  if(strcmp(mode, "chosen") == 0) {
#ifndef __SANITIZE_ADDRESS__
    unsigned char observed[16], expected[16];
    size_t oi;
    for(oi = 0; oi < 16; oi++) {
      observed[oi] = (unsigned char)prebuffer[1500 + oi];
      expected[oi] = mjr[10 + 1500 + oi];
    }
    printf("LAYOUT build=vuln mode=chosen cap=1500 requested=%u bytes=%d overflow=%zu rejected=%d adjacent_len=%u ADJACENT_LOCAL_OVERWRITTEN=%d\n",
           (unsigned)g_requested_len, bytes,
           (size_t)g_requested_len > 1500 ? (size_t)g_requested_len - 1500 : 0,
           g_rejected, (unsigned)len, len != g_requested_len ? 1 : 0);
    printf("CHOSEN observed=");
    for(oi = 0; oi < 16; oi++) printf("%02x", observed[oi]);
    printf("\nCHOSEN expected=");
    for(oi = 0; oi < 16; oi++) printf("%02x", expected[oi]);
    printf("\nCHOSEN_MATCH=%d\n", memcmp(observed, expected, 16) == 0 ? 1 : 0);
    fflush(stdout);
#endif
  }
OBS
gen_block "$v" 708 714 "$out/vuln/gen_sink.h" "src/plugins/janus_recordplay.c"
: >"$out/fixed/gen_sink.h"
gen_block "$f" 669 670 "$out/fixed/gen_sink.h" "src/plugins/janus_recordplay.c"
gen_block "$f" 701 719 "$out/fixed/gen_sink.h" "src/plugins/janus_recordplay.c"
if grep -q 'bytes = fread(prebuffer, sizeof(char), len, file);' "$out/vuln/gen_sink.h" &&
   grep -q 'if(len >= sizeof(prebuffer))' "$out/fixed/gen_sink.h" &&
   ! grep -q 'if(len >= sizeof(prebuffer))' "$out/vuln/gen_sink.h"; then
  pass PINNED_BLOCKS_EXTRACTED
else
  bad PINNED_BLOCKS_EXTRACTED
fi

CFLAGS='-std=gnu11 -O0 -g -Wall -fno-omit-frame-pointer -fno-stack-protector'
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -fsanitize=address -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixed" -o "$out/fixed-bin" "$here/driver.c" || exit 93
# Control: the same pinned sink with the compiler's default stack protector.
gcc -std=gnu11 -O0 -g -Wall -fno-omit-frame-pointer -DVULN_BUILD \
  -I"$out/vuln" -o "$out/protected-bin" "$here/driver.c" || exit 94
pass COMPILE

"$out/protected-bin" chosen >"$out/protected.out" 2>&1
protrc=$?
if [ "$protrc" -ne 0 ]; then pass PROTECTED_NONZERO_RC; else bad PROTECTED_NONZERO_RC; fi
need "$out/protected.out" 'stack smashing detected' PROTECTED_CANARY_DETECTED

"$out/vuln-bin" benign >"$out/benign.out" 2>&1
needre "$out/benign.out" 'LAYOUT build=vuln mode=benign cap=1500 requested=100 bytes=100 overflow=0 rejected=0 adjacent_len=100 ADJACENT_LOCAL_OVERWRITTEN=0' RUNG1_BENIGN_NO_OVERFLOW
need "$out/benign.out" 'ACCEPT mode=benign rejected=0' BENIGN_ACCEPTED

"$out/vuln-bin" chosen >"$out/chosen.out" 2>&1
needre "$out/chosen.out" 'LAYOUT build=vuln mode=chosen cap=1500 requested=1986 bytes=1986 overflow=486 rejected=0 adjacent_len=[0-9]+ ADJACENT_LOCAL_OVERWRITTEN=1' RUNG1_UNBOUNDED_WRITE
need "$out/chosen.out" 'CHOSEN_MATCH=1' RUNG4_CHOSEN_BYTES
need "$out/chosen.out" 'ADJACENT_LOCAL_OVERWRITTEN=1' RUNG4_ADJACENT_LOCAL_CONTROL

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=1 "$out/asan-bin" chosen >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
need "$out/asan.out" 'janus_recordplay.c:707' ASAN_PINNED_WRITE_LINE
need "$out/asan.out" 'WRITE of size' ASAN_WRITE_SIZE

"$out/fixed-bin" chosen >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'REJECT mode=chosen rejected=1' FIXED_GUARD_REJECT
need "$out/fixed.out" 'Info header too big' FIXED_GUARD_LOG_OBSERVED
"$out/fixed-bin" benign >"$out/fixed_benign.out" 2>&1
need "$out/fixed_benign.out" 'LAYOUT build=fixed mode=benign cap=1500 requested=100 bytes=100 overflow=0 rejected=0 adjacent_len=100 ADJACENT_LOCAL_OVERWRITTEN=0' FIXED_BENIGN_OK

{
  printf 'pins: '
  cat "$out/pinned.check" | tr '\n' ' '; printf '\n'
  printf 'vuln-benign: '; cat "$out/benign.out"; printf '\n'
  printf 'vuln-chosen: '; cat "$out/chosen.out"; printf '\n'
  printf 'vuln-stack-protector: '; cat "$out/protected.out"; printf '\n'
  printf 'fixed-chosen: '; cat "$out/fixed.out"; printf '\n'
  printf 'fixed-benign: '; cat "$out/fixed_benign.out"; printf '\n'
  printf 'asan-diagnostic: '
  grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow' "$out/asan.out" && printf 'ERROR=stack-buffer-overflow|'
  grep -q 'WRITE of size 1986' "$out/asan.out" && printf 'WRITE=1986|'
  grep -q 'src/plugins/janus_recordplay.c:707' "$out/asan.out" && printf 'FRAME=janus_recordplay.c:707|'
  grep -q 'SUMMARY: AddressSanitizer: stack-buffer-overflow' "$out/asan.out" && printf 'SUMMARY=stack-buffer-overflow|'
  printf '\n'
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'; exit 0
fi
echo 'SOME CHECKS FAILED rc 1'; exit 1
