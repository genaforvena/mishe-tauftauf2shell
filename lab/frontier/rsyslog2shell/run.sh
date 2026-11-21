#!/usr/bin/env bash
# Replay: bash lab/frontier/rsyslog2shell/run.sh <outdir>
# Executes VERBATIM pinned auth-buffer code from rsyslog contrib/imhttp/imhttp.c
# at v8.2602.0 (vulnerable: calloc(0, len) -> apr_base64_decode) and v8.2604.0
# (fixed: bounded fixed-size stack buffer). Stubbed CivetWeb connection,
# authentic libaprutil decode_len, in-memory Authorization header; no rsyslog
# process, HTTP server, socket or network is used.
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
gen_block() { # file first last out #line-name
  {
    printf '#line %s "%s"\n' "$2" "$5"
    sed -n "${2},${3}p" "$1"
  } >>"$4"
}

cat >"$out/pinned.sha256" <<'EOF'
4e4a9d2c0ad5e55324fe922d768942d2973aca7298e813c8051f63dc7461ee25  imhttp.82020.c
48f69a6fa57c2d4bdd8f12ce83a647f35db9db968f4dce699bdb3ea4d0d9ba8c  imhttp.82040.c
f1935dd2dfeb76a6b115fdb64921b8674fc094fd803877b31b55e78ff26d9ff4  fix.acde2ba.patch
EOF
if (cd "$p" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PIN_SHA256
else
  bad PIN_SHA256
fi

v="$p/imhttp.82020.c"
f="$p/imhttp.82040.c"
line_has "$v" 62 '#define IMHTTP_MAX_BUF_LEN (8192)' VULN_CAP_PIN
line_has "$v" 71 'struct auth_s {' VULN_STRUCT_PIN
line_has "$v" 72 '    char workbuf[IMHTTP_MAX_BUF_LEN];' VULN_WORKBUF_PIN
line_has "$v" 687 'static int parse_auth_header(struct mg_connection *conn, struct auth_s *auth) {' VULN_FN_PIN
line_has "$v" 699 '    size_t len = apr_base64_decode_len((const char *)src);' VULN_LEN_PIN
line_has "$v" 701 '    if (len > sizeof(auth->workbuf)) {' VULN_BRANCH_PIN
line_has "$v" 702 '        auth->pworkbuf = calloc(0, len);' VULN_ZERO_ALLOC_PIN
line_has "$v" 703 '        auth->workbuf_len = len;' VULN_LEN_SAVE_PIN
line_has "$v" 705 '    len = apr_base64_decode(auth->pworkbuf, src);' VULN_SINK_PIN
line_has "$f" 68 '#define BASIC_AUTH_MAX_ENCODED 2048' FIXED_ENCODED_CAP_PIN
line_has "$f" 69 '#define BASIC_AUTH_MAX_DECODED ((BASIC_AUTH_MAX_ENCODED / 4) * 3)' FIXED_DECODED_CAP_PIN
line_has "$f" 79 '    char workbuf[BASIC_AUTH_MAX_DECODED + 1];' FIXED_WORKBUF_PIN
line_has "$f" 774 'static sbool parse_basic_auth_header(struct mg_connection *conn, struct auth_s *auth) {' FIXED_FN_PIN
line_has "$f" 786 '    if (encoded_len > BASIC_AUTH_MAX_ENCODED) {' FIXED_GUARD_PIN
line_has "$f" 792 '    size_t len = apr_base64_decode(auth->workbuf, src);' FIXED_SINK_PIN
line_has "$f" 793 '    if (len == 0 || len > BASIC_AUTH_MAX_DECODED) {' FIXED_LEN_GUARD_PIN
if grep -qF -- '-        auth->pworkbuf = calloc(0, len);' "$p/fix.acde2ba.patch"; then
  pass FIX_COMMIT_REMOVES_ZERO_ALLOC
else
  bad FIX_COMMIT_REMOVES_ZERO_ALLOC
fi

mkdir -p "$out/vuln" "$out/fixed"
: >"$out/vuln/gen_auth.h"
cat >>"$out/vuln/gen_auth.h" <<'HDR'
/* HARNESS — not upstream source. APR decode_len is authentic; the decode sink
 * is an instrumented equivalent compiled into driver.c so ASan sees the write. */
#define apr_base64_decode lab_base64_decode
HDR
gen_block "$v" 71 77 "$out/vuln/gen_auth.h" "contrib/imhttp/imhttp.c"
gen_block "$v" 687 705 "$out/vuln/gen_auth.h" "contrib/imhttp/imhttp.c"
cat >>"$out/vuln/gen_auth.h" <<'OBS'
/* INSTRUMENTATION — not upstream source: observe chosen bytes immediately
 * after the pinned decode, before the overflow can disturb heap state. */
if (strcmp(g_mode, "chosen") == 0) {
#ifndef __SANITIZE_ADDRESS__
  size_t oi;
  printf("LAYOUT build=vuln mode=chosen cap=%zu requested=%zu bytes=%zu dynamic=%d overflow=%zu usable=%zu\n",
         sizeof(auth->workbuf), g_expected_len, len,
         auth->pworkbuf != auth->workbuf ? 1 : 0,
         auth->pworkbuf != auth->workbuf ? (size_t)len : 0,
         malloc_usable_size(auth->pworkbuf));
  printf("CHOSEN observed=");
  for (oi = 0; oi < 16; oi++) printf("%02x", (unsigned char)auth->pworkbuf[oi]);
  printf("\nCHOSEN expected=");
  for (oi = 0; oi < 16; oi++) printf("%02x", g_expected[oi]);
  printf("\nCHOSEN_MATCH=%d\n", memcmp(auth->pworkbuf, g_expected, 16) == 0 ? 1 : 0);
  fflush(stdout);
#endif
}
OBS
gen_block "$v" 706 720 "$out/vuln/gen_auth.h" "contrib/imhttp/imhttp.c"

: >"$out/fixed/gen_auth.h"
cat >>"$out/fixed/gen_auth.h" <<'HDR'
/* HARNESS — not upstream source: same decoder equivalence as the vuln build. */
#define apr_base64_decode lab_base64_decode
HDR
gen_block "$f" 78 83 "$out/fixed/gen_auth.h" "contrib/imhttp/imhttp.c"
gen_block "$f" 774 811 "$out/fixed/gen_auth.h" "contrib/imhttp/imhttp.c"

if grep -q 'auth->pworkbuf = calloc(0, len);' "$out/vuln/gen_auth.h" &&
   grep -q 'len = apr_base64_decode(auth->pworkbuf, src);' "$out/vuln/gen_auth.h" &&
   grep -q 'encoded_len > BASIC_AUTH_MAX_ENCODED' "$out/fixed/gen_auth.h" &&
   ! grep -q 'calloc(0, len)' "$out/fixed/gen_auth.h"; then
  pass PINNED_BLOCKS_EXTRACTED
else
  bad PINNED_BLOCKS_EXTRACTED
fi

INC='-I/usr/include/apr-1.0'
LIB='-laprutil-1'
CFLAGS='-std=gnu11 -O0 -g -Wall -fno-omit-frame-pointer'
gcc $CFLAGS -DVULN_BUILD $INC -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" $LIB || exit 91
gcc $CFLAGS -DVULN_BUILD $INC -I"$out/vuln" -fsanitize=address -o "$out/asan-bin" "$here/driver.c" $LIB || exit 92
gcc $CFLAGS $INC -I"$out/fixed" -o "$out/fixed-bin" "$here/driver.c" $LIB || exit 93
pass COMPILE

"$out/vuln-bin" benign >"$out/benign.out" 2>&1
need "$out/benign.out" 'APR_EQUIV lab=100 real=100 bytes_match=1' APR_EQUIV_BENIGN
needre "$out/benign.out" 'INPUT mode=benign payload=100 encoded=[0-9]+ apr_decode_len=[0-9]+ cap=8192' RUNG1_BENIGN_INPUT
need "$out/benign.out" 'RESULT build=vuln mode=benign rc=1 dynamic=0' RUNG1_BENIGN_STACK_BUFFER

"$out/vuln-bin" chosen >"$out/chosen.out" 2>&1
chosen_rc=$?
printf 'vuln-chosen-rc=%d\n' "$chosen_rc"
need "$out/chosen.out" 'APR_EQUIV lab=9000 real=9000 bytes_match=1' APR_EQUIV_CHOSEN
needre "$out/chosen.out" 'INPUT mode=chosen payload=9000 encoded=12000 apr_decode_len=[0-9]+ cap=8192' RUNG1_CHOSEN_INPUT
needre "$out/chosen.out" 'LAYOUT build=vuln mode=chosen cap=8192 requested=9000 bytes=9000 dynamic=1 overflow=9000 usable=[0-9]+' RUNG1_UNBOUNDED_WRITE
need "$out/chosen.out" 'CHOSEN_MATCH=1' RUNG4_CHOSEN_BYTES
needre "$out/chosen.out" 'CHOSEN observed=54535253595348454c4c212121212121' RUNG4_MARKER_BYTES

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=1 "$out/asan-bin" chosen >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' ASAN_HEAP_OVERFLOW
need "$out/asan.out" 'WRITE of size' ASAN_WRITE_SIZE
need "$out/asan.out" 'contrib/imhttp/imhttp.c:705' ASAN_PINNED_SINK_LINE

"$out/fixed-bin" chosen >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'FIXED_LOG imhttp: rejecting oversized Basic-auth header (12000 bytes, max 2048 bytes)' FIXED_GUARD_LOG
need "$out/fixed.out" 'RESULT build=fixed mode=chosen rc=0 user=(null)' FIXED_GUARD_REJECT
"$out/fixed-bin" benign >"$out/fixed_benign.out" 2>&1
need "$out/fixed.out" 'APR_EQUIV lab=9000 real=9000 bytes_match=1' FIXED_APR_EQUIV
needre "$out/fixed_benign.out" 'RESULT build=fixed mode=benign rc=0 user=' FIXED_BENIGN_OK

{
  printf 'pins: '; cat "$out/pinned.check" | tr '\n' ' '; printf '\n'
  printf 'vuln-benign: '; cat "$out/benign.out"; printf '\n'
  printf 'vuln-chosen: '; cat "$out/chosen.out"; printf '\n'
  printf 'asan-diagnostic: '
  grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$out/asan.out" && printf 'ERROR=heap-buffer-overflow|'
  grep -qE 'WRITE of size [0-9]+' "$out/asan.out" && printf 'WRITE=YES|'
  grep -q 'contrib/imhttp/imhttp.c:705' "$out/asan.out" && printf 'FRAME=imhttp.c:705|'
  grep -q 'SUMMARY: AddressSanitizer: heap-buffer-overflow' "$out/asan.out" && printf 'SUMMARY=heap-buffer-overflow|'
  printf '\n'
  printf 'fixed-chosen: '; cat "$out/fixed.out"; printf '\n'
  printf 'fixed-benign: '; cat "$out/fixed_benign.out"; printf '\n'
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'; exit 0
fi
echo 'SOME CHECKS FAILED rc 1'; exit 1
