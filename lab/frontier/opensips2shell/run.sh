#!/usr/bin/env bash
# Replay: bash lab/frontier/opensips2shell/run.sh <outdir>
# Extracts VERBATIM pinned lines from OpenSIPS modules/xmpp/xmpp.h, xmpp.c and
# xmpp_server.c at tag 4.0.1 (vulnerable) and tag 4.0.2 (fixed by ec24165),
# then compiles drivers that execute those exact statements with stubbed
# collaborators. No daemon, socket, XML parser or network is created.
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
line_has() {
  local text
  text=$(sed -n "$2 p" "$1")
  if printf '%s' "$text" | grep -qF -- "$3"; then
    pass "$4"
  else
    printf 'FAIL %s (line %s: %s)\n' "$4" "$2" "$text"
    bad "$4"
  fi
}
gen_block() {
  { printf '#line %s "%s"\n' "$2" "$5"
    sed -n "$2,$3 p" "$1"
  } > "$4"
}

cat >"$out/pinned.sha256" <<'EOF'
90206e1f7c24e4ec5e5a682bba3f570c70581896c9e5e979019a9fec6fd62efa  config.402.h
1f9bef407bff401142243dfd1a628322e25c0382a26439a755249b6020d628e0  xmpp.c.4.0.1.c
ce3d681a73991318a17b806d7450f17f49c1f8e99163e7965fdbc4c372d32972  xmpp.c.4.0.2.c
1533677b92768ea13efc324a452ca4e2c7b8b0ef475f228588d6179ce55481bc  xmpp.h.4.0.1.c
10c856117666dfd3fe4f1f16a8bfac984b58092a50d6690ae3d803c1a3d8c25f  xmpp.h.4.0.2.c
750abf2fc553bc6a2defc492b2db93ea0603566f5392ab20e18c6597905b68c5  xmpp_server.c.4.0.1.c
d9fe0f6b8737ea1d69c8146ec1c374bcef5d537c5cbb43115587fcb10797e38a  xmpp_server.c.4.0.2.c
EOF
if (cd "$here/pins" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PIN_SHA256
else
  cat "$out/pinned.check"
  bad PIN_SHA256
fi

p="$here/pins"
line_has "$p/xmpp.h.4.0.1.c" 73 '#define ENC_SIP_URI(dst, buf, src)' VULN_MACRO
line_has "$p/xmpp.h.4.0.1.c" 81 'sprintf(buf, "sip:%s", src);' VULN_SPRINTF
line_has "$p/xmpp.c.4.0.1.c" 283 'char buf_from[256];' VULN_SMALL_STACK_BUFFER
line_has "$p/xmpp.c.4.0.1.c" 285 'ENC_SIP_URI(fromstr, buf_from, from);' VULN_CALL_SITE
line_has "$p/xmpp_server.c.4.0.1.c" 361 '!strcmp(tag, "message")' VULN_UNAUTH_STANZA
line_has "$p/xmpp_server.c.4.0.1.c" 382 'xmpp_send_sip_msg(from, to, msg);' VULN_UNAUTH_SINK
line_has "$p/xmpp.h.4.0.2.c" 46 'xmpp_encode_sip_uri' FIXED_BOUNDED_HELPER
line_has "$p/xmpp.h.4.0.2.c" 60 'full_len > MAX_URI_SIZE - 4' FIXED_LENGTH_GUARD
line_has "$p/xmpp.h.4.0.2.c" 64 'snprintf(buf, buf_size, "sip:%s", src)' FIXED_SNPRINTF
line_has "$p/xmpp.c.4.0.2.c" 284 'char buf_from[MAX_URI_SIZE + 1];' FIXED_LARGE_BUFFER
line_has "$p/xmpp.c.4.0.2.c" 295 'from_len > MAX_URI_SIZE' FIXED_CALL_GUARD
line_has "$p/xmpp_server.c.4.0.2.c" 374 '!conn->authenticated' FIXED_DIALBACK_GATE
line_has "$p/config.402.h" 76 '#define MAX_URI_SIZE 1024' MAX_URI_SIZE_PIN
mkdir -p "$out/vuln" "$out/fixed"

gen_block "$p/xmpp.h.4.0.1.c" 73 82 "$out/vuln/gen_encoded.h" xmpp.h
gen_block "$p/xmpp.c.4.0.1.c" 280 285 "$out/vuln/gen_call.h" xmpp.c
gen_block "$p/xmpp.h.4.0.2.c" 46 71 "$out/fixed/gen_encoded.h" xmpp.h
gen_block "$p/xmpp.c.4.0.2.c" 281 303 "$out/fixed/gen_call.h" xmpp.c
pass PINNED_BLOCKS_EXTRACTED

CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -DFIXED_BUILD -I"$out/fixed" -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

"$out/vuln-bin" chosen >"$out/chosen.out" 2>&1
needre "$out/chosen.out" 'LAYOUT build=vuln mode=chosen buflen=256 fromlen=299 written=303 overflow=48 stored_len=303' RUNG1_UNBOUNDED_SPRINTF
need "$out/chosen.out" 'CHOSEN_MATCH=1' RUNG4_CHOSEN_BYTES

"$out/vuln-bin" slash >"$out/slash.out" 2>&1
needre "$out/slash.out" 'LAYOUT build=vuln mode=slash buflen=256 fromlen=299 written=303 overflow=48 stored_len=14' RUNG2_STORED_LEN_MISMATCH

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" chosen >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
need "$out/asan.out" 'WRITE of size 304' ASAN_WRITE_SIZE
need "$out/asan.out" 'xmpp.c:285' ASAN_UPSTREAM_LINE
need "$out/asan.out" 'sprintf' ASAN_UPSTREAM_CALL

"$out/fixed-bin" long >"$out/fixed.out" 2>&1
needre "$out/fixed.out" 'LAYOUT build=fixed mode=long buflen=1025 fromlen=1020 written=1024 overflow=0 stored_len=1024' FIXED_BOUNDED_WRITE
"$out/fixed-bin" over >"$out/fixed_over.out" 2>&1
need "$out/fixed_over.out" 'LAYOUT build=fixed mode=over rejected=1 buflen=1025' FIXED_REJECTS_OVERLONG

{
  printf 'claim GHSA-5gm5-wj62-p234\n'
  cat "$out/chosen.out"
  cat "$out/slash.out"
  printf 'ASAN %s\n' "$(grep -m1 -oE 'ERROR: AddressSanitizer: [a-z-]+' "$out/asan.out")"
  printf 'ASAN %s\n' "$(grep -m1 -oE 'WRITE of size [0-9]+' "$out/asan.out")"
  printf 'ASAN_SITE %s\n' "$(grep -m1 -oE 'xmpp\.c:[0-9]+' "$out/asan.out")"
  cat "$out/fixed.out"
  cat "$out/fixed_over.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'
  exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
