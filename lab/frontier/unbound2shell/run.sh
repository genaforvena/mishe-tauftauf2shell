#!/usr/bin/env bash
# Replay: bash lab/frontier/unbound2shell/run.sh <outdir>
# Executes the VERBATIM pinned ds_create_dnskey_digest() from Unbound
# validator/val_sigcrypt.c at tag release-1.26.0 (vulnerable), fix commit
# 8c2e0fd6cc5b and tag release-1.26.1 (both guarded). Stubbed collaborators
# reproduce the pinned sldns_buffer memcpy with NDEBUG defined by this harness;
# shipping compile flags are UNKNOWN. No daemon, resolver, DNS packet, socket
# or network is created.
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
  local text
  text=$(sed -n "$2 p" "$1")
  if printf '%s' "$text" | grep -qF -- "$3"; then pass "$4"; else
    printf 'FAIL %s (line %s: %s)\n' "$4" "$2" "$text"; bad "$4"
  fi
}
gen_block() {
  { printf '#line %s "%s"\n' "$2" "$5"
    sed -n "$2,$3 p" "$1"
  } > "$4"
}

cat >"$out/pinned.sha256" <<'EOF'
393cc9fd020651d546e7cf5085ef64faad92a2fc9f485f99c43b203cfa395cb3  config_file.c
2bddf6e3c4a337a3a0481a9f9b732b2e478d5f01311fdb3e7d7663560c982570  rrdef.h
eace1c553e69e95b976448860b89f42ddc1dd84a682e3ac42f4fdf7ee3d65303  sbuffer.c
06c463e9ddd4ad106de0b895cb575936a11242f7ea3fce3df943c9cbdd70e7a5  sbuffer.h
2ae7b032cc1d73005b5fe40bebf60363f09d402cc4bacb7c5313f6cdcdeb1acc  val_secalgo.c
477d5e1b6ebdc829a7dd0bcb660f3e26123381fe6d4b7df401c5a17b4611f954  val_sigcrypt.1260.c
807b97e8a4684266324a6e387280e0408141e566e406b23e0f68f11670bd4dc4  val_sigcrypt.1261.c
a490e4bc4525706f573dab8d2ccd0d58f6301ab530f2dd7fc2720be318bdcb6f  val_sigcrypt.fixcommit.c
37afa74d86317dbe961943b118afc95273361e5d4e5c3be5e7ddb0d7435f90a9  worker.c
EOF
if (cd "$p" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PIN_SHA256
else
  cat "$out/pinned.check"; bad PIN_SHA256
fi

line_has "$p/val_sigcrypt.1260.c" 294 'ds_create_dnskey_digest(struct module_env* env,' VULN_FUNC_START
line_has "$p/val_sigcrypt.1260.c" 307 'sldns_buffer_clear(b);' VULN_CLEAR
line_has "$p/val_sigcrypt.1260.c" 308 'sldns_buffer_write(b, dnskey_rrset->rk.dname,' VULN_WRITE_DNAME
line_has "$p/val_sigcrypt.1260.c" 311 'sldns_buffer_write(b, dnskey_rdata+2, dnskey_len-2);' VULN_WRITE_RDATA
line_has "$p/val_sigcrypt.fixcommit.c" 308 'if(!sldns_buffer_available(b, dnskey_rrset->rk.dname_len + dnskey_len-2))' FIXCOMMIT_GUARD
line_has "$p/val_sigcrypt.1261.c" 310 'if(!sldns_buffer_available(b, dnskey_rrset->rk.dname_len + dnskey_len-2))' FIXEDTAG_GUARD
line_has "$p/config_file.c" 176 'cfg->msg_buffer_size = 65552;' MSG_BUFFER_SIZE_PIN
line_has "$p/worker.c" 2436 'worker->env.scratch_buffer = sldns_buffer_new(cfg->msg_buffer_size);' SCRATCH_BUFFER_PIN
line_has "$p/rrdef.h" 29 '#define LDNS_MAX_DOMAINLEN    255' LDNS_MAX_DOMAINLEN_PIN
line_has "$p/rrdef.h" 249 '#define LDNS_MAX_RDFLEN	65535' LDNS_MAX_RDFLEN_PIN
line_has "$p/sbuffer.h" 436 'memcpy(buffer->_data + at, data, count);' SBUFFER_MEMCPY_PIN
line_has "$p/sbuffer.c" 19 'sldns_buffer_new(size_t capacity)' SBUFFER_NEW_PIN
mkdir -p "$out/vuln" "$out/fixcommit" "$out/fixedtag"

gen_block "$p/val_sigcrypt.1260.c" 293 317 "$out/vuln/gen_func.h" val_sigcrypt.c
gen_block "$p/val_sigcrypt.fixcommit.c" 293 319 "$out/fixcommit/gen_func.h" val_sigcrypt.c
gen_block "$p/val_sigcrypt.1261.c" 295 321 "$out/fixedtag/gen_func.h" val_sigcrypt.c
if grep -q 'sldns_buffer_available' "$out/vuln/gen_func.h"; then
  bad VULN_HAS_NO_GUARD
else
  pass VULN_HAS_NO_GUARD
fi
pass PINNED_BLOCKS_EXTRACTED

CFLAGS='-std=gnu11 -O0 -g -Wall -fno-omit-frame-pointer'
gcc $CFLAGS -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -I"$out/vuln" -fsanitize=address -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixcommit" -o "$out/fixcommit-bin" "$here/driver.c" || exit 93
gcc $CFLAGS -I"$out/fixedtag" -o "$out/fixedtag-bin" "$here/driver.c" || exit 94
pass COMPILE

"$out/vuln-bin" benign >"$out/benign.out" 2>&1
needre "$out/benign.out" 'LAYOUT mode=benign cap=65552 dname_len=32 rdata_len=100 written=130 overflow=0 rc=1 limit=130' RUNG1_BENIGN_NO_OVERFLOW

"$out/vuln-bin" chosen >"$out/chosen.out" 2>&1
needre "$out/chosen.out" 'LAYOUT mode=chosen cap=65552 dname_len=255 rdata_len=65535 written=65788 overflow=236 rc=1' RUNG1_UNBOUNDED_WRITE
need "$out/chosen.out" 'GUARD_REJECTED=0' RUNG2_NO_GUARD_IN_VULN
need "$out/chosen.out" 'CHOSEN_MATCH=1' RUNG4_CHOSEN_BYTES

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" chosen >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'heap-buffer-overflow' ASAN_HEAP_OVERFLOW
need "$out/asan.out" 'WRITE of size 65533' ASAN_WRITE_SIZE
need "$out/asan.out" 'sbuffer.h:436' ASAN_UPSTREAM_MEMCPY_LINE
need "$out/asan.out" 'val_sigcrypt.c:311' ASAN_UPSTREAM_CALL_LINE

"$out/fixcommit-bin" chosen >"$out/fixcommit.out" 2>&1
needre "$out/fixcommit.out" 'LAYOUT mode=chosen cap=65552 dname_len=255 rdata_len=65535 written=65788 overflow=236 rc=0' FIXCOMMIT_GUARD_RETURN
need "$out/fixcommit.out" 'GUARD_REJECTED=1' FIXCOMMIT_GUARD_REJECTED
"$out/fixedtag-bin" chosen >"$out/fixedtag.out" 2>&1
need "$out/fixedtag.out" 'GUARD_REJECTED=1' FIXEDTAG_GUARD_REJECTED
"$out/fixedtag-bin" benign >"$out/fixedtag_benign.out" 2>&1
needre "$out/fixedtag_benign.out" 'LAYOUT mode=benign cap=65552 dname_len=32 rdata_len=100 written=130 overflow=0 rc=1' FIXEDTAG_BENIGN_OK

{
  printf 'claim CVE-2026-81642\n'
  cat "$out/benign.out"
  cat "$out/chosen.out"
  printf 'ASAN %s\n' "$(grep -m1 -oE 'ERROR: AddressSanitizer: [a-z-]+' "$out/asan.out")"
  printf 'ASAN %s\n' "$(grep -m1 -oE 'WRITE of size [0-9]+' "$out/asan.out")"
  printf 'ASAN_SITE %s\n' "$(grep -m1 -oE 'sbuffer\.h:[0-9]+' "$out/asan.out")"
  printf 'ASAN_CALL %s\n' "$(grep -m1 -oE 'val_sigcrypt\.c:[0-9]+' "$out/asan.out")"
  cat "$out/fixcommit.out"
  cat "$out/fixedtag.out"
  cat "$out/fixedtag_benign.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'; exit 0
fi
echo 'SOME CHECKS FAILED rc 1'; exit 1
