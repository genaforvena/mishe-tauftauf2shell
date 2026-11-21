#!/usr/bin/env bash
# Replay driver: bash lab/frontier/dnsmasq2shell/run.sh <outdir>
# Extracts VERBATIM pinned lines from dnsmasq src/cache.c at tag v2.92
# (vulnerable) and fix commit 36d081e (fixed) into gen_block.h with #line
# directives, then compiles drivers that execute those exact statements with
# stubbed collaborators. No daemon, socket, DNS packet or network is created.
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
  f=$1; text=$2; want=$3
  got=$(grep -nF -- "$text" "$f" | head -1 | cut -d: -f1)
  if [ "$got" = "$want" ]; then pass "$4"; else bad "$4"; fi
}

cat >"$out/pinned.sha256" <<'EOF'
2918f3929b7054caa657c927ad98c2daa0aed5bf981990a6494c53d90d6e7f30  cache.292.c
bf7f09dd004fd98d4bc46fbc965fb7a10bd28d06b096e7a60101ead4da19879f  dnssec.292.c
2833788d0cd52df0b4d2e0c3374ff9b7933811735cbff6a37ff010b1735bcece  cache.fixed.c
c69256bf3c2405db4595d51d92e3e84eb5ccbd539847177209b0d96a3f7d9c74  dnssec.fixed.c
EOF
if (cd "$here/pins" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PIN_HASHES
else
  bad PIN_HASHES
fi

line_is "$here/pins/cache.292.c" 'sprintf(daemon->addrbuff, arg, addr->log.keytag, addr->log.algo, addr->log.digest);' 2291 VULN_SPRINTF_LINE
line_is "$here/pins/cache.292.c" 'if (!(flags & (F_SERVER | F_IPSET | F_QUERY)) && type > 0)' 2267 VULN_QUERYSTR_GUARD
line_is "$here/pins/cache.fixed.c" 'snprintf(daemon->addrbuff, ADDRSTRLEN, arg, addr->log.keytag, addr->log.algo, addr->log.digest);' 2360 FIXED_SNPRINTF_LINE
line_is "$here/pins/cache.fixed.c" 'if (!(flags & (F_SERVER | F_IPSET | F_QUERY | F_KEYTAG | F_RR)) && type > 0)' 2334 FIXED_QUERYSTR_GUARD
line_is "$here/pins/cache.fixed.c" 'extra = " (not supported)";' 2362 FIXED_EXTRA_SUFFIX
line_is "$here/pins/dnssec.292.c" 'log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS for keytag %hu, algo %hu, digest %hu (not supported)", 0);' 1100 VULN_DS_CALLER
line_is "$here/pins/dnssec.fixed.c" 'log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS for keytag %hu, algo %hu, digest %hu", 1);' 1101 FIXED_DS_CALLER

gen_block() {
  src=$1; from=$2; to=$3; dest=$4
  mkdir -p "$dest"
  printf '#line %d "cache.c"\n' "$from" >"$dest/gen_block.h"
  sed -n "${from},${to}p" "$src" >>"$dest/gen_block.h"
}
gen_block "$here/pins/cache.292.c" 2266 2291 "$out/vuln"
gen_block "$here/pins/cache.fixed.c" 2333 2364 "$out/fixed"
pass PINNED_BLOCKS_EXTRACTED

CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -DVULN_BUILD -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -DFIXED_BUILD -I"$out/fixed" -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

"$out/vuln-bin" capture >"$out/vuln.out" 2>&1
needre "$out/vuln.out" 'LAYOUT buflen=46 written=57 overflow=12 keytag=65535 algo=255 digest=255 type=0' RUNG1_UNBOUNDED_SPRINTF
need "$out/vuln.out" 'VICTIM first_changed=0' RUNG2_STATE_FAILURE
need "$out/vuln.out" 'EXTRA=NULL' VULN_NO_EXTRA_SUFFIX
need "$out/vuln.out" 'VICTIM first_changed=0 tail=20737570' INSTRUMENTED_LITERAL_TAIL

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'heap-buffer-overflow' ASAN_HEAP_OVERFLOW
needre "$out/asan.out" 'WRITE of size [0-9]+' ASAN_WRITE
need "$out/asan.out" 'cache.c:2291' ASAN_UPSTREAM_LINE
need "$out/asan.out" 'sprintf' ASAN_UPSTREAM_CALL

"$out/fixed-bin" capture >"$out/fixed.out" 2>&1
needre "$out/fixed.out" 'LAYOUT buflen=46 written=41 overflow=0 keytag=65535 algo=255 digest=255 type=1' FIXED_BOUNDED_WRITE
need "$out/fixed.out" 'VICTIM first_changed=64' FIXED_VICTIM_UNCHANGED
need "$out/fixed.out" 'EXTRA= (not supported)' FIXED_EXTRA_SUFFIX

{
  grep -E '^(PASS|FAIL) ' "$out/pinned.check" 2>/dev/null || true
  grep -E '^LAYOUT ' "$out/vuln.out"
  grep -E '^VICTIM ' "$out/vuln.out"
  grep -E '^EXTRA ' "$out/vuln.out"
  grep -E 'ERROR: AddressSanitizer|WRITE of size|#[0-9]+ .*cache.c:2291' "$out/asan.out" | sed -E 's/^==[0-9]+==/==PID==/g; s#.*/cache.c#cache.c#g; s/0x[0-9a-f]+/ADDR/g; s/[[:space:]]+[0-9]+[[:space:]]/ N /g'
  grep -E '^LAYOUT ' "$out/fixed.out"
  grep -E '^VICTIM ' "$out/fixed.out"
  grep -E '^EXTRA ' "$out/fixed.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASSED rc 0'
  exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
