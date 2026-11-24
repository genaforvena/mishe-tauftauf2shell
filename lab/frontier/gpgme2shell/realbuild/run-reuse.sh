#!/bin/sh
# Second-operation path for CVE-2026-129975: the stale status buffer is
# reclaimed by the engine reset at the start of the next public operation.
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
check "$(hash ../pinned/fix.patch)" 2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500 "pinned fix.patch"
check "$(hash gpgme-2.2.0/src/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "built vulnerable source"
check "$(hash gpgme-fixed/src/engine-gpg.c)" 10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08 "built patched source"
check "$(grep -c 'gpg->status.buffer = buffer;' gpgme-2.3.1/src/engine-gpg.c)" 1 "2.3.1 immediate writeback"

for b in vuln fixed 231; do
  ASAN_OPTIONS=detect_leaks=0 "./status-reuse-$b" ./fake-gpg.py \
    >"evidence/reuse-$b.out" 2>&1
  echo $? >"evidence/reuse-$b.rc"
done

check "$(cat evidence/reuse-vuln.rc)" 1 "vulnerable second op faults"
check "$(grep -c 'attempting double-free' evidence/reuse-vuln.out)" 1 "ASan names double free"
check "$(grep -c 'gpg_release .*engine-gpg.c:602' evidence/reuse-vuln.out)" 1 "second free in real gpg_release"
check "$(grep -c 'gpgme_op_keylist_start .*keylist.c:1295' evidence/reuse-vuln.out)" 2 "trigger is the next public operation"
check "$(grep -c 'read_status .*engine-gpg.c:1494' evidence/reuse-vuln.out)" 1 "first free in real read_status realloc"
check "$(grep -c 'status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte\[1000\]=0x48' evidence/reuse-vuln.out)" 1 "chosen byte in first callback"
check "$(grep -c 'op1 keylist_end err=General error cb_calls=1' evidence/reuse-vuln.out)" 1 "first op fails at callback error"
check "$(grep -c 'op2 keylist_start' evidence/reuse-vuln.out)" 0 "second op never starts in vulnerable build"

for b in fixed 231; do
  check "$(cat "evidence/reuse-$b.rc")" 0 "reuse-$b rc"
  check "$(grep -c AddressSanitizer "evidence/reuse-$b.out")" 0 "reuse-$b sanitizer-clean"
  check "$(grep -c 'op2 keylist_start err=Success' "evidence/reuse-$b.out")" 1 "reuse-$b second op starts"
  check "$(grep -c 'status_cb call=2 op_marker=Z keyword=GOOD arglen=20' "evidence/reuse-$b.out")" 1 "reuse-$b second op callback receives new bytes"
  check "$(grep -c 'release done' "evidence/reuse-$b.out")" 1 "reuse-$b clean release"
done
check "$(grep -c 'gpgme version=2.3.1' evidence/reuse-231.out)" 1 "2.3.1 control is the real release"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
