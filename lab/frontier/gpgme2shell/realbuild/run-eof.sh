#!/bin/sh
# read_status() EOF early-return path for CVE-2026-129975.
# Requires the ASan builds from build-real.sh; no rebuild and no network.
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

ASAN_OPTIONS=detect_leaks=0 ./status-eof-vuln ./fake-eof-gpg.py \
  >evidence/eof-vuln.out 2>&1
echo $? >evidence/eof-vuln.rc

check "$(cat evidence/eof-vuln.rc)" 1 "vulnerable EOF build faults"
check "$(grep -c 'attempting double-free' evidence/eof-vuln.out)" 1 "ASan names double free"
check "$(grep -c 'gpg_release .*engine-gpg.c:602' evidence/eof-vuln.out)" 1 "second free in real gpg_release"
check "$(grep -c 'gpgme_op_keylist_start .*keylist.c:1295' evidence/eof-vuln.out)" 2 "engine reset occurs on both operations"
check "$(grep -c 'read_status .*engine-gpg.c:1494' evidence/eof-vuln.out)" 1 "first free in real read_status realloc"
check "$(grep -c 'op1 keylist_end err=End of file' evidence/eof-vuln.out)" 1 "first op ends at EOF without a callback error"
check "$(grep -c 'op2 keylist_start' evidence/eof-vuln.out)" 0 "second op never starts in vulnerable build"

cat >evidence/eof-gdb.cmd <<'EOF'
set pagination off
break engine-gpg.c:1494
run ./fake-eof-gpg.py
printf "gdb realloc buffer=%p buffer[1000]=0x%02x bufsize=%zu\n", buffer, (unsigned char) buffer[1000], bufsize
continue
quit
EOF
ASAN_OPTIONS=detect_leaks=0 gdb -q -batch -x evidence/eof-gdb.cmd ./status-eof-vuln \
  >evidence/eof-gdb.out 2>&1
echo $? >evidence/eof-gdb.rc
check "$(grep -c 'gdb realloc buffer=.*buffer\[1000\]=0x48' evidence/eof-gdb.out)" 1 \
  "chosen wire byte in GPGME status buffer at realloc"

for b in fixed 231; do
  ASAN_OPTIONS=detect_leaks=0 "./status-eof-$b" ./fake-eof-gpg.py \
    >"evidence/eof-$b.out" 2>&1
  echo $? >"evidence/eof-$b.rc"
  check "$(cat "evidence/eof-$b.rc")" 0 "eof-$b rc"
  check "$(grep -c AddressSanitizer "evidence/eof-$b.out")" 0 "eof-$b sanitizer-clean"
  check "$(grep -c 'op2 keylist_start err=Success' "evidence/eof-$b.out")" 1 "eof-$b second op starts"
  check "$(grep -c 'release done' "evidence/eof-$b.out")" 1 "eof-$b clean release"
done
check "$(grep -c 'gpgme version=2.3.1' evidence/eof-231.out)" 1 "2.3.1 control is the real release"

ASAN_OPTIONS=detect_leaks=0 EOF_LEN=20 ./status-eof-vuln ./fake-eof-gpg.py \
  >evidence/eof-short.out 2>&1
echo $? >evidence/eof-short.rc
check "$(cat evidence/eof-short.rc)" 0 "vulnerable short-line control rc"
check "$(grep -c AddressSanitizer evidence/eof-short.out)" 0 "short-line control clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/eof-short.out)" 1 "short-line control second op starts"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
