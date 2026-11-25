#!/bin/sh
# Plain-glibc outcome of the CVE-2026-129975 second-operation double free.
# No sanitizer, no network; requires build-plain.sh. Records the exact
# allocator outcome rather than asserting an ASan-style fault.
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
check "$(ldd --version 2>&1 | sed -n 1p | grep -c 'GLIBC 2.39')" 1 "recorded glibc version"

for b in vuln fixed; do
  "./status-reuse-plain-$b" ./fake-gpg.py >"evidence/reuse-plain-$b.out" 2>&1
  echo $? >"evidence/reuse-plain-$b.rc"
done

check "$(cat evidence/reuse-plain-vuln.rc)" 134 "vulnerable plain build aborts"
check "$(grep -c 'double free detected in tcache' evidence/reuse-plain-vuln.out)" 1 "glibc names the tcache double free"
check "$(grep -c 'status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte\[1000\]=0x48' evidence/reuse-plain-vuln.out)" 1 "chosen byte in first callback"
check "$(grep -c 'op2 keylist_start' evidence/reuse-plain-vuln.out)" 0 "second op never starts in vulnerable build"

check "$(cat evidence/reuse-plain-fixed.rc)" 0 "patched plain build exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/reuse-plain-fixed.out)" 1 "patched op2 starts"
check "$(grep -c 'status_cb call=2 op_marker=Z keyword=GOOD arglen=20' evidence/reuse-plain-fixed.out)" 1 "patched op2 callback sees new bytes"
check "$(grep -c 'release done' evidence/reuse-plain-fixed.out)" 1 "patched clean release"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
