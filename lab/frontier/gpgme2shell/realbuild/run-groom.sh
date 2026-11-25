#!/bin/sh
# Plain-glibc allocator-grooming outcome for the CVE-2026-129975 stale free.
# No sanitizer, no network. Requires build-plain.sh. A same-size allocation in
# the failing status callback drains the tcache entry created by realloc, so
# the stale free at op2 reset does not abort and a later malloc aliases it.
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
  for g in 1 0; do
    GROOM_ALLOC=$g "./status-groom-plain-$b" ./fake-gpg.py \
      >"evidence/groom-$b-$g.out" 2>&1
    echo $? >"evidence/groom-$b-$g.rc"
  done
done

check "$(cat evidence/groom-vuln-1.rc)" 0 "groomed vulnerable build exits clean"
check "$(grep -c 'status_cb call=1 op_marker=H keyword=GOOD arglen=1200 byte\[1000\]=0x48' evidence/groom-vuln-1.out)" 1 "chosen byte before early return"
check "$(grep -c 'double free detected in tcache' evidence/groom-vuln-1.out)" 0 "groomed stale free does not abort"
check "$(grep -c 'op2 keylist_start err=Success' evidence/groom-vuln-1.out)" 1 "groomed vulnerable op2 starts"
check "$(grep -c 'groom_calls=1' evidence/groom-vuln-1.out)" 1 "callback allocated once"
check "$(grep -c 'aliased=1' evidence/groom-vuln-1.out)" 1 "post-release malloc aliases callback buffer"
check "$(grep -c 'groom_buf byte\[1000\]=0x41 after byte\[1000\]=0x41' evidence/groom-vuln-1.out)" 1 "chosen 0x41 visible through both pointers"
check "$(grep -c 'release done' evidence/groom-vuln-1.out)" 1 "groomed vulnerable process completes"

check "$(cat evidence/groom-vuln-0.rc)" 134 "ungroomed vulnerable build aborts"
check "$(grep -c 'double free detected in tcache' evidence/groom-vuln-0.out)" 1 "ungroomed stale free aborts in tcache"
check "$(grep -c 'op2 keylist_start' evidence/groom-vuln-0.out)" 0 "ungroomed op2 never starts"

check "$(cat evidence/groom-fixed-1.rc)" 0 "patched groomed build exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/groom-fixed-1.out)" 1 "patched groomed op2 starts"
check "$(grep -c 'aliased=0' evidence/groom-fixed-1.out)" 1 "patched build has no alias"
check "$(grep -c 'groom_buf byte\[1000\]=0x47 after byte\[1000\]=0x41' evidence/groom-fixed-1.out)" 1 "patched callback buffer unchanged by later write"

check "$(cat evidence/groom-fixed-0.rc)" 0 "patched ungroomed build exits clean"
check "$(grep -c 'groom_calls=0' evidence/groom-fixed-0.out)" 1 "patched ungroomed callback allocates nothing"
check "$(grep -c 'aliased=0' evidence/groom-fixed-0.out)" 1 "patched ungroomed build has no alias"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
