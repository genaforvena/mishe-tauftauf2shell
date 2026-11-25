#!/bin/sh
# W13: standalone glibc mechanics for the gpgme double-free free-order branch.
# No GPGME, no network, no ASan. All three cases run against the local libc only.
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

gcc -O0 -Wall -Wno-use-after-free -o plain-key-bypass plain-key-bypass.c || exit 2

for c in key drain full; do
  CASE=$c ./plain-key-bypass >"evidence/keybypass-$c.out" 2>&1
  echo $? >"evidence/keybypass-$c.rc"
done

check "$(cat evidence/keybypass-key.rc)" 134 "key-clobber reclaim still aborts at the second free"
check "$(grep -c 'moved=1' evidence/keybypass-key.out)" 1 "key case: realloc moved and freed the stale chunk"
check "$(grep -c 'double free detected in tcache' evidence/keybypass-key.out)" 1 "key case: glibc tcache double-free report"
check "$(cat evidence/keybypass-drain.rc)" 0 "held reclaim between frees gives a silent double free"
check "$(grep -c 'second free done' evidence/keybypass-drain.out)" 1 "drain case: both frees completed"
check "$(cat evidence/keybypass-full.rc)" 0 "full-tcache model does not alias the stale chunk"
check "$(grep -c 'second free done' evidence/keybypass-full.out)" 1 "full case: both frees completed"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
