#!/bin/sh
# Wire-fed stale status buffer reclaimed by the next public operation.
# One bounded extension of the loopback HKP path: operation 1 uses real gpg
# and a wire-supplied long status line, operation 2 is a keylist on the same
# context. No external contact and no r5 claim.
set -u
cd "$(dirname "$0")" || exit 2
ev=realgpg/evidence
pass=0; fail=0
check () {
  if [ "$1" = "$2" ]; then pass=$((pass+1));
  else fail=$((fail+1)); echo "FAIL: $3 (got '$1', want '$2')"; fi
}
count () { c=$(grep -c "$2" "$1" 2>/dev/null || true); echo "${c:-0}"; }
hash () { sha256sum "$1" | cut -d' ' -f1; }

check "$(hash ../pinned/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "pinned engine-gpg.c"
check "$(hash ../pinned/fix.patch)" 2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500 "pinned fix.patch"
check "$(hash gpgme-2.2.0/src/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "built vulnerable source"
check "$(hash gpgme-fixed/src/engine-gpg.c)" 10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08 "built patched source"
check "$(grep -c 'gpg->status.buffer = buffer;' gpgme-2.3.1/src/engine-gpg.c)" 1 "2.3.1 immediate writeback"

python3 wireloop.py wire-reuse-vuln-H status-wire-reuse-vuln long-H
python3 wireloop.py wire-reuse-vuln-Z status-wire-reuse-vuln long-Z
python3 wireloop.py wire-reuse-vuln-7 status-wire-reuse-vuln long-7
python3 wireloop.py wire-reuse-fixed-H status-wire-reuse-fixed long-H
python3 wireloop.py wire-reuse-231-H status-wire-reuse-231 long-H
python3 wireloop.py wire-reuse-vuln-short status-wire-reuse-vuln short
python3 wireloop.py wire-reuse-fixed-short status-wire-reuse-fixed short

for pair in H:0x48 Z:0x5a 7:0x37; do
  name=wire-reuse-vuln-${pair%%:*}; byte=${pair##*:}
  check "$(cat "$ev/$name.rc")" 1 "$name rc"
  check "$(count "$ev/$name.out" 'attempting double-free')" 1 \
    "$name ASan double free"
  check "$(count "$ev/$name.out" 'gpg_release .*engine-gpg.c:602')" 1 \
    "$name second free in real gpg_release"
  check "$(count "$ev/$name.out" 'read_status .*engine-gpg.c:1494')" 1 \
    "$name first free in real read_status realloc"
  check "$(count "$ev/$name.out" 'gpgme_op_keylist_start .*keylist.c:1295')" 1 \
    "$name second free during next public operation"
  check "$(count "$ev/$name.out" '_gpgme_op_reset .*op-support.c:106')" 1 \
    "$name engine reset is the free path"
  check "$(count "$ev/$name.out" "status_cb call=2 keyword=IMPORTED arglen=1234 byte\[1000\]=$byte")" 1 \
    "$name chosen wire byte in status callback"
  check "$(count "$ev/$name.out" 'op1 verify err=General error cb_calls=2')" 1 \
    "$name first op fails at callback error"
  check "$(count "$ev/$name.out" 'op2 keylist_start')" 0 \
    "$name second op never starts in vulnerable build"
done

for name in wire-reuse-fixed-H wire-reuse-231-H; do
  check "$(cat "$ev/$name.rc")" 0 "$name rc"
  check "$(count "$ev/$name.out" AddressSanitizer)" 0 "$name sanitizer-clean"
  check "$(count "$ev/$name.out" 'status_cb call=2 keyword=IMPORTED arglen=1234 byte\[1000\]=0x48')" 1 \
    "$name wire byte reached callback"
  check "$(count "$ev/$name.out" 'op2 keylist_start err=Success')" 1 \
    "$name second op starts"
  check "$(count "$ev/$name.out" 'release done')" 1 "$name clean release"
done
check "$(count "$ev/wire-reuse-231-H.out" 'gpgme version=2.3.1')" 1 \
  "2.3.1 control is the real release"

for name in wire-reuse-vuln-short wire-reuse-fixed-short; do
  check "$(cat "$ev/$name.rc")" 0 "$name rc"
  check "$(count "$ev/$name.out" AddressSanitizer)" 0 "$name sanitizer-clean"
  check "$(count "$ev/$name.out" 'status_cb call=2 keyword=IMPORTED arglen=154')" 1 \
    "$name short wire key reached"
  check "$(count "$ev/$name.out" 'op1 verify err=Success')" 1 "$name verify succeeded"
  check "$(count "$ev/$name.out" 'op2 keylist_start err=Success')" 1 \
    "$name second op starts"
  check "$(count "$ev/$name.out" 'release done')" 1 "$name clean release"
done

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
