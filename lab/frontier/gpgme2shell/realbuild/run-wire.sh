#!/bin/sh
# Loopback wire replay: an HKP response served on 127.0.0.1 supplies the key
# whose long UID becomes a >1024-byte status line in a real gpg process.
# No external contact, no r5 claim.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
check () {
  if [ "$1" = "$2" ]; then pass=$((pass+1));
  else fail=$((fail+1)); echo "FAIL: $3 (got '$1', want '$2')"; fi
}
count () { c=$(grep -c "$2" "$1" 2>/dev/null || true); echo "${c:-0}"; }
ev=realgpg/evidence

for key in long-H long-Z long-7 short; do
  check "$([ -f "realgpg/keys/$key.asc" ] && echo yes)" yes "key $key exists"
done

python3 wireloop.py wire-vuln-H status-trigger-wire-vuln long-H
python3 wireloop.py wire-vuln-Z status-trigger-wire-vuln long-Z
python3 wireloop.py wire-vuln-7 status-trigger-wire-vuln long-7
python3 wireloop.py wire-fixed-H status-trigger-wire-fixed long-H
python3 wireloop.py wire-231-H status-trigger-wire-231 long-H
python3 wireloop.py wire-vuln-short status-trigger-wire-vuln short
python3 wireloop.py wire-fixed-short status-trigger-wire-fixed short

for pair in H:0x48 Z:0x5a 7:0x37; do
  name=wire-vuln-${pair%%:*}; byte=${pair##*:}
  check "$(cat "$ev/$name.rc")" 1 "$name rc"
  check "$(count "$ev/$name.out" 'attempting double-free')" 1 \
    "$name ASan double free"
  check "$(count "$ev/$name.out" 'gpg_release .*engine-gpg.c:602')" 1 \
    "$name second free in real gpg_release"
  check "$(count "$ev/$name.out" 'read_status .*engine-gpg.c:1494')" 1 \
    "$name first free in real read_status realloc"
  check "$(count "$ev/$name.out" "keyword=IMPORTED .*byte\[1000\]=$byte")" 1 \
    "$name chosen wire byte in status callback"
done

for name in wire-fixed-H wire-231-H wire-vuln-short wire-fixed-short; do
  check "$(cat "$ev/$name.rc")" 0 "$name rc"
  check "$(count "$ev/$name.out" AddressSanitizer)" 0 "$name sanitizer-clean"
  check "$(count "$ev/$name.out" 'keyword=IMPORTED ')" 1 "$name wire key reached"
done
check "$(count "$ev/wire-231-H.out" 'gpgme version=2.3.1')" 1 \
  "2.3.1 control is the real release"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
