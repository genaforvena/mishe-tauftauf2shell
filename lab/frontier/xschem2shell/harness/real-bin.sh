#!/bin/bash
# xschem2shell: real standalone rawtovcd binary (unrenamed main) from the verbatim
# pins, driven through its real argv file path. Bounded consumer-lane evidence.
set -u
export ASAN_OPTIONS=detect_leaks=0
cd "$(dirname "$0")" || exit 1
mkdir -p evidence/realbin

gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  ../pins/rawtovcd-vuln.c -lm -o realbin-vuln-asan \
  > evidence/realbin/vuln.build.log 2>&1
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  ../pins/rawtovcd-fixed.c -lm -o realbin-fixed-asan \
  > evidence/realbin/fixed.build.log 2>&1

python3 - <<'PY' > evidence/realbin/crafted.raw
print("Title: crafted")
print("Plotname: Transient Analysis")
print("No. Variables: 2")
print("No. Points: 0")
print("Variables:")
print("0 time time")
print("1 v(a) voltage")
print("2 " + "H" * 20)
print("Binary:")
PY
sed 's/^2 HHHHHHHHHHHHHHHHHHHH$/1 v(a) voltage/' evidence/realbin/crafted.raw > evidence/realbin/safe.raw

./realbin-vuln-asan evidence/realbin/crafted.raw > evidence/realbin/vuln-attack.out 2>&1
vuln_rc=$?
./realbin-fixed-asan evidence/realbin/crafted.raw > evidence/realbin/fixed-attack.out 2>&1
fixed_rc=$?
./realbin-vuln-asan evidence/realbin/safe.raw > evidence/realbin/safe.out 2>&1
safe_rc=$?

pass=0; fail=0
chk() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
e=evidence/realbin
chk "vuln real binary rc=$vuln_rc, ASan WRITE-8 at pinned line 130" \
  "$([ $vuln_rc -ne 0 ] && grep -q 'ERROR: AddressSanitizer' $e/vuln-attack.out \
     && grep -q 'WRITE of size 8' $e/vuln-attack.out \
     && grep -q 'rawtovcd-vuln.c:130' $e/vuln-attack.out && echo 1 || echo 0)"
chk "fixed real binary rc=$fixed_rc, bad-record reject, no sanitizer error" \
  "$([ $fixed_rc -eq 0 ] && grep -q 'bad variable record' $e/fixed-attack.out \
     && ! grep -q 'AddressSanitizer' $e/fixed-attack.out && echo 1 || echo 0)"
chk "vuln real binary safe input: clean, rc=$safe_rc" \
  "$([ $safe_rc -eq 0 ] && ! grep -q 'AddressSanitizer' $e/safe.out && echo 1 || echo 0)"
echo "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
