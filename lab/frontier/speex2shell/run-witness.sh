#!/usr/bin/env bash
# One-command witness replay for the speex2shell staged evidence.
# Rehashes every pin, deletes all builds/evidence, and rebuilds from scratch.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

echo "== pin verification =="
for pair in \
 "src-Speex-1.2.1.tar.gz beaf2642e81a822eaade4d9ebf92e1678f301abfc74a29159c4e721ee70fdce0" \
 "pinned/bits-Speex-1.2.1.c bd36b8081282f5a6e9558b2ed8a0acace0a6c3c976587802b466ff8c628a335a" \
 "pinned/bits-fix-09b569d1.c cc326d16a06cf3758fd8c7182d0bae58d09ecf6947c957c820de1ea800f99461" \
 "harness/driver.c 39032f087b87502bf7ed4864afd501c8c6cc81cc9541a450e4d369ec4607cdd5" \
 "harness/adjacent.c fbb648978898b0b2ce221c4a335bbe73d0da40990746308a86ff940ca29bcfc8" \
 "harness/run-all.sh a17c1bc65a7eb548fafc5e973cea1affa4a15bcd2fb19983cf549bc1da3435a5"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

echo "== clean rebuild and full replay =="
rm -rf src-vuln src-fixed src-plain-vuln src-plain-fixed evidence
mkdir -p evidence-replay
if bash harness/run-all.sh > evidence-replay/run-all.log 2>&1; then
    ok "run-all.sh full replay"
else
    bad "run-all.sh full replay"
fi
grep -E '^TOTAL:' evidence-replay/run-all.log || true
grep -E '^FAIL ' evidence-replay/run-all.log || true

if need evidence-replay/run-all.log 'TOTAL: 28 PASS / 0 FAIL'; then
    ok "28 inner checks pass after clean rebuild"
else
    bad "28 inner checks pass after clean rebuild"
fi
if need evidence/asan-gcc-vuln-attack.out 'WRITE of size 1' \
   && need evidence/asan-gcc-vuln-attack.out 'bits.c:184' \
   && need evidence/asan-clang-vuln-attack.out '16-byte region'; then
    ok "GCC+Clang ASan WRITE-1 past 16-byte region"
else
    bad "GCC+Clang ASan WRITE-1 past 16-byte region"
fi
if need evidence/adjacent-vuln-plain.out 'canary=696a6b6c6d6e6f705a5a5a5a5a5a5a5a' \
   && need evidence/adjacent-vuln-plain.out 'changed=8 chosen=1' \
   && need evidence/adjacent-fixed-plain.out 'changed=0 chosen=0'; then
    ok "chosen bytes in adjacent live object, vendor fix clean"
else
    bad "chosen bytes in adjacent live object, vendor fix clean"
fi

echo "REPLAY_PASS=$pass REPLAY_FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS REPLAY PASS"
    exit 0
fi
echo "WITNESS REPLAY FAIL"
exit 1
