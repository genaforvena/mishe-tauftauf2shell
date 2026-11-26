#!/usr/bin/env bash
# One-command witness replay for the sailtga2shell staged evidence.
# Rehashes every pin, deletes all builds/evidence, rebuilds and re-asserts.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

echo "== pin verification =="
for pair in \
 "src-v0.9.10.tar.gz dc0d6fa87cb4fa8b514f450a3fb13cee6e3e60f03250f683564fabbec0f722e3" \
 "src-v1.0.0.tar.gz b6f77d6d451b72202c8e11bd5057b697a21f7b6c4ef713f19a96de5a16c08916" \
 "pinned/tga-v0.9.10.c ca00ecde0ba1ca3e0cbee913bfbd88bdeab24468226aca0446d8ea27ae3a45c7" \
 "pinned/tga-fix-parent.c 56467c2fc77995ba561f483e463b08247619f8c4bf6489ba0dc1254351932af7" \
 "pinned/tga-fix.c 13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3" \
 "pinned/tga-v1.0.0.c 13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3" \
 "harness/driver.c 68d083edc106dd7093502ee42123853484820b0cf28186b3feee310ce276f2c9" \
 "harness/make-poc.py e5e1f8aa351c6ab168bf246f12bf19a3ffdfc35c8f2f80527ad47596d892210f" \
 "stubs/libavutil/pixfmt.h b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e" \
 "harness/run-all.sh e2a111e76a4c875029ebba9d7f8e40cabda001b2bff3e8bc30f92840932abba1"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

echo "== clean rebuild and full replay =="
rm -rf build-vuln-asan build-vuln-gcc-asan build-vuln-plain build-fixed-asan build-fixed-plain evidence
mkdir -p evidence-replay
if bash harness/run-all.sh > evidence-replay/run-all.log 2>&1; then
    ok "run-all.sh full replay"
else
    bad "run-all.sh full replay"
fi
grep -E '^TOTAL:' evidence-replay/run-all.log || true
grep -E '^FAIL ' evidence-replay/run-all.log || true

if need evidence-replay/run-all.log 'TOTAL: 38 PASS / 0 FAIL'; then
    ok "38 inner checks pass after clean rebuild"
else
    bad "38 inner checks pass after clean rebuild"
fi
if need evidence/asan-vuln-clang-asan-attack.out 'WRITE of size 4' \
   && need evidence/asan-vuln-clang-asan-attack.out 'tga.c:269' \
   && need evidence/asan-vuln-gcc-asan-attack.out '0 bytes after 256-byte region'; then
    ok "GCC+Clang ASan WRITE-4 past 256-byte region at verbatim sink"
else
    bad "GCC+Clang ASan WRITE-4 past 256-byte region at verbatim sink"
fi
if need evidence/plain-vuln-attack.out 'tail_248_264=aabbccddaabbccddaabbccddaabbccdd' \
   && need evidence/plain-vuln-safe8.out 'tail_248_264=aaaaaaaaaaaaaaaa0000000000000000' \
   && need evidence/asan-fixed-attack.out 'rc=213'; then
    ok "chosen bytes past allocation, controls and vendor fix clean"
else
    bad "chosen bytes past allocation, controls and vendor fix clean"
fi

echo "REPLAY_PASS=$pass REPLAY_FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS REPLAY PASS"
    exit 0
fi
echo "WITNESS REPLAY FAIL"
exit 1
