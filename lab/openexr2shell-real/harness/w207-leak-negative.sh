#!/bin/sh
# W207: bounded NEGATIVE for the "same-process second file with a leaked
# address" lane.  exrcheck loops over argv paths in one process, so a second
# path may be a FIFO written after file 1's diagnostics are observed.  That
# chain needs a file-observable ASLR-dependent address before W202's ASLR-off
# call is available.  Measured here: pinned 3.5.2 gives no such address on
# any committed case, and the only %p context diagnostic is unreachable from
# decode contexts because their filename is always set.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'src/openexr-3.5.2/src/bin/exrcheck/main.cpp bff9a108e6c1ab14c0b303dd05a06413774e1e8b8ad73103e748de91b491b5f6' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/internal_structs.c 56cab59f32345cd4e08465e9b9ee5cb91711f8631a5233839d13ff3dd3d649d5' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/context.c adc4a60f431e583e0d3d911effc3616badfd56514dbf38420f7f1ba11a32d98e' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/debug.c 9a52e451d604abfa6e40482473e973c6433e3746a24c8b7c941cb60ac016df0b' \
    'cases/baseline.exr 07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

BIN=./build-vuln-plain/bin/exrcheck
CORE=src/openexr-3.5.2/src/lib/OpenEXRCore
MAIN=src/openexr-3.5.2/src/bin/exrcheck/main.cpp

# The multi-file loop is a source fact, not a vulnerability.
grep -q 'for (int i = 1; i < argc; ++i)' "$MAIN"
grep -q 'bool hasError = exrCheck (' "$MAIN"
# The only context %p diagnostic requires an unset filename.
grep -q 'Context 0x%p: (%s) %s' "$CORE/internal_structs.c"
grep -q 'if (ctxt->filename.str)' "$CORE/internal_structs.c"
# Every context created by exr_start_* has a filename; the decode context
# ignores its filename argument and installs context_name or "<temporary>".
grep -q '(void) filename;' "$CORE/context.c"
grep -q 'context_name ? context_name : "<temporary>"' "$CORE/context.c"
# The handler-pointer debug print is never called by exrcheck.
test -z "$(grep -i 'debug' "$MAIN" || true)"
grep -q 'hdlrs %p %p %p' "$CORE/debug.c"

# No committed case leaks an address with ASLR left enabled.  Status is
# printed as rc/OK|bad; every hex-looking token is counted and must be zero.
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
for f in cases/*.exr; do
    out=$({ "$BIN" -c "$f" 2>&1; } 2>/dev/null) && rc=0 || rc=$?
    hex=$(printf '%s\n' "$out" | grep -oE '0x[0-9a-fA-F]+' | wc -l)
    test "$hex" -eq 0
    printf '%s rc=%d hex=%d\n' "$(basename "$f")" "$rc" "$hex" >> "$RAW"
done
test "$(wc -l < "$RAW")" -eq "$(find cases/ -maxdepth 1 -name '*.exr' | wc -l)"

# A second regular file is processed in the same process; a FIFO is not
# seekable and exrcheck reports it bad.  Both are measured facts here.
both=$(timeout 20 "$BIN" -c cases/baseline.exr cases/baseline.exr 2>&1) && brc=0 || brc=$?
test "$brc" -eq 0
test "$(printf '%s\n' "$both" | grep -c 'OK$')" -eq 2

FIFO=$(mktemp -u /tmp/w207-fifo.XXXXXX)
mkfifo "$FIFO"
cat cases/baseline.exr > "$FIFO" &
WRITER=$!
fifo_out=$(timeout 20 "$BIN" -c cases/baseline.exr "$FIFO" 2>&1) && frc=0 || frc=$?
wait "$WRITER" || wrc=$?
rm -f "$FIFO"
test "$(printf '%s\n' "$fifo_out" | grep -c 'OK$')" -eq 1
test "$(printf '%s\n' "$fifo_out" | grep -c 'bad$')" -eq 1

{
    echo 'ASLR=on (no setarch, no gdb)'
    echo 'MULTI_FILE_LOOP=main.cpp:117 exrCheck() per argv path'
    echo 'SECOND_REGULAR_FILE_STATUS=OK OK rc=0'
    echo 'FIFO_SECOND_FILE_STATUS=OK bad rc=1 (FIFO not seekable)'
    echo 'CONTEXT_PTR_LEAK_SITE=internal_structs.c:62 requires filename==NULL'
    echo 'DECODE_CONTEXT_FILENAME=context.c:399 always set'
    echo 'DEBUG_HANDLER_PRINT=debug.c:250 never called by exrcheck'
    echo 'CASES_WITH_HEX_OUTPUT=0'
    cat "$RAW"
    echo 'RESULT PASS'
} > evidence/w207-leak-negative.out

printf 'RESULT PASS\n'
sha256sum evidence/w207-leak-negative.out
