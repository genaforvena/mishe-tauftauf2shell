#!/bin/sh
# W209: the shipped `exrcheck -s -c` in-memory stream mode reaches the pinned
# ZSTD sink, but W202's ASLR-off benign-command chain does NOT transfer to it.
# W162 tested only the file-path `-c` mode; W207 left the `-s` FIFO UNKNOWN.
# This replays the stream mode with vulnerable/fixed/safe controls and checks
# that no marker is created in three plain ASLR-off runs.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'src/openexr-3.5.2/src/bin/exrcheck/main.cpp bff9a108e6c1ab14c0b303dd05a06413774e1e8b8ad73103e748de91b491b5f6' \
    'src/openexr-3.5.2/src/lib/OpenEXRUtil/ImfCheckFile.cpp 48b68e0fbab0644bf027f74251e2113f1ea311f9f6fc665eea964b8c350029ef' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/internal_zstd.c 736dad696b6263fd5f715ccf1d93ac7104dc5f50994a769046e586af828abcea' \
    'cases/baseline.exr 07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e' \
    'cases/poc.exr 283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce' \
    'cases/p202-memcpy-system.exr 7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e' \
    'harness/w202-command.cmd 2ea315718753d90adc2a4d398a939d9ccd47a5e77b063ae33a191ff2b2cf12bc'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

MAIN=src/openexr-3.5.2/src/bin/exrcheck/main.cpp
CHECK=src/openexr-3.5.2/src/lib/OpenEXRUtil/ImfCheckFile.cpp
# Source facts: -s reads a seekable path into memory, then uses the stream API.
grep -q 'ifstream instream (filename, ifstream::binary)' "$MAIN"
grep -q 'instream.seekg (0, instream.end)' "$MAIN"
grep -q 'vector<char> data (length)' "$MAIN"
grep -q 'PtrIStream stream (data, numBytes)' "$CHECK"
grep -q 'runCoreChecks (data, numBytes' "$CHECK"

RAW=$(mktemp)
NORM=$(mktemp)
MARKER=/tmp/w202m
trap 'rm -f "$RAW" "$NORM" "$MARKER"' EXIT

# Normalize ASan diagnostics: only PID, build id, paths and addresses vary.
normalize() {
    awk '
        { gsub(/==[0-9]+==/, "==PID==") }
        { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
        { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
        { print }
    '
}
report_asan() {
    grep -E 'ERROR: AddressSanitizer|internal_zstd.c:472|READ of size|memcpy-param-overlap' "$1" \
        | normalize > "$NORM"
    cat "$NORM"
}

# 1. Safe input, vulnerable stream mode: clean.
rm -f "$MARKER"
set +e
timeout 20 env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build-vuln-asan/bin/exrcheck -s -c cases/baseline.exr > "$RAW" 2>&1
base_rc=$?
set -e
test "$base_rc" -eq 0
grep -q 'OK' "$RAW"
test ! -f "$MARKER"

# 2. Advisory PoC, vulnerable stream mode: same pinned sink.
set +e
timeout 20 env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build-vuln-asan/bin/exrcheck -s -c cases/poc.exr > "$RAW" 2>&1
poc_rc=$?
set -e
test "$poc_rc" -ne 0
grep -q 'ERROR: AddressSanitizer: memcpy-param-overlap' "$RAW"
grep -q 'internal_zstd.c:472' "$RAW"
VULN_POC=$(report_asan "$RAW")

# 3. Same PoC, fixed build: rejected before the copy.
set +e
timeout 20 env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build-fixed-asan/bin/exrcheck -s -c cases/poc.exr > "$RAW" 2>&1
fixed_rc=$?
set -e
test "$fixed_rc" -ne 0
grep -q 'bad' "$RAW"
if grep -q 'ERROR: AddressSanitizer' "$RAW"; then
    echo 'fixed build reported ASan' >&2
    exit 1
fi

# 4. W202 PoC, vulnerable stream mode: the sink is reached, but the command
# chain calibrated for file-path mode does not survive the different heap
# layout.
set +e
timeout 20 env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build-vuln-asan/bin/exrcheck -s -c cases/p202-memcpy-system.exr > "$RAW" 2>&1
p202_asan_rc=$?
set -e
test "$p202_asan_rc" -ne 0
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$RAW"
grep -q 'READ of size 3072' "$RAW"
grep -q 'internal_zstd.c:472' "$RAW"
P202_ASAN=$(report_asan "$RAW")

# 5. Plain ASLR-off stream mode, three runs: no command side effect.
i=0
while test "$i" -lt 3; do
    rm -f "$MARKER"
    set +e
    timeout 20 setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -s -c \
        cases/p202-memcpy-system.exr > "$RAW" 2>&1
    plain_rc=$?
    set -e
    test "$plain_rc" -ne 0
    test ! -f "$MARKER"
    grep -q 'free(): invalid pointer' "$RAW"
    printf 'PLAIN_RUN_%d rc=%d marker=absent free_invalid_pointer=1\n' "$((i + 1))" "$plain_rc"
    i=$((i + 1))
done

# 6. GDB with ASLR off: opaque.c:79 is never reached in stream mode.
rm -f "$MARKER"
set +e
timeout 40 gdb -q -batch -ex 'set args -s -c cases/p202-memcpy-system.exr' \
    -x harness/w202-command.cmd ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1
set -e
if grep -q '^CTXT=' "$RAW" || grep -q '^SYSTEM_RDI=' "$RAW"; then
    echo 'stream mode reached the W202 command chain' >&2
    exit 1
fi
test ! -f "$MARKER"
grep -q 'Breakpoint 1 at' "$RAW"
grep -q 'Program received signal SIGABRT' "$RAW"

{
    echo 'MODE=exrcheck -s -c (file read into memory, PtrIStream, runCoreChecks)'
    echo "BASELINE_VULN_ASAN_RC=$base_rc OK=1"
    echo "POC_VULN_ASAN_RC=$poc_rc"
    printf '%s\n' "$VULN_POC"
    echo "POC_FIXED_ASAN_RC=$fixed_rc bad=1 asan=0"
    echo "P202_VULN_ASAN_RC=$p202_asan_rc"
    printf '%s\n' "$P202_ASAN"
    echo 'ASLR=off in plain and gdb runs (setarch -R / disable-randomization on)'
    echo 'GDB_OPAQUE_79_HIT=0 SYSTEM_RDI_HIT=0 MARKER=absent'
    echo 'RESULT PASS'
} > evidence/w209-stream-mode-negative.out

printf 'RESULT PASS\n'
sha256sum evidence/w209-stream-mode-negative.out
