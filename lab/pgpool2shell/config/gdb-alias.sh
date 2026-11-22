#!/bin/bash
# Alias analysis for the CVE-2026-92869 OOB store: map the i=128 port write
# against the JSON object graph of the unchanged direct-call harness.
# Prerequisite: bash run-harness.sh (builds /tmp/w7-pgpool-asan/h7-vuln-plain).
# No daemon, no ports: observation only, no harness write.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${TMPDIR:-/tmp}/w7-pgpool-asan/h7-vuln-plain"
if [ ! -x "$BIN" ]; then
    echo "missing $BIN; run bash run-harness.sh first" >&2
    exit 2
fi
rm -f "$HERE/gdb-alias.out"
gdb -q -batch -x "$HERE/gdb-alias.cmd" "$BIN" >"$HERE/gdb-alias.out" 2>&1
grep -E 'ALIAS HIT|^\$|^0x[0-9a-f]+:|stepping|values\[\]|continuing|stop reason|SIGSEGV|#[0-9] |inferior' "$HERE/gdb-alias.out" | head -100
