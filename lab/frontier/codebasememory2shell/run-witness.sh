#!/usr/bin/env bash
# ONE witness command for the four codebasememory2shell replay asks:
#   #3228 direct-call matrix, #3253 stdio query_graph tool rows,
#   #3526 file-steering addendum, #3799 loopback HTTP /rpc row.
# Runs the three existing, unmodified drivers in order and asserts the raw
# byte chain: unbounded RETURN count -> ASan column READ -> recover-mode
# index-selected WRITE of file-steered bytes at func_bufs[32], with the fixed
# pin rejecting the same queries. No source, pin or canonical evidence file
# is altered: tracked evidence the drivers overwrite is snapshotted and
# restored on exit; all new output goes to $OUT.
#
# Precondition: pins/ holds the two hash-verified tarballs (provisioning;
# the drivers verify all four hashes before building). All servers bind to
# 127.0.0.1 only; there is no off-host request.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
OUT="${1:-$HERE/witness-out-$$}"
mkdir -p "$OUT" || exit 2

pass=0
fail=0
ck() {
    if [ "$1" -eq 0 ]; then echo "PASS $2"; pass=$((pass + 1));
    else echo "FAIL $2"; fail=$((fail + 1)); fi
}
need() {
    local file=$1 pattern=$2 label=$3
    grep -qF -- "$pattern" "$file"; ck $? "$label"
}
absent() {
    local file=$1 pattern=$2 label=$3
    if grep -qF -- "$pattern" "$file"; then ck 1 "$label"; else ck 0 "$label"; fi
}

# Snapshot tracked evidence that the drivers rewrite; restore byte-for-byte.
SNAP=$OUT/snapshot
mkdir -p "$SNAP/direct" "$SNAP/tool" "$SNAP/http" || exit 2
for f in evidence/evidence.log evidence/evidence.sha256 \
         evidence/recover-48.out evidence/gdb-chosen-bytes.out \
         evidence/harness-vuln-asan-RETURN-33.out \
         evidence/harness-vuln-asan-RETURN-48.out \
         evidence/harness-fixed-asan-RETURN-33.out \
         evidence/harness-vuln-plain-RETURN-48.out; do
    [ -f "$f" ] && cp -p "$f" "$SNAP/direct/$(basename "$f")"
done
for f in evidence/replay-mcp-tool-vuln-asan.log \
         evidence/replay-mcp-tool-vuln-recover.log \
         evidence/replay-mcp-tool-fixed-asan.log \
         evidence/replay-mcp-tool-vuln-asan-Q33.err \
         evidence/replay-mcp-tool-vuln-asan-Q48.err \
         evidence/replay-mcp-tool-vuln-recover-Q32.err \
         evidence/replay-mcp-tool-vuln-recover-Q33.err \
         evidence/replay-mcp-tool-vuln-recover-Q48.err \
         evidence/replay-mcp-tool-fixed-asan-Q32.err \
         evidence/replay-mcp-tool-fixed-asan-Q33.err \
         evidence/replay-mcp-tool-fixed-asan-Q48.err; do
    [ -f "$f" ] && cp -p "$f" "$SNAP/tool/$(basename "$f")"
done
for f in evidence/http-replay-all.log evidence/http-vuln-asan-stderr.log \
         evidence/http-vuln-recover-stderr.log evidence/http-fixed-asan-stderr.log; do
    [ -f "$f" ] && cp -p "$f" "$SNAP/http/$(basename "$f")"
done
restore() {
    local f
    for f in "$SNAP/direct"/*; do [ -e "$f" ] && cp -p "$f" "evidence/$(basename "$f")"; done
    for f in "$SNAP/tool"/*; do [ -e "$f" ] && cp -p "$f" "evidence/$(basename "$f")"; done
    for f in "$SNAP/http"/*; do [ -e "$f" ] && cp -p "$f" "evidence/$(basename "$f")"; done
    echo "RESULT: PASS=$pass FAIL=$fail (raw transcripts in $OUT)"
}
trap restore EXIT
trap 'exit 130' TERM INT HUP

echo "=== direct-call matrix $(date -u +%FT%TZ) ==="
bash bootstrap.sh > "$OUT/direct.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && echo 0 || echo 1) "bootstrap.sh rc=0 (4 pins, 4 builds, matrix)"
need "$OUT/direct.log" 'harness-vuln-asan              N=33' "vuln ASan 33-item row present"
need "$OUT/direct.log" 'harness-fixed-asan             N=33' "fixed ASan 33-item row present"
need "$OUT/direct.log" 'harness-vuln-plain             N=48' "plain 48-item row present"

# --- #3228: direct calls into the real pinned Cypher engine -------------
need evidence/recover-48.out 'WRITE of size 70' "recover-mode WRITE of 70 bytes"
need evidence/recover-48.out '#2 0x' "recover WRITE stack has a project_item frame"
need evidence/recover-48.out 'project_item src/cypher/cypher.c:3379' "fault at pinned project_item:3379"
need evidence/recover-48.out 'execute_return_simple src/cypher/cypher.c:4116' "fault via execute_return_simple:4116"
need evidence/recover-48.out 'offset 51840 in frame' "write at func_bufs[32] (offset 51840)"
need evidence/gdb-chosen-bytes.out '0x4d	0x49	0x53	0x48	0x45	0x2d	0x4f	0x4f' "chosen MISHE-OO bytes at func_bufs[32]"
# Fixed ASan rows must be clean; the plain 48-item control intentionally
# aborts in __stack_chk_fail, so its signature is the stack-smash message.
fixed_asan=$(grep -E '^harness-fixed-asan ' "$OUT/direct.log" | grep -vc 'clean$')
ck $([ "$fixed_asan" -eq 0 ] && echo 0 || echo 1) "all fixed ASan rows clean ($fixed_asan dirty)"
need "$OUT/direct.log" 'harness-vuln-plain             N=48  RETURN exit=134' "plain 48-item control aborts in stack-smash"
need "$OUT/direct.log" 'stack smashing detected' "plain 48-item control reports stack smash"
need "$OUT/direct.log" 'harness-vuln-asan              N=33  WITH   exit=0' "WITH-side 33-item control does not overflow"

# --- #3253: real stdio query_graph tool argument ------------------------
echo "=== stdio tool rows $(date -u +%FT%TZ) ==="
bash mcp-tool/replay.sh > "$OUT/tool.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && echo 0 || echo 1) "mcp-tool/replay.sh rc=0"
need "$OUT/tool.log" '=== vuln-asan ===' "vuln-asan tool row built"
need "$OUT/tool.log" '=== vuln-recover ===' "vuln-recover tool row built"
need "$OUT/tool.log" '=== fixed-asan ===' "fixed-asan tool row built"
need "$OUT/tool.log" 'RC=1' "vuln tool REJECTS 33/48 with process rc=1"
need "$OUT/tool.log" 'STDERR_LINES=99' "vuln tool ASan READ report present"
need "$OUT/tool.log" 'STDERR_LINES=681' "recover tool WRITE report present"
need evidence/replay-mcp-tool-vuln-asan-Q33.err 'READ of size 8' "tool ASan column READ"
need evidence/replay-mcp-tool-vuln-asan-Q33.err 'cypher.c:2568' "tool READ at pinned cypher.c:2568"
need evidence/replay-mcp-tool-vuln-asan-Q33.err 'handle_query_graph' "tool fault stack reaches query_graph handler"
need evidence/replay-mcp-tool-vuln-recover-Q33.err 'WRITE of size 68' "recover tool OOB WRITE of 68"
need evidence/replay-mcp-tool-vuln-recover-Q33.err 'project_item' "recover WRITE at project_item"
need evidence/replay-mcp-tool-vuln-recover-Q33.err 'index 32 out of bounds' "recover UBSan index 32"
need evidence/replay-mcp-tool-vuln-recover.log 'MISHE_OO' "recover WRITE carries chosen fixture bytes"
need evidence/replay-mcp-tool-fixed-asan.log 'failed to parse query' "fixed tool rejects 33-item query"
absent evidence/replay-mcp-tool-fixed-asan-Q33.err 'AddressSanitizer' "fixed tool stderr has no ASan"

# --- #3526: file-steered bytes, not a harness constant ------------------
# The W6 gdb check used a throwaway probe; its transcript is preserved.
# Assert it is materially present, without pretending replay.sh regenerates it.
need evidence/mcp-tool-steer-gdb.txt 'CHOSEN2=STEERED' "steer transcript has distinct fixture identifier"
need evidence/mcp-tool-steer-gdb.txt 'len = 68' "steer breakpoint stops on 68-byte property"
need evidence/mcp-tool-steer-gdb.txt 'raw = ' "steer breakpoint shows file-steered raw bytes"
need evidence/mcp-tool-steer-gdb.txt 'cypher.c:4115' "steer transcript shows index-32 UBSan"

# --- #3799: pinned server's loopback HTTP /rpc transport ----------------
echo "=== HTTP /rpc rows $(date -u +%FT%TZ) ==="
bash http-tool/replay.sh all > "$OUT/http.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && echo 0 || echo 1) "http-tool/replay.sh all rc=0"
need "$OUT/http.log" 'ROOT=/tmp/cbm-http-vuln-asan' "HTTP vuln-asan row ran"
need "$OUT/http.log" 'ROOT=/tmp/cbm-http-vuln-recover' "HTTP vuln-recover row ran"
need "$OUT/http.log" 'ROOT=/tmp/cbm-http-fixed-asan' "HTTP fixed-asan row ran"
need evidence/http-vuln-asan-stderr.log 'READ of size 8' "HTTP ASan column READ"
need evidence/http-vuln-asan-stderr.log 'rb_set_columns src/cypher/cypher.c:2568' "HTTP READ at pinned :2568"
need evidence/http-vuln-recover-stderr.log 'WRITE of size 68' "HTTP recover OOB WRITE"
need evidence/http-vuln-recover-stderr.log 'project_item src/cypher/cypher.c:3379' "HTTP WRITE at pinned project_item:3379"
need evidence/http-vuln-recover-stderr.log 'execute_return_simple src/cypher/cypher.c:4116' "HTTP WRITE via execute_return_simple:4116"
need evidence/http-vuln-recover-stderr.log 'offset 51840' "HTTP WRITE at func_bufs[32]"
need evidence/http-replay-all.log 'MISHE_OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx' "HTTP result carries chosen bytes"
need evidence/http-replay-all.log '"isError":true' "fixed HTTP row rejects 33-item query"
absent evidence/http-fixed-asan-stderr.log 'AddressSanitizer' "fixed HTTP stderr clean"

# Preserve one copy of each raw transcript for the independent reviewer.
for f in direct.log tool.log http.log \
         evidence.log recover-48.out gdb-chosen-bytes.out \
         replay-mcp-tool-vuln-asan-Q33.err \
         replay-mcp-tool-vuln-recover-Q33.err \
         replay-mcp-tool-fixed-asan-Q33.err \
         http-replay-all.log http-vuln-asan-stderr.log \
         http-vuln-recover-stderr.log http-fixed-asan-stderr.log; do
    [ -f "evidence/$f" ] && cp -p "evidence/$f" "$OUT/$f"
done
echo "done: $OUT"
