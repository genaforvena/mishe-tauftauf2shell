#!/usr/bin/env bash
# FAST witness triage for the core codebasememory2shell claim (#3228):
# unbounded RETURN count -> ASan column READ at cypher.c:2568 and a
# recover-mode index-selected WRITE of chosen bytes at func_bufs[32], with
# fixed/safe/WITH controls. Only the direct-call lane is rebuilt and run;
# the ~20-min stdio-tool and loopback-HTTP rebuilds in run-witness.sh are
# intentionally skipped. For the full four-ask replay use run-witness.sh.
#
# No source, pin or canonical evidence is left changed: every tracked file
# bootstrap.sh overwrites is snapshotted and restored on exit (TERM/INT/HUP
# included). All new output goes to $OUT. Every server is local; no socket.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
OUT="${1:-$HERE/witness-fast-out-$$}"
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

# Snapshot every tracked evidence file that bootstrap.sh/run-all.sh rewrite.
SNAP=$OUT/snapshot
mkdir -p "$SNAP" || exit 2
mapfile -t TRACKED < <(git ls-files evidence)
for f in "${TRACKED[@]}"; do
    [ -f "$f" ] && mkdir -p "$SNAP/$(dirname "$f")" && cp -p "$f" "$SNAP/$f"
done
restore() {
    local f
    for f in "${TRACKED[@]}"; do
        if [ -f "$SNAP/$f" ]; then cp -p "$SNAP/$f" "$f";
        elif [ -e "$f" ]; then git checkout -- "$f" 2>/dev/null; fi
    done
    echo "RESULT: PASS=$pass FAIL=$fail (raw transcripts in $OUT)"
}
trap restore EXIT
trap 'exit 130' TERM INT HUP

echo "=== bootstrap.sh (4 pins, 4 builds, direct matrix) $(date -u +%FT%TZ) ==="
bash bootstrap.sh > "$OUT/direct.log" 2>&1
rc=$?
ck $([ "$rc" -eq 0 ] && echo 0 || echo 1) "bootstrap.sh rc=0 (4 pins, 4 builds, matrix)"

need "$OUT/direct.log" 'harness-vuln-asan              N=33' "vuln ASan 33-item row present"
need "$OUT/direct.log" 'harness-fixed-asan             N=33' "fixed ASan 33-item row present"
need "$OUT/direct.log" 'harness-vuln-plain             N=48' "plain 48-item row present"

# --- #3228: direct calls into the real pinned Cypher engine -------------
need evidence/recover-48.out 'WRITE of size 70' "recover-mode WRITE of 70 bytes"
need evidence/recover-48.out 'project_item src/cypher/cypher.c:3379' "fault at pinned project_item:3379"
need evidence/recover-48.out 'execute_return_simple src/cypher/cypher.c:4116' "fault via execute_return_simple:4116"
need evidence/recover-48.out 'offset 51840 in frame' "write at func_bufs[32] (offset 51840)"
need evidence/gdb-chosen-bytes.out '0x4d	0x49	0x53	0x48	0x45	0x2d	0x4f	0x4f' "chosen MISHE-OO bytes at func_bufs[32]"
fixed_asan=$(grep -E '^harness-fixed-asan ' "$OUT/direct.log" | grep -vc 'clean$')
ck $([ "$fixed_asan" -eq 0 ] && echo 0 || echo 1) "all fixed ASan rows clean ($fixed_asan dirty)"
need "$OUT/direct.log" 'harness-vuln-plain             N=48  RETURN exit=134' "plain 48-item control aborts in stack-smash"
need "$OUT/direct.log" 'stack smashing detected' "plain 48-item control reports stack smash"
need "$OUT/direct.log" 'harness-vuln-asan              N=33  WITH   exit=0' "WITH-side 33-item control does not overflow"
need "$OUT/direct.log" 'harness-vuln-asan              N=33  RETURN exit=1' "vuln ASan 33-item RETURN faults"
need "$OUT/direct.log" 'harness-vuln-asan              N=32  RETURN exit=0' "vuln ASan 32-item RETURN clean"

[ "$fail" -eq 0 ] && echo "FAST_REPLAY_OK rc=0" || echo "FAST_REPLAY_FAIL rc=1"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
