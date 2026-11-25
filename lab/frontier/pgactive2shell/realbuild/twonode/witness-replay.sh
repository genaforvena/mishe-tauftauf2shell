#!/bin/sh
# One-command replay of the two live two-node conflict arms from a clean
# archive of HEAD. Loopback-only; no external target. Author-side smoke test,
# not an independent verdict: a witness must run it in its own context.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel) || exit 1
T=$(mktemp -d /tmp/pgactive-two-witness.XXXXXX) || exit 1
V219=3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998
V2210=986917a8656c4d099659a148cb077570e233b8d358273354f06b06f57ab2885a
LIBDIR=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib
V219SO=/tmp/pgactive-full-219/pgactive-2.1.9/pgactive.so.v219-installed
# Restore the vulnerable build even when a run aborts before run-two.sh's
# own restore, and clear these lane-owned ports from an earlier aborted run.
trap 'cp "$V219SO" "$LIBDIR/pgactive.so"' EXIT
for PID in $(ps -eo pid,args | grep -E 'postgres -D n[12] -p 5843[12]' | grep -v grep | awk '{print $1}'); do
  kill -QUIT "$PID" 2>/dev/null || true
done
git -C "$REPO" archive HEAD lab/frontier/pgactive2shell/realbuild/twonode \
  | tar x -C "$T" || exit 1
D="$T/lab/frontier/pgactive2shell/realbuild/twonode"
FAIL=0
check() { # label expected-lib link conflict-type action version terms...
  LABEL=$1; WANTLIB=$2; LINK=$3; CT=$4; ACT=$5; VER=$6; shift 6
  OUT="$T/$LABEL.out"
  ( cd "$D" && CONFLICT_TYPE="$CT" ACTION="$ACT" VERSION="$VER" sh run-two.sh ) >"$OUT" 2>&1
  RC=$?
  USED=$(cut -d' ' -f1 /tmp/twonode-used-sha.txt 2>/dev/null)
  # The apply worker crashes after run-two.sh greps its log, so assert on
  # the saved server logs, not on the script's mid-run conflict-log excerpt.
  cat "$D/evidence/server1.log" "$D/evidence/server2.log" >"$T/$LABEL-server.log" 2>/dev/null
  T1=$(cat "$D/evidence/TERMINATIONS1.txt" 2>/dev/null); T1=${T1#TERMINATIONS1=}
  T2=$(cat "$D/evidence/TERMINATIONS2.txt" 2>/dev/null); T2=${T2#TERMINATIONS2=}
  printf '%s RC=%s LIB_OK=%s TERM1=%s TERM2=%s %s\n' \
    "$LABEL" "$RC" "$([ "$USED" = "$WANTLIB" ] && echo 1 || echo 0)" \
    "${T1:-?}" "${T2:-?}" "$LINK"
  [ "$RC" -eq 0 ] && [ "$USED" = "$WANTLIB" ] || FAIL=$((FAIL + 1))
  if [ "$WANTLIB" = "$V2210" ]; then
    [ "$T1" = 0 ] && [ "$T2" = 0 ] || FAIL=$((FAIL + 1))
  else
    [ "${T1:-0}" -ge 1 ] 2>/dev/null && [ "${T2:-0}" -ge 1 ] 2>/dev/null || FAIL=$((FAIL + 1))
  fi
  for TERM in "$@"; do
    grep -q "$TERM" "$T/$LABEL-server.log" || \
      { printf 'MISSING %s: %s\n' "$LABEL" "$TERM"; FAIL=$((FAIL + 1)); }
  done
}
# insert_insert: real apply-worker SIGSEGV in the resolver.
check v219-insert "$V219" 'expect TERM>=1, signal 11' insert_insert SKIP 2.1.9 \
  'was terminated by signal 11'
check v2210-insert "$V2210" 'expect TERM=0' insert_insert SKIP 2.1.10
# delete_delete: local == NULL, fixed 01 into the canary, SIGABRT.
check v219-delete "$V219" 'expect TERM>=1, signal 6' delete_delete SKIP 2.1.9 \
  'stack smashing detected' 'was terminated by signal 6'
check v2210-delete "$V2210" 'expect TERM=0' delete_delete SKIP 2.1.10
printf 'VERDICT=%s FAILURES=%s ROOT=%s\n' \
  "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)" "$FAIL" "$T"
exit "$FAIL"
