#!/bin/sh
# One-command replay of the catalog-derived replication-origin parser arm
# from a clean archive of HEAD. Loopback-only; no external target.
# Author-side smoke test, not an independent witness verdict.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel) || exit 1
T=$(mktemp -d /tmp/pgactive-originwire-witness.XXXXXX) || exit 1
V219=3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998
V2210=986917a8656c4d099659a148cb077570e233b8d358273354f06b06f57ab2885a
LIBDIR=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib
V219SO=/tmp/pgactive-full-219/pgactive-2.1.9/pgactive.so.v219-installed
ASANSO=/tmp/pgactive-full-219/pgactive-2.1.9/pgactive.so
PGBIN=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin
D=$T/lab/frontier/pgactive2shell/realbuild/twonode
cleanup() {
  for N in 1 2; do
    [ -f "$D/n$N/postmaster.pid" ] && "$PGBIN/pg_ctl" -D "$D/n$N" -m immediate -w stop >/dev/null 2>&1
  done
  cp "$V219SO" "$LIBDIR/pgactive.so" 2>/dev/null || true
}
trap cleanup EXIT
# Clear lane-owned ports left by an aborted earlier run.
for PID in $(ps -eo pid,args | grep -E 'postgres -D n[12] -p 5843[12]' | grep -v grep | awk '{print $1}'); do
  kill -QUIT "$PID" 2>/dev/null || true
done
git -C "$REPO" archive HEAD lab/frontier/pgactive2shell/realbuild/twonode \
  | tar x -C "$T" || exit 1

FAIL=0
need() { # label file term...
  L=$1; F=$2; shift 2
  for TERM in "$@"; do
    grep -q "$TERM" "$F" 2>/dev/null || { printf 'MISSING %s: %s\n' "$L" "$TERM"; FAIL=$((FAIL + 1)); }
  done
}
marker() { # key expected
  V=$(cat "$D/evidence/$1.txt" 2>/dev/null); V=${V#$1=}
  printf ' %s=%s' "$1" "${V:-?}"
  [ "${V:-?}" = "$2" ] || FAIL=$((FAIL + 1))
}

run_arm() { # label want-sha env...
  LABEL=$1; WANT=$2; shift 2
  OUT="$T/$LABEL.out"
  ( cd "$D" && env NO_HANDLER=1 ORIGIN_TUPLE=1 "$@" sh run-two.sh ) >"$OUT" 2>&1
  RC=$?
  USED=$(cut -d' ' -f1 /tmp/twonode-used-sha.txt 2>/dev/null)
  [ "$WANT" = ASAN ] && WANT=$(sha256sum "$ASANSO" 2>/dev/null | cut -d' ' -f1)
  cat "$D/evidence/server1.log" "$D/evidence/server2.log" >"$T/$LABEL-server.log" 2>/dev/null
  printf '%s RC=%s LIB_OK=%s' "$LABEL" "$RC" "$([ "$USED" = "$WANT" ] && echo 1 || echo 0)"
  [ "$RC" -eq 0 ] || FAIL=$((FAIL + 1))
  [ "$USED" = "$WANT" ] || FAIL=$((FAIL + 1))
  marker CREATE_GROUP 0
  marker NODE1_READY r
  marker NODE2_READY r
  marker TUPLE_ORIGIN_INSERT 0
  marker TABLE_ON_NODE2 t
  marker PGSTOP1 0
  marker PGSTOP2 0
  printf '\n'
}

terms() { # label expected1 expected2
  T1=$(cat "$D/evidence/TERMINATIONS1.txt" 2>/dev/null); T1=${T1#TERMINATIONS1=}
  T2=$(cat "$D/evidence/TERMINATIONS2.txt" 2>/dev/null); T2=${T2#TERMINATIONS2=}
  printf '  %s TERMINATIONS1=%s TERMINATIONS2=%s\n' "$1" "${T1:-?}" "${T2:-?}"
  [ "${T1:-?}" = "$2" ] && [ "${T2:-?}" = "$3" ] || FAIL=$((FAIL + 1))
}

# 1. Vulnerable 2.1.9, plain: parser reached, elog(longjmp), no termination.
run_arm v219-plain "$V219" VERSION=2.1.9
need v219-plain "$T/v219-plain-server.log" 'could not parse slot name' 'pgactive_1_1_1_1_AZ'
terms v219-plain 0 0

# 2. Vulnerable 2.1.9 rebuilt with ASan: observed stack write in the parser.
run_arm v219-asan ASAN VERSION=2.1.9 ASAN=1
need v219-asan "$T/v219-asan.out" 'ASAN_BUILD=0'
need v219-asan "$T/v219-asan-server.log" 'stack-buffer-overflow' 'WRITE of size 261' \
  'pgactive_parse_replident_name' 'pgactive_catalogs.c:351'

# 3. Fixed 2.1.10: parser rejects the same name, no ASan, no termination.
run_arm v2210-fixed "$V2210" VERSION=2.1.10
need v2210-fixed "$T/v2210-fixed-server.log" 'could not parse replication origin name'
if grep -q 'stack-buffer-overflow' "$T/v2210-fixed-server.log" 2>/dev/null; then
  printf 'MISSING v2210-fixed: unexpected ASan report\n'; FAIL=$((FAIL + 1))
fi
terms v2210-fixed 0 0

printf 'VERDICT=%s FAILURES=%s ROOT=%s\n' \
  "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)" "$FAIL" "$T"
exit "$FAIL"
