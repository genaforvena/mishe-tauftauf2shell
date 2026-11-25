#!/bin/sh
# Non-ASan stack-layout measurement for the REAL pinned 2.1.9 extension.
# Builds pgactive.so from layout/pgactive_catalogs.c (pinned source plus a
# stderr stack dump in the parser error branch), drives the schema-qualified
# SQL function on a loopback cluster at growing payload lengths, records the
# offset of the saved return address relative to replication_name, then
# restores both the build source and the installed library.
#
# LABEL=o1  sh run-layout.sh                       # -O1 -g -fno-omit-frame-pointer
# LABEL=opt sh run-layout.sh                       # PGXS default production flags
set -u
cd "$(dirname "$0")" || exit 1
ROOT=$PWD
LABEL=${LABEL:-o1}
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
SRC=/tmp/pgactive-full-219/pgactive-2.1.9
LIB=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib/pgactive.so
PORT=${PORT:-58423}
SOCK=/tmp/pgactive-layout-sock
PGDATA=$ROOT/pgdata-layout
LOG=evidence/layout-$LABEL-server.log
SUM=evidence/layout-$LABEL-summary.txt
BUILDLOG=evidence/layout-$LABEL-build.log
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" "$LOG" "$SUM" "$BUILDLOG"

cp "$SRC/src/pgactive_catalogs.c" evidence/pgactive_catalogs.c.orig-backup || exit 1
cp "$LIB" evidence/pgactive.so.normal-backup || exit 1

finish() {
  if [ -f "$PGDATA/postmaster.pid" ]; then
    "$PGBIN/pg_ctl" -D "$PGDATA" -m immediate -w stop \
      >"evidence/layout-$LABEL-pgstop.log" 2>&1
    echo "LAYOUT_STOP=$?"
  fi
  cp evidence/pgactive.so.normal-backup "$LIB" 2>/dev/null
  cp evidence/pgactive_catalogs.c.orig-backup "$SRC/src/pgactive_catalogs.c" 2>/dev/null
  echo "NORMAL_SO_RESTORED=$(cmp -s "$LIB" evidence/pgactive.so.normal-backup && echo yes || echo no)"
  echo "SRC_RESTORED=$(cmp -s "$SRC/src/pgactive_catalogs.c" evidence/pgactive_catalogs.c.orig-backup && echo yes || echo no)"
}
trap finish EXIT

cp "$ROOT/pgactive_catalogs.c" "$SRC/src/pgactive_catalogs.c" || exit 1
(
  cd "$SRC" || exit 1
  make clean >"$ROOT/evidence/layout-$LABEL-clean.log" 2>&1
  if [ "$LABEL" = o1 ]; then
    make pgactive.so with_llvm=no \
      CFLAGS='-O1 -g -fPIC -fno-omit-frame-pointer' \
      EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include' \
      >"$ROOT/$BUILDLOG" 2>&1
  else
    make pgactive.so with_llvm=no \
      EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include' \
      >"$ROOT/$BUILDLOG" 2>&1
  fi
) || { echo LAYOUT_BUILD=FAIL; exit 1; }
echo "LAYOUT_BUILD=$?"
cp "$SRC/pgactive.so" "$LIB" || exit 1

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
  >"evidence/layout-$LABEL-initdb.log" 2>&1
echo "LAYOUT_INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/$LOG" -w start \
  -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1 \
      -c shared_preload_libraries=pgactive -c track_commit_timestamp=on \
      -c wal_level=logical" >"evidence/layout-$LABEL-pgstart.log" 2>&1
echo "LAYOUT_PGSTART=$?"
if [ ! -f "$PGDATA/postmaster.pid" ]; then
  cat "evidence/layout-$LABEL-pgstart.log"
  cat "$LOG"
  exit 1
fi
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"
$PSQL -c "CREATE EXTENSION pgactive VERSION '2.1.9';" \
  >"evidence/layout-$LABEL-create.out" 2>&1
echo "LAYOUT_CREATE=$?"

for N in 0 16 32 48 64 72 80 96 112 128 160 192 224 256; do
  PAY=$(printf 'AZ%.0s' $(seq 1 "$N"))
  NAME="pgactive_123_1_2_3_$PAY"
  echo "N=$N NAMELEN=${#NAME}" >> "$SUM"
  $PSQL -c "SELECT * FROM pgactive.pgactive_parse_replident_name('$NAME'::text);" \
    >"evidence/layout-$LABEL-n$N.out" 2>&1
  echo "RC=$?" >> "$SUM"
  grep '^LAYOUT PARSE ' "$LOG" | tail -1 >> "$SUM"
  grep '^LAYOUTWIN PARSE ' "$LOG" | tail -1 \
    | cut -c1-40 >> "$SUM"
done

$PSQL -c "SELECT 1;" >"evidence/layout-$LABEL-liveness.out" 2>&1
echo "LIVENESS_RC=$?" >> "$SUM"
echo "BACKEND_TERMINATIONS=$(grep -c 'terminating backend' "$LOG")" >> "$SUM"
echo '--- layout summary ---'
cat "$SUM"
echo '--- instrumented build warnings (if any) ---'
grep -E 'warning:|error:' "$BUILDLOG" | head -20 || true
