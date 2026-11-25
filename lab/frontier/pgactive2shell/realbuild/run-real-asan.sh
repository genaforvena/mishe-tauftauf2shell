#!/bin/sh
# ASan-instrumented build of the FULL pinned 2.1.9 extension, reached through
# the real CREATE EXTENSION SQL path. LD_PRELOAD supplies the ASan runtime to
# the loopback postmaster. The normal installed library is restored on exit.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
SRC=/tmp/pgactive-full-219/pgactive-2.1.9
LIB=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib/pgactive.so
PORT=${PORT:-58422}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata-asan
SOCK=${ROOT}/sock-asan
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/real-asan-server.log

cp "$LIB" evidence/pgactive.so.normal-backup
(
  cd "$SRC" || exit 1
  make clean >"$ROOT/evidence/real-asan-clean.log" 2>&1
  make pgactive.so with_llvm=no \
    CFLAGS='-O1 -g -fPIC -fsanitize=address -fno-omit-frame-pointer' \
    EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include' \
    >"$ROOT/evidence/real-asan-build.log" 2>&1
) || { cp evidence/pgactive.so.normal-backup "$LIB"; echo ASAN_BUILD=FAIL; exit 1; }
echo "ASAN_BUILD=$?"
cp "$SRC/pgactive.so" "$LIB"

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
    >evidence/real-asan-initdb.log 2>&1
echo "ASAN_INITDB=$?"
LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/real-asan-server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1 \
        -c shared_preload_libraries=pgactive -c track_commit_timestamp=on \
        -c wal_level=logical" >evidence/real-asan-pgstart.log 2>&1
echo "ASAN_PGSTART=$?"
if [ ! -f "$PGDATA/postmaster.pid" ]; then
  cat evidence/real-asan-pgstart.log; cat evidence/real-asan-server.log
  cp evidence/pgactive.so.normal-backup "$LIB"
  exit 1
fi
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"
$PSQL -c "CREATE EXTENSION pgactive VERSION '2.1.9';" \
    >evidence/real-asan-create.out 2>&1
echo "ASAN_CREATE=$?"
ATTACK=$(cat evidence/vuln-attack-name.txt)
$PSQL -c "SELECT * FROM pgactive.pgactive_parse_replident_name('$ATTACK'::text);" \
    >evidence/real-asan-attack.out 2>&1
echo "ASAN_ATTACK_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m immediate -w stop \
    >evidence/real-asan-stop.log 2>&1
echo "ASAN_STOP=$?"
cp evidence/pgactive.so.normal-backup "$LIB"
echo "NORMAL_SO_RESTORED=$(cmp -s "$LIB" evidence/pgactive.so.normal-backup && echo yes || echo no)"
echo '--- ASan server evidence ---'
grep -E 'AddressSanitizer|WRITE of size|replication_name|pgactive_parse_replident_name' \
    evidence/real-asan-server.log | head -20 || true
