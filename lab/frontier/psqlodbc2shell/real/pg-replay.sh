#!/bin/sh
# W147: drive the pinned psqlODBC driver through a real, loopback-only
# PostgreSQL 16.4 server, not the W146 fake handshake. Requires replay.sh
# to have built the ASan vulnerable/fixed trees first.
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
PGPORT=${PGPORT:-59433}
PD=${PGDATA:-$B/w147-pgdata}
DBUSER=$(id -un)

[ -x "$PGBIN/postgres" ] || { echo "no postgres in PGBIN=$PGBIN" >&2; exit 1; }
mkdir -p "$E"

if [ ! -s "$PD/PG_VERSION" ]; then
  "$PGBIN/initdb" -D "$PD" -A trust -U lab --no-instructions \
    >"$E/w147-pg-initdb.log" 2>&1
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

gcc -g -O0 -fsanitize=address "$HERE/odbc-harness.c" -o "$B/w147-pg-harness" -lodbc

for pair in 'vuln asan-vuln' 'fixed asan-fixed'; do
  set -- $pair
  cfg=$1; tree=$2
  dir="$B/w147-pg-$cfg"
  mkdir -p "$dir"
  {
    echo '[pg2shell]'
    echo 'Description = W147 loopback real PostgreSQL DSN'
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

args16=$(printf '1,%.0s' $(seq 1 16))
fn16="{fn CONCAT(${args16%,})}"
run() { # label cfg sql
  label=$1; cfg=$2; sql=$3
  out="$E/w147-pg-$label.out"
  ODBCSYSINI="$B/w147-pg-$cfg" ODBCINI="$B/w147-pg-$cfg/odbc.ini" \
    ASAN_OPTIONS=detect_leaks=0 timeout 30 "$B/w147-pg-harness" "$sql" exec \
    >"$out" 2>&1 || true
  printf '%-16s %s\n' "$label" \
    "$(grep -m1 -E 'WRITE of size|EXECDIRECT rc' "$out" | cut -c1-95)"
}
run vuln-fn16 vuln "SELECT $fn16"
run fixed-fn16 fixed "SELECT $fn16"
run vuln-safe vuln 'SELECT {fn CONCAT(1,2)}'
