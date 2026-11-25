#!/bin/sh
# Two-node loopback pgactive group: drive a real apply-worker conflict into
# pgactive_conflict_handlers_resolve(). No external target, 127.0.0.1 only.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
P1=58431
P2=58432
ROOT=$PWD
NO_HANDLER=${NO_HANDLER:-0}
ACTION=${ACTION:-ROW}
SHARE=/tmp/pgactive-build/pg16root/usr/share/postgresql/16/extension
VERSION=${VERSION:-2.1.9}
NO_CONFLICT=${NO_CONFLICT:-0}
LIBDIR=/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/lib
V219SO=/tmp/pgactive-full-219/pgactive-2.1.9/pgactive.so.v219-installed
V2210SO=/tmp/pgactive-full-2210/pgactive-2.1.10/pgactive.so
ulimit -c unlimited 2>/dev/null || true
case "$VERSION" in
  2.1.9)  cp "$V219SO" "$LIBDIR/pgactive.so" ;;
  2.1.10) cp "$V2210SO" "$LIBDIR/pgactive.so" ;;
  *) echo "unknown VERSION=$VERSION"; exit 2 ;;
esac
sha256sum "$LIBDIR/pgactive.so" > /tmp/twonode-used-sha.txt
ASAN=${ASAN:-0}
PRELOAD=
if [ "$ASAN" = 1 ]; then
  SRC=/tmp/pgactive-full-219/pgactive-2.1.9
  ( cd "$SRC" || exit 1
    make clean >"$ROOT/evidence/asan-clean.log" 2>&1
    make pgactive.so with_llvm=no \
      CFLAGS='-O1 -g -fPIC -fsanitize=address -fno-omit-frame-pointer' \
      EXTRA_CFLAGS='-I/usr/include/postgresql -I/usr/include/postgresql/internal -I/tmp/pgactive-build/pg16root/usr/include' \
      >"$ROOT/evidence/asan-build.log" 2>&1 ) || { echo ASAN_BUILD=FAIL; exit 1; }
  echo "ASAN_BUILD=$?"
  cp "$SRC/pgactive.so" "$LIBDIR/pgactive.so"
  PRELOAD="env LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0"
fi
# 2.1.9 source control still declares default_version=2.1.8; the per-db
# worker's pgactive_maintain_schema() ALTER EXTENSION with no target tries a
# 2.1.9 -> 2.1.8 downgrade and dies. Point this lab-only control file at the
# pinned 2.1.9 SQL.
printf '%s\n' "# pgactive extension" \
  "comment = 'Active-Active Replication Extension for PostgreSQL'" \
  "default_version = '$VERSION'" "module_pathname = '\$libdir/pgactive'" \
  "relocatable = false" "schema = pg_catalog" > "$SHARE/pgactive.control"
for N in 1 2; do
    [ -f "n$N/postmaster.pid" ] && "$PGBIN/pg_ctl" -D "n$N" -m immediate -w stop \
        >"evidence/stop-old$N.log" 2>&1 || true
done
mkdir -p evidence n1 n2 s1 s2
rm -rf n1 n2 evidence/*
USER=mesh-home
DSN1="host=127.0.0.1 port=$P1 dbname=postgres user=$USER"
DSN2="host=127.0.0.1 port=$P2 dbname=postgres user=$USER"
status() { echo "$1=$2" | tee "evidence/$1.txt"; }
psql1() { "$PGBIN/psql" -h "$ROOT/s1" -p "$P1" -d postgres -X -q -v ON_ERROR_STOP=1 "$@"; }
psql2() { "$PGBIN/psql" -h "$ROOT/s2" -p "$P2" -d postgres -X -q -v ON_ERROR_STOP=1 "$@"; }

for N in 1 2; do
    "$PGBIN/initdb" -D "n$N" -A trust --no-sync --no-instructions >"evidence/initdb$N.log" 2>&1
    status "INITDB$N" $?
done

for N in 1 2; do
    PORT=$([ "$N" = 1 ] && echo "$P1" || echo "$P2")
    $PRELOAD "$PGBIN/pg_ctl" -D "n$N" -l "evidence/server$N.log" -w start \
      -o "-p $PORT -k $ROOT/s$N -c listen_addresses=127.0.0.1 \
          -c shared_preload_libraries=pgactive -c track_commit_timestamp=on \
          -c wal_level=logical -c max_replication_slots=10 -c max_wal_senders=10 \
          -c max_worker_processes=20 \
          -c output_plugin_libraries=pgoutput,test_decoding,pgactive" >"evidence/pgstart$N.log" 2>&1
    status "PGSTART$N" $?
done
[ -f n1/postmaster.pid ] && [ -f n2/postmaster.pid ] || {
    echo '--- start failure ---'; cat evidence/pgstart1.log evidence/pgstart2.log
    cat evidence/server1.log evidence/server2.log; exit 1; }

for N in 1 2; do
    if [ "$N" = 1 ]; then Q="psql1"; else Q="psql2"; fi
    $Q -c "CREATE EXTENSION pgactive VERSION '$VERSION';" >"evidence/create$N.out" 2>&1
    status "CREATE$N" $?
    $Q -c "ALTER SYSTEM SET pgactive.skip_ddl_replication=off;" \
        >"evidence/guc${N}a.out" 2>&1
    $Q -c "SELECT pg_reload_conf();" >"evidence/guc${N}b.out" 2>&1
    status "GUC$N" $?
done

psql1 -c "SELECT pgactive.pgactive_create_group('node1', '$DSN1');" >evidence/create-group.out 2>&1
status CREATE_GROUP $?
# The per-db worker flips node_status b -> r after create_group; joining
# before that fails with "node_status=b instead of expected 'r'".
I=0
while [ "$I" -lt 30 ]; do
    S=$("$PGBIN/psql" -h "$ROOT/s1" -p "$P1" -d postgres -X -A -t -q -c \
        "SELECT node_status FROM pgactive.pgactive_nodes WHERE node_name='node1';" 2>/dev/null)
    [ "$S" = r ] && break
    sleep 1; I=$((I+1))
done
status "NODE1_READY" "$S"
psql2 -c "SELECT pgactive.pgactive_join_group('node2', '$DSN2', '$DSN1');" >evidence/join-group.out 2>&1
status JOIN_GROUP $?
I=0
while [ "$I" -lt 60 ]; do
    S2=$("$PGBIN/psql" -h "$ROOT/s2" -p "$P2" -d postgres -X -A -t -q -c \
        "SELECT node_status FROM pgactive.pgactive_nodes WHERE node_name='node2';" 2>/dev/null)
    [ "$S2" = r ] && break
    sleep 1; I=$((I+1))
done
status "NODE2_READY" "$S2"
psql1 -c "SELECT node_name, node_status FROM pgactive.pgactive_nodes;" >evidence/nodes1.out 2>&1
psql2 -c "SELECT node_name, node_status FROM pgactive.pgactive_nodes;" >evidence/nodes2.out 2>&1

# Replicated table with a primary key. DDL replication is on; node 2 should
# receive it automatically.
psql1 -c "CREATE TABLE public.t (id int PRIMARY KEY, val text);" >evidence/table1.out 2>&1
status TABLE1 $?
I=0
while [ "$I" -lt 30 ]; do
    T=$("$PGBIN/psql" -h "$ROOT/s2" -p "$P2" -d postgres -X -A -t -q -c \
        "SELECT to_regclass('public.t') IS NOT NULL;" 2>/dev/null)
    [ "$T" = t ] && break
    sleep 1; I=$((I+1))
done
status "TABLE_ON_NODE2" "$T"

HANDLER='public.resolve_conflict(public.t,public.t,text,regclass,pgactive.pgactive_conflict_type)'
if [ "$NO_HANDLER" != 1 ]; then
  for N in 1 2; do
    if [ "$N" = 1 ]; then Q="psql1"; else Q="psql2"; fi
    $Q -c "CREATE OR REPLACE FUNCTION public.resolve_conflict(a public.t, b public.t, cmd text, rel regclass, typ pgactive.pgactive_conflict_type, OUT c public.t, OUT action pgactive.pgactive_conflict_handler_action) LANGUAGE plpgsql AS \$\$ BEGIN c := a; action := '$ACTION'; END \$\$;" >"evidence/handler-fn$N.out" 2>&1
    status "HANDLER_FN$N" $?
    # pgactive_create_conflict_handler() is a hard stub in 2.1.9; configure
    # the handler with a direct row in the extension table instead.
    $Q -c "INSERT INTO pgactive.pgactive_conflict_handlers (ch_name, ch_type, ch_reloid, ch_fun) VALUES ('h', 'insert_insert', 'public.t'::regclass, '$HANDLER');" >"evidence/handler-reg$N.out" 2>&1
    status "HANDLER_REG$N" $?
    $Q -c "SELECT ch_name, ch_type, ch_fun FROM pgactive.pgactive_conflict_handlers;" >"evidence/handler-list$N.out" 2>&1
  done
fi

# Race the two inserts so both commit before either apply worker delivers
# the other's row; that yields an insert_insert conflict on both nodes.
if [ "$NO_CONFLICT" = 1 ]; then
    # Control: handler configured, but only one node writes. No conflict,
    # so the resolver must not be called.
    psql1 -c "INSERT INTO public.t VALUES (1, 'node1');" >evidence/insert1.out 2>&1
    status INSERT1 $?
else
    # Race the two inserts so both commit before either apply worker
    # delivers the other's row; that yields an insert_insert conflict.
    psql1 -c "INSERT INTO public.t VALUES (1, 'node1');" >evidence/insert1.out 2>&1 & J1=$!
    psql2 -c "INSERT INTO public.t VALUES (1, 'node2');" >evidence/insert2.out 2>&1 & J2=$!
    wait $J1; status INSERT1 $?
    wait $J2; status INSERT2 $?
fi
psql1 -c "SELECT * FROM public.t;" >evidence/rows1.out 2>&1
psql2 -c "SELECT * FROM public.t;" >evidence/rows2.out 2>&1
echo '--- handlers ---'; cat evidence/handler-fn1.out evidence/handler-reg1.out evidence/handler-fn2.out evidence/handler-reg2.out
echo '--- rows ---'; cat evidence/rows1.out evidence/rows2.out
echo '--- conflict log ---'; grep -iE 'conflict|terminated|signal|segmentation|stack' evidence/server1.log evidence/server2.log | tail -40

echo '--- create group ---'; cat evidence/create-group.out
echo '--- join group ---'; cat evidence/join-group.out
echo '--- nodes ---'; cat evidence/nodes1.out evidence/nodes2.out
echo '--- table ---'; cat evidence/table1.out evidence/table2.out

echo '--- GUC ---'; cat evidence/guc1a.out evidence/guc1b.out
echo '--- node status ---'
"$PGBIN/psql" -h "$ROOT/s1" -p "$P1" -d postgres -X -q -c \
  'SELECT node_name, node_status FROM pgactive.pgactive_nodes;'
"$PGBIN/psql" -h "$ROOT/s2" -p "$P2" -d postgres -X -q -c \
  'SELECT node_name, node_status FROM pgactive.pgactive_nodes;'
for N in 1 2; do
    "$PGBIN/pg_ctl" -D "n$N" -m fast -w stop >"evidence/pgstop$N.log" 2>&1
    status "PGSTOP$N" $?
done
for N in 1 2; do
    status "TERMINATIONS$N" "$(grep -c 'was terminated by signal' evidence/server$N.log)"
done
cp "$V219SO" "$LIBDIR/pgactive.so"
sha256sum "$LIBDIR/pgactive.so" > /tmp/twonode-restored-sha.txt
