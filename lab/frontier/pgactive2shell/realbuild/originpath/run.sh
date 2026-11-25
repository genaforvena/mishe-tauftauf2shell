#!/bin/sh
# Bound catalog-derived replication-origin names on loopback PostgreSQL 16.15.
# Question: can the catalog/wire caller of pgactive_parse_replident_name()
# (pgactive_catalogs.c:321 via replorigin_by_oid) carry an overflowing name,
# and can a non-superuser create such an origin? Loopback only.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PORT=${PORT:-58429}
ROOT=$PWD
PGDATA=/tmp/pgactive-originpath-pgdata
SOCK=/tmp
rm -rf "$PGDATA" evidence
mkdir -p evidence
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q"

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
    >evidence/initdb.log 2>&1
echo "INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1 \
        -c shared_preload_libraries=pgactive -c track_commit_timestamp=on \
        -c output_plugin_libraries=pgactive -c wal_level=logical" >evidence/pgstart.log 2>&1
echo "PGSTART=$?"
[ -f "$PGDATA/postmaster.pid" ] || { cat evidence/pgstart.log; cat evidence/server.log; exit 1; }

# pgactive extension present so the parser ACLs are the real ones.
$PSQL -c "CREATE EXTENSION pgactive VERSION '2.1.9';" \
    >evidence/create.out 2>&1
echo "CREATE=$?"
$PSQL -c "ALTER SYSTEM SET pgactive.skip_ddl_replication = off;" \
    >evidence/guc.out 2>&1
$PSQL -c "SELECT pg_reload_conf();" >>evidence/guc.out 2>&1
echo "GUC_RC=$?"
sleep 1

# 63-byte origin name: prefix is 16 bytes ('pgactive_123_1_2_3_'), so 47
# trailing bytes. 64-byte name needs 48 trailing bytes.
$PSQL -c "SELECT pg_replication_origin_create('pgactive_123_1_2_3_' || repeat('a', 47));" \
    >evidence/origin-63.out 2>&1
echo "ORIGIN63_RC=$?"
$PSQL -c "SELECT pg_replication_origin_create('pgactive_123_1_2_3_' || repeat('a', 48));" \
    >evidence/origin-64.out 2>&1
$PSQL -c "SELECT pg_replication_origin_create('pgactive_123_1_2_3_' || repeat('a', 256));" \
    >evidence/origin-272.out 2>&1
echo "ORIGIN272_RC=$?"
$PSQL -c "SELECT roname, length(roname) AS n FROM pg_replication_origin WHERE length(roname) > 63;" \
    >evidence/origin-long.out 2>&1
echo "ORIGIN_LONG_RC=$?"
echo "ORIGIN64_RC=$?"
# Slot names feed pgactive_output.c:382 (pgactive_parse_slot_name) on the
# publisher side of a replication connection.
$PSQL -c "SELECT pg_create_logical_replication_slot('pgactive_1_1_1_1_' || repeat('a', 80), 'pgactive');" \
    >evidence/slot-96.out 2>&1
echo "SLOT96_RC=$?"
$PSQL -c "SELECT slot_name, length(slot_name) AS n FROM pg_replication_slots;" \
    >evidence/slot-catalog.out 2>&1
echo "SLOT_CATALOG_RC=$?"
$PSQL -c "SELECT pg_replication_origin_create('pgactive_123_1_2_3_' || repeat('a', 80));" \
    >evidence/origin-96.out 2>&1
echo "ORIGIN96_RC=$?"
$PSQL -c "SELECT roname, length(roname) AS n FROM pg_replication_origin ORDER BY roname;" \
    >evidence/origin-catalog.out 2>&1
echo "ORIGIN_CATALOG_RC=$?"

# Lower-privilege route: can a plain LOGIN role create an origin at all?
$PSQL -c "CREATE ROLE lowpriv LOGIN;" >evidence/role.out 2>&1
echo "ROLE_RC=$?"
$PSQL -c "SET ROLE lowpriv; SELECT pg_replication_origin_create('lowpriv_origin');" \
    >evidence/lowpriv-origin.out 2>&1
echo "LOWPRIV_ORIGIN_RC=$?"
$PSQL -c "SET ROLE lowpriv; SELECT * FROM pgactive.pgactive_parse_replident_name('pgactive_123_1_2_3_'::text);" \
    >evidence/lowpriv-parser.out 2>&1
echo "LOWPRIV_PARSER_RC=$?"

$PSQL -c "SELECT proname, proacl, prosecdef FROM pg_proc WHERE proname IN ('pgactive_parse_replident_name','pgactive_parse_slot_name','pg_replication_origin_create') ORDER BY proname;" \
    >evidence/acl.out 2>&1
echo "ACL_RC=$?"

# Catalog-derived path: lock_holder is set from replorigin_session_origin in
# pgactive_locks.c:1560; pgactive_get_global_locks_info() at :2550 then calls
# pgactive_fetch_sysid_via_node_id_ifexists() -> replorigin_by_oid() ->
# pgactive_parse_replident_name(). All in one backend session.
$PSQL -c "SELECT pgactive.pgactive_create_group('node1', 'dbname=postgres host=/tmp port=$PORT', 1, ARRAY['default']);" \
    >evidence/create-group.out 2>&1
echo "CREATE_GROUP_RC=$?"
$PSQL -c "SELECT pgactive.pgactive_wait_for_node_ready(5);" \
    >evidence/ready.out 2>&1
echo "READY_RC=$?"
$PSQL -c "SELECT pg_replication_origin_session_setup('pgactive_123_1_2_3_' || repeat('a', 80)); SELECT pgactive.pgactive_acquire_global_lock('ddl_lock');" \
    >evidence/acquire.out 2>&1
echo "ACQUIRE_RC=$?"
$PSQL -c "SELECT * FROM pgactive.pgactive_get_global_locks_info();" \
    >evidence/locks-after.out 2>&1
echo "LOCKS_AFTER_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/pgstop.log 2>&1
echo "PGSTOP=$?"

echo '--- origin 63 ---'; cat evidence/origin-63.out
echo '--- origin 64 ---'; cat evidence/origin-64.out
echo '--- origin 96 ---'; cat evidence/origin-96.out
echo '--- catalog ---'; cat evidence/origin-catalog.out
echo '--- slot 96 ---'; cat evidence/slot-96.out
echo '--- slot catalog ---'; cat evidence/slot-catalog.out
echo '--- lowpriv origin ---'; cat evidence/lowpriv-origin.out
echo '--- lowpriv parser ---'; cat evidence/lowpriv-parser.out
echo '--- acl ---'; cat evidence/acl.out
