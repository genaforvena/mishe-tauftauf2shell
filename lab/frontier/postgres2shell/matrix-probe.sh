#!/bin/bash
# Host-side: for each batch size, send exactly batch_size local rows through
# a 12x-expanding rule and capture the first OOB slot value. Loopback only.
set -u
cd "$(dirname "$0")"
for bs in 8 12 16 20; do
  printf '%s\n' \
    '\\set ON_ERROR_STOP off' \
    'CREATE EXTENSION IF NOT EXISTS postgres_fdw;' \
    'DROP FOREIGN TABLE IF EXISTS ftable;' \
    'DROP TABLE IF EXISTS batch_table, batch_rule_table;' \
    'CREATE TABLE batch_table (x int);' \
    'CREATE TABLE batch_rule_table (x int);' \
    'CREATE RULE batch_rule AS ON INSERT TO batch_table' \
    '  DO INSTEAD INSERT INTO batch_rule_table SELECT i FROM generate_series(1,12) i;' \
    "CREATE SERVER IF NOT EXISTS loopback FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '127.0.0.1', port '5432', dbname 'postgres');" \
    "CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback OPTIONS (user 'postgres', password 'pg2shell');" \
    "CREATE FOREIGN TABLE ftable (x int) SERVER loopback OPTIONS (table_name 'batch_table', batch_size '$bs');" \
    "\\echo == MATRIX bs=$bs rows=$bs ===" \
    "INSERT INTO ftable SELECT i FROM generate_series(1,$bs) i;" \
    '\\echo == END ==' > "/tmp/trigger-matrix-$bs.sql"
  docker cp "/tmp/trigger-matrix-$bs.sql" pg2shell-gdb:/tmp/trigger-groom.sql >/dev/null
  timeout 90 docker exec pg2shell-gdb bash /tmp/groom-probe.sh > "logs/groom-matrix-bs$bs.log" 2>&1
  echo "=== bs=$bs ==="
  grep -E '^HIT i=' "logs/groom-matrix-bs$bs.log" | tail -4
  grep -E 'slot=\(nil\)|SIGSEGV|numInserted' "logs/groom-matrix-bs$bs.log" | head -3
done
date -u
