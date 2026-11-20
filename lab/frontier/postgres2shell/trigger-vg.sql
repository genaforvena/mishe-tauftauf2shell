-- Same CVE-2026-120149 regression as trigger.sql, but the loopback FDW
-- points at the second, Valgrind-wrapped instance on 127.0.0.1:55435.
\set ON_ERROR_STOP off
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
DROP FOREIGN TABLE IF EXISTS ftable;
DROP TABLE IF EXISTS batch_table, batch_rule_table;
CREATE TABLE batch_table (x int);
CREATE TABLE batch_rule_table (x int);
CREATE RULE batch_rule AS ON INSERT TO batch_table
  DO INSTEAD INSERT INTO batch_rule_table SELECT i FROM generate_series(1,3) i;
CREATE SERVER IF NOT EXISTS loopback_vg FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '127.0.0.1', port '55435', dbname 'postgres');
CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback_vg
  OPTIONS (user 'postgres', password 'pg2shell');
CREATE FOREIGN TABLE ftable (x int) SERVER loopback_vg
  OPTIONS (table_name 'batch_table', batch_size '10');
\echo == VALGRIND BATCH INSERT ==
INSERT INTO ftable VALUES (1), (2);
\echo == END ==
