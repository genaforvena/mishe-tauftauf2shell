-- CVE-2026-120149 / GHSA-gqm6-3wfg-52x5 — upstream regression trigger from
-- fix commit 1e0a55a0f (contrib/postgres_fdw/sql/postgres_fdw.sql).
-- One remote INSERT row is expanded into three by a rule; two rows are sent
-- in one batch, so the FDW over-reports inserted rows (6 > 2) and the
-- vulnerable backend walks past rslots[].  Loopback only.
\set ON_ERROR_STOP off
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
DROP FOREIGN TABLE IF EXISTS ftable;
DROP TABLE IF EXISTS batch_table, batch_rule_table;
CREATE TABLE batch_table (x int);
CREATE TABLE batch_rule_table (x int);
CREATE RULE batch_rule AS ON INSERT TO batch_table
  DO INSTEAD INSERT INTO batch_rule_table SELECT i FROM generate_series(1,3) i;
CREATE SERVER IF NOT EXISTS loopback FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '127.0.0.1', port '5432', dbname 'postgres');
CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback
  OPTIONS (user 'postgres', password 'pg2shell');
CREATE FOREIGN TABLE ftable (x int) SERVER loopback
  OPTIONS (table_name 'batch_table', batch_size '10');
\echo == BATCH INSERT OF TWO ROWS (2 sent, rule reports 6) ==
INSERT INTO ftable VALUES (1), (2);
\echo == RULE-TABLE COUNT (expected 6 on both builds) ==
SELECT COUNT(*) FROM batch_rule_table;
\echo == END OF TRIGGER ==
