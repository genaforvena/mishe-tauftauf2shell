-- Signature copied verbatim from pinned pgactive--2.1.9.sql:1491-1501.
CREATE FUNCTION pgactive_parse_replident_name (
    replident text,
    remote_sysid OUT text,
    remote_timeline OUT oid,
    remote_dboid OUT oid,
    local_dboid OUT oid,
    replication_name OUT name
)
RETURNS record
AS :'libdir','pgactive_parse_replident_name_sql'
LANGUAGE C STRICT IMMUTABLE;
