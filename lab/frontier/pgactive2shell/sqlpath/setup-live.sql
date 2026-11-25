-- Instrumented variant of setup.sql: adds two capture-only SQL functions.
-- The parser body is the verbatim v2.1.9 body plus a LIVE_CAPTURE-only memcpy
-- inside the existing error branch, before elog(ERROR) longjmps.
\i setup.sql
CREATE FUNCTION pgactive_live_capture_reset()
RETURNS void
AS :'libdir','pgactive_live_capture_reset'
LANGUAGE C STRICT;

CREATE FUNCTION pgactive_live_capture_bytes()
RETURNS bytea
AS :'libdir','pgactive_live_capture_bytes'
LANGUAGE C STRICT;
