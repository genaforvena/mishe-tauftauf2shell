/* pgactive2sql: the pinned v2.1.9 / v2.1.10 pgactive_parse_replident_name
 * function bodies and their SQL wrapper, compiled as a small C extension
 * against real PostgreSQL 16 server headers. No logic is reimplemented:
 * - vulnerable body: provision/catalogs-v2.1.9.c:347-358, verbatim;
 * - fixed body:      provision/catalogs-v2.1.10.c:347-356, verbatim;
 * - SQL wrapper:     pgactive-2.1.9.tar.gz src/pgactive.c:1513-1544, verbatim.
 * The only added scaffolding is PG_MODULE_MAGIC, the two PGDLLEXPORT
 * declarations, PG_FUNCTION_INFO_V1 and the two type/constant macros, all
 * copied from pinned headers (internal-v2.1.9.h:17,31;
 * internal-v2.1.10.h:34,38; access/xlogdefs.h:60 from the PG16 headers).
 */
#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "access/xlogdefs.h"
#include <inttypes.h>

PG_MODULE_MAGIC;
#ifdef LIVE_CAPTURE
/* Instrumentation-only globals; absent from the verbatim vulnerable/fixed
 * builds. Reads the already-written stack region from the live backend. */
#define LIVE_CAPTURE_BYTES 128
static char pgactive_live_capture[LIVE_CAPTURE_BYTES];
static int	pgactive_live_capture_len = 0;
PGDLLEXPORT Datum pgactive_live_capture_reset(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgactive_live_capture_reset);
PGDLLEXPORT Datum pgactive_live_capture_bytes(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgactive_live_capture_bytes);
#endif

#define EMPTY_REPLICATION_NAME ""
#define pgactiveNodeId_DEFINED
typedef struct pgactiveNodeId
{
	uint64		sysid;
	TimeLineID	timeline;
	Oid			dboid;
}			pgactiveNodeId;

#ifdef FIXED_BUILD
/* v2.1.10 include/pgactive_internal.h:38 */
#define pgactive_REPORIGIN_ID_SCAN_FORMAT "pgactive_%"SCNu64"_%u_%u_%u_%n"
#else
/* v2.1.9 include/pgactive_internal.h:31 */
#define pgactive_REPORIGIN_ID_FORMAT "pgactive_"UINT64_FORMAT"_%u_%u_%u_%s"
#endif

PGDLLEXPORT Datum pgactive_parse_replident_name_sql(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgactive_parse_replident_name_sql);

#ifdef FIXED_BUILD
/* v2.1.10 src/pgactive_catalogs.c:346-357 */
void
pgactive_parse_replident_name(const char *riname, pgactiveNodeId * node, Oid *local_dboid)
{
	int			parsed_len = -1;

	if (sscanf(riname, pgactive_REPORIGIN_ID_SCAN_FORMAT,
			   &node->sysid, &node->timeline, &node->dboid, local_dboid,
			   &parsed_len) != 4 ||
		parsed_len < 0 ||
		riname[parsed_len] != '\0')
		elog(ERROR, "could not parse replication origin name: %s", riname);
}
#else
/* v2.1.9 src/pgactive_catalogs.c:347-358 */
void
pgactive_parse_replident_name(const char *riname, pgactiveNodeId * node, Oid *local_dboid)
{
	NameData	replication_name;

	if (sscanf(riname, pgactive_REPORIGIN_ID_FORMAT,
			   &node->sysid, &node->timeline, &node->dboid, local_dboid,
			   NameStr(replication_name)) != 4)
	{
#ifdef LIVE_CAPTURE
		memcpy(pgactive_live_capture, &replication_name, LIVE_CAPTURE_BYTES);
		pgactive_live_capture_len = LIVE_CAPTURE_BYTES;
#endif
		/* Note: the test above excludes non-empty replication names */
		elog(ERROR, "could not parse slot name: %s", riname);
	}
}
#endif

/* src/pgactive.c:1513-1544 */
Datum
pgactive_parse_replident_name_sql(PG_FUNCTION_ARGS)
{
	const char *replident_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	Datum		values[5];
	bool		isnull[5];
	TupleDesc	tupleDesc;
	HeapTuple	returnTuple;
	char		remote_sysid_str[33];
	pgactiveNodeId remote;
	Oid			local_dboid;

	if (get_call_result_type(fcinfo, NULL, &tupleDesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	memset(values, 0, sizeof(values));
	memset(isnull, 0, sizeof(isnull));

	pgactive_parse_replident_name(replident_name, &remote, &local_dboid);

	snprintf(remote_sysid_str, sizeof(remote_sysid_str),
			 UINT64_FORMAT, remote.sysid);

	values[0] = CStringGetTextDatum(remote_sysid_str);
	values[1] = ObjectIdGetDatum(remote.timeline);
	values[2] = ObjectIdGetDatum(remote.dboid);
	values[3] = ObjectIdGetDatum(local_dboid);
	values[4] = CStringGetTextDatum(EMPTY_REPLICATION_NAME);

	returnTuple = heap_form_tuple(tupleDesc, values, isnull);

	PG_RETURN_DATUM(HeapTupleGetDatum(returnTuple));
}

#ifdef LIVE_CAPTURE
Datum
pgactive_live_capture_reset(PG_FUNCTION_ARGS)
{
	pgactive_live_capture_len = 0;
	PG_RETURN_VOID();
}

Datum
pgactive_live_capture_bytes(PG_FUNCTION_ARGS)
{
	bytea	   *out;

	out = (bytea *) palloc(VARHDRSZ + pgactive_live_capture_len);
	SET_VARSIZE(out, VARHDRSZ + pgactive_live_capture_len);
	memcpy(VARDATA(out), pgactive_live_capture, pgactive_live_capture_len);
	PG_RETURN_BYTEA_P(out);
}
#endif
