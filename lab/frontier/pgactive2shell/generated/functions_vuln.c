/* Verbatim extraction: aws/pgactive v2.1.9 src/pgactive_catalogs.c lines
 * 341-358 (SHA-256 of source in ../provision/catalogs-v2.1.9.c). Only added
 * text: this comment, the include, and the format macro copied verbatim from
 * that tag's include/pgactive_internal.h:31. */
#include "types.h"

/* v2.1.9 include/pgactive_internal.h:31 */
#define pgactive_REPORIGIN_ID_FORMAT "pgactive_" UINT64_FORMAT "_%u_%u_%u_%s"

/*
 * Get node identifiers from a replication identifier (replident, riident) name
 *
 * This isn't in pgactive_common.c because it uses elog().
 */
void
pgactive_parse_replident_name(const char *riname, pgactiveNodeId * node, Oid *local_dboid)
{
	NameData	replication_name;

	if (sscanf(riname, pgactive_REPORIGIN_ID_FORMAT,
			   &node->sysid, &node->timeline, &node->dboid, local_dboid,
			   NameStr(replication_name)) != 4)
	{
		/* Note: the test above excludes non-empty replication names */
		elog(ERROR, "could not parse slot name: %s", riname);
	}
}
