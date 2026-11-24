/* Verbatim extraction: aws/pgactive v2.1.10 src/pgactive_catalogs.c lines
 * 341-357 (SHA-256 of source in ../provision/catalogs-v2.1.10.c). Only added
 * text: this comment, the include, and the format macro copied verbatim from
 * that tag's include/pgactive_internal.h:38. */
#include "types.h"

/* v2.1.10 include/pgactive_internal.h:38 (SCNu64 from <inttypes.h>) */
#define pgactive_REPORIGIN_ID_SCAN_FORMAT "pgactive_%" SCNu64 "_%u_%u_%u_%n"

/*
 * Get node identifiers from a replication identifier (replident, riident) name
 *
 * This isn't in pgactive_common.c because it uses elog().
 */
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
