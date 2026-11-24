#ifndef PGACTIVE2SHELL_TYPES_H
#define PGACTIVE2SHELL_TYPES_H
/* Stand-ins for host PostgreSQL 16 x86_64 Linux headers; no PG logic here.
 * INT64_MODIFIER "l"   -- /usr/include/postgresql/pg_config.h:591
 * NAMEDATALEN 64        -- /usr/include/postgresql/pg_config_manual.h:29
 * NameStr(name)         -- /usr/include/postgresql/internal/c.h:747
 * pgactiveNodeId layout -- pinned internal-v2.1.10.h:67-72
 * No function logic is reimplemented: the two generated files are verbatim
 * pgactive source; only type and helper definitions are stand-ins.
 */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#define INT64_MODIFIER "l"
#define UINT64_FORMAT "%" INT64_MODIFIER "u"

typedef unsigned int Oid;
typedef unsigned int TimeLineID;
typedef unsigned long uint64;

typedef struct pgactiveNodeId
{
	uint64		sysid;
	TimeLineID	timeline;
	Oid			dboid;
}			pgactiveNodeId;

typedef struct nameData
{
	char		data[64];
}			NameData;

/* Records the destination address without altering the pinned function text. */
extern char *g_dest;
#define NameStr(name) (g_dest = (name).data)

#define ERROR 21
extern int g_errors;
#ifdef CAPTURE_MODE
/* Called from the stand-in elog, i.e. after sscanf has written but before the
 * vulnerable function returns, while the stack object is still live. */
extern void dump_chosen(void);
#define elog(level, ...) do { (void)(level); g_errors++; dump_chosen(); \
	fprintf(stderr, "ELOG: " __VA_ARGS__); fputc('\n', stderr); } while (0)
#else
#define elog(level, ...) do { (void)(level); g_errors++; \
	fprintf(stderr, "ELOG: " __VA_ARGS__); fputc('\n', stderr); } while (0)
#endif

#endif
