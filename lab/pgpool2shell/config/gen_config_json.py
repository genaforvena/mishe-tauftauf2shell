#!/usr/bin/env python3
"""Build a watchdog peer POOL_CONFIG JSON with a peer-chosen backend_desc length.

Used for both the direct-call harness cross-check and the loopback type-'Z'
(WD_POOL_CONFIG_DATA) wire replay. All required scalar keys from
get_pool_config_from_json() (4.7.2 wd_json_data.c:51-123) are present.
"""
import json
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 129
chosen = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x42424242

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
cfg["backend_desc"] = [
    {"backend_port": chosen if i >= 128 else 5432, "backend_hostname": "h"}
    for i in range(n)
]
cfg["wd_nodes"] = [{"wd_port": 9000, "pgpool_port": 9999, "hostname": "node0"}]
print(json.dumps(cfg, separators=(",", ":")))
