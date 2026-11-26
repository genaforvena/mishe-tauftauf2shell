/* Minimal urcu stand-in for compiling pinned NeuVector dpi_sig.c. */
#ifndef NEUVECTOR2SHELL_SHIM_URCU_H
#define NEUVECTOR2SHELL_SHIM_URCU_H
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define synchronize_rcu() ((void)0)
#define call_rcu(f, n) ((void)0)
#define rcu_dereference(p) (p)
#endif
