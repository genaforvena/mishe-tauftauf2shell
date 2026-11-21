/* Harness-owned prelude. Verbatim pinned memcached blocks follow this file. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Synthetic stand-ins for daemon types used by the pinned blocks. */
typedef struct item {
    int exptime;
    unsigned int nkey;
    unsigned int it_flags;
    unsigned int time;
    unsigned int ntotal;
    unsigned int flags;
    uint64_t cas;
    unsigned int clsid;
} item;
typedef unsigned long long client_flags_t;
#define ITEM_FETCHED (1u << 8) /* synthetic flag bit; selects a literal branch */
#define ITEM_key(it) ((char *)((it) + 1))
#define ITEM_data(it) ((char *)((it) + 1))
#define ITEM_get_cas(it) ((it)->cas)
#define ITEM_clsid(it) ((it)->clsid)
#define ITEM_ntotal(it) ((it)->ntotal)
#define FLAGS_CONV(it, flags) do { (flags) = (it)->flags; } while (0)

typedef struct conn {
    int (*read)(void *c, char *buf, int len);
    int (*write)(void *c, char *buf, int len);
} conn;

static int g_poll_mode;         /* 0 timeout, 1 POLLOUT, 2 POLLOUT+EAGAIN write */
static int g_poll_calls;
static int g_write_calls;
static int g_bytes_written;
static int g_closes;
static int g_wrap_ready;
static const char *g_backend;   /* plain, guard, bounded */
static char *g_sink;
static size_t g_sink_cap;
static char *g_buf_base;
static size_t g_nominal;
static size_t g_guard_page;
