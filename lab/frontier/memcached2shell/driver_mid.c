/* Harness-owned stubs that need the pinned crawler_client_t definition. */
static void lru_crawler_close_client(crawler_client_t *c)
{
    g_closes++;
    c->c = NULL;
}

static unsigned int current_time;
static unsigned int process_started;

static int item_is_flushed(item *it)
{
    (void)it;
    return 0;
}

static void refcount_decr(item *it)
{
    (void)it;
}

/* Stub: real uriencode_p percent-encodes; this copies the stored key bytes
 * verbatim, which is a strict subset of attacker-controlled output. */
static char *uriencode_p(const char *src, char *dst, int len)
{
    memcpy(dst, src, (size_t)len);
    return dst + len;
}

static char *itoa_64(long v, char *p) { p += sprintf(p, "%ld", v); return p; }
static char *itoa_u64(unsigned long long v, char *p) { p += sprintf(p, "%llu", v); return p; }
static char *itoa_u32(unsigned int v, char *p) { p += sprintf(p, "%u", v); return p; }
