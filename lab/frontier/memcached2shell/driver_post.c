/* Harness-owned wrappers and driver loop. */
#ifdef MC_NO_REAL_MALLOC
static void *__real_malloc(size_t n) { return malloc(n); }
#else
extern void *__real_malloc(size_t n);
#endif

static void fault_handler(int sig)
{
    (void)sig;
    const char *msg = (g_backend && strcmp(g_backend, "guard") == 0)
                          ? "guard_fault=1\n" : "plain_fault=1\n";
    (void)!write(STDOUT_FILENO, msg, strlen(msg));
    _exit(77);
}

void *__wrap_malloc(size_t n)
{
    if (!g_wrap_ready || !g_backend || strcmp(g_backend, "plain") == 0)
        return __real_malloc(n);
    if (strcmp(g_backend, "guard") == 0) {
        size_t ps = (size_t)sysconf(_SC_PAGESIZE);
        size_t pages = (n + ps - 1) / ps + 1;
        void *base = mmap(NULL, pages * ps, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return NULL;
        if (mprotect((char *)base + (pages - 1) * ps, ps, PROT_NONE) != 0) return NULL;
        g_buf_base = base;
        g_guard_page = (size_t)base + (pages - 1) * ps;
        return (char *)base + (pages - 1) * ps - n;
    }
    if (strcmp(g_backend, "bounded") == 0) {
        g_nominal = n;
        g_buf_base = __real_malloc(1u << 20);
        if (!g_buf_base) return NULL;
        memset(g_buf_base, 0, 1u << 20);
        return g_buf_base;
    }
    return __real_malloc(n);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)timeout;
    g_poll_calls++;
    if (nfds == 0) return -1;
    if (g_poll_mode == 0 || g_poll_calls > 5000) return 0; /* stalled client */
    fds[0].revents = POLLOUT;
    return 1;
}

static int stub_read(void *c, char *buf, int len)
{
    (void)c; (void)buf; (void)len;
    errno = EAGAIN;
    return -1;
}

static int stub_write(void *c, char *buf, int len)
{
    (void)c;
    g_write_calls++;
    if (g_poll_mode == 2) { errno = EAGAIN; return -1; }
    if (len < 0) return -1;
    if ((size_t)len > g_sink_cap - (size_t)g_bytes_written) len = (int)(g_sink_cap - (size_t)g_bytes_written);
    memcpy(g_sink + g_bytes_written, buf, (size_t)len);
    g_bytes_written += len;
    return len;
}

int main(int argc, char **argv)
{
    const char *variant = argc > 1 ? argv[1] : "unknown";
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode_s = getenv("MC_POLL_MODE");
    const char *items_s = getenv("MC_ITEMS");
    const char *fill_s = getenv("MC_KEY_FILL");
    g_backend = getenv("MC_BACKEND");
    g_poll_mode = mode_s ? atoi(mode_s) : 0;
    int items = items_s ? atoi(items_s) : 2000;
    int fill = fill_s ? atoi(fill_s) : 0x5a;
    if ((strcmp(g_backend, "guard") == 0 || strcmp(g_backend, "plain") == 0) &&
        !getenv("MC_NO_SIGSEGV_HANDLER"))
        signal(SIGSEGV, fault_handler);

    g_sink_cap = 4u << 20;
    g_sink = __real_malloc(g_sink_cap);
    if (!g_sink) return 2;

    size_t keylen = 64;
    item *it = __real_malloc(sizeof(item) + keylen);
    memset(it, 0, sizeof(item) + keylen);
    it->nkey = (unsigned int)keylen;
    it->it_flags = 0;
    it->exptime = 0;
    it->time = 0;
    it->ntotal = 64;
    it->clsid = 1;
    memset(ITEM_key(it), fill, keylen);

    crawler_module_t cm;
    memset(&cm, 0, sizeof(cm));
    conn cn;
    cn.read = stub_read;
    cn.write = stub_write;
    g_wrap_ready = 1;
    if (lru_crawler_set_client(&cm, &cn, 123) != 0) return 3;
    int written_items = 0;
    int write_ret = 0;
    for (int n = 0; n < items; n++) {
        /* Mirrors the per-LRU caller at pinned crawler.c:632-640 and :679. */
        if (cm.c.buflen - cm.c.bufused < LRU_CRAWLER_MINBUFSPACE) {
            write_ret = lru_crawler_write(&cm.c);
            if (write_ret != 0) break;
        }
        crawler_metadump_eval(&cm, it, 0, 0);
        written_items++;
    }

    long bounded_chosen = 0;
    long bounded_first = -1;
    if (strcmp(g_backend, "bounded") == 0 && g_buf_base && g_nominal) {
        size_t limit = g_nominal + 65536;
        for (size_t off = g_nominal; off < limit; off++) {
            if (((unsigned char *)g_buf_base)[off] == (unsigned char)fill) {
                bounded_chosen++;
                if (bounded_first < 0) bounded_first = (long)(off - g_nominal);
            }
        }
    }

    printf("variant=%s\n", variant);
    printf("items_requested=%d items_appended=%d\n", items, written_items);
    printf("buflen=%d bufused=%d\n", cm.c.buflen, cm.c.bufused);
    printf("poll_calls=%d write_calls=%d bytes_written=%d closes=%d write_ret=%d\n",
           g_poll_calls, g_write_calls, g_bytes_written, g_closes, write_ret);
    if (strcmp(g_backend, "bounded") == 0) {
        static const size_t probes[] = {0, 4, 16, 64, 256, 4096, 65536};
        long matched = 0;
        for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            size_t off = g_nominal + probes[i];
            unsigned char v = ((unsigned char *)g_buf_base)[off];
            printf("bounded_at_%zu=%02x\n", probes[i], v);
            if (v == (unsigned char)fill) matched++;
        }
        printf("bounded_probe_match=%ld/%zu\n", matched, sizeof(probes) / sizeof(probes[0]));
        printf("bounded_chosen=%ld bounded_first_offset=%ld bounded_fill=%d\n",
               bounded_chosen, bounded_first, fill);
    }
    if (g_guard_page) printf("guard_page_offset=%ld\n", (long)(g_guard_page - (size_t)g_buf_base));
    return 0;
}
