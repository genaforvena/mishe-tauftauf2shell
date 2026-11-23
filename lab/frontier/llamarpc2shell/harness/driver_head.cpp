// llamarpc2shell — verbatim-slice driver for ggml-rpc rdma_recv (CVE-2026-118375)
// The rdma_recv body is extracted byte-for-byte from a pinned transport.cpp at
// run time and concatenated between this head and driver_main.cpp.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static constexpr size_t RDMA_CHUNK = 256 * 1024;

// Minimal stand-ins for the verbs types used by the extracted function body.
struct ibv_wc { uint32_t wr_id; uint32_t byte_len; int status; };

struct FakeConn {
    uint8_t * rx_buf = nullptr;
    int posted = 0;
    void * rcq = nullptr;
    uint8_t * rx_slot(int i) { (void)i; return rx_buf; }
    bool post_rx(int) { ++posted; return true; }
};
using rdma_conn = FakeConn;

static uint8_t g_rxbuf[RDMA_CHUNK];
struct FakeRdma { FakeConn * p; FakeConn * get() { return p; } };

static FakeConn     g_conn;
static struct ibv_wc g_wc;
static int          g_poll_calls = 0;

// Deliver exactly one attacker-crafted completion; the peer then drops.
static bool rdma_poll(void *, struct ibv_wc * wc) {
    if (g_poll_calls++ > 0) return false;
    *wc = g_wc;
    return true;
}

#define LOG_ERROR(...) do { std::printf(__VA_ARGS__); } while (0)

struct socket_t {
    struct impl {
        FakeRdma rdma;
        bool rdma_recv(void * data, size_t size);
    };
};

static socket_t::impl g_impl;
