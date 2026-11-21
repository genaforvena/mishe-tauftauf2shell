// Harness-owned driver: builds plaintext RTCP datagrams and calls the pinned decoders.
#include <csignal>
#include <unistd.h>

static void segv_handler(int)
{
    const char msg[] = "guard_fault=1\n";
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(77);
}

static void make_packet(unsigned char *pkt, uint16_t length, unsigned char fmt,
                        unsigned char type, int nb_payload, unsigned char fill)
{
    pkt[0] = (unsigned char)(0x80 | ((fmt & 0x1f) << 2) | 0); // V=2, P=0
    pkt[1] = type;
    pkt[2] = (unsigned char)(length >> 8);
    pkt[3] = (unsigned char)(length & 0xff);
    pkt[4] = 0; pkt[5] = 0; pkt[6] = 0; pkt[7] = 1; // sender SSRC
    for (int i = 0; i < nb_payload; i++) pkt[8 + i] = fill;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    const char *mode = argc > 1 ? argv[1] : "overflow";
    unsigned char fill = argc > 2 ? (unsigned char)strtol(argv[2], NULL, 16) : 0x5a;
    bool twcc = strstr(mode, "twcc") != NULL;
    bool guard = strcmp(mode, "guard") == 0;
    bool collab = strstr(mode, "collab") != NULL;
    uint16_t length = strstr(mode, "assert") ? 0 : (strstr(mode, "benign") ? 2 : 400);
    int nb_payload = length == 0 ? 0 : ((length + 1) * 4 - 8);
    int nb_bytes = 8 + nb_payload;

    // The datagram is harness-owned; upstream reads UDP into a 65535-byte buffer.
    unsigned char *wire = (unsigned char *)calloc(nb_bytes + 16, 1);
    make_packet(wire, length, twcc ? 15 : 0, twcc ? 205 : 203, nb_payload, fill);

    char *object_mem = NULL;
    SrsRtcpCommon *obj = NULL;
    size_t off = SrsRtcpCommon::payload_offset() + kRtcpPacketSize;
    if (guard) {
        signal(SIGSEGV, segv_handler);
        long ps = sysconf(_SC_PAGESIZE);
        char *region = (char *)mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED) { printf("mmap_failed=1\n"); return 2; }
        if (mprotect(region + ps, (size_t)ps, PROT_NONE) != 0) { printf("mprotect_failed=1\n"); return 2; }
        object_mem = region + ps - sizeof(SrsRtcpCommon);
        obj = twcc ? new (object_mem) SrsRtcpTWCC() : new (object_mem) SrsRtcpCommon();
    } else if (collab) {
        object_mem = (char *)calloc(65536, 1);
        obj = twcc ? new (object_mem) SrsRtcpTWCC() : new (object_mem) SrsRtcpCommon();
    } else {
        obj = twcc ? (SrsRtcpCommon *)new SrsRtcpTWCC() : new SrsRtcpCommon();
    }

    SrsBuffer buffer((char *)wire, nb_bytes);
    printf("mode=%s\n", mode);
    printf("length=%u\n", (unsigned)length);
    printf("declared_payload=%d\n", (length + 1) * 4 - 8);
    printf("wire_bytes=%d\n", nb_bytes);
    printf("fill=%02x\n", fill);

    // In twcc mode obj is a real SrsRtcpTWCC, so virtual dispatch reaches the
    // pinned SrsRtcpTWCC::decode rather than SrsRtcpCommon::decode.
    srs_error_t err = obj->decode(&buffer);

    if (err) printf("err=%s\n", err); else printf("err=none\n");
    if (collab) {
        int chosen = 0, first = -1, last = -1;
        for (size_t i = off; i < off + (size_t)nb_payload; i++) {
            if ((unsigned char)object_mem[i] == fill) {
                chosen++;
                if (first < 0) first = (int)(i - off);
                last = (int)(i - off);
            }
        }
        printf("payload_end_offset=%zu\n", off);
        printf("chosen=%d\n", chosen);
        printf("first=%d\n", first);
        printf("last=%d\n", last);
    }
    if (guard) printf("guard_fault=0\n");
    return 0;
}
