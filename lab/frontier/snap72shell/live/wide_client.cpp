// Measure how many bytes of the peer-controlled 65535-byte copy are actually
// chosen by the responder. Plain build only: the destination is deliberately
// large, so the sink does not fault and the copied bytes can be inspected.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "s7_micro_client.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: wide_client PORT\n");
        return 64;
    }
    word port = word(std::atoi(argv[1]));
    TSnap7MicroClient client;
    client.SetConnectionParams("127.0.0.1", 0x0100, 0x0100);
    client.SetParam(p_u16_RemotePort, &port);

    std::printf("CLIENT_CONNECT_BEGIN addr=127.0.0.1 port=%u\n", unsigned(port));
    std::fflush(stdout);
    int connect_rc = client.Connect();
    std::printf("CLIENT_CONNECT_RC=%d\n", connect_rc);
    std::fflush(stdout);
    if (connect_rc != 0)
        return 2;

    const std::size_t dest_size = 200000;
    const unsigned char pat[4] = {0x11, 0x22, 0x33, 0x44};
    unsigned char *dst = new unsigned char[dest_size];
    std::memset(dst, 0x00, dest_size);
    TS7DataItem item;
    std::memset(&item, 0, sizeof(item));
    item.Area = S7AreaDB;
    item.WordLen = S7WLByte;
    item.DBNumber = 1;
    item.Start = 0;
    item.Amount = 1;
    item.pdata = dst;

    std::printf("CLIENT_READ_BEGIN amount=%d dest_size=%zu\n", item.Amount, dest_size);
    std::fflush(stdout);
    int read_rc = client.ReadMultiVars(&item, 1);

    // Slice is 65535, so exactly 65535 destination bytes were written.
    std::size_t matches = 0;
    for (std::size_t i = 0; i < 65535; ++i) {
        if (dst[i] == pat[i % 4])
            ++matches;
    }
    std::size_t first_bad = 65535;
    for (std::size_t i = 0; i < 65535; ++i) {
        if (dst[i] != pat[i % 4]) {
            first_bad = i;
            break;
        }
    }
    std::printf("CLIENT_READ_RC=%d ITEM_RESULT=%d MATCHES=%zu FIRST_BAD_OFFSET=%zu "
                "DST0=%02x DST1=%02x DST2=%02x DST3=%02x DST4=%02x DST17=%02x "
                "DST3999=%02x DST4000=%02x DST4095=%02x DST4096=%02x DST65534=%02x\n",
                read_rc, item.Result, matches, first_bad,
                unsigned(dst[0]), unsigned(dst[1]), unsigned(dst[2]),
                unsigned(dst[3]), unsigned(dst[4]), unsigned(dst[17]),
                unsigned(dst[3999]), unsigned(dst[4000]), unsigned(dst[4095]),
                unsigned(dst[4096]), unsigned(dst[65534]));
    std::fflush(stdout);
    delete[] dst;
    return 0;
}
