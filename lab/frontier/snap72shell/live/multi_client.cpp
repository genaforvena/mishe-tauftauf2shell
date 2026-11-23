// Two-item probe for the pinned opReadMultiVars() offset advance.
// Item 0's destination is deliberately large so its 65535-byte write is
// in-bounds; item 1's destination is one byte, so any second memcpy driven
// by the wild source pointer is observable. No synthetic consumer: this is
// the real pinned client library over a real loopback S7 exchange.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "s7_micro_client.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: multi_client PORT\n");
        return 64;
    }
    word port = word(std::atoi(argv[1]));
    TSnap7MicroClient client;
    client.SetConnectionParams("127.0.0.1", 0x0100, 0x0100);
    client.SetParam(p_u16_RemotePort, &port);

    int connect_rc = client.Connect();
    std::printf("CLIENT_CONNECT_RC=%d\n", connect_rc);
    std::fflush(stdout);
    if (connect_rc != 0)
        return 2;

    const std::size_t dest0_size = 200000;
    unsigned char *dst0 = new unsigned char[dest0_size];
    unsigned char *dst1 = new unsigned char[1];
    std::memset(dst0, 0x00, dest0_size);
    dst1[0] = 0xCC;

    TS7DataItem items[2];
    std::memset(items, 0, sizeof(items));
    for (int i = 0; i < 2; ++i) {
        items[i].Area = S7AreaDB;
        items[i].WordLen = S7WLByte;
        items[i].DBNumber = 1;
        items[i].Start = i;
        items[i].Amount = 1;
    }
    items[0].pdata = dst0;
    items[1].pdata = dst1;

    std::printf("CLIENT_READ_BEGIN items=2 dest0=%zu dest1=1\n", dest0_size);
    std::fflush(stdout);
    int read_rc = client.ReadMultiVars(items, 2);
    std::printf("CLIENT_READ_RC=%d ITEM0_RESULT=%d ITEM1_RESULT=%d "
                "DST0_0=%02x DST0_17=%02x DST0_4000=%02x DST1_0=%02x\n",
                read_rc, items[0].Result, items[1].Result,
                unsigned(dst0[0]), unsigned(dst0[17]),
                unsigned(dst0[4000]), unsigned(dst1[0]));
    std::fflush(stdout);
    delete[] dst1;
    delete[] dst0;
    return 0;
}
