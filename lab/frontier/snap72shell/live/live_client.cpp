// Real pinned TSnap7MicroClient driven over a loopback S7 wire.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "s7_micro_client.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: live_client PORT\n");
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
    std::size_t dest_size = 1;
    if (const char *env_size = std::getenv("LIVE_DEST_SIZE"))
        dest_size = std::strtoul(env_size, 0, 10);
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
    std::printf("CLIENT_READ_RC=%d ITEM_RESULT=%d DST0=%02x DEST17=%02x DEST64=%02x\n",
                read_rc, item.Result, unsigned(dst[0]),
                dest_size > 17 ? unsigned(dst[17]) : 0u,
                dest_size > 64 ? unsigned(dst[64]) : 0u);
    std::fflush(stdout);
    delete[] dst;
    return 0;
}
