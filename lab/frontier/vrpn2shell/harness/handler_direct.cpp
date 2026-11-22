// Direct-call harness for the pinned v07.36 handler. Nothing is reimplemented:
// the function under test is linked from the real vrpnserver library.
#include "vrpn_Connection.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    vrpn_int32 index = static_cast<vrpn_int32>(strtol(argv[1], nullptr, 0));
    char payload[8];
    vrpn_uint32 net = htonl(static_cast<vrpn_uint32>(index));
    memcpy(payload, &net, sizeof(net));
    memcpy(payload + 4, "AAAA", 4);

    vrpn_HANDLERPARAM p;
    memset(&p, 0, sizeof(p));
    p.type = vrpn_CONNECTION_SENDER_DESCRIPTION;
    p.sender = 0;
    p.payload_len = sizeof(payload);
    p.buffer = payload;

    fprintf(stderr, "calling handle_sender_message index=%d\n", index);
    int rv = vrpn_Endpoint::handle_sender_message(nullptr, p);
    fprintf(stderr, "returned rv=%d\n", rv);
    return 0;
}
