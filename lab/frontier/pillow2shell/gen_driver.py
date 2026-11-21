#!/usr/bin/env python3
"""Generate Pillow FPX/JPEG drivers whose fault lines are verbatim pinned bytes.

Statements under a `#line` marker are copied byte-for-byte from pinned upstream
source. The harness supplies stand-ins: an in-memory 4-component CMYK JPEG
decoded by real libjpeg into a correctly sized staging row, then a local row
copy hands that row to the pinned scanline call. System libjpeg is not
ASan-instrumented, so ASan observes the shim's memcpy, not libjpeg's stores.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
PINS = {
    "JpegDecode.v12.2.0.c": "895fc76b3f04e93fbc8a31f952e168432ecd140ae38fc1bba3c70d5803ed4682",
    "JpegDecode.v13.0.0.c": "9c575a6e9e1247f06635047862cca39873e9d888a51b5d592ee0f57965f4c5df",
    "decode.v12.2.0.c": "d9d96888c2ca64788acc3f8376567290aa6c8e5beb76779da0498447fd3f08ce",
    "FpxImagePlugin.v12.2.0.py": "4fa3a75a4bbca8bb1b6240fe6e2eb76706f894a2f96f2d67eeb5653d3e5eb46a",
    "cve112398.json": "3632abba025681d0fea450b37bad7e10516ae46029ba0f2628ae4e77dfac98a8",
    "ghsa-5x8w-8jj5-q52h.html": "3dac6010372a3cca8d67d332d2ea047b7b4009ce4bd30a9a7002d3acc78f8a81",
    "fix112398.patch": "dc0e90b2394c856b68cc694ebe279bfed78550216af2bd73de1a9e2af325fa38",
}
for name, want in PINS.items():
    got = hashlib.sha256((SRC / name).read_bytes()).hexdigest()
    if got != want:
        sys.exit(f"PIN DRIFT {name}: {got} != {want}")

LINES = {name: (SRC / name).read_text().splitlines() for name in PINS if name.endswith(".c")}


def copied(pin, start, end, label):
    out = [f'#line {start} "{label}"']
    out.extend(LINES[pin][start - 1:end])
    return "\n".join(out) + "\n"


HEADER = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <jpeglib.h>

typedef unsigned char UINT8;
#define IMAGING_CODEC_BROKEN (-1)

struct codec_state {
    int xsize, ysize, y, bits, state, errcode;
    size_t bytes;
    UINT8 *buffer;
};
struct decode_context { struct jpeg_decompress_struct cinfo; };
struct pillow_err { struct jpeg_error_mgr pub; jmp_buf jb; };
static jmp_buf pillow_jb;
static UINT8 *staged_row;
static size_t staged_len;
static struct codec_state *Gstate;
static UINT8 Gsnap[128];

static void pillow_error_exit(j_common_ptr c) {
    (void)c;
    longjmp(pillow_jb, 1);
}

/* Stand-in for the destination handoff: this row was produced by the real
   jpeg_read_scanlines at its correct size; only the victim destination is
   stand-in memory. The memcpy is the ASan-visible WRITE. */
static JDIMENSION pillow_row_copy(j_decompress_ptr cinfo, JSAMPARRAY scanlines,
                                  JDIMENSION num_rows) {
    (void)num_rows;
    size_t len = (size_t)cinfo->output_components * cinfo->output_width;
    memcpy(*scanlines, staged_row, len);
    return 1;
}

static unsigned char *make_cmyk_jpeg(int width, int height, int value,
                                     unsigned long *out_len) {
    struct jpeg_compress_struct c;
    struct jpeg_error_mgr e;
    unsigned char *jpg = NULL;
    unsigned long n = 0;
    c.err = jpeg_std_error(&e);
    jpeg_create_compress(&c);
    jpeg_mem_dest(&c, &jpg, &n);
    c.image_width = width;
    c.image_height = height;
    c.input_components = 4;
    c.in_color_space = JCS_CMYK;
    jpeg_set_defaults(&c);
    jpeg_set_quality(&c, 100, TRUE);
    for (int i = 0; i < 4; i++) {
        c.comp_info[i].h_samp_factor = 1;
        c.comp_info[i].v_samp_factor = 1;
    }
    jpeg_start_compress(&c, TRUE);
    UINT8 *row = malloc((size_t)width * 4);
    memset(row, value, (size_t)width * 4);
    JSAMPROW rp[1] = { row };
    for (int y = 0; y < height; y++) jpeg_write_scanlines(&c, rp, 1);
    jpeg_finish_compress(&c);
    jpeg_destroy_compress(&c);
    free(row);
    *out_len = n;
    return jpg;
}

static int decode(const char *mode, int width, int tile, int value) {
    unsigned long jlen = 0;
    unsigned char *jpg = make_cmyk_jpeg(width, 2, value, &jlen);
    static struct codec_state cs;
    memset(&cs, 0, sizeof(cs));
    struct codec_state *state = &cs;
    Gstate = state;
    state->xsize = tile;
    state->ysize = 1;
    state->bits = 16;                 /* FPX MODES "LA" */
    state->state = 1;
    struct decode_context dctx;
    memset(&dctx, 0, sizeof(dctx));
    struct decode_context *context = &dctx;
    struct jpeg_decompress_struct *cinfo = &context->cinfo;
    struct pillow_err jerr;
    cinfo->err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = pillow_error_exit;
    if (setjmp(pillow_jb)) return -3;
    jpeg_create_decompress(cinfo);
    jpeg_mem_src(cinfo, jpg, jlen);
    if (jpeg_read_header(cinfo, TRUE) != JPEG_HEADER_OK) return -2;
'''

FOOTER = r'''
    if (!jpeg_start_decompress(cinfo)) return -2;

FIXED_GUARD
    staged_len = (size_t)cinfo->output_components * cinfo->output_width;
    staged_row = malloc(staged_len);
    JSAMPROW sp[1] = { staged_row };
    if (jpeg_read_scanlines(cinfo, sp, 1) != 1) return -2;

    if (strcmp(mode, "guard") == 0) {
        long ps = sysconf(_SC_PAGESIZE);
        char *pg = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pg == MAP_FAILED) return -2;
        if (mprotect(pg + ps, (size_t)ps, PROT_NONE) != 0) return -2;
        state->buffer = (UINT8 *)(pg + ps - state->bytes);
    }

#define jpeg_read_scanlines pillow_row_copy
    int ok = 0;
SCANLINE
#undef jpeg_read_scanlines
    if (ok == 1 && strcmp(mode, "read") == 0) {
        size_t n = staged_len - state->bytes;
        if (n > sizeof(Gsnap)) n = sizeof(Gsnap);
        memcpy(Gsnap, state->buffer + state->bytes, n);
    }
    return ok;
}

static void hexbyte(const char *tag, UINT8 v) { printf(" %s=%02x", tag, v); }

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "raw";
    int width = argc > 2 ? atoi(argv[2]) : 64;
    int tile = argc > 3 ? atoi(argv[3]) : 32;
    int value = argc > 4 ? (int)strtol(argv[4], NULL, 0) : 0x5a;
    int rv = decode(mode, width, tile, value);
    size_t limit = Gstate->bytes;
    if (strcmp(mode, "exact") == 0 || strcmp(mode, "guard") == 0) {
        printf("rv=%d limit=%zu staged=%zu\n", rv, limit, staged_len);
        return 0;
    }
    if (strcmp(mode, "read") == 0) {
        printf("rv=%d limit=%zu staged=%zu", rv, limit, staged_len);
        for (int i = 0; i < 4; i++) {
            char tag[8];
            snprintf(tag, sizeof(tag), "oob%d", i * 16);
            if (rv == 1) hexbyte(tag, Gsnap[(size_t)i * 16]);
            else printf(" %s=--", tag);
        }
        puts("");
        return rv < 0 ? 1 : 0;
    }
    if (strcmp(mode, "inbounds") == 0) {
        printf("rv=%d limit=%zu staged=%zu", rv, limit, staged_len);
        if (rv == 1) hexbyte("last", Gstate->buffer[limit - 1]);
        puts("");
        return rv < 0 ? 1 : 0;
    }
    printf("rv=%d limit=%zu staged=%zu", rv, limit, staged_len);
    if (rv == 1) hexbyte("row0", Gstate->buffer[0]);
    if (rv == 1) hexbyte("stag0", staged_row[0]);
    puts("");
    return rv < 0 ? 1 : 0;
}
'''


def build(fixed):
    pin = "JpegDecode.v13.0.0.c" if fixed else "JpegDecode.v12.2.0.c"
    label = "JpegDecode_v13.0.0.c" if fixed else "JpegDecode_v12.2.0.c"
    sizing = copied("decode.v12.2.0.c", 223, 223, "decode_v12.2.0.c")
    sizing += copied("decode.v12.2.0.c", 226, 226, "decode_v12.2.0.c")
    spaces = copied(pin, 220, 221, label)
    guard = copied(pin, 247, 253, label) if fixed else ""
    scanline = copied(pin, 263 if fixed else 252, 263 if fixed else 252, label)
    return (HEADER + sizing + spaces + FOOTER
            .replace("FIXED_GUARD", guard)
            .replace("SCANLINE", scanline))


for variant, fixed in (("vuln", False), ("fixed", True)):
    text = build(fixed)
    name = f"driver_{variant}.c"
    (ROOT / name).write_text(text)
    print(name, len(text), hashlib.sha256(text.encode()).hexdigest())
