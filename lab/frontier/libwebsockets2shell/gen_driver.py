#!/usr/bin/env python3
"""Generate drivers whose fault statements are verbatim pinned hpack.c lines.

Every statement under a `#line` marker is copied byte-for-byte from the pinned
upstream source at its exact line number. The surrounding harness supplies only
stand-ins (structs, allocation, caller shape) and never edits the copied lines.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
PINS = {
    "hpack.v4.3.10.c": ("5ce2d424f330fac11735a8c1f9dd50a430c02fb653012f50dd0ae3be69de5439",
                        SRC / "hpack.v4.3.10.c"),
    "hpack.v5.0.0.c": ("9232db68b9b9982a0df02b4e6105993de2d6d93d8a4bb26a070b3c756e8ea584",
                       SRC / "hpack.v5.0.0.c"),
    "fix19773.patch": ("c8dab8820a000a92122dbf6e8e511973789816a6f9d4207569cd4c890ffd2ba9",
                       SRC / "fix19773.patch"),
    "cve19773.json": ("ae98ef58f5912df664ac1fa323ed794a4193f310a33863076cf0114fd014bcc5",
                      SRC / "cve19773.json"),
    "zdi-26-590.html": ("86eed822ed539fd37519909e6045a0dbbfaea8a1b1250e770f74600fecdc56bc",
                        SRC / "zdi-26-590.html"),
}
for name, (want, path) in PINS.items():
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != want:
        sys.exit(f"PIN DRIFT {name}: {got} != {want}")

LINES = {name: path.read_text().splitlines()
         for name, (_, path) in PINS.items() if name.endswith(".c")}


def copied(pin, start, end, tag):
    """Exact pinned source lines with a #line marker at their true location."""
    out = [f'#line {start} "{tag}"']
    out.extend(LINES[pin][start - 1:end])
    out.append('#line 1000 "harness.c"')
    return "\n".join(out) + "\n"


HEADER = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char u_char;
struct lws_frags { int len; };
struct allocated_headers {
    char *data;
    int pos;
    int nfrag;
    struct lws_frags frags[8];
};
struct lws_context { unsigned int max_http_header_data; };
struct lws {
    struct { struct allocated_headers *ah; } http;
    struct { struct lws_context *context; } a;
};

'''


FOOTER = r'''
static char region[4096];

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "collab";
    int limit = argc > 2 ? atoi(argv[2]) : 16;
    unsigned char c = argc > 3 ? (unsigned char) strtoul(argv[3], NULL, 0) : 0x41;
    struct allocated_headers ah;
    struct lws_context ctx;
    struct lws wsi;
    size_t page = (size_t) sysconf(_SC_PAGESIZE);
    char *data = NULL;
    void *map = MAP_FAILED;
    int r1, r2;

    memset(&ah, 0, sizeof(ah));
    memset(&ctx, 0, sizeof(ctx));
    memset(&wsi, 0, sizeof(wsi));
    ctx.max_http_header_data = (unsigned int) limit;
    wsi.http.ah = &ah;
    wsi.a.context = &ctx;

    if (!strcmp(mode, "exact") || !strcmp(mode, "collab") ||
        !strcmp(mode, "chain") || !strcmp(mode, "inbounds") || !strcmp(mode, "exactok")) {
        data = malloc((size_t) limit);
        if (!data) return 2;
        memset(data, 0xa5, (size_t) limit);
    } else if (!strcmp(mode, "guard")) {
        map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED) return 2;
        if (mprotect((char *) map + page, page, PROT_NONE)) return 2;
        data = (char *) map + page - limit;
        memset(data, 0xa5, (size_t) limit);
    } else {
        return 2;
    }
    ah.data = data;
    ah.pos = limit;
    ah.nfrag = 0;

    if (!strcmp(mode, "exactok")) {
        ah.pos = limit - 1;
        r1 = lws_frag_append(&wsi, c);
        printf("mode=%s limit=%d c=%02x rv=%d pos=%d last=%02x\n",
               mode, limit, c, r1, ah.pos, (unsigned char) data[limit - 1]);
    } else
    if (!strcmp(mode, "inbounds")) {
        ah.pos = limit - 1;
        r1 = lws_frag_append(&wsi, c);
        printf("mode=%s limit=%d c=%02x rv=%d pos=%d last=%02x oob0=%02x\n",
               mode, limit, c, r1, ah.pos, (unsigned char) data[limit - 1],
               (unsigned char) data[limit]);
    } else if (!strcmp(mode, "chain")) {
        ah.pos = limit - 1;
        r1 = lws_frag_append(&wsi, 0x41);
        r2 = lws_frag_append(&wsi, c);
        printf("mode=%s limit=%d c=%02x r1=%d r2=%d pos=%d last=%02x oob0=%02x oob1=%02x\n",
               mode, limit, c, r1, r2, ah.pos,
               (unsigned char) data[limit - 1], (unsigned char) data[limit],
               (unsigned char) data[limit + 1]);
    } else {
        r1 = lws_frag_append(&wsi, c);
        if (!strcmp(mode, "exact") || !strcmp(mode, "guard")) {
            printf("mode=%s limit=%d c=%02x rv=%d pos=%d\n",
                   mode, limit, c, r1, ah.pos);
        } else {
            printf("mode=%s limit=%d c=%02x rv=%d pos=%d oob0=%02x oob1=%02x\n",
                   mode, limit, c, r1, ah.pos,
                   (unsigned char) data[limit], (unsigned char) data[limit + 1]);
        }
    }
    if (map != MAP_FAILED) munmap(map, 2 * page); else if (data) free(data);
    return 0;
}
'''


def build(fixed):
    pin = "hpack.v5.0.0.c" if fixed else "hpack.v4.3.10.c"
    tag = "hpack_v5.0.0" if fixed else "hpack_v4.3.10"
    fn = copied(pin, 273, 284 if fixed else 281, tag)
    return HEADER + fn + FOOTER


drivers = {}
for variant in ("vuln", "fixed"):
    drivers[f"driver_{variant}.c"] = build(variant == "fixed")

for name, text in drivers.items():
    (ROOT / name).write_text(text)
    print(name, len(text), hashlib.sha256(text.encode()).hexdigest())
