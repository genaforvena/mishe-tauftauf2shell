/*
 * libyang2shell: real lyd_parse_data_mem(..., LYD_LYB, ...) driver.
 *
 * gen  <outfile>          build a valid non-shrink LYB blob containing one
 *                         string leaf set to "AAAAAAAA", write it to outfile,
 *                         and print the byte layout to stdout.
 * parse <infile> [patch]  load the same module, optionally patch the 4-byte
 *                         little-endian length of "AAAAAAAA" to 0xffffffff,
 *                         then call lyd_parse_data_mem() on the buffer.
 *
 * No sockets. Nothing outside the process is contacted.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "libyang.h"

#define STRVAL "AAAAAAAA"
#define STRLEN (sizeof(STRVAL) - 1)

static const char *YANG_MOD =
    "module t {\n"
    "  namespace \"urn:t\";\n"
    "  prefix t;\n"
    "  leaf s { type string; }\n"
    "}\n";

static struct ly_ctx *
make_ctx(void)
{
    struct ly_ctx *ctx = NULL;
    struct lys_module *mod = NULL;
    LY_ERR rc;
    const char *searchdir = getenv("LY_TEST_SEARCHDIR");
    rc = ly_ctx_new(searchdir, 0, &ctx);
    if (rc || !ctx) {
        fprintf(stderr, "ly_ctx_new failed: %d\n", rc);
        return NULL;
    }
    rc = lys_parse_mem(ctx, YANG_MOD, LYS_IN_YANG, &mod);
    if (rc || !mod) {
        fprintf(stderr, "lys_parse_mem failed: %d\n", rc);
        ly_ctx_destroy(ctx);
        return NULL;
    }
    return ctx;
}

static unsigned char *
slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;

    if (!f) {
        perror("fopen");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = calloc((size_t)n + 4096, 1); /* pad: LYB parse never bounds-checks */
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "slurp failed\n");
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static void
hexdump(const unsigned char *p, size_t n)
{
    size_t i, j;
    for (i = 0; i < n; i += 16) {
        printf("LYB %08zx ", i);
        for (j = 0; j < 16 && i + j < n; j++)
            printf("%02x", p[i + j]);
        printf("\n");
    }
}

static long
find_str(const unsigned char *buf, size_t n)
{
    size_t i;
    for (i = 0; i + STRLEN <= n; i++) {
        if (!memcmp(buf + i, STRVAL, STRLEN) && (i >= 4))
            return (long)i;
    }
    return -1;
}

int
main(int argc, char **argv)
{
    struct ly_ctx *ctx;
    struct lyd_node *data = NULL, *tree = NULL;
    char *lyb = NULL;
    unsigned char *buf;
    size_t n = 0, i;
    long off;
    int patch = 0;
    LY_ERR rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s gen <out> | %s parse <in> [patch]\n", argv[0], argv[0]);
        return 2;
    }

    ctx = make_ctx();
    if (!ctx)
        return 3;

    if (!strcmp(argv[1], "gen")) {
        FILE *f;

        rc = lyd_new_path(NULL, ctx, "/t:s", STRVAL, 0, &data);
        if (rc || !data) {
            fprintf(stderr, "lyd_new_path failed: %d\n", rc);
            return 4;
        }
        f = fopen(argv[2], "wb");
        if (!f) {
            perror("fopen out");
            return 6;
        }
        rc = lyd_print_fd(fileno(f), data, LYD_LYB, 0);
        fclose(f);
        if (rc) {
            fprintf(stderr, "lyd_print_fd failed: %d\n", rc);
            return 5;
        }
        buf = slurp(argv[2], &n);
        if (!buf)
            return 7;
        printf("LYB_LEN=%zu\n", n);
        hexdump(buf, n);
        off = find_str(buf, n);
        printf("STR_OFF=%ld\n", off);
        if (off >= 4) {
            printf("LEN_OFF=%ld\n", off - 4);
            printf("LEN_BYTES=%02x%02x%02x%02x\n", buf[off - 4], buf[off - 3], buf[off - 2], buf[off - 1]);
        }
        free(buf);
        lyd_free_all(data);
        ly_ctx_destroy(ctx);
        return 0;
    }

    if (strcmp(argv[1], "parse")) {
        fprintf(stderr, "unknown mode %s\n", argv[1]);
        return 2;
    }
    {
        const char *how = (argc > 3) ? argv[3] : "none";
        long patch_off = -1;

        buf = slurp(argv[2], &n);
        if (!buf)
            return 7;
        off = find_str(buf, n);
        printf("INPUT_LEN=%zu STR_OFF=%ld\n", n, off);

        if (!strcmp(how, "none")) {
            /* valid-input control */
        } else if (!strcmp(how, "patch")) {
            if (off < 4) {
                fprintf(stderr, "value string not found\n");
                return 8;
            }
            patch_off = off - 4;
        } else if (!strcmp(how, "patchmod")) {
            /* module name: 4-byte LE length 1 followed by 't' */
            const unsigned char pat[] = {0x01, 0x00, 0x00, 0x00, 't'};
            for (i = 0; i + sizeof pat <= n; i++) {
                if (!memcmp(buf + i, pat, sizeof pat)) {
                    patch_off = (long)i;
                    break;
                }
            }
        } else if (!strncmp(how, "off:", 4)) {
            patch_off = strtol(how + 4, NULL, 0);
        } else {
            fprintf(stderr, "unknown patch mode %s\n", how);
            return 2;
        }
        if (patch_off >= 0 && patch_off + 4 <= (long)n) {
            printf("PATCH_OFF=%ld OLD=%02x%02x%02x%02x\n", patch_off, buf[patch_off], buf[patch_off + 1],
                    buf[patch_off + 2], buf[patch_off + 3]);
            for (i = 0; i < 4; i++)
                buf[patch_off + i] = 0xff;
            printf("PATCHED=ffffffff\n");
        }

        rc = lyd_parse_data_mem(ctx, (const char *)buf, LYD_LYB, LYD_PARSE_ONLY, 0, &tree);
        printf("RC=%d\n", rc);
        if (!rc)
            lyd_free_all(tree);
        free(buf);
        ly_ctx_destroy(ctx);
        return 0;
    }
}
