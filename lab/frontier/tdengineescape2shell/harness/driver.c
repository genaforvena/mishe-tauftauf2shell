#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Verbatim pinned trimString(): parent d91020e5 (vuln) or fix 64ff9a8f (fixed). */
#include TRIM_SOURCE

/* Caller shape follows pinned parInsertSql.c:459-464: a stack destination of
   exactly TSDB_MAX_BYTES_PER_ROW bytes, passed as dlen verbatim. */
static int caller(const char *src, int32_t len, unsigned char marker) {
    char buf[32];
    volatile unsigned char guard = marker;
    memset(buf, 'A', sizeof(buf));
    int32_t n = trimString(src, len, buf, (int32_t)sizeof(buf));
    printf("TRIM_N=%d LAST=0x%02x GUARD=0x%02x\n", n, (unsigned char)buf[31], guard);
    return guard == marker ? 0 : 1;
}

/* Same exact-size destination with a real adjacent stack object after it, so
   the single OOB byte can be observed without ASan redzone interference. */
struct victim_frame {
    char buf[32];
    volatile unsigned char victim;
};

static int caller_victim(const char *src, int32_t len, unsigned char marker) {
    struct victim_frame f;
    memset(f.buf, 'A', sizeof(f.buf));
    f.victim = marker;
    int32_t n = trimString(src, len, f.buf, (int32_t)sizeof(f.buf));
    printf("VICTIM_N=%d VICTIM=0x%02x\n", n, f.victim);
    return f.victim == marker ? 1 : 0;
}

int main(int argc, char **argv) {
    char src[64];
    int32_t len;
    int victim = argc > 1 && strcmp(argv[1], "victim") == 0;
    char esc = victim ? (argc > 2 ? argv[2][0] : '%') : (argc > 1 ? argv[1][0] : '%');
    unsigned char marker = argc > 3 ? (unsigned char)argv[3][0] : 0x5a;
    if (argc > 1 && strcmp(argv[1], "safe") == 0) {
        strcpy(src, "'AB'");
        len = 4;
    } else {
        src[0] = '\'';
        for (int i = 1; i <= 31; ++i) src[i] = 'A';
        src[32] = '\\';
        src[33] = esc;
        src[34] = '\'';
        len = 35;
    }
    return victim ? caller_victim(src, len, marker) : caller(src, len, marker);
}
