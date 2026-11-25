/* W205 fixed control: same live-allocation recorder, pinned dev-branch
 * stb_vorbis.c. No signature should exist; the recorder proves the check
 * is not an artifact of the file or the build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LIVE 4096
struct alloc {
    void *p;
    size_t sz;
    unsigned long seq;
    int live;
};
static struct alloc live[MAX_LIVE];
static int live_n = 0;
static unsigned long alloc_seq = 0;

static void *guard_malloc(size_t sz)
{
    void *p = malloc(sz);
    if (p && live_n < MAX_LIVE) {
        live[live_n].p = p;
        live[live_n].sz = sz;
        live[live_n].seq = ++alloc_seq;
        live[live_n].live = 1;
        ++live_n;
    }
    return p;
}

static void guard_free(void *p)
{
    int i;
    for (i = 0; i < live_n; ++i)
        if (live[i].p == p && live[i].live) { live[i].live = 0; break; }
    free(p);
}

#define malloc guard_malloc
#define free guard_free
#define STB_VORBIS_IMPLEMENTATION
#include "stb_vorbis.c"

static int find_watch(uint32_t word, void **out)
{
    int i, k;
    for (i = 0; i < live_n; ++i) {
        const unsigned char *p;
        if (!live[i].live || live[i].sz != 8) continue;
        p = (const unsigned char *) live[i].p;
        for (k = 2; k < 32; ++k) {
            uint32_t w;
            memcpy(&w, p + 4 * k, 4);
            if (w != word) break;
        }
        if (k == 32) { *out = live[i].p; return 1; }
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *fp;
    long n;
    int err = 0;
    unsigned char *buf;
    stb_vorbis *v;
    void *watch = NULL;
    if (argc != 2) { fprintf(stderr, "usage: %s file.ogg\n", argv[0]); return 2; }
    fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 2; }
    if (fseek(fp, 0, SEEK_END) != 0) return 2;
    n = ftell(fp);
    if (n < 0 || n > 1000000) return 2;
    rewind(fp);
    buf = (unsigned char *) malloc((size_t) n);
    if (!buf || fread(buf, 1, (size_t) n, fp) != (size_t) n) return 2;
    fclose(fp);

    v = stb_vorbis_open_memory(buf, (int) n, &err, NULL);
    printf("open_memory=%p err=%d bytes=%ld\n", (void *) v, err, n);
    if (v) stb_vorbis_close(v);
    if (find_watch(0x4b434148u, &watch)) printf("watch=UNEXPECTED_SIGNATURE\n");
    else printf("watch=none\n");
    free(buf);
    return 0;
}
