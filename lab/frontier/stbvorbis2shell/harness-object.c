/* Lab instrumentation for W204: every 8-byte setup allocation is placed on
 * its own RW page followed by PROT_NONE, and a distinct live object with a
 * function-pointer field is placed immediately after the allocation. The
 * pinned stb_vorbis.c is included verbatim; only malloc/free are wrapped.
 * No wrapped pointer is ever called. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_GUARDED 64
struct victim {
    unsigned char canary[64];
    void (*fp)(void);
    unsigned char tail[64];
};
static void *guarded_pages[MAX_GUARDED];
static size_t guarded_lens[MAX_GUARDED];
static struct victim *victims[MAX_GUARDED];
static int guarded_index = 0;

void *guarded_malloc(size_t sz)
{
    void *p = malloc(sz);
    if (sz == 8 && guarded_index < MAX_GUARDED) {
        size_t ps = (size_t) sysconf(_SC_PAGESIZE);
        void *m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            if (mprotect((char *) m + ps, ps, PROT_NONE) == 0) {
                struct victim *v = (struct victim *) ((char *) m + 8);
                memset(v, 0x5a, sizeof *v);
                guarded_pages[guarded_index] = m;
                guarded_lens[guarded_index] = sz;
                victims[guarded_index] = v;
                ++guarded_index;
                return m;
            }
            munmap(m, 2 * ps);
        }
    }
    return p;
}

static int is_guarded(void *p)
{
    int i;
    for (i = 0; i < guarded_index; ++i)
        if (guarded_pages[i] == p) return 1;
    return 0;
}

void guarded_free(void *p)
{
    if (!is_guarded(p)) free(p);
}

#define malloc guarded_malloc
#define free guarded_free
#define STB_VORBIS_IMPLEMENTATION
#include "stb_vorbis.c"

static void report_victims(void)
{
    int i;
    for (i = 0; i < guarded_index; ++i) {
        struct victim *v = victims[i];
        const unsigned char *b = (const unsigned char *) v;
        int changed = 0;
        size_t k;
        for (k = 0; k < sizeof *v; ++k)
            if (b[k] != 0x5a) ++changed;
        printf("victim[%d] changed=%d sizeof=%zu fp=0x%016llx fp_low=0x%08llx\n",
               i, changed, sizeof *v,
               (unsigned long long) (uintptr_t) v->fp,
               (unsigned long long) ((uint32_t) (uintptr_t) v->fp));
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s file.ogg\n", argv[0]); return 2; }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 2; }
    if (fseek(fp, 0, SEEK_END) != 0) return 2;
    long n = ftell(fp);
    if (n < 0 || n > 1000000) return 2;
    rewind(fp);
    unsigned char *buf = (unsigned char *) malloc((size_t) n);
    if (!buf || fread(buf, 1, (size_t) n, fp) != (size_t) n) return 2;
    fclose(fp);
    int err = 0;
    stb_vorbis *v = stb_vorbis_open_memory(buf, (int) n, &err, NULL);
    printf("open_memory=%p err=%d bytes=%ld guarded=%d\n",
           (void *) v, err, n, guarded_index);
    report_victims();
    if (v) stb_vorbis_close(v);
    free(buf);
    return 0;
}
