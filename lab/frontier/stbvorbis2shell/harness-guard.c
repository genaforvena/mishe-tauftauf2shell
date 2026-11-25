/* Lab instrumentation: route 8-byte setup allocations to a RW page followed
 * by a PROT_NONE page, so the OOB expansion loop stops at a measured offset.
 * The pinned stb_vorbis.c is included verbatim; only malloc/free are wrapped. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_GUARDED 256
static void *guarded_pages[MAX_GUARDED];
static size_t guarded_lens[MAX_GUARDED];
static int guarded_index = 0;

void *guarded_malloc(size_t sz)
{
    void *p = malloc(sz);
    /* Default: W203's 8-byte single RW page. Env knobs let W204 measure a
     * longer run of file-derived words before the PROT_NONE page. */
    size_t want = 8;
    long pages = 1;
    const char *s = getenv("MISHE_GUARD_SZ");
    if (s) want = (size_t) strtoul(s, NULL, 0);
    s = getenv("MISHE_GUARD_RW_PAGES");
    if (s) {
        pages = strtol(s, NULL, 0);
        if (pages < 1) pages = 1;
        if (pages > 64) pages = 64;
    }
    if (sz == want && guarded_index < MAX_GUARDED) {
        size_t ps = (size_t) sysconf(_SC_PAGESIZE);
        size_t bytes = (size_t) pages * ps;
        void *m = mmap(NULL, bytes + ps, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            if (mprotect((char *) m + bytes, ps, PROT_NONE) == 0) {
                guarded_pages[guarded_index] = m;
                guarded_lens[guarded_index] = sz;
                ++guarded_index;
                return m;
            }
            munmap(m, bytes + ps);
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
    if (v) stb_vorbis_close(v);
    free(buf);
    return 0;
}
