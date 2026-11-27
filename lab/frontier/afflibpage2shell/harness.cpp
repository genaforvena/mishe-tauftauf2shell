// Frontier harness: real pinned libafflib API on a crafted AFF image.
// No upstream source is edited; ASan frames come from pinned afflib_pages.cpp.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include "afflib.h"
#include "afflib_i.h"

static void create_image(const char *path, uint32_t sector, uint32_t page,
                         const unsigned char *badflag, uint32_t badlen)
{
    AFFILE *af = af_open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (!af) { perror("af_open create"); exit(2); }
    if (af_update_seg(af, AF_SECTORSIZE, sector, 0, 0)) {
        fprintf(stderr, "update sectorsize failed\n"); exit(2);
    }
    if (af_update_seg(af, AF_PAGESIZE, page, 0, 0)) {
        fprintf(stderr, "update pagesize failed\n"); exit(2);
    }
    if (af_update_seg(af, AF_BADFLAG, 0, badflag, badlen)) {
        fprintf(stderr, "update badflag failed\n"); exit(2);
    }
    if (af_close(af)) { fprintf(stderr, "close failed\n"); exit(2); }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc != 6) {
        fprintf(stderr, "usage: %s CREATE|ATTACK image sector page buf\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *path = argv[2];
    uint32_t sector = (uint32_t)strtoul(argv[3], 0, 0);
    uint32_t page = (uint32_t)strtoul(argv[4], 0, 0);
    size_t bufsz = (size_t)strtoul(argv[5], 0, 0);
    unsigned char badflag[16];
    memset(badflag, 0x5a, sizeof(badflag));

    if (!strcmp(mode, "CREATE") || !strcmp(mode, "PATCH")) {
        int oflag = !strcmp(mode, "CREATE")
            ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDWR;
        AFFILE *af = af_open(path, oflag, 0600);
        if (!af) { perror("af_open create"); exit(2); }
        if (af_update_seg(af, AF_SECTORSIZE, sector, 0, 0)) {
            fprintf(stderr, "update sectorsize failed\n"); exit(2);
        }
        if (af_update_seg(af, AF_PAGESIZE, page, 0, 0)) {
            fprintf(stderr, "update pagesize failed\n"); exit(2);
        }
        if (af_update_seg(af, AF_BADFLAG, 0, badflag, sizeof(badflag))) {
            fprintf(stderr, "update badflag failed\n"); exit(2);
        }
        if (af_close(af)) { fprintf(stderr, "close failed\n"); exit(2); }
        printf("PATCHED sector=%u page=%u\n", sector, page);
        return 0;
    }
    int canary = !strcmp(mode, "CANARY");
    if (!canary && strcmp(mode, "ATTACK")) return 2;

    // af_open_with stores the third argument in af->openmode; AF_BADBLOCK_FILL
    // is tested against that field by the pinned af_get_page.
    AFFILE *af = af_open(path, O_RDONLY, AF_BADBLOCK_FILL);
    if (!af) { perror("af_open attack"); return 2; }
    printf("LOADED pagesize=%u sectorsize=%u badflag_set=%d\n",
           af->image_pagesize, af->image_sectorsize, af->badflag_set);
    const size_t CANARY_BYTES = 8192;
    unsigned char *buf = (unsigned char *)malloc(
        bufsz + (canary ? CANARY_BYTES : 0));
    if (!buf) return 2;
    unsigned char *tail = canary ? buf + bufsz : 0;
    if (canary) memset(tail, 0xcc, CANARY_BYTES);
    memset(buf, 0, bufsz);
    size_t bytes = bufsz;
    errno = 0;
    int rc = af_get_page(af, 77, buf, &bytes);
    printf("GETPAGE rc=%d errno=%d bytes=%zu first=%02x\n",
           rc, errno, bytes, buf[0]);
    if (canary) {
        size_t first = 0, last = 0, count = 0;
        for (size_t i = 0; i < CANARY_BYTES; i++) {
            if (tail[i] == 0x5a) {
                if (!count) first = i;
                last = i;
                count++;
            }
        }
        printf("CANARY first=%zu last=%zu count=%zu at10=%02x at64=%02x "
               "at128=%02x at256=%02x\n",
               first, last, count, tail[10], tail[64], tail[128], tail[256]);
    } else {
        volatile unsigned char keep = buf[bufsz - 1];
        (void)keep;
    }
    af_close(af);
    free(buf);
    return 0;
}
