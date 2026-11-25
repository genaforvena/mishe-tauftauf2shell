/* W209 lab-only groom: reserve the deterministic address that the crafted
 * float word spells and place a benign marker there. The mapping is supplied
 * by this harness, NOT by attacker input; it exists only to test whether the
 * file-chosen 64-bit value is a usable canonical pointer. */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

__attribute__((constructor)) static void setup(void)
{
    void *page = (void *) 0x00007f4100007000UL;
    void *p = mmap(page, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { perror("CANON_MAP_FAIL"); return; }
    strcpy((char *) 0x00007f4100007f41UL, "CANON_OK");
    fprintf(stderr, "CANON_MAP_OK page=%p marker=%s\n", p,
            (char *) 0x00007f4100007f41UL);
}
