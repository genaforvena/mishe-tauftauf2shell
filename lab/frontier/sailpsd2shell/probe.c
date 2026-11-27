/* frontier sailpsd2shell — synthetic exact-size allocator probe.
 * Real SAIL decode writes into 8-byte slots followed by visible guard bytes.
 * This is rung-4 lab mechanics, not a production allocator or wire path.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sail/sail.h>

#define SLOTS 64
#define SLOT_SIZE 8
#define GUARD_SIZE 8

static unsigned char slots[SLOTS][SLOT_SIZE + GUARD_SIZE];
static unsigned used;
static int active;

sail_status_t __real_sail_malloc(size_t size, void **ptr);
void __real_sail_free(void *ptr);

sail_status_t __wrap_sail_malloc(size_t size, void **ptr)
{
    if (active && size == SLOT_SIZE && used < SLOTS) {
        unsigned char *slot = slots[used++];
        memset(slot, 0xcc, SLOT_SIZE + GUARD_SIZE);
        *ptr = slot;
        return SAIL_OK;
    }
    return __real_sail_malloc(size, ptr);
}
void __wrap_sail_free(void *ptr)
{
    uintptr_t p = (uintptr_t)ptr;
    uintptr_t begin = (uintptr_t)slots;
    uintptr_t end = begin + sizeof(slots);
    if (p >= begin && p < end) {
        return;
    }
    __real_sail_free(ptr);
}

static void dump_slots(void)
{
    printf("slots=%u\n", used);
    for (unsigned i = 0; i < used; i++) {
        printf("slot%02u data=", i);
        for (unsigned j = 0; j < SLOT_SIZE; j++) {
            printf("%02x", slots[i][j]);
        }
        printf(" guard=");
        for (unsigned j = SLOT_SIZE; j < SLOT_SIZE + GUARD_SIZE; j++) {
            printf("%02x", slots[i][j]);
        }
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: probe FILE.psd\n");
        return 2;
    }

    struct sail_image *image = NULL;
    active = 1;
    sail_status_t st = sail_load_from_file(argv[1], &image);
    active = 0;
    printf("rc=%d\n", (int)st);
    if (st == SAIL_OK && image != NULL) {
        printf("w=%u h=%u pixel_format=%d pixels=%p\n",
               image->width, image->height, (int)image->pixel_format,
               (void *)image->pixels);
    }
    dump_slots();
    return st == SAIL_OK ? 0 : 1;
}
