/* frontier sailpsd2shell — drives the real public SAIL file API only. */
#include <stdio.h>
#include <string.h>
#include <sail/sail.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: driver FILE.psd\n");
        return 2;
    }

    struct sail_image *image = NULL;
    sail_status_t st = sail_load_from_file(argv[1], &image);
    printf("rc=%d\n", (int)st);

    if (st == SAIL_OK && image != NULL) {
        printf("w=%u h=%u pixel_format=%d pixels=%p\n",
               image->width, image->height, (int)image->pixel_format,
               (void *)image->pixels);
        sail_destroy_image(image);
    }

    return st == SAIL_OK ? 0 : 1;
}
