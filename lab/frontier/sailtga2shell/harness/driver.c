/* frontier sailtga2shell — drives the real public SAIL API only. */
#include <string.h>
#include <sail/sail.h>

int main(int argc, char **argv)
{
    if (argc != 2 && !(argc == 3 && strcmp(argv[2], "probe") == 0)) {
        fprintf(stderr, "usage: driver FILE.tga\n");
        return 2;
    }

    struct sail_image *image = NULL;
    sail_status_t st = sail_load_from_file(argv[1], &image);
    printf("rc=%d\n", (int)st);

    if (st == SAIL_OK && image != NULL) {
        printf("w=%u h=%u pixel_format=%d pixels=%p\n",
               image->width, image->height, (int)image->pixel_format, (void *)image->pixels);
        if (argc == 3) {
            const unsigned char *p = (const unsigned char *)image->pixels;
            printf("tail_248_264=");
            for (int off = 248; off < 264; off++) {
                printf("%02x", p[off]);
            }
            printf("\n");
        }
        sail_destroy_image(image);
    }

    return 0;
}
