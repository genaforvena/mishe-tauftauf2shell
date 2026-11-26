/* sailtga2shell w1 — drives the public SAIL memory APIs only.
 * Mirrors harness/driver.c but feeds the exact same 28-byte file bytes from
 * memory. Mode "junior" (default) calls sail_load_from_memory(); mode
 * "explicit" uses the documented advanced path
 * sail_codec_info_from_extension() -> sail_start_loading_from_memory() ->
 * sail_load_next_frame() -> sail_stop_loading(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sail/sail.h>

static void report(struct sail_image *image, int want_probe)
{
    printf("w=%u h=%u pixel_format=%d pixels=%p\n",
           image->width, image->height, (int)image->pixel_format, (void *)image->pixels);
    if (want_probe) {
        const unsigned char *p = (const unsigned char *)image->pixels;
        printf("tail_248_264=");
        for (int off = 248; off < 264; off++) {
            printf("%02x", p[off]);
        }
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: memory-driver FILE.tga [junior|explicit] [probe]\n");
        return 2;
    }
    int explicit = argc >= 3 && strcmp(argv[2], "explicit") == 0;
    int probe = (argc >= 3 && strcmp(argv[2], "probe") == 0)
             || (argc == 4 && strcmp(argv[3], "probe") == 0);

    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return 3;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 3;
    }
    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 3;
    }
    unsigned char *buffer = (unsigned char *)malloc((size_t)n);
    if (buffer == NULL || fread(buffer, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(buffer);
        return 3;
    }
    fclose(f);

    struct sail_image *image = NULL;
    sail_status_t st;
    if (!explicit) {
        st = sail_load_from_memory(buffer, (size_t)n, &image);
        printf("rc=%d\n", (int)st);
        if (st == SAIL_OK && image != NULL) {
            report(image, probe);
            sail_destroy_image(image);
        }
    } else {
        const struct sail_codec_info *codec_info = NULL;
        st = sail_codec_info_from_extension("tga", &codec_info);
        if (st != SAIL_OK) {
            printf("codec_rc=%d\n", (int)st);
            free(buffer);
            return 4;
        }
        void *state = NULL;
        st = sail_start_loading_from_memory(buffer, (size_t)n, codec_info, &state);
        printf("start_rc=%d\n", (int)st);
        if (st == SAIL_OK) {
            st = sail_load_next_frame(state, &image);
            printf("rc=%d\n", (int)st);
            if (st == SAIL_OK && image != NULL) {
                report(image, probe);
                sail_destroy_image(image);
            }
            sail_stop_loading(state);
        }
    }

    free(buffer);
    return 0;
}
