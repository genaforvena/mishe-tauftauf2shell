/* Minimal real-stb_vorbis consumer: feed one Ogg buffer to the public API. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    printf("open_memory=%p err=%d bytes=%ld\n", (void *) v, err, n);
    if (v) stb_vorbis_close(v);
    free(buf);
    return 0;
}
