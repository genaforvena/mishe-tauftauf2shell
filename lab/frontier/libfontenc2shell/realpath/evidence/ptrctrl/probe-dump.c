/*
 * W186 calibration probe: dump words around each live mapping object so the
 * exact addresses of out-of-bounds stores can be read off directly.
 */
#include <stdio.h>
#include <stdint.h>
#include <X11/fonts/fontenc.h>

static void dump(const char *tag, void *p, int nwords)
{
    unsigned short *w = (unsigned short *)p;
    int i;
    printf("%s @ %p:", tag, p);
    for (i = 0; i < nwords; ++i)
        printf(" %04x", w[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    FontEncPtr enc;
    FontMapPtr m;
    int n = 0;

    enc = FontEncFind(argv[1], argv[2]);
    printf("enc=%p\n", (void *)enc);
    if (!enc) return 1;
    for (m = enc->mappings; m; m = m->next) {
        ++n;
        printf("--- m%d=%p ---\n", n, (void *)m);
        dump("m-0x30", (char *)m - 0x30, 28);
        dump("client", m->client_data, 12);
    }
    fflush(stdout);
    return 0;
}
