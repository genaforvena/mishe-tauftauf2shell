/*
 * W186 layout probe: report live FontMapRec function-pointer fields and the
 * FontEncSimpleMapRec data pointer for each mapping returned by FontEncFind().
 * Read-only; used to compute which setCode() index reaches recode/name.
 */
#include <stdio.h>
#include <stdlib.h>
#include <X11/fonts/fontenc.h>

typedef struct {
    unsigned len;
    unsigned short row_size;
    unsigned short first;
    const unsigned short *map;
} ProbeMap;

int main(int argc, char **argv)
{
    const char *charset = (argc > 1) ? argv[1] : "heapobj";
    FontEncPtr enc;
    FontMapPtr m;
    ProbeMap *sm;
    unsigned n = 0;

    enc = FontEncFind(charset, argv[2]);
    printf("enc=%p\n", (void *)enc);
    if (!enc) return 1;
    for (m = enc->mappings; m; m = m->next) {
        ++n;
        sm = (ProbeMap *)m->client_data;
        printf("m%u=%p recode=%p name=%p client=%p map=%p\n",
               n, (void *)m, (void *)m->recode, (void *)m->name,
               (void *)m->client_data, sm ? (void *)sm->map : NULL);
    }
    fflush(stdout);
    return 0;
}
