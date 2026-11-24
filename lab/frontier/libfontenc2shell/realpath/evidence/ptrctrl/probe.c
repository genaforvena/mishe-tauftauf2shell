/*
 * W183 probe: walk the live FontMapRec objects returned by FontEncFind() and
 * call the public recode entry point on each.  A live-object pointer
 * corruption is visible as a changed `map` address and a changed recode
 * result for mapping2.  Not a production consumer.
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
    unsigned code, n = 0;

    enc = FontEncFind(charset, argv[2]);
    printf("FontEncFind=%p\n", (void *)enc);
    if (!enc) return 1;
    for (m = enc->mappings; m; m = m->next) {
        ++n;
        printf("mapping%u=%p client=%p", n, (void *)m, m->client_data);
        if (m->client_data) {
            sm = (ProbeMap *)m->client_data;
            code = ((unsigned)(sm->first / sm->row_size) << 8) |
                   (sm->first % sm->row_size);
            printf(" len=%u row=%u first=%u map=%p map0=%u code=%u recode=%u",
                   sm->len, sm->row_size, sm->first, (void *)sm->map,
                   sm->map ? sm->map[0] : 0xffffu, code,
                   FontEncRecode(code, m));
        }
        printf("\n");
    }
    fflush(stdout);
    return 0;
}
