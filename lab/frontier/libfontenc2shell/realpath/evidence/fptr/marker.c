/*
 * W186 control-flow probe.  benign_marker is a real, lab-chosen function in
 * this binary.  Its address is baked into a crafted .enc as four 16-bit
 * words; if setCode()'s OOB store reaches a live FontMapRec.recode field,
 * FontEncRecode() jumps here.  Fixed/safe-input controls must not jump.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <X11/fonts/fontenc.h>

unsigned benign_marker(unsigned code, void *data)
{
    static const char msg[] = "BENIGN_MARKER_EXECUTED\n";
    (void)code; (void)data;
    write(1, msg, sizeof(msg) - 1);
    return 0xabcd1234u;
}

typedef struct {
    unsigned len;
    unsigned short row_size;
    unsigned short first;
    const unsigned short *map;
} ProbeMap;

int main(int argc, char **argv)
{
    FontEncPtr enc;
    FontMapPtr m;
    ProbeMap *sm;
    unsigned code, n = 0;

    setbuf(stdout, NULL);

    enc = FontEncFind(argv[1], argv[2]);
    printf("enc=%p\n", (void *)enc);
    if (!enc) return 1;
    for (m = enc->mappings; m; m = m->next) {
        ++n;
        sm = (ProbeMap *)m->client_data;
        code = sm ? ((unsigned)(sm->first / sm->row_size) << 8) |
                    (sm->first % sm->row_size) : 0;
        printf("m%u recode=%p calling... ", n, (void *)m->recode);
        printf("recode=%u\n", FontEncRecode(code, m));
    }
    fflush(stdout);
    return 0;
}
