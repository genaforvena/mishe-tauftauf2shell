// Direct-call harness for CVE-2026-133646 (Synchronet BBS answer() TERM copy).
// The vulnerable/fixed statements are generated verbatim from pinned sources
// by gen.sh; everything else here is scaffolding, not a rewrite of answer().
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#define TELNET_TERM_MAXLEN 40   // pinned telnet.h:109
#define TERM_COLS_MAX 999       // pinned sbbsdefs.h:644
#define CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL 301
#define CRYPT_OK 1
#define cryptStatusOK(s) ((s) == CRYPT_OK)
#define lprintf(...) ((void)0)
#define ssh_mutex 0
#define C_IN
typedef int CRYPT_HANDLE;
typedef int CRYPT_ATTRIBUTE_TYPE;
#define pthread_mutex_unlock(x) ((void)0)
// The pinned ssl.c helper is C; this compile-time shim only satisfies C++'s
// void* -> char* conversion without editing a single helper source line.
#define malloc(n) static_cast<char *>(::malloc(n))

static size_t harness_strlcpy(char *dst, const char *src, size_t size)
{
    size_t n = strlen(src);
    if (size) {
        size_t copy = n < size - 1 ? n : size - 1;
        memcpy(dst, src, copy);
        dst[copy] = 0;
    }
    return n;
}
#define strlcpy harness_strlcpy
#define SAFECOPY(dst, src) strlcpy(dst, src, sizeof(dst))  // pinned gen_defs.h:472

#ifdef REDZONE_MODEL
// Rung-3 model: the destination array alone, so ASan's redzone starts where
// the 41-byte array ends. The real sbbs_t has adjacent fields (below).
struct session_t { char terminal[TELNET_TERM_MAXLEN + 1]; };
#else
// Rung-4 layout from pinned sbbs.h:702-705: terminal[41], line_delay,
// console, wordwrap[1000]; alignment puts line_delay at 44, console at 48,
// wordwrap at 52.
struct session_t {
    char terminal[TELNET_TERM_MAXLEN + 1];
    uint32_t line_delay;
    uint32_t console;
    char wordwrap[TERM_COLS_MAX + 1];
};
#endif

static unsigned char wire[64];
static int wire_len = 0;
static int ssh_session = 1;

// cryptGetAttributeString has no destination-size argument. Pinned
// cryptapi.c:2685 sets cmd.strArgLen[0] = RETURN_VALUE(MAX_ATTRIBUTE_SIZE)
// regardless of the caller's array, so the dispatch copy is bounded only by
// the attribute's own length. This stub reproduces that contract: when a
// destination is supplied it writes wire_len bytes into it.
static int cryptGetAttributeString(int sess, int attr, void *value, int *length)
{
    (void)sess; (void)attr;
    if (!value) { *length = wire_len; return CRYPT_OK; }
    memcpy(value, wire, (size_t)wire_len);
    return CRYPT_OK;
}

#ifdef FIXED
#include "helper.inc"   // pinned ssl.c:34-61: get_binary_crypt_attribute/free
#endif

static void build_wire(int len)
{
    static const char m1[] = "MISH", m2[] = "E-OO", m3[] = "TAUFTAUF";
    if (len < 0 || len > 64) len = 64;
    wire_len = len;
    for (int i = 0; i < len; i++) {
        if (i < 41) wire[i] = 'A';
        else if (i < 44) wire[i] = 'x';   // 41..43: intra-object padding
        else if (i < 48) wire[i] = (unsigned char)m1[i - 44]; // line_delay
        else if (i < 52) wire[i] = (unsigned char)m2[i - 48]; // console
        else if (i < 60) wire[i] = (unsigned char)m3[i - 52]; // wordwrap
        else wire[i] = 'Z';
    }
}

static void hexdump(const void *p, int n)
{
    const unsigned char *b = (const unsigned char *)p;
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(int argc, char **argv)
{
    int len = argc > 1 ? atoi(argv[1]) : 64;
    build_wire(len);
    session_t s{};
    {
        char (&terminal)[TELNET_TERM_MAXLEN + 1] = s.terminal;
        int l;
#ifdef FIXED
#include "fixed.inc"
#else
#include "vuln.inc"
#endif
    }
#ifdef REDZONE_MODEL
    printf("MODEL=redzone LEN=%d terminal_bytes=", len);
    hexdump(s.terminal, 41);
    printf("\n");
    const bool clean = (len <= 40);
    for (int i = 0; i < 40 && clean; i++) if (s.terminal[i] != 'A') return 2;
    if (clean && s.terminal[40] != 0) return 3;
    return clean ? 0 : 4;
#else
    printf("MODEL=layout LEN=%d terminal_head=", len);
    hexdump(s.terminal, 16);
    printf(" line_delay=%08x console=%08x wordwrap_head=", s.line_delay, s.console);
    hexdump(s.wordwrap, 16);
    printf("\n");
#ifdef FIXED
    const bool ok = s.line_delay == 0 && s.console == 0 && s.wordwrap[0] == 0 &&
                    memcmp(s.terminal, wire, (size_t)(len < 40 ? len : 40)) == 0 &&
                    s.terminal[len < 41 ? len : 40] == 0;
    if (!ok) { printf("FIXED_CONTROL_FAIL\n"); return 5; }
    printf("FIXED_CONTROL_OK\n");
    return 0;
#else
    if (len <= 40) {
        const bool ok = s.line_delay == 0 && s.console == 0 && s.wordwrap[0] == 0;
        if (!ok) { printf("SHORT_CONTROL_FAIL\n"); return 6; }
        printf("SHORT_CONTROL_OK\n");
        return 0;
    }
    const bool ok = s.line_delay == 0x4853494d &&   // "MISH" at offsets 41..44
                    s.console == 0x4f4f2d45 &&      // "E-OO" at offsets 45..48
                    memcmp(s.wordwrap, "TAUFTAUF", 8) == 0;  // offsets 52..59
    if (!ok) { printf("CHOSEN_BYTES_FAIL\n"); return 7; }
    printf("CHOSEN_BYTES_OK\n");
    return 0;
#endif
#endif
}
