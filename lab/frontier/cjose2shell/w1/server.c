/*
 * cjose2shell W181 — loopback-only HTTP consumer for the AES-KW overflow.
 *
 * Accepts ONE real HTTP request on 127.0.0.1, takes a compact JWE from the
 * Authorization: Bearer header, and feeds it through real cjose_jwe_import()
 * and cjose_jwe_decrypt(). This is a synthetic verifier: it models a
 * pre-auth token check to measure wire-length propagation and heap layout,
 * not a deployed application. It never contacts anything but its own client.
 */
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

static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";


/* Optional link-time malloc trace (plain builds only): identifies the
 * allocation that owns the chunk adjacent to the CEK. Static storage only,
 * so the tracer itself performs no heap allocation. */
#ifdef W1_ALLOCLOG
#define W1_LOG_N 128
struct w1_alloc { void *p; size_t n; void *caller; };
static struct w1_alloc w1_allocs[W1_LOG_N];
static unsigned w1_alloc_i;
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
static void w1_record(void *p, size_t n)
{
    unsigned i = w1_alloc_i++ % W1_LOG_N;
    w1_allocs[i].p = p;
    w1_allocs[i].n = n;
    w1_allocs[i].caller = __builtin_return_address(1);
}
void *__wrap_malloc(size_t n) { void *p = __real_malloc(n); w1_record(p, n); return p; }
void *__wrap_calloc(size_t a, size_t b) { void *p = __real_calloc(a, b); w1_record(p, a * b); return p; }
void *__wrap_realloc(void *q, size_t n) { void *p = __real_realloc(q, n); w1_record(p, n); return p; }
static void w1_dump_neighbours(const unsigned char *cek)
{
    uintptr_t c = (uintptr_t)cek;
    for (unsigned i = 0; i < W1_LOG_N; i++) {
        struct w1_alloc *a = &w1_allocs[i];
        if (!a->p) continue;
        intptr_t off = (intptr_t)a->p - (intptr_t)c;
        if (off >= -64 && off <= 256)
            printf("NEIGHBOUR off=%+ld size=%zu caller=%p\n",
                   (long)off, a->n, a->caller);
    }
}
#endif
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
    if (!bearer) { printf("NO_TOKEN\n"); reply(fd, 0); close(fd); return 3; }
    char *tok = bearer + 7;
    char *end = tok;
    while (*end && *end != '\r' && *end != '\n' && *end != ' ') end++;
    *end = '\0';
    printf("TOKEN_BYTES=%zu\n", strlen(tok));

    /* Independently measure the attacker-supplied segment from the wire. */
    char *d1 = strchr(tok, '.');
    char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    if (!d2) { printf("BAD_TOKEN\n"); reply(fd, 0); close(fd); return 3; }
    size_t seg_len = (size_t)(d2 - d1 - 1);
    uint8_t *wire_raw = NULL;
    size_t wire_raw_len = 0;
    cjose_err werr;
    memset(&werr, 0, sizeof(werr));
    int decoded = cjose_base64url_decode(d1 + 1, seg_len, &wire_raw,
                                         &wire_raw_len, &werr);
    printf("WIRE_SEG_B64=%zu WIRE_DECODE=%d WIRE_EK_RAW_LEN=%zu\n",
           seg_len, decoded, decoded ? wire_raw_len : 0);

    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); reply(fd, 0); close(fd); return 2; }

    cjose_jwe_t *jwe = cjose_jwe_import(tok, strlen(tok), &err);
    printf("IMPORT=%d ERRCODE=%d\n", jwe != NULL, err.code);
    if (!jwe) { reply(fd, 0); close(fd); return 3; }
    printf("JWE_CEK_LEN_BEFORE=%zu JWE_EK_RAW_LEN=%zu\n",
           jwe->cek_len, jwe->to[0].enc_key.raw_len);

    memset(&err, 0, sizeof(err));
    size_t plain_len = 0;
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);
    printf("DECRYPT=%d ERRCODE=%d PLAIN_LEN=%zu CEK_LEN_AFTER=%zu\n",
           dec != NULL, err.code, plain_len, jwe->cek_len);
#ifdef W1_DUMP
    if (jwe->cek) {
        printf("CEK_PTR=%p\n", (void *)jwe->cek);
        printf("CEK_MINUS16=");
        for (int i = -16; i < 0; i++) printf("%02x", jwe->cek[i]);
        printf("\nCEK_PLUS24=");
        for (int i = 24; i < 56; i++) printf("%02x", jwe->cek[i]);
        printf("\n");
#ifdef W1_ALLOCLOG
        w1_dump_neighbours(jwe->cek);
#endif
    }
#endif
    reply(fd, dec != NULL);
    if (dec) cjose_get_dealloc()(dec);
    if (wire_raw) cjose_get_dealloc()(wire_raw);
    cjose_jwe_release(jwe);
    cjose_jwk_release(jwk);
    close(fd);
    close(ls);
    return 0;
}
