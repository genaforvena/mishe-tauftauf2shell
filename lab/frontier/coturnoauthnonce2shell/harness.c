/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Direct sink harness for CVE-2026-43994 / GHSA-74pg-rfh2-5qw5.
 * Logic mirrors upstream fuzzing/FuzzOAuthToken.c from fix commit
 * 46368b3e1ecda2175f8db8b05ece8bbdbf844cea, with a file-reading main so
 * it runs without libFuzzer. The input is the raw bytes of an
 * encoded_oauth_token: two big-endian nonce_len bytes, nonce_len nonce
 * bytes, then key_len/timestamp/lifetime/tag/ciphertext fields.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

static const uint8_t kFuzzAsRsKey[16] = {0};
#define kMinInputLength 31
#define kMaxInputLength MAX_ENCODED_OAUTH_TOKEN_SIZE

static int decode_one(const uint8_t *Data, size_t Size) {
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        printf("INPUT_REJECTED size=%zu\n", Size);
        return 0;
    }
    oauth_key key;
    memset(&key, 0, sizeof(key));
    key.as_rs_alg = A128GCM;
    memcpy(key.as_rs_key, kFuzzAsRsKey, sizeof(kFuzzAsRsKey));
    key.as_rs_key_size = sizeof(kFuzzAsRsKey);
    memcpy(key.auth_key, kFuzzAsRsKey, sizeof(kFuzzAsRsKey));
    key.auth_key_size = sizeof(kFuzzAsRsKey);

    encoded_oauth_token etoken;
    memset(&etoken, 0, sizeof(etoken));
    etoken.size = Size;
    memcpy(etoken.token, Data, Size);

    oauth_token dtoken;
    memset(&dtoken, 0, sizeof(dtoken));
    bool ok = decode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &dtoken);
    printf("DECODE_OK=%d NONCE_LEN=%u\n", ok ? 1 : 0,
           (unsigned)dtoken.enc_block.nonce_length);
    printf("ADJACENT key_length=0x%04x mac_key0=0x%02x timestamp=0x%016llx lifetime=0x%08x\n",
           (unsigned)dtoken.enc_block.key_length,
           (unsigned)dtoken.enc_block.mac_key[0],
           (unsigned long long)dtoken.enc_block.timestamp,
           (unsigned)dtoken.enc_block.lifetime);
    if (ok && dtoken.enc_block.nonce_length > 256) {
        printf("INVARIANT_FAIL\n");
        return 2;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s INPUT\n", argv[0]);
        return 64;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 65;
    }
    static uint8_t buf[kMaxInputLength];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    printf("INPUT_SIZE=%zu\n", n);
    return decode_one(buf, n);
}
