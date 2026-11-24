// Bounded negative probe: does natural stack layout put a control datum at the
// CVE's one-past index?  Built against the pinned vulnerable and fixed plain
// libraries by run-stack-layout.sh.  No struct, no packing, no alignment
// attribute: only ordinary locals declared around a 31-byte output array.
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t kKey[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t kIv[16] = {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
                                0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f};
static void normal(void) {}

int main(void) {
  uint8_t pt[32], ct[64];
  for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;
  pt[31] = 0x48;
  EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
  int n1 = 0, n2 = 0;
  if (!EVP_EncryptInit_ex(e, EVP_aes_128_cbc(), NULL, kKey, kIv) ||
      !EVP_EncryptUpdate(e, ct, &n1, pt, 32) ||
      !EVP_EncryptFinal_ex(e, ct + n1, &n2)) return 2;
  EVP_CIPHER_CTX_free(e);

  void (*cb_after)(void) = normal;
  uint8_t out[31];
  void (*cb_before)(void) = normal;
  uint8_t tail[16];
  memset(out, 0xab, sizeof(out));
  out[31] = 0xab;  /* deliberate canary at the one-past index */
  memset(tail, 0xcc, sizeof(tail));
  volatile uintptr_t frame = (uintptr_t)__builtin_frame_address(0);

  EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
  int n = 0;
  if (!EVP_DecryptInit_ex(d, EVP_aes_128_cbc(), NULL, kKey, kIv)) return 2;
  EVP_DecryptUpdate(d, out, &n, ct, 16);
  EVP_DecryptUpdate(d, out, &n, ct + 16, 16);
  EVP_CIPHER_CTX_free(d);

  uintptr_t oob = (uintptr_t)(out + 31);
  printf("oob=%p cb_after_delta=%ld cb_before_delta=%ld tail_delta=%ld "
         "frame_delta=%ld oob_byte=0x%02x\n",
         (void *)oob,
         (long)((uintptr_t)&cb_after - oob),
         (long)((uintptr_t)&cb_before - oob),
         (long)((uintptr_t)&tail[0] - oob),
         (long)(frame - oob), out[31]);
  return 0;
}
