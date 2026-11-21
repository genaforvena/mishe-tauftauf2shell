/*
 * Lab-only consumer: accepts an index file from a loopback socket and calls
 * the ordinary pinned hnswlib v0.9.0 load constructor on the received bytes.
 * No external network, no real application, no library modifications.
 */
#include "hnswlib/hnswalg.h"
#include "hnswlib/space_l2.h"

#include <arpa/inet.h>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <exception>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: service PORT RECEIVED_INDEX_PATH\n");
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
  printf("service_ready pid=%d port=%d path=%s\n", (int)getpid(), port, path.c_str());
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

  size_t hdr[4] = {0, 0, 0, 0};
  std::ifstream probe(path, std::ios::binary);
  probe.read((char *)hdr, sizeof(hdr));
  probe.close();
  printf("service_received bytes=%zu stored_capacity=%zu count=%zu per=%zu\n",
         total, hdr[1], hdr[2], hdr[3]);
  fflush(stdout);

  hnswlib::L2Space space(21);
  try {
    hnswlib::HierarchicalNSW<float> idx(&space, path);
    printf("service_load=loaded\n");
  } catch (const std::exception &e) {
    printf("service_load=exception what=%s\n", e.what());
  }
  fflush(stdout);
  return 0;
}
