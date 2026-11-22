/* SOES 3.2.0 vs 3.2.1 — CVE-2026-129814 source-bound triage.
 *
 * Drives the REAL ESC_coeprocess() -> SDO_getod() path with one crafted SDO
 * Information "Get Object Description" mailbox request. The modeled condition
 * is an object whose name is at least ESC_MBXDSIZE - 0x0c bytes long: 3.2.0
 * copies 110 name bytes into a 128-byte mailbox slot whose name starts at
 * offset 18, then writes the terminator at MBX[slot+128], one byte past the
 * slot. With ESC_claimbuffer() returning the last slot (2 of 3), that byte is
 * one past the entire MBX[] global, so ASan reports a one-byte overflow.
 * Pinned 3.2.1 shortens the copy loop by one (esc_coe.c:1427) and leaves the
 * terminator inside the slot. The short-name control exits the loop on NUL.
 *
 * The long name is an object-dictionary property supplied by the application,
 * not a field on the wire: the value written is the next name byte, not an
 * attacker-chosen byte. MBX[] is filled in-process: no wire, no HAL, no live
 * slave, no leaked address, no command side effect. Rung 3 on a real pinned
 * handler, rung 4 harness-level at most — NOT wire evidence and NOT rung 5.
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

/* Real MBX/MBXcontrol/ESCvar and the real object handlers from ecat_slv.c. */
#include "ecat_slv.c"

static uint8_t g_data;
static char g_long_name[112];   /* 111 'A' bytes then NUL: >= 111 non-NUL */
static const char n_short[] = "short-name";
static const char n_ms[] = "maxsub";

static const _objd od_2006[] = {
   { 0, DTYPE_VISIBLE_STRING, 8 * 111, ATYPE_RO, n_ms, 0, &g_data },
};
static const _objd od_2007[] = {
   { 0, DTYPE_VISIBLE_STRING, 8, ATYPE_RO, n_ms, 0, &g_data },
};
const _objectlist SDOobjects[] = {
   { 0x2006, OTYPE_VAR, 0, 0, g_long_name, od_2006 },
   { 0x2007, OTYPE_VAR, 0, 0, n_short,     od_2007 },
   { 0xFFFF, 0, 0, 0, NULL, NULL },
};

/* Stubs for ecat_slv.c externs unused on this path. The last mailbox slot
 * makes the one-byte write land just past the MBX[] global itself. */
void ESC_write(uint16_t a, void *b, uint16_t l) { (void)a;(void)b;(void)l; }
void FOE_init(void) {}
void EOE_init(void) {}
void MBX_error(uint16_t err) { (void)err; }
uint8_t ESC_claimbuffer(void) { return (uint8_t)(MBXBUFFERS - 1); }
void ESC_read(uint16_t address, void *buf, uint16_t len)
{ (void)address; if (len) memset(buf, 0, len); }

/* One SDO Information Get Object Description request. Struct offsets:
 * opcode at 6+2, index at 6+2+4 = 12, name at 18. */
static void build_getod(uint16_t index)
{
   memset(MBX, 0, sizeof(MBX));
   _COEobjdesc *r = (_COEobjdesc *)&MBX[0];
   r->mbxheader.length = htoes(COE_HEADERSIZE + 4);
   r->mbxheader.mbxtype = MBXCOE;
   r->coeheader.numberservice = htoes(COE_SDOINFORMATION << 12);
   r->infoheader.opcode = 0x03;
   r->index = htoes(index);
}

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "long";
   uint16_t index;

   memset(g_long_name, 'A', sizeof(g_long_name) - 1);
   g_long_name[sizeof(g_long_name) - 1] = '\0';
   memset(MBXcontrol, 0, sizeof(MBXcontrol));
   memset(MBX, 0, sizeof(MBX));
   ESCvar.MBXrun = 1;
   ESCvar.ALstatus = ESCpreop;
   ESCvar.activembxsize = MBXSIZE;
   ESCvar.xoe = 0;
   ESCvar.mbxoutpost = 0;
   ESCvar.ALstatus = ESCpreop;

#ifdef SOES_FIXED_VERSION
   printf("build: 3.2.1 (hash-pinned fixed source)\n");
#else
   printf("build: 3.2.0 (hash-pinned vulnerable source)\n");
#endif
   printf("mode: %s\n", mode);
   printf("MBX bytes=%zu slots=%u name_limit=%ld\n",
          sizeof(MBX), (unsigned)MBXBUFFERS,
          (long)(ESC_MBXDSIZE - 0x0c));
   if (strcmp(mode, "long") == 0) {
      index = 0x2006;
   } else if (strcmp(mode, "safe") == 0) {
      index = 0x2007;
   } else {
      printf("unknown mode\n");
      return 2;
   }

   build_getod(index);
   MBXcontrol[0].state = MBXstate_inclaim;
   ESCvar.xoe = 0;
   ESC_coeprocess();

   printf("result: xoe=%02x slot=%u state=%02x length=%u\n",
          ESCvar.xoe, (unsigned)ESC_claimbuffer(),
          MBXcontrol[MBXBUFFERS - 1].state,
          (unsigned)etohs(((_COEobjdesc *)&MBX[(MBXBUFFERS - 1) * MBXSIZE])->mbxheader.length));
#ifndef SOES_ASAN
   { const uint8_t end_byte = *(const uint8_t *)((const uint8_t *)MBX + sizeof(MBX));
     const size_t off = (size_t)((MBXBUFFERS - 1) * MBXSIZE + 18 + (ESC_MBXDSIZE - 0x0c));
     printf("byte_at_MBX_end=%02x\n", end_byte);
     printf("verdict: %s-name terminator %s at MBX+%zu (observed byte %02x)\n",
            mode, end_byte ? "written" : "not written", off, end_byte); }
#else
   printf("verdict: %s-name run completed; write evidence is the ASan report above, if any\n", mode);
#endif
   return 0;
}
