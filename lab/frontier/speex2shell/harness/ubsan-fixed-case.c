/* Already-full-buffer UBSan case from xiph/speex issue #42 comment by
 * @GeekQAQ (2026-11-20), reproduced verbatim against the pinned vendor fix
 * commit 09b569d1. This is a SEPARATE bug in the fix (negative truncated
 * length / left shift), not the CVE-2026-116741 OOB write claim. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
   char a[4] = {0x54, 0x72, (char)0xd4, (char)0xb9}, b[16];
   char *buf = calloc(1, 16);
   SpeexBits bits;
   int i;

   for (i = 0; i < 16; i++)
      b[i] = (char)(0x10 + i);
   speex_bits_init_buffer(&bits, buf, 16);
   speex_bits_read_whole_bytes(&bits, b, 16);   /* buffer is now full */
   speex_bits_advance(&bits, 56);               /* 9 unread bytes left */
   speex_bits_read_whole_bytes(&bits, a, 4);    /* nchars = 16 - 16 - 1 = -1 */
   printf("nbytes=%d\n", speex_bits_nbytes(&bits));
   speex_bits_destroy(&bits);
   free(buf);
   return 0;
}
