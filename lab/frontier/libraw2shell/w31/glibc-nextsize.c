/* Host-allocator control for W31: does glibc here reject a 0x11 next-chunk
 * size field?  Run with no argv (victim PREV_INUSE set) and with any argv
 * (PREV_INUSE cleared, matching the W31 free-time state).  gcc -O0 -g. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  unsigned char *a = malloc(1000);          /* earlier live chunk */
  unsigned char *p = malloc(1000);          /* victim */
  unsigned long cs = *(unsigned long *)(p - 8);
  unsigned char *next = p - 16 + cs;
  (void)argv;
  if (argc > 1) *(unsigned long *)(p - 8) = cs & ~1UL;
  *(unsigned long *)(next + 8) = 0x11;
  printf("a=%p p=%p cs=%#lx next=%#lx nextsize=%#lx prev_size=%#lx\n",
         (void *)a, (void *)p, *(unsigned long *)(p - 8),
         (unsigned long)next, *(unsigned long *)(next + 8),
         *(unsigned long *)next);
  printf("calling free\n");
  fflush(stdout);
  free(p);
  printf("free returned OK\n");
  return 0;
}
