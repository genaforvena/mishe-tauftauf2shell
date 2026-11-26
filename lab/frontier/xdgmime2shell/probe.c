/* Internal-state probe: includes the UNMODIFIED pinned xdgmimemagic.c so the
 * driver can report parsed matchlet fields and the bytes written by the
 * byte-swap loop. The consumer path itself is exercised by poc.c.
 */
#include "xdgmimemagic.c"

__attribute__((no_sanitize("address")))
static void
print_bytes (const unsigned char *p, int n)
{
  int i;
  for (i = 0; i < n; i++)
    printf ("%02x ", p[i]);
}

int
main (int argc, char **argv)
{
  XdgMimeMagic *magic;
  XdgMimeMagicMatchlet *m;

  if (argc < 2)
    return 2;
  magic = _xdg_mime_magic_new ();
  _xdg_mime_magic_read_from_file (magic, argv[1]);
  m = magic->match_list ? magic->match_list->matchlet : NULL;
  if (m == NULL)
    {
      printf ("matchlet=none extents=%d\n", magic->max_extent);
      _xdg_mime_magic_free (magic);
      return 3;
    }
  printf ("value_length=%u word_size=%u offset=%d range=%u\n",
	  m->value_length, m->word_size, m->offset, m->range_length);
  printf ("value[0..19] (no_sanitize readback): ");
  print_bytes (m->value, 20);
  printf ("\n");
  if (m->mask != NULL)
    {
      printf ("mask[0..19] (no_sanitize readback): ");
      print_bytes (m->mask, 20);
      printf ("\n");
    }
  _xdg_mime_magic_free (magic);
  return 0;
}
