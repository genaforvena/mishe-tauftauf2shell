/* Public-API-only driver for the pinned xdgmime magic parser.
 * Builds against the UNMODIFIED xdgmimemagic.c and friends from each pin.
 * Usage: poc MAGIC_FILE [DATA_FILE]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdgmimemagic.h"

int
main (int argc, char **argv)
{
  XdgMimeMagic *magic;

  if (argc < 2)
    return 2;

  magic = _xdg_mime_magic_new ();
  _xdg_mime_magic_read_from_file (magic, argv[1]);
  printf ("extents=%d\n", _xdg_mime_magic_get_buffer_extents (magic));
  _xdg_mime_magic_free (magic);
  return 0;
}
