/* Observe a large natural JIF inflate in the real GIMP plugin.
 *
 * LD_PRELOAD interposes inflate(), calls the real function, and reports the
 * real allocation size, total_out, and the chosen-byte run past `indexes`.
 * No bytes are patched and no allocation is arranged: the overflowing write
 * is performed entirely by the real zlib inside the unmodified plugin.
 *
 * `first16` and `SPAN_HEAD` read only bytes that real zlib has written when
 * total_out > usable; for a failed call they are a passive heap snapshot.
 * The reader is bounded to 48 bytes at the allocation edge. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <malloc.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[512];
  int off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  if (write (2, line, off) < 0)
    { }
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  unsigned char *out;
  unsigned long avail;
  int ret;

  if (!real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");

  out = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  ret = real_inflate (strm, flush);

  if (out && avail > 1000000UL)
    {
      unsigned long total = strm ? (unsigned long) strm->total_out : 0UL;
      size_t usable = malloc_usable_size (out);
      size_t limit = total > usable ? total - usable : 0;
      size_t run = 0;
      char hdr[512];
      int n;
      n = snprintf (hdr, sizeof hdr,
                    "SPAN pid=%d avail_out_before=%lu total_out=%lu ret=%d "
                    "out=%p usable=%zu\n",
                    (int) getpid (), avail, total, ret, (void *) out, usable);
      if (write (2, hdr, n) < 0)
        { }
      while (run < limit && out[usable + run] == 0x4d)
        run++;
      n = snprintf (hdr, sizeof hdr,
                    "SPAN_RUN usable=%zu chosen_run_after_usable=%zu "
                    "first16=%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                    usable, run,
                    out[usable], out[usable + 1], out[usable + 2],
                    out[usable + 3], out[usable + 4], out[usable + 5],
                    out[usable + 6], out[usable + 7], out[usable + 8],
                    out[usable + 9], out[usable + 10], out[usable + 11],
                    out[usable + 12], out[usable + 13], out[usable + 14],
                    out[usable + 15]);
      if (write (2, hdr, n) < 0)
        { }
      emit ("SPAN_HEAD=", out + (usable > 8 ? usable - 8 : 0), 48);
    }
  return ret;
}
