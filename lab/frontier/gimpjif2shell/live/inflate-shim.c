/* Observe the real GIMP file-gif-load plugin's JIF inflate() call without
 * modifying the plugin. LD_PRELOAD into the GIMP process; children inherit.
 * Only the wrapped case (avail_out > 1 MiB, small indexes allocation) is
 * dumped. The dump reads heap bytes after the real g_try_malloc region. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[512];
  int  off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  write (2, line, off);
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  unsigned char *out;
  unsigned long  avail;
  int            ret;

  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");

  out   = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  ret   = real_inflate (strm, flush);

  if (out && avail > 1000000UL)
    {
      char hdr[256];
      int  n = snprintf (hdr, sizeof hdr,
                         "SHIM_INFLATE pid=%d avail_out_before=%lu "
                         "total_out=%lu ret=%d out=%p\n",
                         (int) getpid (), avail,
                         strm ? (unsigned long) strm->total_out : 0UL,
                         ret, (void *) out);
      write (2, hdr, n);
      emit ("SHIM_HEAD=", out, 16);
      emit ("SHIM_EDGE=", out + 252, 96);   /* 260-byte region; +4..+88 past */
      emit ("SHIM_FAR=", out + 360, 32);    /* control: beyond written span */
    }
  return ret;
}
