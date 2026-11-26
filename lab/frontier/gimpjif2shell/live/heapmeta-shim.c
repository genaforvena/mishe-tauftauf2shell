/* Real-plugin observation shim: only inflate() is interposed. In addition
 * to the post-WRITE byte dump, record the caller via dladdr and walk the
 * glibc malloc chunk headers following `indexes` (bounded; no malloc
 * interposition — the malloc-family shims crashed the GIMP tree).
 * Temporary shim: compile over live/inflate-shim.so, run, then restore
 * the original from live/inflate-shim.c. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <malloc.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
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

static void
say (const char *fmt, ...)
{
  char b[512];
  va_list ap;
  va_start (ap, fmt);
  int n = vsnprintf (b, sizeof b, fmt, ap);
  va_end (ap);
  if (n > 0)
    write (2, b, (size_t) n < sizeof b ? (size_t) n : sizeof b);
}

/* glibc x86-64: user ptr = chunk + 16, size word at user - 8. The next
 * chunk's user area begins at user + (size & ~7). */
static void
dump_chunks (const unsigned char *out)
{
  size_t sz = ((const size_t *) (out - 8))[0] & ~(size_t) 7;
  say ("SHIM_CHUNK0 usable=%zu chunksz=%zu\n",
       malloc_usable_size ((void *) out), sz);

  const unsigned char *c = out + sz;
  for (int i = 1; i <= 8; i++)
    {
      if ((uintptr_t) c % 16 != 0)
        break;
      size_t raw = ((const size_t *) (c - 8))[0];
      size_t ns  = raw & ~(size_t) 7;
      char hdr[128];
      int n = snprintf (hdr, sizeof hdr,
                        "SHIM_CHUNK%d off=%+ld raw_size=%016zx masked=%zu\n",
                        i, (long) (c - out), raw, ns);
      if (n > 0)
        write (2, hdr, (size_t) n < sizeof hdr ? (size_t) n : sizeof hdr);
      emit ("SHIM_CHUNKBYTES=", c, 16);
      if (ns < 32 || ns > (1u << 22) || (ns & 15))
        break;                 /* implausible or chosen-byte-corrupt size */
      c += ns;
    }
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

      void *retaddr = __builtin_return_address (0);
      Dl_info info;
      if (dladdr (retaddr, &info) && info.dli_fname)
        say ("SHIM_CALLER %s+0x%lx\n", info.dli_fname,
             (unsigned long) ((char *) retaddr - (char *) info.dli_fbase));

      dump_chunks (out);
      emit ("SHIM_HEAD=", out, 16);
      emit ("SHIM_EDGE=", out + 252, 96);
      emit ("SHIM_FAR=", out + 360, 32);
    }
  return ret;
}
