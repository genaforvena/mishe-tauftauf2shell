/* Bounded experiment W252: name the heap chunk adjacent to `indexes` in
 * the real GIMP 3.2.8 file-gif-load plugin without the malloc-family
 * interposition that crashed twice in W250.
 *
 * New hypothesis for those crashes: interposing calloc/realloc/free and
 * reading deep return addresses from a __thread-guarded wrapper broke the
 * AppImage's startup. This shim interposes ONLY malloc, uses no TLS, no
 * dlsym and no printf in the allocator path: __libc_malloc + one static
 * ring record with __builtin_return_address(0). inflate() is interposed as
 * in the canonical shim and dumps the pre-write and post-write chunk
 * headers plus ring entries near strm->next_out.
 *
 * Temporary shim: compile over live/inflate-shim.so, run, then rebuild the
 * canonical shim from live/inflate-shim.c. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <malloc.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);
extern void *__libc_malloc (size_t);

#define NR 8192
struct rec { void *p; size_t n; void *caller; };
static struct rec ring[NR];
static unsigned int pos;

void *
malloc (size_t n)
{
  void *p = __libc_malloc (n);
  unsigned int i = __atomic_fetch_add (&pos, 1, __ATOMIC_RELAXED) & (NR - 1);
  ring[i].p = p;
  ring[i].n = n;
  ring[i].caller = __builtin_return_address (0);
  return p;
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

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[288];
  int  off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  write (2, line, off);
}

/* glibc x86-64: user ptr = chunk + 16, size word at user - 8. */
static void
chunks (const char *tag, const unsigned char *out)
{
  const unsigned char *c = out;
  for (int i = 0; i < 6; i++)
    {
      size_t raw = ((const size_t *) (c - 8))[0];
      say ("%s%d off=%+ld raw_size=%016zx\n", tag, i,
           (long) (c - out), raw);
      size_t ns = raw & ~(size_t) 7;
      if (ns < 32 || ns > (1u << 22) || (ns & 15))
        break;                 /* implausible or chosen-byte-corrupt size */
      c += ns;
    }
}

static void
near_allocs (const unsigned char *out)
{
  uintptr_t o = (uintptr_t) out;
  int shown = 0;
  for (unsigned int i = 0; i < NR && shown < 24; i++)
    {
      struct rec r = ring[i];
      if (!r.p)
        continue;
      uintptr_t p = (uintptr_t) r.p;
      if (p < o - 32 || p >= o + 512)
        continue;
      Dl_info ri;
      const char *mod = "?";
      unsigned long off = 0;
      if (dladdr (r.caller, &ri) && ri.dli_fname)
        {
          mod = ri.dli_fname;
          off = (unsigned long) ((char *) r.caller - (char *) ri.dli_fbase);
        }
      say ("SHIM_ALLOC p=%p delta=%+ld n=%zu caller=%p %s+0x%lx\n",
           r.p, (long) (p - o), r.n, r.caller, mod, off);
      shown++;
    }
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  unsigned char *out;
  unsigned long  avail;
  int            ret;
  int            interesting;

  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");

  out   = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  interesting = out && avail > 1000000UL;

  if (interesting)
    {
      say ("SHIM_PRE pid=%d avail_out_before=%lu out=%p\n",
           (int) getpid (), avail, (void *) out);
      chunks ("SHIM_PRECHUNK", out);
      emit ("SHIM_PREUSER1=", out + 272, 24);
      near_allocs (out);
    }

  ret = real_inflate (strm, flush);

  if (interesting)
    {
      char hdr[256];
      int n = snprintf (hdr, sizeof hdr,
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

      chunks ("SHIM_POSTCHUNK", out);
      emit ("SHIM_HEAD=", out, 16);
      emit ("SHIM_EDGE=", out + 252, 96);
      emit ("SHIM_FAR=", out + 360, 32);
    }
  return ret;
}
