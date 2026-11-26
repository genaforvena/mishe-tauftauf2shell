/* Observe what the real file-jif-load plugin does after the wrapped
 * inflate() WRITE. Wraps the shipped inflate() unchanged for the observed
 * call, then timestamps large GLib allocations, GEGL buffer writes and the
 * release of the overflowed region. No plugin source is modified. */
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);
typedef void *(*alloc_fn) (size_t);
typedef void (*free_fn) (void *);
typedef void (*buffer_set_fn) (void *, const void *, int, const void *,
                               const void *, int);

static pid_t watched_pid;
static unsigned char *watched_out;
static struct timespec t0;

static double
ms_now (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (double) (ts.tv_sec - t0.tv_sec) * 1000.0
         + (double) (ts.tv_nsec - t0.tv_nsec) / 1000000.0;
}

static void
note (const char *fmt, ...)
{
  char buf[512];
  va_list ap;
  int n = snprintf (buf, sizeof buf, "TRACE %.3f pid=%d ", ms_now (),
                    (int) getpid ());
  va_start (ap, fmt);
  n += vsnprintf (buf + n, sizeof buf - (size_t) n, fmt, ap);
  va_end (ap);
  if (n > 0)
    {
      if ((size_t) n >= sizeof buf)
        n = (int) sizeof buf - 1;
      buf[n++] = '\n';
      write (2, buf, (size_t) n);
    }
}

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[512];
  int off = snprintf (line, sizeof line, "%s", prefix);
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
  unsigned long avail;
  int ret;

  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");
  out   = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  ret   = real_inflate (strm, flush);
  if (out && avail > 1000000UL)
    {
      clock_gettime (CLOCK_MONOTONIC, &t0);
      watched_pid = getpid ();
      watched_out = out;
      char hdr[256];
      int n = snprintf (hdr, sizeof hdr,
                        "SHIM_INFLATE pid=%d avail_out_before=%lu "
                        "total_out=%lu ret=%d out=%p\n",
                        (int) watched_pid, avail,
                        strm ? (unsigned long) strm->total_out : 0UL,
                        ret, (void *) out);
      write (2, hdr, n);
      emit ("SHIM_HEAD=", out, 16);
      emit ("SHIM_EDGE=", out + 252, 96);
      emit ("SHIM_FAR=", out + 360, 32);
      note ("INFLATE done ret=%d", ret);
    }
  return ret;
}

static void *
large_alloc (const char *kind, size_t size)
{
  static alloc_fn real_malloc, real_try_malloc;
  void *p;

  if (! watched_pid || getpid () != watched_pid)
    goto plain;
  if (size < (32UL << 20))
    goto plain;
  note ("ALLOC %s enter size=%zu", kind, size);
  p = ! strcmp (kind, "try_malloc")
      ? ((real_try_malloc
          = real_try_malloc ? real_try_malloc : (alloc_fn) dlsym (RTLD_NEXT, "g_try_malloc")) (size))
      : ((real_malloc
          = real_malloc ? real_malloc : (alloc_fn) dlsym (RTLD_NEXT, "g_malloc")) (size));
  note ("ALLOC %s done ptr=%p", kind, p);
  return p;
plain:
  if (! strcmp (kind, "try_malloc"))
    {
      if (! real_try_malloc)
        real_try_malloc = (alloc_fn) dlsym (RTLD_NEXT, "g_try_malloc");
      return real_try_malloc (size);
    }
  if (! real_malloc)
    real_malloc = (alloc_fn) dlsym (RTLD_NEXT, "g_malloc");
  return real_malloc (size);
}

void *
g_malloc (size_t size)
{
  return large_alloc ("malloc", size);
}

void *
g_try_malloc (size_t size)
{
  return large_alloc ("try_malloc", size);
}

void
g_free (void *p)
{
  static free_fn real_free;
  if (! real_free)
    real_free = (free_fn) dlsym (RTLD_NEXT, "g_free");
  if (watched_pid && getpid () == watched_pid && p == watched_out)
    note ("FREE indexes=%p", p);
  real_free (p);
}

void
gegl_buffer_set (void *buffer, const void *rect, int level,
                 const void *format, const void *src, int rowstride)
{
  static buffer_set_fn real_set;
  if (! real_set)
    real_set = (buffer_set_fn) dlsym (RTLD_NEXT, "gegl_buffer_set");
  if (watched_pid && getpid () == watched_pid)
    note ("GEGL_SET enter buffer=%p level=%d rowstride=%d", buffer,
          level, rowstride);
  real_set (buffer, rect, level, format, src, rowstride);
  if (watched_pid && getpid () == watched_pid)
    note ("GEGL_SET done");
}
