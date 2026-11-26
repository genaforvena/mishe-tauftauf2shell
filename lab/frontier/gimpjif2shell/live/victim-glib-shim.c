/* Name the live GLib allocation adjacent to `indexes` in the real plugin.
 * Narrower than libc malloc interposition: wraps only g_malloc,
 * g_try_malloc, g_realloc and g_free, the pattern already exercised by
 * trace-shim.c. LD_PRELOAD through the AppImage AppRun; no plugin edit. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);
typedef void *(*alloc_fn) (size_t);
typedef void *(*realloc_fn) (void *, size_t);
typedef void (*free_fn) (void *);

static inflate_fn real_inflate;
static alloc_fn real_malloc, real_try_malloc;
static realloc_fn real_realloc;
static free_fn real_free;

#define NR 8192
struct rec { void *p; size_t n; void *c0; void *c1; };
static struct rec allocs[NR];
static void *frees[NR];
static unsigned int apos, fpos;

static void
add_alloc (void *p, size_t n)
{
  unsigned int i = apos++ & (NR - 1);
  allocs[i].p = p;
  allocs[i].n = n;
  allocs[i].c0 = __builtin_return_address (1);
  allocs[i].c1 = NULL;
}

static void
add_free (void *p)
{
  if (p)
    frees[fpos++ & (NR - 1)] = p;
}

static int
was_freed (void *p)
{
  for (unsigned int i = 0; i < NR; i++)
    if (frees[i] == p)
      return 1;
  return 0;
}

void *
g_malloc (size_t n)
{
  if (!real_malloc)
    real_malloc = (alloc_fn) dlsym (RTLD_NEXT, "g_malloc");
  void *p = real_malloc (n);
  add_alloc (p, n);
  return p;
}

void *
g_try_malloc (size_t n)
{
  if (!real_try_malloc)
    real_try_malloc = (alloc_fn) dlsym (RTLD_NEXT, "g_try_malloc");
  void *p = real_try_malloc (n);
  add_alloc (p, n);
  return p;
}

void *
g_realloc (void *old, size_t n)
{
  if (!real_realloc)
    real_realloc = (realloc_fn) dlsym (RTLD_NEXT, "g_realloc");
  void *p = real_realloc (old, n);
  if (old)
    add_free (old);
  add_alloc (p, n);
  return p;
}

void
g_free (void *p)
{
  if (!real_free)
    real_free = (free_fn) dlsym (RTLD_NEXT, "g_free");
  add_free (p);
  real_free (p);
}

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[512];
  int off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  if (write (2, line, off) < 0) { }
}

static void
dump_maps (void)
{
  char buf[4096];
  FILE *fd = fopen ("/proc/self/maps", "r");
  if (!fd)
    return;
  while (fgets (buf, sizeof buf, fd))
    if (strstr (buf, "file-gif-load") || strstr (buf, "libglib-2.0")
        || strstr (buf, "libc.so"))
      {
        size_t n = strlen (buf);
        if (write (2, "MAP ", 4) < 0 || write (2, buf, n) < 0) { }
      }
  fclose (fd);
}

int
inflate (z_streamp strm, int flush)
{
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
      char hdr[256];
      int n = snprintf (hdr, sizeof hdr,
                        "SHIM_INFLATE pid=%d avail_out_before=%lu "
                        "total_out=%lu ret=%d out=%p\n",
                        (int) getpid (), avail,
                        strm ? (unsigned long) strm->total_out : 0UL,
                        ret, (void *) out);
      if (write (2, hdr, n) < 0) { }
      emit ("SHIM_HEAD=", out, 16);
      emit ("SHIM_EDGE=", out + 252, 96);
      emit ("SHIM_FAR=", out + 360, 32);
      for (unsigned int i = 0; i < NR; i++)
        {
          struct rec r = allocs[i];
          uintptr_t p = (uintptr_t) r.p, o = (uintptr_t) out;
          if (p < o || p >= o + 600 || !r.p || was_freed (r.p))
            continue;
          n = snprintf (hdr, sizeof hdr,
                        "VICTIM p=%p size=%zu delta=%ld c0=%p c1=%p\n",
                        r.p, r.n, (long) (p - o), r.c0, r.c1);
          if (write (2, hdr, n) < 0) { }
        }
      dump_maps ();
    }
  return ret;
}
