/* Bounded experiment: name the heap object adjacent to `indexes` in the
 * real GIMP file-gif-load plugin. LD_PRELOAD into the AppImage AppRun;
 * children inherit. Records recent malloc/calloc/realloc call sites and,
 * when the wrapped JIF inflate() returns, prints live allocations near
 * strm->next_out. The plugin source is not modified. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);

/* Direct libc allocator entry points: dlsym(RTLD_NEXT,"malloc") can itself
 * allocate during first resolution and recurse into this wrapper. */
extern void *__libc_malloc (size_t);
extern void *__libc_calloc (size_t, size_t);
extern void *__libc_realloc (void *, size_t);
extern void __libc_free (void *);

static inflate_fn real_inflate;
static __thread int busy;

#define NR 16384
struct rec { void *p; size_t n; void *c0; void *c1; };
static struct rec allocs[NR];
static void *frees[NR];
static unsigned int apos, fpos;

static void
resolve_inflate (void)
{
  if (busy || real_inflate)
    return;
  busy = 1;
  real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");
  busy = 0;
}

static void
add_alloc (void *p, size_t n)
{
  unsigned int i = apos++ & (NR - 1);
  if (!p)
    return;
  allocs[i].p = p;
  allocs[i].n = n;
  allocs[i].c0 = __builtin_return_address (1);
  allocs[i].c1 = __builtin_return_address (2);
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
malloc (size_t n)
{
  void *p = __libc_malloc (n);
  if (!busy)
    {
      busy = 1;
      add_alloc (p, n);
      busy = 0;
    }
  return p;
}

void *
calloc (size_t a, size_t b)
{
  void *p = __libc_calloc (a, b);
  if (!busy)
    {
      busy = 1;
      add_alloc (p, a * b);
      busy = 0;
    }
  return p;
}

void *
realloc (void *old, size_t n)
{
  void *p = __libc_realloc (old, n);
  if (!busy)
    {
      busy = 1;
      if (old)
        add_free (old);
      add_alloc (p, n);
      busy = 0;
    }
  return p;
}

void
free (void *p)
{
  if (!busy)
    {
      busy = 1;
      add_free (p);
      busy = 0;
    }
  __libc_free (p);
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
    resolve_inflate ();
  out = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  ret = real_inflate ? real_inflate (strm, flush) : -1;

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
