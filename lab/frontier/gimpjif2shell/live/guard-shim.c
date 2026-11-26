/* Bounded experiment W289: observe the real GIMP 3.2.8 JIF overflow at the
 * exact `indexes` boundary, without modifying the plugin.
 *
 * g_try_malloc(260) is served from a two-page mmap whose second page is
 * PROT_NONE, with user pointer placed 260 bytes before that guard. When
 * inflate() is called with that pointer as next_out, install a SIGSEGV
 * handler and call the real zlib. A write past byte 260 must fault with
 * si_addr == user + 260; the handler logs the chosen tail bytes and RIP
 * before exiting. No address is chosen by the file and nothing is
 * dereferenced on behalf of the attacker: this is a detector, not a
 * control-flow experiment.
 *
 * Temporary shim: compile over live/inflate-shim.so, run through the
 * patched AppRun, then rebuild the canonical shim from inflate-shim.c. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include <zlib.h>
typedef int (*inflate_fn) (z_streamp, int);
typedef void (*gfree_fn) (void *);
extern void *__libc_malloc (size_t);

#define PAGESZ 4096
#define MAXG 16
#define IDX_N 260

struct guard {
  void  *base;
  size_t n;
  unsigned char *p;
  z_streamp strm;
  int armed;
};

static struct guard guards[MAXG];
static unsigned int nguards;
static struct guard *active;

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  static const char hex[] = "0123456789abcdef";
  char buf[128];
  size_t k = 0;
  while (prefix[k] && k + 1 < sizeof buf) { buf[k] = prefix[k]; k++; }
  for (size_t i = 0; i < n && k + 2 < sizeof buf; i++)
    {
      buf[k++] = hex[p[i] >> 4];
      buf[k++] = hex[p[i] & 15];
    }
  buf[k++] = '\n';
  write (2, buf, k);
}

static void
fault (int sig, siginfo_t *si, void *ctx)
{
  struct guard *g = active;
  if (! g)
    _exit (96);

  char line[256];
  int n = snprintf (line, sizeof line,
                    "GUARD_FAULT sig=%d code=%d si_addr=%p delta=+%ld "
                    "rip=%p total_out=%lu\n",
                    sig, si->si_code, si->si_addr,
                    (long) ((unsigned char *) si->si_addr - g->p),
                    (void *) ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RIP],
                    g->strm ? (unsigned long) g->strm->total_out : 0UL);
  if (n > 0)
    write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
  emit ("GUARD_TAIL16=", g->p + IDX_N - 16, 16);
  emit ("GUARD_TAIL4=", g->p + IDX_N - 4, 4);
  _exit (97);
}

void *
g_try_malloc (size_t n)
{
  if (n == IDX_N && nguards < MAXG)
    {
      void *base = mmap (NULL, 2 * PAGESZ, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (base != MAP_FAILED
          && mprotect ((char *) base + PAGESZ, PAGESZ, PROT_NONE) == 0)
        {
          struct guard *g = &guards[nguards++];
          g->base = base;
          g->n = n;
          g->p = (unsigned char *) base + PAGESZ - IDX_N;
          g->strm = NULL;
          g->armed = 0;
          return g->p;
        }
      if (base != MAP_FAILED)
        munmap (base, 2 * PAGESZ);
    }
  return __libc_malloc (n);
}

void
g_free (void *p)
{
  for (unsigned int i = 0; i < nguards; i++)
    if (p == guards[i].p)
      {
        munmap (guards[i].base, 2 * PAGESZ);
        guards[i].base = NULL;
        guards[i].p = NULL;
        return;
      }
  static gfree_fn real_g_free;
  if (! real_g_free)
    real_g_free = (gfree_fn) dlsym (RTLD_NEXT, "g_free");
  if (real_g_free)
    real_g_free (p);
  else
    free (p);
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");

  if (strm && strm->avail_out > 1000000UL)
    for (unsigned int i = 0; i < nguards; i++)
      if (guards[i].p && guards[i].p == (unsigned char *) strm->next_out)
        {
          struct sigaction sa;
          memset (&sa, 0, sizeof sa);
          sa.sa_sigaction = fault;
          sa.sa_flags = SA_SIGINFO;
          sigemptyset (&sa.sa_mask);
          sigaction (SIGSEGV, &sa, NULL);

          guards[i].strm = strm;
          guards[i].armed = 1;
          active = &guards[i];

          char line[256];
          int n = snprintf (line, sizeof line,
                            "GUARD_ARMED pid=%d p=%p guard=%p "
                            "avail_out=%lu inflated_fn=%p\n",
                            (int) getpid (), (void *) guards[i].p,
                            (char *) guards[i].base + PAGESZ,
                            (unsigned long) strm->avail_out,
                            (void *) real_inflate);
          if (n > 0)
            write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
          Dl_info info;
          if (dladdr ((void *) real_inflate, &info) && info.dli_fname)
            {
              char path[256];
              int m = snprintf (path, sizeof path,
                                "GUARD_INFLATE_MODULE=%s base=%p sym=%s\n",
                                info.dli_fname, info.dli_fbase,
                                info.dli_sname ? info.dli_sname : "?");
              if (m > 0)
                write (2, path, (size_t) m < sizeof path ? (size_t) m : sizeof path);
            }
          break;
        }

  int ret = real_inflate (strm, flush);

  if (active && active->armed)
    {
      char line[256];
      int n = snprintf (line, sizeof line,
                        "GUARD_SURVIVED total_out=%lu ret=%d avail_out=%lu\n",
                        (unsigned long) strm->total_out, ret,
                        (unsigned long) strm->avail_out);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
      active->armed = 0;
      active = NULL;
    }
  return ret;
}
