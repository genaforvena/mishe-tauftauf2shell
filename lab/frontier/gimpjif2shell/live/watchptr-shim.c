/* Bounded experiment W290: does the real GIMP 3.2.8 JIF loader dereference
 * the adjacent live pointer overwritten by the zlib output?
 *
 * No allocator interposition. The published-ptr JIF places the chosen
 * unmapped word 0x00007f0000414243 at out+280, where W252 found a live
 * pointer into a 96-byte GLib/GObject object. This shim only wraps
 * inflate(), logs the word before/after the real zlib call, and installs a
 * SIGSEGV handler for that call. A fault at the chosen address would be a
 * real-plugin dereference of attacker-chosen data; no fault is a negative
 * result, not a pass.
 *
 * Temporary shim: compile to /tmp/watchptr.so, preload via the extracted
 * AppRun, then restore the canonical preload line. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);

static const uintptr_t CHOSEN = 0x00007F0000414243UL;
static unsigned char *watched;
static z_streamp watched_strm;

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
  uintptr_t addr = (uintptr_t) si->si_addr;
  char line[256];
  int n = snprintf (line, sizeof line,
                    "WATCH_FAULT sig=%d code=%d si_addr=%p chosen=%d "
                    "delta_from_chosen=%ld rip=%p total_out=%lu\n",
                    sig, si->si_code, si->si_addr, addr == CHOSEN,
                    (long) (addr - CHOSEN),
                    (void *) ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RIP],
                    watched_strm
                    ? (unsigned long) watched_strm->total_out : 0UL);
  if (n > 0)
    write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
  if (watched)
    emit ("WATCH_WORD_AT_FAULT=", watched + 272, 24);
  _exit (98);
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");

  int interesting = strm && strm->avail_out > 1000000UL;
  if (interesting)
    {
      struct sigaction sa;
      memset (&sa, 0, sizeof sa);
      sa.sa_sigaction = fault;
      sa.sa_flags = SA_SIGINFO;
      sigemptyset (&sa.sa_mask);
      sigaction (SIGSEGV, &sa, NULL);

      watched = (unsigned char *) strm->next_out;
      watched_strm = strm;
      char line[256];
      int n = snprintf (line, sizeof line,
                        "WATCH_ARMED pid=%d out=%p avail_out=%lu "
                        "chosen=%p inflate=%p\n",
                        (int) getpid (), (void *) watched,
                        (unsigned long) strm->avail_out,
                        (void *) CHOSEN, (void *) real_inflate);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
      emit ("WATCH_WORD_BEFORE=", watched + 272, 24);

      Dl_info info;
      if (dladdr ((void *) real_inflate, &info) && info.dli_fname)
        {
          char path[256];
          int m = snprintf (path, sizeof path,
                            "WATCH_MODULE=%s base=%p sym=%s\n",
                            info.dli_fname, info.dli_fbase,
                            info.dli_sname ? info.dli_sname : "?");
          if (m > 0)
            write (2, path, (size_t) m < sizeof path ? (size_t) m : sizeof path);
        }
    }

  int ret = real_inflate (strm, flush);

  if (interesting)
    {
      char line[256];
      int n = snprintf (line, sizeof line,
                        "WATCH_SURVIVED total_out=%lu ret=%d\n",
                        (unsigned long) strm->total_out, ret);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
      emit ("WATCH_WORD_AFTER=", watched + 272, 24);
    }
  return ret;
}
