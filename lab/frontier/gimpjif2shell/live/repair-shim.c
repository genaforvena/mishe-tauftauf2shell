/* Bounded experiment W301: do live objects adjacent to `indexes` use the
 * attacker-chosen pointer written at out+280?  W252 measured a live 0x20
 * chunk at out+256 (user out+272) holding [1, pointer], and W290 put the
 * unmapped chosen word 0x00007f0000414243 at out+280 with the JIF.  That
 * run also corrupted the adjacent chunk size (out+264 = 0x4d...), so the
 * loader never got past g_free(indexes).  This shim repairs only that
 * collateral size and the object's first word after the real inflate(),
 * leaving the file-chosen pointer at out+280 untouched.  No plugin source
 * is modified; the pointer remains file-chosen, the repair is instrumented.
 *
 * Temporary shim: compile into this directory, preload via the extracted
 * AppRun, then restore its canonical preload line. */
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
                    "REPAIR_FAULT sig=%d code=%d si_addr=%p chosen=%d "
                    "delta_from_chosen=%ld rip=%p total_out=%lu\n",
                    sig, si->si_code, si->si_addr, addr == CHOSEN,
                    (long) (addr - CHOSEN),
                    (void *) ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RIP],
                    watched_strm
                    ? (unsigned long) watched_strm->total_out : 0UL);
  if (n > 0)
    write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
  if (watched)
    {
      emit ("REPAIR_WORD_AT_FAULT=", watched + 264, 24);
      emit ("REPAIR_CHUNK_AT_FAULT=", watched + 256, 16);
    }
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
                        "REPAIR_ARMED pid=%d out=%p avail_out=%lu chosen=%p\n",
                        (int) getpid (), (void *) watched,
                        (unsigned long) strm->avail_out, (void *) CHOSEN);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
      emit ("REPAIR_WORD_BEFORE=", watched + 264, 24);
    }

  int ret = real_inflate (strm, flush);

  if (interesting && watched && strm->total_out >= 448)
    {
      /* Restore the two words destroyed as collateral: the next chunk's
       * size (0x21, as measured pre-write by W252) and the live object's
       * first word (1).  The file-chosen pointer at out+280 is preserved. */
      uint64_t sz = 0x21, one = 1;
      memcpy (watched + 264, &sz, sizeof sz);
      memcpy (watched + 272, &one, sizeof one);
      char line[256];
      int n = snprintf (line, sizeof line,
                        "REPAIR_PATCHED pid=%d total_out=%lu out=%p\n",
                        (int) getpid (), (unsigned long) strm->total_out,
                        (void *) watched);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
      emit ("REPAIR_WORD_AFTER=", watched + 264, 24);
    }
  else if (interesting)
    {
      char line[256];
      int n = snprintf (line, sizeof line,
                        "REPAIR_SKIPPED total_out=%lu\n",
                        (unsigned long) strm->total_out);
      if (n > 0)
        write (2, line, (size_t) n < sizeof line ? (size_t) n : sizeof line);
    }
  return ret;
}
