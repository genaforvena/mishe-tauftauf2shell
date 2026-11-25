/* Stand-in declarations for the verbatim pinned ms_kill() body.
 * Constants are from upstream include/ircd_defs.h at parent 7bc7e34:
 *   KILLLEN 200 (:71), BUFSIZE 512 (:78). LOCAL_COPY is strdupa() per
 *   include/stdinc.h:52; here it is an exact-length heap copy so the harness
 *   never overflows before the pinned sprintf(). Every macro/function below
 *   is a stand-in, not upstream code, and is listed here to keep the seam
 *   honest. */
#ifndef MISHE_PRELUDE_H
#define MISHE_PRELUDE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 512
#define KILLLEN 200
#define KILLCHASETIMELIMIT 90
#define ERR_NOSUCHNICK 401
#define ERR_CANTKILLSERVER 483
#define SNO_GENERAL 0
#define SNO_SKILL 0
#define L_ALL 0
#define L_KILL 0

#define EmptyString(x) ((x) == NULL || *(x) == '\0')
#define IsDigit(c) ((c) >= '0' && (c) <= '9')
#define IsServer(c) (((c)->flags & 1u) != 0)
#define IsMe(c) (((c)->flags & 2u) != 0)
#define MyConnect(c) (((c)->flags & 4u) != 0)
#define IsOper(c) (((c)->flags & 8u) != 0)
#define IsService(c) (((c)->flags & 16u) != 0)
#define FLAGS_KILLED 32u

struct Client {
	char name[64];
	char username[64];
	char host[64];
	char orighost[64];
	struct Client *servptr;
	unsigned int flags;
};
struct MsgBuf { int unused; };

static char *mishe_local_copy(const char *s)
{
	char *p = strdup(s);
	if (p == NULL) exit(3);
	return p;
}
#define LOCAL_COPY(s) mishe_local_copy(s)
static struct Client mishe_victim;
static const char *form_str(int n) { (void)n; return "*"; }
static const char *get_oper_name(struct Client *c) { (void)c; return "oper"; }
static struct Client *find_person(const char *n) { (void)n; return &mishe_victim; }
static struct Client *whowas_get_history(const char *n, long t) { (void)n; (void)t; return NULL; }
static void sendto_one_numeric() {}
static void sendto_one_notice() {}
static void sendto_one() {}
static void sendto_realops_snomask() {}
static void ilog() {}
static void relay_kill() {}
static void exit_client() {}

/* Mirrors pinned m_kill.vuln.c:44 `static char buf[BUFSIZE];` */
static char buf[BUFSIZE];

static struct Client mishe_victim;
static struct Client mishe_source;
static struct Client mishe_server;


#endif
