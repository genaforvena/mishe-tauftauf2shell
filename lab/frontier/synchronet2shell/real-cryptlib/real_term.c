/*
 * Real cryptlib probe for CVE-2026-133646 (no stubbed getter).
 *
 * Creates an SSH client session, sets the pty-req terminal attribute, then
 * performs the exact one-call form pinned at answer.cpp:543-549:
 *   l = 0; cryptGetAttributeString(ssh_session, ...TERMINAL, terminal, &l);
 *   terminal[sizeof(terminal)-1] = 0;
 * The destination is the pinned sbbs.h:702-705 field layout. The copy is
 * performed by the vendored, patched cryptlib built from parent 42f586d7.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include "cryptlib.h"

#define TELNET_TERM_MAXLEN 40
#define TERM_COLS_MAX 999

struct session_t {
	char terminal[TELNET_TERM_MAXLEN + 1];
	uint32_t line_delay;
	uint32_t console;
	char wordwrap[TERM_COLS_MAX + 1];
};

static void dump_range(const char *tag, const unsigned char *p, int from, int to)
{
	int i;
	printf("%s [%d..%d]:", tag, from, to - 1);
	for (i = from; i < to; i++)
		printf(" %02x", p[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	int term_len = (argc > 1) ? atoi(argv[1]) : 64;
	CRYPT_SESSION sess = CRYPT_UNUSED;
	unsigned char term[128];
	struct session_t s;
	int status, len = 0;
	int i;

	if (term_len < 1 || term_len > (int)sizeof(term)) {
		fprintf(stderr, "term_len out of range\n");
		return 2;
	}
	for (i = 0; i < term_len; i++)
		term[i] = (unsigned char)('A' + (i % 26));
	term[term_len] = 0;

	status = cryptInit();
	printf("cryptInit=%d\n", status);
	status = cryptCreateSession(&sess, CRYPT_UNUSED, CRYPT_SESSION_SSH);
	printf("cryptCreateSession=%d handle=%d\n", status, (int)sess);
	if (cryptStatusError(status))
		return 3;

	status = cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, CRYPT_UNUSED);
	printf("create channel status=%d\n", status);

	status = cryptSetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, term, term_len);
	printf("set TERM len=%d status=%d\n", term_len, status);
	if (cryptStatusError(status))
		return 4;

	status = cryptGetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, NULL, &len);
	printf("query status=%d len=%d\n", status, len);
	if (cryptStatusError(status))
		return 5;

	memset(&s, 0, sizeof(s));
	len = 0;
	status = cryptGetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, s.terminal, &len);
	s.terminal[sizeof(s.terminal) - 1] = 0;
	printf("copy status=%d len=%d\n", status, len);
	printf("offsets: terminal=%zu line_delay=%zu console=%zu wordwrap=%zu\n",
		offsetof(struct session_t, terminal),
		offsetof(struct session_t, line_delay),
		offsetof(struct session_t, console),
		offsetof(struct session_t, wordwrap));
	printf("line_delay=0x%08x console=0x%08x wordwrap[0..7]='%.8s'\n",
		s.line_delay, s.console, s.wordwrap);
	dump_range("tail", (const unsigned char *)&s, 40, 64);
	cryptDestroySession(sess);
	cryptEnd();
	return 0;
}
