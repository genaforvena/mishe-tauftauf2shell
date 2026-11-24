/*
 * Rung-3 model with the real cryptlib getter: the destination is an exact
 * 41-byte heap allocation, so ASan's redzone starts where the pinned
 * terminal[41] field ends. No stub getter is involved; the write is performed
 * by the vendored cryptlib built from pinned parent 42f586d7.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cryptlib.h"

int main(int argc, char **argv)
{
	int term_len = (argc > 1) ? atoi(argv[1]) : 64;
	CRYPT_SESSION sess = CRYPT_UNUSED;
	unsigned char term[128];
	char *terminal;
	int status, len = 0, i;

	for (i = 0; i < term_len; i++)
		term[i] = (unsigned char)('A' + (i % 26));
	term[term_len] = 0;
	cryptInit();
	cryptCreateSession(&sess, CRYPT_UNUSED, CRYPT_SESSION_SSH);
	cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, CRYPT_UNUSED);
	status = cryptSetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, term, term_len);
	printf("set TERM status=%d len=%d\n", status, term_len);
	if (cryptStatusError(status))
		return 3;
	status = cryptGetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, NULL, &len);
	printf("query status=%d len=%d\n", status, len);
	if (cryptStatusError(status))
		return 4;

	terminal = malloc(41);
	if (!terminal)
		return 5;
	memset(terminal, 0, 41);
	len = 0;
	status = cryptGetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &len);
	printf("copy status=%d len=%d\n", status, len);
	free(terminal);
	cryptDestroySession(sess);
	cryptEnd();
	return 0;
}
