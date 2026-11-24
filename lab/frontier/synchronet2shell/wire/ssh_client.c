/* Cryptlib SSH client that sets a 64-byte TERM before activating a loopback
 * session. Used only against the local server in this lab. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptlib.h"
#ifndef TRUE
#define TRUE 1
#endif

int main(int argc, char **argv)
{
	int term_len = (argc > 1) ? atoi(argv[1]) : 64;
	CRYPT_SESSION sess = CRYPT_UNUSED;
	unsigned char term[128];
	int status, i, bytes = 0;
	unsigned char buf[4096];

	for (i = 0; i < term_len; i++)
		term[i] = (unsigned char)('A' + (i % 26));
	term[term_len] = 0;
	cryptInit();
	cryptCreateSession(&sess, CRYPT_UNUSED, CRYPT_SESSION_SSH);
	cryptSetAttributeString(sess, CRYPT_SESSINFO_SERVER_NAME, "127.0.0.1", 9);
	cryptSetAttribute(sess, CRYPT_SESSINFO_SERVER_PORT, 22222);
	cryptSetAttributeString(sess, CRYPT_SESSINFO_USERNAME, "lab", 3);
	cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, CRYPT_UNUSED);
	status = cryptSetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, term, term_len);
	printf("client set TERM status=%d len=%d\n", status, term_len);
	status = cryptSetAttribute(sess, CRYPT_SESSINFO_ACTIVE, TRUE);
	printf("client ACTIVE status=%d\n", status);
	status = cryptPopData(sess, buf, sizeof(buf), &bytes);
	printf("client POP status=%d bytes=%d\n", status, bytes);
	cryptDestroySession(sess);
	cryptEnd();
	return 0;
}
