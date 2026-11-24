/*
 * Minimal loopback SSH server using the vendored cryptlib built from pinned
 * parent 42f586d7. It performs the same one-call TERM getter as
 * sbbs_t::answer() into the pinned 41-byte field layout. This is NOT a real
 * Synchronet build; it is a wire-path probe of the real cryptlib attribute.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include "cryptlib.h"

#define PORT 22222
#define TELNET_TERM_MAXLEN 40
#define TERM_COLS_MAX 999

#ifndef TRUE
#define TRUE 1
#endif

struct session_t {
	char terminal[TELNET_TERM_MAXLEN + 1];
	uint32_t line_delay;
	uint32_t console;
	char wordwrap[TERM_COLS_MAX + 1];
};

static CRYPT_SESSION sess;
static struct session_t reader_s;

static void *activate_thread(void *unused)
{
	int status, attempt;
	for (attempt = 0; attempt < 3; attempt++) {
		status = cryptSetAttribute(sess, CRYPT_SESSINFO_ACTIVE, TRUE);
		printf("ACTIVE attempt=%d status=%d\n", attempt, status);
		fflush(stdout);
		if (cryptStatusOK(status))
			break;
		if (status != CRYPT_ENVELOPE_RESOURCE)
			break;
		/* answer.cpp:314-323: read presented credentials, then allow. */
		{
			char user[128];
			int len = 0;
			if (cryptStatusOK(cryptGetAttributeString(sess,
					CRYPT_SESSINFO_USERNAME, user, &len)) && len > 0) {
				user[len < (int)sizeof(user) ? len : sizeof(user) - 1] = 0;
				printf("USERNAME='%s' len=%d\n", user, len);
			}
		}
		status = cryptSetAttribute(sess, CRYPT_SESSINFO_AUTHRESPONSE, TRUE);
		printf("AUTHRESPONSE status=%d\n", status);
		fflush(stdout);
	}
	return NULL;
}

static void *reader_thread(void *unused)
{
	unsigned char buf[4096];
	int bytes = 0, status;
	while (1) {
		status = cryptPopData(sess, buf, sizeof(buf), &bytes);
		printf("POP status=%d bytes=%d\n", status, bytes);
		fflush(stdout);
		{
			int cand, cst;
			for (cand = 0; cand < 16; cand++) {
				char cb[128];
				int cl = (int)sizeof(cb);
				cst = cryptSetAttribute(sess,
					CRYPT_SESSINFO_SSH_CHANNEL, cand);
				if (cryptStatusError(cst))
					continue;
				cst = cryptGetAttributeString(sess,
					CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL,
					cb, &cl);
				printf("READER SWEEP cand=%d term=%d len=%d data=%.64s\n",
					cand, cst, cl, cb);
				fflush(stdout);
			}
		}
		{
			char probe[128];
			int plen = (int)sizeof(probe);
			int pst = cryptGetAttributeString(sess,
				CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, probe, &plen);
			printf("READER TERM status=%d len=%d data=%.64s\n",
				pst, plen, probe);
			fflush(stdout);
			if (cryptStatusOK(pst) && plen > 0) {
				int clen = 0, j;
				memset(&reader_s, 0, sizeof(reader_s));
				pst = cryptGetAttributeString(sess,
					CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL,
					reader_s.terminal, &clen);
				printf("READER COPY status=%d len=%d\n", pst, clen);
				printf("offsets: terminal=%zu line_delay=%zu "
					"console=%zu wordwrap=%zu\n",
					offsetof(struct session_t, terminal),
					offsetof(struct session_t, line_delay),
					offsetof(struct session_t, console),
					offsetof(struct session_t, wordwrap));
				printf("line_delay=0x%08x console=0x%08x "
					"wordwrap[0..7]='%.8s'\n",
					reader_s.line_delay, reader_s.console,
					reader_s.wordwrap);
				printf("tail[40..63]:");
				for (j = 40; j < 64; j++)
					printf(" %02x",
						((unsigned char *)&reader_s)[j]);
				printf("\n");
				fflush(stdout);
				{
					/* Exact pinned answer.cpp:543 one-call form into a
					   41-byte field; ASan gives this buffer a redzone. */
					char redzone[41];
					int rl = 0, rst;
					memset(redzone, 0, sizeof(redzone));
					rst = cryptGetAttributeString(sess,
						CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL,
						redzone, &rl);
					printf("REDZONE COPY status=%d len=%d byte40=%02x\n",
						rst, rl, (unsigned char)redzone[40]);
					fflush(stdout);
				}
				break;
			}
		}
		if (cryptStatusError(status))
			break;
	}
	return NULL;
}

int main(void)
{
	CRYPT_CONTEXT key = CRYPT_UNUSED;
	pthread_t tid, reader;
	struct session_t s;
	int status, len = 0, i;

	cryptInit();
	status = cryptCreateContext(&key, CRYPT_UNUSED, CRYPT_ALGO_RSA);
	printf("create key=%d\n", status);
	status = cryptSetAttributeString(key, CRYPT_CTXINFO_LABEL, "ssh-host", 8);
	printf("key label=%d\n", status);
	status = cryptSetAttribute(key, CRYPT_CTXINFO_KEYSIZE, 256);
	printf("key size=%d\n", status);
	status = cryptGenerateKey(key);
	printf("generate=%d\n", status);
	if (cryptStatusError(status)) return 2;

	status = cryptCreateSession(&sess, CRYPT_UNUSED, CRYPT_SESSION_SSH_SERVER);
	printf("create server=%d\n", status);
	if (cryptStatusError(status)) return 4;
	status = cryptSetAttributeString(sess, CRYPT_SESSINFO_SERVER_NAME,
		"127.0.0.1", 9);
	printf("bind name=%d\n", status);
	status = cryptSetAttribute(sess, CRYPT_SESSINFO_SERVER_PORT, PORT);
	printf("bind port=%d\n", status);
	status = cryptSetAttribute(sess, CRYPT_SESSINFO_PRIVATEKEY, key);
	printf("set key=%d\n", status);
	status = cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_OPTIONS,
		CRYPT_SSHOPTION_NONE_AUTH);
	printf("none-auth option=%d\n", status);
	/* AUTHRESPONSE is set by activate_thread after a resource request,
	 * matching pinned answer.cpp:297-310. */
	status = cryptSetAttribute(sess, CRYPT_OPTION_NET_READTIMEOUT, 5);
	printf("read timeout=%d\n", status);

	pthread_create(&tid, NULL, activate_thread, NULL);
	/* reader_thread is started after channel selection: cryptlib stores
	 * pty-req attributes on the channel current at message-processing time. */
	int cid = -1;
	for (i = 0; i < 100; i++) {
		usleep(100000);
		if (cryptStatusOK(cryptGetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, &cid)))
			break;
	}
	printf("CHANNEL poll i=%d status=%d cid=%d\n", i, status, cid);
	if (cid >= 0) {
		status = cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, cid);
		printf("CHANNEL early select status=%d\n", status);
		pthread_create(&reader, NULL, reader_thread, NULL);
	}
	if (cid >= 0) {
		char ctype[64];
		int ctype_len = 0, waits;
		for (waits = 0; waits < 50; waits++) {
			usleep(100000);
			status = cryptSetAttribute(sess, CRYPT_SESSINFO_SSH_CHANNEL, cid);
			if (cryptStatusError(status))
				continue;
			ctype_len = 0;
			status = cryptGetAttributeString(sess,
				CRYPT_SESSINFO_SSH_CHANNEL_TYPE, ctype, &ctype_len);
			if (cryptStatusOK(status) && ctype_len > 0 && ctype_len < (int)sizeof(ctype)) {
				ctype[ctype_len] = 0;
				printf("CHANNEL TYPE '%s' len=%d\n", ctype, ctype_len);
				fflush(stdout);
				if (strncmp(ctype, "shell", 5) == 0)
					break;
			}
		}
		printf("CHANNEL TYPE final waits=%d status=%d\n", waits, status);
		fflush(stdout);
	}
	int found = -1, found_len = 0, pass, cand;
	for (pass = 0; pass < 20 && found < 0; pass++) {
		usleep(100000);
		for (cand = 0; cand < 8; cand++) {
			int l2 = 0, st2;
			if (cryptStatusError(cryptSetAttribute(sess,
					CRYPT_SESSINFO_SSH_CHANNEL, cand)))
				continue;
			st2 = cryptGetAttributeString(sess,
				CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, NULL, &l2);
			if (cryptStatusOK(st2) && l2 > 0) {
				found = cand;
				found_len = l2;
				break;
			}
		}
	}
	printf("TERM sweep pass=%d cid=%d status=%d len=%d\n",
		pass, found, status, found_len);

	memset(&s, 0, sizeof(s));
	len = 0;
	status = cryptGetAttributeString(sess,
		CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, s.terminal, &len);
	s.terminal[sizeof(s.terminal) - 1] = 0;
	printf("COPY status=%d len=%d\n", status, len);
	printf("offsets: terminal=%zu line_delay=%zu console=%zu wordwrap=%zu\n",
		offsetof(struct session_t, terminal),
		offsetof(struct session_t, line_delay),
		offsetof(struct session_t, console),
		offsetof(struct session_t, wordwrap));
	printf("line_delay=0x%08x console=0x%08x wordwrap[0..7]='%.8s'\n",
		s.line_delay, s.console, s.wordwrap);
	printf("tail[40..63]:");
	for (i = 40; i < 64; i++)
		printf(" %02x", ((unsigned char *)&s)[i]);
	printf("\n");
	fflush(stdout);
	pthread_join(tid, NULL);
	return 0;
}
