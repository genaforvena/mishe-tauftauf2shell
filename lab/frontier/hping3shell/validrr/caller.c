/* W20 bounded caller: feed a 60-byte IP header (ihl=15) with one Record
 * Route option to the verbatim pinned display_ipopt(). The embedded option
 * length and pointer are supplied on the command line; the 512-byte backing
 * buffer keeps the SOURCE of the memcpy in bounds so an ASan report isolates
 * the DESTINATION overflow in old_rr[MAX_IPOPTLEN]. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hping2.h"

void display_ipopt(char *buf);

int main(int argc, char **argv)
{
	static unsigned char buf[512];
	int optlen, ptr;

	if (argc != 3) {
		fprintf(stderr, "usage: caller OPTLEN PTR\n");
		return 2;
	}
	optlen = atoi(argv[1]);
	ptr = atoi(argv[2]);
	memset(buf, 0x5a, sizeof(buf));
	buf[0] = 0x4f;                 /* version 4, ihl 15 => 60-byte header */
	buf[20] = IPOPT_RR;
	buf[21] = (unsigned char)optlen;
	buf[22] = (unsigned char)ptr;
	display_ipopt((char *)buf);
	printf("RETURNED_CLEAN\n");
	return 0;
}
