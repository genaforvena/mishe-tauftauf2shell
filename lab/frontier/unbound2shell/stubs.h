#ifndef UNBOUND_FRONTIER_STUBS_H
#define UNBOUND_FRONTIER_STUBS_H
/* Minimal collaborators for the verbatim pinned ds_create_dnskey_digest().
 * This harness defines NDEBUG, so the assert() inside
 * sldns_buffer_write_at() is absent: the stub memcpy below is the exact
 * pinned body at sldns/sbuffer.h:433-438 with that assert compiled out.
 * Shipping compile flags are UNKNOWN.
 * No Unbound daemon, resolver, DNS packet, parser or network is involved.
 */
#define NDEBUG 1
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LDNS_MAX_DOMAINLEN 255  /* pinned sldns/rrdef.h:29 */
#define LDNS_MAX_RDFLEN    65535 /* pinned sldns/rrdef.h:249 */
#define MSG_BUFFER_SIZE    65552 /* pinned util/config_file.c:176 */

struct sldns_buffer {
	size_t _position, _limit, _capacity;
	uint8_t *_data;
	unsigned _fixed : 1;
	unsigned _status_err : 1;
};
typedef struct sldns_buffer sldns_buffer;

struct rrset_key { uint8_t *dname; size_t dname_len; };
struct ub_packed_rrset_key { struct rrset_key rk; };
struct module_env { sldns_buffer *scratch_buffer; void *scratch; };

/* Verbatim pinned sldns/sbuffer.c:19-42 (sldns_buffer_new). */
#line 19 "sldns/sbuffer.c"
sldns_buffer* sldns_buffer_new(size_t capacity)
{
	sldns_buffer *buffer = (sldns_buffer*)malloc(sizeof(sldns_buffer));

	if (!buffer) {
		return NULL;
	}

	buffer->_data = (uint8_t *) malloc(capacity);
	if (!buffer->_data) {
		free(buffer);
		return NULL;
	}

	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = capacity;
	buffer->_fixed = 0;
	buffer->_status_err = 0;

	return buffer;
}

#line 189 "sldns/sbuffer.h"
static inline void sldns_buffer_clear(sldns_buffer *buffer)
{
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity;
}

#line 206 "sldns/sbuffer.h"
static inline void sldns_buffer_flip(sldns_buffer *buffer)
{
	buffer->_limit = buffer->_position;
	buffer->_position = 0;
}

#line 270 "sldns/sbuffer.h"
static inline size_t sldns_buffer_limit(sldns_buffer *buffer)
{
	return buffer->_limit;
}

static inline uint8_t *sldns_buffer_at(const sldns_buffer *buffer, size_t at)
{
	return buffer->_data + at;
}

#line 343 "sldns/sbuffer.h"
static inline uint8_t *sldns_buffer_begin(const sldns_buffer *buffer)
{
	return sldns_buffer_at(buffer, 0);
}

#line 411 "sldns/sbuffer.h"
static inline int sldns_buffer_available_at(sldns_buffer *buffer, size_t at,
	size_t count)
{
	return count <= buffer->_capacity - at;
}

#line 423 "sldns/sbuffer.h"
static inline int sldns_buffer_available(sldns_buffer *buffer, size_t count)
{
	return sldns_buffer_available_at(buffer, buffer->_position, count);
}

/* Verbatim pinned sldns/sbuffer.h:433-438 with the NDEBUG-elided assert
 * removed; memcpy destination, source and count are unchanged. */
#line 433 "sldns/sbuffer.h"
static inline void sldns_buffer_write_at(sldns_buffer *buffer, size_t at,
	const void *data, size_t count)
{
	memcpy(buffer->_data + at, data, count);
}

#line 462 "sldns/sbuffer.h"
static inline void sldns_buffer_write(sldns_buffer *buffer, const void *data,
	size_t count)
{
	sldns_buffer_write_at(buffer, buffer->_position, data, count);
	buffer->_position += count;
}

/* Remaining pinned collaborators; bodies are measurement instrumentation. */
void rrset_get_rdata(struct ub_packed_rrset_key *k, size_t idx,
	uint8_t **rdata, size_t *len);
void query_dname_tolower(uint8_t *d);
int ds_get_digest_algo(struct ub_packed_rrset_key *k, size_t idx);
int secalgo_ds_digest(int algo, unsigned char *data, size_t len,
	unsigned char *digest);

#endif
