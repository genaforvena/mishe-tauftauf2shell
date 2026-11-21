#ifndef ACCELPPP_STUB_H
#define ACCELPPP_STUB_H

/* Minimal stand-ins for accel-ppp's list.h and log.h types. The production
 * unpack_msg()/log_unpack_msg() bodies extracted at replay time are compiled
 * verbatim against these definitions. */
#include <stddef.h>
#include <sys/time.h>
#include <string.h>

#define LOG_MAX_SIZE 4096
#define BUF_SIZE (LOG_MAX_SIZE + 64)
#define __export
#define min(a, b) ((a) < (b) ? (a) : (b))

struct list_head {
	struct list_head *next, *prev;
};

#define INIT_LIST_HEAD(head) do { (head)->next = (head); (head)->prev = (head); } while (0)
#define list_add_tail(entry, head) do { \
	(entry)->next = (head); \
	(entry)->prev = (head)->prev; \
	(head)->prev->next = (entry); \
	(head)->prev = (entry); \
} while (0)
#define list_for_each_entry(pos, head, member) \
	for (pos = (typeof(pos))((char *)((head)->next) - offsetof(typeof(*pos), member)); \
	     &pos->member != (head); \
	     pos = (typeof(pos))((char *)pos->member.next - offsetof(typeof(*pos), member)))

struct log_chunk_t {
	struct list_head entry;
	int len;
	char msg[0];
};

struct log_target_t {
	struct list_head entry;
	void *log;
	void *reopen;
};

struct log_msg_t {
	struct list_head entry;
	void *lpd;
	void *tpd;
	struct timeval timestamp;
	int level;
	struct log_chunk_t *hdr;
	struct list_head *chunks;
};

struct tcp_target_t {
	struct log_target_t target;
	struct list_head entry;
	int fd;
	int buf_size;
	int buf_pos;
	char *buf;
};
int log_unpack_msg(struct log_msg_t *msg, char *buf, int size);

#endif
