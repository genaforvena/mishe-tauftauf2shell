/* Feed a complete ICAP request through a socketpair into the real c-icap
   libicapapi: exported ci_connection_read_nonblock + ci_headers_unpack +
   process_encapsulated + ci_request_destroy. parse_header() itself is hidden
   in the library, so its post-read header loop is reproduced here in shape.
   Still NOT a running icap-server and NOT a network socket. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <c-icap.h>
#include <request.h>
#include <header.h>
#include <net_io.h>

int main(int argc, char **argv)
{
    const char *v = (argc > 2) ? argv[2] : "90";
    int safe = (argc > 1 && !strcmp(argv[1], "safe"));
    char wire[1024];
    if (safe)
        snprintf(wire, sizeof(wire),
                 "REQMOD icap://127.0.0.1:1344/echo ICAP/1.0\r\n"
                 "Host: 127.0.0.1:1344\r\n"
                 "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3\r\n\r\n");
    else
        snprintf(wire, sizeof(wire),
                 "REQMOD icap://127.0.0.1:1344/echo ICAP/1.0\r\n"
                 "Host: 127.0.0.1:1344\r\n"
                 "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3, "
                 "req-body=4, req-body=%s\r\n\r\n", v);
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) { perror("socketpair"); return 2; }
    ssize_t w = write(fds[1], wire, strlen(wire));
    if (w != (ssize_t)strlen(wire)) { fprintf(stderr, "DBG short write %zd\n", w); return 2; }
    close(fds[1]);
    ci_connection_t *conn = (ci_connection_t *)calloc(1, sizeof(ci_connection_t));
    conn->fd = fds[0];
    ci_request_t *req = ci_request_alloc(conn);
    if (!req) return 2;
    /* Data is already queued on the socketpair; bypass ci_wait_for_data,
       which rejects this synthetic fd in the real library. */
    int wd = 1;
    if (wd < 0) { fprintf(stderr, "DBG wait=%d\n", wd); return 2; }
    int n = ci_connection_read_nonblock(conn, req->request_header->buf,
                                        req->request_header->bufsize);
    req->request_header->bufused = n;
    int st = ci_headers_unpack(req->request_header);
    printf("wire_bytes=%d unpack=%d headers=%d\n", n, st, req->request_header->used);
    if (st == EC_100) {
        for (int i = 1; i < req->request_header->used; i++)
            if (!strncasecmp(req->request_header->headers[i], "Encapsulated:", 13))
                st = process_encapsulated(req, req->request_header->headers[i]);
    }
    printf("parse=%d entities5=%p trash0=%p alias=%d trash0_type=%d trash0_start=%d\n",
           st, (void *)req->entities[5], (void *)req->trash_entities[0],
           (req->entities[5] && req->entities[5] == req->trash_entities[0]),
           req->trash_entities[0] ? req->trash_entities[0]->type : -1,
           req->trash_entities[0] ? req->trash_entities[0]->start : -1);
    fflush(stdout);
    ci_request_destroy(req);
    printf("destroy done\n");
    return 0;
}
