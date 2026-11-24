/* Drive the REAL c-icap libicapapi functions on a REAL ci_request_t.
   No pinned copies, no stand-in struct: ci_request_alloc/process_encapsulated/
   ci_request_destroy are exported symbols from the ASan-built library.
   Build and run recipe: realbuild/README.md. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-icap.h>
#include <request.h>
#include <header.h>
#include <net_io.h>

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "attack";
    const char *val = (argc > 2) ? argv[2] : "90";
    char hdr[512];
    if (!strcmp(mode, "safe"))
        snprintf(hdr, sizeof(hdr),
                 "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3");
    else
        snprintf(hdr, sizeof(hdr),
                 "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3, "
                 "req-body=4, req-body=%s", val);
    ci_connection_t *conn = (ci_connection_t *)calloc(1, sizeof(ci_connection_t));
    if (!conn) return 2;
    ci_request_t *req = ci_request_alloc(conn);
    if (!req) { free(conn); return 2; }
    int r = process_encapsulated(req, hdr);
    printf("parse=%d entities5=%p trash0=%p alias=%d trash0_type=%d trash0_start=%d\n",
           r, (void *)req->entities[5], (void *)req->trash_entities[0],
           (req->entities[5] && req->entities[5] == req->trash_entities[0]),
           req->trash_entities[0] ? req->trash_entities[0]->type : -1,
           req->trash_entities[0] ? req->trash_entities[0]->start : -1);
    fflush(stdout);
    ci_request_destroy(req);
    printf("destroy done\n");
    return 0;
}
