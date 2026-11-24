# Real `query_graph` tool-path probe — 2026-11-24

## What was measured

The vulnerable pin's own MCP server binary was built with ASan and driven over
its real stdio JSON-RPC transport by a local Python client (one `tools/call`
line in, one line out). No direct C harness call is involved in these rows.

Source path, verified in the pinned tree: `query_graph` is entry 3 of `TOOLS[]`
(`src/mcp/mcp.c:376-397`), dispatched without a gate at `:5728-5730`;
`handle_query_graph()` copies the caller's raw `query` string at `:2056` and
calls `cbm_cypher_execute(store, query, project, max_rows, &result)` at `:2082`.
The advertised schema requires `query` and `project` strings; there is no
projection-width validation.

## Build (lab reduction, stated honestly)

`make -j2 -f Makefile.cbm cbm GRAMMAR_SRCS='internal/cbm/grammar_c.c internal/cbm/grammar_zz_labstub.c' CFLAGS_EXTRA='-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-lm -lstdc++ -lpthread -lz -fsanitize=address,undefined'` in `src/codebase-memory-mcp-5554f8a46abf/`.

The unmodified upstream `MCP_SRCS`/`CYPHER_SRCS`/`STORE_SRCS`, `main.c`,
extraction sources and vendored sqlite3/mimalloc/tree-sitter runtime are used.
Only the C grammar is linked: all other `tree_sitter_*` entry points are
lab-authored NULL stubs (`internal/cbm/grammar_zz_labstub.c`, inside the
gitignored extracted tree) because compiling all 157 grammars on this 2-core
host exceeded 600 s. The fixture is a single C file, so no stub is called on
this path. This is a reduced build of the real server, not the stock binary.

## Fixture and calls

- `CBM_CACHE_DIR=/tmp/cbm-mcp-cache-vuln`, `CBM_INDEX_SUPERVISOR=0`,
  `ASAN_OPTIONS=detect_leaks=0`.
- `index_repository` tool call with `repo_path=/tmp/cbm-mcp-fixture`, `mode=fast`,
  `name=probe`: 5 nodes, 4 edges, status `indexed`. The fixture defines a
  `Function` node whose 68-byte `name` is
  `MISHE_OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx`.
- `query_graph` tool calls with `query = "MATCH (f:Function) RETURN " + ", ".join(["f.name"] * N)`,
  `project="probe"`, `max_rows=10`, for N=1, 32, 33, 48.

## Observed (raw log `evidence/mcp-tool-asan-vuln.log`)

- N=1 and N=32: process rc=0, one JSON-RPC result with `total:1`, the chosen
  name in every column, `mcp.request ... tool=query_graph status=ok`.
- N=33 and N=48: process rc=1, no JSON response, ASan
  `stack-buffer-overflow`, `READ of size 8` at `cypher.c:2568` in
  `rb_set_columns`, with the stack
  `build_return_columns:4095` ← `execute_return_clause:4382` ←
  `execute_single:4442` ← `cbm_cypher_execute:4473` ←
  **`handle_query_graph:2082` ← `cbm_mcp_handle_tool:5729` ←
  `cbm_mcp_server_handle:6095` ← `cbm_mcp_server_run:6317` ← `main:802`**.
  Frame `execute_single` reports `col_names` at `[992,1248)` and the access
  at offset 1248.

## Recover-mode WRITE through the tool call (`evidence/mcp-tool-recover-Q*.err`)

Same server rebuilt with `-fsanitize-recover=address`, driven with
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=0`. N=32 stays clean (rc=0, valid
JSON, no ASan). N=33 and N=48 return rc=0 with valid JSON and emit ASan
reports on stderr:

- `READ of size 8` at `cypher.c:2568` in `rb_set_columns`, same stack as above.
- `WRITE of size 68` via `memcpy` at `project_item cypher.c:3379` ←
  `execute_return_simple:4116` ← `execute_return_clause:4386` ←
  `execute_single:4442` ← `cbm_cypher_execute:4473` ←
  **`handle_query_graph:2082` ← `cbm_mcp_handle_tool:5729` ←
  `cbm_mcp_server_handle:6095` ← `cbm_mcp_server_run:6317` ← `main:802`**.
  ASan places the write at offset 51840 in `execute_single`'s frame: exactly
  the first byte past `func_bufs` `[35456,51840)`, i.e. `func_bufs[32]`,
  16384 bytes past the last in-bounds buffer. The 68 bytes are the C fixture's
  function name starting `MISHE_OO…`, selected by projection item index.
- Adjacent observations in the same call: UBSan `index 32 out of bounds for
  type 'char *[32]'` at `cypher.c:4115`, `WRITE of size 1` at `cypher.c:3380`,
  `WRITE of size 8` at `cypher.c:4115`, and OOB reads in `rb_add_row:2581`.

This is rung-3 corruption and rung-4 index-selected placement reached through
the real MCP tool argument path, still local-only. The chosen bytes at the
destination were previously observed byte-for-byte with gdb in the direct-call
harness (`evidence/GDB.txt`); this tool-path rebuild did not repeat gdb.

## Fixed-release control (`evidence/mcp-tool-fixed-asan.log`)

The fixed pin `e69e0844dbc1` was built and driven identically: N=1 and N=32
return valid JSON with chosen name; N=33 and N=48 return
`"failed to parse query"`, `isError:true`, clean stderr (6 log lines, no
ASan report). The parse-time guard at fixed `cypher.c:1655-1663` therefore
holds through the real tool argument path as well.

## Ceiling

Local stdio process only — no HTTP transport, no socket, no remote request, no
agent-influenced query, no pointer control, no command, no witness verdict and
no rung 5. The advisory's AV:L/PR:L vector remains consistent with this reach.
The full server build and the HTTP/UI transport were not exercised.
