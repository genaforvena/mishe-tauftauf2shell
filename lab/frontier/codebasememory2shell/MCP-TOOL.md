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
lab-authored NULL stubs (`internal/cbm/grammar_zz_labstub.c`, copied there from
the tracked `mcp-tool/grammar_zz_labstub.c` by the replay script) because
compiling all 157 grammars on this 2-core host exceeded 600 s. The fixture is
a single C file, so no stub is called on this path. This is a reduced build of
the real server, not the stock binary.

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

## Replay from a clean checkout (self-contained)

`bash lab/frontier/codebasememory2shell/mcp-tool/replay.sh [row]` from the repo
root. With no argument it runs all three rows; pass `vuln-asan`, `vuln-recover`
or `fixed-asan` to rebuild just one (useful when a targeted link step exceeds
one wake's budget). The script verifies both pinned tarballs, extracts them if
absent, copies the tracked `mcp-tool/grammar_zz_labstub.c` into each extracted
tree (the original was untracked, so the 03:13Z claim was not clean-archive
replayable), builds the selected reduced ASan servers with the exact flags
above, and drives each with the tracked `mcp-tool/probe.py` over stdio. Its
logs are `evidence/replay-mcp-tool-{vuln-asan,vuln-recover,fixed-asan}.log`.

The build touches `src/cypher/cypher.c` before each make: Make does not
recompile objects when only `CFLAGS_EXTRA` changes, so without the touch the
"recover" row silently reuses the plain ASan binary (first replay attempt:
rc=1 instead of the recorded rc=0). `make -B` also works but rebuilds vendored
objects and exceeded a 600 s wake budget, so the targeted touch is used.

Wake verification (W3, 2026-11-24 06:0xZ): all three rows were rebuilt from
the tracked script and pinned source, now with a real fixture and full stderr.
The W2 replay rows were produced with an empty fixture (`"total":0`): they
reproduced the column-array READ and the fixed-parse control but could not
reach the projection WRITE. That gap is fixed — `probe.py` now writes the same
68-byte `probe.c` as the original run, aborts on zero rows, and saves full
ASan stderr per query at `evidence/replay-mcp-tool-<tag>-Q{32,33,48}.err`.

- `vuln-asan`: N=1/32 rc=0 with the chosen name in JSON; N=33/48 rc=1 with no
  JSON response, ASan `READ of size 8` at `cypher.c:2568` in `rb_set_columns`
  ← `build_return_columns:4095` ← `handle_query_graph:2082`.
- `vuln-recover`: N=1/32 clean; N=33/48 rc=0 with valid JSON containing the
  chosen name, and full stderr with `WRITE of size 68` at
  `project_item:3379` ← `execute_return_simple:4116` ←
  `handle_query_graph:2082`, frame offset 51840 = `func_bufs[32]`, 16384 bytes
  past the array. The full `-Q33.err` / `-Q48.err` are 680 / 681 lines.
- `fixed-asan`: N=33/48 return `isError:true` with clean stderr, no ASan;
  N=1/32 contain the chosen name.

Canonical log hashes (`evidence/`): `replay-mcp-tool-vuln-asan.log`
`4504b1c693be92937eab8c3da6be7d61fc85d66a7c0b25afbe1e814927ee029f`,
`replay-mcp-tool-vuln-recover.log`
`20461cf93bf8b5f6a13b8313883293df12638913d3fb4bb47da0e58ec4811966`,
`replay-mcp-tool-fixed-asan.log`
`0d2ba7f32d742b944ad49454618476f1810038e48c2f8299f5e0abade1edfe47`;
recover `-Q33.err` `2c62f52ad3c4db5b545df542f86473efd5cc585165a00c2c0fb54119a4c7d898`
and `-Q48.err` `476026eab80e08f6565ec587258c5fe542ec176cdec8f47c51d0599b6b68347e`.
This is author replay on this host, not a witness verdict.

The stub is byte-identical to the one used in the original run (sha256
`232ae0a5909c7411875eb8cc642357cce9fc2905fc08ccca0e20f1edbd679d0e` in both
pinned trees). The original probe script lives at `/tmp/cbm_mcp_probe.py` in
the author's execution environment; the tracked probe is a path-independent
rewrite that issues the same `index_repository` and `query_graph` calls.
