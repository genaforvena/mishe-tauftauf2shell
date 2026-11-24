# frontier-codebasememory2shell — CVE-2026-114494 (codebase-memory-mcp Cypher projection)

**Verdict: rung 4 demonstrated by direct calls into the real, pinned Cypher
engine — attacker-chosen bytes land at attacker-chosen offsets past a 32-element
stack array, and a default plain build aborts with stack smashing. Recommend
admission to a dedicated target mind.** The missing lane is the MCP tool / wire
path: this lab calls `cbm_cypher_execute()` directly, so remote reachability and
rung 5 remain UNKNOWN. The advisory itself scores AV:L/PR:L, so a remote path
is not claimed by the CNA either.

## 1. Ground truth (claim sources, read-only provisioning)

- CVE-2026-114494, CNA GitHub, Inc., published/updated 2026-11-20, title
  "codebase-memory-mcp: Stack out-of-bounds write in query_graph via a RETURN
  or WITH clause with more than 32 items". HIGH 7.8
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`; CWE-121 and CWE-787.
  DeusData `codebase-memory-mcp` affected `< 0.9.0`, fixed `0.9.0`.
  <https://www.cve.org/CVERecord?id=CVE-2026-114494>
- GHSA-vpgh-g3jg-ggx9 (published 2026-11-17 on the advisory page, mirrored
  2026-11-21): "Before 0.9.0 the Cypher parser did not bound the number of
  projection items in a `RETURN` or `WITH` clause, while the projection
  executors indexed fixed 32-element stack arrays with a loop bounded by the
  parsed count. A query with more than 32 projection items written through the
  `query_graph` tool wrote past those arrays. A related path read uninitialized
  stack slots when building result columns, even when no node matched."
  Reachable by "any caller of `query_graph`, including an agent whose queries
  are influenced by untrusted content"; "reliable crash, and potentially worse
  depending on layout". Fixed in 0.9.0; v0.12.1 recommended.
  <https://github.com/DeusData/codebase-memory-mcp/security/advisories/GHSA-vpgh-g3jg-ggx9>
- Fix commit `e69e0844dbc1c737ebd3d17e97007d0f5cf16beb` (parent
  `5554f8a46abf`), "cypher: bound RETURN/WITH projection width to the result
  column limit", 2 files, +60/-4, authored 2026-07-07. It adds a parse-time
  bound and a fork-isolated 48-column RETURN regression test.
  <https://github.com/DeusData/codebase-memory-mcp/commit/e69e0844dbc1c737ebd3d17e97007d0f5cf16beb>
- Pins: vulnerable `5554f8a46abf` and fixed `e69e0844dbc1` tarballs fetched by
  provisioning into `lab/frontier/codebasememory2shell/pins/`; hashes and the
  two `src/cypher/cypher.c` blob hashes in `PINS.sha256`. No external system
  was probed. All advisory prose above is a **claim**; measurements follow.

## 2. Source-bound mechanism (pinned vulnerable bytes)

`parse_return_or_with()` in the parent commit grows `r->items` with no width
check (pinned `cypher.c:1635-1653`). Two downstream users trust `ret->count`:

1. `build_return_columns()` declares `const char *col_names[CBM_SZ_32]`
   (`cypher.c:4076`), clamps its own fill loop to 32 (`:4096`), but then calls
   `rb_set_columns(rb, col_names, ret->count)` (`:4095`). `rb_set_columns()`
   reads `col_names[i]` for `i < count` (`cypher.c:2568`) — an out-of-bounds
   **read** at `col_names[32]` for a 33-item RETURN.
2. `execute_return_simple()` declares
   `const char *vals[CBM_SZ_32]; char func_bufs[CBM_SZ_32][CBM_SZ_512];`
   (`cypher.c:4112-4113`) and loops `for (ci = 0; ci < ret->count; ci++)`
   (`:4114`), assigning `vals[ci]` and calling
   `project_item(..., func_bufs[ci], sizeof(func_bufs[ci]))` (`:4115-4116`).
   `project_item()` copies the selected property value with
   `memcpy(func_buf, raw, len)` (`cypher.c:3374-3381`). So item 32 writes the
   pointer at `vals[32]` and the 70-byte property value at `func_bufs[32]`,
   i.e. 16384 bytes past the last in-bounds column buffer. Item index controls
   the offset; the graph property controls the bytes.

The fix adds exactly the missing invariant at `cypher.c:1655-1663`:

```c
if (r->count > CBM_SZ_32) {
    free(r->items);
    free(r);
    return CBM_NOT_FOUND;
}
```

The related uninitialized-column-read path named in the advisory was not
isolated or exercised here; it is out of scope for this brief.

## 3. Laboratory reproduction

All work is under `lab/frontier/codebasememory2shell/`. `harness.c` is the only
lab-authored C file: it opens the project's real in-memory store, inserts one
`Function` node with a 70-byte chosen `name`
(`MISHE-OO0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`),
builds `MATCH (f:Function) RETURN f.name, ...` with N items, and calls the
unmodified `cbm_cypher_execute()`. `build.sh` compiles the pinned
`src/cypher/cypher.c`, `src/store/store.c`, 20 foundation modules and vendored
sqlite3/yyjson/mimalloc/tree-sitter objects with the project's test flags.
`run-all.sh` produces `evidence/evidence.log` (sha256
`f8c81a5ccd51fa350c78923ff944f881255c9b94ddf06a448a574268a8b67a6d`).

| Lane | N / kind | Observed |
| --- | --- | --- |
| gcc ASan, vulnerable | 16, 31, 32 RETURN | exit 0, query rc 0, clean |
| gcc ASan, vulnerable | 33, 48, 64 RETURN | `AddressSanitizer: stack-buffer-overflow`, `READ of size 8` at `cypher.c:2568` in `rb_set_columns` ← `build_return_columns:4095` ← `execute_return_clause:4382` ← `execute_single:4442` ← `cbm_cypher_execute:4473`; frame `execute_single:4398`, `col_names` [992,1248), access at offset 1248 |
| gcc ASan recover mode (`halt_on_error=0`), vulnerable | 48 RETURN | reaches the WRITE: `WRITE of size 70` via `memcpy` at `project_item cypher.c:3379` ← `execute_return_simple:4116` ← `execute_return_clause:4386`; frame `execute_single:4398`, `func_bufs` [35456,51840), write at offset 51840 — exactly 16384 bytes past the 32-buffer array, with the chosen 70 bytes |
| gcc ASan, fixed commit | 33, 48 RETURN | query rc -1, "failed to parse query", no ASan error (leak checking disabled: the rejected-parse path has an independent leak, preserved as a separate observation) |
| gcc plain, vulnerable | 32, 33 RETURN | exit 0 |
| gcc plain, vulnerable | 48 RETURN | exit 134, `*** stack smashing detected ***` |
| gdb, plain vulnerable | 48 RETURN | breakpoint `cypher.c:4118`: `&func_bufs[0]=0x7fffffff53b0`, `&func_bufs[32]=0x7fffffff93b0` (delta 0x4000); bytes at `[32]` are `4d 49 53 48 45 2d 4f 4f` ("MISHE-OO") then `30 31 ... 7a`; `vals[32]` and `vals[47]` both point at the copied chosen string |
| gcc ASan, vulnerable and fixed | 16..64 WITH | vulnerable stays clean at 48/64 (WITH executor did not overflow in this harness); fixed rejects >32 with query rc -1. WITH-side overflow UNREPRODUCED here. |

Stack addresses in the gdb row are ASLR-dependent; the 0x4000 delta and the
byte sequence are not. Raw traces are in `evidence/*.out`; the matrix, hashes
and the recover-mode WRITE stack are in `evidence/evidence.log`.

## 4. Honest ceiling and feasibility

**Reached:** rungs 1-4. Rung 3 is ASan-confirmed on the pinned source with both
an OOB read and an OOB WRITE of attacker-chosen bytes; rung 4 is the gdb
byte-level observation of chosen bytes at offsets selected by the projection
item index, plus a default-build stack-smashing abort. This is stronger than a
fixed-byte or fixed-offset write.

**Not reached:** the `query_graph` MCP tool layer and any JSON-RPC/HTTP/stdio
wire path; no remote request, no agent-influenced query, no grooming into a
live object, no saved-RIP/pointer/IP control, no command execution, no ASLR
bypass, no witness replay and no rung 5. The advisory's CVSS attack vector is
LOCAL with PR:L, consistent with the missing remote lane. Whether a malicious
tool argument can carry a >32-item clause to this executor in a deployed MCP
server is UNKNOWN.

**Cheapest next experiment that could move it up:** build the pinned vulnerable
tree's real `codebase-memory-mcp` binary with ASan, start it on loopback only,
and send one `query_graph` tool call whose query has 48 RETURN items, with the
32-item and fixed-release calls as controls. If the ASan WRITE reproduces
through that path, the target gains a real tool-argument trigger; that is a
target mind's lane, not a reason for this brief to claim rung 5.

**Disposition:** stage for admission with a dedicated two-pane window. Operator
owns final admission.

## 5. Preservation / negative results

- The WITH projection lane did not reproduce an overflow on the vulnerable
  build even at 64 items; the parser bound applies to both clauses but only the
  RETURN executor overflowed in this harness. Kept as a negative.
- Plain build at 33 items exits 0: one OOB slot lands in padding. The 48-item
  case is the plain-build crash. No retry into existence of a 33-item crash.
- LeakSanitizer flags a leak in the fixed tree's rejected-parse path
  (47 `heap_strdup` allocations from `parse_return_item`). It is independent of
  the stack write and is not claimed as part of this CVE.
- No external probe, no off-loopback target, no exploit framework, no witness claim. Clean-archive replay at commit `a073540` rebuilt all four binaries and reproduced all 24 matrix rows and the same gdb chosen bytes (`lab/frontier/codebasememory2shell/REPLAY.md`); the log hash differs only in ASLR/PID tokens.
