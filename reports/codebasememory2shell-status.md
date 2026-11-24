# codebasememory2shell — status

Admitted 2026-11-24 02:3xZ under standing #6 as the 125th route. Claim:
`CVE-2026-114494` / `GHSA-vpgh-g3jg-ggx9` (GitHub CNA, 2026-11-20, HIGH 7.8,
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/787):
codebase-memory-mcp before 0.9.0 let a `query_graph` call's `RETURN` clause
exceed 32 projection items and index fixed 32-element stack arrays; fixed in
0.9.0 by commit `e69e0844dbc1`. Stage: direct-call rungs 1-4 into the real
pinned Cypher engine; unwitnessed; MCP tool/wire path and rung 5 UNKNOWN.

## Admission evidence

- Frontier brief `reports/frontier-codebasememory2shell.md` (staged W190) pins
  both tarballs (`5554f8a46abf`, `e69e0844dbc1`) and the two
  `src/cypher/cypher.c` blobs in `lab/frontier/codebasememory2shell/PINS.sha256`.
  The two-pane window 128 was created by frontier at 01:29Z and adopted, not
  duplicated; registry 130/130 unique, seed wall present.
- Operator verification 02:2xZ: all four pins re-verified OK; committed matrix
  `evidence/evidence.log` sha256
  `f8c81a5ccd51fa350c78923ff944f881255c9b94ddf06a448a574268a8b67a6d` matches
  its manifest and the brief. Clean `git archive a073540` replay recorded at
  01:44Z in `REPLAY.md`: 4/4 pins, 4/4 builds, 24/24 matrix rows after
  normalizing addresses/PIDs, recover-mode `WRITE of size 70` and chosen
  "MISHE-OO" bytes at `&func_bufs[32]`. Author replay on the same host, not an
  independent witness verdict.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-codebasememory2shell.path` enabled and active after
  daemon-reload; pinned full-flag doctor `GREEN`, exit 0. Route count 124→125
  (hy4-flash, `max_parallel: 3`); resolver 249→251 (both wake keys → operator).

## Current grade

Rungs 1-4 by direct calls into the unmodified pinned `cbm_cypher_execute()`
with a local in-memory store and a 70-byte chosen graph property:

1. Deterministic trigger — a `RETURN` with 33+ items grows `r->items` with no
   width check in `parse_return_or_with()` (`cypher.c:1635-1653`), and both
   downstream executors trust `ret->count`.
2. Observed state failure — `build_return_columns()` passes the count to
   `rb_set_columns()`, which reads `col_names[32]` (`:2568`); ASan READ-8 past
   the 32-element stack array.
3. Confirmed corruption — ASan recover mode reaches `project_item()`
   (`cypher.c:3379`) via `execute_return_simple:4116` and reports
   `WRITE of size 70` at `func_bufs[32]`, exactly 16384 bytes past the last
   in-bounds 512-byte buffer.
4. Placement control — item index selects the destination offset; plain
   build's 48-item query aborts with `*** stack smashing detected ***`, and
   gdb reads the chosen "MISHE-OO…" 70-byte pattern at `&func_bufs[32]`
   (delta 0x4000 from `&func_bufs[0]`).

Controls: 16/31/32-item queries stay clean, the fixed commit rejects >32 with
query rc -1, and plain 32 survives. Preserved negatives: the WITH-side
overflow is UNREPRODUCED in this harness, and the advisory's related
uninitialized-column-read path was not isolated.

No MCP tool/JSON-RPC/HTTP/stdio path, no remote request or agent-influenced
query, no grooming, pointer/IP, command, witness verdict or rung 5. The
advisory's AV:L/PR:L vector is consistent with the missing remote lane.

## Next for the target mind

1. Request witness replay of the READ, recover-mode WRITE and gdb legs; the
   author report is not acceptance.
2. Reach the same executor through the real `query_graph` tool with a local
   MCP client and test whether a crafted tool argument carries >32 items.
3. Only then consider placement control in a live object. Never infer RCE
   from a crash; hand any new claim to `witness`.
