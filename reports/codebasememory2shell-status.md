# codebasememory2shell — status

Admitted 2026-11-24 02:3xZ under standing #6 as the 125th route. Claim:
`CVE-2026-114494` / `GHSA-vpgh-g3jg-ggx9` (GitHub CNA, 2026-11-20, HIGH 7.8,
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/787):
codebase-memory-mcp before 0.9.0 let a `query_graph` call's `RETURN` clause
exceed 32 projection items and index fixed 32-element stack arrays; fixed in
0.9.0 by commit `e69e0844dbc1`. Stage: rungs 1-4 by direct calls AND by the
real `query_graph` MCP tool argument path on a reduced local ASan server;
no HTTP/remote request, no witness verdict and no rung 5.

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
uninitialized-column-read path was not isolated. W4 adds the causal reason for
the WITH negative: pinned `cypher.c:3585-3591`, `with_add_vbinding_var()`
stores projected items only while `vb->var_count < CYP_BUF_16` (16); both
`execute_with_simple` (`:3673-3679`) and `execute_with_aggregate`
(`:3642-3654`) funnel through it, so WITH items 17+ are silently dropped and
the 48-item harness query returns 1 row / 1 column. The structural bound, not
an unlucky stack layout, explains why only the RETURN executor overflowed.

The MCP tool argument path is no longer UNKNOWN: a real pinned `query_graph`
tool call reaches the same sink (see `lab/frontier/codebasememory2shell/MCP-TOOL.md`
and `evidence/mcp-tool-*.log`), including recover-mode `WRITE of size 68` at
`func_bufs[32]`, 16384 bytes past the last in-bounds buffer, with the chosen
fixture bytes. It remains a local stdio process: no HTTP transport, no remote
request, no agent-influenced query, no grooming, pointer/IP, command, witness
verdict or rung 5. The advisory's AV:L/PR:L vector remains consistent.

W6 closes the tool-path byte-choice gap: a distinct 68-byte identifier in the
indexed fixture (`STEEREDabcdefghij…`) was staged at the OOB destination as
`len = 68` bytes from `raw` on the 33rd `project_item` memcpy under gdb, so
the chosen bytes come from the indexed file, not a harness constant
(`evidence/mcp-tool-steer-gdb.txt`, `MCP-TOOL.md` § "File-steering").

The tool-path claim is clean-archive replayable and fully replayed by the
author: `mcp-tool/replay.sh` tracks its previously untracked lab stub
(`grammar_zz_labstub.c`, sha256
`232ae0a5909c7411875eb8cc642357cce9fc2905fc08ccca0e20f1edbd679d0e`, identical
to both pinned-tree copies), a path-independent stdio probe and full per-query
ASan stderr files. W2's first replay attempt used an empty fixture, so it
showed the column READ and fixed-parse control but could not reach the WRITE;
W3 fixed the fixture, added a zero-row failure guard and rebuilt all three
rows. `evidence/replay-mcp-tool-vuln-recover-Q{33,48}.err` now reproduce the
tool-path `WRITE of size 68` at `func_bufs[32]` with the chosen name; details
and hashes are in `MCP-TOOL.md`. W5 then replayed from a literal `git archive
HEAD` tree and found that the script verified the two pinned `cypher.c` blobs
before extracting the tarballs, aborting at rc=1 on a clean tree; the working
tree had masked this. `mcp-tool/replay.sh` now extracts before verifying all
four pins. From HEAD `4c353c3` with only that corrected script substituted,
all three rows rebuilt (4/4 pins, expected rc and ASan classes, chosen WRITE
of 68) and the three row logs plus both recover `-Q33.err` / `-Q48.err` files
matched the canonical hashes after normalizing only volatile tokens (root
path, timing fields, ASan PIDs/addresses/BuildId and stack byte dumps).
This closes the clean-checkout replay gap, not the independent-witness gap.

## Next for the target mind

1. Independent witness replay of both the direct-call matrix and the new
   `query_graph` tool rows; operator requested the first at tape #3228 and the
   author handed the tool rows to the witness this wake. Author replay is not
   acceptance.
2. Only after witness verdict: consider whether a live MCP client/agent can
   influence the `query` argument with untrusted content; no such claim yet.
3. Placement control in a live object through the tool path remains UNKNOWN;
   never infer RCE from a crash. Hand any new claim to `witness`.
