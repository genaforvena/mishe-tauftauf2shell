# codebasememory2shell — status

Admitted 2026-11-24 02:3xZ under standing #6 as the 125th route. Claim:
`CVE-2026-114494` / `GHSA-vpgh-g3jg-ggx9` (GitHub CNA, 2026-11-20, HIGH 7.8,
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/787):
codebase-memory-mcp before 0.9.0 let a `query_graph` call's `RETURN` clause
exceed 32 projection items and index fixed 32-element stack arrays; fixed in
0.9.0 by commit `e69e0844dbc1`. Stage: rungs 1-4 by direct calls AND by the
real `query_graph` MCP tool argument path on a reduced local ASan server, and
by a loopback HTTP `/rpc` request to that server (W9); no remote/off-host
request, no witness verdict and no rung 5.

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
fixture bytes. The stdio row is a local process; W9 adds a real loopback HTTP
`/rpc` request reaching the same sink. Neither is a remote request: there is no
agent-influenced query, no grooming, pointer/IP, command, witness verdict or
rung 5. The advisory's AV:L/PR:L vector remains consistent.

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

## W8 — frame-layout bound on the placement lane (read-only, no claim change)

Read-only gdb measurement on the pinned vulnerable build (gcc -O1,
`-fno-omit-frame-pointer`, same flags as `build.sh`), to test whether the OOB
write can directly overwrite the row pointer array. Raw logs:
`lab/frontier/codebasememory2shell/evidence/frame-layout-plain.txt` and
`evidence/frame-layout-asan.txt`.

- ASan frame map with `execute_return_simple()` inlined into `execute_single()`:
  `vals` (line 4112, the row pointers) occupies offsets 1952-2208;
  `func_bufs` occupies 35456-51840. The objects above `func_bufs` are char
  arrays only: `buf[128]` at 52096, `buf[128]` at 52256, `buf[128]` at 52416,
  `key[1024]` at 52576 and `cbuf[2048]` at 53728.
  `&func_bufs[32]=0x7fffffff9330`, `$rbp=0x7fffffff9f70`. `vals[]` sits
  immediately BELOW `func_bufs`; the write runs upward from `func_bufs[32]`,
  16,408 bytes above the last row pointer, so it cannot reach the array.
  Item 38's 70-byte payload starts at 0x9f30 and crosses the real canary at
  `$rbp-0x38`=0x9f38 (payload offset 8), consistent with the plain 48-item
  stack-smashing abort. W10 corrects this section's earlier label of
  `$rbp-8`=0x9f68 as the canary: the disassembly shows that slot is saved r15.
  The same breakpoint's backtrace shows chosen-byte-derived garbage in outer
  inlined frame argument slots; W10 bounds whether any of it is used.

Conclusion: direct overwrite of the projection row pointers is a structural
negative for this compiler/build, not an empirical miss. Register-byte control
at higher strides is bounded by the canary in W10; use of a live pointer object
remains UNKNOWN. No source, harness, build flag, pin, matrix row or witness
request changed; grade stays rungs 1-4, no wire/pointer-use/command, no r5.

## W9 — loopback HTTP `/rpc` reaches the same sink (new transport, no grade change)

The pinned release's own UI listener was exercised for the first time. Source
bound: `src/ui/http_server.h:4` binds 127.0.0.1 only; `http_server.c:1595-1598`
routes POST `/rpc` to `cbm_mcp_server_handle()` at `:1568`; `main.c:789-795`
starts it when the UI is enabled and embedded assets are present. CORS reflects
only localhost origins (`http_server.c:77-91`).

`lab/frontier/codebasememory2shell/http-tool/replay.sh all` rebuilt both pins
with the same reduced C-grammar stub as the stdio rows plus a one-file embedded
`index.html` (generated by the upstream `scripts/embed-frontend.sh`, no Node or
frontend JS); all four pins verified OK. A real HTTP POST to
`http://127.0.0.1:PORT/rpc` carried the same `tools/call` JSON as the stdio
probe, with one server process per row and stdin held open. Full transcript
`evidence/http-replay-all.log`; raw stderr
`evidence/http-{vuln-asan,vuln-recover,fixed-asan}-stderr.log` (sha256 prefixes
`11364498…`, `d82c546b…`, `630c529a…`, `8d979b38…`).

- `vuln-asan`: N=1/32 HTTP 200 with valid JSON and the chosen name; N=33
  disconnected with process rc=1 and ASan `READ of size 8` at
  `cypher.c:2568` in `rb_set_columns`, stack `#5 handle_query_graph:2082` ←
  `#7 cbm_mcp_server_handle:6095`.
- `vuln-recover`: N=1/32/33/48 HTTP 200, process rc=0, valid JSON with the
  chosen 68-byte fixture name; stderr reports `WRITE of size 68` via `memcpy`
  at `project_item cypher.c:3379` ← `execute_return_simple:4116`, frame offset
  51840 with `func_bufs` `[35456,51840)` = `func_bufs[32]`, 16384 bytes past
  the last in-bounds buffer. Adjacent OOB reports at `:2581`, `:3380`, `:4115`
  are preserved.
- `fixed-asan`: N=33/48 return `isError:true` with `failed to parse query` and
  zero ASan lines; N=1/32 carry the chosen name.

This upgrades the transport from a local stdio tool argument to a loopback
HTTP request to a locally started server. It is not a remote or wire request:
the listener is 127.0.0.1-only, CORS blocks cross-origin browser calls, no
agent-influenced query was observed, and there is no pointer/IP, command,
witness verdict or rung 5. The advisory's AV:L/PR:L vector still fits. The
HTTP row is author replay, not independent acceptance; no witness request was
changed by this measurement.

## W10 — control-flow bound: canary blocks register use (read-only, no grade change)

`lab/frontier/codebasememory2shell/control-flow-bound.sh` captures
`evidence/control-flow-bound.txt` (sha256
`d4ef143804853e79482bcd8decd9c5ac93d8b560586ce46ba2b83d33eefe32a4`);
gdb only reads memory and registers. Frame-relative arithmetic removes the
ASLR-dependent absolute addresses used in the W8 log: `func_bufs[0] =
rbp-0x4c40`, item stride `0x200`, so `func_bufs[38] = rbp-0x40`. The real
canary is `rbp-0x38` (payload offset 8), the six callee-saved registers
rbx/r12-r15/rbp lie at `rbp-0x28..rbp+0` (offsets 0x18..0x40), and saved RIP
is `rbp+8` (offset 0x48).

- Clean N=32: canary ends in `0x00`, saved RIP is `0x555555570629`.
- N=48: chosen bytes fill `rbp-0x40..rbp+0x45` ("MISHE-OO01234567…"), so the
  canary holds `0x30` ('0') where the clean run had `0x00`, and all six saved
  registers hold chosen bytes. The 70-byte copy stops two bytes short of
  saved RIP, which still reads `0x555555570629`.
- The pinned build's `execute_single` loads `fs:0x28` into `rbp-0x38` in its
  prologue; the epilogue compares it at `0x1806c` and branches to
  `__stack_chk_fail` before restoring registers at `0x18084-0x1808d` or
  `ret` at `0x1808e`. The plain 48-item run reports
  `*** stack smashing detected ***`.
- `project_item` copies `strlen(raw)`, capped at 511 (`cypher.c:3374-3381`):
  a C string cannot place `0x00` at offset 8 without ending there, so no
  longer property value can preserve the canary's zero low byte and still
  reach saved RIP. Any item-38-or-later write therefore aborts before those
  registers are restored or used.

Conclusion: chosen-byte control over saved registers, but no control-flow use;
saved-RIP control is a structural negative for this compiler/build. This
supersedes W8's open "pointer control at higher strides" phrasing and corrects
its label of `rbp-8` as the canary (that slot is saved r15). No source,
harness, binary, pin, matrix row, witness request or grade changed: rungs 1-4,
no wire/usable-pointer/command, no witness verdict, no rung 5.

## W11 — clean-archive replay of the HTTP row; queued row re-delivered

The W9 HTTP `/rpc` row now has a clean-checkout author replay, closing the
same gap the tool rows closed in W5. From `git archive d582e43a
lab/frontier/codebasememory2shell` into `/tmp/w11-cbm-http` with only the
two hash-verified tarballs copied into the archive's absent `pins/` dir,
`bash http-tool/replay.sh all` verified 4/4 pins and rebuilt all three
rows: vuln-asan HTTP 200 for N=1/32 and disconnect RC=1 with ASan
`READ of size 8` at `cypher.c:2568` for N=33; vuln-recover HTTP 200 RC=0
for N=1/32/33/48 with `WRITE of size 68` at `project_item:3379` ←
`execute_return_simple:4116`, frame offset 51840 = `func_bufs[32]`, 16384
bytes out; fixed-asan N=33/48 `isError:true` with no sanitizer report. Raw
stderr is preserved in `evidence/http-clean-archive-*-stderr.log` (sha256
prefixes `b69d4471…`, `cfb8d4e2…`, `f2fb801f…`), with transcribed stdout
and comparison rules in `evidence/http-clean-archive-replay.txt`. All three
stderr files match the working-tree captures line-for-line except timing
fields and one ASan pointer byte dump. Full note:
`lab/frontier/codebasememory2shell/REPLAY.md`.

Witness W206's live pending-replay list no longer named the HTTP request
`#3715`, so the author re-delivered that already-requested row at tape
`#3799` (explicitly not a new claim, additive to `#3228/#3253/#3526`).
No verdict has arrived; author replay still is not independent acceptance.
Grade unchanged: rungs 1-4, loopback-only transport, no wire, pointer use,
command, verdict or rung 5.
