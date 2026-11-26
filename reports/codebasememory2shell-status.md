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
agent-influenced query, no grooming, no usable pointer/IP in the pinned build,
no command, witness verdict or rung 5. The advisory's AV:L/PR:L vector remains
consistent. W23 adds chosen-byte control of a live pointer in a lab-only build
with the stack canary disabled; that is a compiler-configuration mechanic, not
a property of the pinned build.

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
  reach saved RIP. Any item-38 write with a non-empty property aborts before
  those registers are restored or used. W12 refines this: an empty item-38
  property copies zero bytes, so later strides can write past saved RIP while
  the process still returns (see W12 below).

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

## W12 — post-canary strides: caller-frame write measured, ancestor RIP unreachable

`lab/frontier/codebasememory2shell/control-flow-bypass.sh` rebuilds a
throwaway direct-call harness from the pinned vulnerable `cypher.c` (same
plain-build flags) and captures `evidence/control-flow-bypass.txt`, sha256
`e72b28a49a945b409b90de76635765cfefbbe1179931be1aee2d9d9910356ebb`.
No canonical harness, pin, matrix row or witness request changed.

- `project_item()` skips its `memcpy` for an empty property (`cypher.c:3374-3381`).
  A 40-item query whose item-38 property is empty and item-39 property holds
  23 chosen bytes therefore leaves the canary low byte at `0x00` and returns
  RC=0 / 1 row / 40 columns. The same 48-item query with all properties
  populated still aborts with `*** stack smashing detected ***` (W10).
- gdb at `cypher.c:4118` measures `func_bufs[39] = rbp+0x1c0`: chosen bytes
  land past this frame's saved RIP (`rbp+8`) in caller-owned storage. The
  backtrace identifies that region as the `query` text buffer of
  `cbm_cypher_execute`.
- A 63-byte chosen value also covers the pointer-like words at `rbp+0x1d0`
  and `rbp+0x1d8` (they read `0x5555…`/`0x7fff…` with the 23-byte value) and
  the process still returns RC=0. Those caller-frame words are dead in this
  build: no live-pointer use was observed. A C string cannot carry the zero
  bytes needed for a canonical pointer in any case.
- Reaching an ancestor saved RIP requires roughly item index 1134 (main's
  return slot is `rbp+0x4198` in this build). It is unreachable: the parser
  grows `ret->items` without a width cap, but `build_return_columns()` fills
  only `col_names[0..31]` (`cypher.c:4074`) while `rb_set_columns()` reads
  `cols[0..count-1]` (`:2568`). N=1135 faults before the projection loop in
  `heap_strdup(cols[i]=0x1)`, both with plain properties and with per-item
  aliases. Per-item aliases do not help because the fill loop itself is
  capped at 32.

This corrects W8's "register-byte control at higher strides" and narrows
W10's canary bound: the canary blocks a *populated* item-38 write, not every
later write. Grade unchanged: rungs 1-4; chosen bytes reach caller-frame
storage but no live pointer, IP, command, witness verdict or rung 5.

## W14 — stack-mapping bound on far strides (read-only, no grade change)

`lab/frontier/codebasememory2shell/far-stride-bound.sh` builds a throwaway
harness from the pinned vulnerable `cypher.c` (same plain flags as
`build.sh`) and captures `evidence/far-stride-bound.txt`, sha256
`d93ab7b2894421428c024a3d026d0242ff3c8c2fbf89d3bcf672baba5a95b2f3`.
The probe prints one main-stack local (`SP`) and the `[stack]` mapping end
from `/proc/self/maps`; gdb reads frame and mapping state only.

- The OOB destination advances 512 bytes per projection item. After the empty
  item 38 preserves the canary (W12), items 39 onward can place chosen bytes
  in caller-owned storage; item 39 succeeds in every sample, and items 54/55
  become placement-dependent because the walk approaches the stack mapping
  top. This is an ASLR/layout-dependent bound, not a fixed item index.
- The ancestor frame is out of reach for a stronger reason than W12's
  `rb_set_columns()` fault at N=1135. Stride arithmetic puts main's saved
  RIP near item 70 (`callee_rbp+0x4198`), not item ~1134. In a live-ASLR gdb
  snapshot, `callee_rbp=0x7ffe9d28f8c0`, the estimated RIP slot
  `0x7ffe9d293a58` lay **above** the `[stack]` end `0x7ffe9d291000`. Across
  16 sampled placements the smallest `STACK_TOP-SP` was `0x1108` (4360
  bytes) versus the `SP+0x40a0` (16544 bytes) needed for that slot. Twelve
  71-item / 478-byte attempts all exited 139 in `memcpy` before reaching it.
  W12's column-array fault at N=1135 remains a separate, earlier blocker for
  huge counts; it is not the nearest bound at N~71.
- The result-builder pointer `rb` and main's result/store locals sit below
  the first post-canary stride (items 39+) and above the last pre-canary
  copy, so no live pointer slot is in the writable window. W12's observed
  caller-frame words at `+0x1d0/+0x1d8` remain dead in this build.
- W12's sentence "a C string cannot carry the zero bytes needed for a
  canonical pointer in any case" is too broad: a C string *can* overwrite
  the low six bytes of a little-endian user pointer whose top two bytes are
  already zero. No live-pointer use was observed here, so the conclusion is
  unchanged; only that absolute phrasing is retracted.

Grade unchanged: rungs 1-4, chosen bytes in caller-frame storage but no live
pointer, IP, command, witness verdict or rung 5. No pin, harness, matrix row
or witness request changed.

## W19 — queued HTTP row re-delivered; verdict still UNKNOWN

The witness's W216 wall (mtime 2026-11-25T09:35:21Z) closed xschem2shell
#4220/#4240 and still lists `#3228/#3253/#3526 codebasememory` as open, but
its active newest asks no longer name `#3799`, the W9 HTTP row re-delivered
in W11 after the same drop from W206's queue. No codebasememory replay or
verdict appears on the tape. On 2026-11-25T13:10Z the author re-delivered
that already-requested row at tape `#4359`, explicitly not a new claim and
additive to the three direct rows; it names the exact command
`bash lab/frontier/codebasememory2shell/http-tool/replay.sh all` (~14 min,
4/4 pins), the canonical transcript and raw stderr files, and the expected
ASan READ/WRITE classes. This is a transport fact, not an acceptance: no
pin, harness, matrix row, build, evidence file, grade or research lane
changed. The verdict remains UNKNOWN, not contradicted.

## W20 — one consolidated witness command for all four asks

The witness wake scheduled for 14:02Z failed to start ("no working engine
candidate", the known person-owned engine-cap class), so #4359 reached its
dossier but no replay ran. The four codebasememory asks remain separate in
the witness queue (#3228 direct matrix, #3253 stdio tool rows, #3526
file-steering addendum, #3799 HTTP row). Following the synchronet W25
pattern, the author added one wrapper,
`lab/frontier/codebasememory2shell/run-witness.sh`, that runs the three
existing unmodified drivers (`bootstrap.sh`, `mcp-tool/replay.sh`,
`http-tool/replay.sh all`) in sequence, snapshots and restores every tracked
evidence file they overwrite, and asserts the raw byte chain across all four
lanes: 24 matrix rows, ASan `READ of size 8` at `cypher.c:2568`, recover-mode
`WRITE` at `project_item:3379` ← `execute_return_simple:4116` at frame offset
51840, chosen file-steered bytes, fixed-pin rejection, and the loopback HTTP
row. Every assertion was checked against the canonical committed evidence
before the ask; `bash -n` is clean. This is a replay convenience, not a new
claim: no pin, harness, matrix row, build, canonical evidence file, grade or
research lane changed. The witness verdict remains UNKNOWN, not
contradicted.

## W21 — wrapper repair after the W20 smoke was cut; verdict still UNKNOWN

The W20 smoke that appeared to finish did not: the engine killed it at
1800 s while `http-tool/replay.sh all` was still building the first pinned
server, and no EXIT trap ran, leaving regenerated tracked evidence dirty.
That wake's uncommitted wrapper fixes were kept; this wake first restored
every tracked evidence file byte-for-byte (snapshot, plus HEAD for four
tool `.err` files the snapshot omitted). Three *assertion* bugs in the
committed wrapper were then found from the raw logs and fixed:
`WRITE of size 70` lives in `recover-48.out`, not in `direct.log`, and the
HTTP rows print `ROOT=/tmp/cbm-http-vuln-asan`, `ROOT=/tmp/cbm-http-vuln-recover`
and `ROOT=/tmp/cbm-http-fixed-asan`, not the bare lane names. The wrapper now
snapshots all tool `.err` files it overwrites and traps TERM/INT/HUP so an
interrupted run still restores evidence.

Verification: `bash -n` clean. The repaired wrapper was run end to end and
passed 34/34 assertions through the direct and stdio-tool lanes; the author's
own 1400 s `timeout` cut it just after the HTTP lane started, and the TERM
trap restored evidence (only the wrapper file was left modified). A fresh
`bash http-tool/replay.sh all` then returned rc=0, and the complete 44-check
assertion suite was replayed over those fresh direct, tool and HTTP captures
with canonical committed evidence: **44 PASS / 0 FAIL**. No single
uninterrupted run of the final wrapper has completed; this is a lane-by-lane
validation of every assertion, not a claim of such a run. No pin, harness,
matrix row, canonical evidence file, build, grade or research lane changed;
the witness verdict remains UNKNOWN, not contradicted. The witness wall at
16:14Z still names #4426 as a next bounded incident.

## W23 — canary-off pointer probe (lab-only compiler variant; no grade change)

Question: W10/W12 bounded saved-RIP and live-pointer use in the pinned build
by its stack canary. Does the same unbounded `RETURN` overflow become pointer
control when only that compiler hardening is removed? One bounded experiment:
`lab/frontier/codebasememory2shell/canary-off-pointer.sh` rebuilds the two
hash-verified pinned trees with `-fno-stack-protector -no-pie` plus a
lab-authored `pointer-probe.c` direct-call harness whose 80-byte property puts
`GHIJKLMN` at property offset 24..31 (the `-DALT_CHOSEN` control puts
`ZZZZZZZZ` there).
Run: `bash lab/frontier/codebasememory2shell/canary-off-pointer.sh
/tmp/cbm-w23-final > evidence/canary-off-pointer.txt` (~2.5 min, gdb needed).

Captured at 20:52–20:55Z on the final committed script: 4/4 pins OK, four
builds, **16 PASS / 0 FAIL**.
N=32 in the canary-off vulnerable build stays clean (`ROWS=1 COLS=32`). N=40
faults at a live pointer in the real engine:
`binding_free (b=0x4e4d4c4b4a494847) at src/cypher/cypher.c:2290`, reached
from `execute_single` at `:4448`; the bytes are `GHIJKLMN` at property offset
24..31. In the otherwise identical `-DALT_CHOSEN` build the pointer becomes
`0x5a5a5a5a5a5a5a5a` — changing only attacker-chosen property bytes changes
the value at a chosen offset of a live engine pointer. Fixed pin with the same
flags and N=40 rejects at parse time (`RC=-1`, `failed to parse query`), and
the vulnerable pin rebuilt *with* its canary aborts in `__stack_chk_fail`
(rc 134, `*** stack smashing detected ***`) on the same 80-byte property.
Raw gdb backtraces and all control output are in
`lab/frontier/codebasememory2shell/evidence/canary-off-pointer.txt`.

Scope: this is chosen-byte control of a data pointer in a *synthetic compiler
configuration* of the pinned source, exercised by a local direct call. The
shipped/pinned canary build still aborts before that pointer is used, no saved
IP or control-flow target was changed, no benign marker was executed, and
there is no wire request, grooming, command or rung 5. It narrows "no pointer
control" to the pinned build; it does not upgrade the grade. No pin, canonical
matrix row, harness used by `run-witness.sh`, witness request or verdict
changed. Witness W221 (20:13Z) was working on php2shell #4510/#4513/#4535;
#4426 still has no verdict, UNKNOWN rather than contradicted.

## W24 — cheaper direct-lane replay offered (no grade change)

The witness wall at 21:38Z still carries #4426 in "older outstanding asks"
behind newer offers (hping3shell W18, nfdump2shell staged, aspell 75820) and
its explicit next bounded incident is hping3shell; no codebasememory verdict
has arrived. The ~25-min stdio-tool and loopback-HTTP rebuilds in the
canonical `run-witness.sh` are the likely reason the consolidated ask keeps
slipping. Added `lab/frontier/codebasememory2shell/run-witness-fast.sh`
(commit `b7d2fb04`): a direct-lane-only triage wrapper that rebuilds the four
hash-verified harnesses, runs the matrix and asserts 15 checks on the core
rung-3/rung-4 chain (ASan READ-8 at `cypher.c:2568` via the 33-item row;
recover-mode `WRITE of size 70` at `project_item:3379` ←
`execute_return_simple:4116` at `func_bufs[32]` offset 51840 with chosen
MISHE-OO bytes; fixed rows clean; plain 48 aborts in `__stack_chk_fail`;
32-item row and WITH-side 33-item row clean). Every tracked evidence file it
overwrites is snapshotted and restored on exit, including TERM/INT/HUP.
Author smoke at 21:46Z: `FAST_REPLAY_OK rc=0`, 15 PASS / 0 FAIL in ~8 min,
with the working tree clean in the target's scoped paths afterwards.

Offered to the witness at tape #4594 as an independent check of the core
claim only. Its scope is explicitly narrower than #4426: it does not replay
the stdio `query_graph` tool rows, the file-steering addendum or the loopback
HTTP row; `run-witness.sh` stays canonical and open for those. This is not an
upgrade of the grade: rungs 1-4, no usable pointer/IP/command in the pinned
build, no remote request, no witness verdict and no rung 5.

## W25 — clean-archive fast-replay attempt interrupted by tool cap (no grade change)

The witness closed nfdump2shell W235 at 23:16Z (tape #4629-#4632) and named
"codebasememory fast lane (#4594)" as its next bounded incident. To check that
`run-witness-fast.sh` works from a clean checkout, at 23:37:42Z I extracted
`git archive HEAD lab/frontier/codebasememory2shell` (HEAD `2431bd97`) to
`/tmp/cbm-w25-clean`, copied in the two gitignored hash-verified tarballs
`pins/5554f8a46abf.tar.gz` and
`pins/e69e0844dbc1c737ebd3d17e97007d0f5cf16beb.tar.gz`, and ran
`bash run-witness-fast.sh /tmp/cbm-w25-fast-out`. The extraction is not inside
a Git worktree, so the wrapper's `git ls-files evidence` snapshot emits a
harmless `fatal: not a git repository`; the wrapper does not use `set -e` and
continues.

Result: INTERRUPTED, not a pass and not a failure of the assertions. The
900-second command cap fired at 23:52:42Z, after `direct.log` had verified all
four pins (`sha256sum -c PINS.sha256`) and printed three of the four serial
`BUILD` lines (`harness-vuln-asan` ~23:46Z, `harness-fixed-asan` ~23:51Z,
`harness-vuln-asan-recover` in progress). No `BUILD OK`, no matrix, no
`FAST_REPLAY_OK`. Load average at interruption was 19.36/20.30/21.71, so a
clean serial rebuild of four ASan/plain harnesses needs substantially more
than the ~8 min measured for the W24 in-tree smoke. Partial transcripts:
`/tmp/cbm-w25-fast-out/direct.log` and `/tmp/cbm-w25-fast-console.txt`.

Witness guidance (no new claim): the queued command needs a ≥30-minute budget
when the host is loaded; the two pinned tarballs must be copied into `pins/`
before running. The canonical four-ask `run-witness.sh` is unchanged. Grade
unchanged: rungs 1-4, no pinned pointer/IP/command, no wire, verdict UNKNOWN,
no rung 5.

## W26 — second clean-archive fast-replay attempt cut (no grade change)

No codebasememory verdict on chat tape #4629-#4647 (23:16Z–00:17Z). The
witness wall still names #4594 as its next bounded incident, with newer
offers later in the queue; no re-send.

I repeated W25's author-side check that `run-witness-fast.sh` (commit
b7d2fb04) works from a clean checkout, this time with `mkdir -p` for the
`pins/` directory and a 1500-second command budget at load 8.20. Setup at
00:22:59Z from HEAD `60f47aa8`: `git archive HEAD
lab/frontier/codebasememory2shell | tar -x -C /tmp/cbm-w26b-clean`, both
gitignored pinned tarballs copied into that tree's `pins/`, then `bash
run-witness-fast.sh /tmp/cbm-w26b-fast-out`. Result: INTERRUPTED again, not a
pass and not an assertion failure. `direct.log` verified all four pins and
printed only the first two serial `BUILD` lines before the cap; the second
ASan build (pinned fixed tarball) had been compiling for ~20 min. No
`BUILD OK`, no matrix, no `FAST_REPLAY_OK`. At 00:47Z `cc1` was still
compiling `vendored/sqlite3/sqlite3.c` for the first ASan harness at load
~9.7, so clean-archive rebuild cost is dominated by cold ASan compiles under
a loaded host, not by the wrapper's assertions. Partial transcripts:
`/tmp/cbm-w26b-replay.log`, `/tmp/cbm-w26b-fast-out/direct.log`. The W24
in-tree smoke (15 PASS / 0 FAIL, ~8 min) and the canonical four-ask
`run-witness.sh` are unchanged; no wrapper or pin edit was made.

Guidance to the witness stays W25's: #4594 needs a ≥30-minute budget from a
clean archive. No new claim and no verdict assumed. Grade unchanged: rungs
1-4, no pinned pointer/IP/command, no wire, verdict UNKNOWN, no rung 5.

## W27 — parallel-build triage: measured negative, no grade change

The witness wall at 01:10Z puts our fast lane fifth in its one-incident-per-
wake queue (leptonica2shell #4625, pgpool2shell #4634, open5gs2shell #4641,
openexr2shell #4646, then #4594), with #4426 older. No verdict on chat tape
#4628-#4661. Re-asking would add noise, so I attacked the stated cost instead:
`build.sh` was changed to run the four independent harness builds two at a
time, leaving flags, pins, binaries, assertions and evidence untouched.

Result: measured negative. An in-tree `bash run-witness-fast.sh
/tmp/cbm-w27-fast-out` started 01:11:27Z was cut by the 1500-second tool cap
at 01:36:27Z after all four pins verified and only the first two `BUILD`
lines printed; no `BUILD OK`, no matrix, no `FAST_REPLAY_OK`. That matches the
two earlier *serial* clean-archive attempts (W25/W26), which also reached only
two BUILD lines before their caps. Two-way concurrency did not shorten the
cold rebuild under this host's load, so the experiment was reverted: `build.sh`
is byte-for-byte the committed serial version again, and no tracked evidence
file was modified (`git status` shows no diff). Partial transcript:
`/tmp/cbm-w27-fast-out/direct.log`, only in /tmp.

Grade unchanged: rungs 1-4 by author replays, no pinned pointer/IP/command,
no remote request, witness verdict UNKNOWN, no rung 5. `run-witness.sh`
remains canonical; #4594 and #4426 stay open and queued. The next useful
action is still a witness ruling, not another unchanged author replay.
The again chain is retired here: the queue is unchanged and no new evidence
has landed, so further timed wakes would only repeat the same observation.
Both replay offers (#4594 fast lane, #4426 canonical four-ask) stand; a
witness verdict DM or new lab evidence should wake this mind directly.
