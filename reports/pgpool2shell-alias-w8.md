# pgpool2shell — W8: alias analysis of the CVE-2026-92869 OOB store

Date: 2026-11-22 ~18:02–18:06Z. Operator #1488 recorded W7, asked the witness
to replay `lab/pgpool2shell/config`, and handed this mind "any new evidence"
with an explicit boundary: no rung-5 widening and no address-steering claim
without alias evidence. This wake closes the alias gap left open in
`reports/pgpool2shell-config-w7.md`; it does not add a new primitive or a new
grade. Everything below is author-measured, on this host only.

## Question

W7 measured a peer-chosen 32-bit value at a layout-fixed OOB slot on a live
4.7.2 watchdog child, then a SIGSEGV in `json_value_free_ex` whose pointer's
low 32 bits matched that value. Which object field is the slot, and does the
chosen value actually cause the fault? Both were UNKNOWN in W7.

## Answer

**The slot is `json_object_entry.value` for the `backend_hostname` key of a
peer-supplied backend JSON object.** The peer chooses the stored 32-bit value;
the upper 16 bits of the pointer come from the pre-existing heap pointer and
are unchanged. Destination offset is fixed by the parser/allocator layout.
The chosen value causally drives the daemon fault. No address steering.

## Evidence

### 1. Direct-call harness: the store lands in a live `json_value`, not in the `values[]` array

`bash lab/pgpool2shell/config/gdb-alias.sh` (`gdb-alias.cmd` → `gdb-alias.out`,
unchanged `h7-vuln-plain` harness, 4.7.2 plain, N=129):

- `sizeof(BackendDesc) = 113672`; `config->backend_desc = 0x55555556a330`;
  OOB destination `&backend_info[128].backend_port = 0x555555586038`,
  i.e. 256 bytes past the palloc'd buffer.
- The peer-supplied `backend_desc` json_value's `u.array.values` is at
  `0x55555558b6b0`; computed alias index `-2767`, so the store is **not** a
  child pointer of that array.
- The destination is the `type` field of a different `json_value` node in the
  parsed tree: `x/gx` before `0x3`, after the line-136 store `0x42424242`.
  Adjacent words show the same 48-byte `json_value` stride with `parent`
  pointers into the tree.

Harness fault is **not** caused by the chosen value: N=129 with chosen
`0x00000000` and `0x11111111` both abort with `free(): invalid size`,
rc 134 (`evidence-harness-chosen-zero.txt`,
`evidence-harness-chosen-alt.txt`). The unconditional 253-byte OOB
`strncpy` hostname zero-fill corrupts heap metadata in this harness; the
W7 case-G readback remains a genuine chosen-value store but its harness
abort is not a value-controlled effect.

### 2. Live daemon: value-control control experiment

`bash lab/pgpool2shell/config/gdb-run.sh 0x11111111 gdb-alias-wire.out
gdb-alias-wire.peer` (14 s, pinned 4.7.2 `-g -O0` watchdog child, one
loopback type-`Z` `WD_POOL_CONFIG_DATA` packet, N=129). Ports 19003–19006
checked free before start; only this script's own PIDs killed afterward.

- At `wd_json_data.c:136`, `i=128`: `x/wx` at `0x55555591dbe0` =
  `0x11111111`; backtrace `get_pool_config_from_json` ←
  `standard_packet_processor` (`watchdog.c:4472`) ← `watchdog_main`.
- Continuing: `json_value_free_ex (value=0x555511111111) at utils/json.c:1079`.
  W7 with chosen `0x42424242` gave `0x555542424242`. The low 32 bits track
  the peer's value exactly; the high 16 bits stay `0x5555`. Second value,
  same layout, same fault site.

### 3. Live daemon: exact field identification

`bash lab/pgpool2shell/config/gdb-run.sh 0x11111111 gdb-alias-wire3.out
gdb-alias-wire3.peer gdb-alias-wire2.cmd` (same controls):

- OOB destination `0x55555591dbe0`; `root = 0x5555558c5ad8`.
  Enumeration of all 38 `root->u.object` entries shows their `value` fields
  at `0x5555558c4ba8`…`0x5555558c4f20` — the OOB slot is **not** in the root
  object's entry array.
- Memory at the slot before the store: `0x00005555558cfca8` (a valid
  `json_value *`); after the line-136 store: `0x0000555511111111`.
- The surrounding 24-byte `json_object_entry` pattern identifies the slot:
  entry at `0x55555591dbd0` has `name = 0x55555591dbf5`,
  `name_length = 0x10` (16 = `strlen("backend_hostname")`), and
  `value = 0x55555591dbe0` (the OOB slot). The name string bytes at
  `0x55555591dbf5` read `backend_hostname`; the preceding entry's
  `name_length` is `0xc` (`backend_port`). `gen_config_json.py` emits
  `{"backend_port": ..., "backend_hostname": "h"}` — `backend_hostname` is
  the last entry of each backend object.
- Fault chain: `json_value_free (value=root)` →
  `json_value_free_ex`, whose object case walks
  `values[--length].value` in reverse (`utils/json.c:1100`). It therefore
  loads the corrupted `backend_hostname` child pointer first. gdb reports the
  fault PC at `utils/json.c:1079` (`switch (value->type)`) with
  `value=0x555511111111`; the `value->parent = 0` assignment in that block is
  at `utils/json.c:1075`. This matches the identified field and the pointer.

## Grade and limits

- Unchanged from W7: rung 3 ASan corruption + wire crash; rung 4 chosen-value
  write at a **layout-fixed** offset, including on a live daemon via one
  loopback peer packet; fixed 4.7.3 and safe N=128 controls remain clean.
  Condition: `wd_authkey = ''`, accepted loopback watchdog peer (PR:L
  equivalent).
- New: the field identity and the causal value→fault link are established on
  the pinned 4.7.2 daemon build. Both are author-measured; the witness has
  not replayed this lane or this analysis.
- **No address steering.** The peer controls 32 bits of the stored value,
  not the destination address; the upper 16 bits are inherited from the
  original `json_value *`, and the destination is fixed by the layout.
  `wd_nodes`, `wd_authkey` set, and any command side effect remain unmeasured.
  Rung 5 is not claimed.

## Replay

    cd lab/pgpool2shell/config
    bash run-harness.sh            # rebuilds binaries and A–G evidence
    bash gdb-alias.sh              # harness alias map (~1 s)
    bash gdb-run.sh 0x11111111 gdb-alias-wire.out gdb-alias-wire.peer
    bash gdb-run.sh 0x11111111 gdb-alias-wire3.out gdb-alias-wire3.peer gdb-alias-wire2.cmd

`gdb-run.sh` defaults to the original W7 arguments when called with no
parameters. Both wire replays require ports 19003–19006 free and kill only
the daemon and peer they start. No non-loopback probe, no other plant or node.

## W12 (2026-11-26 02:58–03:02Z) — live-daemon negative control, no steering

Question: W8 showed the OOB store overwrites the **low 32 bits** of a live
`json_object_entry.value` pointer. Could a peer choose the original low 32 bits
and turn the fatal free into a benign one, i.e. steer the freed pointer to a
chosen live object? This is a new, bounded control, not a retry of the closed
address-steering lanes.

Method: same pinned 4.7.2 `-g -O0` watchdog child, one loopback type-`Z`
`WD_POOL_CONFIG_DATA` packet with `backend_desc` N=129 and 12-byte hostname,
under gdb (gdb disables ASLR for the inferior, so addresses are stable across
runs). Ports 19003–19006 were checked free before each run; only the peer and
daemon started by each script were killed. No breakpoint at
`watchdog.c:4478` with an early `kill` in the decisive runs — the daemon outcome
was allowed to complete.

- CHOSEN `0x11111111`: slot `0x55555591dbe0` before `0x00005555558cfca8`,
  after `0x0000555511111111`; SIGSEGV at `utils/json.c:1079` in
  `json_value_free_ex`.
- CHOSEN `0x558cfca8` (exact low 32 bits of the pre-store pointer): before and
  after both `0x00005555558cfca8` — the pointer is restored — yet after the
  config-verify warnings the child prints `free(): invalid pointer` and dies
  with SIGABRT. Replayed twice, identical normalized hash.
- CHOSEN `0x558c5ad8` (low 32 bits of the parsed JSON root): after
  `0x00005555558c5ad8`, same `free(): invalid pointer` / SIGABRT. A conditional
  breakpoint at `utils/json.c:1075` on that pointer fires **once** — the normal
  `json_value_free(root)` entry — not a second visit, so there is no evidence
  the free was routed to a chosen live node.

Earlier runs that stopped at `watchdog.c:4478` and killed the child immediately
appeared clean; that was an artifact of our own early stop, not a daemon
outcome. Those transcripts were discarded and must not be cited as clean.

Conclusion: the eventual `free(): invalid pointer` abort on the live daemon is
value-independent, extending W8's harness finding from a synthetic consumer to
the real watchdog child. The only value-dependent effect measured is the
earlier SIGSEGV when the chosen low 32 bits map to unmapped memory. W8's label
stands: peer-controlled low-32 value at a layout-fixed destination; no
destination steering, no demonstrated steering to a chosen live object, no
command side effect, no r5. The chosen low-32 values are build/host-specific
under a debugger-disabled ASLR and are not a wire-portable address primitive.
Grade unchanged. Author-measured only; no witness replay of this control.

Replay from the repository root (assets in
`lab/pgpool2shell/config/pointer-control/`):

    bash lab/pgpool2shell/config/gdb-run.sh 0x11111111 pointer-control/before.out pointer-control/before.peer gdb-alias-wire2.cmd
    bash lab/pgpool2shell/config/gdb-run.sh 0x558cfca8 pointer-control/restore-count.out pointer-control/restore-count.peer pointer-control/gdb-count.cmd
    bash lab/pgpool2shell/config/gdb-run.sh 0x558c5ad8 pointer-control/root-count.out pointer-control/root-count.peer pointer-control/gdb-count.cmd
    bash lab/pgpool2shell/config/pointer-control/hash-evidence.sh

`EVIDENCE_HASHES.txt` holds the four normalized hashes: baseline
`542fd88b…`, restored `90e11d54…` twice, root `55cbf6ae…`.
