# Non-ASan stack layout of the real 2.1.9 parser (2026-11-25 03:09Z)

`pgactive_catalogs.c` here is the pinned v2.1.9 file plus one noinline helper
called in the existing error branch, after the unbounded `%s` store and before
`elog(ERROR)`. The helper reads `__builtin_return_address(0)` at function
entry, searches a 320-byte window from `&replication_name - 64` for that
value, and emits one `LAYOUT` line and one `LAYOUTWIN` hex line to the
postmaster log. Control flow is unchanged. `run-layout.sh` restores both the
build source and the installed library on exit.

```sh
LABEL=o1  sh run-layout.sh   # -O1 -g -fPIC -fno-omit-frame-pointer
LABEL=opt sh run-layout.sh   # PGXS default production flags
```

Both runs: `LAYOUT_BUILD=0`, `LAYOUT_INITDB=0`, `LAYOUT_PGSTART=0`,
`LAYOUT_CREATE=0`, `LIVENESS_RC=0`, `BACKEND_TERMINATIONS=0`,
`LAYOUT_STOP=0`, `NORMAL_SO_RESTORED=yes`, `SRC_RESTORED=yes`.
Loopback only: 127.0.0.1:58423, socket `/tmp/pgactive-layout-sock`.

## Observed

- o1: `PRE=0x74dd997497d7`, `BASE=0x7ffc7ac14f90`; first downward search
  match at offset **-40** relative to `replication_name`, another at
  **+104**.
- opt: `PRE=0x71c1adcae310`, `BASE=0x7ffdc6d77490`; first downward search
  match at **-32**, another at **+120**. Disassembly of this build places
  the real saved return-address slot at +120 (see correction below).
- A payload of `AZ` repeated N bytes writes exactly N+1 bytes starting at
  offset 0: N=16 covers offsets 0..31, N=48 covers 0..95, N=96 covers
  0..191, N>=128 covers every window offset 0..254 with `41 5a` repeating.
- At N=256 the +104/+120 words read `415a415a415a415a` in both builds;
  the -40/-32 words are unchanged.
- No backend terminated at any payload length; `SELECT 1` afterwards
  succeeds. Every run reaches `ERROR: could not parse slot name: ...`.

## Interpretation (negative result)

1. In the opt build the parser's `replication_name` is at `rbp-0x70`, the
   stack canary at `rbp-0x28` (offset +72) and the saved return address at
   `rbp+8` (offset +120). The -32 match from the downward search is below
   the frame pointer and is not this function's return-address slot; what
   placed that copy there stays UNKNOWN. The original claim that the saved
   RA sits below the buffer was wrong; see `evidence/disassembly-correction.txt`.
2. The +120 slot is overwritten by payloads of 120 bytes or more: at N=256
   its bytes alternate `41 5a`. The canary at +72 is overwritten too.
   Neither is consumed, because control leaves via `elog(ERROR)` longjmp,
   not `ret`.
3. Every input that makes `%s` match also makes the pinned `!= 4` check
   fail, so the overflow is always followed immediately by the error
   longjmp. Caller-frame locals above the buffer are abandoned, not
   dereferenced.
4. The saved-pointer/return-address route toward a stronger rung 4 is
   therefore structurally blocked here. The earlier chosen-byte marker
   remains rung 4 AS LABELED; no IP, no command side effect, no rung 5.

Evidence: `evidence/layout-o1-summary.txt`, `evidence/layout-opt-summary.txt`
and the `LAYOUT`/`LAYOUTWIN` lines in `evidence/layout-o1-server.log` and
`evidence/layout-opt-server.log`. The first script attempt failed because the
lab socket path exceeded PostgreSQL's 107-byte limit; the socket was moved
to `/tmp`, and that failed attempt is preserved only in ignored logs.
Do not retry a gdb attach: `ptrace_scope=1` denies it
(`../sqlpath/evidence/gdb-live-capture.out`); the host guard was untouched.

## Correction 2026-11-25 06:15Z (machine-code check, no new cluster)

`objdump -d --disassemble=pgactive_parse_replident_name` on the opt build
left by `run-layout.sh` (`/tmp/pgactive-full-219/pgactive-2.1.9/pgactive.so`)
shows `lea -0x70(%rbp),%r12` for the `sscanf` destination,
`mov %fs:0x28,%rax; mov %rax,-0x28(%rbp)` for the canary, and
`mov 0x8(%rbp),%r13` for the caller return address. The function's saved
RA is therefore at `rbp+8`, i.e. 120 bytes above the buffer. The cold
path passes that same value to the layout helper. The `.rodata` format at
0x3c842 is `pgactive_%lu_%u_%u_%u_%s`; any non-empty match assigns five
conversions, so the pinned `!= 4` test always sends an overflowing input
to the error longjmp. Full commands, instruction excerpt, frame
arithmetic and the N=256 window bytes are in
`evidence/disassembly-correction.txt`. Only the opt build was
disassembled; the o1 -40/+104 offsets are first-match observations, not
verified slot locations. Outcome unchanged: no saved-pointer or IP
control, no command side effect. The reason is the longjmp, not a return
address below the buffer.

## Production-build check 2026-11-25 08:06Z (binary only, no cluster)

The earlier disassembly covered the instrumented opt build. The shipped,
non-instrumented library (`evidence/pgactive.so.normal-backup`,
sha256 `3177a37c...162998`) inlines the parser into
`pgactive_parse_replident_name_sql` (0x16290) and has the same frame:
buffer at `rbp-0x70`, canary at `rbp-0x28` (+72), saved RA at `rbp+8`
(+120). Spilled `fcinfo`/`riname`/`values`/`isnull` registers sit at
+80/+88/+96/+104 — inside the overflow window — but the cold path passes
`riname` in `%r12` and only the success return pops those slots. The
success path is unreachable for an overflowing name: a throwaway glibc 2.39
probe with the pinned five-conversion format returns 4 with the `%s`
destination untouched, and returns 5 for any non-empty tail. Details and
exact instruction addresses in `evidence/production-frame-check.txt`.
The saved-pointer/IP route stays closed in the production build too; no
cluster was started and no source was changed. Author observation, not a
witness verdict.

## Clean-archive replay and generated-name bound (2026-11-25 08:59Z)

The negative was replayed from committed bytes, not the working tree:
`git archive b620fc1a lab/frontier/pgactive2shell/realbuild/layout |
tar x -C /tmp/pgactive-layout-clean`, then `LABEL=opt sh run-layout.sh`
with the installed normal library verified at sha256
`3177a37c...162998` before the run. All 15 lengths returned RC=1,
`LIVENESS_RC=0`, `BACKEND_TERMINATIONS=0`, `LAYOUT_STOP=0`,
`NORMAL_SO_RESTORED=yes`, `SRC_RESTORED=yes`; the first downward RA-value
match is again `RAOFF=-32`. At N=256 the canary slot (+72) and the saved
RA slot (+120) both hold chosen `41 5a` bytes, and the backend still lives.
The saved-pointer negative is therefore not a working-tree artifact.
Commands, hashes and decoded offsets: `evidence/clean-archive-replay.txt`.
Author replay, not an independent witness verdict.

A source-only bound on the wire path: in the pinned 2.1.9 tree both name
builders pass the empty tail constant — `pgactive_replident_name()`
(`src/pgactive_catalogs.c:386-398`) and `pgactive_slot_name()`
(`src/pgactive_common.c:40-45`) format `pgactive_REPORIGIN_ID_FORMAT` /
`pgactive_SLOT_NAME_FORMAT` with `EMPTY_REPLICATION_NAME`. Names the
extension generates itself therefore have an empty `%s` tail and cannot
overflow. The vulnerable caller
`pgactive_fetch_sysid_via_node_id_ifexists()`
(`src/pgactive_catalogs.c:303-333`) obtains `riname` from
`replorigin_by_oid()`, so reaching the overflow needs a hand-crafted name
already stored in the replication-origin catalog — consistent with the
advisory's "use only pgactive-generated names" workaround. This narrows
the trigger but does not supply one; the two SQL entry points remain
owner-only and the single-node group stayed in state `b`. Rung ceiling
unchanged.
