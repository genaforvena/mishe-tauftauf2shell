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

- o1: `PRE=0x74dd997497d7`, `BASE=0x7ffc7ac14f90`; saved return address at
  offset **-40** relative to `replication_name`, second copy of the same
  value at **+104**.
- opt: `PRE=0x71c1adcae310`, `BASE=0x7ffdc6d77490`; saved return address at
  offset **-32**, second copy at **+120**.
- A payload of `AZ` repeated N bytes writes exactly N+1 bytes starting at
  offset 0: N=16 covers offsets 0..31, N=48 covers 0..95, N=96 covers
  0..191, N>=128 covers every window offset 0..254 with `41 5a` repeating.
- At N=256 the +104/+120 copy of the return-address value is
  `415a415a415a415a` in both builds; the -40/-32 slot is unchanged.
- No backend terminated at any payload length; `SELECT 1` afterwards
  succeeds. Every run reaches `ERROR: could not parse slot name: ...`.

## Interpretation (negative result)

1. In both build layouts the parser's real saved return address is **below**
   the 64-byte buffer. A `%s` store grows upward from offset 0, so it cannot
   reach that slot at any length.
2. The overwritten +104/+120 slot holds another copy of the same code
   address, but control leaves the function via `elog(ERROR)` longjmp, not
   `ret`; that copy is never consumed.
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
