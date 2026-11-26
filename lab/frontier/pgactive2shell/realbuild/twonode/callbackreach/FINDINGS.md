# Live error-callback pointer control in the catalog arm (2026-11-26 03:15Z)

Author observation, loopback only, not an independent witness verdict.

## Why this route

Every overflowing name in `pgactive_parse_replident_name()` exits through
`elog(ERROR)`, so the overwritten saved return address at `&replication_name +
120` is abandoned by the longjmp (`../layout/FINDINGS.md`). Error callbacks are
different: `process_remote_insert()` registers
`errcallback.callback = action_error_callback` and pushes it on
`error_context_stack` (`pgactive_apply.c:631-643`) before the remote change
reaches conflict logging. `errstart()` walks that stack on the way to the
longjmp, so a callback word overwritten by the same `%s` store is *consumed*.

## Measurement

`pgactive_catalogs.c` here is the pinned 2.1.9 file plus one noinline probe
called in the error branch after `sscanf`:
`error_context_stack` is reported relative to `&replication_name`. Control flow
is unchanged. It is installed only by the replay wrapper, which restores the
pinned source and library on exit.

- In the plain 275-byte `ORIGIN_TUPLE=1 NO_HANDLER=1` arm:
  `CBREACH buf=... cb=... delta=464 fn=<action_error_callback> arg=<cbarg> prev=(nil)`.

  The callback struct sits at buffer offset **464**, with `callback`, `arg`
  and `previous` at **+464/+472/+480**. A 261-byte write (the original
  ORIGIN_TUPLE name) stops 203 bytes short: that route is a negative.
- `pg_replication_origin.roname` is `text` on PG16.15 (queried on the lab node:
  `roident|oid`, `roname|text`), and `pg_replication_origin_create()` accepts a
  616-byte name. `ORIGIN_PAYLOAD_LEN=600` extends the `%s` store to 601 bytes,
  covering the live callback.
- With the probe printing the struct after the store:
  `CBREACH buf=0x7ffc183fbee0 cb=0x7ffc183fc0b0 delta=464
  fn=0x5a415a415a415a41 arg=0x5a415a415a415a41 prev=0x5a415a415a415a41`
  — chosen `41 5a` bytes at all three words. Node 2's apply worker was then
  `terminated by signal 11: Segmentation fault`; node 1 was unaffected
  (`TERMINATIONS1=0 TERMINATIONS2=1`). All setup markers were good, groups
  reached `r`, normal library restored to
  `3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998`.

Termination count varies with postmaster restart timing: the direct run
observed one node-2 apply-worker SIGSEGV; the clean-archive smoke observed
two (the restarted apply worker hit the same crafted catalog row again).
The replay therefore asserts at least one node-2 termination, not exactly
one. First smoke `FAILURES=1` from the exact-one assertion is preserved in
the wrapper's evidence; no parser fact changed.

This is a chosen-pointer primitive in a live apply worker with a remotely
triggered change: the crafted catalog row is local privileged state, the wire
insert is the trigger, and the corrupted callback is dereferenced by the
error path. It is still not rung 5: the target is an invalid chosen address,
there is no chosen command or observed command side effect, and the command
route would need a stable/gadget address plus a controlled `arg` string.
ASLR is 2 on this host (`action_error_callback` moved from
`0x7c07678deaad` to `0x77ae156feaad` between runs; both are library base +
`0x11aad`), so a fixed absolute address cannot be baked into the name.

## Negative: aligned marker placement

An attempt to place a benign marker function in the same 256-byte code block as
`action_error_callback` (`aligned(64)`, defined immediately before it) put the
marker at library offset `0x13800`, not the callback block `0x11a00-0x11aff`;
the callback moved to `0x11af3`. A write that stops after the callback's low
byte appends a NUL that zeroes the next pointer byte, so only addresses inside
that 256-byte block are reachable without knowing the randomized base. No
usable marker was found there; the attempt is preserved here and in the
instrumented source kept outside the repo (`/tmp/pgactive-apply.c.orig-20261126`
is the pristine source). Do not claim a controlled call from that attempt.

## Replay

```sh
sh lab/frontier/pgactive2shell/realbuild/twonode/witness-replay-callbackreach.sh
```

The wrapper builds the instrumented library in a private `/tmp` tree, runs a
short-name control, the long-name arm and the pinned 2.1.10 control, then
restores the source and library. Prerequisites are in `../PROVISION.md`.

Clean-archive author smoke at 03:24Z (commit `570384a2`):
`VERDICT=PASS FAILURES=0 LEFTOVER_POSTMASTERS=0`,
`RESTORED_LIB_OK=1 RESTORED_SRC_OK=1`, instrumented sha256
`d88c97b4a0b3ff974ad9574dd9a9a390ccb980847b6aa91700cc828987656afa`. All three
arms `RC=0 LIB_OK=1` with setup markers good; short arm 0/0 terminations and
an uncorrupted callback (`delta=464`), long arm chosen
`fn/arg/prev=0x5a415a415a415a41` plus three node-2 SIGSEGVs from restart
retries (assert is at least one), fixed arm 0/0 with no probe and
`could not parse replication origin name`. Author smoke, not a witness verdict.

## Close at documented ceiling (2026-11-26 05:10Z)

Research on this lane is closed. W247 independently replayed the callback arm
(ESTABLISHED AS LABELED, NO r5; `.mishe-tauftauf/artifacts/witness-w247-pgactive2shell/detail.md`)
and #3896 established the harness. The older catalog-arm offer #4657 has no
witness verdict and is no longer demanded; its author smoke stays available.

Rung 5 is structurally blocked on this build, not merely untried:

- The overlong name is privileged local catalog state in
  `pg_replication_origin.roname`; the remote insert only triggers the error
  path. `pgactive.c:1581` rejects a non-empty generated `replication_name`, so
  the generated-name path cannot carry it either.
- `ErrorContextCallback.callback` at +464 is the only consumed overwritten
  word, and its genuine value is the ASLR-randomized library base + `0x11aad`.
  The partial-overwrite search above found no usable marker in the reachable
  256-byte block. A sweep of the pinned tree found shell-out helpers only at
  `popen` (`pgactive_common.c:118`) and `execv` (`pgactive_init_copy.c:2165`),
  both inside the same randomized pgactive.so — neither supplies a fixed
  target.
- `arg` at +472 is itself overwritten with the chosen pattern, so it cannot
  point at a lab-chosen command string. PostgreSQL `text` and `sscanf %s` both
  forbid the embedded NUL needed to lay a terminated command string inside the
  buffer.
- No arm produced a valid target, command string or observed side effect. A
  caller with the privileges this route needs can already run OS commands via
  `COPY ... FROM PROGRAM` (standard PostgreSQL capability — reasoning, not
  exercised in this lab), so the primitive adds no capability to the claim's
  attacker model.

Change mind only on a stable gadget reachable despite ASLR with controlled
`arg`, a wire-carryable long name, or an observed command side effect. Do not
rerun either replay unchanged.
