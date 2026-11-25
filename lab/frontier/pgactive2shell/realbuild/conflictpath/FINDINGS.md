# Second stack object in the 2.1.9 → 2.1.10 diff: conflict handlers (2026-11-25 09:05Z)

This is a **separate candidate primitive in the same pinned releases**, found
while checking whether the advisory's other workaround ("keep
`pgactive.pgactive_conflict_handlers` empty") points at code distinct from the
replication-origin parser. It is not the CVE's `%s` parser bug and it does
not change the report's rung ceiling. No cluster was started; work was
source reading, one standalone ASan probe and disassembly of the already
committed shipped-library backup.

## Source difference

Pinned `src/pgactive_conflict_handlers.c`, in
`pgactive_conflict_handlers_resolve()`:

- 2.1.9 `:716`: `FunctionCallInfoBaseData fcinfo;` — a flexible-array struct
  declared with no room for `args[]`.
- 2.1.9 `:751-791`: `InitFunctionCallInfoData(fcinfo, &finfo, 5, ...)` then
  writes `fcinfo.args[0..4].value/.isnull` and calls
  `FunctionCallInvoke(&fcinfo)`.
- 2.1.10 `:716`: `LOCAL_FCINFO(fcinfo, 5);` allocates five `NullableDatum`
  slots; all later accesses become `fcinfo->args[...]` and the missing
  `isnull=false` initialisers are added.

Other C files in the release diff (`pgactive_apply.c`,
`pgactive_init_copy.c`) carry unrelated hardening; `pgactive_internal.h`
adds the two `*SCAN_FORMAT` macros with `%n` for the parser fix.

## ASan probe (standalone, real PG 16.15 headers)

`fcinfo-probe.c` reproduces the pinned store sequence with chosen constants
in place of `heap_copy_tuple_as_datum()` and `cstring_to_text()`. Output in
`evidence/asan-fcinfo-probe.out`: `sizeof(FunctionCallInfoBaseData)=32`,
`offsetof(args)=32`, `sizeof(NullableDatum)=16`, and ASan
`WRITE of size 8` at offset 160 of a frame whose `fcinfo` object occupies
`[128,160)`. The first `args[0].value` store is one byte past the object;
five 16-byte slots (80 bytes) follow. Confirmed memory corruption (rung 3)
in a probe, not in a server.

## Shipped-library frame (binary only)

`objdump -d --disassemble=pgactive_conflict_handlers_resolve` on
`../layout/evidence/pgactive.so.normal-backup` (sha256 `3177a37c...162998`)
places `fcinfo` at `rbp-0x60` (32 bytes) and the writes at:

| Source store | Address | Aliases |
| --- | --- | --- |
| `args[0].value` | `rbp-0x40` (0x210c3) | first byte past object |
| `args[0].isnull` | `rbp-0x38` (0x210d5) | **stack canary slot** |
| `args[1].value` | `rbp-0x30` (0x210ea) | local |
| `args[1].isnull` | `rbp-0x28` (0x210fc) | local |
| `args[2].value` | `rbp-0x20` (0x21108) | command-tag text pointer |
| `args[3].value` | `rbp-0x10` (0x21113) | relation OID |
| `args[4].value` | `rbp+0x00` (0x2111d) | **saved RBP** |

The canary is loaded from `%fs:0x28` at `0x2108c` and checked from
`rbp-0x38` at `0x21255-0x21262` before a normal `pop %rbp; ret`
(`0x21278-0x21279`). No write to `rbp+0x08` was observed, so this frame's
saved return address stays intact. `-0xf8(%rbp)` is `sete` from
`cmpq $0, -0xe0(%rbp)` at `0x21017-0x21025`, i.e. `local == NULL`; it is
copied to `rbp-0x38` at `0x210d5`. A separate probe on this host read
`%fs:0x28` as `...4100`, low byte `00`. Consequently:

- `local == NULL` (the `UpdateDelete`/`DeleteDelete` callers) writes `01`
  into the canary's low byte → the check at `0x21262` fails →
  `__stack_chk_fail` abort.
- `local != NULL` (the `InsertInsert`/`UpdateUpdate` caller) writes `00`,
  preserving the canary; the function returns with saved RBP replaced by the
  event-type integer, so the caller's frame pointer is corrupted. The saved
  RA is untouched. Both outcomes are inferred from the disassembly and the
  observed canary byte, not from a live conflict.

## Reachability and limits

`pgactive_conflict_handlers_resolve()` is called only from
`src/pgactive_apply.c:1185`, `:1405` and `:1605`, all inside the apply
worker's conflict paths. A configured row in
`pgactive.pgactive_conflict_handlers` is required; a single-node loopback
cluster has no apply worker handling a remote conflict, matching the
advisory's "keep conflict handlers empty" workaround. No live trigger, no
chosen bytes at chosen offsets in a live process, no pointer/IP control and
no command side effect were demonstrated here. Rung ceiling unchanged;
witness replay does not yet cover this path.
