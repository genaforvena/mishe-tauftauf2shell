# Babelfish2Shell status

Handed off to the operator 2026-11-20 ~22:1xZ under standing approval #6,
on frontier's fresh-find handoff. Admission, charter and docs/task.md entry
are the operator's next step. The dedicated two-pane window `babelfish2shell`
(inner socket), restorer registry entry and seed wall are already live from
frontier. Wake trigger units and the presentation.json `active` entry are owed
from the person's full-flag sync (`docs/runtime-pin.md`) — never a bare
`mishe sync`. Frontier re-ran the extracted harness from committed sources at
handoff: `bash lab/frontier/babelfish2shell/run.sh` printed `ALL CHECKS PASS`,
rc 0; pins `c5559f08…` / `d4b09e8c…` match the brief.

## Target

Babelfish for PostgreSQL TDS prelogin heap overflow, CVE-2026-119923 /
GHSA-vq28-vgj3-r26w / AWS bulletin 2026-166-AWS (CWE-122, CVSS 3.1 9.8
Critical, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CVSS 4.0 9.3).
Remote unauthenticated crafted prelogin packet to the TDS port (default 1433).
Fix commit `ab820bddaffa540af82f2f689c3e535f82f14d89`, vulnerable tag
`BABEL_4_8_0`, fixed tag `BABEL_4_10_0` (backports at 5.6/6.1). Distinct from
the postgres2shell FDW lane and from CVE-2026-119924 (authenticated RPC OOB
read).

## Mechanism and reproduction

- `tdslogin.c:342-363`: `ParsePreLoginRequest` reads a 16-bit network-order
  `length` from the packet with no bound, then `initStringInfo(&temp->val)`.
- PostgreSQL `initStringInfo` allocates exactly 1024 bytes.
- `tdslogin.c:377-383`: `TdsGetbytes(prev->val.data, prev->length)` copies
  `length` packet bytes into that 1024-byte buffer with no resize.
- `TdsGetbytes` (`tdscomm.c:634-659`) `memcpy`s the sender's bytes verbatim,
  so both the count and the written values are attacker-controlled.
- The fix rejects `length > 4096` and calls `enlargeStringInfo` before the
  copy, plus adds the consolidated NULL-deref / bounds guards.
- Harness (pinned digests above): rung 1 `length=4096 si_capacity=1024
  oob_writes=3072 first_oob=1024 last_oob=4095`; rung 2 length 1050/1150/2100
  clobbers neither/first/both neighbour stamps; rung 3 ASan `WRITE of size
  4096`, `0 bytes after 1024-byte region` in `wire_getbytes`; rung 4 packet
  bytes `de ad be ef ca fe ba be` and `41 42 43 44` land byte-exact at offsets
  1100/2000; fixed control `rc=0 oob_writes=0` and clean under ASan; 5/5
  traces byte-identical.

## Evidence boundary

Rungs 1/2/3 established in the extracted harness. Rung 4 shows sender-chosen
bytes at sender-chosen offsets **in the extracted harness**; no live-process
demonstration exists. No real Babelfish/PostgreSQL process, TDS endpoint,
palloc/heap layout, real neighbouring object, pointer control or marker
execution was observed. The consumer-reality check (actual palloc chunk size
and adjacent allocation) is still owed before any stock-build rung-4 claim.
External claims are claims, not lab findings; author report is not
acceptance; witness owns replay.

## Next bounded steps

1. Build Babelfish 4.8 + patched PostgreSQL 16 with ASan on loopback; send a
   raw TDS prelogin packet with `length=4096` and a marked payload to
   127.0.0.1:1433; confirm the real 1024-byte allocation and the ASan WRITE,
   and identify the genuine clobbered neighbour.
2. For a live rung 4, find a real neighbouring field whose overwrite by chosen
   bytes gives a useful effect; keep value control separate from pointer
   control or execution claims.
3. Replay the same packet against 4.10 to confirm the fix removes the fault.

## What would change my mind

A bound on `length` before the copy in the vulnerable source, a clean witness
replay losing the ASan WRITE or chosen-byte read-back, or a real stock
`initStringInfo` allocation larger than 1024 bytes.
