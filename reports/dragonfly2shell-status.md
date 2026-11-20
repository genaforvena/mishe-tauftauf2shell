# Dragonfly2Shell status

Admitted 2026-11-20 by the operator under standing approval #6 (handoff
#179/#186). Dedicated two-pane window and two-pane restorer registry entry are
live; hy4-flash route is set. Trigger unit is still owed from the person's
full-flag sync per `docs/runtime-pin.md`.

## Inherited, not yet re-run by this mind

- **Target.** DragonflyDB memcached reply-builder key echo,
  GHSA-9q98-cx72-pg45 (no CVE). Affected <= 1.40.1, fixed 1.40.2 (PR #8213).
  `--memcached_port` is off by default; the protocol is unauthenticated.
- **Mechanism (source-bound from the fix).** `ParseValueless()` lacks the
  250-byte key limit, so a 20000-byte key created over RESP reaches
  `MCReplyBuilder::SendValue` and an unbounded copy past the 8192-byte
  `kMaxBufferSize` block.
- **Stock differential.** Pinned v1.40.1 echoes all 20000 key bytes in a
  20024-byte reply and stays alive; v1.40.2 answers a 29-byte wire
  `CLIENT_ERROR bad data chunk`. Witness gdb on the unstripped stock binary
  observed `SendValue` with `rdx = 0x4e20 = 20000`.
- **Rungs 1/2 ESTABLISHED.** Rung 2 mechanism OBSERVED on stock under gdb.

## Open

- Rung 3 on stock is **NOT demonstrated**: Valgrind fiber-stack false
  positives kill v1.40.1 before the reply. The ASan `WRITE of size 20000` is a
  labeled synthetic harness, not a stock result.
- Rung 4 is **NOT demonstrated**: the mimalloc free-list -> GOT -> shell chain
  is a claim. Next bounded step: gdb on the extracted unstripped binary to name
  the reply allocation and write, then the published free-list poison with
  `T = 0x19ef560` only after an observed controlled `malloc()` return.
- Loopback ports 16379/16211 only. Preserve negatives; label every rung by
  the build that produced it. Evidence: `reports/frontier-dragonfly2shell.md`.
