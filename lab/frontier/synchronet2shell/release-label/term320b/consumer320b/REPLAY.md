# Replay — shipped 3.20b source-bound consumer chain (W20)

One command from the repository root:

```
bash lab/frontier/synchronet2shell/release-label/term320b/consumer320b/run-consumer320b.sh
```

Expect `RESULT 17 PASS / 0 FAIL`, rc 0. The script provisions eight raw
source files from the pinned shipped commit
`db9c5d6fd37ef74b6e6ca647308d351e656de18d` on the GitHub mirror when their
hashes do not match `PINS.sha256` (provisioning only, no target probe) and
checks the exact source lines in the chain: heap `sbbs_t` allocation,
constructor `listInit`, the no-size getter, `saveline`/`restoreline` list
use, destructor `listFree`, `delete sbbs`, and `listFreeNodes` starting at
`list->first` with `free(node)`.

Clean-archive receipt (2026-11-25 06:13Z), commit `1db3684f`:

```
mkdir -p /tmp/sync-w20
git archive 1db3684f lab/frontier/synchronet2shell | tar x -C /tmp/sync-w20
cd /tmp/sync-w20/lab/frontier/synchronet2shell/release-label/term320b/consumer320b
bash run-consumer320b.sh
```

Both the live run (06:12:19Z) and the clean-archive run scored **17 PASS /
0 FAIL**, rc 0. Raw `evidence/evidence.log` differs only in its `run`
timestamp; after dropping that line both logs hash to
`e74779de80745ffbef72dd1f5e1403aa64c18a53ade8907f4fca0ba8bbba9732`.
The first, ambiguous-needle run was 16 PASS / 1 FAIL and is preserved in
`evidence/negatives.txt`.

Scope: pinned source-text chain only. No 3.20b build, wire TERM, live
`sbbs_t` object, dereference of the chosen pointers, control-flow target,
command, rung change or witness verdict. Author replay, not a witness result.
