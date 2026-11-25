# Replay — shipped 3.20b pointer reach (W19)

One command from the repository root:

```
bash lab/frontier/synchronet2shell/release-label/term320b/run-term320b.sh
```

Expect `RESULT 10 PASS / 0 FAIL`, `PTR_CONTROL_OK` in the two plain 64-byte
cases, `SHORT_CONTROL_OK` for the 40-byte control, ASan `WRITE of size 64`
for both compilers in the 64-byte redzone cases, and no ASan report for the
40-byte control. The script fetches five raw source files from the pinned
3.20b commit `db9c5d6fd37ef74b6e6ca647308d351e656de18d` on the GitHub mirror
when absent and verifies all five with `PINS.sha256`; provisioning only, no
network probe. `gen.sh` extracts the verbatim TERM-copy statement from the
fetched `answer.cpp` into `vuln320b.inc`; the harness does not retype it.

Clean-archive replay (replace `<commit>` with the commit containing this
lane):

```
git archive <commit> lab/frontier/synchronet2shell | tar x -C /tmp/sync-320b
cd /tmp/sync-320b/lab/frontier/synchronet2shell/release-label/term320b
bash run-term320b.sh
```

Raw `evidence/evidence.log` embeds absolute checkout paths, PIDs and ASLR
addresses, so compare normalized output (strip those tokens) or the pass
counts and the printed pointer values.

## Scope

This is a source-bound harness on the shipped 3.20b field layout: the
verbatim copy statement writes chosen bytes into a modeled `sbbs_t` prefix.
No 3.20b build, no SSH wire session, no dereference of the chosen pointers,
no measured control-flow impact, no witness verdict and no rung change.
The 64-byte cap is the same pinned source/wire bound as the 3.21e lanes.

## Author clean-archive receipt (2026-11-25 04:32Z)

Commit `28c3fe15`: `git archive 28c3fe15 lab/frontier/synchronet2shell | tar x
-C /tmp/sync-w19-320b`, then `bash run-term320b.sh` in the extracted lane:
**10 PASS / 0 FAIL**, rc 0, same `PTR_CONTROL_OK` values. Raw evidence sha256
`a6fc464b3b746fea0cc98a03592de576cfc51012d8bfd329cb2a1322da5d8995` in the
archive (author tree `d5a926a964a2bc492986eda9b497e603a53ed25c62e603a1700bdbf1a7a3a6df`);
the difference is volatile tokens only. After normalizing timestamps, PIDs,
ASLR addresses, checkout paths and BuildIds while preserving the chosen
pointer constants, both logs hash to
`a4612f97bddb1dc25037d53203ce491be2800693ef4271beef1e82a435ffcb72`.
Author replay, not a witness verdict.
