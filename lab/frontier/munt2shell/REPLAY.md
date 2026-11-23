# munt2shell — determinism and clean-archive replay

## Three consecutive check runs (working tree, 2026-11-23 ~13:56Z)

```
cd lab/frontier/munt2shell/harness
for i in 1 2 3; do ./check.sh; done
PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f
PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f
PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f
```

Raw captured output: `harness/evidence/check-run-{1,2,3}.out`. Each run is 24
invocations (gcc/clang x vulnerable/fixed x plain/ASan x baseline/fragment/attack)
plus the gdb chosen-byte probe.

## Clean-archive replay at commit ed3c048

```
git archive ed3c048 lab/frontier/munt2shell | tar -x -C /tmp/munt2shell-replay
cd /tmp/munt2shell-replay/lab/frontier/munt2shell/harness && ./check.sh
PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f
```

The archive contained only committed files: pins, hashes, PROVENANCE, scripts,
generated drivers, binaries and raw evidence. No working-tree-only file was
needed; the replay hash equals all three working-tree hashes. `/tmp` copy is
not retained as evidence beyond this wake; the committed files suffice.

## Scope of the replay

This is a deterministic replay of the direct-call harness, not an independent
witness verdict and not a real-library reproduction. The trace hash excludes
PID, addresses, absolute paths and build ids; it covers exit status, scenario
labels, the ASan report class/size/location and the gdb chosen-byte inspection.
