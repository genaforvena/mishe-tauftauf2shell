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

## Scope of the direct-call harness replay

This is a deterministic replay of the stubbed direct-call harness. It is
neither the real-library reproduction below nor the independent witness
verdict (chat #2781, §8 of `reports/frontier-munt2shell.md`). The trace hash
excludes PID, addresses, absolute paths and build ids; it covers exit status,
scenario labels, the ASan report class/size/location and the gdb chosen-byte
inspection.

## Real-library lane: clean-archive replay

`real/build_and_run.sh` and `real/build_clang_asan.sh` need two source trees
and a tarball; both trees and the tarball are gitignored, so a clean
`git archive HEAD lab/frontier/munt2shell` needs this preparation:

```
mkdir -p real/src
curl -fL --output real/src/munt-libmt32emu_2_8_3.tar.gz \
  https://github.com/munt/munt/archive/refs/tags/libmt32emu_2_8_3.tar.gz
cd real
./prepare_src.sh [path-to-tarball]
./build_and_run.sh       # gcc: 2 variants x {asan,plain} x 8 scenarios
./build_clang_asan.sh    # clang ASan: C API attack, vuln and fixed
```

`prepare_src.sh` refuses a tarball whose sha256 differs from
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`, refuses
committed pins that differ from `PINS.sha256`, and checks the three pinned
files in each tree after extraction/patching. It replaces only
`real/src/vuln-2_8_3` and `real/src/fixed-1749f7f`; reruns are idempotent.
Fetching the tarball is provisioning, not testing; no probe leaves loopback.

The independent witness (chat #2781) performed the equivalent preparation
and rebuild from a clean archive: 34/34 rc cases matched the committed
matrix, all 34 `.out` files were normalized-identical, and gcc and clang
ASan reproduced the 40001-byte overflow at upstream
`MidiStreamParser.cpp:250`. Verdict ESTABLISHED at real-library rungs 1-4,
NOT rung 5. Raw author outputs: `real/evidence/`; analysis:
`real/REAL_EVIDENCE.md`.

## Author clean-archive replay at commit 7423dc6 (2026-11-23 W167)

From `git archive HEAD lab/frontier/munt2shell` into `/tmp/w167-munt`, with
the provisioned tarball copied to `real/src/` (that ignored directory and
tarball are not in the archive):

- `harness/check.sh`: `PASS=129 FAIL=0 TRACE=735c136e1c6740ca…ac0d1146f`.
- `real/prepare_src.sh`: tarball hash OK; three pinned files verified in both
  regenerated trees; no working-tree-only file needed.
- `real/build_and_run.sh`: all 32 rc lines match the committed matrix
  case-for-case (compared programmatically against
  `real/evidence/results.txt`, first 32 lines).
- `real/build_clang_asan.sh`: vulnerable C API attack `rc=1`, fixed `rc=0`.
- Fresh ASan output again shows `WRITE of size 40001`, 0 bytes after a
  32768-byte region at upstream `MidiStreamParser.cpp:250` (gcc and clang);
  the plain C API attack reads back `tail_0x5a=7233/16384`.

Replay artifacts were left in `/tmp/w167-munt`, not committed; the committed
sources, pins, scripts and raw author evidence remain the durable record.
