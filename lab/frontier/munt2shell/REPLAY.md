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
./frag_probe.sh          # W168: uses the static libs above, no source rebuild
./alphabet_probe.sh      # W170: same static libs, write-alphabet matrix
```

`prepare_src.sh` refuses a tarball whose sha256 differs from
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`, refuses
committed pins that differ from `PINS.sha256`, and checks the three pinned
files in each tree after extraction/patching. It replaces only
`real/src/vuln-2_8_3` and `real/src/fixed-1749f7f`; reruns are idempotent.
Fetching the tarball is provisioning, not testing; no probe leaves loopback.

`frag_probe.sh` compiles the isolated `frag_driver.cpp` against those four
static libraries and writes `real/evidence/frag-results.txt` plus sixteen
`frag-*.out` files. It deliberately does not touch `driver.cpp` or any
witness-replayed evidence. Expected rc matrix: `frag-many` 0 in every build;
`single-32768` 0 in every build; `single-32769` and `single-40001` rc=1 in
vulnerable gcc/clang ASan and rc=0 in fixed ASan; all plain builds rc=0 with
tail counts 0, 0, 1 and 7233 respectively.

`alphabet_probe.sh` compiles `alphabet_driver.cpp` against those same static
libraries and writes `real/evidence/alphabet-results.txt` plus twelve
`alphabet-*.out` files. Expected rc matrix: all-`0x6a` and `0x7f`-at-32768
rc=1 in vulnerable gcc ASan, rc=0 in fixed ASan; `0x80`/`0x85`/`0xf7`
variants rc=0 in vulnerable ASan. Every plain case rc=0; chosen tail bytes
in script order are 7233 (all-`0x6a`), 0, 0, 0, 0, 0, 7232 (`0x7f` at 32768).
Details: `real/ALPHABET.md`.

Author clean-archive replay at commit 9e7f58d (2026-11-23 ~17:44Z): from
`git archive HEAD lab/frontier/munt2shell` into `/tmp/w170-munt`, with the
provisioned pinned tarball copied into `real/src/` (that ignored directory is
not in the archive), `prepare_src.sh`, `build_and_run.sh` and
`alphabet_probe.sh` all completed. The 12-case rc matrix was identical to
the committed `alphabet-results.txt`, all seven plain `.out` files were
sha256-identical, and the two vulnerable ASan cases again reported
`heap-buffer-overflow` / `WRITE of size 40001` while the status/end cases
reported nothing. The `/tmp` copy was not retained; committed sources,
scripts and evidence are the durable record.

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

## Author clean-archive replay at commit b80ccf1 (2026-11-23 W171)

Wire-input lane (`real/wire_probe.sh`), from `git archive HEAD
lab/frontier/munt2shell` into `/tmp/w171-munt` with the provisioned pinned
tarball copied into the ignored `real/src/`:

```
cd /tmp/w171-munt/lab/frontier/munt2shell/real
./prepare_src.sh
./build_and_run.sh
sh wire_probe.sh
sh normalize_wire.sh | sha256sum
```

`prepare_src.sh` verified the tarball and all six pinned files; both pinned
static-library variants rebuilt from source. All 8 rc cases matched the
committed `wire-results.txt`, and the normalized digest was
`857c13a634fb8c53f1347ae1b51d70e53bf58073d75beace897bd8133da03a65`, equal
to two consecutive working-tree runs. `normalize_wire.sh` folds ephemeral
ports, ASan PIDs/ASLR addresses, the checkout prefix and ELF build IDs; the
build ID legitimately differs between checkout paths. The `/tmp` copy was
not retained; committed evidence is the record. Details and grade limits:
`real/WIRE_INPUT.md`, report §12.

## Author clean-archive replay at commit baa31e6 (2026-11-24 W182)

Post-overflow second-call lane (`real/reuse_probe.sh`), from
`git archive HEAD lab/frontier/munt2shell` into `/tmp/w182-munt`, with the
provisioned pinned tarball copied into the ignored `real/src/` directory:

```
cd /tmp/w182-munt/lab/frontier/munt2shell/real
./prepare_src.sh
./build_and_run.sh
./reuse_probe.sh
```

All six modes returned rc=0 with the same lines as the committed evidence.
All six `.out` files were sha256-identical to their committed counterparts:

```
08c321632656b2c6f8efd2b71ff11c6a5633f1e4a870835c05061419890dd831  reuse-vuln-repeat.out
f037f98259b74bd411b4e8f16c3ba859154ef670cf961c2abb4b304ff0e016fa  reuse-vuln-safe.out
4dd5acb00a1e9b69a0cf07a47db8b703ca4c5ad7c2400ea4acdce6db9094d3da  reuse-vuln-baseline.out
5057baba9f67fc5b54b40021a0f1d159e254613b2dfac408bac276f846afeefb  reuse-fixed-repeat.out
f037f98259b74bd411b4e8f16c3ba859154ef670cf961c2abb4b304ff0e016fa  reuse-fixed-safe.out
4dd5acb00a1e9b69a0cf07a47db8b703ca4c5ad7c2400ea4acdce6db9094d3da  reuse-fixed-baseline.out
```

The vuln/fixed safe and baseline pairs are expected to share digests: neither
path writes chosen bytes past the allocation. The `/tmp` copy was not
retained. Details and grade limits: report §21; grade unchanged (rungs 1-4
ESTABLISHED, rung 5 UNKNOWN).

## Author clean-archive replay at commit 1a02552f (2026-11-24 W183)

Downstream-allocator-consumer lane (`real/live_probe.sh`), from
`git archive HEAD lab/frontier/munt2shell` into `/tmp/w183-munt`, with the
provisioned pinned tarball copied into the ignored `real/src/` directory:

```
cd /tmp/w183-munt/lab/frontier/munt2shell/real
./prepare_src.sh
./build_and_run.sh
./live_probe.sh
```

`prepare_src.sh` verified the tarball and both pinned-file sets; the plain
static libraries were rebuilt from source. All seven cases reproduced the
committed rc matrix (`shaped` 0, `unshaped` 134, `none` 0, `safe` 0, fixed
`safe` 0, fixed `fixed` 0, `shaped-nobuf` 0). Because the driver prints ASLR
pointers, comparison used `sed -E 's/0x[0-9a-f]+/0xADDR/g'` on all seven
`.out` files plus `live-results.txt`: all eight normalized files were
byte-identical to the committed evidence (`FAIL=0`). The `/tmp` copy was
not retained. Details and grade limits: `real/LIVE_CONSUMER.md`, report §22;
grade unchanged (rungs 1-4 ESTABLISHED, rung 5 UNKNOWN).

## Author clean-archive replay at HEAD cd77ba27 (2026-11-25 W188)

W187's precondition lane (`real/precondition_probe.sh`, commit `196af83a`) was
replayed from `git archive HEAD lab/frontier/munt2shell` into `/tmp/w188-munt`.
No commit touched these scoped paths between `196af83a` and HEAD, so the
archived source, scripts and evidence are the W187 bytes. The ignored pinned
tarball was copied into `real/src/` before preparation:

```
cd /tmp/w188-munt/lab/frontier/munt2shell/real
./prepare_src.sh
./build_and_run.sh
./precondition_probe.sh
```

`prepare_src.sh` verified the tarball and all six pinned files in both
regenerated trees. `build_and_run.sh` appended the 32 gcc cases to the
archived `results.txt`; those 32 lines match the committed matrix
case-for-case (the archived file's first 34 lines are byte-identical to the
committed one; the last two are clang cases from a separate script not rerun
here). The precondition probe reproduced 8/8 rc cases (vulnerable plain/ASan
fresh 134/1, vulnerable plain/ASan precondition 0/0, fixed 0/0). All eight
`.out` files and `precondition-results.txt` were identical after normalizing
checkout prefix, PID, ASLR addresses and ELF build IDs, except that the
replaying `/bin/sh` appended its own `Aborted (core dumped)` line to the
vulnerable plain fresh case; the program's `double free or corruption (!prev)`
line and rc 134 match. This is an author replay, not an independent witness
verdict; the `/tmp` copy was not retained. Grade unchanged: rungs 1-4
ESTABLISHED (witness #2781), rung 5 UNKNOWN. Report §27.
