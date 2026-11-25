# REPLAY — fontforge2shell W196 (2026-11-24 04:42Z)

Clean-archive replay of the staged evidence from commit `e5e4a65`
(brief, harness, pinned source and fix patch are all tracked; build
artifacts are intentionally untracked).

```sh
git archive e5e4a65 | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell" && sh run-all.sh > replay-all.log 2>&1
grep -E '^asan-|plain-|normalized gdb' replay-all.log | sha256sum
```

Result: 5/5 expected return codes — `asan-attack 1`, `asan-fixed 0`,
`asan-safe 0`, `plain-attack 134`, `plain-fixed 0` — and the same gdb
bytes `4d 49 53 00` at `encs-4`. The normalized transcript hash
(`grep -E '^asan-|plain-|normalized gdb' … | sha256sum`) is byte-exact
between the author's evidence log and the replay:

`56fd8adaa060730e30174414d17ac0c0a55cdd7badf3a516d498821e465633bb`

Raw `evidence/gdb.txt` hashes differ only because of ASLR/PID/address
tokens (`f6af356a…7992` author, `1c389b1b…68d844` replay); the normalized
bytes line and the RC matrix are identical. Harness sha256 is identical
in both trees: `401bad9634b3227263d0a0ed33ff8fc3acc11608df9ab568d614a90862e5ddbe`.

This is an author-side replay, not an independent witness verdict. No
real FontForge build, PCF GUI/Import path, pointer control, command or
rung 5 is claimed by the W196 section above; W9 below adds real-build
lanes at the labeled scope.

## W9 — clean-tree one-command replay of the real-build lanes (2026-11-24 23:5xZ)

`replay-real.sh` builds four trees from the pinned source and fix patch and
replays the W2-W8 real-path lanes without network, loopback or a GUI. Run it
from a clean archive of a commit containing the script (here `HEAD` before
the W9 commit), with the local source tarball supplied by env:

```sh
git archive HEAD lab/frontier/fontforge2shell reports/frontier-fontforge2shell.md | tar -x -C "$TMP"
cp lab/frontier/fontforge2shell/replay-real.sh "$TMP/lab/frontier/fontforge2shell/"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh
```

Inputs re-verified in the clean tree: `fontforge/fvimportbdf.c` sha256
`df766f9c881848cc4ea57456678e67c0e85fcf2a6ed308d1912b54181f0eb30d`,
tarball `613424039e0e1b6bb106f8f0df287e1d249ac285d854f4e1964d68e9b9ad7eb0`,
`truncated.pcf` `0c8dc0fe…d528703`, `complete.pcf` `149f03de…8eaa1526`,
`size-91.pcf` `e29a2e46…f93d40f27f3c9dd2`, `sponge-32.pcf`
`129afa8d…14f62350f`. CMake cache values matched the live-tree build
(same set of `ENABLE_*` and `CMAKE_BUILD_TYPE=Debug` values).

Observed return codes (`/tmp/ff2s-replay.log`, 23:52-23:54Z):

| lane | plain | fixed plain | ASan | fixed ASan |
|---|---|---|---|---|
| W8 `Open()` truncated PCF | 134 | 0 | 1 | 0 |
| W8 `Open()` complete control | 0 | — | 0 | — |
| W6 size-91 then 32-glyph import | 134 | 0 | 1 | 0 |
| W7 size-71 then choice-4 import | 139 | 0 | 1 | 0 |

The W8 RC matrix matched the authored one (rc 134/0/1/0 plus 0/0
controls). ASan reported `WRITE of size 4` four bytes before a 16-byte
region at `fvimportbdf.c:1751` on every vulnerable lane; all patched
builds exited 0.

Negative result, preserved: the W6 and W7 *post-overflow consumer* lanes
are build-path sensitive on this host. The same generated PCFs and the
same CMake values, built at `/tmp/lab/...` instead of the live lab path,
gave plain rc 134 (`free(): invalid next size (normal)`) and rc 139 for
W6/W7, where the live path build exited 0. Re-running the clean-tree
binaries with the live-path scripts reproduced rc 134/139, so the script
absolute path is not the cause; the two binaries' sha256 differ
(`bac0beae…5af7` live, `f3741145…f030` clean) even though the source and
cache values match. Embedded build paths reach the gettext locale path
used by the notice consumer. This does NOT change the rung-4 overflow
result (ASan WRITE at :1751 and the chosen `4d 49 53 00` at `encs-4` are
unchanged); it limits the consumer-lane rc claims to the exact build
path measured in `CONSUME.md` / `FILECHOICE.md`. No pointer/IP, command
or rung-5 claim is made from either outcome. Author-side receipt, not an
independent witness verdict.


## W11 — file-chosen pointer dereference in the same replay driver (2026-11-25 01:2xZ)

`replay-real.sh` now appends a W11 section after the W9 hashes; it does not
change the W2-W9 lanes above. From this lab directory, with the four builds
already present (or after the script builds them from the pinned tarball):

```sh
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh
```

The appended section regenerates `replay-value-atk50-save.ff`,
`replay-value-probe-save.ff`, `replay-value-atkceiling-save.ff` and
`replay-gdb-deref.cmd` from `$PWD`, then runs the seven cases in
`DEREF.md` section 3. Author-side receipt at 01:24Z, replay rc 0 overall:

| case | observed rc |
|---|---|
| atk50 + Save, plain | 139 |
| in-bounds probe + Save, plain | 0 |
| ceiling + Save, plain | 139 |
| atk50 + Save, fixed plain | 0 |
| atk50 + Save, ASan | 1 (original WRITE-4 at :1751) |
| probe + Save, ASan | 0 |
| atk50 + Save, patched ASan | 0 |

gdb in the same driver: `SIGSEGV` at `SFDDumpBitmapChar sfd.c:1671`,
`pc=0x5555556d1883`, `pt = bfc->bitmap = 0x0000555500414243`. PCF hashes
printed by the replay match `DEREF.md`: atk50
`8f0da475…4fd67`, atkceiling `54408140…8bbdb`, probe `4b37ed44…67d7b6`.

This is another author-side replay on the same host, not an independent
witness verdict. No full pointer control, chosen mapped target, marker
execution, command or r5 is claimed.

## W12 — true write-value ceiling 0x01FFFE00 (2026-11-25 01:5xZ)

`make-value-ceiling-high.py` regenerates `value-ceiling-high.pcf` (131361
bytes), `import-value-ceiling-high.ff` and `gdb-value-ceiling-high.cmd` from
the pinned `truncated.pcf`. With the four builds present, from this directory:

```sh
python3 make-value-ceiling-high.py
gdb -q -batch -x gdb-value-ceiling-high.cmd ./build-plain/bin/fontforge
for b in build-plain build-fixed-plain build-asan build-fixed; do
  ASAN_OPTIONS=detect_leaks=0 ./$b/bin/fontforge -script import-value-ceiling-high.ff >/dev/null 2>&1
  echo "$b rc=$?"
done
```

Expected: gdb `HIT glyph=-1 i=65535`, `$1 = 0x1fffe00`, watchpoint word
`0x01fffe0000000021`, bytes `00 fe ff 01` at `encs-4`; rc row
134/0/1/0 in `ceiling-high-controls.txt`. This corrects W10/W11's
`0x0100FEFF` "hard ceiling" overclaim (`CEILING-CORRECTION.md`); byte 3 is
still only `0/1`, no mapped target and no r5. Author-side replay on this
host, not an independent witness verdict.


## W13 — one-command real replay with a self-checking oracle (2026-11-25 02:4xZ)

The real-path offer is now a single command with an explicit pass/fail
oracle, so a replay does not have to interpret rc tables by hand. W13 adds
the W12 high-ceiling lane to `replay-real.sh` and asserts 17
build-path-independent cases. The W6/W7 post-overflow consumer lanes stay
informational: W9 measured their rc as build-path sensitive on this host.

From a clean archive, with the local source tarball supplied by env:

```sh
git archive <commit> lab/frontier/fontforge2shell | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh
```

Expected assert block:

| lane | expected rc (plain / fixed-plain / ASan / fixed ASan) |
|---|---|
| W8 `Open()` truncated | 134 / 0 / 1 / 0 |
| W8 `Open()` complete control | 0 / — / 0 / — |
| W11 atk50+Save, probe+Save, ceiling+Save (plain) | 139 / 0 / 139 |
| W11 atk50+Save fixed-plain / ASan / probe ASan / fixed ASan | 0 / 1 / 0 / 0 |
| W12 high-ceiling | 134 / 0 / 1 / 0 |

Script rc 0 and the final line `REPLAY_REAL_OK: 17/17 stable-lane checks
passed`. The W12 gdb section prints `HIT glyph=-1 i=65535`, `$1 =
0x1fffe00` and watchpoint word `0x01fffe0000000021`; the PCF hash is
`9a6b2603a873afc55819734ef3dada52232e6a2647502fd06ab04764ec2f6b82`.

Author-side receipts, both 17/17 `PASS` with script rc 0 and the W12 gdb
lines and PCF hash above: live lab tree at 02:46Z, and a clean git archive
of `HEAD` into `/tmp/ff2s-w13-clean` at 02:5xZ with the extended script
copied in and the pinned tarball supplied by env (that run rebuilt all four
build trees from source). Neither is an independent witness verdict. No
full pointer control, chosen mapped target in the default PIE build, marker,
command or r5 is claimed. W14 below adds a chosen mapped address in a local
non-PIE build only, dereferenced as data.

## W14 — non-PIE chosen mapped-address dereference (2026-11-25 04:1xZ)

`make-nonpie-case.py` regenerates two attack PCFs and the in-bounds control
from pinned `truncated.pcf`; `replay-nonpie.sh` builds vulnerable and patched
headless trees with `-DCMAKE_EXE_LINKER_FLAGS=-no-pie` and asserts 15 stable
lanes. From a clean archive of a commit containing the script:

```sh
git archive <commit> lab/frontier/fontforge2shell | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-nonpie.sh
```

Expected: both binaries are `EXEC (Executable file)`; gdb at `sfd.c:1671`
shows `bfc->bitmap=pt=0x414243` / `0x5a4344` with distinct mapped `.text`
bytes (`0f 5e 45 f0` vs `8b 30 8b 4d`); plain rc 0 for both, patched and
in-bounds controls keep a heap pointer and rc 0; saved SFDs differ. Final
line `REPLAY_NONPIE_OK: 15 checks, 0 failed`, script rc 0. Full evidence and
limits in `NONPIE.md`. Author-side, not a witness verdict; no branch,
marker, command or r5, and no shipped-default claim.

## W15 — negative code-pointer sweep of the write window (2026-11-25 04:4xZ)

With `build-plain` (from `replay-real.sh`) and `build-nopie` (from
`replay-nonpie.sh`) present, one command scans every 8-byte-aligned word in
`encs-131072 .. encs-4` at the vulnerable store for a value in that build's
`r-xp` mapping:

```sh
sh replay-w15.sh
```

Expected: `CAND_COUNT 0` / `RESULT NONE` for the default PIE build;
`RESULT ASCII_ONLY` for the non-PIE build with a bounded count (0..8),
the final line `REPLAY_W15_OK: 6 checks, 0 failed` and rc 0. The exact
non-PIE count is build-path sensitive: 6 ASCII fragments in the live tree,
5 in a clean archive, all short strings (`nis`, `ell`, `ENT`, ...), never
code pointers. An earlier oracle asserted exactly 6 and failed on the
clean archive; the check now asserts the path-independent invariant.
Full method, decision rule and limits in `FUNCTIONPTR.md`. Author-side
negative, not a witness verdict: no live function pointer reachable in
either measured build at write time, so W14's mapped address remains data.

## W16 — negative-divisor write byte (2026-11-25 05:5xZ)

With both build sets present (`replay-real.sh`, `replay-nonpie.sh`), one
command regenerates the negative-divisor PCFs, reruns both gdb transcripts
and checks the control matrix and mapping containment:

```sh
sh replay-negdiv.sh
```

Expected: `HIT glyph=-50 i=65532` in both transcripts, bytes
`fe 05 01 ff` at `encs-200`, pointers `0x00005555ff0105fe` (PIE) and
`0x00000000ff0105fe` (non-PIE), both outside every mapping printed in the
same transcript, all-skipped safe control rc 0 in six trees, vulnerable
plain/non-PIE rc 0, ASan rc 1 with `WRITE of size 4` at `:1751`, and the
final line `REPLAY_NEGDIV_OK: 20 checks, 0 failed` with rc 0. The huge
in-bounds variant faults in patched builds too and is not a control.
Full arithmetic, hashes and disposition in `NEGDIV.md`. Author-side
negative for mapped-target reach, not a witness verdict; grade unchanged.

Clean-archive receipt: commit `c9c5b891`, rebuilt all six trees with
`FF2S_TARBALL=<local pinned tarball>`; `replay-real.sh` 17/17,
`replay-nonpie.sh` 15/15 and `replay-negdiv.sh` 20/20, each rc 0. The four
PCF hashes and `replay-negdiv-mapping.out` hash are byte-identical to the
live tree (`070fcf9a…c5a9d26a7`). Author-side replay, not a witness verdict.

## W17 — one command for all three real-build suites (2026-11-25 06:4xZ)

`replay-all.sh` runs `replay-real.sh`, `replay-nonpie.sh` and
`replay-negdiv.sh` in order and checks each suite's own final oracle line,
so a witness can replay every author-side real-build lane in one incident:

```sh
git archive <commit> lab/frontier/fontforge2shell | tar -x -C "$TMP"
cp lab/frontier/fontforge2shell/src/fontforge-20251009.tar.gz \
   "$TMP/lab/frontier/fontforge2shell/src/"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=src/fontforge-20251009.tar.gz sh replay-all.sh
```

Expected: `PASS replay-real.sh rc=0 [REPLAY_REAL_OK: 17/17 stable-lane
checks passed]`, `PASS replay-nonpie.sh rc=0 [REPLAY_NONPIE_OK: 15 checks,
0 failed]`, `PASS replay-negdiv.sh rc=0 [REPLAY_NEGDIV_OK: 20 checks, 0
failed]`, twelve normalized evidence hashes (including
`replay-negdiv-mapping.out` =
`070fcf9a9de051aaa00976fb47e15ff3bd4e768c4d4990d6a0f8a97c5a9d26a7`),
final line `REPLAY_ALL_OK: 3 suites (17 + 15 + 20 = 52 checks), 0 failed`,
rc 0. Live-tree receipt at 06:47Z: 3/3 suites, 52/52 checks, 16 s.

This is a wrapper, not a new experiment: each underlying suite already has
its own clean-archive receipt (W9/W13/W14/W16 above). No grade change, no
witness verdict, no r5. It supersedes the separate #4047 (default path)
and #4098 (non-PIE) offers by adding W16's previously unoffered suite.
