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
**W26 reach correction:** `getformint16()` (`fvimportbdf.c:1354-1363`)
does not sign-extend. Complete two-byte indices are `0..65535`; only EOF
(`-1`) or a present low byte followed by EOF (`low-256`, i.e. `-256..-1`)
can pass the vulnerable guard. The actual write window is therefore
`encs-1024 .. encs-4`, not the 128 KiB range asserted in W15/W18/W23/W24/W25.
Those earlier scans covered a superset and remain valid negatives for the
bytes they scanned, but their "full signed-16-bit window" wording was wrong.


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

Clean-archive receipt at `efdb6d31` (06:49Z): fresh `/tmp/ff2s-w17-clean`
archive, all six trees rebuilt offline from the pinned tarball,
`sh replay-all.sh` 3/3 PASS (17/17, 15/15, 20/20), final
`REPLAY_ALL_OK: 3 suites (17 + 15 + 20 = 52 checks), 0 failed`, rc 0.
All twelve hashes are byte-identical to the live tree, including
`070fcf9a…c5a9d26a7`. Author-side replay, not a witness verdict.

## W18 — changed-allocation-state sweep (2026-11-25 09:2xZ)

`replay-w18.sh` imports `complete.pcf` before the pinned `truncated.pcf`,
proving `encs` moved (`+0x730` in both builds versus W15's single-import
baseline), then repeats W15's full-window code-pointer scan. Prerequisites:
`replay-real.sh`, `replay-nonpie.sh` and `replay-w15.sh` in the same tree.

```sh
cd lab/frontier/fontforge2shell && sh replay-w18.sh
```

Expected: 7/7 checks, rc 0, final line `REPLAY_W18_OK: 7 checks, 0 failed`.
PIE `CAND_COUNT 0` / `RESULT NONE`; non-PIE `RESULT ASCII_ONLY` with a
bounded path-sensitive count (6 in the live tree). Normalized hashes:
`alloc-w18.out` `fb1b4ea8…94e4f7c4b381af2fdc48290bebf5bd6df7a`,
`scan-w18-nopie.out` `971214f7…cad14adafafc7b8e4d`, and
`scan-w18-pie.out` `313c4ce4…6a2176094` (byte-identical to W15's PIE scan).
Full method, raw dump hashes and limitations in `ALLOCSTATE.md`. Author-side
negative, no witness verdict, no grade change, no r5.

Clean-archive receipt at `42e0f33f` (09:32Z): archive extracted to
`/tmp/ff2s-w18-clean-I5iWW8`, pinned tarball copied in, both offline builds
and the W15 baseline rebuilt; `replay-real.sh` 17/17, `replay-nonpie.sh`
15/15, `replay-w15.sh` 6/6, `replay-w18.sh` 7/7, chain rc 0. The PIE scan
hash `313c4ce4…6a2176094` is byte-identical to the live tree; the non-PIE
scan has three printable fragments instead of six and the `encs` delta is
`+0x7b0` instead of `+0x730` (W9/W15 build-path sensitivity). No candidate
is a code pointer in either tree. Author-side replay, not a witness verdict.

## W23 — tcache-disabled allocation state sweep (2026-11-25 15:0xZ)

`replay-w23.sh` repeats the full-window code-pointer scan under a third
allocator state, `GLIBC_TUNABLES=glibc.malloc.tcache_count=0`, with no new
build. It first records an untuned baseline transcript and requires `encs`
to move in the notcache lane, proving the state actually changed, then
scans for live code pointers. Prerequisites: `replay-real.sh` and
`replay-nonpie.sh` in the same tree.

```sh
cd lab/frontier/fontforge2shell && sh replay-w23.sh
```

Expected: 12/12 checks, rc 0, final line `REPLAY_W23_OK: 12 checks, 0 failed`.
Same `glyph=-1, i=3` store in both lanes. PIE `CAND_COUNT 0` / `RESULT NONE`;
non-PIE `RESULT ASCII_ONLY` with a bounded path-sensitive count (7 in the
live tree). `encs` moved `-0x3f0` (non-PIE) and `-0x4f0` (PIE). Normalized
hashes: `scan-w23-pie.out` `313c4ce4…6a2176094` (byte-identical to W15's
and W18's PIE scans), `scan-w23-nopie.out`
`249952b3…de64637a743d6`. Full method, gdb transcripts and limitations in
`ALLOCSTATE-TCACHE.md`. Author-side negative, no witness verdict, no grade
change, no r5.

Clean-archive receipt at `f2dd5a78` (15:2xZ): archive
`/tmp/ff2s-w23-clean.V2F1KD`, pinned tarball hash
`6134240…d68e9b9ad7eb0` verified, both offline builds rebuilt;
`replay-real.sh` 17/17, `replay-nonpie.sh` 15/15 and `replay-w23.sh` 12/12,
each rc 0. The PIE scan hash `313c4ce4…6a2176094` is byte-identical to the
live tree (and W15/W18). The non-PIE scan is `RESULT ASCII_ONLY` with a
different build-path-sensitive count (4 vs 7), like W9/W15/W18; no code
pointer in either. `encs` moves again in the clean tree (non-PIE `0xa92220
-> 0xa91b70`; PIE `0x555555c48430 -> 0x555555c47c80`). Author-side replay,
not a witness verdict.

## W24 — third build (`RelWithDebInfo`, -O2 PIE) sweep (2026-11-25 18:0xZ)

W23 left "another build" UNKNOWN. W24 builds the same pinned vulnerable
source with `-DCMAKE_BUILD_TYPE=RelWithDebInfo` instead of `Debug` (same
option set and tarball, default PIE) and runs the W15 full-window scan:

```sh
cd lab/frontier/fontforge2shell
FLAGS='-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_GUI=OFF -DENABLE_NATIVE_SCRIPTING=ON -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBSPIRO=OFF -DENABLE_LIBGIF=OFF -DENABLE_LIBJPEG=OFF -DENABLE_LIBPNG=OFF -DENABLE_LIBREADLINE=OFF -DENABLE_LIBTIFF=OFF -DENABLE_WOFF2=OFF -DENABLE_HARFBUZZ=OFF -DENABLE_SANITIZER=none'
cmake -S src/fontforge-20251009 -B build-rel $FLAGS > build-rel-configure.log 2>&1
cmake --build build-rel --target fontforgeexe -j2 > build-rel-build.log 2>&1
sh replay-w24.sh
```

Expected: 3/3 checks, rc 0, final line `REPLAY_W24_OK: 3 checks, 0 failed`.
gdb hits `fvimportbdf.c:1751` with `W24 encs=0x555555b2f240 glyph=-1
i=3`; the build's executable r-xp range is
`0x5555555bc000..0x555555824000`. Scan: `CAND_COUNT 0` / `RESULT NONE`,
hash `6d3399d2c9d19b36d616325913399fc55a61deeb07d60e09e04d79f418c326be`
(live tree). Method, hashes and limitations in `THIRDBUILD.md`. Author-side
negative, no witness verdict, no grade change, no r5. No replay demand is
added; #4165 remains the single bundled offer.

Clean-archive receipt at `115ae976` (18:04Z): archive
`/tmp/ff2s-w24-clean.ex9aFH`, pinned tarball hash
`6134240…d68e9b9ad7eb0` verified, source extracted from the tarball and
`build-rel` rebuilt offline with the same cmake flags. `sh replay-w24.sh`
3/3 PASS, rc 0, `REPLAY_W24_OK: 3 checks, 0 failed`. `encs` is
`0x555555b2f430` (build-path sensitivity, live `0x555555b2f240`), same
`glyph=-1 i=3` store; the normalized scan hash
`6d3399d2c9d19b36d616325913399fc55a61deeb07d60e09e04d79f418c326be`
is byte-identical to the live tree, with `CAND_COUNT 0` / `RESULT NONE`.
Author-side replay, not a witness verdict.

## W25 — late-allocation-state scan (2026-11-25 18:4xZ)

W15/W18/W23/W24 scanned the write window at the vulnerable store and left a
later-created object UNKNOWN. With `build-plain` and `build-nopie` present:

```sh
cd lab/frontier/fontforge2shell && sh replay-w25.sh
```

`replay-w25.sh` drives `New(); Import(truncated.pcf); Save(...)`, stops at
`fvimportbdf.c:1751 if glyph < 0`, saves `encs`, sets a later breakpoint at
`sfd.c:1671`, continues and dumps the same 128 KiB window at the resulting
stop. Both builds hit `glyph=-1 i=3` and then abort at the corrupted free
with `double free or corruption (out)` before the later breakpoint. The
PIE scan is `CAND_COUNT 0` / `RESULT NONE` (hash
`313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76`,
byte-identical to W15/W23); non-PIE is `CAND_COUNT 5` / `RESULT ASCII_ONLY`
(hash `2c980b3dbe6842de7666460e55bbd1ce886ec91ff9c50cb3ece659aad77f63c0`,
all short printable fragments). Expected oracle: 8/8 checks, rc 0, final
line `REPLAY_W25_OK: 8 checks, 0 failed`. Method, hashes and limits in
`LATESTATE.md`. Author-side negative, no witness verdict, no grade change,
no r5; a PCF/grooming variant that survives the free, a GUI callback or a
deliberately planted called function pointer remains UNKNOWN.

Clean-archive receipt at `96ee8154` (18:45Z): archive
`/tmp/ff2s-w25-clean.GNE18I`, pinned tarball hash
`613424039e0e1b6bb106f8f0df287e1d249ac285d854f4e1964d68e9b9ad7eb0`
verified, `build-plain` and `build-nopie` rebuilt offline with the same
cmake flags; `sh replay-w25.sh` 8/8 PASS, rc 0. Both lanes again hit
`glyph=-1 i=3` and abort at the corrupted free before the later
breakpoint; `encs` moved (`0x555555c48460` PIE, `0xa92250` non-PIE).
PIE scan hash
`313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76`
is byte-identical to the live tree; non-PIE is `CAND_COUNT 4` /
`RESULT ASCII_ONLY` (build-path sensitive count), hash
`457b05b47f43feb767d332c40bd504bd5fbdd5987387e353a8ca68e8bcb87ae5`.
Author-side replay, not a witness verdict; no grade change.
## W26 — actual reach correction and surviving-free later scan (2026-11-25 19:2xZ)

With `build-plain` and `build-nopie` present:

```sh
cd lab/frontier/fontforge2shell && sh replay-w26.sh
```

The script proves the decoder boundary in both builds: a complete `0xBEF2`
index is `glyph=48882 accepted=0`; the same low byte `0xF2` with the high
byte missing is `glyph=-14 accepted=1`. It then uses W7's surviving poison
`size-71.pcf` plus `choice-4.pcf`, stops when the second import's real
`pcf_properties.props` equals the original `encs`, scans only the reachable
`encs-1024..encs` window against **every** `r-xp` mapping, and continues to
the later `Save()` consumer. Both builds reach the props consumer and Save;
both scans are `CAND_COUNT 0` / `RESULT NONE`. Oracle: 18/18 checks, rc 0,
final line `REPLAY_W26_OK: 18 checks, 0 failed`.

Normalized hashes: `scan-w26-pie.out`
`b88042281496bd3687aa256fc2832ce070f73db7dfd8ea2c8ca04389f8d1887a`;
`scan-w26-nopie.out`
`eb4d373e8b716dbb2ef3287700f0757a0d1360f39029702e094311eb7452a321`.
Method and the preserved unreachable-gconv lead are in `LATESTATE.md`.
Author-side correction/negative, not a witness verdict; no grade change,
no branch, marker, command or r5. No new replay demand; #4165 stays queued.

## W27 — called-pointer lane closure (2026-11-25 20:0xZ)

With `build-plain` and `build-nopie` present:

```sh
cd lab/frontier/fontforge2shell && sh replay-w27.sh
```

The script measures the heap `Encoding` object's field offsets (72/80/88/96)
against `encs` in both builds, shows both direct function-pointer fields are
NULL with no assignment site in the source, traces one writable negative
index per truncated file (`truncated.pcf`: `i=3 glyph=-1`), and drives a
file-derived overwrite of the live `tounicode` descriptor with `0x414243`.
Non-PIE produces `tounicode=0x414243` and `iconv cd=0x414243`; PIE inherits
the high dword (`0x555500414243`). Both reach `iconv` from `UniFromEnc`, then
fault in glibc `__gconv` at `gconv.c:45` before any indirect call. Oracle:
23/23 checks, rc 0, final line `REPLAY_W27_OK: 23 checks, 0 failed`.

The `Encoding`/`encs` distance is argv-sensitive, so `w27-target.py` derives
the glyph index from each transcript; all three gdb runs in a lane reuse one
command-file path to keep the measured distance valid for the write run.
Normalized hashes (`^W27` lines only, excluding volatile PID lines):
`686cf6af93bc290e19450c6ecdd998e1f456c8fcf79bbd90ff686c3dce1e0f16`
(pie fields), `c259f977eabd3f20b31dbe9393310d765eca087cdb5728d17a062b15066dc743`
(non-PIE fields),
`1268fefa2e8bb4b8faeb941c262a95286a4fd91c3ce718c682f49351c61a7378`
(pie glyph trace),
`a61310d3646425356ffd63a579b8c5340deab671992e17fbf17a26a19016bcb4`
(non-PIE glyph trace),
`462f15a3639881f0fb2bc99944850bff6501a344bacb5096a0a86070092576e1`
(pie callpath),
`42438481fe1952363efb82854de39892f60c373d438c0e7e8d952f34fa6a97e6`
(non-PIE callpath). Method and limits: `CALLEDPATH.md`. Author-side negative,
not a witness verdict; no branch, marker, command or r5. No new replay
demand; #4165 stays queued.

## W28 — two-import function-pointer lane (2026-11-25 21:3xZ)

With `build-plain` and `build-nopie` present:

```sh
cd lab/frontier/fontforge2shell && sh replay-w28.sh
```

Two crafted PCFs make two negative-glyph writes in one non-PIE process: the
first zeroes the live `Encoding.tounicode` descriptor at `encs-696` (plain
rc 0, so the process survives), the second tries to set `tounicode_func` at
`encs-680` to the chosen non-PIE `putchar@plt` address `0x406ec0`. Gdb shows
`delta=-768` at the first store but `delta=-5632` at the second: each import
reallocates `encs` far from the cached `Encoding`, so the function-pointer
slot is never written and `encoding.c:2593` is never reached. A 0..8
benign-import sweep keeps `encname` fixed and moves the second `encs`
5632..63696 bytes away; `New()` between imports gives `+67120`. Oracle:
11/11 checks, rc 0, final line `REPLAY_W28_OK: 11 checks, 0 failed`.
Method, hashes and limits: `FUNCPATH.md`. Author-side negative, not a
witness verdict; no branch, marker, command, r5 or grade change. No new
replay demand; #4165 stays queued.


## W29 — two stores in one table, forced second offset (2026-11-25 23:4xZ)

With `build-plain` and `build-nopie` present:

```sh
cd lab/frontier/fontforge2shell && sh replay-w29.sh
```

`make-twostore-case.py` truncates the PCF after one encoding-index byte and
sets `tot=2`, so iteration 0 writes `encs[-8]` with glyph `-2`/value 0 and
iteration 1 writes `encs[-4]` with glyph `-1`/value 1 in the same `encs`
allocation. Gdb prints `W29S1 i=0 glyph=-2 value=0 word[-8]=0x21 word[-4]=0`,
`W29S2 i=1 glyph=-1 value=1` and `W29POST word[-8]=0 word[-4]=0x1` in both
builds; plain non-PIE rc 134. The second offset is forced by sticky EOF and
its value is dependent (V0+1 or V0+256), so no second chosen destination;
duplicate TOC entries cannot give a second table because `pcfSeekToType()`
takes the first match. Oracle: 16/16 checks, rc 0, final line
`REPLAY_W29_OK: 16 checks, 0 failed`. Method, hashes and limits:
`TWOSTORE.md`. Author-side negative, not a witness verdict; no branch,
marker, command, r5 or grade change. No new replay demand; #4165 stays queued.
