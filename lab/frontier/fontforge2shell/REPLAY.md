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
