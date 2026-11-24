# Native KiCad 8.0.8 real-process import (W182, 2026-11-23)

## What changed versus W181

W181 used the 10.0.6 AppImage, whose DwarFS (type 3) mount left eeschema in
uninterruptible `Dsl` state and whose CLI never selected the Altium plugin.
This lane uses a **native, locally extracted KiCad 8.0.8** — no FUSE, no root,
no AppImage extractor. The GUI Symbol Editor was driven to
`File > Import > Symbol...`, which really calls `SCH_IO_ALTIUM` on the supplied
`.SchLib`.

## Provisioning (all local, no install into the host)

- `kicad_8.0.8+dfsg-1_amd64.deb`, from
  `http://archive.ubuntu.com/ubuntu/pool/universe/k/kicad/kicad_8.0.8+dfsg-1_amd64.deb`,
  sha256 `ba875b23de8c4259c04f60906aa7a3c80dd0dd77abf2973ef16ac5b155b9c3bd`.
  `kicad-cli version` → `8.0.8`.
- Extracted with `dpkg-deb -x` into
  `lab/frontier/kicad2shell/provisioned/apt-kicad8/`; missing runtime pieces
  came from Ubuntu pool debs in `provisioned/apt-debs/` and were extracted into
  the same local tree: wxWidgets 3.2 runtime (3.2.4+dfsg-4build1, also used for
  the 7.0.11 attempt), `libnotify4` 0.8.3, `libgit2-1.9` 1.9.1+ds-1ubuntu1,
  `libpython3.13` / `-minimal` / `-stdlib` 3.13.3-1, `libglew2.2` and
  `libglu1-mesa`. `ldd apt-kicad8/usr/bin/eeschema` and
  `ldd apt-kicad8/usr/bin/_eeschema.kiface` have no missing libraries.
- Environment for every run:
  `LD_LIBRARY_PATH=$PWD/provisioned/apt-kicad/usr/lib/x86_64-linux-gnu:$PWD/provisioned/apt-kicad8/usr/lib/x86_64-linux-gnu`,
  `PYTHONHOME=$PWD/provisioned/apt-kicad8/usr`,
  `PYTHONPATH=$PWD/provisioned/apt-kicad8/usr/lib/python3.13`,
  `KICAD_CONFIG_HOME=$PWD/provisioned/kicad8-config`.
- First-run dialogs were pre-seeded, not guessed at runtime:
  `kicad8-config/8.0/kicad_common.json` (written by KiCad itself),
  `kicad8-config/8.0/local.kicad_sym` (empty symbol library, generator
  `kicad_symbol_editor`, version `20231120`) and a `sym-lib-table` registering
  that absolute path as library `local`. Without a library selected,
  `File > Import > Symbol...` shows "No symbol library selected." and never
  opens the file chooser; that was an observed negative, not a pass.
- Xvfb `:1xx`, 1280x1024x24, `-ac -nolisten tcp`, **no window manager**. The
  locally unpacked twm has a broken config that grabs the X server, so using it
  made `xwininfo`/`import` hang; dropping twm made every window query work.

## Source identity

Tag 8.0.8 of `KiCad/kicad-source-mirror`,
`eeschema/sch_io/altium/sch_io_altium.cpp`, sha256
`874481b47dbc2cb2aab51e4a19872b210158dde7243a8884aec37cee96ed0e39`, contains
the vulnerable sequence at lines 4491-4498:
`wxAtoi(remaining)` → `resize(ind)` → `aFontSizes[ind - 1] = scaled`.
Tag 7.0.11 has no `eeschema/sch_io/altium/` directory at all (Altium plugin
introduced in 8.0) and is a recorded negative.
The first stable fixed release remains 10.0.7 (`FIXED-RELEASE.md`).

## Exact driver

`provisioned/gui-import.sh <tag> <file> [gdb]` starts Xvfb, starts eeschema,
then sends the same clicks/keys on every run: dismiss the wxPython notice
(900,495), `Tools` (264,11), `Symbol Editor` (320,87), select library `local`
(60,157), `File` (20,11), `Import` (60,238), `Symbol...` (330,239), GTK
chooser `Ctrl+L`, type absolute `.SchLib` path, `Return`. Logs and screenshots
are `provisioned/gui-<tag>.{log,png}`. Coordinates are specific to the
1280x1024 Xvfb screen and this KiCad build.

## Observed results

- **Safe input** — unmodified vendor
  `vendor/mounting_holes.SchLib` (sha256
  `b510e91114cb2365117e01ece6c9709a11e0f1eaf1b016bef38419aa9beb56a0`).
  `gui-control-orig.png` shows `MH M2.5 Mounting hole` imported into `local`
  and selected in the symbol editor; the process was still alive in `Sl` after
  39 s and `gui-control-orig.log` is empty (sha256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
  This proves the real Altium plugin and `ParseLibHeader` were reached.
- **Hostile input** — one-byte patch at file offset 685,
  `vendor/mounting_holes-sizez.SchLib` (sha256
  `09ebf2aa9ca5dc9a52aa1edec4f55d5ca56913bd567114a127472ff90b286d23`;
  `Size2=9|` → `SizeZ=9|`, giving `ind=0` after uppercasing). Plain run:
  eeschema became a zombie and `eeschema8-import.log` contains exactly
  `double free or corruption (out)`. Replay under gdb: SIGABRT/Aborted,
  glibc `malloc_printerr` → `_int_free_merge_chunk` with
  `size=69818988363808`, then five frames in
  `provisioned/apt-kicad8/usr/lib/kicad/_eeschema.kiface` before `make_fcontext`;
  full transcript `gui-crash-gdb.log` (sha256
  `c59e789c750fb2b307c74cb178c1f00289520005edef9e61bfdcaafd729d0487`).
  The vendor kiface has no debug symbols, so those frames are not symbolized;
  the causal attribution rests on the pinned harness evidence plus the
  safe-input control, not on a gdb function name.
- **Second hostile patch** — `vendor/mounting_holes-size0.SchLib` (one-byte
  patch at file offset 650, `|Size1=10|` → `|Size0=99|`; sha256 recorded in
  `vendor/PINS-vendor.sha256`). With a freshly reset empty target library the
  real process died with `Segmentation fault (core dumped)`, exit **139**
  (`gui-crash-size0-rc.rc`, stderr empty). This matches the harness's distinct
  first-sorting-key fault mode (null-adjacent store), whereas the later-sorting
  `SizeZ` key corrupts malloc metadata: both predictions from the pinned
  harness were observed in a real KiCad process. The `SizeZ` abort also
  reproduced from a freshly reset target library (`gui-crash-fresh.log`,
  sha256 `ad7d25253d0821de30d58bc35ecdf0639ea0de6186822d2afb0780c325917dbe`).
  The `SizeZ` replay also recorded exit **134** (`gui-crash-sizez-rc.rc`,
  stderr `double free or corruption (out)`), matching the harness's glibc abort.
- The released binary has **no ASan**. A clean exit would not have been a
  pass; the observed abort is a real crash in a real KiCad 8.0.8 process.

## Ceiling (unchanged for rung 5)

Real process, real Altium plugin, real vendor-format bytes: yes. No ASan in
the vendor build, no fixed-build control in this real process (the fixed guard
is exercised in the committed harness lanes), no downstream consumer read, no
socket/wire delivery, no pointer or control-flow target, no benign marker or
command, no independent witness replay of this lane. This lane upgrades the
real-process reachability gap to a deterministic crash; it does not establish
rung 5, which stays UNKNOWN.

## W183 (2026-11-24 00:19-00:25Z): chosen bytes in the real process

The remaining real-process question was whether the four overwritten bytes
are *file-controlled*, not merely a constant abort. Five imports were run
through the same driver against a freshly reset 75-byte empty `local.kicad_sym`
each time; all five used `MODE=gdb`. The three one-digit fixtures are the
already-pinned vendor files; the two six-digit fixtures are new same-length
in-place patches of `mounting_holes-sizez.SchLib` at file offset 0x2ae:
`SizeZ=9|FontName2=Consolas|` → `SizeZ=<n>|FontName2=XXX|` (25 bytes before and
after, CFB structure untouched, sha256 in `fixtures/PINS-w183.sha256`).

The real KiCad 8.0.8 scale is `schIUScale.MilsToIU( wxAtoi(value) * 72.0 /
10.0 )`: `MilsToIU` truncates the mils to an integer and multiplies by
`IU_PER_MIL = 254`. The harness stub had only the truncated mils, which is why
its gdb words are 0x40/0x32/0x07 rather than the real 0x3f80/0x319c/0x6f2.
The OOB store sets the upper half of the freed chunk's size field (the lower
half stays 0x20), so the glibc `size=` in the SIGABRT backtrace is exactly
`(int(SizeZ * 72 / 10) * 254 << 32) | 0x20`:

| fixture | SizeZ | predicted / observed chunk size |
| --- | --- | --- |
| `mounting_holes-sizez.SchLib` | 9 | `0x3f8000000020` / `69818988363808` |
| `mounting_holes-sizez7.SchLib` | 7 | `0x319c00000020` / `54546084659232` |
| `mounting_holes-sizez1.SchLib` | 1 | `0x6f200000020` / `7636451852320` |
| `w183-sizez-138889.SchLib` | 138889 | `0xf23bb8000000020` / `1090921693184000032` |
| `w183-sizez-200000.SchLib` | 200000 | `0x15cd0e0000000020` / `1570927238184960032` |

All five were SIGABRT in glibc `_int_free_merge_chunk` with `double free or
corruption (out)` and the same five unsymbolized `_eeschema.kiface` frames.
The safe control (`w183-control.log`, empty; `.rc` `alive`) ran immediately
after a reset with the unmodified vendor file. Full transcripts, rc files and
the two new fixtures are in `evidence/` and `fixtures/`. The offline check
`sh chosen-byte-check.sh` reports PASS=16 FAIL=0, trace
`3b352f6ecf3cbdabf8987243460234e42626868df70dfee7a7de021ba427398a`; it
verifies pins, the exact predicted word in each transcript and the control.
It does not re-run the GUI and does not itself prove the crash.

This upgrades chosen-byte rung-4 evidence from the stubbed harness lanes into
a real KiCad 8.0.8 process: an ordinary file edit selects the exact four bytes
at a chosen heap offset. It is still not a pointer or control-flow target:
the word lands in the corrupted chunk's size field, and glibc aborts. No ASan
in the vendor build, no fixed-build control in this process, no downstream
consumer read, no wire delivery, no marker, no witness replay of this lane.
Rung 5 stays UNKNOWN.
