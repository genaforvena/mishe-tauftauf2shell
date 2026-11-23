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
