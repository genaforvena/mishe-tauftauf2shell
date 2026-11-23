# Real KiCad process probe (W181, 2026-11-23 22:47-23:05Z) — provisioning negative

## Provisioning (public release asset, not an external probe)

The official KiCad AppImage mirror was used only to provision a local binary:
`https://mirrors.mit.edu/kicad/appimage/stable/kicad-10.0.6-x86_64-lite.AppImage.tar`
(HTTP 200, `content-length: 302243840`, `last-modified: 2026-08-28T20:54:51Z`).
It is kept uncommitted under `lab/frontier/kicad2shell/provisioned/`:

- tar sha256 `8c789e36644856cff30a66801692881582b9ca7c7475699494e614ce1bcb1f9c` (302243840 bytes)
- extracted AppImage sha256 `806e949cb357f9f0a05c3298c36eecb2b06d79c0a36e12c99f75aad9c89f0792`
- `kicad-cli version` through the runtime prints `10.0.6` — the first stable
  release without the `if( ind < 1 ) continue;` guard (`FIXED-RELEASE.md`).

The AppImage is a Sharun/DwarFS image, not squashfs. `./AppImage --appimage-mount`
prints a live `/tmp/.mount_kicad...` path and keeps it mounted; commands below
used `$MP/bin/kicad-cli` from that mount. `--appimage-extract` twice failed to
finish (240 s reached 13%, a second 280 s pass reached 23%), leaving only a
partial `AppDir` (3031 of 39282 `share/kicad` files); that partial tree was not
used for the results below.

## Observed: CLI cannot select the Altium SCHLIB importer

`kicad-cli --help` on 10.0.6 lists `fp,jobset,pcb,sch,sym,version`; `sch` has
`erc,export,upgrade` and `sym` has `export,upgrade`. There is no `sch import`
or `sym import` in the released binary, although `kicad/cli/command_sch_import.cpp`
exists at the later pinned parent commit `bf3e3fa...`. So the importer cannot be
driven headlessly by that subcommand.

`kicad-cli sym export svg -o OUT vendor/<fixture>.SchLib` was run on all five
committed vendor fixtures (unmodified and the four `Size0`/`SizeZ` patches)
with `QT_QPA_PLATFORM=offscreen`, 20 s timeout, isolated output dirs. Every run
opened the named file (verified with `strace -f -e trace=openat` on the hostile
fixture), exited `rc=0`, wrote 0 stdout bytes, 0 stderr bytes and **0 SVG
files**. The native `.kicad_sym` control built in `provisioned/test-lib.kicad_sym`
exits `rc=0` and writes `TEST_unit1.svg` under the same CLI. This is a
deterministic *negative for this entry point*: released `kicad-cli` does not
route `.SchLib` through `SCH_IO_ALTIUM`, so `ParseLibHeader` was not reached.

A clean exit from a vendor binary without ASan is NOT a pass: it only shows
this command never exercised the vulnerable function.

## Observed: GUI headless attempt did not become a usable path

`Xvfb :99 -screen 0 1600x1000x24`, a locally unpacked `twm` (no root needed),
and `$MP/bin/eeschema` were started. The eeschema process entered uninterruptible
`Dsl` state within 8-15 s on two attempts; its window was created but never
rendered (root screenshots all black), and `import` dialogs could not be
reached. Killing the stuck eeschema was also necessary before other CLI calls
would respond. No symbol-library import was performed and no GUI crash was
observed; the cause of the GUI stall is UNKNOWN (FUSE/DwarFS I/O and absent
hardware GL are candidates, not conclusions).

## Ceiling

No real KiCad importer execution, no ASan-instrumented vendor binary, no
consumer, no socket/wire, no pointer/control-flow target, no marker or command.
The four-byte write and caller-chosen words remain established only in the
committed verbatim-slice lanes. Rung 5 stays UNKNOWN; witness #2996's verdict
is untouched. The next real-path move needs a working GUI/Symbol Editor import
(or a locally built `eeschema` with the Altium plugin) before the crafted
`.SchLib` can be said to reach `ParseLibHeader` in a full KiCad process.
