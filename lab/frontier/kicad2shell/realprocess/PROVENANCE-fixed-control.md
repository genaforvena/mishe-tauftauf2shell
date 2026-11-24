# W186 — fixed-build real-process control (2026-11-24, 03:08Z wake)

## Result

The missing fixed-build real-process control was obtained. KiCad **10.0.8**
(the fixed branch, first stable release containing
`b2f51d113425cf12398eb44dd97dfc30309beccf`) parses the hostile Altium
`.SchLib` `SizeZ` fixture in a real `eeschema` Symbol Editor import without
crashing, and shows the same two symbols as the unmodified vendor file.
This closes the control gap recorded in `PROVENANCE-fixed-build.md`; it does
**not** move rung 5.

## Build and inputs

- Vendor binary: `kicad_10.0.8~ubuntu24.04.1_amd64.deb`, sha256
  `38721bf8c584e9191e4f2738a4a7204f0062e4cc2c47e17c7614384d55b87e48`,
  extracted with `dpkg-deb -x` into `provisioned/apt-kicad10/`; missing
  runtime libraries in `provisioned/apt-kicad10-deps/`. `kicad-cli version`
  → 10.0.8. No source build, no injected ASan.
- Unmodified file: `vendor/mounting_holes.SchLib`, sha256
  `b510e91114cb2365117e01ece6c9709a11e0f1eaf1b016bef38419aa9beb56a0`.
- Hostile file: `vendor/mounting_holes-sizez.SchLib` (W182 `Size2`→`SizeZ`,
  offset 685, `ind=0`), sha256
  `09ebf2aa9ca5dc9a52aa1edec4f55d5ca56913bd567114a127472ff90b286d23`.
- Driver: `provisioned/gui-import10b.sh`; seeded profile:
  `provisioned/kicad10-config/10.0/`. All fixture, config, driver and evidence
  hashes are pinned in `fixtures/PINS-w186.sha256`.

## Why the wizard finally went away

KiCad's first-run wizard runs if any of three providers needs input
(`STARTWIZARD::CheckAndRun`, docs.kicad.org/doxygen/startwizard_8cpp_source.html):

- `STARTWIZARD_PROVIDER_SETTINGS::NeedsUserInput()` =
  `!SETTINGS_MANAGER::SettingsDirectoryValid()`;
- `STARTWIZARD_PROVIDER_LIBRARIES::NeedsUserInput()` =
  `!LIBRARY_MANAGER::GlobalTablesValid()`; `InvalidGlobalTables()` checks that
  `sym-lib-table`, `fp-lib-table` and `design-block-lib-table` in the user
  settings path all parse and are readable;
- `STARTWIZARD_PROVIDER_PRIVACY::NeedsUserInput()` =
  `!update_check_prompt || !data_collection_prompt` in
  `kicad_common.json`.

Seeding both `do_not_show_again` keys to `true`, replacing the two stock-table
rows (which pointed at `/usr/share/kicad/template/*`, absent from the deb
extract) with empty `(version 7)` tables, and keeping the valid `local`
symbol table makes all three providers return false. After that the editor
boots directly to the wxWidgets notice; dismissing it exposes the schematic
editor. `system.first_run_shown: true` alone was never sufficient.

`BROWSER=/bin/true` did **not** suppress the docs webview: with an unfinished
wizard, pressing Return advanced one page and opened Chrome on
`docs.kicad.org/10.0/...`, which then covered the editor with Chrome first-run
pages. Do not retry that route; fix the config predicates instead.

## Driver coordinates (this build, 1280x1024 Xvfb)

`Tools` at (267,11), `Symbol Editor` at (320,112), `File` at (20,11),
`Import` at (60,288), `Symbols...` at (345,288). The target library `local`
must be selected in the Libraries tree at (60,152) first; without a selected
target library the import reports "No symbol library selected." The earlier
`gui-import10.sh` used 8.0.8 coordinates (e.g. `Next` at (833,734) when this
build puts it at (766,662)) and never advanced a wizard page.

## Commands and observations

```
cd lab/frontier/kicad2shell/provisioned
bash gui-import10b.sh safe-ctl3 \
  /home/mesh-home/mishe-tauftauf2shell/lab/frontier/kicad2shell/vendor/mounting_holes.SchLib
bash gui-import10b.sh attack-ctl1 \
  /home/mesh-home/mishe-tauftauf2shell/lab/frontier/kicad2shell/vendor/mounting_holes-sizez.SchLib gdb
```

- `safe-ctl3`: process alive, empty stderr, import chooser lists
  `MH M2.5 Mounting hole` and `MH M3`.
  Evidence `evidence/w186-fixed-safe.{rc,png}`.
- `attack-ctl1` under gdb: process alive, no `Program received signal`,
  `SIGABRT`, `SIGSEGV`, `double free` or `corruption` in the log, same two
  symbols in the chooser. Evidence
  `evidence/w186-fixed-attack.{rc,png,gdb.log}`; the two screenshots are
  byte-identical (same sha256).
- Earlier failed attempts in this wake (`safe-ctl1`, `safe-ctl2`) hit `Add
  Library` / "No symbol library selected" and are preserved only as ignored
  lab artifacts; they are not passes.

Contrast (vulnerable 8.0.8, W182/W183): the same `SizeZ` fixture aborts in
glibc with `double free or corruption (out)` during `ParseLibHeader`.

## Ceiling and disposition

Fixed real-process control: **reached**, at the labeled scope of a GUI-driven
import into the official 10.0.8 binary with a seeded lab profile. The fixed
binary has no ASan, so a clean exit alone would not prove absence of memory
corruption; here it is paired with the verbatim fixed source guard and the
harness fixed controls. No symbol was committed to the target library (the
chooser was left open), no pointer/control-flow target was observed, no benign
marker, no wire delivery and no witness replay of this lane. The corrupted
word still lands in allocator metadata / ASan redzone, not an adjacent live
object. **Rung 5 remains UNKNOWN.** An independent witness replay is owed
before this lane can count as accepted.

## Replay check

`bash lab/frontier/kicad2shell/realprocess/fixed-control-check.sh` from the
repository root: PASS=10 FAIL=0, trace
`8229bcd8bfdda107783efd2e1fce5d30707c17811ea3dbc91ce299ecd5733386`.
The trace is sha256 over the concatenation of the 14 files pinned in
`fixtures/PINS-w186.sha256`, in pin-file order.
