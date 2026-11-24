# kicad2shell — clean-archive replay (2026-11-23 W162)

Source commit `20d4d70` ("kicad2shell W162: stage direct-call rung-1..4 harness
and brief"). Replay performed from an exported archive, not the working tree:

```
git archive 20d4d70 lab/frontier/kicad2shell reports/frontier-kicad2shell.md \
  | tar -x -C "$(mktemp -d /tmp/kicad2shell-replay.XXXXXX)"
cd <replay>/lab/frontier/kicad2shell/harness
./run.sh    # re-extracts slices, verifies all 4 PINS.sha256 entries, builds 8 binaries
./check.sh  # 24 invocations + 2 gdb probes
```

Observed: `70` archived files, `built 8 binaries`, pins verified by `run.sh`
(`sha256sum -c PINS.sha256` is fatal on mismatch), `PASS=52 FAIL=0`, trace
`dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6` — exact
match with the three in-tree runs. Working-tree runs also gave `52 PASS / 0
FAIL` three times with the same trace.

The replay directory is a throwaway, gitignored-by-location `/tmp` artifact;
no replay output is copied back into the committed tree.

## Real-parser replay (2026-11-23 17:45Z wake)

From `lab/frontier/kicad2shell/realparser/`: `sh run.sh` rebuilds 8 binaries
from the verbatim upstream parser slices plus the pinned `ParseLibHeader`
slices; `sh check.sh` runs 32 invocations and 36 assertions. Two in-tree runs
and a clean-archive replay at commit `7ad20c7` gave `PASS=36 FAIL=0` with the
same trace hash
`b228ec002755ffbf9e54ddcf5a4a9952a425efe82ec3915a038fe29ef93ff4ee`.
The archive replay checked both `../PINS.sha256` (4/4) and
`PINS-realparser.sha256` (5/5) before building.
The raw upstream parser files and three verbatim slice hashes are pinned in
`PINS-realparser.sha256`; provenance and the lab/wx/CFB boundary are in
`PROVENANCE-realparser.md`.

## Real-compound-file replay (2026-11-23 18:18Z wake)

From `lab/frontier/kicad2shell/realcfb/`: `sh run.sh` regenerates the four CFB
fixtures, verifies them with `olefile` 0.46 (`ALL_FIXTURES_OK`), checks both
pin files (5/5 and 4/4), then builds 8 binaries from the same verbatim upstream
slices plus a real header → DIFAT → FAT → directory → miniFAT → mini-stream
walk. `sh check.sh` runs 32 invocations and 38 assertions. Two in-tree runs
and a clean-archive replay at commit `455d92e` (`git archive` of
`lab/frontier/kicad2shell` and `reports/frontier-kicad2shell.md`, 246 archived
files) gave `PASS=38 FAIL=0` with the same trace hash
`d46a353639e2d48effa117f7dc3735d48923f094222f1e04a620260f8eafc53c`.
The earlier harness trace hashes are unchanged. Provenance, the lab/wx/KiCad
boundary and the preserved fixture defects are in `realcfb/PROVENANCE-realcfb.md`.

## KiCad-own-reader replay (2026-11-23 19:23Z wake)

From `lab/frontier/kicad2shell/kicadreader/`: `sh run.sh` regenerates the four
CFB fixtures from `../realcfb/make_cfb.py`, verifies them with `olefile`
(`ALL_FIXTURES_OK`), verifies three pin files (new reader 2/2, realparser 5/5,
ParseLibHeader 4/4), then builds eight binaries from KiCad 10.0.6's verbatim
`compoundfilereader.h`/`utf.h` plus the pinned upstream parser slices.
`sh check.sh` runs 32 invocations and 38 assertions. Two in-tree runs and a
clean-archive replay at commit `337c164` (`git archive` of
`lab/frontier/kicad2shell` and `reports/frontier-kicad2shell.md`, 333 archived
files) gave `PASS=38 FAIL=0` with the same trace hash
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260`.
Earlier trace hashes are unchanged. Provenance, the restored-include build
failure and the ceiling are in `kicadreader/PROVENANCE-kicadreader.md`.

## Vendor-produced `.SchLib` replay (2026-11-23 W180)

From `lab/frontier/kicad2shell/vendor/`: `sh check.sh` verifies six fixture
hashes, reads all five compound files with `olefile`, runs 20 reader
invocations plus three gdb probes against the **already-committed**
`../kicadreader` binaries (no rebuild, no network). Two in-tree runs gave
`PASS=23 FAIL=0` with trace
`42db33cb056a52d223a51a6af7d0ffd5cfaeeb4a6f64fc8c28d80fdd6e341e4f`.
A clean-archive replay at commit `de13eac` (`git archive` of the whole
repository) reproduced `PASS=23 FAIL=0` and the same trace hash exactly.
The earlier `56bc1f8` replay of the two-patch lane (13 assertions, trace
`fcd8ca1bd4231c6fcc45d0008225e7979cabae97066a89da48179391b4352f43`) also
matched. All earlier lane traces are unchanged. Provenance, upstream commit
and license are in `vendor/PROVENANCE-vendor-file.md`.

## Low-index `Size-1` replay (2026-11-24 W187)

From `lab/frontier/kicad2shell/lowindex/`: `sh check.sh` rebuilds eight
binaries from the shared verbatim pins with the measured KiCad mils-to-IU
scale, then runs 16 invocations and 41 assertions. An in-tree run and a
clean-archive replay at commit `197e70d` (`git archive` of
`lab/frontier/kicad2shell`, `reports/frontier-kicad2shell.md` and
`reports/kicad2shell-status.md`, 487 archived files) both printed
`PASS=41 FAIL=0` with the same trace hash
`999e6733e903364be0f7bd8ded350c0ac979fff5d9b2fe837d27e05794264796`.
The pinned real-process artifacts replay with
`sh ../realprocess/real-check-w187.sh` (`PASS=9 FAIL=0` in both trees);
the GUI fault itself is not replayed by that check — its exact command,
fixture patch and control are in `lowindex/PROVENANCE-lowindex.md`.
All earlier lane trace hashes are unchanged.
