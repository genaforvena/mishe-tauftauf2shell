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
