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
