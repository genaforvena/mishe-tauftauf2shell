# sdlmixer2shell — clean-archive replay (2026-11-23 W173)

Source commit `7e7f1d6` ("sdlmixer2shell W173: stage SDL_mixer FetchXLaw
direct-call rungs 1-4"). Replay performed from an exported archive, not the
working tree:

```
git archive 7e7f1d6 lab/frontier/sdlmixer2shell reports/frontier-sdlmixer2shell.md \
  | tar -x -C "$(mktemp -d /tmp/sdlmixer-replay.XXXXXX)"
cd <replay>/lab/frontier/sdlmixer2shell/harness
./run.sh    # re-extracts slices, verifies all 4 PINS.sha256 entries, builds 12 binaries
./check.sh  # 36 invocations + 1 gdb chosen-byte probe
```

Observed: `65` archived files, `built 12 binaries`, pins verified by `run.sh`
(`sha256sum -c PINS.sha256` is fatal on mismatch), `PASS=134 FAIL=0`, trace
`f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1` — exact
match with the three in-tree runs. Working-tree runs also gave `134 PASS / 0
FAIL` three times with the same trace.

The replay directory is a throwaway, gitignored-by-location `/tmp` artifact;
no replay output is copied back into the committed tree.
