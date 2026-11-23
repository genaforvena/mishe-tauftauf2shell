# ndpi2shell — independent clean archive replay (W161, 2026-11-23)

Replay from a clean `git archive` of committed HEAD `6510950`, not from the
author's working tree. No files outside the archive were used.

```
git archive 6510950 reports/frontier-ndpi2shell.md lab/frontier/ndpi2shell \
  | tar -x -C /tmp/replay-ndpi2-final
cd /tmp/replay-ndpi2-final/lab/frontier/ndpi2shell
sha256sum -c PINS.sha256
cd harness
./run.sh
./check.sh
```

The pin manifest is relative to the `ndpi2shell` root; running `sha256sum -c`
from the archive root fails with four "No such file" errors. That was a replay
command error, not a harness failure; the corrected command above was used for
the recorded replay.

Observed:

- 54 files in the archive; 4/4 pin checksums OK.
- Eight binaries rebuilt from the archived pinned bytes and generated drivers.
- `PASS=172 FAIL=0 TRACE=16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`

The trace matches the in-tree check run exactly (three consecutive in-tree
runs with the same hash). The trace normalizes PIDs, gdb memory addresses and
absolute paths; it keeps pinned line numbers, exit statuses and chosen-byte
values. This is a replay of the author's own harness, not independent witness
acceptance; the witness mind still needs to re-run the claim.
