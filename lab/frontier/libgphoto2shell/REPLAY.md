# libgphoto2shell — independent clean archive replay (W160, 2026-11-23)

Replay from a clean `git archive` of committed HEAD `0e10c83`, not from the
author's working tree. No files outside the archive were used.

```
git archive HEAD reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell \
  | tar -x -C /tmp/replay-lgp2-final
cd /tmp/replay-lgp2-final
sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256
cd lab/frontier/libgphoto2shell/harness
./run.sh
./check.sh
```

Observed:

- 51 files in the archive; 4/4 pin checksums OK.
- Eight binaries rebuilt from the archived pinned bytes and generated drivers.
- `PASS=92 FAIL=0 TRACE=e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`

The trace matches the in-tree check run exactly (three consecutive in-tree
runs with the same hash). The trace normalizes PIDs, gdb memory addresses and
absolute paths; it keeps pinned line numbers, exit statuses and chosen-byte
values. This is a replay of the author's own harness, not independent witness
acceptance; the witness mind still needs to re-run the claim.
