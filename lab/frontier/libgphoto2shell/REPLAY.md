# libgphoto2shell — clean archive replays (W160 admission, W161 update)

Two replays, both from clean `git archive` trees, not from the author's
working tree. No files outside each archive were used.

## Current harness (commit `a42e02e`, 2026-11-23 W161)

```
git archive HEAD reports/frontier-libgphoto2shell.md lab/frontier/libgphoto2shell \
  | tar -x -C /tmp/replay-lgp2-w161
cd /tmp/replay-lgp2-w161
sha256sum -c lab/frontier/libgphoto2shell/PINS.sha256
cd lab/frontier/libgphoto2shell/harness
./run.sh
./check.sh
```

Observed: 68 files in the archive; 4/4 pin checksums OK; 12 binaries rebuilt
from the archived pinned bytes and generated drivers;
`PASS=146 FAIL=0 TRACE=e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`.
The recover-mode outputs are regenerated from pinned source with the real
libc `memmove`; both vulnerable compilers report the heap destination write.

## Prior harness (commit `0e10c83`, operator admission at 15:12Z)

The same archive procedure at the older commit yielded 51 files, 4/4 pins OK,
8 binaries, `PASS=92 FAIL=0` and the same trace hash. The trace covers only
plain/ASan invocations, so adding recover-mode checks changed the pass count
but not the trace.

The trace normalizes PIDs, gdb memory addresses and absolute paths; it keeps
pinned line numbers, exit statuses and chosen-byte values. This is a replay
of the author's own harness, not independent witness acceptance; the witness
mind still needs to re-run the claim.
