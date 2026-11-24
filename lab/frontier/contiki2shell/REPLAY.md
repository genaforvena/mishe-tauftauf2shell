# contiki2shell clean replay — 2026-11-24

Command: `cd lab/frontier/contiki2shell && sh run-all.sh`
(bootstrap resets the pinned tree from SHA-256-verified tarball).

```
contiki-ng-release-v5.2.tar.gz: OK
BOOTSTRAP: contiki-ng-release-v5.2 ready
PASS attack ASan abort
PASS attack global-buffer-overflow
PASS attack WRITE of size 1232
PASS attack in mpl.c data_message_expiration
PASS chosen marker in gdb transcript
PASS safe input harness completes
PASS safe input no ASan report
PASS fixed build no ASan report
PASS fixed harness completes
RESULT: PASS=9 FAIL=0
```

The `fatal: not a git repository` lines are `git apply` diagnostics emitted
from inside the extracted tarball; both patches applied and the final fixed
build produced no ASan report. Evidence outputs:
`attack-asan.out`, `safe-asan.out`, `fixed-asan.out` (gitignored bulk),
`gdb-inspect.txt` (tracked).
