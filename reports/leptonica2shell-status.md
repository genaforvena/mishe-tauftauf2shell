# leptonica2shell — admitted status (2026-11-25 23:2xZ)

Frontier W235 staged this lane; the operator admitted it at 23:2xZ under
standing #6 as the 153rd declared target mind (record below).
Brief:
`reports/frontier-leptonica2shell.md`; pins, stand-ins and raw evidence:
`lab/frontier/leptonica2shell/PROVENANCE.md`.

**ADMITTED by the operator at 23:2xZ under standing #6 as the 153rd declared
target mind.** Frontier W235's evidence below is preserved unchanged. The
live two-pane window 161 (created 23:06:59Z, panes `%324`/`%325`) was adopted,
not duplicated. No hy4-flash route, resolver key or generated wake unit was
added: `.mishe-tauftauf/operator/standing-approvals.md:47-51` reserves engine
config, systemd units and the full-flag sync to the person. `check-omp-only.py`
is RED for `leptonica2shell: no route` and `nfdump2shell: no route` (154
declared roles); the 23:09Z doctor run lists fifteen missing unit files. The
`failed-m2shell-doctor-service` RED was re-observed GREEN on a named
person-owned disposition, not on a clean doctor run. Grade unchanged: rung 3
pinned verbatim / rung 4 PARTIAL synthetic readback, no r5, witness UNKNOWN.

Claim: `CVE-2026-137063` (published 2026-11-25, CWE-122, CVSS 6.8), heap
buffer overflow in Leptonica 1.79.0-1.87.0 `l_byteaInitFromStream()`; upstream
fix `c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd` adds the missing
`nbytes > MaxArraySize` check. No fixed release is named in the feed.

Evidence: byte-identical pinned excerpts of `l_byteaCreate()` and
`l_byteaInitFromStream()` from tag 1.87.0 and the fix commit, driven by a
1,000,000,001-byte sparse file mapped read-only. GCC and Clang ASan report
`heap-buffer-overflow`, `WRITE of size 1000000001`, 0 bytes after the 201-byte
region, with stacks in the pinned excerpts; fixed build rejects
(`stream too large`, `BA=NULL`), a 16-byte stream is clean, and a synthetic
bounded plain consumer shows the chosen `MISHE-LEPTONICA` bytes at
`data+201..215`. `bash lab/frontier/leptonica2shell/run-all.sh`:
17 PASS / 0 FAIL, rc 0.

Grade: **rung 3 pinned verbatim / rung 4 PARTIAL** (file-chosen bytes at
chosen offsets, but observed through a synthetic bounded consumer). No real
library build, adjacent object, pointer, wire, command or r5. Witness
verdict UNKNOWN.

## Next

1. Replay `run-all.sh` from a clean archive and ask the witness to verify the
   labeled grade.
2. Build real Leptonica 1.87.0 and the fixed commit with ASan; call
   `l_byteaInitFromFile()` on the same sparse file and confirm the write in
   the real library.
3. Enumerate real callers of `l_byteaInitFromStream()` and look for a live
   consumer whose heap neighborhood can be measured. Keep the no-pointer,
   no-command ceiling until then.


## Clean-archive replay receipt (frontier W235, 2026-11-25 23:08Z)

`git archive 925b35c2 lab/frontier/leptonica2shell` extracted to
`/tmp/w235-lept-clean2`, `bash .../run-all.sh` from that directory:
**17 PASS / 0 FAIL**, rc 0. In-tree run from the same commit gave the same
result. The first clean replay from commit `ae82b2e7` failed one control
(LeakSanitizer on the undestroyed stand-in bytea); the harness was repaired
with `l_byteaDestroy(&ba)` and the failure preserved in `PROVENANCE.md`.
No pinned upstream byte changed. This is an author-side replay; witness
verdict on the staged grade stays UNKNOWN.