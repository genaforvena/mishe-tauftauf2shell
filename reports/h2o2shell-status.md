# h2o2shell — status

Admitted 2026-11-22 ~18:28Z under standing approval #6 as the 77th target
mind and 81st engine route. Charter `.mishe-tauftauf/charters/h2o2shell.md`,
seed wall `.mishe-tauftauf/walls/h2o2shell.md`; staged by frontier at commit
`4cf9784`, brief [reports/frontier-h2o2shell.md](frontier-h2o2shell.md).
Frontier's DM #1517 recorded the existing two-pane window (inner index 86,
registry 87 windows); admission adopted it and added the model route,
wake-failure signal and three units, not a duplicate window.

- Claim: CVE-2026-55368 / GHSA-m998-r5ww-rqjf, "Out-of-bounds writes in H2O
  access-log formatting", GitHub security advisory published 2026-10-23,
  High 8.1, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. H2O HTTP server, affected
  commit `4212ce114506a073505fd389db16ad2ba4e582a0` and earlier, fixed
  `48b7ae12107fd2b118e4641da49599e9aac8edd8` (merge of PR #3757). Claim
  URLs, fix patch and build notes in `lab/frontier/h2o2shell/PROVENANCE.md`.
- Primitive: `lib/core/logconf.c:842-843` in `h2o_log_request()` appends
  `req->error_logs->bytes` with no preceding `RESERVE`; the fix adds one.
  The real caller `lib/handler/access_log.c:48` passes a 4096-byte stack
  buffer, so a long `error_logs` can overrun it when `%{error}x` is in a
  configured access-log format. The advisory's other two cases (`%q` empty,
  numeric NUL) are source-bound from the fix hunks but not harnessed here.
- Pins: vulnerable `4212ce11…` and fixed `48b7ae12…` (git archive stream
  hashes `b7a7ac60…` / `0cf7bd8d…`, `lib/core/logconf.c` hashes
  `23dabdc7…` / `f6b0349a…`, fix patch `411c36fa…`). Operator replay from the
  repo root rechecked the commit IDs, both archive hashes, both source hashes
  and the patch hash — all matched `pins/PIN_HASHES.txt`. Running the six
  staged harness binaries and normalizing into a clean temp directory
  reproduced all six `EVIDENCE_HASHES.txt` digests byte for byte (vuln-ASan
  rc 1, other five rc 0). Frontier's clean git-archive rebuild is recorded
  in `harness/clean-replay.log` (`REPLAY_IDENTICAL=yes`).
- Grade at admission: **rungs 1/2 accounting failure, rung 3 natural ASan
  `heap-buffer-overflow WRITE of size 1` 0 bytes after a 64-byte sink at
  `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843`,
  rung 4 chosen-byte control at DIRECT-CALL scope only.** Plain readback
  writes chosen `M..B` at offsets 0..15 past the sink plus the `\n` suffix
  at 16; the fixed pin expands and is ASan-clean; safe 8-byte inputs are
  clean on both pins. The 64-byte sink is a harness choice, not the stock
  4096-byte stack array.
- UNKNOWN: a live h2o process, loopback socket, wire request, configured
  `%{error}x` log format, whether a real request can grow `error_logs` past
  4096 bytes, allocator-neighbour object, pointer control, command, and
  rung 5. No witness replay yet; this is author/operator-measured only.
- First bounded experiment: build the pinned vulnerable `h2o` binary
  out-of-tree with ASan, configure an affected access-log format, drive a
  loopback-only request producing a long error log and observe whether the
  real 4096-byte stack buffer faults; fixed-pin and short-request controls
  stay clean. If a single request cannot grow `error_logs` that far, record
  the direct-call ceiling as the honest grade.
