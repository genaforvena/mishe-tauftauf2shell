# mongoosemip2shell — ADMITTED (166th target mind, 2026-11-26)

Brief: `reports/frontier-mongoosemip2shell.md`. Lab:
`lab/frontier/mongoosemip2shell/`. Claim: GHSA-4mgp-8m9m-q872 /
ZDI-CAN-29386 (no CVE assigned), Mongoose `<= 7.23` MIP `read_conn()` FIN
branch falls through the resize check; a FIN carrying 400 bytes writes 288
bytes past a 512-byte heap receive buffer; fixed in 7.24 by commit
`9c6b4edd37869816b186e16e7a6616229c49f9fc`. State: **ADMITTED 08:19Z under
standing #6**; window 174 adopted from frontier (panes %350/%351 live, no
duplicate). Route and three generated wake units are not present in the
current omp-only/doctor readings, person-reserved. Independent witness W256
clean-archive replay is ESTABLISHED AS LABELED (see below).

Evidence: the canonical `run-all.sh` sha256
`6f99384f721f8c1bd839c760f6c7d9a6e5c1ee6d35abd28e622f1dda4268e393` verifies
the tarball, patch and harness pins, builds pinned 7.23/7.24 with GCC and
Clang ASan at `MG_IO_SIZE=512`, and drives a mock-L2, full-handshake harness
with an attack FIN and a fit-within-buffer safe FIN. Operator clean-archive
replays: commit `66833e50` (canonical runner `6f99384f…`) and the earlier
staging commit `3cd4f730` (runner `5d0e10f7…`), each with the pinned tarballs
and patch copied into the extracted tree, both returned `RESULT PASS=8 FAIL=0`,
rc 0. Evidence:
`.mishe-tauftauf/replays/mongoosemip2shell-op-20261126T0819Z`. Vulnerable 7.23
under both compilers gives `WRITE of size 400` at `mongoose.c:9763` (pinned
`src/net_builtin.c:1527`) from `read_conn`, 0 bytes after a 512-byte
`mg_iobuf_resize` region; 7.24 grows the receive buffer from 512 to 800 and is
clean; both safe controls are clean. Grade: rung 3 verbatim / rung 4 PARTIAL —
attacker-chosen length and `0x5a` bytes, but no named adjacent object, pointer
control, live wire path, command execution or r5.

Next: a rung-4 attempt only if the plain-build harness instability is repaired
and a measured layout shows the `0x5a` bytes reaching a length/pointer field.
Witness W256 independently replayed the canonical runner from a clean
`git archive 66833e50` with both tarballs re-fetched and matched: 8 PASS /
0 FAIL rc 0, vulnerable GCC+Clang `WRITE of size 400` at pinned
`net_builtin.c:1527`, 7.24 and both safe controls clean. Verdict: ESTABLISHED
AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no grade change, NO r5.
Detail: `.mishe-tauftauf/artifacts/witness-w256-mongoosemip2shell/detail.md`.
Preserve the negatives in `PROVENANCE.md`: ZDI PoC link is an HTML login page, non-ASan builds crash
on both tags in `mg_timer_poll` before the handshake, and the early checksum,
driver-poll-gate and event-type mistakes. The advisory's CVSS 9.8 and RCE
prose remain claims, not local results.
