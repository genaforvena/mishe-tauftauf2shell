# mongoosemip2shell — STAGED (frontier, 2026-11-26)

Brief: `reports/frontier-mongoosemip2shell.md`. Lab:
`lab/frontier/mongoosemip2shell/`. Claim: GHSA-4mgp-8m9m-q872 /
ZDI-CAN-29386 (no CVE assigned), Mongoose `<= 7.23` MIP `read_conn()` FIN
branch falls through the resize check; a FIN carrying 400 bytes writes 288
bytes past a 512-byte heap receive buffer; fixed in 7.24 by commit
`9c6b4edd37869816b186e16e7a6616229c49f9fc`. State: **STAGED, admission
owed**. Window created by frontier; operator admission and independent witness
replay owed. No wake unit, route or sync change by frontier (person/genome
reserved).

Evidence: `run-all.sh` sha256
`5d0e10f7410649464861508563ae17b212bf357eaac2869f5e8981af2d4620fa`
verifies tarball, patch and harness pins; builds pinned 7.23/7.24 with GCC and
Clang ASan at `MG_IO_SIZE=512`; and drives a mock-L2, full-handshake harness
with an attack FIN and a fit-within-buffer safe FIN. Result at 08:08Z:
`RESULT PASS=8 FAIL=0`. Vulnerable 7.23 under both compilers gives
`WRITE of size 400` at `mongoose.c:9763` (pinned `src/net_builtin.c:1527`)
from `read_conn`, 0 bytes after a 512-byte `mg_iobuf_resize` region; 7.24 grows
the receive buffer from 512 to 800 and is clean; both safe controls are clean.
Grade: rung 3 verbatim / rung 4 PARTIAL — attacker-chosen length and bytes,
but no named adjacent object, pointer control, live wire path, command
execution or r5.

Next: witness replay from a clean archive; then a rung-4 attempt only if the
plain-build harness instability is repaired and a measured layout shows the
`0x5a` bytes reaching a length/pointer field. Preserve the negatives in
`PROVENANCE.md`: ZDI PoC link is an HTML login page, non-ASan builds crash on
both tags in `mg_timer_poll` before the handshake, and the early harness
checksum/event-type mistakes. The advisory's CVSS 9.8 and RCE prose remain
claims, not local results.
