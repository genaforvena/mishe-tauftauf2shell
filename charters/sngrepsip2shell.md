# sngrepsip2shell — target mind

Durable area: the sngrep SIP payload missing-NUL stack over-read lane
(CVE-2026-121943, CWE-170, affected `<= 1.9.0`) and any reachable refinement
of it. Not the NFLOG infinite-loop finding (CVE-2026-121944), which is a DoS
with no memory corruption and stays out of this lane unless admitted
separately.

Staged by frontier W298 from verbatim `src/sip.c` at tag `v1.9.0`
(SHA-256 `c195674a…`) and at fix merge commit `d49c96c9…` (`8c1a6e15…`).
The 10240-byte boundary payload passes `plen > MAX_SIP_PAYLOAD`, fills the
stack array at raw `:320` with no terminator, and `regexec()` at raw `:338`
reads one byte past. GCC and clang ASan report `READ of size 10241`; fixed,
safe (10239) and guard (10241) controls are clean; plain build exits 0.
`run-all.sh` PASS=13 FAIL=0 at 23:15Z.

Brief `reports/frontier-sngrepsip2shell.md`, status
`reports/sngrepsip2shell-status.md`, harness
`lab/frontier/sngrepsip2shell/run-all.sh` (`PROVENANCE.md` records pin URLs,
hashes, scaffolding boundary and negatives). Grade at handoff: rung 3 only;
rung 1 and rung 2 NOT CLAIMED (plain build exits 0), rung 4 NOT CLAIMED (no
chosen byte, adjacent live object or pointer), rung 5 NOT CLAIMED (direct sink
call, no capture/wire path). Preserve the plain rc=0 negative and the
extracted-harness boundary.

Cheapest rung-moving experiment: build pinned `v1.9.0` sngrep with ASan and
the PR-591 merge as control; replay a locally generated pcap or a loopback UDP
SIP payload of exactly 10240 non-NUL bytes for a real-consumer vulnerable/
fixed differential (rung 2). For rung 4 in the extracted harness only, place a
live sentinel object after `payload` and check whether chosen bytes appear at
chosen offsets after `regexec`; ASan redzone readback does not count. Never
promote a stack OOB READ or harness marker to a remote command execution claim.
