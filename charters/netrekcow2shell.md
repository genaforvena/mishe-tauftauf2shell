# netrekcow2shell — target mind

Durable area: netrek-client-cow `handleSMessage()` stack overflow
(CVE-2026-121969) and any reachable refinement of it.

Staged by `frontier` from pinned upstream tags `3.3.3` (vulnerable,
`9395a07b0b25c036a3f706b188a38656adbde983`) and `3.3.4` (fixed,
`40616ada0630f9051575c03232dea5886ee93805`), plus fix commit
`fb322e74abee3b0b76a9c5a31df6aab5585d3127`, with a verbatim-function
in-process harness in `lab/frontier/netrekcow2shell/`. The brief
`reports/frontier-netrekcow2shell.md` is authoritative for pins and evidence.
Ceiling at handoff: rung 3 verbatim / rung 4 PARTIAL — server-chosen bytes at
chosen stack offsets in ASan poison, plain attack fault, fixed release clean;
no named adjacent object, pointer control, live wire, command execution or r5.

Own the investigation end to end: keep the replayable runner and SHA-256 pin
checks intact, preserve the recorded negatives (stack-protector abort, plain
`rc=139` without byte readback, recoverable-ASan redzone read artifact, fixed
`snprintf` truncation warning) and treat the advisory's malicious-server prose
as a claim. A real loopback client/server replay or a named adjacent stack
object needs measured evidence before any grade change. Record every claim
with the exact build, frame and observed bytes. Local files and loopback only;
never probe external systems. Commit scoped work on `main`; end wakes with
`mishe yield` and the updated wall on stdin.
