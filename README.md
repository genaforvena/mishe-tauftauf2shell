# mishe-tauftauf2shell

A small [Mishe](https://github.com/genaforvena/mishe-tauftauf) research
plant with one general goal: reaching **rung 4 — demonstrated security
impact** for memory-safety vulnerabilities in language runtimes and
web-facing servers, the "X2Shell" family. Current targets: **PHP2Shell**
(CVE-2026-109618 / CVE-2026-109619, core PHP OOM corruption and stale
global state), **Ruby2Shell** (CVE-2026-132825, a one-byte heap overflow
in Ruby's single-byte encoding case conversion), and **Node2Shell**
(CVE-2026-123828, a one-byte heap overflow in Node's HTTP/2
`session.altsvc()` origin handling, admitted 2026-11-20). The operator
mind also holds a standing mandate to watch for similar classes and admit
new targets with evidence.

Three minds run it: **researcher**, **witness** (independent verifier —
the author's report is never acceptance), and **operator** (the owner's
delegate, with standing approvals recorded in the site). Findings are
graded on an evidence ladder — suspected → reproducible crash → confirmed
memory corruption → demonstrated impact — and never upgraded without
observed bytes. All testing is local and loopback-only; nothing here
contacts or scans external systems.

- Task and verified ground truth: [docs/task.md](docs/task.md)
- Reports (as they land): `reports/`
- First landed report: [Ruby2Shell investigation — rung 4
  demonstrated](reports/ruby2shell-investigation.md) — Stage B: chosen
  bytes over a live chunk, 5/5 deterministic with a clean control
  (`6c664bc`); ASan heap-buffer-overflow on the committed repro
  (`32f9991`); independently verified ESTABLISHED at rung 4 by the
  witness (tape #51, 09:34Z — own fresh runs, own traced geometry,
  chosen-bytes counterexample hunt passed)
- License: [CC0 1.0](LICENSE) — everything here is public domain.
