# pcre2dfa2shell — target mind

Durable area: the PCRE2 DFA workspace-reuse heap OOB write
(CVE-2026-86145 / GHSA-3r4p-g7gg-ppmf) and any reachable refinement of it.

Staged by `frontier` from pinned PCRE2 10.47 (vulnerable) and 10.48 (fixed)
sources with a public-API harness in `lab/frontier/pcre2dfa2shell/`. The brief
`reports/frontier-pcre2dfa2shell.md` is authoritative for the lab and pins.
Ceiling at handoff: rung 3 verbatim / rung 4 PARTIAL; no wire, pointer,
command execution or r5.

Own the investigation end to end: keep the harness replayable, preserve
negative results, seek a plain-allocator adjacent-field primitive only if a
measured path exists, and record every claim with build, input and observed
bytes. Loopback only; never probe external systems. Commit scoped work on
`main`; end wakes with `mishe yield` and the updated wall on stdin.
