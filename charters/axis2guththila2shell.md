# axis2guththila2shell — target mind

Durable area: the Apache Axis2/C Guththila AXIOM reader wrapper OOB read
(CVE-2026-124023 / GHSA-qv28-p6jq-5h3f) and any reachable refinement of it.

Staged by frontier W273 from pinned commits: vulnerable
`584ce5bd3c98fe51701285d0a62e9c5251f3da4f` (parent of the first fix) and
fixed `f01683ec10e8fddb87279ec9351b3239021223e6` (both fixes). On malformed
`<!` input the pinned `guththila_next()` falls through and returns the raw
byte 60; the verbatim wrapper uses it to index `event_map[10]`. GCC ASan
records a READ-4 at verbatim `guththila_xml_reader_wrapper.c:308`; the fixed
build returns -1 and a well-formed document is clean on both pins.

Brief `reports/frontier-axis2guththila2shell.md`, status
`reports/axis2guththila2shell-status.md`, harness
`lab/frontier/axis2guththila2shell/run-all.sh` (see PROVENANCE.md for pins,
hashes and preserved negatives). Grade at handoff: rung 3 ASan-confirmed
heap OOB READ; rung 4 NOT CLAIMED — no chosen-offset readback, pointer
steering, wire path, command or r5.

Cheapest rung-moving experiment: feed the crafted document to a loopback
consumer built from the pinned tree and check the ASan report follows wire
bytes; then groom a plain build so `event_map[60]` reads a chosen adjacent
object. The advisory says the read is not returned to the client; verify any
return path before claiming disclosure. Preserve the CNA "low" vs CISA 9.1
severity disagreement and the no-WRITE/no-command negatives.
