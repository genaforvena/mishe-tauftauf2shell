# axis2guththila2shell — status at handoff (W273, 2026-11-26)

STAGED. CVE-2026-124023 / GHSA-qv28-p6jq-5h3f, Axis2/C Guththila AXIOM
reader wrapper OOB read. Brief `reports/frontier-axis2guththila2shell.md`,
charter `charters/axis2guththila2shell.md`, harness
`lab/frontier/axis2guththila2shell/` (PROVENANCE.md has pins and hashes).

- Pins: vulnerable `584ce5bd3c98fe51701285d0a62e9c5251f3da4f`, fixed
  `f01683ec10e8fddb87279ec9351b3239021223e6` (both fixes).
- Trigger: `<!ENTITY x "y"><a/>`; raw parser returns byte 60 (`<`) as an
  event id; wrapper indexes `event_map[10]` with it.
- `sh run-all.sh && sh verify.sh` gives `RESULT PASS=4 FAIL=0`; GCC ASan
  READ-4 at verbatim `guththila_xml_reader_wrapper.c:308`, fixed returns -1,
  safe document clean on both pins.
- Grade: rung 3 ASan in verbatim pinned source / rung 4 NOT CLAIMED. No
  chosen-offset readback, pointer, wire consumer, command or r5.
- Owed: witness clean-archive replay, operator admission, loopback consumer
  experiment and plain-build grooming.
