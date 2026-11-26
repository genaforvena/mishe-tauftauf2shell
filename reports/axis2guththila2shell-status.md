# axis2guththila2shell — status (ADMITTED 2026-11-26 19:0xZ)

ADMITTED under standing #6 as the 183rd declared target mind; staged window
187 adopted (panes %378/%379 live, dead=0, registry entry present, no
duplicate). CVE-2026-124023 / GHSA-qv28-p6jq-5h3f, Axis2/C Guththila AXIOM
reader wrapper OOB read. Brief `reports/frontier-axis2guththila2shell.md`,
charter `charters/axis2guththila2shell.md`, harness
`lab/frontier/axis2guththila2shell/` (PROVENANCE.md has pins and hashes).

- Pins: vulnerable `584ce5bd3c98fe51701285d0a62e9c5251f3da4f`, fixed
  `f01683ec10e8fddb87279ec9351b3239021223e6` (both fixes).
- Trigger: the 19-byte document `<!ENTITY x "y"><a/>`; raw parser returns byte
  60 (`<`) as an event id; the verbatim wrapper indexes `event_map[10]` with it.
- Author harness: `sh run-all.sh && sh verify.sh` gives `RESULT PASS=4 FAIL=0`;
  GCC ASan READ-4 at verbatim `guththila_xml_reader_wrapper.c:308`, 192 bytes
  past the 72-byte allocation at line 218; fixed `event[0]=-1`, safe document
  clean on both pins.
- Operator clean-archive replay 18:57Z: `git archive HEAD
  lab/frontier/axis2guththila2shell` plus only the ignored pinned
  `src/vuln.tar.gz` and `src/fixed.tar.gz` (sha256 `da9cf3c1…` / `3421cf3b…`),
  both extracted; runner `59da25bc…`, driver `7ada2943…` match PROVENANCE;
  `sh run-all.sh` rc 0 and `sh verify.sh` RESULT PASS=4 FAIL=0 rc 0, same ASan
  frame and controls. No author build/out or extracted source was reused.
- Grade: **rung 3 ASan in verbatim pinned source / rung 4 NOT CLAIMED**.
  No chosen-offset readback, pointer, wire consumer, command or r5. CNA
  "low" vs CISA ADP 9.1 AV:N severity disagreement is preserved; advisory
  network vector is a claim, this run used no socket.
- Owed: independent witness clean-archive replay; the named lane experiment —
  drive the crafted document through a loopback HTTP/SOAP consumer built from
  the pinned tree, require the ASan report to follow received wire bytes with
  fixed and safe-input controls, then groom a plain build for a chosen
  adjacent-object readback. Verify any client return path before claiming
  disclosure; preserve the no-WRITE/no-command negatives.
