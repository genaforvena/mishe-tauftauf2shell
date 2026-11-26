# frontier-axis2guththila2shell — Guththila event_map raw-byte index (CVE-2026-124023)

Status: **STAGED, rung 3 ASan-confirmed in verbatim pinned source (W273,
2026-11-26)**. Highest-ranked retained-queue candidate on wire exposure
(CISA CVSS 9.1 AV:N) and a two-line primitive; the trigger was derived from
pinned source and executed. Pins, hashes, refetch commands and preserved
negatives are in `lab/frontier/axis2guththila2shell/PROVENANCE.md`.

## Claim source and scope

- CVE-2026-124023 / GHSA-qv28-p6jq-5h3f, published 2026-11-12 by Apache,
  title "Apache Axis2/C: Out-of-bounds read in the Guththila XML reader
  wrapper", CWE-125. CNA JSON:
  `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/124xxx/CVE-2026-124023.json`;
  OSV `https://osv.dev/vulnerability/CVE-2026-124023`; advisory
  `https://github.com/advisories/GHSA-qv28-p6jq-5h3f`. CNA records affected
  git range `f2b30c159720cf63ada72f19183828533154c749` before the first fix
  and semver `0` through `2.0.0`; "fix in next release" is a claim, not a
  released version verified here.
- CISA ADP assigns `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` (9.1);
  the CNA's textual severity field says "low". Both are preserved; neither
  was re-scored. The advisory says the read is not returned to the client.
- Two fix commits, both fetched and read:
  `23110287924e79d05a5b4712298c355d1f05c606` (wrapper bounds check) and
  `f01683ec10e8fddb87279ec9351b3239021223e6` (parser fallthrough returns -1).
- Checked before staging: no brief, charter, lane, manifest row or wall entry
  for Axis2/C Guththila; not on the do-not-duplicate list. Apache2shell is a
  different admitted target (HTTP server), untouched.

## Source-bound mechanism (pinned bytes)

- `guththila_xml_reader_wrapper_next()` in the vulnerable wrapper
  (`axiom/src/parser/guththila/guththila_xml_reader_wrapper.c:301-309`) calls
  `guththila_next()` and returns `event_map[i]` for any `i != -1`. The struct
  at `:145-153` declares `int event_map[10]`; valid event constants are 0..7
  (`guththila/include/guththila.h:62-72`).
- `guththila_next()` in `guththila/src/guththila_xml_parser.c` ends with
  `return c;` at verbatim line 1244. On an unrecognised `<!` declaration the
  fallback hands back the raw input byte, not an event constant. The second
  fix changes line 1244 to `return -1;`.
- The first fix adds `if (i < 0 || i >= sizeof(event_map)/sizeof(event_map[0])) return -1;`
  in the wrapper. Both fixes are present in the pinned fixed tree.
- Derived trigger: the 19-byte document `<!ENTITY x "y"><a/>`. Observed
  locally: vulnerable raw parser returns `60` (the `<` byte) as `raw[0]`;
  the fixed parser returns `-1`.

## Local experiment and observed bytes

`lab/frontier/axis2guththila2shell/run-all.sh` builds both **unmodified**
pinned trees with GCC 12 `-fsanitize=address`; `verify.sh` runs four controls.
Console `evidence-run-console.log`: `RESULT PASS=4 FAIL=0`.

- Vulnerable + attack: `AddressSanitizer: heap-buffer-overflow`, `READ of size 4`,
  top frame `guththila_xml_reader_wrapper_next` at verbatim wrapper line 308;
  address 192 bytes past the 72-byte wrapper allocation from verbatim line
  218. rc 1. This is the real wrapper operation called through
  `reader->ops->next()`, driven by an in-memory XML document.
- Fixed + attack: rc 0, `event[0]=-1`, no ASan report — the observed rung-2
  state failure and fixed control.
- Safe document `<a>text</a>`: both pins rc 0, first event `6`, no ASan
  report.

## Honest grade

Rung 3: ASan-confirmed heap OOB READ in verbatim pinned upstream source, via
the real AXIOM reader wrapper's public `next()` operation and a crafted
document. Rung 2 (state failure) is observed as the raw-byte event id and the
fixed `-1`. Rung 4 **NOT CLAIMED**: no chosen bytes observed at chosen
offsets, no pointer or control-flow steering, no wire consumer, no command,
no r5. The advisory's network vector is a claim; this lab used no socket.

## Cheapest next experiment to move up a rung

Put the crafted document on a local loopback HTTP/SOAP consumer built from
the same pinned tree and confirm the ASan report follows received wire bytes,
with fixed and safe-input controls. Then, on a plain build, groom the
allocation following the wrapper so the out-of-range `event_map[60]` read
lands on a chosen adjacent object and read the chosen value back as an event
code. A rung-4 claim needs observed chosen bytes at chosen offsets, not a
larger repeated read; the advisory says the value is not returned to the
client, so verify any return path before claiming disclosure.

## Ranked alternatives from this sweep

- TinyUSB CVE-2026-61497 / GHSA-qf63-w79j-qw7p: HID host report-descriptor
  underflow → OOB read, fixed 0.21.0 by `85047e177…`; researcher PoC and
  4-byte crafted descriptor exist. Strong next candidate; embedded stack,
  no server wire path yet.
- libmikmod CVE-2026-105837 / GHSA-rr6f-2vgw-5v76: DSM `numtrk` UWORD
  truncation → heap OOB write, fixed 3.3.14 by `a125eabb…`; deterministic
  file trigger derivable, but AV:L and needs 4097 PATT blocks.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All testing is local against
pinned source; no external system was probed. Admission is the operator's;
wake units and full-flag sync stay with the person. Witness replay from clean
tarballs is owed before any ESTABLISHED verdict.
