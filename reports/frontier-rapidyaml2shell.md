# frontier-rapidyaml2shell — parser annotation stack OOB WRITE (CVE-2026-120455)

Status: **staged, rung 3 measured (W269 2026-11-26)**. Ranked next after
libsoup2shell because the fix commit is public and small, the trigger is a
one-line YAML document, and the default convenience API puts the overflowed
array on the stack. The advisory itself is source-review only and `AV:L`; no
remote path is claimed. See `lab/frontier/rapidyaml2shell/PROVENANCE.md` and
the measured section at the end.

## Claim source and scope

- CVE-2026-120455 / GHSA-pj6m-mgp5-m3qx, published 2026-11-02, updated
  2026-11-09: rapidyaml through 0.16.0 has an out-of-bounds write in
  `ParseEngine::_add_annotation()` when YAML supplies excess consecutive
  anchors or tags, overflowing a fixed two-element annotation array in
  release builds. CWE-787 / CWE-121; CVSS v4 6.9
  `AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. GHSA lists no
  package and unknown affected/patched versions. OSV:
  https://osv.dev/vulnerability/CVE-2026-120455 .
- Upstream report: https://github.com/biojppm/rapidyaml/issues/680 (Haind03,
  2026-11-01, closed 2026-11-05). It is explicitly **static source review**:
  no clone, build, execution or host contact; the author asks for release
  sanitizer tests. Tested v0.16.0 at `f8ac8dd50f4f7916579d55a05ebf9c6488e52670`
  and master `f7fb179d0a42291b7a51073c163b4d4de2ab853e`.
- Upstream fix: commit `0b4f4c1985dc` (parent `fd35d14ee73c`, 2026-11-04,
  PR #682, "Parser: ensure error and not assert on excess tags/anchors"),
  https://github.com/biojppm/rapidyaml/commit/0b4f4c1985dc . GitHub's
  `/releases/latest` still returns v0.16.0 (published 2026-07-22), so the fix
  is **unreleased**: a patched build must be made from the commit, not a
  release tarball.
- Checked before staging: no brief, charter, manifest row, wall receipt or
  lab lane for rapidyaml in this plant; not on the wall's do-not-duplicate or
  screened-out lists.

## Source-bound mechanism

From the fix hunk, verbatim behaviour on each side:

- `Annotation` in `src/c4/yml/parse_engine.hpp:249-260` holds
  `Entry annotations[2]` and `uint8_t num_entries`. The fix introduces
  `RYML_NUMANNOT_ (2)` but does not change the capacity.
- All three `_add_annotation()` overloads in
  `src/c4/yml/parse_engine.def.hpp` previously wrote
  `dst->annotations[dst->num_entries]` unconditionally, guarded only by
  `RYML_ASSERT_PARSE_CB_(..., dst->num_entries < C4_COUNTOF(...), ...)`,
  which compiles away when `NDEBUG` defines `C4_USE_ASSERT=0`. The fix
  replaces that with an always-on `if (num_entries < RYML_NUMANNOT_) ... else
  _c4err("parse error: too many tags/anchors")`.
- The "too many" checks in the `_handle_annotations_before_*` consumers run
  only when the parser reaches the node, after every annotation has been
  appended. A third consecutive annotation therefore writes one `Entry` past
  the two-element array. Per issue #680, `Entry` is 48 bytes on 64-bit
  (16-byte `csubstr` + two `size_t` + 16-byte `csubstr`), so the third write
  reaches `num_entries` and following engine members.
- Two shapes are named upstream: flow `[&a &b &c x]` through
  `_handle_seq_flow` (`parse_engine.def.hpp:5524-5535`, no line check), and
  three single-tag block lines through `_handle_unk` (`:8011-8021`; the
  line-checked overload compares only `annotations[0].line`). The fix adds
  regression tests for both (`test/test_engine_z_annot.cpp`,
  `test/test_engine_4_anchor.cpp`).
- `ryml::parse_in_place()` constructs a stack `TmpParser`
  (`src/c4/yml/parse.cpp:114-134` per the report), so in a default release
  build the write lands in adjacent stack memory. No read-back, pointer value
  or command is claimed by the report.

## Honest feasibility / rung-4 assessment

Strong rung 3 candidate: a deterministic 48-byte stack OOB WRITE from a
one-line input, with a public always-on-check fix for a fixed control.
Rung 4 needs more than a sanitizer report in a lab driver: the input starts
with source-buffer pointers and token lengths at a fixed offset, not a
chosen pointer or arbitrary bytes at chosen offsets. A loopback consumer that
parses attacker-supplied YAML would supply a wire path, but no such consumer
or request-to-parse call path exists in this plant; advisory `AV:L` says the
claim itself is local. Floor: rung 3 real-source ASan OOB WRITE / rung 4
PARTIAL, no pointer control, no command, no r5. Would change that: a named
adjacent object with chosen bytes at chosen offsets in a live loopback
consumer, or a fixed-build counterexample.

## Cheapest rung-moving experiment

Pin v0.16.0 `f8ac8dd50f4f7916579d55a05ebf9c6488e52670` and fix
`0b4f4c1985dc`; compile the verbatim upstream source in `-DNDEBUG -O0
-fsanitize=address` with a lab-only driver calling `ryml::parse_in_place()` on `[&a &b &c x]` and three `!tag` lines, plus a
two-annotation safe control. Confirm the ASan report at the pinned
`_add_annotation()` line; confirm the fixed build returns a parse error with
no ASan report. If that holds, stage with provenance and a dedicated window;
a real request-taking consumer is a separate, much larger experiment.

## Measured W269 result (author, not independent acceptance)

The vulnerable v0.16.0 tree `f8ac8dd50f4f7916579d55a05ebf9c6488e52670` and
fix `0b4f4c1985dc99d2773c1f1da7b447d610bbb1d4` were fetched from public
GitHub; the runner checks both pinned `parse_engine.def.hpp` hashes and
compiles the full verbatim trees with a lab-only driver calling the real
`ryml::parse_in_place()` API. No upstream line was edited.

`lab/frontier/rapidyaml2shell/run-all.sh` sha256
`f42c5d6508f60d8a76f1536e3c16c3b30bee95122ca2b961518ad403fdd157b8`:
`RESULT PASS=20 FAIL=0`, rc 0, 13:07Z–13:08Z. Console sha256
`1ab09829923135fba5ee622499c1e9131d4d1aacacefc35fefbbf1c4d7f77076`.
This is an **intra-object** overflow: the write stays inside the enclosing
stack `TmpParser`, so default GCC ASan sees nothing (preserved negative).
Clang 18 with `-fsanitize-address-field-padding=2` reports
`AddressSanitizer: intra-object-overflow`, `WRITE of size 16` at pinned
`src/c4/yml/parse_engine.def.hpp:4313` in `_add_annotation()`, called from
`_handle_seq_flow()` and `parse_in_place()` at `parse.cpp:182`.
`{val: &a &b &c x}` also triggers a WRITE-16. The fixed build reports
`parse error: too many tags/anchors` with no ASan report; safe `[&a x]`
parses cleanly in both builds. Three tag lines and block sequence anchors
reach earlier consumer errors in this build and are preserved negatives,
not claimed triggers.

Grade: rung 3 real-source ASan intra-object stack OOB WRITE; rung 4
**NOT CLAIMED**. No named adjacent object with chosen bytes at chosen
offsets, no pointer value, no request-to-parse path, no command and no r5.
The advisory's partial input influence (source pointer, token length) is not
an arbitrary write. A loopback consumer parsing attacker YAML with an ASan
report there, a chosen-value overwrite of adjacent parser state, or a
fixed-build counterexample would change this assessment.
