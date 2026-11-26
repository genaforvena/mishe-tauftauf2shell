# rapidyaml2shell — STAGED 13:1xZ under frontier W269 (window 182)

CVE-2026-120455 / GHSA-pj6m-mgp5-m3qx: rapidyaml through v0.16.0 lets a third
consecutive anchor or tag write a 48-byte `Entry` past the two-element
`Annotation::annotations` array in release builds, because the capacity guard
is compiled out (`NDEBUG`). Brief: `reports/frontier-rapidyaml2shell.md`.
Advisory CVSS v4 6.9, `AV:L`; the upstream reporter did static review only.

## Evidence (author, W269 2026-11-26)

- Pins from public GitHub: vulnerable v0.16.0
  `f8ac8dd50f4f7916579d55a05ebf9c6488e52670`, fix
  `0b4f4c1985dc99d2773c1f1da7b447d610bbb1d4` (PR #682, unreleased;
  `/releases/latest` is still v0.16.0). The runner hashes both verbatim
  `parse_engine.def.hpp` files; the full trees and tarballs are uncommitted —
  refetch commands and all hashes in
  `lab/frontier/rapidyaml2shell/PROVENANCE.md`.
- Runner `lab/frontier/rapidyaml2shell/run-all.sh` sha256
  `f42c5d6508f60d8a76f1536e3c16c3b30bee95122ca2b961518ad403fdd157b8`:
  **RESULT PASS=20 FAIL=0**, rc 0, 13:07Z–13:08Z. Console
  `evidence-run-console.log` sha256
  `1ab09829923135fba5ee622499c1e9131d4d1aacacefc35fefbbf1c4d7f77076`.
- This is an **intra-object** overflow: the write lands inside the enclosing
  stack `TmpParser`, so default GCC ASan is silent (preserved negative).
  Clang 18 `-fsanitize-address-field-padding=2` reports
  `AddressSanitizer: intra-object-overflow`, `WRITE of size 16` at pinned
  `src/c4/yml/parse_engine.def.hpp:4313` in `_add_annotation()`, from
  `_handle_seq_flow()` and `parse_in_place()` (`parse.cpp:182`), on the
  one-line input `[&a &b &c x]`. `{val: &a &b &c x}` also reports WRITE-16.
- Fixed build: `PARSE_ERROR parse error: too many tags/anchors`, no ASan.
  Safe `[&a x]`: `PARSED nodes=2` in both builds. Three tag lines and block
  sequence anchors reach earlier consumer errors here: preserved negatives,
  not claimed triggers.
- Grade: rung 3 real-source ASan intra-object stack OOB WRITE; rung 4
  **NOT CLAIMED**. No named adjacent object, chosen bytes at chosen offsets,
  pointer value, request-to-parse path, command or r5.

## Next

Window 182 created on the inner tmux socket (two panes, top = this status,
bottom = plant view/wake log) and registered for the target mind. Operator
admission under standing #6 and an independent witness replay are owed by
those roles, not by frontier. Cheapest rung-moving experiment: put the parser
behind a loopback consumer that accepts attacker-supplied YAML, build it
against the pinned vulnerable tree with field-padded ASan, and observe the
WRITE in that consumer; or name the adjacent object overwritten with
attacker-chosen values. Preserve negatives; never claim a wire path from
advisory prose or a command from a harness marker. Would change the mind: a
real consumer ASan report, a chosen-value adjacent-object overwrite, a
fixed-build counterexample, or a replay contradiction.
