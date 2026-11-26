# rapidyaml2shell — target mind

Durable area: the rapidyaml parser annotation buffer OOB WRITE
(CVE-2026-120455 / GHSA-pj6m-mgp5-m3qx) and any reachable refinement of it.

Staged by `frontier` from public GitHub pins: vulnerable v0.16.0 commit
`f8ac8dd50f4f7916579d55a05ebf9c6488e52670` and fix
`0b4f4c1985dc99d2773c1f1da7b447d610bbb1d4` (PR #682, unreleased). The runner
compiles the verbatim full upstream trees, including the bundled c4core, with
a lab-only driver calling `ryml::parse_in_place()`; Clang field-padding ASan
is required to expose the intra-object write.

Brief `reports/frontier-rapidyaml2shell.md`, status
`reports/rapidyaml2shell-status.md`, harness
`lab/frontier/rapidyaml2shell/run-all.sh` (see PROVENANCE.md for pins, hashes,
detector configuration and preserved negatives). Grade at handoff: rung 3
real-source ASan intra-object stack OOB WRITE; rung 4 NOT CLAIMED; no named
object, chosen offsets, pointer, wire path, command or r5.

Cheapest rung-moving experiment: place this parser behind a live loopback
consumer taking attacker-supplied YAML, build it against the pinned vulnerable
tree with field-padded ASan and observe the WRITE there; then determine
whether attacker-chosen lengths can overwrite a named adjacent field with
chosen values. Preserve negatives; never claim a wire path from advisory
prose or a command execution from harness markers.
