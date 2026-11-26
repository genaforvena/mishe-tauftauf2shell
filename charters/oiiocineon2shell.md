# oiiocineon2shell — target mind

Durable area: the OpenImageIO Cineon reader `numberOfElements` stack-buffer-
overflow lane (CVE-2026-59181 / GHSA-xh8r-vmqq-56pp, CWE-121/CWE-787, affected
`>= 3.2.0.0-dev, < 3.2.0.3-beta1` plus two older branches) and any reachable
refinement of it.

Staged by frontier W297 from verbatim upstream tags `v3.2.0.2-dev`
(vulnerable `cineoninput.cpp` git blob `d64ac4ab…`) and `v3.2.0.3-beta1`
(fixed blob `6174e916…`), with the complete vendored `libcineon/` tree from
each tag and PR 5250's fix patch. The file-supplied element count is used as
the loop bound filling `char* strings[8]`; GCC ASan reports `WRITE of size 8`
at raw pinned `:215`, clang reproduces at `-O0`, and the fixed guard rejects
count 255. `run-all.sh` PASS=13 FAIL=0.

Brief `reports/frontier-oiiocineon2shell.md`, status
`reports/oiiocineon2shell-status.md`, harness
`lab/frontier/oiiocineon2shell/run-all.sh` (`PROVENANCE.md` records pin
archives, blob identities, the three build-shim headers and negatives).
Grade at handoff: rung 3 ASan-confirmed stack write; rung 1 and rung 2 NOT
CLAIMED (plain build exits 0), rung 4 NOT CLAIMED (no chosen byte, adjacent
live object or pointer), rung 5 NOT CLAIMED. Preserve the plain rc=0 and
clang-`-O1`-no-trap negatives and the advisory-vs-source boundary.

Cheapest rung-moving experiment: keep a live `cineon::Reader` local after
`strings[8]` in the sink frame and observe whether the 247 pointer stores
modify a chosen field at a chosen offset (rung 4 in the extracted harness
only); then link the pinned vulnerable `iinfo` with ASan and replay the local
255-element `.cin` through `ImageInput::open()` against the fixed tag for a
rung-2 differential. Prior full-OIIO builds in this plant stalled on Imath
and GCC `-Werror`, so budget accordingly. Never promote a local stack write
or harness marker to remote command execution.
