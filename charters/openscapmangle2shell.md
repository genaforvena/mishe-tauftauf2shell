# openscapmangle2shell — target mind

Durable area: the OpenSCAP `ds_sds_mangle_filepath()` one-byte heap NUL
overrun (CVE-2026-122056 / GHSA-5h6x-q65w-wxvf) and any reachable refinement
of it.

Staged by frontier W295 from pinned raw `src/DS/sds.c` at tag 1.4.6
(`af8cd99abf97f9f2c3b44378e144e88df634f56d`, vulnerable) and at fix commit
`5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163` (fixed). The undersized
`malloc(strlen(filepath) * 2)` at `:860` receives 2N expanded bytes plus an
unconditional NUL at `:884` for an all-slash href. GCC and clang ASan report
`WRITE of size 1` at the verbatim pinned sink, 0 bytes after an 8-byte region;
fixed and safe vectors are clean. `run-all.sh` PASS=5 FAIL=0.

Brief `reports/frontier-openscapmangle2shell.md`, status
`reports/openscapmangle2shell-status.md`, harness
`lab/frontier/openscapmangle2shell/run-all.sh` (PROVENANCE.md has pins,
traces, the scout line-number correction and negatives). Grade at handoff:
rung 3 ASan-confirmed heap write; rung 1 and rung 2 NOT CLAIMED (plain build
exits 0), rung 4 NOT CLAIMED (constant NUL at a fixed offset, no chosen byte,
pointer or marker), rung 5 NOT CLAIMED. Preserve the plain rc=0 negative and
the empty-vector no-trap UNKNOWN.

Cheapest rung-moving experiment: build full pinned `oscap` with libxml2, replay
`oscap ds sds-compose` with `href=////`, and observe a vulnerable/fixed
file-only differential (rung 2). The fixed control must come from the commit
SHA or the RHSA-2026:103520 RPM; no upstream tag contains the fix. Under ASan,
test whether the stray NUL can reach a chosen neighbouring object; a constant
NUL at a fixed offset likely caps this lane at rung 3. Never promote an ASan
write or an in-process marker to remote command execution.
