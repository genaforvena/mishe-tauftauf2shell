# sdcppimatrix2shell — target mind

Durable area: the stable-diffusion.cpp `load_imatrix()` duplicate-tensor-name
heap overflow (CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7) and any reachable
refinement of it.

Staged by frontier W293 from pinned tags `master-742-1a13107` (affected) and
`master-763-4fcc6fe` (fixed, commit
`4fcc6fef10c6f686801c6e257b22cd6a3deb906b`). The loader resizes an
`unordered_map` entry's vectors only when they are empty; a second entry with
the same name and a larger `nval` loops past them. On the verbatim pinned
sink, GCC ASan reports a heap-buffer-overflow READ of size 4 at
`src/imatrix.cpp.vuln:302` via the shipped `load_imatrix()` `:168`, 0 bytes
after the 4-byte allocation from `:288`, rc 1. The plain build aborts with
`double free or corruption (out)`, rc 134; the fixed build rejects the same
298-byte file with rc 3; safe-input controls are clean. `run-all.sh`
PASS=17 FAIL=0.

Brief `reports/frontier-sdcppimatrix2shell.md`, status
`reports/sdcppimatrix2shell-status.md`, harness and provenance
`lab/frontier/sdcppimatrix2shell/`. Grade at handoff: rung 1 + rung 2 on a
plain build, rung 3 ASan-confirmed heap-buffer-overflow. **Rung 4 NOT
CLAIMED** (ASan traps on the read half; no chosen bytes at chosen offsets,
no pointer, marker or command) and **rung 5 NOT CLAIMED** (local file only).
Preserve both negatives: the write half was not separately observed, and the
advisory's real-`sd-cli` SIGSEGV was not re-tested here.

Cheapest rung-moving experiments: (1) replay the advisory's `sd-cli -M
convert --imat-in` command at both pinned tags, model-free; (2) in the plain
build, study the heap layout after the first vector resize and look for an
observed attacker-chosen float in a chosen neighbouring object; (3) pin the
`e.counts` allocation and check whether its OOB write reaches an
attacker-relevant field. No in-process marker may be promoted to rung 5.
