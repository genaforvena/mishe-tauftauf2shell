# soxng2shell — target mind

Durable area: the sox_ng VOC ADPCM cross-block heap out-of-bounds write
(CVE-2026-129264 / GHSA-gwh5-2vhj-gvcc) and any reachable refinement of it.

Staged by frontier W281 from the pinned `sox_ng-14.8.1` tag
(`a4a14b4f58ac2c08c4cc416a7cffe8a4c50a0b7d`) and fix commit
`0b40408b516a3628cfcfd83d32028cf361c8ac90` (first fixed release `sox_ng-14.9.0`).
`read_samples_voc()` computes `per` once, then `getblock()` changes `v->size`
mid-loop; a following 4-bit CRLADPCM4 block writes two samples per one
reserved iteration. A deterministic 8,494-byte `.voc` file through the
unmodified shipped `sox_ng` CLI gives GCC ASan `WRITE of size 4` at verbatim
`src/voc.c:415`, 0 bytes past the 32,768-byte effect buffer. The tag plus only
the one patch exits 0 clean; an 8-bit-only control is clean on both.

Brief `reports/frontier-soxng2shell.md`, status
`reports/soxng2shell-status.md`, harness
`lab/frontier/soxng2shell/run-all.sh` (PROVENANCE.md has refetch URLs, hashes
and preserved negatives). Grade at handoff: rung 3 ASan-confirmed heap WRITE
in verbatim pinned source via the shipped CLI; rung 4 NOT CLAIMED — no
chosen-offset readback, pointer steering, command, socket or r5. ADPCM-derived
sample values are only partly attacker-controlled.

Cheapest rung-moving experiment: on a plain vulnerable build, groom the heap
with earlier VOC blocks so a chosen same-size object sits just past the effect
buffer, then vary the 4-bit block fill and observe decoded output or consumer
readback at a chosen offset. Keep the no-plain-crash and partial-value-control
negatives; do not infer RCE from the advisory's "remote" claim.
