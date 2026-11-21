# Frontier brief — OpenJPEG TLM/SOT index overflow (OpenJpeg2Shell)

**Status: frontier find, brief + harness COMPLETE (2026-11-21 ~14:45Z);
UNADMITTED, witness replay and operator admission pending. Rungs 1/2/3 are
ESTABLISHED on the real, verbatim-pinned OpenJPEG 2.5.4 `opj_decompress`
binary: rung 3 is the ASan report, rungs 1/2 run without sanitizers. Rung 4 is
INSTRUMENTED: two chosen 64-bit stream-offset values, byte-exact, at the
TPsot-derived out-of-bounds offsets in a staged heap area. No JPEG 2000
application, listener, real heap neighbour object, pointer, control-flow
diversion or execution was observed — all stay UNKNOWN. The fix is a pinned
master commit, not a tagged release.**

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: OSV-2025-219, "Heap-buffer-overflow in
  `opj_j2k_read_tile_header`", OSS-Fuzz issue 403673832. Published
  2025-03-18T00:18:30Z, modified 2026-10-20T17:24:20Z. Crash type as reported:
  "Heap-buffer-overflow WRITE 8", crash state
  `opj_j2k_read_tile_header` ← `opj_j2k_decode_tiles` ← `opj_j2k_decode`.
  Ecosystem severity HIGH. No CVE or GHSA identifier is present in the OSV
  record; the public claim is tracked under the OSV id.
- **Versions**: OSV's affected range is git `introduced 954c6e3c…`, fixed by
  `d33cbecc…` and `91d08b11…`; its concrete version list still names v2.5.3
  and v2.5.4 as affected. The fix commit is dated 2026-02-10 and is on master,
  but **no tagged release contains it** at the time of writing. Per operator
  #916 precedent a fixed pin suffices for admission; every fixed-side claim
  below is scoped to commit `91d08b11`, not to a release.
- **Public report and PoC**: upstream issue #1620 (opened 2026-01-20 by
  `soiax`, closed 2026-02-10) explains the mismatch between a `tp_index` array
  sized from TLM entries and an unbounded SOT `TPsot` index, and publishes a
  202-byte raw codestream (`poc.zip`, really a `.j2k`) plus an ASan trace with
  `WRITE of size 8` 8 bytes after a 24-byte region. Issue #1620 and its fix PR
  #1621 (merged 2026-02-10T21:02:47Z, merge commit `d33cbecc…`) are pinned.
- **Fix**: commit `91d08b11a72764f6d199f32fa0c1b1abd4edc2ad` ("Fix heap buffer
  overlfow in opj_j2k_read_sod") adds a three-part guard at the sink: require
  `tp_index != NULL` and `current_tile_part < nb_tps` before the two stores.
  Patch pin in `lab/frontier/openjpeg2shell/src/fix-91d08b11.patch`.
- **Pins**: eight SHA-256 pins including both full source tarballs, the public
  PoC, the OSV/issue/PR/commit records and the fix patch in
  `lab/frontier/openjpeg2shell/src/SHA256SUMS`; digest table in
  `lab/frontier/openjpeg2shell/PROVENANCE.md`.

## Source-bound mechanism (raw pinned bytes)

- `openjpeg.h:996-1004`: `opj_tp_index_t` is three `OPJ_OFF_T` (8-byte) fields
  — `start_pos`, `end_header`, `end_pos` — so one entry is 24 bytes.
- `j2k.c:8939` in `opj_j2k_build_tp_index_from_tlm` allocates
  `current_nb_tps * sizeof(opj_tp_index_t)` with `opj_calloc`, i.e. the number
  of tile-parts declared in TLM. The public PoC's TLM yields a one-entry,
  24-byte allocation.
- `j2k.c:4659` copies the SOT marker's `TPsot` field into
  `tile_index[tile].current_tpsno` with no consistency check against
  `nb_tps`. In the PoC `TPsot = 1` while `nb_tps = 1`.
- `j2k.c:5081-5090` in `opj_j2k_read_sod` takes that value as
  `l_current_tile_part` and stores, with no guard:
  `tp_index[l_current_tile_part].end_header = l_current_pos` (`:5086`) and
  `.end_pos = l_current_pos + m_sot_length + 2` (`:5088`). `l_current_pos` is
  an `OPJ_OFF_T` stream offset, so each store is **8 bytes** and the value is
  a 64-bit codestream-derived integer. The offset from the allocation base is
  `TPsot * 24 + 8` for the first store.
- Fixed `91d08b11` `j2k.c:5083-5092` wraps both stores in
  `if (tp_index && l_current_tile_part < nb_tps)`. A similar guard already
  exists at `j2k.c:8460-8463` in a different function; that unrelated guard is
  not protection for this sink. The harness checks the exact sink block.

## Lab evidence (`lab/frontier/openjpeg2shell/`, `bash run.sh <outdir>`)

`10 PASS / 0 FAIL`, trace
`sha256=6983a6a11c8236c6e991e15faa326b4c64f6269cf7f5f4fabca081bf7aa111ea`
over the ordered PASS lines (no PIDs, addresses or paths).

- **Rung 1** — the real unsanitized `opj_decompress` reaches `opj_j2k_read_sod`
  on the public PoC; gdb at `:5092` reports `tile=0 tpsno=1 nb_tps=1 pos=157`.
- **Rung 2** — the observed accounting failure is exactly the mismatch:
  SOT `TPsot=1` indexes a one-entry 24-byte `tp_index`, i.e. the first store
  targets `tp_index[1].end_header` at allocation base +32.
- **Rung 3** — ASan on the verbatim pinned source:
  `WRITE of size 8`, `opj_j2k_read_sod j2k.c:5086` ← `opj_j2k_read_tile_header
  :9912` ← `opj_j2k_decode_tiles :12079` ← `opj_j2k_exec :9181` ←
  `opj_j2k_decode :12425` ← `opj_decode openjpeg.c:526` ← `main
  opj_decompress.c:1582`; "8 bytes after 24-byte region"; allocation
  `opj_calloc` ← `opj_j2k_build_tp_index_from_tlm j2k.c:8939` ←
  `opj_j2k_read_header_procedure :9152`. Log: `out-w75/asan-orig.log`.
- **Fixed side** — the same PoC on pinned `91d08b11` decodes cleanly under
  ASan, `rc=0`, emits "Generated Outfile"; no ASan report. Log:
  `out-w75/fixed.log`.
- **Rung 4 INSTRUMENTED** — gdb on the unsanitized pinned build reads the two
  written values back from the area adjacent to the 24-byte allocation:
  public PoC `OOB_ENDHDR=0x…009d (157)`, `OOB_ENDPOS=0x…009f (159)` at offsets
  +32/+40. A harness-authored COM pad inserts 384 bytes before the SOT
  (`make-pad.py`, no other PoC byte changed); the same sink then writes
  `0x…021d (541)` and `0x…021f (543)` at the same +32/+40, and the padded file
  still faults the pinned sink under ASan. The attacker chooses the 64-bit
  value through codestream layout and the offset through `TPsot`; the bytes
  are byte-exact, but the destination is a staged adjacent heap area, not an
  identified live object. Logs: `out-w75/gdb-orig.log`, `gdb-pad.log`,
  `asan-pad.log`.

## Rung-4 feasibility and cheapest next experiment

The write value is a stream offset, not an arbitrary 64-bit constant: it is
bounded by practical codestream length, and the useful part (low bytes) can be
shifted by padding. The index multiplies by 24, so larger `TPsot` values reach
far past the small `tp_index` allocation — usually unmapped memory, i.e. a
crash, unless a groomed heap places an object at that offset. Public metadata
makes a real consumer route plausible: Pillow GHSA-78g4-xqwv-q3g8 bundles
libopenjp2 2.5.4 reachable from `Image.open().load()`. That route was NOT built
or tested here; it is a claim, not lab evidence.

Cheapest rung-4 step for an admitted target mind: build the actual
`opj_decompress`/Pillow consumer on loopback against pinned 2.5.4, feed the
padded codestream, set a gdb watchpoint on `tp_index[1].end_header`, and
observe whether a live heap object's metadata or pointer field is overwritten
before the process aborts. Until that is observed, pointer control,
control-flow diversion and execution stay UNKNOWN.

## Next-candidate queue (updated 2026-11-21)

- wolfSSL CVE-2026-6679 (DTLS 1.3 ACK integer truncation, fixed 5.9.1) and
  HTSlib CVE-2026-62257 (CRAM v4 pointer write, fixed 1.24) are the remaining
  ranked candidates. wolfSSL's stateful DTLS path is more expensive than this
  decode path; HTSlib has a released fixed version.
- OpenJPEG is ranked first for a dedicated mind once admitted; handoff needs
  this brief, the live two-pane window and the operator's admission.

## Scope and boundaries

Local process only: no socket, listener, external probe or other plant's lane.
Sources were fetched read-only as provisioning. Harness stand-ins, exact
copied ranges and the corrected 64-bit write-value label are in
`PROVENANCE.md`. Witness re-runs this claim with a clean `git archive` replay.
