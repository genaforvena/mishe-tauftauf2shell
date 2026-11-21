# Frontier brief — OpenJPEG TLM/SOT index overflow (OpenJpeg2Shell)

**Status (updated 2026-11-21 ~16:52Z by openjpeg2shell): ADMITTED; witness
replay ESTABLISHED AS CLAIMED (#957/#958, and #1022 for consumer-reality).
Rungs 1/2/3 ESTABLISHED on the real, verbatim-pinned OpenJPEG 2.5.4
`opj_decompress`. Rung 4: chosen 64-bit stream offsets are byte-exact at the
TPsot-derived OOB offsets; the consumer-reality check observes them landing on
a live neighbouring `tp_index` object and a live malloc size word, the low-bit
grooming sweep shows padding chooses the resulting glibc `free()` path, and a
Pillow consumer check reaches the same sink inside `Image.open().load()` in
both the official bundled-library wheel and a pinned-source build.
Availability impact is demonstrated in a shipped Python image library; no
pointer-value control, controlled dereference at a chosen address,
control-flow diversion, execution or web-facing listener was observed — all
UNKNOWN. The fix is a pinned master commit, not a tagged release.**
Scoped commit `958b319`; trace
`sha256=6983a6a11c8236c6e991e15faa326b4c64f6269cf7f5f4fabca081bf7aa111ea`
(10 PASS / 0 FAIL, clean `git archive` replay). Live two-pane window
`openjpeg2shell` index 60 on the inner tmux socket, registry entry 62,
wall `.mishe-tauftauf/walls/openjpeg2shell.md`. Witness verdict #958; operator
admission #989 under standing #6. Replay traces: consumer-reality
`sha256=55123f30823bda1083c5f4f8b4025767ae89b3fdcec06c3285f82a1aea57c3a1`;
low-bit grooming
`sha256=2c4ca81dc6c31e97969c9a203c8125fe02cfc04e13c0871193027a95204a7dd6`;
Pillow consumer reachability
`sha256=4903f4dc2468a38d5ca1244cd205b36ee6cc0c52b7e43e62e9d0f2370f7596e0`
(15 PASS / 0 FAIL).


## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: OSV-2025-219, "Heap-buffer-overflow in
  `opj_j2k_read_tile_header`", OSS-Fuzz issue 403673832. Published
  2025-03-18T00:18:30Z, modified 2026-10-20T17:24:20Z. Crash type as reported:
  "Heap-buffer-overflow WRITE 8", crash state
  `opj_j2k_read_tile_header` ← `opj_j2k_decode_tiles` ← `opj_j2k_decode`.
  The pinned OSV JSON has **no severity field**; no CVE or GHSA identifier is
  present, so the claim is tracked under the OSV id.
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
  are byte-exact. That earlier run did not identify the destination; the
  consumer-reality check below does: a live neighbouring `tp_index` object.
  Logs: `out-w75/gdb-orig.log`, `gdb-pad.log`, `asan-pad.log`.

## Consumer reality on this host (2026-11-21 ~16:08Z, openjpeg2shell)

The AGENTS.md consumer-reality check was performed on the real, unsanitized,
verbatim-pinned `opj_decompress` under glibc 2.39-0ubuntu8.12 (x86-64):
`bash lab/frontier/openjpeg2shell/consumer-reality.sh` → **10 PASS / 0 FAIL**,
trace
`sha256=55123f30823bda1083c5f4f8b4025767ae89b3fdcec06c3285f82a1aea57c3a1`,
logs and gdb transcript in `lab/frontier/openjpeg2shell/out-consumer/`.
Hardware watchpoints are unavailable in this container (gdb 15.1: "Could not
insert hardware watchpoint"), so the observation uses breakpoints at the real
sink plus direct heap-word readback.

- glibc maps the 24-byte `tp_index` request to a 0x20 chunk: user base
  `0x…ecf0`, size word `0x21` at base−8. The following 0x20 chunk's user area
  begins at base+32, and gdb reports **tile 1's live `tp_index` array at
  `0x…ed10` = tile 0 base + 32** — exactly the OOB destination. At the next
  sink hit, tile 1's `start_pos` reads back `0x21d` (541), the chosen offset
  stored by the TPsot=1 write. This is a live object, not filler.
- The next sink hit (tile 0, TPsot=2, pos 555) overwrites the **following
  chunk's malloc size word** at base+56 from `0x151` (PREV_INUSE only) to
  `0x22b` = 555; `0x22b & 0x2` sets IS_MMAPPED. `opj_j2k_tcp_destroy` then
  calls `free(0x…ed30)` on that chunk's user pointer; glibc takes the
  `munmap_chunk()` path and aborts: `munmap_chunk(): invalid pointer`, rc 134.
  Backtrace: `__libc_free ← opj_free ← opj_j2k_tcp_destroy (j2k.c:9526) ←
  opj_j2k_cp_destroy (:9562)`. Deterministic in 3/3 direct runs of the
  original 202-byte PoC, and also on the padded PoC.
- Controls: pinned fix `91d08b11` in a plain (non-ASan) build decodes the
  padded PoC rc 0 with "Generated Outfile" and no abort; flipping SOT TPsot
  1→0 removes both the OOB and the allocator abort (rc 1, "Invalid tile part
  index"). Fixed-side claims remain scoped to that master pin, not a release.
- Honest boundary: the written value is still a codestream-derived 64-bit
  stream offset, not an arbitrary pointer. What is demonstrated is chosen
  bytes at chosen offsets in a live neighbouring object and live allocator
  metadata, with a deterministic abort in a real decoder process. No
  pointer-value control, pointer dereference, control-flow diversion,
  execution or listener was observed at that point; a Pillow consumer was
  exercised later (section below). Rung 4 stays PARTIAL/INSTRUMENTED under
  that label; no shell claim.

## Low-bit grooming: chosen size word selects the allocator outcome (2026-11-21 ~16:50Z)

`bash lab/frontier/openjpeg2shell/groom.sh <outdir>` → **5 PASS / 0 FAIL**,
trace
`sha256=2c4ca81dc6c31e97969c9a203c8125fe02cfc04e13c0871193027a95204a7dd6`,
sweep table and per-run logs in `lab/frontier/openjpeg2shell/out-groom/`.
Question: can benign COM padding tune the OOB-written stream offset — the
`end_header` value landing on the live `m_mct_records` chunk's size word at
`tp_index` base +56 — into a chosen glibc chunk size, and what does the real
`free()` do with it?

The inserted COM segment adds 6+N bytes before the first SOT, so the second
tile-part's SOD offset, i.e. the value the TPsot=2 store writes at base+56, is
177+N. A small `free()` interposer built by the script logs the size word at
the pointer actually passed to `free()` in the unsanitized pinned process.
This observes the unperturbed heap: gdb breakpoints change this small PoC's
layout (at the sink the size word at base+56 reads 0, and the crash disappears),
so the decisive observation is from the interposer, not gdb.

Sweep N=0..16 (size word 177..193 = 0xb1..0xc1):

- N=0 (0xb1) and N=15/16 (0xc0/0xc1): the chosen size word is accepted,
  `free()` returns normally and the decoder exits rc 0 with "Generated
  Outfile" — the metadata corruption is **silent**. The interposer sees the
  chosen size at the freed pointer.
- Size words 0xb2/0xb3/0xb6/0xb7/0xba/0xbb/0xbe/0xbf: `munmap_chunk():
  invalid pointer`, rc 134.
- Size words 0xb4/0xb5/0xbc/0xbd: rc 139 SIGSEGV, consistent with a
  backward-consolidation dereference; that internal path was not traced under
  the unperturbed process, so the mechanism stays an inference.
- Size words 0xb8/0xb9: `free(): invalid size`, rc 134.

The outcome class is chosen by codestream padding and repeats deterministically.
The fixed pin `91d08b11` decodes the N=1 codestream rc 0 with "Generated
Outfile", no allocator diagnostic.

Honest boundary: the value remains a bounded stream offset (177..193 here;
541/555 in the larger pad), not an arbitrary pointer. The glibc *path* is
codestream-chosen and the availability impact is real, but the pointer
dereferenced in the SIGSEGV class comes from stale heap words, not from
codestream-supplied bytes. No chosen-address pointer control, controlled
dereference, control-flow diversion or execution was observed. This
strengthens the demonstrated availability impact; rung 4 stays PARTIAL.


## Pillow / libopenjp2 2.5.4 consumer reachability (2026-11-21 ~16:52Z)

`bash lab/frontier/openjpeg2shell/pillow-consumer.sh <outdir>` → **15 PASS /
0 FAIL**, trace
`sha256=4903f4dc2468a38d5ca1244cd205b36ee6cc0c52b7e43e62e9d0f2370f7596e0`,
logs in `lab/frontier/openjpeg2shell/out-pillow/`. This closes the gap the
earlier sections left open: whether the GHSA-78g4-xqwv-q3g8 claim — a web-facing
image consumer reaches the vulnerable library — holds on this host. Everything
here is a local Python process; the PyPI fetches are pinned provisioning with
verified SHA-256, never probes.

- **Official shipped wheel, bundled library.** The manylinux CPython 3.12
  `pillow-12.2.0` wheel reports `PIL.features.version("jpg_2000") == "2.5.4"`,
  the exact affected pin; the pinned sdist's own
  `depends/install_openjpeg.sh` sets `archive=openjpeg-2.5.4`. `Image.open(
  path).load()` on either the public 202-byte PoC or the padded PoC aborts
  deterministically with `corrupted size vs. prev_size`, rc 134; the bundled
  benign `test-card-lossless.jp2` loads rc 0. No library swapping: this is the
  unmodified wheel's own JPEG 2000 decoder.
- **Exact sink inside `load()`.** Pillow 12.2.0 built with `JPEG2K_ROOT` against
  the pinned vulnerable `libopenjp2.so.7`, with an ASan build of the same pinned
  source, reports `heap-buffer-overflow WRITE of size 8` at `j2k.c:5086`; the
  24-byte region is allocated at `j2k.c:8939`. The stack runs
  `opj_read_tile_header → j2k_decode_entry (libImaging/Jpeg2KDecode.c:794) →
  ImagingJpeg2KDecode (:949) → _decode (src/decode.c:132)` into the Python
  caller. The plain pinned build faults rc 139 on both PoCs, the fixed pin
  `91d08b11` in the same Pillow process decodes the padded PoC rc 0 with
  `LOAD_OK`, and `LD_LIBRARY_PATH` resolution of each `.so` is asserted, not
  assumed. A plain source install of the sdist has no JPEG 2000
  (`jpg_2000 None`), so the route comes from the official wheel's bundle or a
  deliberate pinned `JPEG2K_ROOT` build.

gdb on the plain Pillow process places the rc 139 fault in `PyGC_Collect()`
during `Py_FinalizeEx()`: the corrupted allocator metadata survives `load()`
and faults at interpreter teardown, not at the sink. No listener, web server,
external request or process outside this lab was used.

Honest boundary: the written value remains a bounded codestream-derived stream
offset, not a pointer. Reachability from a shipped Python image library is now
lab evidence, but the primitive is unchanged — no chosen-address pointer
control, controlled dereference, control-flow diversion, code execution or
shell, and no web-facing listener. Rung 4 stays PARTIAL with a stronger
availability-impact label; any shell claim remains UNKNOWN.

## Rung-4 feasibility and remaining gap

The write value is a stream offset, not an arbitrary 64-bit constant: it is
bounded by practical codestream length, and the useful part (low bytes) can be
shifted by padding. The index multiplies by 24, so larger `TPsot` values reach
far past the small `tp_index` allocation — usually unmapped memory, i.e. a
crash, unless a groomed heap places an object at that offset. Public metadata
makes a real consumer route plausible, and that route has now been exercised
locally (section above): the official Pillow 12.2.0 wheel bundles libopenjp2
2.5.4 and reaches the sink through `Image.open().load()`, aborting on the PoC.

The consumer-reality check above found a live neighbouring object and a live
malloc size word overwritten, with a deterministic abort in the real decoder;
the grooming sweep showed padding also chooses which allocator path fires.
The Pillow check adds reachability from a shipped image library but not a new
primitive: the written value stays a bounded stream offset. Hardware
watchpoints were unavailable in this container; equivalent evidence came from
sink breakpoints and direct heap readback. Remaining gap: pointer-value
control, control-flow diversion, execution and a web-facing listener remain
UNKNOWN. No chosen-address pointer dereference was observed, and none appears
reachable from a bounded stream-offset write with the heap layouts seen here.

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
