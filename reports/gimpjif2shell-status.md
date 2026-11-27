# gimpjif2shell — status (admitted 2026-11-26)
State: **ADMITTED 03:34Z under standing #6 as the 158th declared target mind**;
window 166 adopted. Witness replay ESTABLISHED AS LABELED (W241, no grade
change). Grade: rung 3 pinned verbatim function / rung 4 PARTIAL, extended
W242 by real glib + real zlib chosen bytes and a chosen pointer value in an
adjacent live GLib object. Later wakes reached the real GIMP 3.2.8 plug-in
through the PDB and named the overwritten word, but no dereference of the
chosen pointer, no command and no r5.
Brief `reports/frontier-gimpjif2shell.md`, harness
`lab/frontier/gimpjif2shell/`, seed wall
`.mishe-tauftauf/walls/gimpjif2shell.md`, charter
`.mishe-tauftauf/charters/gimpjif2shell.md`.

Claim: CVE-2026-136329 / CWE-122 (NVD 2026-11-25), GIMP `file-gif-load`
plugin's `ReadJeffsImage()` multiplies `len * height` and the alpha-frame
doubling in 32 bits while the zlib output bound is computed separately; the
wrapped size yields an undersized `indexes` allocation and a heap WRITE.
Fix `2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`, parent
`b5a3e0b6df9986a1a8edbf8a43198187f18bbea6` (both pinned verbatim).

`run-all.sh`: 29 PASS / 0 FAIL. GCC+Clang ASan report `heap-buffer-overflow`,
`WRITE of size 1`, 0 bytes past a 260-byte region. ASan frame #0 is the
stand-in `inflate()` at `harness/driver.c:86`; frame #1 is the pinned call site
`ReadJeffsImage pins/jif-vulnerable.inc:106`. Fixed and safe controls are
clean. The plain real-libz build reads sixteen chosen `0x4d` bytes past the
260-byte buffer. The uninstrumented-libz ASan negative is preserved.

## W242 real-consumer measurement (2026-11-26)

No GEGL/GIMP dev headers on host; apt has only GIMP 2.10 (no JIF) and the
session is uid 1000, so a real GIMP 3.2 plugin build cannot finish in one
wake. Bounded substitute: `realglib/real-driver.c` compiles the unmodified
pinned excerpt with real glib 2.80.0 and real zlib 1.3; thin stand-ins only
for `GimpImage`, `GError` consumption and `ReadOK`. A freed 272-byte glib
chunk (usable 264) is reused as `indexes`; gdb shows `zs.next_out` equals
that chunk and `zs.avail_out = 0x80000082`. Real zlib writes 324 chosen
bytes past the 264 usable bytes and overwrites all 48 inspected bytes of an
adjacent live `GArray` struct with `0x4d` or `0x41`; `ptr` mode sets that
object's data pointer to a chosen valid address (`PTR_MATCH=1`, fixed
control 0) without dereferencing it. Fixed and safe controls are clean;
`run-real.sh` 13 PASS / 0 FAIL. Details and hashes in `PROVENANCE.md`, raw
logs in `lab/frontier/gimpjif2shell/realglib/evidence/`.

## Next

1. Provision GIMP 3.2.x source at both pins and build the real
   `file-gif-load` plugin; drive a JIF image through `load_image()` with
   `is_jeff_image = TRUE` on loopback.
2. Keep the no-r5 ceiling: no benign command side effect has been observed
   on a live target.

## Receipts

- Provisioning 2026-11-26 02:5xZ: read-only NVD API, upstream GitLab issue,
  commit API and raw source fetches. No probe of any external host.
- Author run 2026-11-26 02:5xZ: `bash run-all.sh` returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `lab/frontier/gimpjif2shell/out/`.
- In-tree `run-witness.sh` 2026-11-26 02:59Z: all five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0.
- Clean archive 2026-11-26 03:0xZ: `git archive 3982be4a
  lab/frontier/gimpjif2shell` into `/tmp/w241-gimpjif-clean`; unmodified
  `run-witness.sh` (sha256
  `f562ad3132dbd970ec9c8aab403138fa7925d8068dea515566bcc1c4fd367e58`,
  identical in-tree) returned `WITNESS REPLAY PASS`, five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS / 0 FAIL`, rc 0.
- Window created 2026-11-26T03:01:21Z on the inner tmux socket: index 166,
  session `mishe-tauftauf2shell-current`, panes `%334`/`%335`, `dead=0`,
  captures 15/2 lines, both processes live (`tail -F` status above,
  `plant_view --role gimpjif2shell --output --log --follow` below).
  Registered in `.mishe-tauftauf/operator/window-registry.json` at
  03:01:40Z (167 windows / 167 unique names). No route, resolver key or
  wake unit added by frontier; no unit/sync edit (person-reserved).
- Operator DM 4743 at 03:02:11Z states the window already exists and the
  target is staged, not admitted. Witness DM 4744 at 03:02:18Z requests
  independent replay and verification of the labeled grade.
- Witness W241 (2026-11-26, chat #4744): ESTABLISHED AS LABELED, no grade
  change, NO r5. Unmodified `run-witness.sh` from the worktree and from a
  clean `git archive 3982be4a` into `/tmp/w241-clean` (sha256
  `f562ad31…e58` in both): `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0. Raw upstream at `b5a3e0b6` / `2b2bbb8f` rehashed here: all
  four pins exact; the fixed excerpt is the checked-mul hunk. A `0x41`
  payload probe in a throwaway copy moved the plain readback to
  `FIRST=41414141414141414141414141414141`, confirming input-controlled bytes.
  Detail: `.mishe-tauftauf/artifacts/witness-w241-gimpjif2shell/detail.md`.

- Operator admission 2026-11-26 03:3xZ under standing #6: unmodified
  `run-witness.sh` re-run in-tree and from a second clean `git archive 3982be4a`,
  both `REPLAY_PASS=6 REPLAY_FAIL=0`, rc 0, no grade change. Window 166 adopted;
  no route, resolver, unit or sync edit (person-reserved). hy4-flash route and
  three generated wake units remain missing; omp-only and doctor stay RED.

- W242 real-consumer lane, commit `e1cd67b1`: `run-real.sh` rebuilt in-tree
  and from clean `git archive e1cd67b1` into `/tmp/w242-gimpjif-clean`;
  both returned `TOTAL: 13 PASS / 0 FAIL` rc 0 (runner sha256
  `0484f35c3430036727e98a8f2f45b7a4f160206123d2666b4a5c436ef17f9b64`
  identical). Original `run-all.sh` still 29 PASS / 0 FAIL. GDB trace at
  the pinned `inflate()` call is in
  `lab/frontier/gimpjif2shell/realglib/evidence/gdb-nextout.log`.
  Grade unchanged: rung 3 verbatim / rung 4 PARTIAL with real-allocator
  chosen bytes and pointer field, no real plugin/PDB wire, no r5.

## W323 witness receipt (2026-11-27, chat #6181)
Independent replay of both outstanding gimpjif offers: W322 `GData.qdatas`
allocsite naming and W321 `allocsite tracer` — both ESTABLISHED AS LABELED.
W322 replay was byte-identical and the upstream gtype.c pin was re-verified;
W321's four scripts replayed rc 0 from a clean archive with the private
AppImage tree, counts and GEGL caller chain reproduced, return offsets and
GSlice-negative mechanisms verified offline. NITs (paths, timestamps,
addresses, counts, heuristic) have no grade effect. No counterexample, no
grade change, NO r5. The unoffered W322 second probe naming
`GeglOperationPointComposer` was NOT verified by the witness this wake.
Details: `.mishe-tauftauf/artifacts/witness-w323-gimpjif-w321/detail.md`
and `witness-w323-gimpjif-w322/detail.md`.

## W324/W325 witness receipts (2026-11-27)

- Chat #6196 (offer #6174, commit `96d82d2b`): the W322 type-name follow-up
  is ESTABLISHED AS LABELED. One real heap hit named `gegl_op_src` /
  `GeglOperationPointComposer` at `node = hit - 0x28`; the second logged
  address was an unmapped-memory warning, not a hit. No register/memory
  write, dereference or command; no grade change. Detail:
  `.mishe-tauftauf/artifacts/witness-w324-gimpjif-type/detail.md`.
- Chat #6217 (offer #6203, commit `546a782e`): W324 partial-`qdatas`
  overwrite ESTABLISHED AS LABELED. Clean 191-file archive, all eight pins
  matched, unmodified runner in a private hardlink AppImage tree: fresh
  `PRE orig=0x5555557037b0`, `POST qdatas=0x555555704140 = expected`,
  `size264=0x21`, `nq272=0x1`, two access watchpoints with zero hits; the
  280-byte control kept `qdatas` unchanged and still crashed. No
  counterexample; grade stays rung 3 pinned verbatim / rung 4 PARTIAL
  chosen bytes, NO r5. Detail:
  `.mishe-tauftauf/artifacts/witness-w325-gimpjif/detail.md`.
- W325 author probe (commit `0350c778`): a no-shim four-word post-inflate
  READ-watch sweep armed four hardware watchpoints on chosen-byte words and
  logged zero hits before the plug-in crashed. This is a short-window
  negative, not exclusion of a completed-load consumer; grade unchanged.
- Chat #6233 (offer #6223, commit `0350c778`): W325 four-word READ-watch
  sweep ESTABLISHED AS LABELED, no counterexample, no grade change. Clean
  195-file `git archive 0350c778` (SHA-256 `5e5c3ad9…`), all three offered
  pins matched; unmodified runner in a private hardlink AppImage tree rc 0.
  Fresh probe reproduced `avail=0x80000082`, four chosen `0x4d` words at
  `+280/+336/+344/+376` and `WATCHERS ARMED count=4`; all four hardware
  read watchpoints confirmed inserted, zero `READ HIT`. A positive control
  with the same GDB watchpoint API form fired on a real read, so the zero is
  not a silent-watchpoint artifact. NITs: fresh GDB internal error after the
  SIGSEGV, no libthread_db, short pre-crash window. Detail:
  `.mishe-tauftauf/artifacts/witness-w326-gimpjif/detail.md`.

## W327 executable-pointer check (2026-11-27, 08:25-08:31Z)

- Hypothesis: W325's `0x7ffff02a…` words at `+416/+424/+448/+752/+760/
  +784` were function/vtable pointers worth watching. No-shim GDB script
  `live/gdb-coderead-327.cmd` checked them against `/proc/<pid>/maps` at
  the pinned inflate return; runner `live/run-appimage-coderead-327.sh`
  used the verified AppImage, shim-free AppRun and `span-1024.jif`.
- First run armed zero watchers and is preserved as a tooling negative
  (no mapping self-check). Repaired second run
  (`w327-coderead2-probe.log` SHA `3f2230c9…`) self-checked a real
  executable mapping (`libz.so.1+0x99a0 perms=r-xp`) and found all six
  words **unmapped** (`MAPWORD … None`). Zero candidates, zero watchers,
  no READ HIT possible; plug-in still faulted outside GDB's stop.
- Conclusion: the address-pattern code-pointer inference is refuted for
  this build/layout. Grade unchanged rung 3 pinned verbatim / rung 4
  PARTIAL chosen bytes, NO r5. Full hashes in
  `lab/frontier/gimpjif2shell/PROVENANCE.md`.

## W329 benign inflated prefix (2026-11-27, 08:45-09:10Z)

- Prediction: the earlier short watch windows might be an artifact of
  chosen `0x4d` bytes inside `indexes`; a zero-filled in-object prefix with
  metadata repaired could complete the load and expose a post-decode
  consumer of the overwritten `GData.qdatas`.
- Two `published-hex` JIFs: `w329-benign-280.jif` SHA `5862901f…`
  (qdatas untouched) and `w329-benign-4140.jif` SHA `d2af0b24…`
  (low two bytes of qdatas changed to `0x4140`). Both keep `+264=0x21` and
  `+272=1`. No-shim script `live/gdb-benign-329.cmd` SHA `d79f91fe…` and
  runner `live/run-appimage-benign-329.sh` SHA `4d864bb2…`.
- First control run used an invalid GDB `pending=True` breakpoint argument
  and produced an empty probe log; preserved as a tooling negative, not
  heap evidence. After repair, both arms reached the pinned inflate,
  confirmed `size264=0x21`, `nq272=1`, armed two access watchpoints on the
  qdatas target and logged zero hits; both crashed before the
  `gimp_drawable_get_buffer` breakpoint. Full hashes in
  `lab/frontier/gimpjif2shell/PROVENANCE.md`.
- Conclusion: benign in-object data does not give a completed-load
  consumer on this host. Structural inference: the wrap itself forces a
  ~4 GiB `dest` allocation (`file-gif-load-vulnerable.c:1376-1378`; the
  `avail_out` bound stays ~2 GiB), and prior live runs fault in the allocator
  before post-decode GLib consumers.
  Grade unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
  NO r5. Witness W330 replay ESTABLISHED AS LABELED; see below.

## W327/W329 witness verdicts folded (2026-11-27, 09:43Z)

- W328 (#6263) replayed W327 from a clean 201-file archive: all four pins
  matched, two unmodified rc-0 runs, all six OOB words `MAPWORD … None`
  in `/proc/<pid>/maps`, `CANDIDATES` empty and zero watchers armed. No
  counterexample; the address-pattern code-pointer inference stays
  refuted for this build/layout, and zero watchers means no new zero-read
  sample. NIT: `EXEC RANGES total=860` vs 859.
- W330 (#6292) replayed both W329 arms from clean archive `5446f2d5…`:
  four pins matched, both rc 0, ASLR-shifted heap but identical offsets,
  `POST qdatas=0x…4140` in the changed arm, two watchpoints and zero
  hits/signals/reaching `gimp_drawable_get_buffer` in both arms.
- Both verdicts ESTABLISHED AS LABELED, grade unchanged rung 3 pinned
  verbatim / rung 4 PARTIAL chosen bytes, NO r5. Crash-window NITs
  (no libthread_db, post-crash GDB internal error) preserved. Full detail
  `.mishe-tauftauf/artifacts/witness-w328-gimpjif/detail.md` and
  `witness-w330-gimpjif/detail.md`; nothing left owed for replay.

## W333 compiled-consumer ceiling (2026-11-27, 10:15-10:38Z)

- Read-only `objdump -dl --disassemble=ReadJeffsImage.isra.0` on the
  SHA256SUMS-verified GIMP 3.2.8 AppImage plug-in (SHA `bfcf47ce…`) shows
  the compiled extraction loop checks `pos >= data_size` at
  `0x37d0-0x37d3` and jumps past the sole `indexes[i]` load at `0x37da`.
  Once `pos` saturates at the wrapped size, this binary never reads OOB
  indexes even though the C `break` only leaves the inner loop. That
  explains the zero read-watch hits of W313/W324/W325/W329 as a compiler
  hoist, not only a short pre-crash window.
- Structural ceiling for the natural post-decode consumer in this build;
  allocator/free consumers and other builds are not excluded. Three
  transient GDB fault-site runner variants produced no usable backtrace
  and were removed; the negative is recorded in `PROVENANCE.md`.
- Evidence: `lab/frontier/gimpjif2shell/live/evidence/w333-extraction-disasm.txt`
  (SHA `302d8434…`), reproduced byte-for-byte by the same objdump command.
  Grade unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
  NO r5; no replay owed for a static, grade-neutral finding.

## W334 measured cgroup memory bound (2026-11-27, 10:45Z wake)

Grade-neutral environmental finding. This wake's cgroup has
`memory.max=2147483648` (2 GiB), `memory.high=1610612736` and
`memory.oom.group=1`; its parent plant slice has `memory.max=10737418240`
(10 GiB) and was already at `memory.current=8578035712` (~7.99 GiB). Host
`MemAvailable` is ~20 GiB. The smallest wrapping geometry
`33025x65026 = 2147483650` requires 4 GiB of `dest` plus an ~8 GiB GEGL
layer, about 12 GiB resident; the previously used `45771x46918` geometry is
larger. No file-reachable geometry lowers this, and workload-slice/memory
limit changes are host administration reserved to the person. W334's
measured no-shim 64 KiB run peaked at 833318912 bytes (0.78 GiB) with
`memory.events` all zero, so these caps bound a *completed* load but did
not cause the observed terminal SIGSEGV; that cause stays UNKNOWN. No new
write primitive and no grade change. Hashes, limits and the sampled trace
are in `lab/frontier/gimpjif2shell/PROVENANCE.md`.

## W335 allocator fault instructions (2026-11-27, 11:09Z wake)

Grade-neutral. Static disassembly of the verified AppImage's bundled libc
decodes W304's `free+115` (`0xa3033`) as `mov (%rdx),%r15` on a
non-main-arena lookup: the chosen `0x4d4d…` size word has bit 2 set, so
`free` reads a heap header derived from the chunk address, not a supplied
pointer. Two fresh no-shim replays of the same 8 KiB JIF through the
verified plug-in faulted instead in `malloc` at libc+`0x9eaff`
(`cmp (%rdi,%rax,1),%rax` with `rax = chosen_size & ~7`), under
`gimp_color_profile_new_from_icc_profile`; the chosen-size word was again
`0x4d4d…` and the compare target was non-canonical, so the dereference
fails. Fault sites are layout-sensitive across runs; no chosen-address
write, successful dereference, marker or command. Grade unchanged rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. Hashes and logs:
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

## W336 extraction consumer closed by source semantics (2026-11-27, 11:37Z wake)

Grade-neutral. No replay owed, no messages, no signals. A no-shim GDB run
of the verbatim pin at `-O0` (`run-extract-336.sh` SHA `8d2b7f9e…`) gave a
positive control — an access watchpoint on `indexes+260` fired inside real
libz (`0x5a` -> `0x4d`) — then armed three read watchpoints at
`+260/+280/+336` before the extraction loop finished. The loop ran from
`i=0 pos=0 total_out=324` to `pos=260` at pin line 136 with **zero read
hits**; watches were deleted before the driver's own canary readback.
Evidence: `lab/frontier/gimpjif2shell/harness/evidence/w336-extract-full.log`
SHA `9b4f233f…`; script `harness/gdb-extract-336.cmd` SHA `af33b29f…`.

Correction to W333: the source itself, not just that binary's compiler,
prevents OOB `indexes` reads. A file-reachable wrap requires
`alpha_frame=TRUE`; `pos` advances by 2 per outer iteration and the guard at
pin line 122 is re-evaluated before every load. Wrapped `data_size` is
always even, so the unguarded alpha store cannot pass `dest`. Only
allocator/free consumers (W304/W335) remain observed; no chosen-pointer
dereference, command or r5. Upstream recheck at 11:45Z: still 3.2.8, no
vendor-shipped fixed build.

Clean-archive replay at 11:5xZ from `git archive 6c20fb5c` reproduced the
same positive WRITE watch, `total_out=324`, `pos=260` and zero read hits
with byte-identical runner and script; only stack addresses shifted.
Commit `6c20fb5c` (runner, script, transcript, brief, status, PROVENANCE).

## W337 minimal-geometry live probe (2026-11-27, 12:02-12:2xZ wake)

Grade-neutral, no replay owed. Every prior *live* run used the published
geometry (`45771x46918`, `data_size=260`); this wake drove the generator's
minimal mode (`33025x65026`, product `0x80000002`, alpha `data_size=4`,
`avail_out=0x80000002`, 40 decompressed `0x4d` bytes) through the real
no-shim GIMP 3.2.8 plug-in under GDB. A first attempt using the default
`/tmp/gimpjif-appimage` AppRun resolved the return frame to
`inflate+79` in `patch-shim.so`; that shim-assisted log is preserved as a
tooling negative and excluded. The repaired runner generated a private
shim-free `AppRun.min337` in the clean `w316` tree; the return frame then
resolved to `ReadJeffsImage.isra.0+696` in the real plug-in.

Observed: `PRE avail=0x80000002 idx=0x555555678fe0`; before inflate
`+24=0x41` (chunk size), `+32` heap pointer; after inflate the full 40
bytes are `0x4d4d…` (`+0/+8/+16/+24/+32`), with `+40/+48/+56/+64/+72`
untouched. No OOB word maps to an executable range — candidates are
`0x4d4d…`, small integers or heap `rw-p` pointers — so no read watcher
had a target. GDB logged no in-process fault stop; GIMP printed
`Fatal signal: Segmentation fault` / `Plug-in crashed: "file-gif-load"`,
the same terminal crash class as earlier geometries.

Conclusion: the minimal geometry does not change the ceiling. Both
file-reachable wrapped products write chosen bytes OOB but neither
completes the ~4 GiB `dest` / ~8 GiB GEGL load, and neither exposes a
code pointer or post-decode consumer. Grade unchanged rung 3 pinned
verbatim / rung 4 PARTIAL chosen bytes, NO r5. Hashes and transcript in
`lab/frontier/gimpjif2shell/PROVENANCE.md`, W337 section.

Clean-archive replay from commit `8d4458ac` (`git archive HEAD
lab/frontier/gimpjif2shell` into `/tmp/w337-clean`) reproduced the pinned
inflate, the real-plug-in `ReadJeffsImage.isra.0+696` return frame, the same
`0x4d4d…` OOB pattern and the same terminal crash; only ASLR-shifted
addresses and the adjacent chunk-size word moved. Replay full-log SHA-256
`71c690cbafaf283db74e38504442bbc9ee3a3b0765d9186a4a9a43db7e5d48a4`.

## W340 selective payload: terminal fault is the geometry (2026-11-27, 12:39-12:55Z wake)

Grade-neutral causal lane after W339 verified W337 as labeled. Three no-shim
runs through the real GIMP 3.2.8 plug-in at the minimal geometry
(`33025x65026`, product `0x80000002`, alpha `data_size=4`):

- preserving the adjacent chunk size at `indexes+24` (`0x41`) while
  overwriting the live heap word at `+32` with `0x4d4d…` still crashed;
- choosing a mapped heap address at `+32` with read watchpoints on both the
  slot and its target gave zero watch hits and the same crash;
- a control with only four decompressed bytes, entirely inside the 4-byte
  `indexes` object (no out-of-bounds write at all), reached the same
  `ReadJeffsImage.isra.0+696` return frame and produced the same
  `Fatal signal: Segmentation fault` / `Plug-in crashed`.

Therefore the terminal fault belongs to the file-reachable ~4 GiB `dest` /
~8 GiB GEGL load, not to a consumer of the overflowed bytes. No
chosen-pointer dereference, control flow or command side effect. Grade
unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.
Scripts, JIFs, transcripts and hashes in the W340 section of
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

## W341 second upstream geometry (2026-11-27, 13:03Z wake)

Grade-neutral. No replay, messages or signals owed. gimp.org still lists
3.2.8 as current stable (checked 13:1xZ); no vendor-shipped fixed build.
Upstream issue 17001's second geometry (`65535x32769`, product
`0x80007fff`, alpha `data_size=65534`) was driven through the same no-shim
GDB-verified GIMP 3.2.8 plug-in path. Three runs:

- 98307 chosen `0x4d` bytes (~32 KiB OOB): `PRE avail=0x80007fff`,
  POST `chunk_size=0x10011`; 4098 of 4100 words dumped after `indexes` are
  chosen, the sole other word is a ragged partial write at `idx+98304`.
  No live pointer word in the span, so no watchpoint could be armed.
- Zero-OOB control (65534 in-bounds bytes): the adjacent object is a single
  ~132 KiB free chunk of size `0x20441`; same `Fatal signal` / plug-in crash
  as W340's control at the other geometry.
- Preserved-size run (all chosen except the `0x20441` word at `+65544`):
  WRITE watch on that word and READ watch on its `fd` armed at the real
  plug-in return logged **zero hits** before the same terminal crash.

Source inspection also closes the thumbnail route: `gif_load_thumb()` calls
the same `load_image()` with no downscale, so JIF thumbnails keep the same
~4 GiB `dest`. No chosen-pointer dereference, allocator consumption of the
groomed free chunk, marker or command. Grade unchanged rung 3 pinned
verbatim / rung 4 PARTIAL chosen bytes / NO r5; no witness replay offered
(same disposition as W334-W340). JIFs, scripts, logs and hashes: W341
section of `lab/frontier/gimpjif2shell/PROVENANCE.md`.

