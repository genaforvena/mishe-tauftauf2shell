# mcuboot2shell — admitted status (2026-11-25 08:35Z)

## 2026-11-25 08:35Z — ADMITTED under standing #6 (143rd route)

- Verified staged claim, charter, wall, lab and pre-existing window 151
  (panes %304/%305); no second window created.
- Added the hy4-flash `max_parallel: 3` route in `.mishe-tauftauf/engine/routes.json`
  and both resolver keys in `.mishe-tauftauf/resolvers.json`; re-read and
  JSON-parsed both files after the edit.
- EXACT full-flag sync from `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a`: `written 9, removed 0` (three roles x three units),
  daemon-reload, slice/debounce/path present, path enabled and active.
- Pinned full-flag doctor `PASS local plant out of Git` / `GREEN`, rc 0;
  `for_role` returns `RoutedEngine`; `doctor` and `omp-only` GREEN.
- Grade unchanged from handoff: rung 3 pinned function / rung 4 PARTIAL chosen
  bytes, harness 22 PASS / 0 FAIL; no real build, serial wire, AES image,
  pointer/IP/command, r5; witness UNKNOWN.

The staged record below is preserved as the pre-admission evidence.

CVE-2026-16663 / GHSA-7c8v-m3pm-wh74, MCUboot encrypted serial-recovery
`decrypt_region_inplace()` absolute-header-index OOB write. Brief:
`reports/frontier-mcuboot2shell.md`. Lab: `lab/frontier/mcuboot2shell/`.

Grade: rung 3 CONFIRMED in the verbatim pinned function with stand-ins
(ASan dynamic-stack-buffer-overflow WRITE; clang agreement; Valgrind invalid
write in the deep case). Rung 4 PARTIAL: caller-chosen bytes read back at
`buf+6144` and a different caller-chosen string at the same OOB destination.
No real MCUboot build, no serial/USB wire, no real AES image, no pointer/IP/
command control, no rung 5. Witness UNKNOWN. AV:L, pre-authentication.
Upstream fix `6e1465c38e3d` merged on main; patched 2.5.1 release projected
by the advisory, not observed.

`sh lab/frontier/mcuboot2shell/harness/run.sh`: 22 PASS / 0 FAIL; log at
`harness/evidence/run-all.log`. Fixed and safe controls are clean; GCC/Clang
ASan do not flag the deep 2048-byte jump (preserved negative), Valgrind does.
Target window 151 on the inner tmux socket; operator owns final admission.

Handoff receipt 05:59Z: commit `bf2a32ff`; clean git-archive replay 22 PASS /
0 FAIL; window 151 alive (panes %304/%305), registry 152/152 unique; operator
DM #4142 (window already exists), witness DM #4143. No grade change.

## 2026-11-25 09:03Z — W1 real-source host build (target mind)

- Provisioned the parent and fix MCUboot trees locally under
  `lab/frontier/mcuboot2shell/{upstream-parent,upstream}` (fetching only;
  no external probe). Pinned whole files hash-identical to upstream.
- Built the real pinned vulnerable and fixed `boot_serial_encryption.c` with
  the real `encrypted.c` + TinyCrypt AES-CTR and a 4096-byte flash shim;
  interposed only a logging wrapper around `boot_enc_decrypt` (upstream body
  compiled unchanged via a rename macro). Recipe, hashes and evidence:
  `lab/frontier/mcuboot2shell/real/PROVENANCE.md`.
- Parent ASan `edge`: real OOB access at `buf+4104` in the AES-CTR path
  (`READ of size 1`, pinned `:175` → `encrypted.c:722`). Parent plain
  `attack`/`attack2`: real decryptor wrote chosen `MISHE-REAL-AES!!` at
  `buf+6144`/`buf+1024`, with adjacent-stack ciphertext grooming as an
  explicit condition. Fixed source: `buf+8`/`buf+2048`/`buf+1024`, rc 0,
  ASan clean. Valgrind 0 errors in the real build; deep ASan negative kept.
- Grade moved from rung 4 PARTIAL to **rung 4 DEMONSTRATED in the lab host
  build** (real pinned source and real AES decryptor, stated grooming
  condition). Still no live bootloader process, wire, real encrypted image,
  pointer/IP/command, rung 5. Witness UNKNOWN; author evidence only.

### W1 replay receipt (2026-11-25 09:05Z)

Scoped commit `ee7fe914`. A `git archive HEAD` replay of
`lab/frontier/mcuboot2shell/{real,src}` into a throwaway directory, with the
ignored `upstream-parent/` tree symlinked for provisioning, ran `sh run.sh`
again: `REPLAY_OK`; `asan-edge.out` contains two
`dynamic-stack-buffer-overflow` lines; `plain-attack.out` reads back
`4d495348452d5245414c2d4145532121`; `fixed-asan-attack.out` has zero
`ERROR: AddressSanitizer` lines. Addressed DM #4236 to witness (independent
replay requested) and #4237 to operator (material grade change) on the
shared chat tape.

## 2026-11-25 09:07Z — loopback serial-path check (bounded negative)

Charter's next gate was whether an existing host serial-recovery instance can
expose the upload path on 127.0.0.1. In the provisioned parent tree, no.

- `boot/boot_serial/src/boot_serial.c:173` holds a `boot_uart_funcs` table;
  `boot_serial.h:37-39` defines it as two caller-supplied `read`/`write`
  callbacks. `boot_serial_start()` (`boot_serial.c:2033`) and
  `boot_serial_check_start()` (`:2052`) process SMP/MCUmgr commands through
  those callbacks; `bs_upload()` (`:1146`) reaches
  `boot_handle_enc_fw()` (`:1494`) after an encrypted upload.
- A grep of `sim/` for `boot_serial_start`, `boot_uart_funcs`, `socket(`,
  `AF_INET` and `mcumgr` finds no matches. The simulator is a bootloader
  logic harness, not a serial server. No Zephyr/native_sim host runner is
  provisioned in this tree.
- Conclusion: **NO_LOOPBACK_PATH** in the provisioned source. A live
  loopback target would require adding new transport code and a real serial
  process; that is a separate bounded experiment, not a claim here. No
  external probe was made. Rung 5 remains UNKNOWN; all wire/process/r5
  negatives from the staged grade still stand.

- Independent read-only source trace confirms the same conclusion: platform
  byte sources are Zephyr UART/CDC-ACM (`boot/zephyr/serial_adapter.c`),
  Mynewt hardware UART (`boot/mynewt/src/main.c`), ESP32 UART/USB-JTAG
  (`boot/espressif/port/serial_adapter.c`); all feed `boot_serial_input()`
  in-process. The host simulator compiles bootutil + `csupport/run.c` but
  **not** `boot_serial.c` (`sim/mcuboot-sys/build.rs:604-643`); its CLI has
  only `run`/`runall`/`sizes`. The Mynewt test builds SMP frames in memory
  and calls `boot_serial_input()` directly
  (`boot/boot_serial/test/src/boot_test.c`). `docs/serial_recovery.md`
  describes an external mcumgr client on `/dev/ttyACM0`, not loopback.

## 2026-11-25 09:49Z — W2 live loopback wire-to-sink (target mind)

A new lab process (`lab/frontier/mcuboot2shell/real/wire-harness.c`) listens
only on `127.0.0.1`, accepts a 32-byte MCUboot image header from a client,
and feeds those wire bytes as `hdr` to the real pinned
`decrypt_region_inplace()` and the real AES-CTR `boot_enc_decrypt()`. The
wrapper logs the real destination pointer minus the 4096-byte VLA base.

- Wire `ih_hdr_size=4104` → real decrypt call `len=4088`, destination
  `buf+4104`, process SIGSEGV (139). `6144` → `len=2048`, `buf+6144`, rc 0.
  `7168` → `len=1024`, `buf+7168`, rc 0. In-bounds control `2048` → `buf+0`,
  rc 0. Raw logs `real/evidence/wire-<hdr>.log`; recipe, hashes and full
  conditions in `real/WIRE-PROVENANCE.md`.
- Grade: rung 4 DEMONSTRATED extended to a **live loopback wire-to-sink
  path** with client-controlled header bytes; the chosen-plaintext readback
  still belongs to W1 and requires its stated stack grooming. Rung 5 stays
  UNKNOWN: no MCUboot serial/SMP parser, no real encrypted image/key TLV,
  no pointer/IP/command control, and the transport is a lab shim.
- Stack grooming was disabled here because it corrupts this server's own
  frame; an earlier groomed run is preserved as a negative in the
  provenance. No ASan run in W2; W1 remains the memory-corruption evidence.
  Witness verdict remains UNKNOWN (author evidence only).

### W2 replay receipt (2026-11-25 09:53Z)

Scoped commit `4ed74036`. A `git archive HEAD` replay of
`lab/frontier/mcuboot2shell/{real,src}` into a throwaway directory, with the
ignored `upstream-parent/` tree symlinked and `real/run.sh` run first to
rebuild the ignored object, ran `wire-run.sh` again: all four rows
reproduced (`dst_delta=4104/6144/7168/0`, 4104 SIGSEGV 139, others rc 0,
`WIRE_DONE`). Addressed DM #4257 asks the witness to replay; verdict remains
UNKNOWN.

## 2026-11-25 11:01Z — W3 wire-to-chosen-bytes (target mind)

- Added a `WIRE_GROOM` variant of the W2 loopback listener: server locals
  move to static storage and the client supplies a 16-byte chosen plaintext
  after the 32-byte header. Same verbatim pinned
  `decrypt_region_inplace()` and real TinyCrypt AES-CTR decryptor.
- Measured with wire string `WIRE-CHOICE-1234`: `ih_hdr_size=6144` →
  real destination `buf+6144`, readback `574952452d43484f4943452d31323334`,
  rc 0; `7168` → `buf+7168`, same readback, rc 0; `2048` control →
  `buf+0`, same readback, rc 0; `4104` → `buf+4104`, bogus `len` and
  SIGSEGV (139), preserved as a negative. Default W2 path re-run after the
  edit still gives its four original rows and no readback.
- Grade: rung 4 DEMONSTRATED extended to **wire-to-chosen-bytes** in a live
  loopback process, under the stated adjacent-stack grooming condition.
  Rung 5 UNKNOWN: lab transport shim, no MCUboot SMP/CBOR parser, no real
  encrypted image/key TLV, no pointer/IP/command control, no witness verdict.
  Recipe, hashes, table, negatives: `lab/frontier/mcuboot2shell/real/
  WIRE-GROOM-PROVENANCE.md`; raw logs `real/evidence/wire-groom-*.log`.

### W3 replay receipt (2026-11-25 11:01Z)

Scoped commit `3a04096d`. A `git archive HEAD` replay of
`lab/frontier/mcuboot2shell/` into a throwaway directory, with the ignored
`upstream-parent/` tree symlinked and `real/run.sh` run first to rebuild the
ignored object, reproduced all four rows from `wire-groom-run.sh`:
`dst_delta=6144/7168/4104/0`, readback hex
`574952452d43484f4943452d31323334` on 6144/7168/2048, 4104 SIGSEGV 139,
`WIRE_GROOM_DONE`. Witness replay not yet observed; verdict UNKNOWN.

## 2026-11-25 14:44Z — W4 native SMP upload path (target mind)

- Built the **real** MCUboot `boot_serial.c`, zcbor decoder/encoder,
  pinned `boot_serial_encryption.c` and real TinyCrypt AES-CTR decryptor
  into a native host process (`real/smp/`). Only flash, UART, OS, CRC/base64
  and wrapped-key loading are shims; the two local source copies differ
  from upstream by tracing only. Full recipe, hashes and negatives:
  `lab/frontier/mcuboot2shell/real/smp/SMP-PROVENANCE.md`.
- A loopback listener accepts one real mcumgr image-upload packet: CBOR
  `{"image":0,"data":<MCUboot image header + encrypted body + TLV>,"len":N,
  "off":0}` plus 16 wire-chosen plaintext bytes. The real
  `boot_serial_input()` → `bs_upload()` → `boot_handle_enc_fw()` →
  `decrypt_image_inplace()` → `decrypt_region_inplace()` path drives the
  OOB sink for the first time; W3's bespoke transport shim is no longer the
  header's entry point.
- Measured: `ih_hdr_size=6144` → real decrypt `len=2048` at `dst_delta=6144`
  with readback `574952452d43484f4943452d31323334` (`WIRE-CHOICE-1234`);
  `7168` → `len=1024` at `dst_delta=7168`, same readback; `2048` control →
  `dst_delta=2048`, no chosen string; `4104` → `len=4088` at
  `dst_delta=4104`, SIGSEGV 139 (negative preserved). `READBACK delta=`
  lines in `real/smp/evidence/smp-{6144,7168}.log` are the evidence; later
  in-bounds decrypts overwrite the final buffer. Replay: `sh real/smp/run.sh`.
- Grade: rung 4 DEMONSTRATED extended through MCUboot's real SMP command
  dispatch and CBOR decoder. Rung 5 UNKNOWN: native host build, not Zephyr
  or a real MCU; no serial-port framing parser (packet goes straight to
  `boot_serial_input()`), no real encrypted image/key TLV (key load
  shimmed), no ASan in W4, no pointer/IP/command control, no benign command
  execution, no witness verdict. Author evidence only.

## 2026-11-25 17:17Z — W5 rung-5 feasibility negative (target mind)

Gdb (`sh real/smp/stack-layout.sh`) dumped the real native SMP process stack at
the wrapper in `boot_enc_decrypt()`. Relative to the 4096-byte VLA base,
saved return-address slots are `+5048` (`decrypt_image_inplace`), `+5096`
(`boot_handle_enc_fw`) and `+5688` (`bs_upload`); the wrapper's own saved rip
is at `-8`. Controlled OOB writes start above all of them (`6144` covers
`[+6144,+8192)`, `7168` covers `[+7168,+8192)`) and the words there are
groomed ciphertext/image data, not pointers. The `4104` row logs garbage
`len=1929027880 dst_delta=40415` and SIGSEGVs, so it is not a controlled
pointer write either. No chosen byte was observed in a saved return slot.

Decision: return-address overwrite toward rung 5 is structurally closed at
this native host build/frame geometry; grade unchanged (rung 4 DEMONSTRATED,
rung 5 UNKNOWN). Not a universal closure: a Zephyr/real-MCU frame layout was
not tested. Evidence `real/smp/evidence/stack-layout.txt`, recipe
`real/smp/stack-layout.sh`. W3/W4 witness verdicts remain UNKNOWN.

## 2026-11-25 19:56Z — W6 fragmented real UART loop + W7 fixed-control repair (target mind)

- Reconciled the unknown wake attempt 13: its W6 edits were all unstaged and
  its last action was a source edit, not a committed result. Its fixed-4104
  logs had no decrypt call and a smashed gdb frame. Cause was the lab groom
  shim writing `memcpy(buf+4104, g_groom_ct, 2048)` at sector 0, not the
  pinned fixed function. `real/smp/smp-shims.c` now compiles the groom out
  under `M2S_FIXED_CONTROL`; the pre-repair `-fixed-o0-4104.log` is a kept
  negative and `debug-fixed-*` files were removed.
- Rebuilt parent/fixed and replayed all eight cases with
  `sh real/smp/serial-run.sh`. Parent unchanged: 6144/7168 read back
  `574952452d43484f4943452d31323334` at `dst_delta=6144/7168`, 2048 in
  bounds, 4104 SIGSEGV 139. All four fixed cases now rc 0; fixed 4104 has
  in-bounds decrypts (`dst_delta=8/0/0`). Raw logs
  `real/smp/evidence/serial-smp-serial-*.log`.
- The client drives MCUboot's real `boot_serial_start_inactivity()` →
  `boot_serial_read_console()` → `boot_serial_input_raw()` → `bs_upload()`
  loop over a socket-backed `boot_uart_funcs`, with 400-byte image chunks
  split into ≤97-byte UART fragments. This closes W4's direct-call gap.
- Grade unchanged: rung 4 DEMONSTRATED through a real fragmented SMP upload;
  rung 5 UNKNOWN (no Zephyr/real MCU, real key TLV, pointer/IP/command
  control, benign command execution or witness replay). W3/W4/W6 witness
  verdicts remain UNKNOWN; author evidence only.

### W6/W7 replay receipt (2026-11-25 19:56Z)

Scoped commit `5f73e34c` (19 files). A `git archive HEAD
lab/frontier/mcuboot2shell` replay into a throwaway directory, with the
ignored `upstream-parent/` tree symlinked, ran `sh real/smp/serial-run.sh`
again: `SERIAL_RUN_DONE`, eight `hdr_size=` rows with
`SERVER_RC=0/0/0/139` for parent and `0/0/0/0` for fixed, the parent
`REAL_DECRYPT off=4096 len=2048 dst_delta=6144` row and its
`READBACK ... 574952452d43484f4943452d31323334`, and fixed 4104's in-bounds
`off=0 len=4088 dst_delta=8`. The earlier RED
`failed-m2shell-wake-mcuboot2shell-service` signal from attempt 13's no-yield
exit is already GREEN (`source=failure-recovered`, observed ~19:51Z); cause
was the provider 429 retry-after, not a unit defect. Witness verdict on
W3/W4/W6 remains UNKNOWN (author evidence only).

## 2026-11-25 20:34Z — W8 clean-groom ceiling (target mind)

Added a `nogroom` parent variant (`-DM2S_NO_GROOM`), a wire-clean runner
`real/smp/serial-clean.sh` and a gdb probe `real/smp/clean-layout.py`.
Clean replay: parent 4104/5000/6000 → rc 139 with OOB writes of 4088/3192/
2192 bytes at `dst_delta` 4104/5000/6000; parent 7000 → rc 0 with 1192 bytes
at `+7000`; parent 2048 and fixed 4104 → rc 0, in-bounds only. Gdb shows
saved code addresses at `+5048/+5088/+5688` and uploaded image magic at
`+5056`, but the low-offset write smashes `tc_ctr_mode` itself before return;
frame 7 holds a garbage return address. Clean wire-only chosen bytes at OOB
offsets are **not** demonstrated without the lab groom; rung 4 stands with
that condition, rung 5 remains UNKNOWN. Host load 8–11 made the old 2 ms
fragment sleeps flaky, so the clean runner sends fragments contiguously.
Witness verdicts on all earlier rows remain UNKNOWN.

### W8 replay receipt (2026-11-25 20:38Z)

Scoped commit `6dade634` (15 files). A `git archive HEAD
lab/frontier/mcuboot2shell` replay into `/tmp/m2s-w8-replay-fHEf5y`, with the
ignored `upstream-parent/` tree symlinked, ran `sh real/smp/serial-clean.sh`
to `CLEAN_RUN_DONE`: parent rows 4104/2048/5000/6000/7000 gave
`SERVER_RC=139/0/139/139/0` and the fixed 4104 control gave 0. Witness
verdicts remain UNKNOWN; no command execution or witness replay observed.

## 2026-11-25 21:10Z — W9 independent replay offer (target mind)

No new measurement or grade change in W9. Both native return-address windows
(W5 high offset, W8 low offset) are closed on this build, and a third local
`serial-clean.sh` repeat would add no evidence. Sent chat message #4573 to the
witness offering an independent replay from a clean `git archive HEAD
lab/frontier/mcuboot2shell`: `sh real/smp/serial-clean.sh` (expected
`CLEAN_RUN_DONE`, parent 4104/2048/5000/6000/7000 →
`SERVER_RC=139/0/139/139/0`, fixed 4104 → 0) and
`python3 real/smp/clean-layout.py 4104` (`evidence/clean-layout.txt`: code
pointers at `+5048/+5088/+5688`, image magic at `+5056`, garbage frame-7 RIP).
The offer explicitly asks the witness to test the causal caveat: without the
`smp-shims.c` groom, wire-derived bytes reach the OOB window but the
chosen-byte readback at `+6144/+7168` is not reproduced; rung 4's chosen bytes
remain conditioned on that documented lab groom.

Grade unchanged: rung 4 DEMONSTRATED under the groom condition, rung 5
UNKNOWN; W3/W4/W6/W8 witness verdicts remain UNKNOWN until an independent
reply is observed. No physical serial, Zephyr/MCU, real key TLV, pointer/IP/
command control or benign command execution.

### W9 replay wrapper and author receipt (2026-11-25 21:14Z)

Added `lab/frontier/mcuboot2shell/replay-frontier.sh`: a one-command replay
from a clean `git archive HEAD lab/frontier/mcuboot2shell`, with
`M2S_UPSTREAM` naming the gitignored provisioned `upstream-parent` tree that
the wrapper symlinks into the archive. It runs `serial-clean.sh` and
`clean-layout.py`, then asserts the rc rows, the OOB/in-bounds markers and
the layout magic; it never asserts from logs unless the runner itself
succeeded. Follow-up chat message #4574 puts this wrapper in front of the
witness.

Author receipt: from `/tmp/m2s-w9r2-bcAGcT` (clean archive, upstream
symlinked) the wrapper printed 11/11 `OK` rows and `REPLAY_FRONTIER_OK`;
parent `SERVER_RC=139/0/139/139/0` for 4104/2048/5000/6000/7000, fixed 4104
`0`, parent `dst_delta=4104`, fixed `dst_delta=8`, `CLEAN_LAYOUT_DONE` and
magic `96f3b83d`. Preserved negative: the first wrapper draft symlinked
`upstream-parent` one directory too high, so the clean-archive build failed
(`cc1: fatal error: ../../upstream-parent/boot/bootutil/src/encrypted.c: No
such file or directory`) and its assertions initially read the archived
committed logs as if fresh; both faults were fixed in commit `89d8628b`
before the passing replay above. Commits: `fb3cfc13` (offer record),
`fcf3ffa9` (wrapper), `89d8628b` (fix). Grade unchanged: rung 4
DEMONSTRATED under the groom condition, rung 5 UNKNOWN; witness verdicts
UNKNOWN.

## 2026-11-25 22:56Z — W10 source-graph consumer negative (target mind)

Read-only check of the real upstream call chain behind the pinned write,
prompted by the W8 finding that no clean-return control-flow object is in
reach on this native build. Chat #4573/#4574 remain the canonical replay
offer; no third local replay was run, and no witness verdict has arrived
(witness queue at 22:56Z: nfdump, codebasememory, aspell, libraw, awslc).

Facts from the provisioned parent tree,
`lab/frontier/mcuboot2shell/upstream-parent/boot/boot_serial/src/`:

* `boot_serial_encryption.c:119-204` — `decrypt_region_inplace()` takes the
  absolute `ih_hdr_size` as `idx` at `:162` and passes `&buf[idx]` to
  `boot_enc_decrypt()` at `:175-177`. The fixed tree
  `upstream/boot/boot_serial/src/boot_serial_encryption.c:160-161` instead
  computes `idx = hdr->ih_hdr_size - abs_off` with
  `blk_sz = chunk_sz - idx`, i.e. an index bounded by the sector chunk.
* `boot_serial_encryption.c:183-188` — after decryption the only consumers
  of `buf` are `flash_area_write(fap, off + bytes_copied, buf, chunk_sz)`
  and the stack wipe at `:202`. The OOB-decrypted bytes at `buf+idx` with
  `idx > chunk_sz` are outside the written span and are never stored in the
  flashed image; they can only corrupt adjacent stack state.
* `boot_serial.c:1481` sends the SMP response (`boot_serial_output()`)
  *before* `:1494` calls `boot_handle_enc_fw(fap)`; the only post-decrypt
  action is the error log at `:1495-1497`. No zcbor/command dispatch parses
  decrypted bytes in this path.
* The other in-tree `boot_enc_decrypt()` callers
  (`bootutil/src/loader.c:922`, `ram_load.c:185`,
  `bootutil_img_hash.c:210`) use `off - hdr->ih_hdr_size` as the AES block
  offset argument, not as a buffer index; the index bug is local to the
  serial recovery path.

Disposition: on the real SMP consumer there is no post-decrypt command
dispatch or flashed-payload path for the OOB bytes, consistent with W5/W8.
Rung 4 stays DEMONSTRATED only under the documented groom; rung 5 stays
UNKNOWN. This is source-graph evidence, not a build or wire measurement,
and it does not change any witness verdict.

## 2026-11-25 23:28Z — W11 wire-vs-flash ciphertext differential (target mind)

No mcuboot verdict arrived; the tape through #4632 still ends with the
witness on nfdump/codebasememory/aspell/libraw/awslc. The canonical
`replay-frontier.sh` offer from W9 was not re-sent. One bounded experiment
closes the causal question left by W8's groom caveat.

`lab/frontier/mcuboot2shell/real/smp/wire-differential.sh` drives four
fragmented loopback SMP uploads with `ih_hdr_size=6144`, all `SERVER_RC=0`,
all `dst_delta=6144`. `client.py` now separates the 16-byte wire prefix
(`M2S_WIRE_PT`) from the plaintext used to build the uploaded flash
ciphertext (`M2S_CT_PT`); defaults preserve the old behavior. Evidence:
`real/smp/evidence/wire-differential.txt` and `wire-diff-*.log`.

* Groom build, prefix `WIRE-CHOICE-1234` then `DIFF-WIRE-987654` (flash
  ciphertext held fixed): OOB readback is
  `574952452d43484f4943452d31323334` then
  `444946462d574952452d393837363534`. The chosen 16 bytes track the wire
  prefix exactly, as in W4/W6.
* `nogroom` build, prefix held fixed and only the flash ciphertext changed:
  the final run reads back
  `1337d531b29cde09efb09d44a44830f5` in both arms (byte_diff 0/16;
  `WIRE_DIFFERENTIAL_OK`). An earlier run of the same pair differed in one
  of 16 bytes (`...b39c...` vs `...b09c...`), so strict invariance is not
  claimed; neither run produced either chosen 16-byte pattern.

Cause from the pinned source: `upstream-parent/boot/bootutil/src/encrypted.c:722`
calls `bootutil_aes_ctr_decrypt(..., buf, sz, blk_off, buf)` in place. At
`&buf[ih_hdr_size]` the AES input and output are the same OOB stack bytes;
the uploaded ciphertext lives in `buf[0..chunk_sz)` and is never the source
for the OOB window. `smp-shims.c:45-52` is what preloads `g_groom_ct` into
`buf+idx`, which is why only the groom condition yields chosen bytes. This
is a measured differential on the native build, not a universal closure for
custom crypto implementations with separate input/output buffers.

W10 correction: `upstream-parent/boot/bootutil/src/loader.c:889-924` does pass
`&buf[idx]`, but its `idx = hdr->ih_hdr_size - abs_off` is relative to the
chunk and smaller than `chunk_sz`; W10's compressed phrase "off -
ih_hdr_size ... not as a buffer index" should be read that way. The serial
recovery path remains the only absolute-index caller found.

After the client edit, `M2S_UPSTREAM=$PWD/upstream-parent sh
replay-frontier.sh` was re-run in-tree: 11/11 `OK`, `REPLAY_FRONTIER_OK`,
so the W9 canonical replay is unchanged. Grade unchanged: rung 4
DEMONSTRATED only with the documented groom; rung 5 UNKNOWN. All witness
verdicts on this lane remain UNKNOWN (author evidence only). Chat #4573/#4574
stay the standing replay offer; no new demand was sent.

Clean-archive receipt at 23:30Z after commit `3ac0636e`: `git archive HEAD
lab/frontier/mcuboot2shell` extracted to `/tmp/m2s-w11-5AnE9g` with
`M2S_UPSTREAM` pointed at the provisioned `upstream-parent` tree. Both
`replay-frontier.sh` (11/11 `OK`, `REPLAY_FRONTIER_OK`) and the new
`real/smp/wire-differential.sh` (`WIRE_DIFFERENTIAL_OK`) passed from that
committed snapshot. No grade or witness-state change.

## 2026-11-26 00:06Z — W12 stack-protector-all build (target mind)

Built a second, genuinely different build of the same loopback serial path
with `CFLAGS=-fstack-protector-all` and no groom:
`sh lab/frontier/mcuboot2shell/real/smp/stack-protector.sh`. The script
restores the canonical `smp-serial-nogroom` binary at the end. Instrumentation
was checked, not assumed: `objdump -d` counts 252 `__stack_chk_fail@plt`
calls in `smp-serial-sp` against 4 in `smp-serial-nogroom` (the pinned
`decrypt_region_inplace` is static and inlined, so no per-function symbol
exists to quote).

`real/smp/evidence/stack-protector.txt` and `evidence/sp-*.log`:
`ih_hdr_size=4104` → `SERVER_RC=139`, `CANARY=NOT_TRIPPED`; the two
`REAL_DECRYPT` rows are `off=0 len=0 dst_delta=4104` then
`off=4096 len=4088 dst_delta=4104`, and the readback is garbage. The
process dies with SIGSEGV before the instrumented function returns, so no
canary report is printed. `ih_hdr_size=2048` → `SERVER_RC=0`,
`SERIAL_DONE`/`SMP_DONE`, no canary report. Stack protector changes neither
the fault nor its observability on this path; it is not a mitigation that
turns this into a clean, controlled write.

Grade unchanged: rung 4 DEMONSTRATED only with the documented groom, rung 5
UNKNOWN. No witness verdict received; chat #4573/#4574 remain the standing
replay offer and were not re-sent.

## 2026-11-26 01:41Z — W13 clean-archive receipt and research closure (target mind)

No witness verdict and no unread message arrived in this wake. Rather than
repeat the W8/W10/W11/W12 measurements, I verified the canonical W9 replay
once from a clean archive of current HEAD `1146959c`:

```
rm -rf /tmp/m2s-w13-replay && mkdir -p /tmp/m2s-w13-replay
git archive HEAD lab/frontier/mcuboot2shell | tar x -C /tmp/m2s-w13-replay
M2S_UPSTREAM=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/mcuboot2shell/upstream-parent \
  sh /tmp/m2s-w13-replay/lab/frontier/mcuboot2shell/replay-frontier.sh
```

Result: 11/11 `OK`, `REPLAY_FRONTIER_OK` — parent 4104/5000/6000 →
`SERVER_RC=139` with `dst_delta=4104`, 2048/7000 and fixed 4104 → rc 0,
fixed `dst_delta=8`, layout magic `96f3b83d`. This is a receipt for the
committed snapshot, not a new measurement.

Research is closed at the documented ceiling. On this build the chain is
broken at three independent points: the serial consumer performs no
post-decrypt dispatch (W10), clean OOB bytes are stack residue rather than
uploaded ciphertext without the documented groom (W11), and the plain,
optimized and stack-protected builds do not return cleanly from the OOB
write (W5/W8/W12). Grade unchanged: rung 4 DEMONSTRATED only with the
groom; rung 5 UNKNOWN. No witness stage is ESTABLISHED; chat #4573/#4574
remain the standing replay offer and were not re-sent.

The repeated `--again` chain is retired: absence of a reply is not evidence.
Reopen only on a witness reply with a reproducible counterexample or
ESTABLISHED verdict, or on a genuinely different build/consumer that has
wire-controlled in-place-AES OOB input, a clean return and real post-decrypt
command dispatch.
