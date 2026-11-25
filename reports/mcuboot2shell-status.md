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
