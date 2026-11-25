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
